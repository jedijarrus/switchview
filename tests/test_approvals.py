"""The four-eyes principle (Phase 4a, Tasks 6 and 7): a generic approval mechanism (app/approvals.py, the routes in
app/api_approvals.py). Off by default; with it on (settings.four_eyes, PUT /api/settings/approvals, Admin) a change in expert mode
cannot be applied directly: /plan says so ("approval": true), /apply refuses it (409), and whoever has Ändern requests it instead
(POST /api/approvals) with exactly the desired state they sent and the preview they saw. A request is listed, withdrawn by its
requester, rejected by someone else with Freigeben, or expires after its hours (24 by default); every step is audited and announced
to the listeners (approvals.subscribe). Task 7 adds reviewing and approving.

The app runs in-process through FastAPI's TestClient, signed in per request as the user its X-Test-User header names
(apifix.by_header). The plan is a fake (api_changes._make_plan, fake_plan: it plans what STATE says) and so is the start of a change
(changes.run_change records the id on the call, the task it would become never has to run): no switch, no network.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

import api_approvals
import api_changes
import apifix
import approvals
import changes
import db
import dbfix
import roles

ran: list[int] = []
BASE_USERS = {"anna": apifix.user("aendern", "anna"), "ben": apifix.user("freigeben", "ben"), "cleo": apifix.user("admin", "cleo"),
              "notfall": apifix.user("admin", "admin", method="local"), "lea": apifix.user("lesen", "lea")}
USERS: dict = {}
PLAN = {"mode": "ports", "ports": ["6"], "change": {"untagged": "20"}, "expert": True}


def H(who):
    return {"X-Test-User": who}


def four_eyes(on=True):
    """The four-eyes principle on (or off); the hours stay the default."""
    asyncio.run(db.set_setting("four_eyes", "1" if on else "0"))


class STATE:                                # what fake_plan plans against; a test sets it to "change the switch"
    shown = ["vlan 20 untagged 6"]
    blocked = []


async def fake_plan(row, body):
    plan = {"shown": list(STATE.shown), "commands": list(STATE.shown), "blocked": list(STATE.blocked), "mechanism": "ssh", "warnings": [],
            "desired": {"6": {"u": "20"}}, "before": {"6": {"u": "1"}}, "expert": body.expert}
    return plan, {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}, "ports", api_changes._summary(body)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A fresh database with one switch "SW" in zone "EK" (its id is the fixture's value), the fake plan, the recording run_change
    and no listener."""
    apifix.fresh_db(tmp_path, monkeypatch)
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1", zone="EK")
    STATE.shown = ["vlan 20 untagged 6"]
    STATE.blocked = []
    ran.clear()
    monkeypatch.setattr(api_changes, "_make_plan", fake_plan)

    def run_fake(cid):
        ran.append(cid)             # recorded on the call itself: the task it would become never has to run

        async def nothing():
            return None
        return nothing()

    monkeypatch.setattr(changes, "run_change", run_fake)
    monkeypatch.setattr(approvals, "_listeners", [])
    return sid


@pytest.fixture
def client(world, monkeypatch):
    """A TestClient signed in per request as USERS[<X-Test-User>] (BASE_USERS unless a test adds someone)."""
    USERS.clear()
    USERS.update(BASE_USERS)
    with apifix.signed_in(monkeypatch) as c:
        apifix.by_header(USERS)
        yield c


def ask(client, sid, who="anna", plan=PLAN):
    p = client.post(f"/api/switches/{sid}/plan", json=plan, headers=H(who)).json()
    return p, client.post("/api/approvals", json={"kind": "port_change", "switch_id": sid, "plan": {**plan, "mechanism": p["mechanism"],
                                                                                                    "token": p["token"]}},
                          headers=H(who))


@pytest.mark.parametrize("kind, request_, on, want", [
    ("port_change", {"mode": "ports", "expert": True}, True, True), ("port_change", {"mode": "ports", "expert": False}, True, False),
    ("port_change", {"mode": "ports", "expert": True}, False, False), ("port_change", {"mode": "revert", "expert": True}, True, False),
    ("bulk_change", {"expert": True}, True, False)])
def test_needs_approval(kind, request_, on, want):
    assert approvals.needs_approval(kind, request_, on) is want


def test_without_four_eyes_an_expert_change_runs_directly(world, client):                         # Pin of today's rule, now with roles
    p = client.post(f"/api/switches/{world}/plan", json=PLAN, headers=H("ben")).json()
    assert p["approval"] is False and client.post(f"/api/switches/{world}/apply", json={**PLAN, "token": p["token"]},
                                                  headers=H("ben")).status_code == 200 and len(ran) == 1
    assert client.post(f"/api/switches/{world}/plan", json=PLAN, headers=H("anna")).status_code == 403


def test_with_four_eyes_the_preview_asks_for_approval_and_apply_refuses(world, client):
    four_eyes()
    p = client.post(f"/api/switches/{world}/plan", json=PLAN, headers=H("anna")).json()
    assert p["approval"] is True
    for who in ("anna", "ben", "cleo"):
        r = client.post(f"/api/switches/{world}/apply", json={**PLAN, "token": p["token"]}, headers=H(who))
        assert (r.status_code, r.json()["detail"]) == (409, api_changes.APPROVAL_NEEDED)
    assert ran == [] and client.post(f"/api/switches/{world}/plan", json={**PLAN, "expert": False}, headers=H("anna")).json()["approval"] is False


def test_a_request_keeps_what_the_requester_saw(world, client):
    four_eyes()
    p, r = ask(client, world)
    aid = r.json()["id"]
    a = client.get(f"/api/approvals/{aid}", headers=H("ben")).json()
    assert (a["status"], a["requested_by"], a["requester_role"], a["payload"], a["preview"]["commands"], a["preview"]["token"], a["own"]) == (
        "open", "anna", "aendern", PLAN, STATE.shown, p["token"], False)
    assert "requester_subject" not in a and client.get(f"/api/approvals/{aid}", headers=H("anna")).json()["own"] is True
    assert datetime.fromisoformat(a["expires_at"]) - datetime.fromisoformat(a["requested_at"]) == timedelta(hours=24)
    assert dbfix.query("SELECT username, action, role FROM audit WHERE action LIKE 'approval%'") == [("anna", "approval_requested", "aendern")]


@pytest.mark.parametrize("setup, status, detail", [
    (lambda: None, 409, api_approvals.NO_APPROVAL_NEEDED),                                      # four eyes off
    (lambda: four_eyes() or setattr(STATE, "shown", ["vlan 30 untagged 6"]), 409, api_changes.STALE),     # another plan than the preview's
    (lambda: four_eyes() or setattr(STATE, "blocked", [{"port": "6", "reason": "x"}]), 409, "Nicht ausführbar: 6: x")])
def test_a_request_is_checked_like_apply(world, client, setup, status, detail):
    p = client.post(f"/api/switches/{world}/plan", json=PLAN, headers=H("ben")).json()
    setup()
    r = client.post("/api/approvals", json={"kind": "port_change", "switch_id": world, "plan": {**PLAN, "mechanism": "ssh", "token": p["token"]}},
                    headers=H("ben"))
    assert (r.status_code, r.json()["detail"]) == (status, detail) and dbfix.query("SELECT count(*) FROM approvals") == [(0,)]


def test_only_the_requester_withdraws_and_only_once(world, client):
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    assert client.post(f"/api/approvals/{aid}/withdraw", headers=H("ben")).json()["detail"] == api_approvals.ONLY_OWN
    assert client.post(f"/api/approvals/{aid}/withdraw", headers=H("anna")).status_code == 200
    assert client.post(f"/api/approvals/{aid}/withdraw", headers=H("anna")).json()["detail"] == f"Anfrage #{aid} ist zurückgezogen"
    assert dbfix.query("SELECT username, action, role FROM audit WHERE action = 'approval_withdrawn'") == [("anna", "approval_withdrawn", "aendern")]


def test_a_rejection_keeps_its_comment_and_never_comes_from_the_requester(world, client):
    four_eyes()
    aid = ask(client, world, "ben")[1].json()["id"]
    assert client.post(f"/api/approvals/{aid}/reject", json={}, headers=H("ben")).json()["detail"] == api_approvals.OWN_REJECT
    assert client.post(f"/api/approvals/{aid}/reject", json={"comment": "nicht heute"}, headers=H("cleo")).status_code == 200
    a = client.get(f"/api/approvals/{aid}", headers=H("lea")).json()
    assert (a["status"], a["decided_by"], a["comment"]) == ("rejected", "cleo", "nicht heute")
    assert dbfix.query("SELECT detail FROM audit WHERE action = 'approval_rejected'")[0][0].endswith(": nicht heute")


def test_a_request_expires(world, client):
    four_eyes()
    ask(client, world)
    dbfix.query("UPDATE approvals SET expires_at = ?", ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),))
    assert [a["status"] for a in client.get("/api/approvals?status=all", headers=H("lea")).json()] == ["expired"]
    assert dbfix.query("SELECT username, action, role FROM audit WHERE action = 'approval_expired'") == [(None, "approval_expired", None)]
    assert asyncio.run(approvals.expire_due()) == 0


def test_listeners_hear_every_step_and_a_failing_one_costs_nothing(world, client):
    four_eyes()
    heard = []

    async def ear(event, a):
        heard.append((event, a["id"]))

    async def broken(event, a):
        raise RuntimeError("kaputt")

    approvals.subscribe(broken)
    approvals.subscribe(ear)
    aid = ask(client, world)[1].json()["id"]
    client.post(f"/api/approvals/{aid}/withdraw", headers=H("anna"))
    bid = ask(client, world)[1].json()["id"]
    client.post(f"/api/approvals/{bid}/reject", json={}, headers=H("cleo"))
    eid = ask(client, world)[1].json()["id"]
    dbfix.query("UPDATE approvals SET expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (eid,))
    client.get("/api/approvals?status=all", headers=H("lea"))
    assert heard == [("requested", aid), ("withdrawn", aid), ("requested", bid), ("rejected", bid), ("requested", eid), ("expired", eid)]


def test_the_four_eyes_setting(world, client):
    assert client.put("/api/settings/approvals", json={"four_eyes": True, "hours": 48}, headers=H("cleo")).status_code == 200
    s = client.get("/api/settings", headers=H("lea")).json()
    assert (s["four_eyes"], s["approval_hours"], client.get("/api/auth/me", headers=H("lea")).json()["four_eyes"]) == (True, 48, True)
    assert dbfix.query("SELECT detail FROM audit WHERE action = 'approval_settings'") == [("Vier-Augen-Prinzip: an, Ablauf: 48 h",)]
    assert {client.put("/api/settings/approvals", json={"four_eyes": True, "hours": h}, headers=H("cleo")).status_code for h in (0, 169)} == {422}


def test_turning_four_eyes_off_keeps_open_requests(world, client):
    four_eyes()
    ask(client, world)
    four_eyes(False)
    [a] = client.get("/api/approvals?status=open", headers=H("ben")).json()
    assert (a["status"], a["switch_name"], a["switch_zone"], "payload" in a, "requester_subject" in a) == ("open", "SW", "EK", False, False)


def test_deleting_the_switch_deletes_its_requests(world, client):
    four_eyes()
    ask(client, world)
    client.delete(f"/api/switches/{world}", headers=H("cleo"))
    assert dbfix.query("SELECT count(*) FROM approvals") == [(0,)]


# ── Beyond the plan's tests: what the interface names and no test above holds ─────────────────────────────────────────────────────
@pytest.mark.parametrize("plan", [{**PLAN, "expert": False}, {"mode": "revert", "of": 1, "expert": True}, {"mode": "prepare", "expert": True},
                                  {"mode": "save", "of": 1}])
def test_with_four_eyes_only_an_expert_port_change_is_requested(world, client, plan):
    """needs_approval comes before the rights of the mode: a prepare by Ändern is 409, not 403; nothing is planned or stored."""
    four_eyes()
    r = client.post("/api/approvals", json={"kind": "port_change", "switch_id": world, "plan": plan}, headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, api_approvals.NO_APPROVAL_NEEDED)
    assert dbfix.query("SELECT count(*) FROM approvals") == [(0,)]


def test_with_four_eyes_taking_back_an_expert_change_stays_freigeben(world, client):
    four_eyes()
    [(cid,)] = dbfix.query("INSERT INTO changes(switch_id, kind, summary, status, expert, sent) VALUES (?, 'ports', 'x', 'ok', 1, 1) "
                           "RETURNING id", (world,))
    r = client.post(f"/api/switches/{world}/plan", json={"mode": "revert", "of": cid}, headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (403, roles.denial("freigeben", "aendern", "Eine Änderung im Expertenmodus zurückzunehmen"))


def test_a_request_and_a_rejection_hold_the_zone(world, client):
    """The switch is in zone "EK"; olga (Ändern) and otto (Freigeben) may change only in "VK"."""
    USERS["olga"] = apifix.user("aendern", "olga", zones=["VK"])
    USERS["otto"] = apifix.user("freigeben", "otto", zones=["VK"])
    four_eyes()
    token = client.post(f"/api/switches/{world}/plan", json=PLAN, headers=H("anna")).json()["token"]
    r = client.post("/api/approvals", json={"kind": "port_change", "switch_id": world, "plan": {**PLAN, "mechanism": "ssh", "token": token}},
                    headers=H("olga"))
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("EK", ["VK"]))
    aid = ask(client, world)[1].json()["id"]
    r = client.post(f"/api/approvals/{aid}/reject", json={}, headers=H("otto"))
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("EK", ["VK"]))
    assert client.get(f"/api/approvals/{aid}", headers=H("otto")).json()["status"] == "open"


def test_a_decided_or_unknown_request_is_refused(world, client):
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    client.post(f"/api/approvals/{aid}/withdraw", headers=H("anna"))
    r = client.post(f"/api/approvals/{aid}/reject", json={"comment": "zu spät"}, headers=H("ben"))
    assert (r.status_code, r.json()["detail"]) == (409, f"Anfrage #{aid} ist zurückgezogen")
    for method, path in (("GET", ""), ("POST", "/withdraw"), ("POST", "/reject")):
        r = client.request(method, f"/api/approvals/{aid + 1}{path}", json={}, headers=H("ben"))
        assert (r.status_code, r.json()["detail"]) == (404, api_approvals.NOT_FOUND)
    assert client.get("/api/approvals?status=open", headers=H("lea")).json() == []
    assert [a["status_label"] for a in client.get("/api/approvals?status=all", headers=H("lea")).json()] == ["zurückgezogen"]


def test_a_request_is_decided_once(world, client):
    """set_status changes an open request only (one UPDATE): of two decisions at once the second changes nothing, whatever the
    routes checked before."""
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    assert asyncio.run(approvals.set_status(aid, approvals.REJECTED, USERS["cleo"], comment="nein")) is True
    assert asyncio.run(approvals.set_status(aid, approvals.WITHDRAWN, USERS["anna"])) is False
    assert dbfix.query("SELECT status, decided_by, comment FROM approvals") == [("rejected", "cleo", "nein")]
