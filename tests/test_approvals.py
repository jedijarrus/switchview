"""The four-eyes principle (Phase 4a, Tasks 6 and 7): a generic approval mechanism (app/approvals.py, the routes in
app/api_approvals.py). Off by default; with it on (settings.four_eyes, PUT /api/settings/approvals, Admin) a change in expert mode
cannot be applied directly: /plan says so ("approval": true), /apply refuses it (409), and whoever has Ändern requests it instead
(POST /api/approvals) with exactly the desired state they sent and the preview they saw. A request is listed, withdrawn by its
requester, rejected by someone else with Freigeben, or expires after its hours (24 by default); every step is audited and announced
to the listeners (approvals.subscribe). Task 7: a second person with Freigeben or Admin reviews a request against a fresh plan
(POST /api/approvals/{aid}/preview) and approves it (…/approve) into the change loop of /apply (api_changes.start_change): never their
own request (same subject or same user name), never the emergency login; the claim of the request and the change row are one write
(changes.create_change's claim), a plan that is no longer the requester's preview sends nothing and makes the request stale, a
transient refusal (busy, unreadable, disabled, another zone) leaves it open.

The app runs in-process through FastAPI's TestClient, signed in per request as the user its X-Test-User header names
(apifix.by_header). The plan is a fake (api_changes._make_plan, fake_plan: it plans what STATE says) and so is the start of a change
(changes.run_change records the id on the call, the task it would become never has to run): no switch, no network. Two tests go
further: the concurrent approvals run through an httpx AsyncClient on the same app (as in tests/test_change_guard.py), and the end
to end test plans with the real _make_plan and runs the real run_change against the fake ProCurve of ssh_env (tests/sshfix.py).
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import HTTPException

import api_approvals
import api_changes
import apifix
import approvals
import cfgparse
import changes
import db
import dbfix
import main
import roles
import sshcli
import sshfix
from loginfix import CSRF

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


# ── Task 7: reviewing and approving ───────────────────────────────────────────────────────────────────────────────────────────────
def approve(client, aid, who, token=None, comment=""):
    token = token or client.get(f"/api/approvals/{aid}", headers=H(who)).json()["preview"]["token"]
    return client.post(f"/api/approvals/{aid}/approve", json={"token": token, "comment": comment}, headers=H(who))


def listen() -> list:
    """Every (event, request id) approvals.emit announces from now on (world resets the listeners)."""
    heard = []

    async def ear(event, a):
        heard.append((event, a["id"]))

    approvals.subscribe(ear)
    return heard


def test_an_approval_starts_the_change_through_start_change(world, client):
    four_eyes()
    p, r = ask(client, world)
    aid = r.json()["id"]
    heard = listen()
    fresh = client.post(f"/api/approvals/{aid}/preview", headers=H("ben")).json()
    assert (fresh["matches"], fresh["commands"]) == (True, p["commands"])
    got = approve(client, aid, "ben", comment="passt").json()
    cid = got["id"]
    assert got == {"id": cid, "approval": aid} and ran == [cid]
    ch = dbfix.query("SELECT username, role, approved_by, expert, status FROM changes WHERE id = ?", (cid,))
    assert ch == [("anna", "aendern", "ben", 1, "queued")]
    a = client.get(f"/api/approvals/{aid}", headers=H("lea")).json()
    assert (a["status"], a["decided_by"], a["change_id"], a["comment"]) == ("approved", "ben", cid, "passt")
    assert dbfix.query("SELECT username, action, role FROM audit WHERE action IN ('approval_approved', 'approval_run') ORDER BY id") == [
        ("ben", "approval_approved", "freigeben"), ("ben", "approval_run", "freigeben")] and heard == [("approved", aid)]


@pytest.mark.parametrize("change", [lambda: setattr(STATE, "shown", ["vlan 30 untagged 6"]),
                                    lambda: setattr(STATE, "blocked", [{"port": "6", "reason": "x"}])],
                         ids=["other-plan", "blocked"])
def test_a_changed_switch_makes_the_request_stale_and_sends_nothing(world, client, change):
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    change()
    heard = listen()
    assert client.post(f"/api/approvals/{aid}/preview", headers=H("ben")).json()["matches"] is False
    r = approve(client, aid, "ben")
    assert r.status_code == 409 and r.json()["detail"].startswith(api_approvals.STALE_REQUEST)
    assert (ran, dbfix.query("SELECT count(*) FROM changes"), client.get(f"/api/approvals/{aid}", headers=H("ben")).json()["status"]) == (
        [], [(0,)], "stale")
    assert dbfix.query("SELECT action FROM audit WHERE action = 'approval_stale'") == [("approval_stale",)] and heard == [("stale", aid)]


def test_a_busy_switch_or_an_unreadable_one_leaves_the_request_open(world, client, monkeypatch):
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    dbfix.query("INSERT INTO changes(switch_id, kind, summary, status) VALUES (?, 'ports', 'x', 'running')", (world,))
    assert approve(client, aid, "ben").json()["detail"] == changes.BUSY
    dbfix.query("DELETE FROM changes")
    monkeypatch.setattr(api_changes, "_make_plan", dbfix.raising_async_fn(HTTPException(502, "nicht lesbar")))
    assert approve(client, aid, "ben").status_code == 502 and client.get(f"/api/approvals/{aid}", headers=H("ben")).json()["status"] == "open"


@pytest.mark.parametrize("asker, approver", [("ben", "ben"), ("cleo", "cleo")])
def test_nobody_approves_their_own_request(world, client, asker, approver):
    four_eyes()
    aid = ask(client, world, asker)[1].json()["id"]
    assert approve(client, aid, approver).json()["detail"] == api_approvals.SELF and ran == []


def test_the_same_user_name_counts_as_the_same_person(world, client):                        # Review Focus 3
    four_eyes()
    aid = ask(client, world, "ben")[1].json()["id"]
    USERS["ben-alt"] = apifix.user("freigeben", "BEN", subject="entra:ben@example.org")
    assert approve(client, aid, "ben-alt").json()["detail"] == api_approvals.SELF


def test_the_same_subject_counts_as_the_same_person_under_another_name(world, client):        # identity, not the session or the name
    four_eyes()
    aid = ask(client, world, "ben")[1].json()["id"]
    USERS["ben-neu"] = apifix.user("freigeben", "benjamin", subject="entra:ben")
    assert approve(client, aid, "ben-neu").json()["detail"] == api_approvals.SELF


@pytest.mark.parametrize("decide", ["UPDATE approvals SET status = 'withdrawn'", "UPDATE approvals SET expires_at = '2000-01-01T00:00:00+00:00'"],
                         ids=["withdrawn", "expired"])
def test_a_request_decided_while_it_is_planned_starts_nothing(world, client, monkeypatch, decide):       # Review Focus 1
    """The request passes the approve route's own checks, then is withdrawn (or runs out) while the change is planned: the claim in
    create_change's transaction finds it no longer open, the change row is rolled back, nothing runs."""
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    token = client.get(f"/api/approvals/{aid}", headers=H("ben")).json()["preview"]["token"]

    async def plan_then_decide(row, body):
        dbfix.query(decide)
        return await fake_plan(row, body)

    monkeypatch.setattr(api_changes, "_make_plan", plan_then_decide)
    r = approve(client, aid, "ben", token=token)
    assert (r.status_code, r.json()["detail"], ran, dbfix.query("SELECT count(*) FROM changes")) == (
        409, api_approvals.DECIDED.format(aid=aid), [], [(0,)])


def test_the_emergency_login_approves_nothing(world, client):
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    assert approve(client, aid, "notfall").json()["detail"] == api_approvals.EMERGENCY


def test_the_token_must_be_the_requests(world, client):
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    assert approve(client, aid, "ben", token="0" * 16).json()["detail"] == api_approvals.REVIEW_AGAIN


def test_approving_after_the_switch_moved_sends_nothing(world, client):                         # Review Focus 4
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    USERS["ben-ek"] = apifix.user("freigeben", "ben2", zones=["EK"])
    dbfix.query("UPDATE switches SET enabled = 0")
    assert approve(client, aid, "ben").json()["detail"] == api_changes.DISABLED
    dbfix.query("UPDATE switches SET enabled = 1, zone = 'VK'")
    assert approve(client, aid, "ben-ek").json()["detail"] == roles.zone_denial("VK", ["EK"])
    assert client.get(f"/api/approvals/{aid}", headers=H("ben")).json()["status"] == "open"
    client.delete(f"/api/switches/{world}", headers=H("cleo"))
    assert approve(client, aid, "ben", token="x").status_code == 404
    assert ran == []


def test_an_expired_or_withdrawn_request_is_not_approved(world, client):
    four_eyes()
    a1 = ask(client, world)[1].json()["id"]
    a2 = ask(client, world)[1].json()["id"]
    dbfix.query("UPDATE approvals SET expires_at = ? WHERE id = ?", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), a1))
    client.post(f"/api/approvals/{a2}/withdraw", headers=H("anna"))
    assert [approve(client, a, "ben", token="x").json()["detail"] for a in (a1, a2)] == [f"Anfrage #{a1} ist abgelaufen",
                                                                                          f"Anfrage #{a2} ist zurückgezogen"]


async def test_two_approvals_at_once_start_one_change(world, monkeypatch):                    # Review Focus 1
    """Two approvers at once: both plan (the plan waits for both to have started), one claims the request in create_change's
    transaction, the other gets 409 and leaves no change row (create_change's busy check or the claim refuses it)."""
    await db.set_setting("four_eyes", "1")
    with apifix.signed_in(monkeypatch):
        apifix.by_header(BASE_USERS)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test", headers=CSRF) as c:
            p = (await c.post(f"/api/switches/{world}/plan", json=PLAN, headers=H("anna"))).json()
            r = await c.post("/api/approvals", json={"kind": "port_change", "switch_id": world,
                                                     "plan": {**PLAN, "mechanism": p["mechanism"], "token": p["token"]}}, headers=H("anna"))
            aid = r.json()["id"]
            token = (await c.get(f"/api/approvals/{aid}", headers=H("anna"))).json()["preview"]["token"]
            calls, both = [], asyncio.Event()

            async def gated_plan(row, body):
                calls.append(body)
                if len(calls) == 2:
                    both.set()
                await asyncio.wait_for(both.wait(), 5)     # both approvals are past the early busy check and planning
                return await fake_plan(row, body)

            monkeypatch.setattr(api_changes, "_make_plan", gated_plan)
            responses = await asyncio.gather(*(c.post(f"/api/approvals/{aid}/approve", json={"token": token, "comment": ""}, headers=H(who))
                                               for who in ("ben", "cleo")))
    assert sorted(r.status_code for r in responses) == [200, 409] and len(calls) == 2
    assert next(r for r in responses if r.status_code == 409).json()["detail"] in (changes.BUSY, api_approvals.DECIDED.format(aid=aid))
    assert dbfix.query("SELECT count(*) FROM changes") == [(1,)] and len(ran) == 1
    [winner] = [r.json() for r in responses if r.status_code == 200]
    assert dbfix.query("SELECT status, change_id FROM approvals") == [("approved", winner["id"])]


async def test_a_failing_claim_leaves_no_change(world):
    async def claim(conn, cid):
        raise approvals.AlreadyDecided()

    with pytest.raises(approvals.AlreadyDecided):
        await changes.create_change(world, "anna", "ports", "x", {}, {"shown": ["a"], "desired": {}, "before": {}, "mechanism": "ssh"},
                                    role="aendern", claim=claim)
    assert dbfix.query("SELECT count(*) FROM changes") == [(0,)]


def test_an_approved_change_keeps_the_check_in_the_lock(ssh_env, monkeypatch):
    """End to end on the ProCurve of ssh_env (the real _make_plan over its SSH way, the real create_change and run_change), four eyes on. First anna
    asks for the expert name change "Drucker-EK" on port 3, ben approves, the real run_change runs it: the lines go out (the fake
    switch does not take them, so the read-back ends it "unclear", never "aborted"). Then
    anna asks for "Drucker-VK", ben approves, and before the change runs port 3 got that name at the switch: run_change reads, plans
    and compares in the lock as for every change and ends aborted, nothing more sent."""
    real, started = changes.run_change, []

    def record(cid):
        started.append(cid)             # recorded on the call, as world's run_change; the test runs the real one itself
        return asyncio.sleep(0)

    async def fresh_cfg(sid, max_age_s=changes.CFG_MAX_AGE_S):
        return cfgparse.parse_config(ssh_env.running)       # the preview's read: the real one opens a netmiko session (sshcli._open)

    async def inventory(sid):
        return {"ports": {"3": {"n": "3", "tr": "", "l": [], "o": False}}, "uplinks": {"3"}}    # port 3 an uplink: expert mode

    def trap(*args, **kwargs):
        raise AssertionError("no real SSH session in this test")

    monkeypatch.setattr(changes, "run_change", record)
    monkeypatch.setattr(changes, "fresh_cfg", fresh_cfg)
    monkeypatch.setattr(changes, "inventory", inventory)
    monkeypatch.setattr(sshcli, "ConnectHandler", trap)
    monkeypatch.setattr(approvals, "_listeners", [])
    asyncio.run(db.set_setting("four_eyes", "1"))

    def approved(client, name) -> int:
        plan = {"ports": ["3"], "change": {"name": name}, "expert": True}
        p, r = ask(client, ssh_env.sid, "anna", plan)
        assert p["approval"] is True and p["mechanism"] == "ssh" and p["commands"] and r.status_code == 200, (p, r.json())
        got = approve(client, r.json()["id"], "ben")
        assert got.status_code == 200, got.json()
        return got.json()["id"]

    with apifix.signed_in(monkeypatch) as client:
        apifix.by_header(BASE_USERS)
        cid = approved(client, "Drucker-EK")
        assert started == [cid]
        asyncio.run(real(cid))
        first = ssh_env.change(cid)
        assert (first["status"], first["username"], first["approved_by"]) == ("unclear", "anna", "ben")
        assert ssh_env.sent == [json.loads(first["commands"])]
        sent = list(ssh_env.sent)
        cid2 = approved(client, "Drucker-VK")
    ssh_env.running = sshfix.RUNNING + 'interface 3\n   name "Drucker-VK"\n   exit\n'
    asyncio.run(real(cid2))
    second = ssh_env.change(cid2)
    assert (second["status"], second["error"], ssh_env.sent) == ("aborted", "Der Switch hat sich seit der Vorschau geändert. Bitte Vorschau neu laden.",
                                                                  sent)


# ── Beyond the plan's tests of Task 7: what the interface names and no test above holds ───────────────────────────────────────────
def test_the_review_holds_the_zone_and_needs_an_open_request(world, client):
    """The fresh preview only at a switch of the reviewer's zones (the zone of now), only of an open request, 404 for none."""
    four_eyes()
    USERS["otto"] = apifix.user("freigeben", "otto", zones=["VK"])
    aid = ask(client, world)[1].json()["id"]
    r = client.post(f"/api/approvals/{aid}/preview", headers=H("otto"))
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("EK", ["VK"]))
    client.post(f"/api/approvals/{aid}/withdraw", headers=H("anna"))
    r = client.post(f"/api/approvals/{aid}/preview", headers=H("ben"))
    assert (r.status_code, r.json()["detail"]) == (409, f"Anfrage #{aid} ist zurückgezogen")
    r = client.post(f"/api/approvals/{aid + 1}/preview", headers=H("ben"))
    assert (r.status_code, r.json()["detail"]) == (404, api_approvals.NOT_FOUND)


def test_review_and_approval_plan_exactly_the_request_on_its_write_way(world, client, monkeypatch):
    """The reviewer's preview and the approval plan the payload as the requester sent it, on the write way of the requester's preview
    (never chosen anew); the approval with the preview's token, the review without one."""
    four_eyes()
    p, r = ask(client, world)
    aid = r.json()["id"]
    bodies = []

    async def recording_plan(row, body):
        bodies.append(body)
        return await fake_plan(row, body)

    monkeypatch.setattr(api_changes, "_make_plan", recording_plan)
    client.post(f"/api/approvals/{aid}/preview", headers=H("ben"))
    assert approve(client, aid, "ben").status_code == 200
    assert bodies == [api_changes.PlanIn(**PLAN, mechanism="ssh"), api_changes.PlanIn(**PLAN, mechanism="ssh", token=p["token"])]


def test_the_audit_names_the_request_its_change_and_the_trimmed_comment(world, client):
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    cid = approve(client, aid, "ben", comment="  passt  ").json()["id"]
    assert dbfix.query("SELECT target, detail FROM audit WHERE action IN ('approval_approved', 'approval_run') ORDER BY id") == [
        (str(world), f"#{aid} Port 6: VLAN 20 → Änderung #{cid}: passt"), (str(world), f"#{aid} → Änderung #{cid}")]
    bid = ask(client, world)[1].json()["id"]
    dbfix.query("UPDATE changes SET status = 'ok'")
    cid2 = approve(client, bid, "cleo", comment="   ").json()["id"]
    assert dbfix.query("SELECT detail FROM audit WHERE action = 'approval_approved' ORDER BY id DESC LIMIT 1") == [
        (f"#{bid} Port 6: VLAN 20 → Änderung #{cid2}",)]
    assert dbfix.query("SELECT id, decided_by, comment FROM approvals ORDER BY id") == [(aid, "ben", "passt"), (bid, "cleo", None)]


def test_a_stale_request_keeps_who_found_it_and_why(world, client):
    four_eyes()
    aid = ask(client, world)[1].json()["id"]
    STATE.shown = ["vlan 30 untagged 6"]
    r = approve(client, aid, "ben")
    assert r.json()["detail"] == f"{api_approvals.STALE_REQUEST} ({api_changes.STALE})"
    assert dbfix.query("SELECT status, decided_by, reason, change_id FROM approvals") == [("stale", "ben", api_changes.STALE, None)]
    assert dbfix.query("SELECT username, target, detail, role FROM audit WHERE action = 'approval_stale'") == [
        ("ben", str(world), f"#{aid} Port 6: VLAN 20: {api_changes.STALE}", "freigeben")]
