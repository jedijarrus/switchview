"""Phase 4c, Task 8: four eyes for bulk changes (the kind bulk_change of app/approvals.py, registered by app/api_bulk.py; the routes
are those of app/api_approvals.py).

With the four-eyes principle on, every bulk change is requested instead of started (POST /api/approvals with
{"kind": "bulk_change", "bulk": <the body of POST /api/bulk>}): checked like the start (the limits, the rights at every switch, every
switch against its preview token) and stored with the preview its requester saw. Such a request has no switch of its own; its zones
are those of all its switches, and whoever rejects, reviews or approves it needs every one of them. The reviewer's preview plans
every switch anew and says per switch whether it still matches; the approval checks every switch against its preview token, makes
the request stale and starts nothing when one changed, and else creates the bulk change under the requester's name in the write that
claims the request (approvals.bulk_id) and schedules its run. Nobody approves their own request, the emergency login none.

The app runs in-process through FastAPI's TestClient, signed in per request as the user its X-Test-User header names
(apifix.by_header). The world (tests/bulkfix.py) has switches A and B in zone EK and C in zone VK, a fake planner and a recorded
bulk.schedule (world.scheduled). No switch, no network.
"""
import asyncio

import httpx
import pytest
from bulkfix import fake_plan, items_of, make_world
from fastapi import HTTPException
from loginfix import CSRF
from test_alerts import configure
from test_approvals import PLAN, H, approve, four_eyes

import alerts
import api_approvals
import api_bulk
import api_changes
import apifix
import approvals
import bulk
import crypto
import db
import dbfix
import main
import roles

USERS = {"anna": apifix.user("aendern", "anna"), "eva": apifix.user("aendern", "eva", zones=["EK"]), "ben": apifix.user("freigeben", "ben"),
         "bert": apifix.user("freigeben", "bert", zones=["EK"]), "cleo": apifix.user("admin", "cleo"),
         "notfall": apifix.user("admin", "admin", method="local")}


@pytest.fixture
def world(tmp_path, monkeypatch):
    """The bulk world with A and B in EK and C in VK, and no listener of the approvals."""
    monkeypatch.setattr(approvals, "_listeners", [])
    return make_world(tmp_path, monkeypatch, zones=("EK", "EK", "VK"))


@pytest.fixture
def client(world, monkeypatch):
    """A TestClient signed in per request as USERS[<X-Test-User>]."""
    with apifix.signed_in(monkeypatch) as c:
        apifix.by_header(USERS)
        yield c


def plan_body(world) -> dict:
    return {"targets": [{"switch_id": s, "ports": ["1"]} for s in (world.a, world.b, world.c)], "change": {"untagged": "30"}}


def request(client, world, who="anna", planner=None, **over):
    preview = client.post("/api/bulk/plan", json=plan_body(world), headers=H(planner or who)).json()
    return client.post("/api/approvals", json={"kind": "bulk_change", "bulk": items_of(preview, **over)}, headers=H(who))


def test_the_predicate_names_every_bulk_with_four_eyes():
    assert approvals.needs_approval(approvals.BULK_CHANGE, {}, True) is True and approvals.needs_approval(approvals.BULK_CHANGE, {}, False) is False


def test_the_kind_is_registered_with_what_it_starts():
    kind = approvals.KINDS[approvals.BULK_CHANGE]
    assert (kind.label, kind.started, approvals.KINDS[approvals.PORT_CHANGE].started) == ("Sammeländerung", "Sammeländerung", "Änderung")


@pytest.mark.parametrize("body", [{"kind": "port_change", "plan": PLAN}, {"kind": "port_change", "switch_id": 1}, {"kind": "bulk_change"},
                                  {"kind": "bulk_change", "switch_id": 1, "plan": PLAN}])
def test_a_request_without_its_parts_is_refused(world, client, body):
    four_eyes()
    r = client.post("/api/approvals", json=body, headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (422, api_approvals.MISSING) and dbfix.query("SELECT count(*) FROM approvals") == [(0,)]


def test_a_bulk_request_has_the_limits_of_a_bulk(world, client):                         # bulk.validate, as POST /api/bulk
    four_eyes()
    item = {"switch_id": world.a, "ports": ["1"], "token": "t", "mechanism": "ssh"}
    r = client.post("/api/approvals", json={"kind": "bulk_change", "bulk": {"items": [item, item], "change": {"untagged": "30"}}}, headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (422, bulk.TWICE.format(sid=world.a)) and dbfix.query("SELECT count(*) FROM approvals") == [(0,)]


def test_without_four_eyes_a_bulk_needs_no_approval(world, client):
    r = request(client, world)
    assert (r.status_code, r.json()["detail"]) == (409, api_approvals.NO_APPROVAL_NEEDED) and dbfix.query("SELECT count(*) FROM approvals") == [(0,)]


def test_the_start_of_a_bulk_asks_the_one_predicate(world, client, monkeypatch):
    """POST /api/bulk refuses with four eyes on because approvals.needs_approval says so, not by the setting itself."""
    four_eyes()
    preview = client.post("/api/bulk/plan", json=plan_body(world), headers=H("anna")).json()
    r = client.post("/api/bulk", json=items_of(preview), headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, bulk.APPROVAL_NEEDED)
    asked = []
    monkeypatch.setattr(approvals, "needs_approval", lambda kind, request, on: asked.append((kind, request, on)) or False)
    assert client.post("/api/bulk", json=items_of(preview), headers=H("anna")).status_code == 200
    assert asked == [(approvals.BULK_CHANGE, {}, True)]


def test_with_four_eyes_a_bulk_is_requested_with_its_preview(world, client):
    four_eyes()
    aid = request(client, world).json()["id"]
    a = client.get(f"/api/approvals/{aid}", headers=H("ben")).json()
    assert (a["kind"], a["kind_label"], a["switch_id"], a["status"], a["summary"]) == ("bulk_change", "Sammeländerung", None, "open",
                                                                                     "VLAN 30 · 3 Ports an 3 Switches")
    assert [s["switch"] for s in a["preview"]["sections"]] == ["A", "B", "C"] and a["preview"]["sections"][0]["commands"] == ["vlan 30 untagged 1"]
    assert a["preview"]["token"] == bulk.token_of([(s["switch_id"], s["token"]) for s in a["preview"]["sections"]])
    assert dbfix.query("SELECT username, action, target FROM audit WHERE action = 'approval_requested'") == [("anna", "approval_requested", "")]


def test_a_bulk_request_stores_what_was_sent_and_what_was_seen(world, client):
    """The payload is the body of POST /api/bulk as sent (BulkIn(**payload) restores it), the preview a section per ready switch with
    exactly these keys and the skipped switches with their name of now and their reason; the list carries bulk_id."""
    four_eyes()
    world.plans["C"] = {"blocked": [{"port": "1", "reason": "Uplink"}]}
    aid = request(client, world, on_error="continue").json()["id"]
    a = client.get(f"/api/approvals/{aid}", headers=H("ben")).json()
    assert api_bulk.BulkIn(**a["payload"]).model_dump(mode="json") == a["payload"]
    assert ([i["switch_id"] for i in a["payload"]["items"]], a["payload"]["on_error"], a["payload"]["confirm_minutes"]) == (
        [world.a, world.b], "continue", None)
    assert a["preview"]["summary"] == a["summary"] == "VLAN 30 · 2 Ports an 2 Switches"
    assert a["preview"]["sections"][1] == {"switch_id": world.b, "switch": "B", "ports": ["1"], "mechanism": "ssh",
                                           "commands": ["vlan 30 untagged 1"], "warnings": [],
                                           "token": a["payload"]["items"][1]["token"]}
    assert a["preview"]["skipped"] == [{"switch_id": world.c, "switch": "C", "reason": "Port 1: Uplink"}]
    [row] = client.get("/api/approvals", headers=H("ben")).json()
    assert (row["bulk_id"], row["change_id"], row["switch_name"], row["switch_zone"]) == (None, None, None, None)


def test_a_bulk_request_whose_preview_is_outdated_is_refused(world, client):
    four_eyes()
    preview = client.post("/api/bulk/plan", json=plan_body(world), headers=H("anna")).json()
    world.plans["B"] = {"shown": ["vlan 40 untagged 1"]}
    r = client.post("/api/approvals", json={"kind": "bulk_change", "bulk": items_of(preview)}, headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, bulk.OUTDATED.format(list=f"B: {api_changes.STALE}"))
    assert dbfix.query("SELECT count(*) FROM approvals") == [(0,)]


def test_a_bulk_request_checks_the_rights_of_each_switch(world, client):
    four_eyes()
    r = request(client, world, "eva", planner="anna")                                  # a body with C, which eva's own preview denies
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("VK", ["EK"])) and dbfix.query("SELECT count(*) FROM approvals") == [(0,)]


def test_the_zones_of_a_bulk_are_those_of_its_switches_now(world):
    payload = {"items": [{"switch_id": s} for s in (world.c, world.a, world.b, world.c + 100)]}
    assert asyncio.run(bulk.zones_of(payload)) == ["EK", "VK"]
    dbfix.query("UPDATE switches SET zone = '' WHERE id = ?", (world.b,))
    dbfix.query("DELETE FROM switches WHERE id = ?", (world.c,))
    assert asyncio.run(bulk.zones_of(payload)) == ["", "EK"] and asyncio.run(bulk.zones_of({"items": []})) == []


@pytest.mark.parametrize("route", ["reject", "preview", "approve"])
def test_a_reviewer_needs_every_zone_of_the_bulk(world, client, route):
    four_eyes()
    aid = request(client, world).json()["id"]
    body = {"token": "x"} if route == "approve" else {}
    r = client.post(f"/api/approvals/{aid}/{route}", json=body, headers=H("bert"))
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("VK", ["EK"]))
    assert dbfix.query("SELECT status FROM approvals") == [("open",)] and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]


def test_a_reviewer_with_every_zone_of_the_bulk_decides_it(world, client):
    """A bulk over EK only: bert (Freigeben in EK) reviews and approves it; the zones are those of now, so once B moves to VK a second
    request of the same switches is no longer his."""
    four_eyes()
    preview = client.post("/api/bulk/plan", json={"targets": [{"switch_id": s, "ports": ["1"]} for s in (world.a, world.b)],
                                                  "change": {"untagged": "30"}}, headers=H("anna")).json()
    body = {"kind": "bulk_change", "bulk": items_of(preview)}
    first, second = (client.post("/api/approvals", json=body, headers=H("anna")).json()["id"] for _ in range(2))
    assert client.post(f"/api/approvals/{first}/preview", headers=H("bert")).json()["matches"] is True
    assert approve(client, first, "bert").status_code == 200
    dbfix.query("UPDATE switches SET zone = 'VK' WHERE id = ?", (world.b,))
    r = client.post(f"/api/approvals/{second}/reject", json={}, headers=H("bert"))
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("VK", ["EK"]))
    assert client.post(f"/api/approvals/{second}/reject", json={"comment": "doppelt"}, headers=H("ben")).status_code == 200
    assert dbfix.query("SELECT status FROM approvals ORDER BY id") == [("approved",), ("rejected",)]


def test_the_reviewers_preview_replans_every_switch(world, client):
    four_eyes()
    aid = request(client, world).json()["id"]
    p = client.post(f"/api/approvals/{aid}/preview", headers=H("ben")).json()
    assert p["matches"] is True and [s["matches"] for s in p["sections"]] == [True] * 3
    world.plans["B"] = {"shown": ["vlan 40 untagged 1"]}
    p = client.post(f"/api/approvals/{aid}/preview", headers=H("ben")).json()
    assert p["matches"] is False and [s["matches"] for s in p["sections"]] == [True, False, True]


def test_the_reviewers_preview_names_what_runs_now(world, client):
    """The fresh preview: kind and summary of the request, per switch its name, ports, commands of now, write way and token; with
    every switch matching its token is the request's (the one …/approve takes). A switch that is blocked now, gone or on another
    write way does not match and says why."""
    four_eyes()
    aid = request(client, world).json()["id"]
    a = client.get(f"/api/approvals/{aid}", headers=H("ben")).json()
    p = client.post(f"/api/approvals/{aid}/preview", headers=H("ben")).json()
    assert (p["kind"], p["summary"], p["token"]) == ("bulk_change", a["summary"], a["preview"]["token"])
    assert p["sections"][0] == {"switch_id": world.a, "switch": "A", "ports": ["1"], "status": "ready", "reason": "", "mechanism": "ssh",
                                "commands": ["vlan 30 untagged 1"], "warnings": [], "token": a["preview"]["sections"][0]["token"],
                                "matches": True}
    world.plans["A"] = {"blocked": [{"port": "1", "reason": "Uplink"}]}
    world.plans["B"] = {"mechanism": "snmp"}
    dbfix.query("DELETE FROM switches WHERE id = ?", (world.c,))
    p = client.post(f"/api/approvals/{aid}/preview", headers=H("ben")).json()
    assert p["matches"] is False and p["token"] != a["preview"]["token"]
    assert [(s["switch"], s["status"], s["reason"], s["matches"]) for s in p["sections"]] == [
        ("A", "blocked", "Port 1: Uplink", False), ("B", "ready", api_bulk.OTHER_WAY, False),
        (f"#{world.c}", "error", "Switch nicht gefunden", False)]


def test_approving_starts_the_bulk_once_under_the_requesters_name(world, client):
    four_eyes()
    aid = request(client, world).json()["id"]
    r = approve(client, aid, "ben").json()
    [(bid, user, by)] = dbfix.query("SELECT id, username, approved_by FROM bulks")
    assert r == {"id": bid, "approval": aid, "kind": "bulk_change"} and (user, by) == ("anna", "ben") and world.scheduled == [bid]
    assert dbfix.query("SELECT status, bulk_id, change_id FROM approvals") == [("approved", bid, None)]
    [(detail,)] = dbfix.query("SELECT detail FROM audit WHERE action = 'approval_approved'")
    assert detail.endswith(f"→ Sammeländerung #{bid}")


def test_the_approved_bulk_is_the_requested_one(world, client):
    """The bulk an approval starts: the requester's role, no API token, the request's on_error, its switches waiting with the ports,
    tokens and write ways of the request and the skipped one with its reason; the audit names the request, the bulk and the trimmed
    comment, without a target; a second approval is refused and starts nothing."""
    four_eyes()
    world.plans["C"] = {"blocked": [{"port": "1", "reason": "Uplink"}]}
    aid = request(client, world, on_error="continue").json()["id"]
    a = client.get(f"/api/approvals/{aid}", headers=H("ben")).json()
    bid = approve(client, aid, "ben", comment="  passt  ").json()["id"]
    assert dbfix.query("SELECT username, role, api_token, approved_by, summary, on_error, status FROM bulks") == [
        ("anna", "aendern", None, "ben", a["summary"], "continue", "queued")]
    assert dbfix.query("SELECT switch_name, ports, mechanism, token, status, detail FROM bulk_items WHERE bulk_id = ? ORDER BY pos", (bid,)) == [
        ("A", '["1"]', "ssh", a["payload"]["items"][0]["token"], "waiting", ""),
        ("B", '["1"]', "ssh", a["payload"]["items"][1]["token"], "waiting", ""), ("C", "[]", None, None, "skipped", "Port 1: Uplink")]
    assert dbfix.query("SELECT username, action, target, detail, role FROM audit WHERE action IN ('approval_approved', 'approval_run') ORDER BY id") == [
        ("ben", "approval_approved", "", f"#{aid} {a['summary']} → Sammeländerung #{bid}: passt", "freigeben"),
        ("ben", "approval_run", "", f"#{aid} → Sammeländerung #{bid}", "freigeben")]
    assert dbfix.query("SELECT decided_by, comment FROM approvals") == [("ben", "passt")]
    r = approve(client, aid, "cleo", token=a["preview"]["token"])
    assert (r.status_code, r.json()["detail"]) == (409, f"Anfrage #{aid} ist freigegeben") and world.scheduled == [bid]


def test_the_token_must_be_the_bulk_requests(world, client):
    four_eyes()
    aid = request(client, world).json()["id"]
    r = approve(client, aid, "ben", token="0" * 16)
    assert (r.status_code, r.json()["detail"]) == (409, api_approvals.REVIEW_AGAIN) and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]


def test_a_changed_switch_makes_a_bulk_request_stale_and_starts_nothing(world, client):
    four_eyes()
    aid = request(client, world).json()["id"]
    world.plans["B"] = {"shown": ["vlan 40 untagged 1"]}
    r = approve(client, aid, "ben")
    reason = bulk.OUTDATED.format(list=f"B: {api_changes.STALE}")
    assert (r.status_code, r.json()["detail"]) == (409, f"{api_approvals.STALE_REQUEST} ({reason})")
    assert dbfix.query("SELECT status, reason FROM approvals") == [("stale", reason)] and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]
    assert world.scheduled == [] and dbfix.query("SELECT username, target, detail FROM audit WHERE action = 'approval_stale'") == [
        ("ben", "", f"#{aid} VLAN 30 · 3 Ports an 3 Switches: {reason}")]


SECRET = "geheim-4711"
UNREADABLE = HTTPException(502, f"Konfiguration des Switches per SNMP nicht lesbar: {SECRET} abgelehnt")


def test_a_stale_bulk_request_keeps_no_secret_of_a_switch(world, client):
    """A switch that cannot be read at the approval refuses with an SSH or SNMP error text (502), which may name a secret of the
    switch: the reason is masked with them (confirm._mask_of) where it is stored (approvals.reason, read by every role), audited,
    answered and announced (the alert's text)."""
    four_eyes()
    db.execute_sync("UPDATE switches SET snmp_community = ? WHERE id = ?", (crypto.encrypt(SECRET), world.a))
    aid = request(client, world).json()["id"]
    heard = []

    async def ear(event, a):
        heard.append((event, a["reason"]))

    approvals.subscribe(ear)
    world.plans["A"] = UNREADABLE
    r = approve(client, aid, "ben")
    reason = bulk.OUTDATED.format(list="A: Konfiguration des Switches per SNMP nicht lesbar: *** abgelehnt")
    assert (r.status_code, r.json()["detail"]) == (409, f"{api_approvals.STALE_REQUEST} ({reason})")
    assert dbfix.query("SELECT status, reason FROM approvals") == [("stale", reason)] and heard == [("stale", reason)]
    assert dbfix.query("SELECT detail FROM audit WHERE action = 'approval_stale'") == [(f"#{aid} VLAN 30 · 3 Ports an 3 Switches: {reason}",)]
    assert SECRET not in client.get("/api/approvals", headers=H("eva")).text


def test_a_refused_bulk_names_no_secret_of_a_switch(world, client):
    """The same mask in the 409 of a request and of a start (bulk.precheck is the check of both), each switch with its own secrets."""
    preview = client.post("/api/bulk/plan", json=plan_body(world), headers=H("anna")).json()
    db.execute_sync("UPDATE switches SET snmp_community = ? WHERE id = ?", (crypto.encrypt(SECRET), world.b))
    world.plans["A"] = world.plans["B"] = UNREADABLE
    masked = "Konfiguration des Switches per SNMP nicht lesbar: *** abgelehnt"
    detail = bulk.OUTDATED.format(list=f"A: {UNREADABLE.detail}; B: {masked}")              # the secret is B's, not A's
    r = client.post("/api/bulk", json=items_of(preview), headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, detail)
    four_eyes()
    r = client.post("/api/approvals", json={"kind": "bulk_change", "bulk": items_of(preview)}, headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, detail)


def test_the_reviewers_preview_names_no_secret_of_a_switch(world, client):
    four_eyes()
    db.execute_sync("UPDATE switches SET snmp_community = ? WHERE id = ?", (crypto.encrypt(SECRET), world.a))
    aid = request(client, world).json()["id"]
    world.plans["A"] = UNREADABLE
    p = client.post(f"/api/approvals/{aid}/preview", headers=H("ben")).json()
    assert (p["sections"][0]["status"], p["sections"][0]["reason"], p["matches"]) == (
        "error", "Konfiguration des Switches per SNMP nicht lesbar: *** abgelehnt", False)


def test_the_reviewers_preview_plans_at_most_five_switches_at_once(world, client, monkeypatch):
    four_eyes()
    for i in range(12):
        world.extra(f"S{i}")
    preview = client.post("/api/bulk/plan", json={"targets": [{"switch_id": s, "ports": ["1"]} for s in world.extra_ids],
                                                  "change": {"untagged": "30"}}, headers=H("anna")).json()
    aid = client.post("/api/approvals", json={"kind": "bulk_change", "bulk": items_of(preview)}, headers=H("anna")).json()["id"]
    busy, peak = [0], [0]

    async def slow(row, body):
        busy[0] += 1
        peak[0] = max(peak[0], busy[0])
        await asyncio.sleep(0.05)
        busy[0] -= 1
        return await fake_plan(row, body)

    monkeypatch.setattr(api_changes, "_make_plan", slow)
    p = client.post(f"/api/approvals/{aid}/preview", headers=H("ben")).json()
    assert p["matches"] is True and len(p["sections"]) == 12 and peak[0] == bulk.PARALLEL


def test_the_alerts_tell_a_bulk_request_without_a_switch(world, client):
    """The real listener (alerts.on_approval; the world has none) with a request that has no switch of its own: no " an <switch>" in
    the text, no fact "Switch", no switch in the row."""
    four_eyes()
    asyncio.run(configure(mail=True, events=["approval"]))
    approvals.subscribe(alerts.on_approval)
    aid = request(client, world).json()["id"]
    assert approve(client, aid, "ben").status_code == 200
    assert dbfix.query("SELECT event, title, text, switch_id, switch_name, facts FROM alert_outbox ORDER BY id") == [
        ("approval", f"Freigabe #{aid} angefordert", "VLAN 30 · 3 Ports an 3 Switches, angefordert von Anna", None, "", '{"_view": "approvals"}'),
        ("approval", f"Freigabe #{aid} freigegeben", "VLAN 30 · 3 Ports an 3 Switches, angefordert von Anna, entschieden von ben", None, "",
         '{"_view": "approvals"}')]


@pytest.mark.parametrize("asker, who, detail", [("ben", "ben", api_approvals.SELF), ("cleo", "cleo", api_approvals.SELF),
                                                ("anna", "notfall", api_approvals.EMERGENCY)])
def test_nobody_approves_their_own_bulk_and_the_emergency_login_none(world, client, asker, who, detail):
    four_eyes()
    aid = request(client, world, asker).json()["id"]
    r = approve(client, aid, who)
    assert (r.status_code, r.json()["detail"]) == (403, detail) and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]


def test_a_token_never_approves_a_bulk(world, client, monkeypatch):
    four_eyes()
    aid = request(client, world).json()["id"]
    monkeypatch.setitem(USERS, "bot", apifix.user("freigeben", "bot") | {"api_token": {"id": 1, "name": "ci"}})
    r = approve(client, aid, "bot")
    assert (r.status_code, r.json()["detail"]) == (403, api_approvals.APPROVE_VIA_TOKEN) and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]


def test_the_requester_withdraws_a_bulk_request(world, client):
    four_eyes()
    aid = request(client, world, "eva", planner="eva").json()["id"]                      # eva's preview skips C, the body has A and B
    assert client.post(f"/api/approvals/{aid}/withdraw", headers=H("eva")).status_code == 200
    assert dbfix.query("SELECT status FROM approvals") == [("withdrawn",)]
    assert dbfix.query("SELECT username, target FROM audit WHERE action = 'approval_withdrawn'") == [("eva", "")]


def test_a_claim_names_the_bulk_or_the_change_and_no_other_column(world, client):
    four_eyes()
    aid = request(client, world).json()["id"]

    async def claim(column):
        async with db.db() as conn:
            await approvals.claim(conn, aid, USERS["ben"], "", 7, column=column)
            await conn.commit()

    with pytest.raises(ValueError):
        asyncio.run(claim("status"))
    assert dbfix.query("SELECT status, bulk_id, change_id FROM approvals") == [("open", None, None)]
    asyncio.run(claim("bulk_id"))
    assert dbfix.query("SELECT status, bulk_id, change_id FROM approvals") == [("approved", 7, None)]


async def test_two_approvals_at_once_start_one_bulk(world, monkeypatch):
    """As the concurrent approvals of tests/test_approvals.py (httpx.AsyncClient on the same app): both approvers plan every switch
    (the plan waits until both have started all three), one starts the bulk, the other is 409 DECIDED, and there is exactly one bulks
    row."""
    await db.set_setting("four_eyes", "1")
    with apifix.signed_in(monkeypatch):
        apifix.by_header(USERS)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test", headers=CSRF) as c:
            preview = (await c.post("/api/bulk/plan", json=plan_body(world), headers=H("anna"))).json()
            aid = (await c.post("/api/approvals", json={"kind": "bulk_change", "bulk": items_of(preview)}, headers=H("anna"))).json()["id"]
            token = (await c.get(f"/api/approvals/{aid}", headers=H("anna"))).json()["preview"]["token"]
            calls, both = [], asyncio.Event()

            async def gated_plan(row, body):
                calls.append(row["name"])
                if len(calls) == 6:
                    both.set()
                await asyncio.wait_for(both.wait(), 5)     # both approvals are planning; neither has created its bulk yet
                return await fake_plan(row, body)

            monkeypatch.setattr(api_changes, "_make_plan", gated_plan)
            responses = await asyncio.gather(*(c.post(f"/api/approvals/{aid}/approve", json={"token": token, "comment": ""}, headers=H(who))
                                               for who in ("ben", "cleo")))
    assert sorted(r.status_code for r in responses) == [200, 409] and sorted(calls) == ["A", "A", "B", "B", "C", "C"]
    assert next(r for r in responses if r.status_code == 409).json()["detail"] == api_approvals.DECIDED.format(aid=aid)
    [winner] = [r.json() for r in responses if r.status_code == 200]
    assert dbfix.query("SELECT id FROM bulks") == [(winner["id"],)] and world.scheduled == [winner["id"]]
    assert dbfix.query("SELECT count(*) FROM bulk_items") == [(3,)]
    assert dbfix.query("SELECT status, bulk_id FROM approvals") == [("approved", winner["id"])]
