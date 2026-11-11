"""Phase 4c, Task 7: running a bulk change (POST /api/bulk and its run, app/bulk.py, app/api_bulk.py).

POST /api/bulk takes the ready sections of a preview (per switch its ports, its preview token and its write way) and the skipped
ones with their reason, checks the limits, the rights of every switch and the four-eyes principle, plans every switch once more
against its preview token and starts only when all of them match. The run, a date job of the scheduler (bulk.run), starts the
switches one after another, each as a normal change of the guided loop through api_changes.start_change with the bulk's id, and
waits for its end in the database; by default the first failure stops the rest ("continue" goes on), a cancel acts between two
switches, and with confirm_minutes every switch waits for its confirmation while the deadlines of the waiting ones grow with the
run and "Alle bestätigen" confirms them together. The summary names per switch what ran (with its change), a bulk with failures
raises the alert bulk_problem, and a restart ends a running one as interrupted.

The app runs in-process through FastAPI's TestClient, signed in per request as the user its X-Test-User header names
(apifix.by_header). The world (tests/bulkfix.py) has switches A, B and C in zone EK, a fake planner, a fake changes.run_change
(world.ends, world.order, world.after_start) and a recorded bulk.schedule (world.scheduled); a test runs the bulk itself with
asyncio.run(bulk.run(bid)). No switch, no network.
"""
import asyncio
from datetime import datetime, timedelta

import pytest
from bulkfix import fake_plan, items_of, make_world, start
from fastapi import HTTPException
from test_alerts import configure
from test_approvals import H

import api_changes
import apifix
import bulk
import changes
import confirm
import crypto
import db
import dbfix
import main
import monitor
import roles

USERS = {"anna": apifix.user("aendern", "anna"), "ek": apifix.user("aendern", "ek", zones=["EK"]), "ben": apifix.user("freigeben", "ben"),
         "bob": apifix.user("aendern", "bob")}


@pytest.fixture
def world(tmp_path, monkeypatch):
    return make_world(tmp_path, monkeypatch, zones=("EK", "EK", "EK"))


@pytest.fixture
def client(world, monkeypatch):
    """A TestClient signed in per request as USERS[<X-Test-User>]."""
    with apifix.signed_in(monkeypatch) as c:
        apifix.by_header(USERS)
        yield c


def got(client, bid, who="anna") -> dict:
    return client.get(f"/api/bulk/{bid}", headers=H(who)).json()


def test_a_bulk_starts_once_every_switch_matches_its_preview(world, client):
    r = start(client, world)
    assert r.status_code == 200 and set(r.json()) == {"id"} and world.scheduled == [r.json()["id"]]
    b = got(client, r.json()["id"])
    assert (b["status"], b["username"], b["on_error"], [i["status"] for i in b["items"]]) == ("queued", "anna", "stop", ["waiting"] * 3)
    assert dbfix.query("SELECT username, action FROM audit") == [("anna", "bulk_start")] and dbfix.query("SELECT count(*) FROM changes") == [(0,)]


def test_one_outdated_switch_stops_the_whole_bulk_before_anything_runs(world, client):    # Review Focus 4
    preview = client.post("/api/bulk/plan", json={"targets": [{"switch_id": s, "ports": ["1"]} for s in (world.a, world.b)],
                                                  "change": {"untagged": "30"}}, headers=H("anna")).json()
    world.plans["B"] = {"shown": ["vlan 40 untagged 1"]}
    r = client.post("/api/bulk", json=items_of(preview), headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, bulk.OUTDATED.format(list=f"B: {api_changes.STALE}"))
    assert dbfix.query("SELECT count(*) FROM bulks") == [(0,)] and world.scheduled == []


def test_with_four_eyes_a_bulk_must_be_requested(world, client):
    asyncio.run(db.set_setting("four_eyes", "1"))
    r = start(client, world)
    assert (r.status_code, r.json()["detail"]) == (409, bulk.APPROVAL_NEEDED) and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]


def test_a_bulk_body_has_the_limits_of_its_preview(world, client):                      # bulk.validate: a forged body, not the UI's
    item = {"switch_id": world.a, "ports": ["1"], "token": "t", "mechanism": "ssh"}
    r = client.post("/api/bulk", json={"items": [item], "skipped": [{"switch_id": world.a}], "change": {"untagged": "30"}}, headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (422, bulk.TWICE.format(sid=world.a)) and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]


def test_a_bulk_checks_every_switch_against_the_zones(world, client):
    dbfix.query("UPDATE switches SET zone = 'VK' WHERE id = ?", (world.c,))
    r = start(client, world, "ek", planner="anna")                                      # a body with C, which ek's own preview denies
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("VK", ["EK"])) and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]


def test_the_switches_run_one_after_another_as_changes_of_the_bulk(world, client):
    bid = start(client, world).json()["id"]
    assert asyncio.run(bulk.run(bid)) == "done" and world.order == [world.a, world.b, world.c]
    assert dbfix.query("SELECT switch_id, username, role, bulk_id, status FROM changes ORDER BY id") == [
        (s, "anna", "aendern", bid, "ok") for s in (world.a, world.b, world.c)]
    b = got(client, bid)
    assert (b["status"], [(i["status"], i["change"]["status"]) for i in b["items"]], b["counts"]["done"]) == ("done", [("done", "ok")] * 3, 3)
    assert dbfix.query("SELECT action FROM audit ORDER BY id") == [("bulk_start",), ("bulk_done",)]
    assert asyncio.run(monitor.explained_ports(world.a, "2000-01-01 00:00:00", "2100-01-01 00:00:00")) == {"1", "2"}    # Pin (4b Später 4c)


def test_the_first_failure_stops_the_rest(world, client):                                 # Review Focus 4
    asyncio.run(configure(mail=True, events=["bulk_problem"]))
    world.ends["B"] = "unclear"
    bid = start(client, world).json()["id"]
    assert asyncio.run(bulk.run(bid)) == "failed"
    [(cb,)] = dbfix.query("SELECT id FROM changes WHERE switch_id = ?", (world.b,))
    assert [(i["switch"], i["status"], i["detail"]) for i in got(client, bid)["items"]] == [
        ("A", "done", ""), ("B", "failed", f"Änderung #{cb} unklar"), ("C", "not_started", bulk.NOT_STARTED.format(why=bulk.WHY_STOPPED))]
    assert dbfix.query("SELECT event, title FROM alert_outbox") == [("bulk_problem", f"Sammeländerung #{bid} mit Fehlern beendet")]


def test_continue_on_error_runs_the_rest(world, client):
    world.ends["B"] = "failed"
    bid = start(client, world, on_error="continue").json()["id"]
    assert asyncio.run(bulk.run(bid)) == "failed" and [i["status"] for i in got(client, bid)["items"]] == ["done", "failed", "done"]


def test_a_start_refusal_counts_as_a_failure(world, client):                              # Review Focus 4
    bid = start(client, world).json()["id"]
    dbfix.query("INSERT INTO changes(switch_id, kind, summary, status) VALUES (?, 'ports', 'x', 'running')", (world.b,))
    asyncio.run(bulk.run(bid))
    assert [(i["status"], i["detail"]) for i in got(client, bid)["items"]] == [
        ("done", ""), ("failed", changes.BUSY), ("not_started", bulk.NOT_STARTED.format(why=bulk.WHY_STOPPED))]


def test_cancel_stops_between_switches(world, client):                                    # Review Focus 4
    bid = start(client, world).json()["id"]
    world.after_start[world.a] = lambda: dbfix.query("UPDATE bulks SET cancel_requested = 1")
    assert asyncio.run(bulk.run(bid)) == "cancelled"
    assert [i["status"] for i in got(client, bid)["items"]] == ["done", "not_started", "not_started"]
    assert got(client, bid)["items"][1]["detail"] == bulk.NOT_STARTED.format(why=bulk.WHY_CANCELLED)


def test_only_the_starter_or_freigeben_cancels_and_only_a_running_bulk(world, client):
    bid = start(client, world).json()["id"]
    r = client.post(f"/api/bulk/{bid}/cancel", headers=H("bob"))
    assert (r.status_code, r.json()["detail"]) == (403, bulk.CANCEL_WHO)
    assert client.post(f"/api/bulk/{bid}/cancel", headers=H("ben")).status_code == 200
    asyncio.run(bulk.run(bid))
    r = client.post(f"/api/bulk/{bid}/cancel", headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, bulk.NOT_RUNNING.format(bid=bid))
    assert dbfix.query("SELECT username, action FROM audit WHERE action LIKE 'bulk_cancel%'") == [("ben", "bulk_cancel"), ("anna", "bulk_cancelled")]


def test_a_bulk_with_confirmation_extends_the_deadlines_and_confirms_all(world, client, monkeypatch):
    world.ends |= {"A": "pending", "B": "pending", "C": "pending"}
    bid = start(client, world, confirm_minutes=5).json()["id"]
    assert asyncio.run(bulk.run(bid)) == "done"
    until = {u for (u,) in dbfix.query("SELECT confirm_until FROM changes WHERE bulk_id = ?", (bid,))}
    assert len(until) == 1 and got(client, bid)["counts"]["pending"] == 3
    seen = []

    async def confirm_one(cid, user):
        seen.append((cid, user["username"]))
        return {"ok": True, "id": cid}

    monkeypatch.setattr(confirm, "confirm_change", confirm_one)
    r = client.post(f"/api/bulk/{bid}/confirm", headers=H("anna")).json()
    ids = [i for (i,) in dbfix.query("SELECT id FROM changes WHERE bulk_id = ? ORDER BY id", (bid,))]
    assert r == {"confirmed": ids, "refused": []} and seen == [(i, "anna") for i in ids]


def test_a_change_taken_back_unconfirmed_meanwhile_stops_the_rest(world, client, monkeypatch):
    world.ends |= {"A": "pending", "B": "pending", "C": "pending"}
    bid = start(client, world, confirm_minutes=5).json()["id"]
    real = bulk._extend_deadlines

    async def watcher_took_a_back(b, minutes):                                          # its revert #99 ended ok
        await real(b, minutes)
        dbfix.query("UPDATE changes SET status = 'unclear', error = ?, reverted_by = 99 WHERE switch_id = ? AND bulk_id = ?",
                    (changes.REVERT_STARTED.format(rid=99), world.a, b))

    monkeypatch.setattr(bulk, "_extend_deadlines", watcher_took_a_back)
    assert asyncio.run(bulk.run(bid)) == "failed"
    [(ca,)] = dbfix.query("SELECT id FROM changes WHERE switch_id = ?", (world.a,))
    assert [(i["status"], i["detail"]) for i in got(client, bid)["items"]][1:] == [
        ("not_started", bulk.NOT_STARTED.format(why=bulk.WHY_STOPPED))] * 2 and got(client, bid)["items"][0]["detail"] == bulk.UNCONFIRMED.format(cid=ca)


def test_a_restart_marks_a_running_bulk_interrupted(world, client):
    asyncio.run(configure(mail=True, events=["bulk_problem"]))
    bid = start(client, world).json()["id"]
    dbfix.query("UPDATE bulks SET status = 'running'")
    dbfix.query("UPDATE bulk_items SET status = 'done', change_id = 7 WHERE pos = 0")
    dbfix.query("UPDATE bulk_items SET status = 'running', change_id = 8 WHERE pos = 1")
    assert asyncio.run(bulk.mark_interrupted()) == 1
    b = got(client, bid)
    assert (b["status"], [(i["status"], i["detail"]) for i in b["items"]]) == ("interrupted", [
        ("done", ""), ("failed", bulk.WHY_RESTART), ("not_started", bulk.NOT_STARTED.format(why=bulk.WHY_RESTART))])
    assert dbfix.query("SELECT event, title FROM alert_outbox") == [("bulk_problem", f"Sammeländerung #{bid} durch Neustart abgebrochen")]
    assert asyncio.run(bulk.mark_interrupted()) == 0


def test_a_bulk_started_with_an_api_token_names_it_in_the_audit_of_its_run(world, client, monkeypatch):
    monkeypatch.setitem(USERS, "bot", apifix.user("aendern", "anna") | {"api_token": {"id": 1, "name": "ci"}})
    bid = start(client, world, "bot").json()["id"]
    assert dbfix.query("SELECT api_token FROM bulks") == [("ci (#1)",)]
    asyncio.run(bulk.run(bid))
    assert dbfix.query("SELECT token FROM audit WHERE action = 'bulk_done'") == [("ci (#1)",)]


def test_the_list_of_bulks_and_an_unknown_one(world, client):
    first, second = start(client, world).json()["id"], start(client, world).json()["id"]
    assert [b["id"] for b in client.get("/api/bulk", headers=H("anna")).json()] == [second, first]
    r = client.get("/api/bulk/999", headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (404, bulk.NOT_FOUND)


# ── Beyond the plan's tests of Task 7: what the interface names and no test above holds ───────────────────────────────────────────
@pytest.mark.parametrize("body, detail", [
    (lambda w: {"items": [{"switch_id": w.a, "ports": ["1"], "token": "t", "mechanism": "ssh"}],
                "skipped": [{"switch_id": i} for i in range(100, 120)]}, bulk.TOO_MANY_SWITCHES),
    (lambda w: {"items": [{"switch_id": s, "ports": ["1"], "token": "t", "mechanism": "ssh"} for s in (w.a, w.b, w.a)]},
     "Switch #{a} steht doppelt in der Sammeländerung"),
    (lambda w: {"items": [{"switch_id": i, "ports": [str(p) for p in range(1, 201)], "token": "t", "mechanism": "ssh"} for i in range(1, 7)]},
     bulk.TOO_MANY_PORTS)])
def test_the_limits_of_a_bulk_body_count_items_and_skipped_together(world, client, body, detail):
    r = client.post("/api/bulk", json=body(world) | {"change": {"untagged": "30"}}, headers=H("ben"))
    assert (r.status_code, r.json()["detail"]) == (422, detail.format(a=world.a)) and dbfix.query("SELECT count(*) FROM bulks") == [(0,)]


def test_a_switch_that_cannot_run_with_confirmation_is_named_and_nothing_starts(world, client):
    world.plans["B"] = {"mechanism": "snmp"}                                              # B a ProCurve over SNMP: every SET saves itself
    r = start(client, world, confirm_minutes=5)
    assert (r.status_code, r.json()["detail"]) == (409, bulk.OUTDATED.format(list=f"B: {api_changes.CONFIRM_AUTOSAVE}"))
    assert dbfix.query("SELECT count(*) FROM bulks") == [(0,)] and world.scheduled == []


def test_every_switch_that_does_not_match_is_named(world, client):
    preview = client.post("/api/bulk/plan", json={"targets": [{"switch_id": s, "ports": ["1"]} for s in (world.a, world.b, world.c)],
                                                  "change": {"untagged": "30"}}, headers=H("anna")).json()
    world.plans |= {"A": {"blocked": [{"port": "1", "reason": "Uplink"}]},
                    "C": HTTPException(502, "Konfiguration des Switches per SNMP nicht lesbar: Timeout")}
    r = client.post("/api/bulk", json=items_of(preview), headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, bulk.OUTDATED.format(
        list="A: Nicht ausführbar: 1: Uplink; C: Konfiguration des Switches per SNMP nicht lesbar: Timeout"))


def test_the_check_before_the_start_plans_at_most_five_switches_at_once(world, client, monkeypatch):
    for i in range(12):
        world.extra(f"S{i}")
    preview = client.post("/api/bulk/plan", json={"targets": [{"switch_id": s, "ports": ["1"]} for s in world.extra_ids],
                                                  "change": {"untagged": "30"}}, headers=H("anna")).json()
    busy, peak = [0], [0]

    async def slow(row, body):
        busy[0] += 1
        peak[0] = max(peak[0], busy[0])
        await asyncio.sleep(0.05)
        busy[0] -= 1
        return await fake_plan(row, body)

    monkeypatch.setattr(api_changes, "_make_plan", slow)
    assert client.post("/api/bulk", json=items_of(preview), headers=H("anna")).status_code == 200 and peak[0] == bulk.PARALLEL


def test_the_answer_names_each_switch_its_zone_its_change_and_the_counts(world, client):
    world.plans["C"] = {"blocked": [{"port": "1", "reason": "Uplink/Trunk: nur im Expertenmodus"}]}
    bid = start(client, world, on_error="continue", confirm_minutes=3).json()["id"]
    b = got(client, bid)
    assert set(b) == {"id", "created_at", "username", "role", "approved_by", "summary", "change", "expert", "on_error", "confirm_minutes",
                      "status", "cancel_requested", "finished_at", "items", "counts"}
    assert (b["summary"], b["change"]["untagged"], b["expert"], b["on_error"], b["confirm_minutes"], b["cancel_requested"], b["role"]) == (
        "VLAN 30 · 4 Ports an 2 Switches", "30", False, "continue", 3, False, "aendern")
    assert [(i["pos"], i["switch"], i["zone"], i["ports"], i["status"], i["detail"], i["change"]) for i in b["items"]] == [
        (0, "A", "EK", ["1", "2"], "waiting", "", None), (1, "B", "EK", ["1", "2"], "waiting", "", None),
        (2, "C", "EK", [], "skipped", "Port 1: Uplink/Trunk: nur im Expertenmodus", None)]
    assert b["counts"] == {"done": 0, "failed": 0, "skipped": 1, "not_started": 0, "waiting": 2, "running": 0, "pending": 0, "unconfirmed": 0}
    world.ends["A"] = "pending"
    asyncio.run(bulk.run(bid))
    [ca, cb] = [i for (i,) in dbfix.query("SELECT id FROM changes ORDER BY id")]
    a = got(client, bid)["items"][0]["change"]
    assert set(a) == {"id", "status", "error", "saved", "confirm_until", "confirmed_by", "reverted_by"} and (a["id"], a["status"]) == (ca, "pending")
    listed = client.get("/api/bulk", headers=H("anna")).json()
    assert listed == [{"id": bid, "created_at": b["created_at"], "username": "anna", "summary": b["summary"], "status": "done",
                       "counts": {"done": 2, "failed": 0, "skipped": 1, "not_started": 0, "waiting": 0, "running": 0, "pending": 1,
                                  "unconfirmed": 0}}]
    assert cb != ca and client.get("/api/bulk?limit=0", headers=H("anna")).status_code == 422


def test_a_switch_deleted_or_disabled_since_the_start_fails_without_a_change(world, client):
    bid = start(client, world, on_error="continue").json()["id"]
    db.execute_sync("DELETE FROM switches WHERE id = ?", (world.a,))                     # with the foreign keys: the item keeps its name
    db.execute_sync("UPDATE switches SET enabled = 0 WHERE id = ?", (world.b,))
    assert asyncio.run(bulk.run(bid)) == "failed" and world.order == [world.c]
    assert [(i["switch_id"], i["switch"], i["status"], i["detail"]) for i in got(client, bid)["items"]] == [
        (None, "A", "failed", bulk.GONE), (world.b, "B", "failed", api_changes.DISABLED), (world.c, "C", "done", "")]


def test_a_refused_start_is_stored_masked(world, client):
    db.execute_sync("UPDATE switches SET snmp_community = ? WHERE id = ?", (crypto.encrypt("geheim-4711"), world.a))
    bid = start(client, world).json()["id"]
    world.plans["A"] = HTTPException(502, "Konfiguration per SNMP nicht lesbar: geheim-4711 abgelehnt")
    asyncio.run(bulk.run(bid))
    assert got(client, bid)["items"][0]["detail"] == "Konfiguration per SNMP nicht lesbar: *** abgelehnt"


def test_an_unexpected_error_ends_the_run_failed_with_the_rest_not_started(world, client, monkeypatch):
    bid = start(client, world, on_error="continue").json()["id"]
    real = api_changes.start_change

    async def broken(row, body, maker, **kw):
        if row["name"] == "B":
            raise RuntimeError("database is locked")
        return await real(row, body, maker, **kw)

    monkeypatch.setattr(api_changes, "start_change", broken)
    assert asyncio.run(bulk.run(bid)) == "failed"
    b = got(client, bid)
    assert (b["status"], b["finished_at"] is not None, [(i["status"], i["detail"]) for i in b["items"]]) == ("failed", True, [
        ("done", ""), ("failed", bulk.CRASHED), ("not_started", bulk.NOT_STARTED.format(why=bulk.WHY_STOPPED))])


def test_a_change_taken_back_after_the_last_switch_still_fails_the_bulk(world, client, monkeypatch):
    world.ends |= {"A": "pending", "B": "pending", "C": "pending"}
    bid = start(client, world, confirm_minutes=5).json()["id"]
    real, calls = bulk._extend_deadlines, []

    async def after_c(b, minutes):
        await real(b, minutes)
        calls.append(b)
        if len(calls) == 3:                                                             # its revert #99 ended ok
            dbfix.query("UPDATE changes SET status = 'unclear', error = ?, reverted_by = 99 WHERE switch_id = ? AND bulk_id = ?",
                        (changes.REVERT_STARTED.format(rid=99), world.b, b))

    monkeypatch.setattr(bulk, "_extend_deadlines", after_c)
    assert asyncio.run(bulk.run(bid)) == "failed"
    [(cb,)] = dbfix.query("SELECT id FROM changes WHERE switch_id = ?", (world.b,))
    assert [(i["status"], i["detail"]) for i in got(client, bid)["items"]] == [("done", ""), ("done", bulk.UNCONFIRMED.format(cid=cb)), ("done", "")]


def test_a_change_that_ended_ok_without_a_confirm_is_no_failure(world, client):
    """CONFIRM_SKIPPED: a switch that saved the change itself ends it ok without a confirm; and a run that ends a change unclear keeps
    its own detail (the ledger's ruling on UNCONFIRMED)."""
    world.ends |= {"A": "ok", "B": "unclear"}
    bid = start(client, world, confirm_minutes=5, on_error="continue").json()["id"]
    assert asyncio.run(bulk.run(bid)) == "failed"
    [(cb,)] = dbfix.query("SELECT id FROM changes WHERE switch_id = ?", (world.b,))
    assert [(i["status"], i["detail"]) for i in got(client, bid)["items"]] == [("done", ""), ("failed", f"Änderung #{cb} unklar"), ("done", "")]


def test_confirm_all_names_each_refused_change(world, client, monkeypatch):
    world.ends |= {"A": "pending", "B": "pending"}
    bid = start(client, world, confirm_minutes=5).json()["id"]
    asyncio.run(bulk.run(bid))
    ca, cb = [i for (i,) in dbfix.query("SELECT id FROM changes WHERE status = 'pending' ORDER BY id")]

    async def confirm_one(cid, user):
        if cid == cb:
            raise HTTPException(409, confirm.TOO_LATE.format(cid=cid))
        return {"ok": True, "id": cid}

    monkeypatch.setattr(confirm, "confirm_change", confirm_one)
    r = client.post(f"/api/bulk/{bid}/confirm", headers=H("bob"))
    assert r.json() == {"confirmed": [ca], "refused": [{"id": cb, "detail": confirm.TOO_LATE.format(cid=cb)}]}
    assert [client.post(f"/api/bulk/999/{what}", headers=H("anna")).status_code for what in ("confirm", "cancel")] == [404, 404]


def test_a_queued_bulk_that_is_cancelled_starts_nothing(world, client):
    bid = start(client, world).json()["id"]
    assert client.post(f"/api/bulk/{bid}/cancel", headers=H("anna")).json() == {"ok": True, "id": bid}
    assert asyncio.run(bulk.run(bid)) == "cancelled" and world.order == [] and asyncio.run(bulk.run(bid)) == "cancelled"
    assert [i["detail"] for i in got(client, bid)["items"]] == [bulk.NOT_STARTED.format(why=bulk.WHY_CANCELLED)] * 3
    assert dbfix.query("SELECT detail FROM audit WHERE action = 'bulk_cancelled'") == [(f"#{bid} VLAN 30 · 6 Ports an 3 Switches: 0 erledigt, "
                                                                                       "0 fehlgeschlagen, 3 nicht gestartet",)]


def test_a_restart_names_the_api_token_of_the_bulk_and_leaves_the_context_as_it_was(world, client, monkeypatch):
    monkeypatch.setitem(USERS, "bot", apifix.user("aendern", "anna") | {"api_token": {"id": 1, "name": "ci"}})
    start(client, world, "bot")
    assert asyncio.run(bulk.mark_interrupted()) == 1 and db.AUDIT_TOKEN.get() is None
    assert dbfix.query("SELECT username, token FROM audit WHERE action = 'bulk_interrupted'") == [("anna", "ci (#1)")]


async def test_the_start_of_the_app_ends_a_running_bulk(world, monkeypatch):
    """lifespan runs bulk.mark_interrupted right after changes.mark_interrupted; the scheduler's start and stop are no-ops here."""
    for name in ("add_job", "start", "shutdown"):
        monkeypatch.setattr(main.scheduler, name, lambda *args, **kwargs: None)
    async with db.db() as conn:
        await conn.execute("INSERT INTO bulks(created_at, username, summary, change, on_error, status) VALUES "
                           "('2026-11-08 09:00:00', 'anna', 'VLAN 30', '{}', 'stop', 'running')")
        await conn.commit()
    async with main.lifespan(main.app):
        assert dbfix.query("SELECT status FROM bulks") == [("interrupted",)]


def test_schedule_adds_one_date_job_per_bulk(monkeypatch):
    added = []
    monkeypatch.setattr(main.scheduler, "add_job", lambda *args, **kwargs: added.append((args, kwargs)))
    bulk.schedule(7)
    assert added == [((bulk.run, "date"), {"args": [7], "id": "bulk-7", "replace_existing": True, "misfire_grace_time": None})]


def test_the_deadlines_of_the_waiting_changes_move_with_the_run(world, client):
    """Each extension sets every waiting change of the bulk to now + confirm_minutes (the fake run leaves 5 minutes): at the end B and
    C have the deadline of the last switch; A, confirmed while B ran, no longer waits and keeps its own."""
    world.ends |= {"A": "pending", "B": "pending", "C": "pending"}
    world.after_start[world.b] = lambda: dbfix.query("UPDATE changes SET status = 'ok', confirm_until = '2026-01-02 00:00:00', "
                                                     "confirmed_by = 'anna' WHERE switch_id = ?", (world.a,))
    bid = start(client, world, confirm_minutes=7).json()["id"]
    before = changes._now()
    assert asyncio.run(bulk.run(bid)) == "done"
    until = dict(dbfix.query("SELECT switch_id, confirm_until FROM changes WHERE bulk_id = ?", (bid,)))
    assert until[world.a] == "2026-01-02 00:00:00" and until[world.b] == until[world.c] > before
    later = datetime.strptime(until[world.c], "%Y-%m-%d %H:%M:%S") - datetime.strptime(before, "%Y-%m-%d %H:%M:%S")
    assert timedelta(minutes=7) <= later <= timedelta(minutes=7, seconds=5)


# ── Task 7 review round 1 ─────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("error, reverted_by, detail", [
    (f"{confirm.UNREACHABLE} (Konfiguration per SNMP nicht lesbar: Timeout)", None,
     f"Änderung #{{cid}}: {confirm.UNREACHABLE} (Konfiguration per SNMP nicht lesbar: Timeout)"),
    (f"{confirm.NOT_TAKEN_BACK} (Switch deaktiviert)", None, f"Änderung #{{cid}}: {confirm.NOT_TAKEN_BACK} (Switch deaktiviert)"),
    (changes.REVERT_STARTED.format(rid=99), None, "Änderung #{cid}: Nicht bestätigt: Rücknahme #99 gestartet"),
    (changes.REVERT_STARTED.format(rid=99), 99, bulk.UNCONFIRMED),
    (None, None, bulk.UNCONFIRMED_BARE)], ids=["unreachable", "not-taken-back", "revert-started", "taken-back", "no-error"])
def test_the_detail_of_an_unconfirmed_end_says_only_what_happened(world, client, monkeypatch, error, reverted_by, detail):
    """Review Focus 2: the switch drops off the network during the deadline and the watch gives up (unclear with confirm.UNREACHABLE,
    or NOT_TAKEN_BACK), or its revert has only started: the bulk's summary must not say "zurückgenommen" while the change says it was
    not - only a change its revert marked (reverted_by: the revert ended ok) is UNCONFIRMED; any other names the change's own error.
    It is a failure either way, and stop stops the rest."""
    world.ends |= {"A": "pending", "B": "pending", "C": "pending"}
    bid = start(client, world, confirm_minutes=5).json()["id"]
    real = bulk._extend_deadlines

    async def a_ended_unconfirmed(b, minutes):
        await real(b, minutes)
        dbfix.query("UPDATE changes SET status = 'unclear', error = ?, reverted_by = ? WHERE switch_id = ? AND bulk_id = ?",
                    (error, reverted_by, world.a, b))

    monkeypatch.setattr(bulk, "_extend_deadlines", a_ended_unconfirmed)
    assert asyncio.run(bulk.run(bid)) == "failed"
    [(ca,)] = dbfix.query("SELECT id FROM changes WHERE switch_id = ?", (world.a,))
    items = got(client, bid)["items"]
    assert [(i["status"], i["detail"]) for i in items] == [("done", detail.format(cid=ca))] + [
        ("not_started", bulk.NOT_STARTED.format(why=bulk.WHY_STOPPED))] * 2
    assert (items[0]["change"]["error"], items[0]["change"]["reverted_by"]) == (error, reverted_by)


def test_the_detail_of_an_unconfirmed_end_follows_its_revert_while_the_bulk_runs(world, client, monkeypatch):
    """With continue the run looks again before each switch and after the last: A's revert has started at the look before B and has
    ended ok (reverted_by) at the look before C - the detail says what holds at the last look."""
    world.ends |= {"A": "pending", "B": "pending", "C": "pending"}
    bid = start(client, world, confirm_minutes=5, on_error="continue").json()["id"]
    real, calls, seen = bulk._extend_deadlines, [], []

    async def a_taken_back_in_two_steps(b, minutes):
        await real(b, minutes)
        calls.append(b)
        if len(calls) == 1:
            dbfix.query("UPDATE changes SET status = 'unclear', error = ? WHERE switch_id = ? AND bulk_id = ?",
                        (changes.REVERT_STARTED.format(rid=99), world.a, b))
        seen.append(dbfix.query("SELECT detail FROM bulk_items WHERE bulk_id = ? AND pos = 0", (b,))[0][0])
        if len(calls) == 2:
            dbfix.query("UPDATE changes SET reverted_by = 99 WHERE switch_id = ? AND bulk_id = ?", (world.a, b))

    monkeypatch.setattr(bulk, "_extend_deadlines", a_taken_back_in_two_steps)
    assert asyncio.run(bulk.run(bid)) == "failed" and world.order == [world.a, world.b, world.c]
    [(ca,)] = dbfix.query("SELECT id FROM changes WHERE switch_id = ?", (world.a,))
    assert seen[1] == f"Änderung #{ca}: Nicht bestätigt: Rücknahme #99 gestartet"
    assert [(i["status"], i["detail"]) for i in got(client, bid)["items"]] == [("done", bulk.UNCONFIRMED.format(cid=ca)), ("done", ""),
                                                                               ("done", "")]


def test_a_deadline_that_has_passed_is_not_extended(world, client):
    """A deadline that has passed is final: the watch (every 15 s) takes that change back, and the extension after a later switch of
    the bulk does not revive it before the watch gets there (Bekannte Grenzen: "läuft die Frist der früheren vorher ab, der Wächter
    nimmt sie zurück")."""
    world.ends |= {"A": "pending", "B": "pending", "C": "pending"}
    world.after_start[world.b] = lambda: dbfix.query("UPDATE changes SET confirm_until = '2000-01-01 00:00:00' WHERE switch_id = ?",
                                                     (world.a,))
    bid = start(client, world, confirm_minutes=7).json()["id"]
    assert asyncio.run(bulk.run(bid)) == "done"
    until = dict(dbfix.query("SELECT switch_id, confirm_until FROM changes WHERE bulk_id = ?", (bid,)))
    assert until[world.a] == "2000-01-01 00:00:00" and until[world.b] == until[world.c] > changes._now()


@pytest.mark.parametrize("status, reason", [(changes.PENDING, lambda cid: changes.PENDING_BUSY.format(cid=cid)),
                                            ("running", lambda cid: changes.BUSY)], ids=["waiting", "running"])
def test_a_switch_busy_at_the_start_is_named_and_nothing_starts(world, client, status, reason):
    """The early busy check of start_change in the check before the start: a switch with a change that runs or waits for its
    confirmation (a second bulk over the switches of a first one that still waits) stops the start before any switch is changed."""
    preview = client.post("/api/bulk/plan", json={"targets": [{"switch_id": s, "ports": ["1"]} for s in (world.a, world.b)],
                                                  "change": {"untagged": "30"}}, headers=H("anna")).json()
    dbfix.query("INSERT INTO changes(switch_id, kind, summary, status) VALUES (?, 'ports', 'x', ?)", (world.b, status))
    [(cid,)] = dbfix.query("SELECT id FROM changes")
    r = client.post("/api/bulk", json=items_of(preview), headers=H("anna"))
    assert (r.status_code, r.json()["detail"]) == (409, bulk.OUTDATED.format(list=f"B: {reason(cid)}"))
    assert dbfix.query("SELECT count(*) FROM bulks") == [(0,)] and world.scheduled == []


def test_freigeben_cancels_another_ones_bulk_only_with_the_zone_of_each_of_its_switches(world, client, monkeypatch):
    """Cancel decides which switches get changed: a Freigeben who did not start the bulk needs the zone of every switch it runs at
    (as Task 8's approval of a bulk change); a skipped switch runs nothing and does not count; the starter is never asked."""
    monkeypatch.setitem(USERS, "ute", apifix.user("freigeben", "ute", zones=["EK"]))
    dbfix.query("UPDATE switches SET zone = 'VK' WHERE id = ?", (world.c,))
    bid = start(client, world).json()["id"]
    r = client.post(f"/api/bulk/{bid}/cancel", headers=H("ute"))
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("VK", ["EK"]))
    assert dbfix.query("SELECT cancel_requested FROM bulks WHERE id = ?", (bid,)) == [(0,)]
    world.plans["C"] = {"blocked": [{"port": "1", "reason": "Uplink"}]}
    other = start(client, world).json()["id"]
    assert client.post(f"/api/bulk/{other}/cancel", headers=H("ute")).status_code == 200
    assert client.post(f"/api/bulk/{bid}/cancel", headers=H("anna")).status_code == 200


# ── Final review of Phase 4c ──────────────────────────────────────────────────────────────────────────────────────────────────────
def test_the_status_is_that_of_the_run_and_the_counts_follow_the_changes_after_it(world, client):
    """Finding 1: the deadlines end N minutes after the last switch (T7-e), so a run with confirmation ends done while its changes
    still wait (pending). What they do after the run leaves the status of the bulk change and its alert as they are; its counts say
    it: unconfirmed, a done switch whose change ended without its confirmation (the rule of bulk._unconfirmed: A, taken back by the
    watch), not one that was confirmed (B) or still waits (C)."""
    asyncio.run(configure(mail=True, events=["bulk_problem"]))
    world.ends |= {"A": "pending", "B": "pending", "C": "pending"}
    bid = start(client, world, confirm_minutes=2).json()["id"]
    assert asyncio.run(bulk.run(bid)) == "done"
    assert got(client, bid)["counts"] == {"done": 3, "failed": 0, "skipped": 0, "not_started": 0, "waiting": 0, "running": 0, "pending": 3,
                                          "unconfirmed": 0}
    ca, cb, _ = [i for (i,) in dbfix.query("SELECT id FROM changes WHERE bulk_id = ? ORDER BY id", (bid,))]
    dbfix.query("UPDATE changes SET status = 'unclear', error = ?, reverted_by = 19 WHERE id = ?", (changes.REVERT_STARTED.format(rid=19), ca))
    dbfix.query("UPDATE changes SET status = 'ok', saved = 1, confirmed_by = 'anna' WHERE id = ?", (cb,))
    b = got(client, bid)
    assert (b["status"], b["counts"]) == ("done", {"done": 3, "failed": 0, "skipped": 0, "not_started": 0, "waiting": 0, "running": 0,
                                                   "pending": 1, "unconfirmed": 1})
    assert client.get("/api/bulk", headers=H("anna")).json()[0]["counts"] == b["counts"]
    assert dbfix.query("SELECT count(*) FROM alert_outbox") == [(0,)]


@pytest.mark.parametrize("change, unconfirmed", [
    ("status = 'unclear', confirm_minutes = NULL", 0),                                   # never waited: a bulk without confirmation
    ("status = 'ok', saved = 1", 0),                                                     # ok without a confirm: the switch saved itself
    ("status = 'unclear', error = 'x'", 1),                                              # the watch gave up
    ("status = 'failed'", 1),
    ("status = 'unclear', confirmed_by = 'anna'", 0)],                                   # confirmed, then its save went wrong
    ids=["no-confirmation", "saved-itself", "gave-up", "failed", "confirmed"])
def test_unconfirmed_counts_by_the_rule_of_an_unconfirmed_end(world, client, change, unconfirmed):
    world.ends |= {"A": "pending"}
    bid = start(client, world, confirm_minutes=5).json()["id"]
    asyncio.run(bulk.run(bid))
    dbfix.query(f"UPDATE changes SET {change} WHERE switch_id = ? AND bulk_id = ?", (world.a, bid))
    assert got(client, bid)["counts"]["unconfirmed"] == unconfirmed
