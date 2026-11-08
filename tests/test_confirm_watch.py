"""Phase 4c, Task 5: the watch over the changes that wait for their confirmation (confirm.watch, a scheduler job every 15 seconds and
once at the start), the automatic revert (confirm.auto_revert), the restart that tells of every change it ends, and the switch's
reachability (confirm.reachable).

A change past its deadline (changes.confirm_until, UTC) is due at once, without a check; any other waiting change is checked by
reachable (sysUpTime over SNMP with the read identity), and one whose switch did not answer twice in a row is due too. A due change
is taken back as a normal revert: _make_plan of the revert for its preview token, then start_change as the user "SwitchView" without
a role - planned, read afresh in the lock, verified and saved by run_change as every change. A revert that cannot start ends the
waiting "unclear" with a clear text (the switch keeps the change unsaved until it restarts), with an audit and an alert; one with
nothing left to take back ends without an alert; a change that no longer waits (confirmed, taken back by hand) is left alone.

The watch cases plan with a fake api_changes._make_plan and record the start of the revert instead of running it (changes.run_change),
with confirm.reachable replaced; the two reachable cases use the real one against a fake snmp.get. The end-to-end case runs the real
run_change twice on the fake ProCurve of ssh_env (tests/sshfix.py). No network, no switch.
"""
import asyncio
import json
import types
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from test_alerts import configure
from test_change_outcome import OFF, queued_change, until
from test_confirm import pending_change

import api_changes
import apifix
import changes
import confirm
import db
import dbfix
import main
import poller
import snmp
import sshcli
import sshfix
from cfgparse import parse_config


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A fresh database with the ProCurve SW of sshfix.procurve() (sid). The revert plans world.shown (["interface 2 enable"] unless
    a test sets it), raises world.plan_error, or calls world.plan when that is set (a fake api_changes._make_plan); the start of a
    change is recorded in ran (changes.run_change). confirm.reachable answers world.answer (True unless set) and counts its calls in
    gets; the misses and the R27 marks start empty; alerts go out by mail for confirm_revert."""
    apifix.fresh_db(tmp_path, monkeypatch)
    w = types.SimpleNamespace(sid=dbfix.insert_switch(**sshfix.procurve()), shown=["interface 2 enable"], plan_error=None, plan=None, ran=[],
                              answer=True, gets=0)

    async def fake_plan(row, body):
        if w.plan is not None:
            return await w.plan(row, body)
        if w.plan_error is not None:
            raise w.plan_error
        plan = {"shown": w.shown, "commands": w.shown, "blocked": [], "mechanism": "ssh", "warnings": [], "expert": False,
                "desired": {"2": {"en": True}} if w.shown else {}, "before": {"2": {"en": False}} if w.shown else {}}
        return plan, {"desired": {"2": {"en": True}}, "expert": False}, "ports", f"Rückgängig #{body.of}: Port 2: Aus"

    def run_fake(cid):
        w.ran.append(cid)
        return asyncio.sleep(0)

    async def reachable(row):
        w.gets += 1
        return w.answer

    monkeypatch.setattr(api_changes, "_make_plan", fake_plan)
    monkeypatch.setattr(changes, "run_change", run_fake)
    monkeypatch.setattr(confirm, "reachable", reachable)
    monkeypatch.setattr(confirm, "_misses", {})
    monkeypatch.setattr(changes, "_cfg_stale", set())
    asyncio.run(configure(mail=True, events=["confirm_revert"]))
    return w


def pending(sid, until, user="anna") -> int:
    """A change of sid waiting for its confirmation until `until` (UTC text), as run_change leaves one; its id."""
    [(cid,)] = dbfix.query(
        "INSERT INTO changes(switch_id, username, kind, summary, request, ports, desired, before, commands, status, steps, expert, mechanism, "
        "sent, role, confirm_minutes, confirm_until) VALUES (?, ?, 'ports', 'Port 2: Aus', '{}', '[\"2\"]', '{\"2\": {\"en\": false}}', "
        "'{\"2\": {\"en\": true}}', '[\"interface 2 disable\"]', 'pending', '[]', 0, 'ssh', 1, 'aendern', 5, ?) RETURNING id", (sid, user, until))
    return cid


def at(minutes: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


def row(cid) -> dict:
    return dict(zip(("status", "error", "saved", "steps", "reverted_by"),
                    dbfix.query("SELECT status, error, saved, steps, reverted_by FROM changes WHERE id = ?", (cid,))[0]))


def dbfix_row(cid) -> dict:
    """The whole changes row of cid as a dict, as changes.actions_of reads it."""
    conn = dbfix.connect()
    try:
        return dict(conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)).fetchone())
    finally:
        conn.close()


def told() -> list[tuple]:
    return dbfix.query("SELECT event, title FROM alert_outbox ORDER BY id")


async def test_an_answering_switch_waits_for_its_deadline(world):
    cid = pending(world.sid, at(3))
    assert await confirm.watch() == 0 and row(cid)["status"] == "pending" and world.ran == [] and world.gets == 1


async def test_a_due_deadline_takes_the_change_back(world):
    deadline = at(-1)
    cid = pending(world.sid, deadline)
    assert await confirm.watch() == 1
    [(rid, of, user, role, status)] = dbfix.query("SELECT id, revert_of, username, role, status FROM changes WHERE id <> ?", (cid,))
    assert (of, user, role, status, world.ran, world.gets) == (cid, confirm.AUTO_USER, None, "queued", [rid], 0)
    ch = row(cid)
    assert (ch["status"], ch["error"]) == ("unclear", changes.REVERT_STARTED.format(rid=rid))
    why = confirm.TIMED_OUT.format(until=deadline[11:16])
    assert [s[1] for s in json.loads(ch["steps"])] == [confirm.REVERTING_STEP.format(why=why), changes.REVERT_STARTED.format(rid=rid)]
    assert told() == [("confirm_revert", f"Änderung #{cid} an SW-EK-01 wird zurückgenommen")]


# Beyond the brief: the text of the alert (summary, starter, why, the revert's number) and that the revert is a normal one, its
# preview token the one of the commands it plans
async def test_the_alert_names_why_and_the_revert(world):
    deadline = at(-1)
    cid = pending(world.sid, deadline)
    await confirm.watch()
    [(rid, request, commands)] = dbfix.query("SELECT id, request, commands FROM changes WHERE id <> ?", (cid,))
    why = confirm.TIMED_OUT.format(until=deadline[11:16])
    assert dbfix.query("SELECT text, switch_id, switch_name, dedup_key FROM alert_outbox") == [
        (f"Port 2: Aus (von anna): {why}. Rücknahme #{rid}.", world.sid, "SW-EK-01", f"confirm_revert:confirm:{cid}")]
    assert (json.loads(request), json.loads(commands)) == ({"desired": {"2": {"en": True}}, "expert": False}, ["interface 2 enable"])


async def test_a_switch_that_stops_answering_is_taken_back_after_two_checks(world):     # Review Focus 2
    cid, world.answer = pending(world.sid, at(4)), False
    assert await confirm.watch() == 0 and row(cid)["status"] == "pending"
    assert await confirm.watch() == 1 and row(cid)["status"] == "unclear"
    assert json.loads(row(cid)["steps"])[0][1] == confirm.REVERTING_STEP.format(why=confirm.NO_ANSWER)


async def test_one_good_answer_starts_the_count_again(world):
    cid = pending(world.sid, at(4))
    for answer in (False, True, False):
        world.answer = answer
        await confirm.watch()
    assert row(cid)["status"] == "pending" and world.ran == []


# Beyond the brief: the count of a change that no longer waits goes, and at most PARALLEL checks run at once
async def test_the_misses_of_a_change_that_ended_go(world):
    cid, world.answer = pending(world.sid, at(4)), False
    await confirm.watch()
    assert confirm._misses == {cid: 1}
    dbfix.query("UPDATE changes SET status = 'ok' WHERE id = ?", (cid,))
    assert await confirm.watch() == 0 and confirm._misses == {}


async def test_the_checks_run_at_most_five_at_once(world, monkeypatch):
    for i in range(7):
        pending(dbfix.insert_switch(**sshfix.procurve(name=f"SW-{i}", host=f"203.0.113.{30 + i}")), at(4))
    now, most = [0], [0]

    async def slow(row):
        now[0] += 1
        most[0] = max(most[0], now[0])
        await asyncio.sleep(0.02)
        now[0] -= 1
        return True

    monkeypatch.setattr(confirm, "reachable", slow)
    assert await confirm.watch() == 0 and most[0] == confirm.PARALLEL


async def test_a_revert_that_cannot_reach_the_switch_ends_in_a_clear_state(world):     # Review Focus 2
    cid = pending(world.sid, at(-1))
    world.plan_error = HTTPException(502, "Konfiguration des Switches nicht lesbar: timeout")
    assert await confirm.watch() == 0
    ch = row(cid)
    assert (ch["status"], ch["error"], ch["saved"]) == ("unclear", f"{confirm.UNREACHABLE} (Konfiguration des Switches nicht lesbar: timeout)", 0)
    assert dbfix.query("SELECT count(*) FROM changes") == [(1,)] and changes.actions_of(dbfix_row(cid))["can_revert"] is True
    assert told() == [("confirm_revert", f"Änderung #{cid} an SW-EK-01 nicht zurückgenommen")]
    assert dbfix.query("SELECT username, action, role FROM audit") == [("anna", "change_unclear", "aendern")]


async def test_the_revert_plans_from_a_fresh_read_of_the_switch(world):               # Review Focus 2: no read from the cache
    cid, seen = pending(world.sid, at(-1)), []

    async def plan(r, body):
        seen.append(r["id"] in changes._cfg_stale)
        raise HTTPException(502, "Konfiguration des Switches nicht lesbar: timeout")

    world.plan = plan
    await confirm.watch()
    assert seen == [True] and row(cid)["error"].startswith(confirm.UNREACHABLE)


async def test_the_watch_never_names_the_api_token_of_whoever_woke_the_scheduler(world):
    db.AUDIT_TOKEN.set(("anna", "ci (#1)"))              # APScheduler runs a job in the context of the call that woke it
    pending(world.sid, at(-1))
    world.plan_error = HTTPException(502, "Konfiguration des Switches nicht lesbar: timeout")
    await confirm.watch()
    assert dbfix.query("SELECT username, action, token FROM audit") == [("anna", "change_unclear", None)]


async def test_another_refusal_names_itself(world):
    cid = pending(world.sid, at(-1))
    world.plan_error = HTTPException(409, "Treiber x kann das nicht")
    await confirm.watch()
    assert row(cid)["error"] == f"{confirm.NOT_TAKEN_BACK} (Treiber x kann das nicht)"


# Beyond the brief: a blocked port is refused like a 409 with "Nicht ausführbar: …" (its port sends nothing, so the plan is empty
# but not "nothing to take back"), and the give-up is a step of the change
async def test_a_blocked_revert_is_not_taken_back(world):
    cid = pending(world.sid, at(-1))

    async def blocked(r, body):
        plan = {"shown": [], "commands": [], "blocked": [{"port": "2", "reason": "Uplink"}], "mechanism": "ssh"}
        return plan, {}, "ports", "x"

    world.plan = blocked
    assert await confirm.watch() == 0
    error = f"{confirm.NOT_TAKEN_BACK} (Nicht ausführbar: 2: Uplink)"
    assert (row(cid)["error"], json.loads(row(cid)["steps"])[-1][1:]) == (error, [error, "error"]) and world.ran == []


# Beyond the brief: the reason of a give-up is masked like every stored text of a change (the switch's SSH password of
# sshfix.procurve) before it is stored and before it goes out in the alert
async def test_the_reason_of_a_give_up_shows_no_secret(world):
    cid = pending(world.sid, at(-1))
    world.plan_error = HTTPException(502, "Konfiguration des Switches nicht lesbar: login manager/ssh-s3cret refused")
    await confirm.watch()
    want = f"{confirm.UNREACHABLE} (Konfiguration des Switches nicht lesbar: login manager/*** refused)"
    assert (row(cid)["error"], json.loads(row(cid)["steps"])[-1][1]) == (want, want)
    assert dbfix.query("SELECT text FROM alert_outbox") == [(f"Port 2: Aus (von anna): {want}",)]


async def test_nothing_left_to_take_back_ends_the_wait_without_an_alert(world):
    cid, world.shown = pending(world.sid, at(-1)), []
    assert await confirm.watch() == 0
    assert (row(cid)["status"], row(cid)["error"], told()) == ("unclear", confirm.NOTHING_BACK, [])


async def test_a_confirm_that_won_the_race_is_left_alone(world):                         # Review Focus 1
    cid = pending(world.sid, at(-1))

    async def confirmed_first(r, body):
        dbfix.query("UPDATE changes SET status = 'running' WHERE id = ?", (cid,))
        raise HTTPException(409, "Diese Änderung lässt sich nicht zurücknehmen")

    world.plan = confirmed_first
    assert await confirm.watch() == 0 and row(cid)["status"] == "running" and told() == [] and world.ran == []


# Beyond the brief: a confirm that lands between the watch's read of the change and its step leaves no revert step in its run's
# steps, and nothing is planned (the read is made to see the change still waiting, the database has it running)
async def test_a_confirm_between_the_read_and_the_step_gets_no_step(world, monkeypatch):
    cid, planned, real = pending(world.sid, at(-1)), [], confirm._named

    async def read_before_the_confirm(c):
        return dict(await real(c)) | {"status": "pending"}

    async def plan(r, body):
        planned.append(body.of)
        raise AssertionError("no plan for a change that no longer waits")

    monkeypatch.setattr(confirm, "_named", read_before_the_confirm)
    world.plan = plan
    dbfix.query("UPDATE changes SET status = 'running', steps = '[[\"t\", \"Bestätigt von anna\", \"info\"]]' WHERE id = ?", (cid,))
    assert await confirm.auto_revert(cid, confirm.NO_ANSWER) is None
    assert (row(cid)["status"], json.loads(row(cid)["steps"])) == ("running", [["t", "Bestätigt von anna", "info"]])
    assert (planned, world.ran, told()) == ([], [], [])


async def test_the_first_watch_after_a_restart_takes_back_what_ran_out(world, monkeypatch):   # Review Focus 1
    cid, jobs = pending(world.sid, at(-10)), {}
    monkeypatch.setattr(main.scheduler, "add_job", lambda func, trigger, **kw: jobs.__setitem__(kw["id"], (func, trigger, kw)))
    for name in ("start", "shutdown"):
        monkeypatch.setattr(main.scheduler, name, lambda *args, **kwargs: None)
    async with main.lifespan(main.app):
        assert row(cid)["status"] == "pending"                               # mark_interrupted leaves a waiting change alone
        func, trigger, kw = jobs["confirm"]
        assert (func, trigger, kw["seconds"], kw["next_run_time"] is not None) == (confirm.watch, "interval", confirm.CHECK_S, True)
        assert await func() == 1 and row(cid)["status"] == "unclear"


async def test_the_start_tells_of_every_change_it_ends(ssh_env):
    await configure(mail=True, events=["change_problem"])
    a, b = queued_change(ssh_env, sent=0), queued_change(ssh_env, sent=1)              # from tests/test_change_outcome.py
    assert await changes.mark_interrupted() == 2
    assert told() == [("change_problem", f"Änderung #{a} an SW-EK-01 abgebrochen"), ("change_problem", f"Änderung #{b} an SW-EK-01 unklar")]


async def test_reachable_asks_the_uptime_with_the_read_identity(monkeypatch):
    seen = []

    async def get(host, cred, oids, timeout=15):
        seen.append((host, cred, oids, timeout))
        return {confirm.SYS_UPTIME: "123"}

    monkeypatch.setattr(snmp, "get", get)
    monkeypatch.setattr(poller, "creds_of", lambda row, write=False: {"read": True, "write": write})
    assert await confirm.reachable({"host": "10.0.0.1"}) is True
    assert seen == [("10.0.0.1", {"read": True, "write": False}, [confirm.SYS_UPTIME], confirm.REACH_TIMEOUT_S)]


@pytest.mark.parametrize("answer", [snmp.SnmpError("Timeout"), OSError("x"), {}])
async def test_reachable_is_false_on_any_error_or_no_answer(monkeypatch, answer):
    async def get(*args, **kwargs):
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(snmp, "get", get)
    monkeypatch.setattr(poller, "creds_of", lambda row, write=False: {})
    assert await confirm.reachable({"host": "10.0.0.1"}) is False


async def test_end_to_end_an_unconfirmed_ssh_change_comes_back(ssh_env, monkeypatch):
    """The real run_change twice on the ProCurve of ssh_env: the change waits, its deadline runs out, the watch takes it back through
    _make_plan, start_change and run_change (fresh_cfg reads ssh_env.running and the inventory names port 2, as in
    test_an_approved_change_keeps_the_check_in_the_lock of tests/test_approvals.py; no netmiko session)."""
    asked = []

    async def fresh_cfg(sid, max_age_s=changes.CFG_MAX_AGE_S):
        return parse_config(ssh_env.running)       # the preview's read: the real one opens a netmiko session (sshcli._open)

    async def reachable(row):
        asked.append(row["id"])
        return True

    def trap(*args, **kwargs):
        raise AssertionError("no real SSH session in this test")

    monkeypatch.setattr(changes, "fresh_cfg", fresh_cfg)
    monkeypatch.setattr(confirm, "reachable", reachable)
    monkeypatch.setattr(confirm, "_misses", {})
    monkeypatch.setattr(sshcli, "ConnectHandler", trap)
    cid = await pending_change(ssh_env, monkeypatch, runs=(OFF, sshfix.RUNNING))
    dbfix.query("UPDATE changes SET confirm_until = ? WHERE id = ?", (at(-1), cid))
    assert await confirm.watch() == 1 and asked == []
    [(rid,)] = dbfix.query("SELECT id FROM changes WHERE revert_of = ?", (cid,))
    await until(lambda: not api_changes._tasks)                 # the revert's run to its very end (audit, alerts)
    rev = ssh_env.change(rid)
    assert row(cid)["reverted_by"] == rid and (rev["status"], rev["saved"], rev["username"], rev["role"]) == ("ok", 1, confirm.AUTO_USER, None)
    assert ssh_env.saves == 1 and ssh_env.sent == [["interface 2 disable"], ["interface 2 enable"]]
