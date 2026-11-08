"""Phase 4c, Task 4: a change with confirmation (changes.PENDING, "wartet auf Bestätigung") and "Bestätigen" (app/confirm.py).

A port change started with confirm_minutes runs as every change does (the switch's lock, a fresh read, planned again, sent, read back,
verified), but instead of write memory it waits in the status pending with its deadline in the database (changes.confirm_until, UTC)
and the step changes.PENDING_STEP. "Bestätigen" (confirm.confirm_change, POST /api/changes/{cid}/confirm) takes the same row from
pending over running to ok: over SSH it saves only after a fresh read of the running-config that still holds the change (else
unclear with confirm.DRIFT, nothing saved), over SNMP it ends unsaved as every SNMP change of a driver without snmp_autosave does. It
may confirm who started the change (any case) or approved it, or anyone with Freigeben, always in their zones; of two confirms at
once exactly one wins, and a confirm after the deadline is too late. While a change waits, its switch takes no other change but its
revert, which ends the waiting in the transaction of its INSERT (changes.REVERT_STARTED). The preview says whether a confirmation is
possible (the key confirm of /plan): only for a port change, and not over SNMP at a driver that saves every SET by itself.

The SSH cases run the real run_change against the fake ProCurve of ssh_env (tests/sshfix.py): no network, no switch. The API cases
plan with a fake api_changes._make_plan that names the world's write way (as fake_plan in tests/test_approvals.py) and record the
start of a change instead of running it (changes.run_change).
"""
import asyncio
import json
import types
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from test_change_outcome import OFF, switch_runs, until

import api_changes
import apifix
import changes
import confirm
import dbfix
import roles
import sshfix
from cfgparse import parse_config

TIME = "%Y-%m-%d %H:%M:%S"
ANNA = apifix.user("aendern", "anna")


async def pending_change(env, monkeypatch, minutes=5, user="anna", runs=(OFF,)) -> int:
    """Port 2 off on env's ProCurve with confirmation, as start_change creates it, run by run_change; the switch runs runs[i] after its
    i-th lines (switch_runs: OFF for this change, a test that also sends the revert passes the state after it)."""
    switch_runs(monkeypatch, *runs)
    req, inv = {"ports": ["2"], "set": {"status": "off"}, "expert": False}, {"ports": {"2": {"tr": "", "l": [], "o": False}}, "uplinks": set()}

    async def inventory(sid):
        return inv

    monkeypatch.setattr(changes, "inventory", inventory)
    plan = changes.plan_ports("", inv, parse_config(env.running), req)
    cid = await changes.create_change(env.sid, user, "ports", "Port 2: Aus", req, plan | {"mechanism": "ssh"}, role="aendern",
                                      confirm_minutes=minutes)
    await changes.run_change(cid)
    return cid


async def confirmed(env, cid, user=ANNA) -> dict:
    answer = await confirm.confirm_change(cid, user)
    await until(lambda: env.change(cid)["status"] != "running")
    return answer


async def test_a_change_with_confirmation_is_verified_but_not_saved(ssh_env, monkeypatch):
    cid = await pending_change(ssh_env, monkeypatch)
    ch = ssh_env.change(cid)
    assert (ch["status"], ch["saved"], ch["confirm_minutes"], ch["error"], ssh_env.saves) == ("pending", 0, 5, None, 0)
    deadline = datetime.strptime(ch["confirm_until"], TIME).replace(tzinfo=timezone.utc)
    assert timedelta(minutes=4, seconds=50) < deadline - datetime.now(timezone.utc) <= timedelta(minutes=5)
    assert json.loads(ch["steps"])[-1][1:] == [changes.PENDING_STEP.format(until=deadline.strftime("%H:%M")), "warn"]
    assert dbfix.query("SELECT username, action, role FROM audit") == [("anna", "change_pending", "aendern")]
    assert ssh_env.repolls == [ssh_env.sid] and changes.actions_of(ch) == {"can_revert": True, "can_save": False}


async def test_confirm_saves_after_a_fresh_read(ssh_env, monkeypatch):
    cid = await pending_change(ssh_env, monkeypatch)
    assert await confirmed(ssh_env, cid) == {"ok": True, "id": cid}
    ch = ssh_env.change(cid)
    assert (ch["status"], ch["saved"], ch["confirmed_by"], ssh_env.saves) == ("ok", 1, "anna", 1)
    assert [s[1] for s in json.loads(ch["steps"])][-3:] == [confirm.CONFIRMED_STEP.format(user="anna"), "Speichere (write memory)",
                                                            "Gespeichert"]
    assert dbfix.query("SELECT username, action FROM audit ORDER BY id") == [("anna", "change_pending"), ("anna", "change_confirm"),
                                                                            ("anna", "change_ok")]


async def test_confirm_refuses_to_save_a_switch_that_no_longer_matches(ssh_env, monkeypatch):
    cid = await pending_change(ssh_env, monkeypatch)
    ssh_env.running = sshfix.RUNNING                                                     # port 2 enabled again, outside SwitchView
    await confirmed(ssh_env, cid)
    ch = ssh_env.change(cid)
    assert (ch["status"], ch["saved"], ssh_env.saves) == ("unclear", 0, 0) and ch["error"].startswith(confirm.DRIFT)


async def test_two_confirms_at_once_save_once(ssh_env, monkeypatch):                     # Review Focus 1
    cid = await pending_change(ssh_env, monkeypatch)
    got = await asyncio.gather(confirm.confirm_change(cid, ANNA), confirm.confirm_change(cid, ANNA), return_exceptions=True)
    refused = [g for g in got if isinstance(g, HTTPException)]
    assert len(refused) == 1 and (refused[0].status_code, refused[0].detail) == (409, confirm.NOT_PENDING.format(cid=cid))
    await until(lambda: ssh_env.change(cid)["status"] != "running")
    assert (ssh_env.change(cid)["status"], ssh_env.saves) == ("ok", 1)


async def test_a_confirm_after_the_deadline_is_too_late(ssh_env, monkeypatch):           # Review Focus 1
    cid = await pending_change(ssh_env, monkeypatch)
    dbfix.query("UPDATE changes SET confirm_until = '2000-01-01 00:00:00' WHERE id = ?", (cid,))
    with pytest.raises(HTTPException) as e:
        await confirm.confirm_change(cid, ANNA)
    assert (e.value.status_code, e.value.detail) == (409, confirm.TOO_LATE.format(cid=cid))
    assert (ssh_env.change(cid)["status"], ssh_env.saves) == ("pending", 0)


@pytest.mark.parametrize("who, ok", [
    (apifix.user("aendern", "anna"), True), (apifix.user("aendern", "Anna"), True),       # who started it, in any case
    (apifix.user("aendern", "ben"), False), (apifix.user("freigeben", "ben"), True),
    (apifix.user("aendern", "cleo"), True),                                               # cleo approved it (approved_by)
    (apifix.user("freigeben", "ben", zones=["VK"]), False)])                             # another zone: the zone refuses first
async def test_who_may_confirm(ssh_env, monkeypatch, who, ok):
    cid = await pending_change(ssh_env, monkeypatch)
    dbfix.query("UPDATE changes SET approved_by = 'cleo' WHERE id = ?", (cid,))
    if ok:
        assert (await confirmed(ssh_env, cid, who))["ok"] is True                    # waits for the save it spawned
        return
    with pytest.raises(HTTPException) as e:
        await confirm.confirm_change(cid, who)
    assert (e.value.status_code, e.value.detail) == (403, roles.zone_denial("", ["VK"]) if who["zones"] else confirm.WHO)


async def test_a_pending_change_blocks_every_other_change_but_its_revert(ssh_env, monkeypatch):
    cid = await pending_change(ssh_env, monkeypatch)
    plan = {"shown": ["interface 3 disable"], "desired": {"3": {"en": False}}, "before": {"3": {"en": True}}, "mechanism": "ssh"}
    with pytest.raises(changes.Busy) as e:
        await changes.create_change(ssh_env.sid, "ben", "ports", "Port 3: Aus", {}, plan)
    assert str(e.value) == changes.PENDING_BUSY.format(cid=cid)
    rid = await changes.create_change(ssh_env.sid, "ben", "ports", f"Rückgängig #{cid}", {}, plan, revert_of=cid)
    ch = ssh_env.change(cid)
    assert (ch["status"], ch["error"]) == ("unclear", changes.REVERT_STARTED.format(rid=rid))
    assert json.loads(ch["steps"])[-1][1:] == [changes.REVERT_STARTED.format(rid=rid), "warn"]


# ── The API: the preview, /apply and the route ────────────────────────────────────────────────────────────────────────────────────
PORTS = {"ports": ["2"], "change": {"status": "off"}}


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A fresh database; switch(driver) adds the switch "SW" with that driver (its id). The plan is a fake (api_changes._make_plan):
    "interface 2 disable" for a port change, nothing for a save, over the write way mech ("ssh" unless a test sets it). The start of a
    change is recorded in ran (changes.run_change), the task it would become never has to run."""
    apifix.fresh_db(tmp_path, monkeypatch)
    w = types.SimpleNamespace(mech="ssh", ran=[], switch=lambda driver="procurve", **cols: dbfix.insert_switch(
        name="SW", host="10.0.0.1", driver=driver, **cols))

    async def fake_plan(row, body):
        shown = [] if body.mode == "save" else ["interface 2 disable"]
        plan = {"shown": shown, "commands": shown, "blocked": [], "mechanism": w.mech, "warnings": [], "expert": body.expert,
                "desired": {"2": {"en": False}} if shown else {}, "before": {"2": {"en": True}} if shown else {}}
        kind = "save" if body.mode == "save" else "ports"
        return plan, {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}, kind, api_changes._summary(body)

    def run_fake(cid):
        w.ran.append(cid)

        async def nothing():
            return None
        return nothing()

    monkeypatch.setattr(api_changes, "_make_plan", fake_plan)
    monkeypatch.setattr(changes, "run_change", run_fake)
    return w


@pytest.fixture
def client(world, monkeypatch):
    """A TestClient signed in as apifix.USER (Admin)."""
    with apifix.signed_in(monkeypatch) as c:
        yield c


def preview(client, sid, payload) -> dict:
    r = client.post(f"/api/switches/{sid}/plan", json=payload)
    assert r.status_code == 200, r.text
    return r.json()


def apply(client, sid, payload, **extra):
    p = preview(client, sid, payload)
    return client.post(f"/api/switches/{sid}/apply", json={**payload, "token": p["token"], "mechanism": p["mechanism"], **extra})


@pytest.mark.parametrize("driver, mech, payload, want", [
    ("procurve", "ssh", PORTS, {"possible": True, "why": None}),
    ("procurve", "snmp", PORTS, {"possible": False, "why": api_changes.CONFIRM_AUTOSAVE}),
    ("generic", "snmp", PORTS, {"possible": True, "why": None}),
    ("procurve", "ssh", {"mode": "revert", "of": 1}, {"possible": False, "why": api_changes.CONFIRM_ONLY_PORTS})])
def test_the_preview_says_whether_confirmation_is_possible(world, client, driver, mech, payload, want):
    sid, world.mech = world.switch(driver), mech
    assert preview(client, sid, payload)["confirm"] == want | {"default_minutes": 5, "max_minutes": 30}


def test_apply_hands_the_minutes_to_the_change_or_refuses_them(world, client):
    sid, world.mech = world.switch("procurve"), "snmp"                  # a ProCurve saves every SNMP SET by itself
    r = apply(client, sid, PORTS, confirm_minutes=7)
    assert (r.status_code, r.json()["detail"]) == (409, api_changes.CONFIRM_AUTOSAVE)
    assert dbfix.query("SELECT count(*) FROM changes") == [(0,)] and world.ran == []
    world.mech = "ssh"
    r = apply(client, sid, PORTS, confirm_minutes=7)
    assert r.status_code == 200, r.text
    cid = r.json()["id"]
    assert dbfix.query("SELECT confirm_minutes, confirm_until, status FROM changes WHERE id = ?", (cid,)) == [(7, None, "queued")]
    assert world.ran == [cid]


@pytest.mark.parametrize("minutes", [0, 31, "5", True])
def test_the_minutes_are_bounded(world, client, minutes):
    sid = world.switch("procurve")
    assert apply(client, sid, PORTS, confirm_minutes=minutes).status_code == 422
    assert dbfix.query("SELECT count(*) FROM changes") == [(0,)] and world.ran == []


def test_the_confirm_route_answers_for_what_it_finds(world, client):
    sid = world.switch("procurve")
    r = client.post("/api/changes/999/confirm")
    assert (r.status_code, r.json()["detail"]) == (404, confirm.NOT_FOUND)
    [(done,)] = dbfix.query("INSERT INTO changes(switch_id, username, kind, summary, status, steps, mechanism, sent, confirm_minutes) "
                            "VALUES (?, 'anna', 'ports', 'Port 2: Aus', 'ok', '[]', 'ssh', 1, 5) RETURNING id", (sid,))
    r = client.post(f"/api/changes/{done}/confirm")
    assert (r.status_code, r.json()["detail"]) == (409, confirm.NOT_PENDING.format(cid=done))
    deadline = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime(TIME)
    [(waiting,)] = dbfix.query("INSERT INTO changes(switch_id, username, kind, summary, status, steps, mechanism, sent, confirm_minutes, "
                               "confirm_until) VALUES (?, 'anna', 'ports', 'Port 2: Aus', 'pending', '[]', 'ssh', 1, 5, ?) RETURNING id",
                               (sid, deadline))
    dbfix.query("UPDATE switches SET enabled = 0 WHERE id = ?", (sid,))
    r = client.post(f"/api/changes/{waiting}/confirm")
    assert (r.status_code, r.json()["detail"]) == (409, api_changes.DISABLED)
    assert dbfix.query("SELECT status, confirmed_by FROM changes WHERE id = ?", (waiting,)) == [("pending", None)]
