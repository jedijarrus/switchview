"""Phase 3 Task 6: what a change checks before anything goes out.

  * Inside the switch lock: run_change (SSH) and _run_snmp read the switch row again once they hold sshcli.lock(sid), and a switch that
    was disabled meanwhile ends the change "failed" with "Switch ist deaktiviert: nichts gesendet", before anything else, and without
    a re-poll: a change that ends "failed" re-polls only when it sent something (Phase 5 Task 10). The inventory
    (changes.inventory, the poll's ports and uplinks) is read only after that, inside the lock: a change that waited may find a poll a
    change before it renewed.
  * A disabled switch gets no change in any mode: POST /plan and /apply answer 409 main.DISABLED; main._inventory turns the LookupError
    of changes.inventory (the switch is not in the map) into the same 409 at each of its call sites.
  * One change at a time per switch: changes.create_change reads in BEGIN IMMEDIATE whether the switch has a queued or running change
    and raises changes.Busy, else it inserts in the same transaction; /apply answers 409 changes.BUSY either way, its early check stays.
  * The stale mark: switch_cfg.stale (1 once an SNMP SET or SSH lines may have changed the switch since the read, changes.mark_cfg_stale;
    taken_at stays the time of the read). /api/netmap serves it as "cfgStale", and while it is set a port's on / off comes from the
    poll, not from the read.

No network, no switch: the API runs in-process (FastAPI TestClient without `with`, so no lifespan and no scheduler; an httpx
AsyncClient on the same app for the concurrent requests) against a fresh database per test; run_change talks to the fake ProCurve of
ssh_env (tests/sshfix.py). Only seams Task 11 keeps are replaced: on changes the SSH read, the inventory and the run; netmiko's
ConnectHandler and the SNMP calls are traps wherever a request could reach them (no_io).
"""
import asyncio
import json

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import auth
import cfgparse
import changes
import config
import db
import dbfix
import main
import snmp
import snmpwrite
import sshcli
import sshfix
from loginfix import CSRF
from test_secret_destination import USER, create

DISABLED_RUN = "Switch ist deaktiviert: nichts gesendet"
PLAN = {"shown": [], "desired": {}, "before": {}, "mechanism": "ssh"}
FOUR_PORTS = "vlan 1\n   untagged 1-4\n   exit\n"    # ports 1-4 untagged in VLAN 1, all on
# The inventory of a ProCurve whose poll knows the ports 1 and 2, no uplinks
PORT_INV = {"ports": {p: {"n": p, "tr": "", "l": [], "o": False} for p in ("1", "2")}, "uplinks": set()}
PORT2_OFF = sshfix.RUNNING + "interface 2\n   disable\n   exit\n"    # ssh_env's ProCurve once it took "interface 2 disable"


def _never(*args, **kwargs):
    raise AssertionError("the scheduler must not start in a test (no background polling, no network)")


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app signed in as USER, against a fresh database under tmp_path set up by the app's own init_db (as in
    tests/test_secret_destination.py)."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    monkeypatch.setattr(main.scheduler, "start", _never)
    asyncio.run(db.init_db())
    main.app.dependency_overrides[auth.current_user] = lambda: USER
    try:
        yield TestClient(main.app, headers=CSRF)
    finally:
        main.app.dependency_overrides.pop(auth.current_user, None)


@pytest.fixture
async def api_async(api):
    """An httpx.AsyncClient on main.app in the test's own event loop, so that requests really run concurrently; through api the same
    database and the same user override (as in tests/test_secret_destination.py)."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test", headers=CSRF) as client:
        yield client


class Gate:
    """changes.fresh_cfg for the race: each call counts itself in `waiting` and waits until set(), then answers FOUR_PORTS parsed."""

    def __init__(self):
        self.waiting = 0
        self.event = asyncio.Event()

    async def fresh_cfg(self, sid: int, max_age_s: int = changes.CFG_MAX_AGE_S) -> dict:
        self.waiting += 1
        await self.event.wait()
        return cfgparse.parse_config(FOUR_PORTS)

    def set(self):
        self.event.set()


@pytest.fixture
def gate(monkeypatch) -> Gate:
    """The SSH read of the preview waits at a Gate; the inventory knows port 1 (no uplinks); run_change does nothing."""
    g = Gate()

    async def inventory(sid):
        return {"ports": {"1": {"n": "1", "tr": "", "l": [], "o": False}}, "uplinks": set()}

    async def nothing():
        return None

    monkeypatch.setattr(changes, "fresh_cfg", g.fresh_cfg)
    monkeypatch.setattr(changes, "inventory", inventory)
    monkeypatch.setattr(changes, "run_change", lambda cid: nothing())
    return g


@pytest.fixture
def no_io(monkeypatch):
    """Every way to a switch is a trap: netmiko's ConnectHandler and the SNMP calls fail the test before anything leaves the process."""
    def trap(*args, **kwargs):
        raise AssertionError("no switch I/O in this test")

    async def async_trap(*args, **kwargs):
        trap()

    monkeypatch.setattr(sshcli, "ConnectHandler", trap)
    for name in ("get", "walk", "set_vars"):
        monkeypatch.setattr(snmp, name, async_trap)


@pytest.fixture
def port_inv(monkeypatch) -> list[bool]:
    """changes.inventory answers PORT_INV; the list records, per call, whether the switch's lock was held then. The fake ProCurve of
    ssh_env takes the lines it is sent: after "interface 2 disable" it runs PORT2_OFF."""
    seen: list[bool] = []
    real = sshfix.FakeSSH.send_config_set

    async def inventory(sid):
        seen.append(sshcli.lock(sid).locked())
        return PORT_INV

    def send(self, commands, **kwargs):
        assert list(commands) == ["interface 2 disable"], commands
        self.env.running = PORT2_OFF
        return real(self, commands, **kwargs)

    monkeypatch.setattr(changes, "inventory", inventory)
    monkeypatch.setattr(sshfix.FakeSSH, "send_config_set", send)
    return seen


async def until(cond):
    """Wait in steps of 10 ms, at most 5 s, for cond() to hold."""
    for _ in range(500):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not reached in 5 s")


def count_changes(sid: int) -> int:
    return dbfix.query("SELECT count(*) FROM changes WHERE switch_id = ?", (sid,))[0][0]


async def port2_off(env) -> int:
    """The change "port 2 off" of env's ProCurve, planned on its running-config against PORT_INV, created (queued); its id."""
    req = {"ports": ["2"], "set": {"status": "off"}}
    plan = changes.plan_ports("", PORT_INV, cfgparse.parse_config(env.running), req)
    assert (plan["blocked"], plan["commands"]) == ([], ["interface 2 disable"]), plan
    return await changes.create_change(env.sid, "tester", "ports", "Port 2: Aus", req, plan)


async def waited_change(env, *, disable: bool) -> int:
    """Run "port 2 off" while another action holds the switch's lock; once the run waits for it, disable the switch (if disable), then
    release the lock and let the run end. Its id."""
    cid = await port2_off(env)
    lock = sshcli.lock(env.sid)
    await lock.acquire()
    task = asyncio.create_task(changes.run_change(cid))
    try:
        await until(lambda: "Warte auf laufende Aktion" in env.change(cid)["steps"])
        if disable:
            dbfix.query("UPDATE switches SET enabled = 0 WHERE id = ?", (env.sid,))
    finally:
        lock.release()
    await task
    return cid


# ── One change at a time per switch ───────────────────────────────────────────────────────────────────────────────────────────────
async def test_two_concurrent_applies_create_one_change(api, api_async, gate, no_io):
    sid = create(api, ssh_user="manager", ssh_pass="ssh-s3cret")        # a ProCurve with SSH: the plan goes through fresh_cfg
    body = {"ports": ["1"], "change": {"status": "off"}, "token": changes.cmd_token(["interface 1 disable"])}
    tasks = [asyncio.create_task(api_async.post(f"/api/switches/{sid}/apply", json=body)) for _ in range(2)]
    await until(lambda: gate.waiting == 2)                               # both are past the early check
    gate.set()
    responses = await asyncio.gather(*tasks)
    assert sorted(r.status_code for r in responses) == [200, 409] and count_changes(sid) == 1
    assert next(r for r in responses if r.status_code == 409).json()["detail"] == changes.BUSY


async def test_create_change_refuses_a_second_running_change(ssh_env):
    await changes.create_change(ssh_env.sid, "t", "ports", "a", {}, PLAN)
    with pytest.raises(changes.Busy, match="läuft gerade"):
        await changes.create_change(ssh_env.sid, "t", "ports", "b", {}, PLAN)
    assert count_changes(ssh_env.sid) == 1


@pytest.mark.parametrize("status, refused", [("queued", True), ("running", True), ("ok", False), ("unclear", False), ("failed", False),
                                             ("aborted", False)])
async def test_only_a_queued_or_running_change_blocks_the_next(ssh_env, status, refused):
    """A finished change, whatever its end, leaves the switch free; another switch's running change says nothing about this one."""
    other = dbfix.insert_switch(name="SW-EK-02", host="203.0.113.22", driver="procurve")
    await changes.create_change(other, "t", "ports", "anderer Switch", {}, PLAN)
    first = await changes.create_change(ssh_env.sid, "t", "ports", "a", {}, PLAN)
    dbfix.query("UPDATE changes SET status = ? WHERE id = ?", (status, first))
    if refused:
        with pytest.raises(changes.Busy, match=changes.BUSY):
            await changes.create_change(ssh_env.sid, "t", "ports", "b", {}, PLAN)
    else:
        assert await changes.create_change(ssh_env.sid, "t", "ports", "b", {}, PLAN) > first
    assert count_changes(ssh_env.sid) == (1 if refused else 2)


# ── A disabled switch gets no change ──────────────────────────────────────────────────────────────────────────────────────────────
def test_plan_and_apply_on_a_disabled_switch_are_409(api, no_io):
    sid = create(api, enabled=False)
    for path in ("plan", "apply"):
        r = api.post(f"/api/switches/{sid}/{path}", json={"ports": ["1"], "change": {"status": "off"}})
        assert (r.status_code, r.json()["detail"]) == (409, main.DISABLED)


@pytest.mark.parametrize("payload", [{"mode": "prepare"}, {"mode": "save", "of": 1}, {"mode": "revert", "of": 1}],
                         ids=["prepare", "save", "revert"])
def test_every_mode_on_a_disabled_switch_is_409(api, no_io, payload):
    """Also "Vorbereiten", "Speichern" and "Rückgängig" (one rule for every mode), on a switch with SSH access and a change to save or
    take back: 409 before anything is read."""
    sid = create(api, enabled=False, ssh_user="manager", ssh_pass="ssh-s3cret")
    dbfix.query("INSERT INTO changes(switch_id, kind, summary, status, before, mechanism, sent) VALUES (?, 'ports', 'Port 1: Aus', "
                "'unclear', ?, 'ssh', 1)", (sid, json.dumps({"1": {"en": True}})))
    for path in ("plan", "apply"):
        r = api.post(f"/api/switches/{sid}/{path}", json=payload)
        assert (r.status_code, r.json()["detail"]) == (409, main.DISABLED)


@pytest.mark.parametrize("way", ["ssh", "snmp", "revert"])
async def test_a_switch_that_leaves_the_map_while_planning_is_409(api, no_io, monkeypatch, way):
    """The switch is disabled between the start of the request and its read of the inventory: the LookupError of changes.inventory
    (the switch is not in the map) is 409 main.DISABLED at each call site (_make_plan, _plan_snmp, _plan_revert), never a 500."""
    if way == "snmp":
        sid = create(api, snmp_write=True, snmp_rw_community="rw-s3cret")
    else:
        sid = create(api, ssh_user="manager", ssh_pass="ssh-s3cret")
    row = await main._row(sid)
    dbfix.query("UPDATE switches SET enabled = 0 WHERE id = ?", (sid,))

    async def fresh_cfg(sid, max_age_s=changes.CFG_MAX_AGE_S):
        return cfgparse.parse_config(FOUR_PORTS)

    async def read_cfg(row, driver, *, with_poe=False):
        return {"ports": {"1": {}}}, {}

    monkeypatch.setattr(changes, "fresh_cfg", fresh_cfg)
    monkeypatch.setattr(snmpwrite, "read_cfg", read_cfg)
    if way == "revert":
        [(cid,)] = dbfix.query("INSERT INTO changes(switch_id, kind, summary, status, before, mechanism, sent) VALUES (?, 'ports', "
                               "'Port 1: Aus', 'ok', ?, 'ssh', 1) RETURNING id", (sid, json.dumps({"1": {"en": True}})))
        payload = main.PlanIn(mode="revert", of=cid)
    else:
        payload = main.PlanIn(ports=["1"], change={"status": "off"})
    with pytest.raises(HTTPException) as e:
        await main._make_plan(row, payload)
    assert (e.value.status_code, e.value.detail) == (409, main.DISABLED)


async def test_a_switch_disabled_while_the_change_waits_gets_nothing(ssh_env, port_inv):
    row = ssh_env.change(await waited_change(ssh_env, disable=True))
    assert (row["status"], row["error"], row["sent"], ssh_env.sent) == ("failed", DISABLED_RUN, 0, [])
    assert [s[1:] for s in json.loads(row["steps"])] == [["Warte auf laufende Aktion an diesem Switch", "info"], [DISABLED_RUN, "error"]]


async def test_a_failed_change_re_polls_only_when_it_sent_something(ssh_env, port_inv):         # Phase 3 T6-R2
    row = ssh_env.change(await waited_change(ssh_env, disable=True))
    assert (row["status"], row["sent"], ssh_env.repolls) == ("failed", 0, [])


@pytest.mark.parametrize("kind", ["save", "prepare"])
async def test_a_disabled_switch_gets_no_save_or_prepare_either(ssh_env, kind):
    """Speichern and Vorbereiten are refused the same way, without a session."""
    dbfix.query("UPDATE switches SET enabled = 0 WHERE id = ?", (ssh_env.sid,))
    cid = await changes.create_change(ssh_env.sid, "tester", kind, kind, {}, PLAN)
    await changes.run_change(cid)
    row = ssh_env.change(cid)
    assert (row["status"], row["error"], row["sent"], ssh_env.sent) == ("failed", DISABLED_RUN, 0, [])


async def test_the_positive_control_a_switch_left_enabled_while_waiting_gets_the_change(ssh_env, port_inv):
    row = ssh_env.change(await waited_change(ssh_env, disable=False))
    assert (row["status"], ssh_env.sent) == ("ok", [["interface 2 disable"]])


async def test_the_inventory_is_read_after_the_lock(ssh_env, port_inv):
    """changes.inventory runs inside sshcli.lock(sid), once: a change that waited for the lock plans against the poll as it is then."""
    cid = await port2_off(ssh_env)
    await changes.run_change(cid)
    assert (ssh_env.change(cid)["status"], port_inv) == ("ok", [True])


@pytest.mark.parametrize("kind", ["save", "prepare"])
async def test_save_and_prepare_read_no_inventory(ssh_env, port_inv, kind):
    """Only a port change needs the poll's ports and uplinks."""
    cid = await changes.create_change(ssh_env.sid, "tester", kind, kind, {}, PLAN)
    await changes.run_change(cid)
    assert ssh_env.change(cid)["finished_at"] is not None and port_inv == []


# ── The stale mark ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("stale, st", [(1, "off"), (0, "protected")])
async def test_build_map_marks_a_stale_config_and_takes_on_off_from_the_poll(api, stale, st):
    """A ProCurve whose poll has port 2 administratively down and whose stored read (switch_cfg) has it on: while the read is stale,
    port 2 is "off" (the poll), else "protected" (the read)."""
    sid = dbfix.insert_switch(name="SW-EK-01", host="203.0.113.21", driver="procurve", enabled=1)
    dbfix.query("INSERT INTO ports(switch_id, ifindex, name, oper, admin) VALUES (?, 2, '2', 0, 0)", (sid,))
    dbfix.query("INSERT INTO switch_cfg(switch_id, taken_at, parsed, stale) VALUES (?, '2026-11-06 08:00:00', ?, ?)",
                (sid, json.dumps(cfgparse.parse_config(FOUR_PORTS)), stale))
    m = await main.build_map()
    s = m["switches"][0]
    assert s["cfgStale"] is bool(stale) and next(p for p in s["ports"] if p["n"] == "2")["st"] == st
    assert s["cfgAt"] == "2026-11-06 08:00:00"                          # the time of the read, stale or not


@pytest.mark.parametrize("admin, x, m, st", [(1, False, False, "protected"), (1, False, True, "known"), (1, True, True, "radius"),
                                             (0, True, True, "off")])
async def test_a_stale_read_keeps_its_nac_state_for_a_port_the_poll_shows_on(api, admin, x, m, st):
    """On / off from the poll, the rest (Protected, Bekannte Geräte, RADIUS) still from the read: the read's own "disable" no longer
    counts once it is stale."""
    sid = dbfix.insert_switch(name="SW-EK-01", host="203.0.113.21", driver="procurve", enabled=1)
    dbfix.query("INSERT INTO ports(switch_id, ifindex, name, oper, admin) VALUES (?, 3, '3', ?, ?)", (sid, admin, admin))
    nac = (["aaa port-access authenticator 3"] if x else []) + (["aaa port-access mac-based 3"] if m else [])
    cfg = cfgparse.parse_config(FOUR_PORTS + "interface 3\n   disable\n   exit\n" + "".join(line + "\n" for line in nac))
    read = cfgparse.port_state(cfg, "3")
    assert (read["en"], read["x"], read["m"]) == (False, x, m)              # the read: off, with its NAC state
    dbfix.query("INSERT INTO switch_cfg(switch_id, taken_at, parsed, stale) VALUES (?, '2026-11-06 08:00:00', ?, 1)",
                (sid, json.dumps(cfg)))
    port = next(p for p in (await main.build_map())["switches"][0]["ports"] if p["n"] == "3")
    assert port["st"] == st


async def test_mark_cfg_stale_keeps_the_read_and_store_cfg_clears_the_mark(ssh_env):
    await changes.store_cfg(ssh_env.sid, FOUR_PORTS)
    [(young,)] = dbfix.query("SELECT taken_at FROM switch_cfg WHERE switch_id = ?", (ssh_env.sid,))
    await changes.mark_cfg_stale(ssh_env.sid)
    assert await changes.cached_cfg(ssh_env.sid) == (cfgparse.parse_config(FOUR_PORTS), young, True)
    await changes.store_cfg(ssh_env.sid, FOUR_PORTS)
    assert (await changes.cached_cfg(ssh_env.sid))[2] is False
    assert await changes.cached_cfg(ssh_env.sid + 1) == (None, None, False)     # no read stored


async def test_fresh_cfg_reads_again_for_a_stale_entry(ssh_env, monkeypatch):
    """A young entry marked stale is not served: fresh_cfg reads for real, and the read clears the mark."""
    reads: list[int] = []

    async def backup_config(sid, trigger="nightly"):
        reads.append(sid)
        await changes.store_cfg(sid, ssh_env.running)
        return {"ok": True, "changed": False}

    monkeypatch.setattr(sshcli, "backup_config", backup_config)
    await changes.store_cfg(ssh_env.sid, FOUR_PORTS)
    assert await changes.fresh_cfg(ssh_env.sid) == cfgparse.parse_config(FOUR_PORTS) and reads == []
    await changes.mark_cfg_stale(ssh_env.sid)
    assert await changes.fresh_cfg(ssh_env.sid) == cfgparse.parse_config(ssh_env.running) and reads == [ssh_env.sid]
    assert (await changes.cached_cfg(ssh_env.sid))[2] is False
