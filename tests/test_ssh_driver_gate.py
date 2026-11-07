"""R37 / R39: every SSH-only path respects the switch's driver. netmiko speaks to a switch as hp_procurve with ProCurve commands, and
only the ProCurve parser and masker read the answer; so a switch whose driver has no SSH-CLI (the cap cli: every driver but procurve)
never gets an SSH session, not even with SSH credentials stored (they are kept, never used). The paths of the review's R37 table:
  1. the nightly backup (sshcli.backup_all) skips a driver without backup, with no session and no error noise;
  2. POST /api/switches/{sid}/backup (backup), 3. /config/refresh and 4. /port-access (cli) answer 409 with a German reason;
  5. POST /test reports SSH as "nicht verwendet (Treiber ohne CLI)", not as a failure;
  6. changes.fresh_cfg refuses on its own, even with a cached read from before a driver change;
  7. run_change's SSH branch re-reads the switch row after taking the lock and refuses a driver without cli: nothing sent;
  8. build_map ignores switch_cfg for a driver without cli (a ProCurve misparse would show every port as "Protected");
  and below all of them the one choke point: sshcli._device, which connect and _run_show (everything that reaches ConnectHandler) go
  through. 9-11 are the UI (Backups view, connection test, SSH fieldset); the server side of 11 (stored credentials kept) is here.

netmiko's ConnectHandler is replaced by a recorder (sshcli.ConnectHandler, tests/sshfix.py): a switch without cli must never reach it, and a ProCurve
must still get its session (the positive control, so no check here passes by never trying). A recorder, not a raise: several of
these paths catch every exception and would turn an AssertionError into an ordinary error result. No network: the SNMP part of the
connection test is faked, re-polls are recorded, never run. Expected messages are written out by hand.
"""
import asyncio
import json
import logging
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone

import pytest

import apifix
import cfgparse
import changes
import crypto
import db
import main
import snmp
import sshcli
from sshfix import Sessions

NO_CLI = "Treiber cisco hat keine SSH-CLI"
UNUSED = {"ok": None, "unused": True, "detail": "nicht verwendet (Treiber ohne CLI)"}
PC_HOST, CISCO_HOST = "203.0.113.21", "203.0.113.31"
RUNNING_CONFIG = 'hostname "SW-EK-01"\nvlan 1\n   name "DEFAULT_VLAN"\n   untagged 1-24\n   exit\ninterface 3\n   disable\n   exit\n'


@pytest.fixture
def world(tmp_path, monkeypatch) -> Sessions:
    """A fresh database under tmp_path (the app's own init_db); ConnectHandler recorded; fresh locks and R27 marks; re-polls recorded."""
    apifix.fresh_db(tmp_path, monkeypatch)
    sessions = Sessions(RUNNING_CONFIG)
    monkeypatch.setattr(sshcli, "ConnectHandler", sessions)
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    monkeypatch.setattr(changes, "_cfg_stale", set())
    monkeypatch.setattr(changes, "_repoll", sessions.repoll)
    return sessions


@pytest.fixture
def api(world, monkeypatch):
    """A TestClient on main.app (created without `with`: no lifespan, no scheduler), signed in as apifix.USER."""
    with apifix.signed_in(monkeypatch) as client:
        yield client


def query(sql: str, args: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(db.settings.db_path)
    try:
        rows = conn.execute(sql, args).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def add_switch(driver: str, host: str, *, ssh: bool = True) -> int:
    """A switches row with SSH credentials (unless ssh is False): manager / an encrypted password."""
    cols = {"name": f"SW-{driver}", "host": host, "driver": driver, "snmp_version": "2c", "snmp_community": crypto.encrypt("read-s3cret")}
    if ssh:
        cols |= {"ssh_user": "manager", "ssh_pass": crypto.encrypt("ssh-s3cret")}
    conn = sqlite3.connect(db.settings.db_path)
    try:
        cur = conn.execute(f"INSERT INTO switches ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(cols.values()))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def young_cfg(sid: int, text: str = RUNNING_CONFIG):
    """A young switch_cfg entry (the cache of fresh_cfg), as a read of the running-config leaves it."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    query("INSERT INTO switch_cfg(switch_id, taken_at, parsed) VALUES (?,?,?)", (sid, now, json.dumps(cfgparse.parse_config(text))))


async def row_of(sid: int):
    async with db.db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)) as cur:
            return await cur.fetchone()


# ── The choke point: sshcli._device ───────────────────────────────────────────────────────────────────────────────────────────────
async def test_no_ssh_session_for_a_driver_without_cli(world):
    """connect and _run_show (and so run_shows, test_ssh, backup_config) reach ConnectHandler only through _device, which refuses a
    driver without cli with the German reason; a ProCurve gets its session."""
    cisco, pc = await row_of(add_switch("cisco", CISCO_HOST)), await row_of(add_switch("procurve", PC_HOST))
    for call in (lambda: sshcli.connect(cisco), lambda: sshcli._run_show(cisco, ["show version"])):
        with pytest.raises(sshcli.NoCliError, match=f"^{NO_CLI}$"):
            call()
    with pytest.raises(sshcli.NoCliError, match=f"^{NO_CLI}$"):
        await sshcli.run_shows(cisco, ["show port-access authenticator"])
    assert world.hosts == []
    sshcli.connect(pc)
    assert (await sshcli.run_shows(pc, ["show version"]))["show version"] == sshcli.clean(RUNNING_CONFIG)
    assert world.hosts == [PC_HOST, PC_HOST]


# ── 1. The nightly backup ─────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_nightly_backup_skips_a_driver_without_backup_silently(world, caplog):
    """backup_all backs up the ProCurve and skips the Catalyst (SSH credentials stored and all): no session, no backup, no switch_cfg
    from a ProCurve misparse, and no warning in the log for it."""
    cisco, pc = add_switch("cisco", CISCO_HOST), add_switch("procurve", PC_HOST)
    with caplog.at_level(logging.WARNING):
        await sshcli.backup_all()
    assert world.hosts == [PC_HOST]
    assert query("SELECT switch_id, trigger FROM config_backups") == [(pc, "nightly")]
    assert query("SELECT switch_id FROM switch_cfg") == [(pc,)]
    assert [r.getMessage() for r in caplog.records] == []
    assert query("SELECT ssh_user FROM switches WHERE id = ?", (cisco,)) == [("manager",)]    # kept, never used


async def test_backup_config_refuses_a_driver_without_cli(world):
    """backup_config itself (behind the nightly backup, the manual one, the config refresh and fresh_cfg) answers with the reason."""
    assert await sshcli.backup_config(add_switch("cisco", CISCO_HOST), "manual") == {"ok": False, "error": NO_CLI}
    assert world.hosts == [] and query("SELECT count(*) FROM config_backups") == [(0,)]


# ── 2.-4. The API endpoints ───────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path, detail", [
    ("backup", "Konfiguration sichern geht nur über die SSH-CLI (ProCurve), Treiber cisco kann das nicht"),
    ("config/refresh", "Konfiguration lesen geht nur über die SSH-CLI (ProCurve), Treiber cisco kann das nicht"),
    ("port-access", "Anmeldungen anzeigen geht nur über die SSH-CLI (ProCurve), Treiber cisco kann das nicht"),
])
@pytest.mark.parametrize("ssh", [True, False])
def test_ssh_only_endpoints_answer_409_for_a_driver_without_cli(api, world, path, detail, ssh):
    sid = add_switch("cisco", CISCO_HOST, ssh=ssh)
    r = api.post(f"/api/switches/{sid}/{path}")
    assert (r.status_code, r.json()) == (409, {"detail": detail})
    assert world.hosts == [] and query("SELECT count(*) FROM config_backups") == [(0,)]


@pytest.mark.parametrize("path", ["backup", "config/refresh", "port-access"])
def test_ssh_only_endpoints_still_work_for_procurve(api, world, path):
    r = api.post(f"/api/switches/{add_switch('procurve', PC_HOST)}/{path}")
    assert r.status_code == 200, r.text
    assert world.hosts == [PC_HOST]


# ── 5. The connection test ────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ssh", [True, False])
def test_connection_test_reports_ssh_unused_for_a_driver_without_cli(api, world, monkeypatch, ssh):
    """Not "fehlgeschlagen" (the switch needs no SSH, with or without credentials stored) and no session; SNMP is tested as always."""
    async def get(host, cred, oids, timeout=15):
        return {"1.3.6.1.2.1.1.5.0": "SW-cisco"}
    monkeypatch.setattr(snmp, "get", get)
    r = api.post(f"/api/switches/{add_switch('cisco', CISCO_HOST, ssh=ssh)}/test")
    assert r.json() == {"snmp": {"ok": True, "detail": "SW-cisco"}, "ssh": UNUSED, "warnings": []}    # a readable community: no warning
    assert world.hosts == []
    r = api.post(f"/api/switches/{add_switch('procurve', PC_HOST)}/test")
    assert r.json()["ssh"] == {"ok": True, "detail": 'hostname "SW-EK-01"'} and world.hosts == [PC_HOST]


# ── 6. fresh_cfg ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_fresh_cfg_refuses_a_driver_without_cli_even_from_the_cache(world):
    """A young cached read from before a driver change is no configuration of this switch any more: refused, never served."""
    sid = add_switch("cisco", CISCO_HOST)
    young_cfg(sid)
    with pytest.raises(RuntimeError, match=f"^{NO_CLI}$"):
        await changes.fresh_cfg(sid)
    with pytest.raises(RuntimeError, match=f"^{NO_CLI}$"):
        await changes.fresh_cfg(sid, max_age_s=0)
    assert world.hosts == []
    pc = add_switch("procurve", PC_HOST)
    young_cfg(pc)
    assert await changes.fresh_cfg(pc) == cfgparse.parse_config(RUNNING_CONFIG) and world.hosts == []    # from the cache, as before


# ── 7. run_change, SSH branch ─────────────────────────────────────────────────────────────────────────────────────────────────────
async def ssh_change(sid: int) -> int:
    """A port change over SSH as /apply creates one on a ProCurve ("interface 3 enable")."""
    plan = {"desired": {"3": {"en": True}}, "before": {"3": {"en": False}}, "shown": ["interface 3 enable"], "blocked": [],
            "mechanism": "ssh"}
    return await changes.create_change(sid, "tester", "ports", "Port 3: An", {"ports": ["3"], "set": {"status": "on"}}, plan)


async def change_of(cid: int) -> dict:
    async with db.db() as conn:
        async with conn.execute("SELECT status, error, saved, steps FROM changes WHERE id = ?", (cid,)) as cur:
            r = dict(await cur.fetchone())
    return r | {"steps": [(text, level) for _, text, level in json.loads(r["steps"])]}


async def test_run_change_ssh_refuses_a_driver_without_cli(world):
    """An SSH change of a switch whose driver is now cisco (changed after /apply): failed, nothing sent, no session, no backup."""
    sid = add_switch("procurve", PC_HOST)
    cid = await ssh_change(sid)
    query("UPDATE switches SET driver = 'cisco' WHERE id = ?", (sid,))
    await changes.run_change(cid)
    ch = await change_of(cid)
    assert (ch["status"], ch["error"], ch["saved"], ch["steps"]) == ("failed", f"{NO_CLI}: nichts gesendet", 0,
                                                                    [(f"{NO_CLI}: nichts gesendet", "error")])
    assert world.hosts == [] and query("SELECT count(*) FROM config_backups") == [(0,)]


async def test_run_change_ssh_rereads_the_switch_row_after_the_lock(world):
    """The mirror of R33: the driver changes to cisco while the change waits for the switch's lock (the row read before the lock still
    says procurve). After the wait the row of then counts: refused, nothing sent."""
    sid = add_switch("procurve", PC_HOST)
    cid = await ssh_change(sid)
    lock = sshcli.lock(sid)
    await lock.acquire()
    task = asyncio.create_task(changes.run_change(cid))
    for _ in range(300):
        if (await change_of(cid))["steps"]:
            break
        await asyncio.sleep(0.01)
    query("UPDATE switches SET driver = 'cisco' WHERE id = ?", (sid,))
    lock.release()
    await task
    ch = await change_of(cid)
    assert (ch["status"], ch["error"]) == ("failed", f"{NO_CLI}: nichts gesendet")
    assert ch["steps"] == [("Warte auf laufende Aktion an diesem Switch", "info"), (f"{NO_CLI}: nichts gesendet", "error")]
    assert world.hosts == []


async def test_run_change_ssh_still_runs_for_procurve(world):
    """The positive control: the same change on the ProCurve connects and reads its configuration (and then aborts, since the empty
    inventory of this test has no port 3, which is beside the point: the session was opened)."""
    sid = add_switch("procurve", PC_HOST)
    cid = await ssh_change(sid)
    await changes.run_change(cid)
    assert world.hosts == [PC_HOST]
    assert (await change_of(cid))["steps"][:2] == [(f"Verbinde mit {PC_HOST}", "info"), ("Konfiguration vorher gelesen", "info")]


# ── 8. build_map ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
NAC_CONFIG = RUNNING_CONFIG + "aaa port-access authenticator 1\naaa port-access authenticator active\n"


async def test_build_map_ignores_switch_cfg_of_a_driver_without_cli(world):
    """A Catalyst with a switch_cfg entry (a ProCurve misparse, or one from before a driver change) is shown as never read: port states
    from the poll alone ("off" for an admin-down port, unknown otherwise), no limit, no read time, no RADIUS readiness. The ProCurve
    keeps what its read says (port 1 RADIUS, port 3 off)."""
    for sid, host in ((add_switch("cisco", CISCO_HOST), CISCO_HOST), (add_switch("procurve", PC_HOST), PC_HOST)):
        query("INSERT INTO ports(switch_id, ifindex, name, admin, oper) VALUES (?, 1, '1', 1, 1), (?, 3, '3', 0, 0)", (sid, sid))
        young_cfg(sid, NAC_CONFIG)
    m = await main.build_map()
    by_driver = {s["driver"]: s for s in m["switches"]}
    cisco, pc = by_driver["cisco"], by_driver["procurve"]
    assert [(p["n"], p["st"], p["lim"]) for p in cisco["ports"]] == [("1", "", None), ("3", "off", None)]
    assert (cisco["cfgAt"], cisco["ready"]) == (None, None)
    assert [(p["n"], p["st"], p["lim"]) for p in pc["ports"]] == [("1", "radius", None), ("3", "off", None)]
    assert pc["cfgAt"] is not None and pc["ready"]["active"] is True


# ── 11. Stored SSH credentials of a non-CLI switch are kept ───────────────────────────────────────────────────────────────────────
def test_a_driver_change_keeps_the_ssh_credentials(api, world):
    """Switching the driver to cisco (the form sends the stored SSH user and leaves the password alone) keeps the SSH access stored,
    unused; switching back to procurve uses it again."""
    sid = add_switch("procurve", PC_HOST)
    body = {"name": "SW-procurve", "host": PC_HOST, "ssh_user": "manager", "ssh_pass": None}
    assert api.put(f"/api/switches/{sid}", json={**body, "driver": "cisco"}).status_code == 200
    stored = query("SELECT driver, ssh_user, ssh_pass FROM switches WHERE id = ?", (sid,))[0]
    assert stored[:2] == ("cisco", "manager") and crypto.decrypt(stored[2]) == "ssh-s3cret"
    assert api.post(f"/api/switches/{sid}/config/refresh").status_code == 409 and world.hosts == []
    assert api.put(f"/api/switches/{sid}", json={**body, "driver": "procurve"}).status_code == 200
    assert api.post(f"/api/switches/{sid}/config/refresh").status_code == 200 and world.hosts == [PC_HOST]
