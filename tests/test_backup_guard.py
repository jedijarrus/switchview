"""F5 and E27: one switch never stops the nightly backup, a configuration that does not parse is still kept as a backup, and the show
commands that print secrets in clear text are never run.

The nightly backup (sshcli.backup_all) walks every switch in turn; before Phase 2 an exception of one (a running-config that
cfgparse.parse_config could not read, raised from changes.store_cfg) ended the walk, and every later switch went without a backup.
A backup is the evidence, all the more for a switch that sends something odd: it is stored (masked) even when its parse fails.

netmiko's ConnectHandler is replaced by a recorder (sshcli.ConnectHandler, tests/sshfix.py) whose sessions answer every show command
with a small running-config; no network, no switch. Each test gets its own database under tmp_path, set up by the app's own init_db.
"""
import asyncio
import sqlite3
from collections import defaultdict

import pytest

import changes
import config
import db
import sshcli
from dbfix import connect, insert_switch, raising_async, raising_async_fn
from sshfix import Session, Sessions, procurve

RUNNING_CONFIG = 'hostname "SW-EK-01"\nvlan 1\n   name "DEFAULT_VLAN"\n   untagged 1-24\n   exit\n'


@pytest.fixture
def world(tmp_path, monkeypatch) -> Sessions:
    """A fresh database under tmp_path; ConnectHandler recorded; fresh locks and R27 marks."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    asyncio.run(db.init_db())
    sessions = Sessions(RUNNING_CONFIG)
    monkeypatch.setattr(sshcli, "ConnectHandler", sessions)
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    monkeypatch.setattr(changes, "_cfg_stale", set())
    return sessions


def add_switch(host: str) -> int:
    """A ProCurve switches row with SSH credentials (manager / an encrypted password); its id."""
    return insert_switch(**procurve(name=f"SW-{host}", host=host))


def row_of(sid: int) -> sqlite3.Row:
    conn = connect()
    try:
        return conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)).fetchone()
    finally:
        conn.close()


def backups() -> dict[int, int]:
    """The number of config_backups rows per switch_id."""
    conn = connect()
    try:
        return {r[0]: r[1] for r in conn.execute("SELECT switch_id, count(*) FROM config_backups GROUP BY switch_id")}
    finally:
        conn.close()


def stored_cfg(sid: int):
    conn = connect()
    try:
        return conn.execute("SELECT parsed FROM switch_cfg WHERE switch_id = ?", (sid,)).fetchone()
    finally:
        conn.close()


# ── The nightly backup: one switch at a time, none stops the others ────────────────────────────────────────────────────────────────
async def test_one_bad_switch_does_not_stop_the_nightly_backup(world, monkeypatch):   # F5, Eingabe: Switch 2 liefert Unlesbares
    ids = [add_switch(f"203.0.113.{i}") for i in (21, 22, 23)]
    real = changes.store_cfg
    monkeypatch.setattr(changes, "store_cfg", lambda sid, c: raising_async(ValueError("kaputt")) if sid == ids[1] else real(sid, c))
    await sshcli.backup_all()
    assert backups() == {ids[0]: 1, ids[1]: 1, ids[2]: 1}


async def test_the_nightly_backup_survives_any_exception_of_one_switch(world, monkeypatch, caplog):
    """backup_all catches every exception per switch (a broken database write, a bug in backup_config itself), logs it with the
    switch, and goes on with the next one."""
    ids = [add_switch(f"203.0.113.{i}") for i in (21, 22, 23)]
    real = sshcli.backup_config
    monkeypatch.setattr(sshcli, "backup_config",
                        lambda sid, trigger="nightly": raising_async(RuntimeError("kaputt")) if sid == ids[1] else real(sid, trigger))
    await sshcli.backup_all()
    assert backups() == {ids[0]: 1, ids[2]: 1}
    assert [(r.levelname, r.getMessage(), r.exc_info[0]) for r in caplog.records if r.name == "switchview.ssh"] == [
        ("ERROR", f"Nächtliche Sicherung von Switch {ids[1]} fehlgeschlagen", RuntimeError)]


async def test_a_cancelled_nightly_backup_stops(world, monkeypatch):
    """Only exceptions are caught, not a cancellation: stopping the process still ends the walk."""
    for i in (21, 22):
        add_switch(f"203.0.113.{i}")
    calls = []

    async def cancelled(sid, trigger="nightly"):
        calls.append(sid)
        raise asyncio.CancelledError()

    monkeypatch.setattr(sshcli, "backup_config", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await sshcli.backup_all()
    assert len(calls) == 1


# ── One backup: kept even when the parse fails ────────────────────────────────────────────────────────────────────────────────────
async def test_the_backup_is_kept_when_the_config_is_unreadable(world, monkeypatch):
    sid = add_switch("203.0.113.21")
    monkeypatch.setattr(changes, "store_cfg", raising_async_fn(ValueError("kaputt")))
    res = await sshcli.backup_config(sid)
    assert res["ok"] is False and "gesichert, aber nicht auswertbar" in res["error"] and backups() == {sid: 1}


async def test_an_oversized_config_is_kept_but_not_cached(world, monkeypatch):
    """The real parse, not a stand-in: a running-config beyond cfgparse.MAX_REFS (here lowered to 1000, so that the test stays small)
    is stored as a backup, switch_cfg gets nothing from it, and the answer names the type and the text of the parse error."""
    monkeypatch.setattr(Session, "send_command", lambda self, cmd, read_timeout=None:
                        'hostname "SW"\ninterface 1-100\n   tagged vlan 1-20\n   exit\n')
    monkeypatch.setattr("cfgparse.MAX_REFS", 1000)
    sid = add_switch("203.0.113.21")
    res = await sshcli.backup_config(sid, "manual")
    assert res == {"ok": False, "error": "Konfiguration gesichert, aber nicht auswertbar: ValueError: Konfiguration zu groß: mehr als "
                                         "1000 Port-/VLAN-Einträge"}
    assert backups() == {sid: 1} and stored_cfg(sid) is None


async def test_fresh_cfg_reports_an_unreadable_config_and_drops_the_cache(world, monkeypatch):
    """The read path of the preview (changes.fresh_cfg -> backup_config "lesen"): the parse error comes back as the RuntimeError text,
    and the cached read no longer counts (R27)."""
    sid = add_switch("203.0.113.21")
    monkeypatch.setattr(changes, "store_cfg", raising_async_fn(ValueError("kaputt")))
    with pytest.raises(RuntimeError, match="^Konfiguration gesichert, aber nicht auswertbar: ValueError: kaputt$"):
        await changes.fresh_cfg(sid)
    assert sid in changes._cfg_stale and backups() == {sid: 1}


async def test_a_readable_config_is_still_backed_up_and_cached(world):
    """The positive control: the usual case answers ok and leaves a backup and a switch_cfg entry."""
    sid = add_switch("203.0.113.21")
    assert await sshcli.backup_config(sid) == {"ok": True, "changed": True}
    assert backups() == {sid: 1} and stored_cfg(sid) is not None and world.hosts == ["203.0.113.21"]


# ── show commands that print secrets (E27) ────────────────────────────────────────────────────────────────────────────────────────
async def test_show_radius_is_never_run(world):
    with pytest.raises(ValueError, match="nie ausgeführt"):
        await sshcli.run_shows(row_of(add_switch("203.0.113.21")), ["show radius"])
    assert world.hosts == []


@pytest.mark.parametrize("cmd", ["show radius host 203.0.113.10", "show tech all", "show tacacs", "SHOW Radius", "  show   tech"])
async def test_no_command_that_prints_secrets_opens_a_session(world, cmd):
    """Each of show radius / tech / tacacs, in any case and spacing, refuses the whole call before a session opens, even behind a
    harmless command; the message quotes the command."""
    with pytest.raises(ValueError, match=f"^„{cmd}“ gibt Geheimnisse im Klartext aus und wird nie ausgeführt$"):
        await sshcli.run_shows(row_of(add_switch("203.0.113.21")), ["show version", cmd])
    assert world.hosts == []


@pytest.mark.parametrize("cmd", ["show running-config", "show version", "show port-access authenticator clients", "show radiusx",
                                 "show technical"])
async def test_other_show_commands_still_run(world, cmd):
    """The guard of the test above: every other command still gets its session (a word that only starts like one does too)."""
    res = await sshcli.run_shows(row_of(add_switch("203.0.113.21")), [cmd])
    assert res == {cmd: RUNNING_CONFIG} and world.hosts == ["203.0.113.21"]
