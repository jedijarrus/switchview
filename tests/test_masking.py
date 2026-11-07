"""NV masking:changes-error-and-steps-persisted-unmasked, §6 (d), Thema A, E25/E26: no secret SwitchView knows lands in a change
(error, steps, output) or leaves a backup, and §6 Revert-Portname (E28): a name read from a switch goes back over SSH only when it is
safe in a CLI line.

The secrets are the RADIUS key and every secret of the switch (changes._secrets_of): its SSH password, its communities (except
"public") and its SNMPv3 passphrases, read and write. They are masked in every form they reach a text in: as they are, and as
netmiko writes a command into a ReadTimeout (repr(re.escape(cmd))); and before any text is cut, so no half of one stays.

No network: sshcli.connect is replaced by a fake session (ssh_env, tests/sshfix.py), SNMP reads and writes by stand-ins, re-polls are
recorded and never run. Each test gets its own database under tmp_path, set up by the app's own init_db.
"""
import asyncio
import hashlib
import json
import logging
import re

import pytest
from fastapi.testclient import TestClient
from netmiko.exceptions import ReadTimeout

import auth
import cfgparse
import changes
import config
import crypto
import db
import main
import snmp
import snmpwrite
import sshcli
from cfgparse import parse_config
from dbfix import connect, insert_switch, query, raising_async_fn
from sshfix import SshEnv, procurve

USER = {"username": "tester", "name": "Tester", "method": "local"}
SWITCH_SECRETS = {"ssh_pass": "ssh-s3cret", "snmp_community": "ro-s3cret", "snmp_auth_pass": "ro-auth-s3cret",
                  "snmp_priv_pass": "ro-priv-s3cret", "snmp_rw_community": "rw-s3cret", "snmp_rw_auth_pass": "rw-auth-s3cret",
                  "snmp_rw_priv_pass": "rw-priv-s3cret"}


def add_switch(**cols) -> int:
    """A switches row: the ProCurve of ssh_env (sshfix.procurve), updated by cols; its id."""
    return insert_switch(**procurve(**cols))


def _never(*args, **kwargs):
    raise AssertionError("the scheduler must not start in a test (no background polling, no network)")


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app (no lifespan, scheduler booby-trapped) against a fresh database, signed in as USER."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    monkeypatch.setattr(main.scheduler, "start", _never)
    asyncio.run(db.init_db())
    main.app.dependency_overrides[auth.current_user] = lambda: USER
    try:
        yield TestClient(main.app, headers={"X-Requested-With": "SwitchView"})
    finally:
        main.app.dependency_overrides.pop(auth.current_user, None)


def create(api) -> int:
    r = api.post("/api/switches", json={"name": "SW-VK-02", "host": "203.0.113.42", "zone": "VK"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def old_backup(sid: int, text: str) -> int:
    """A config_backups row as one from before this update: the content stored as it is, without the masking of today."""
    conn = connect()
    try:
        cur = conn.execute("INSERT INTO config_backups(switch_id, taken_at, sha, content, trigger) VALUES (?, datetime('now'), ?, ?, ?)",
                           (sid, hashlib.sha256(text.encode()).hexdigest(), text, "nightly"))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def old_change(sid: int, error: str, steps: list, output: str) -> int:
    """A failed RADIUS preparation of switch sid as a changes row from before this update: error, steps and output stored as they
    are, without the masking of today."""
    conn = connect()
    try:
        cur = conn.execute("INSERT INTO changes(switch_id, username, kind, summary, commands, status, steps, output, error, finished_at) "
                           "VALUES (?, 'tester', 'prepare', 'RADIUS vorbereiten', '[]', 'failed', ?, ?, ?, datetime('now'))",
                           (sid, json.dumps(steps), output, error))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# ── A change over SSH ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_read_timeout_does_not_leak_the_radius_key(ssh_env):         # NV, Eingabe: netmikos ReadTimeout-Text
    cmd = "radius-server host 203.0.113.10 key S3cr3t.Key!"
    ssh_env.on_send = ReadTimeout(f"\n\nPattern not detected: {re.escape(cmd)!r} in output.")
    row = ssh_env.change(await ssh_env.run_prepare(radius_server="203.0.113.10", radius_key="S3cr3t.Key!"))
    assert row["status"] == "unclear" and "S3cr3t" not in json.dumps(row) and "***" in row["error"]


async def test_the_log_gets_the_traceback_masked(ssh_env, caplog):
    """The exception that ends a change goes to the container log with its whole traceback, masked like the stored texts: here the
    ReadTimeout of a RADIUS preparation, which names the key."""
    cmd = "radius-server host 203.0.113.10 key S3cr3t.Key!"
    ssh_env.on_send = ReadTimeout(f"\n\nPattern not detected: {re.escape(cmd)!r} in output.")
    with caplog.at_level(logging.ERROR, logger="switchview.changes"):
        cid = await ssh_env.run_prepare(radius_server="203.0.113.10", radius_key="S3cr3t.Key!")
    assert "S3cr3t" not in caplog.text
    [rec] = [r for r in caplog.records if r.name == "switchview.changes"]
    text = rec.getMessage()
    assert (rec.levelname, rec.exc_info) == ("ERROR", None) and text.startswith(f"Änderung {cid}: Traceback (most recent call last):")
    assert 'netmiko.exceptions.ReadTimeout: \n\nPattern not detected: ' in text and 'key\\\\ "***"' in text


async def test_the_ssh_password_never_lands_in_a_change(ssh_env):
    ssh_env.on_connect = RuntimeError("login manager/ssh-s3cret refused")
    row = ssh_env.change(await ssh_env.run_prepare(radius_server="203.0.113.10", radius_key="S3cretKey1"))
    assert "ssh-s3cret" not in json.dumps(row) and "***" in row["error"]


async def test_a_secret_is_masked_before_the_error_is_cut(ssh_env):
    """error keeps 300 characters of the exception text; a key that straddles the cut must not leave its first half."""
    ssh_env.on_connect = RuntimeError("x" * 295 + "S3cretKey1 refused")
    row = ssh_env.change(await ssh_env.run_prepare(radius_server="203.0.113.10", radius_key="S3cretKey1"))
    assert row["error"] == "RuntimeError: " + "x" * 295 + "*** r" and "S3cre" not in json.dumps(row)


async def test_every_secret_of_the_switch_is_masked_in_the_change(ssh_env):
    """The switch's SNMP secrets too, read and write, and with the row of after the lock (read again there): here the RW community is
    set while the change waits for the switch's lock."""
    query("UPDATE switches SET snmp_community = ?, snmp_auth_pass = ? WHERE id = ?",
          (crypto.encrypt("ro-s3cret"), crypto.encrypt("ro-auth-s3cret"), ssh_env.sid))
    lock = sshcli.lock(ssh_env.sid)
    await lock.acquire()
    ssh_env.on_connect = RuntimeError("ro-s3cret ro-auth-s3cret rw-s3cret ssh-s3cret S3cretKey1")
    task = asyncio.create_task(ssh_env.run_prepare(radius_server="203.0.113.10", radius_key="S3cretKey1"))
    for _ in range(300):
        if query("SELECT id FROM changes WHERE steps != '[]'"):
            break
        await asyncio.sleep(0.01)
    query("UPDATE switches SET snmp_rw_community = ? WHERE id = ?", (crypto.encrypt("rw-s3cret"), ssh_env.sid))
    lock.release()
    row = ssh_env.change(await task)
    assert row["error"] == "RuntimeError: *** *** *** *** ***" and "s3cret" not in json.dumps(row).lower()


async def test_an_unreadable_config_still_ends_the_change(ssh_env, monkeypatch):
    """The store_cfg calls in run_change's finally are guarded one by one: when the read-back does not parse, the change still ends
    with its audit row and its re-poll, the backups are kept, and the cached read no longer counts (R27)."""
    monkeypatch.setattr(changes, "store_cfg", raising_async_fn(ValueError("kaputt")))
    cid = await ssh_env.run_prepare(radius_server="203.0.113.10", radius_key="S3cretKey1")
    row = ssh_env.change(cid)
    assert (row["status"], row["finished_at"] is not None) == ("unclear", True)
    assert query("SELECT username, action, target, detail FROM audit") == [("tester", "change_unclear", str(ssh_env.sid),
                                                                           f"#{cid} RADIUS vorbereiten")]
    assert ssh_env.repolls == [ssh_env.sid] and ssh_env.sid in changes._cfg_stale
    assert query("SELECT trigger FROM config_backups") == [(f"vor #{cid}",)]    # the read-back is the same text: stored once


async def test_an_oversized_config_fails_the_change_cleanly(ssh_env, monkeypatch):
    """The real parse: a running-config beyond MAX_REFS (lowered to 1000 here) fails the change before anything is sent, with the
    parse error; it is kept as the backup "vor", the audit runs, no re-poll (nothing was sent)."""
    monkeypatch.setattr(cfgparse, "MAX_REFS", 1000)
    ssh_env.running = 'hostname "SW"\ninterface 1-100\n   tagged vlan 1-20\n   exit\n'
    cid = await ssh_env.run_prepare(radius_server="203.0.113.10", radius_key="S3cretKey1")
    row = ssh_env.change(cid)
    assert (row["status"], row["error"]) == ("failed", "ValueError: Konfiguration zu groß: mehr als 1000 Port-/VLAN-Einträge")
    assert ssh_env.sent == [] and query("SELECT trigger FROM config_backups") == [(f"vor #{cid}",)]
    assert [a for (a,) in query("SELECT action FROM audit")] == ["change_failed"] and ssh_env.repolls == []


async def test_every_step_text_is_masked(ssh_env, monkeypatch):
    """Not only the error: each step is masked as it is written. A revert that the plan refuses names the port's old name in its
    step, and a switch can have set that name to anything, here the SSH password."""
    async def inventory(sid):
        return {"ports": {"1": {"tr": "", "l": [], "o": False}}, "uplinks": set()}

    monkeypatch.setattr(changes, "inventory", inventory)
    plan = {"shown": [], "desired": {}, "before": {}, "mechanism": "ssh"}
    cid = await changes.create_change(ssh_env.sid, "tester", "ports", "Rücknahme", {"desired": {"1": {"name": "a ssh-s3cret"}}}, plan)
    await changes.run_change(cid)
    row = ssh_env.change(cid)
    assert row["status"] == "aborted" and "ssh-s3cret" not in row["steps"] + row["error"] + row["output"]
    assert [text for _, text, _ in json.loads(row["steps"])][-1].startswith("Abgebrochen: 1: Name „a ***“ lässt sich per SSH nicht")


def test_prepare_preview_never_shows_the_key():                               # Thema A „CLI-Vorschau“ (hält den Stand fest)
    plan = changes.plan_prepare(parse_config(""), {"server": "203.0.113.10", "key": "S3cretKey1"})
    assert not any("S3cretKey1" in line for line in plan["shown"])


# ── A change over SNMP ────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def snmp_change(env: SshEnv, monkeypatch, leak: str) -> int:
    """An SNMP port change of env's switch (SNMP write on, RW community rw-s3cret) with stand-ins for the SNMP reads, the plan and the
    SET: the SET fails with "SET: <leak>", the read-back with "Timeout: <leak>". The change id (created, not run)."""
    query("UPDATE switches SET snmp_write = 1, snmp_community = ?, snmp_rw_community = ? WHERE id = ?",
          (crypto.encrypt("ro-s3cret"), crypto.encrypt("rw-s3cret"), env.sid))
    reads = iter([({}, {}), snmp.SnmpError(f"Timeout: {leak}")])

    async def read_cfg(row, driver, with_poe=False):
        r = next(reads)
        if isinstance(r, Exception):
            raise r
        return r

    async def inventory(sid):
        return {"ports": {}, "uplinks": set()}

    monkeypatch.setattr(changes, "inventory", inventory)
    monkeypatch.setattr(snmpwrite, "read_cfg", read_cfg)
    monkeypatch.setattr(changes, "plan_ports", lambda *a, **k: {"blocked": [], "shown": ["Port 1: An"], "ops": [("1.3.6", "i", "1")],
                                                                "desired": {}, "before": {}})
    monkeypatch.setattr(snmpwrite, "apply_ops", raising_async_fn(snmp.SnmpError(f"SET: {leak}")))
    plan = {"shown": ["Port 1: An"], "desired": {}, "before": {}, "mechanism": "snmp"}
    return await changes.create_change(env.sid, "tester", "ports", "Port 1: An", {"ports": ["1"], "set": {"status": "on"}}, plan)


async def test_an_snmp_change_masks_error_steps_and_output(ssh_env, monkeypatch):
    """_run_snmp masks like run_change: the SET's error text (output and its step) and the failed read-back (error and its step)
    carry every secret here, and none of them is stored."""
    await db.set_setting("radius_key", crypto.encrypt("S3cretKey1"))
    cid = await snmp_change(ssh_env, monkeypatch, "ro-s3cret rw-s3cret ssh-s3cret S3cretKey1")
    await changes.run_change(cid)
    row = ssh_env.change(cid)
    assert (row["status"], row["output"], row["error"]) == ("unclear", "SET: *** *** *** ***",
                                                            "Zurücklesen per SNMP fehlgeschlagen: Timeout: *** *** *** ***")
    assert "s3cret" not in json.dumps(row).lower()
    assert any("SET nicht bestätigt (SET: *** *** *** ***)" in text for _, text, _ in json.loads(row["steps"]))


async def test_an_snmp_change_masks_with_the_row_of_after_the_lock(ssh_env, monkeypatch):
    """As on the SSH path: a secret saved while the change waits for the switch's lock is masked too."""
    cid = await snmp_change(ssh_env, monkeypatch, "rw-n3w")
    lock = sshcli.lock(ssh_env.sid)
    await lock.acquire()
    task = asyncio.create_task(changes.run_change(cid))
    for _ in range(300):
        if ssh_env.change(cid)["steps"] != "[]":
            break
        await asyncio.sleep(0.01)
    query("UPDATE switches SET snmp_rw_community = ? WHERE id = ?", (crypto.encrypt("rw-n3w"), ssh_env.sid))
    lock.release()
    await task
    row = ssh_env.change(cid)
    assert (row["status"], row["output"]) == ("unclear", "SET: ***") and "n3w" not in json.dumps(row)


async def test_an_snmp_change_logs_its_traceback_masked(ssh_env, monkeypatch, caplog):
    """_run_snmp logs like run_change: an exception none of its steps expects (here from the SET) with its traceback, masked."""
    cid = await snmp_change(ssh_env, monkeypatch, "-")
    monkeypatch.setattr(snmpwrite, "apply_ops", raising_async_fn(RuntimeError("boom rw-s3cret ro-s3cret")))
    with caplog.at_level(logging.ERROR, logger="switchview.changes"):
        await changes.run_change(cid)
    assert ssh_env.change(cid)["error"] == "RuntimeError: boom *** ***" and "s3cret" not in caplog.text
    [rec] = [r for r in caplog.records if r.name == "switchview.changes"]
    assert rec.exc_info is None and "Traceback (most recent call last):" in rec.getMessage()
    assert rec.getMessage().endswith("RuntimeError: boom *** ***\n")


# ── A change row from before this update ──────────────────────────────────────────────────────────────────────────────────────────
def test_old_change_rows_are_masked_on_output(api):                          # NV, Eingabe: Altzeile mit netmikos ReadTimeout-Text
    """A row stored before the masking of this update (written by sqlite here) is served masked with the secrets SwitchView knows now:
    the RADIUS key in the form netmiko's ReadTimeout gives it (repr(re.escape(cmd))), which since FW-b the key\\\\ pattern of
    mask_secrets finds as well (hence '"***"' in place of the key), and each switch's own secrets in the rows of that switch. What is
    no secret stays as stored, and so does the row in the database (E26)."""
    asyncio.run(db.set_setting("radius_key", crypto.encrypt("Old.Rad!Key1")))
    sid, other = add_switch(), add_switch(name="SW-VK-02", host="203.0.113.42", ssh_pass=crypto.encrypt("ssh-z2"))
    leak = f"ReadTimeout: \n\nPattern not detected: {re.escape('radius-server host 203.0.113.10 key Old.Rad!Key1')!r} in output."
    masked = leak.replace("Old\\\\.Rad!Key1", '"***"')
    steps = [["2026-11-01 08:00:00", "Verbinde mit 203.0.113.21", "info"], ["2026-11-01 08:00:09", leak, "error"]]
    cid = old_change(sid, leak, steps, "login manager/ssh-s3cret\nradius-server host 203.0.113.10 key Old.Rad!Key1\n")
    cid2 = old_change(other, "RuntimeError: login manager/ssh-z2 refused", [["2026-11-01 08:01:00", "ssh-z2", "error"]], "")
    served = {c["id"]: c for c in api.get("/api/changes").json()}
    assert (served[cid]["error"], served[cid]["steps"]) == (masked, [steps[0], ["2026-11-01 08:00:09", masked, "error"]])
    assert served[cid]["output"] == 'login manager/***\nradius-server host 203.0.113.10 key "***"\n'
    assert (served[cid2]["error"], served[cid2]["steps"][0][1]) == ("RuntimeError: login manager/*** refused", "***")
    for path in (f"/api/changes/{cid}", f"/api/changes?switch_id={sid}", f"/api/changes/{cid2}"):
        assert not re.search(r"Old\W*Rad|ssh-s3cret|ssh-z2", api.get(path).text), path
    assert query("SELECT error, steps FROM changes WHERE id = ?", (cid,)) == [(leak, json.dumps(steps))]


def test_an_old_change_row_hides_a_radius_key_changed_since(api):
    """The advice for such a row is to change the RADIUS key; after that SwitchView no longer knows the old one. mask_secrets still
    finds it behind "key" in netmiko's escaped form (key\\\\ <key>, up to the closing quote of the repr), as it finds "key <key>"."""
    asyncio.run(db.set_setting("radius_key", crypto.encrypt("New.Rad!Key2")))
    sid = add_switch()
    leak = f"ReadTimeout: \n\nPattern not detected: {re.escape('radius-server host 203.0.113.10 key Old.Rad!Key1')!r} in output."
    cid = old_change(sid, leak, [["2026-11-01 08:00:09", leak, "error"]], "")
    served = api.get(f"/api/changes/{cid}").json()
    assert served["error"] == leak.replace("Old\\\\.Rad!Key1", '"***"') and served["steps"][0][1] == served["error"]


# ── changes._secrets_of ───────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_secrets_of_names_every_secret_of_the_switch():
    row = {k: crypto.encrypt(v) for k, v in SWITCH_SECRETS.items()} | {"host": "203.0.113.21", "ssh_user": "manager"}
    assert sorted(changes._secrets_of(row, {"server": "203.0.113.10", "key": "S3cretKey1"})) == sorted([*SWITCH_SECRETS.values(),
                                                                                                    "S3cretKey1"])


def test_secrets_of_reads_every_secret_column():
    """The drift guard: changes keeps its own list (it cannot import main), and it must name exactly main.SECRET_FIELDS."""
    assert sorted(changes._SWITCH_SECRETS) == sorted(main.SECRET_FIELDS) == sorted(SWITCH_SECRETS)


def test_secrets_of_leaves_out_what_is_no_secret():
    """Nothing empty, nothing undecryptable, and no community "public" (any case, outer whitespace ignored, R-T); without a row only
    the RADIUS key."""
    row = {"ssh_pass": None, "snmp_community": crypto.encrypt(" Public "), "snmp_rw_community": crypto.encrypt("PUBLIC"),
           "snmp_auth_pass": "not-a-fernet-token", "snmp_priv_pass": crypto.encrypt(""), "snmp_rw_auth_pass": None,
           "snmp_rw_priv_pass": crypto.encrypt("rw-priv-s3cret")}
    assert changes._secrets_of(row, {"server": "", "key": ""}) == ["rw-priv-s3cret"]
    assert changes._secrets_of(None, {"server": "203.0.113.10", "key": "S3cretKey1"}) == ["S3cretKey1"]


# ── Backups ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_old_backups_are_masked_on_output(api, tmp_path):                    # api, create wie in tests/test_switch_api.py
    sid = create(api)                                                          # zwei Altzeilen per sqlite, unmaskiert wie vor dem Update
    b1, b2 = old_backup(sid, 'snmpv3 user "u" auth sha-256 "X1"\n'), old_backup(sid, 'snmpv3 user "u" auth sha-256 "X2"\n')
    assert "X1" not in api.get(f"/api/backups/{b1}").text and not re.search("X[12]", api.get(f"/api/backups/{b2}/diff").text)


def test_old_backups_are_not_rewritten(api):
    """E26: the stored rows keep their content; only what is served is masked again."""
    sid = create(api)
    text = 'hostname "SW"\nsnmpv3 user "u" auth sha-256 "X1"\n'
    bid = old_backup(sid, text)
    assert api.get(f"/api/backups/{bid}").text == 'hostname "SW"\nsnmpv3 user "u" auth sha-256 "***"\n'
    assert query("SELECT content FROM config_backups WHERE id = ?", (bid,)) == [(text,)]


def test_the_diff_of_old_backups_still_shows_what_changed(api):
    """The masked diff compares masked texts: a changed secret alone is no difference, a changed line next to it still is."""
    sid = create(api)
    old_backup(sid, 'hostname "A"\nsnmpv3 user "u" auth sha-256 "X1"\n')
    bid = old_backup(sid, 'hostname "B"\nsnmpv3 user "u" auth sha-256 "X2"\n')
    diff = api.get(f"/api/backups/{bid}/diff").text
    assert '-hostname "A"' in diff and '+hostname "B"' in diff and not re.search("X[12]", diff)
    assert 'snmpv3 user "u" auth sha-256 "***"' in diff


async def test_a_new_backup_is_stored_masked(ssh_env):
    """store_backup masks with today's patterns (the v3 spelling of §6 (d) included) before it stores."""
    await sshcli.store_backup(ssh_env.sid, 'snmpv3 user "u" auth sha-256 "X1" priv aes-256 "Y1"\n', "manual")
    assert query("SELECT content FROM config_backups") == [('snmpv3 user "u" auth sha-256 "***" priv aes-256 "***"\n',)]


# ── Text read from a switch, written back over SSH (§6 Revert-Portname, E28) ─────────────────────────────────────────────────────
def test_ssh_revert_refuses_an_unsafe_name():                                 # §6 Revert-Portname
    inv = {"ports": {"1": {"tr": "", "l": [], "o": False}}, "uplinks": set()}
    plan = changes.plan_ports("", inv, parse_config("vlan 1\n   untagged 1\n   exit\n"), {"desired": {"1": {"name": "a b\nvlan 1 untagged 2"}}})
    assert plan["blocked"][0]["port"] == "1" and plan["commands"] == []


@pytest.mark.parametrize("name", ["a b", "x" * 65, "Raum\t2", "Raumä"])
def test_ssh_revert_names_the_reason(name):
    inv = {"ports": {"1": {"tr": "", "l": [], "o": False}, "2": {"tr": "", "l": [], "o": False}}, "uplinks": set()}
    plan = changes.plan_ports("", inv, parse_config("vlan 1\n   untagged 1-2\n   exit\n"),
                              {"desired": {"1": {"name": name}, "2": {"name": "Platz-107"}}})
    assert plan["blocked"] == [{"port": "1", "reason": f"Name „{name}“ lässt sich per SSH nicht sicher zurückschreiben "
                                                         "(erlaubt: Buchstaben, Ziffern und . _ : @ -)"}]
    assert plan["commands"] == ["interface 2 name Platz-107"]


def test_ssh_revert_still_writes_a_safe_or_an_empty_name():
    """The guard of the tests above: a name PORTNAME_RE allows and an empty one (no interface … name) still go back."""
    inv = {"ports": {"1": {"tr": "", "l": [], "o": False}, "2": {"tr": "", "l": [], "o": False}}, "uplinks": set()}
    cfg = parse_config('vlan 1\n   untagged 1-2\n   exit\ninterface 2\n   name "alt"\n   exit\n')
    plan = changes.plan_ports("", inv, cfg, {"desired": {"1": {"name": "a@b:c.d_e-f"}, "2": {"name": ""}}})
    assert plan["blocked"] == [] and plan["commands"] == ["interface 1 name a@b:c.d_e-f", "no interface 2 name"]
