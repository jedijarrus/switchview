"""NV transport:tls-verify-off-and-no-ssh-hostkey-pinning, topic A "SSH host-key pinning (TOFU)": SwitchView remembers each switch's
SSH host key at the first successful contact and from then on refuses any other key before it logs in (paramiko checks the key after
the key exchange and before the authentication, so the password never reaches an impostor). The key stays when the switch's address
changes; forgetting it is a deliberate click (DELETE /api/switches/{sid}/ssh-host-key). Whether a key is pinned is decided by the
database under the switch's lock (sshcli._open reads it fresh), never by the row a caller read earlier. TLS verification for
PacketFence and OPNsense is on for new installations; a stored value stays.

netmiko's ConnectHandler is replaced by a recorder (Paramikoish) that does what netmiko and paramiko do with the parameters sshcli
hands over: with ssh_strict it loads the alt_key_file with the real paramiko.HostKeys and compares the key the "server" offers
(world.offer, real paramiko key objects) the way SSHClient.connect does, raising netmiko's NetmikoTimeoutException with paramiko's
own message; only after that check does it count a login. No network, no switch: each test gets its own database under tmp_path,
set up by the app's own init_db.
"""
import asyncio
import base64
import json
import os
import sqlite3
from collections import defaultdict
from contextlib import closing

import paramiko
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from netmiko import NetmikoTimeoutException

import apifix
import changes
import config
import crypto
import db
import names
import pf
import sshcli

HOST = "203.0.113.21"
RUNNING_CONFIG = 'hostname "SW-EK-01"\nvlan 1\n   name "DEFAULT_VLAN"\n   untagged 1-24\n   exit\n'


def _openssh(public_key) -> str:
    return public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()


KEY_A = _openssh(ed25519.Ed25519PrivateKey.generate().public_key())
KEY_B = _openssh(ed25519.Ed25519PrivateKey.generate().public_key())


def pkey(line: str) -> paramiko.PKey:
    """The paramiko key object of an OpenSSH public key line ("ssh-ed25519 AAAA…"), as a server's transport would hold it."""
    kind, b64 = line.split()
    return paramiko.PKey.from_type_string(kind, base64.b64decode(b64))


def netmiko_text(exc: Exception) -> str:
    """The message netmiko 4.8 wraps a paramiko SSHException of the connection set-up in (BaseConnection.establish_connection)."""
    return f"\nA paramiko SSHException occurred during connection creation:\n\n{exc}\n\n"


class Transport:
    def __init__(self, key: paramiko.PKey):
        self.key = key

    def get_remote_server_key(self) -> paramiko.PKey:
        return self.key


class SSHClient:
    """netmiko's remote_conn_pre (a paramiko SSHClient), as far as sshcli reads it."""

    def __init__(self, key: paramiko.PKey):
        self.transport = Transport(key)

    def get_transport(self) -> Transport:
        return self.transport


class Session:
    """A netmiko connection to a ProCurve after the login: show commands answer with RUNNING_CONFIG, config sets are recorded."""

    def __init__(self, world: "Paramikoish", key: paramiko.PKey):
        self.world = world
        self.remote_conn_pre = SSHClient(key)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.disconnect()
        return False

    def send_command(self, cmd, read_timeout=None):
        return RUNNING_CONFIG

    def send_config_set(self, commands, **kwargs):
        self.world.sent.append(list(commands))
        return ""

    def save_config(self):
        pass

    def disconnect(self):
        self.world.disconnects += 1


class Paramikoish:
    """sshcli.ConnectHandler: records every parameter set (params) and the content of its alt_key_file (known_hosts), checks the
    offered key like paramiko before the login (logins counts only the logins after that check), and hands out a Session whose
    remote_conn_pre reports the offered key. during_login: a hook run after the check, before the session is handed out."""

    def __init__(self):
        self.params: list[dict] = []
        self.known_hosts: list[str] = []
        self.logins = 0
        self.disconnects = 0
        self.sent: list[list[str]] = []
        self.offered = KEY_A
        self.during_login = None
        self.refuse: Exception | None = None
        self.repolls: list[int] = []

    def offer(self, key: str):
        self.offered = key

    def __call__(self, **device):
        self.params.append(device)
        host_keys = paramiko.HostKeys()
        if device.get("alt_host_keys"):
            with open(device["alt_key_file"]) as f:
                self.known_hosts.append(f.read())
            host_keys.load(device["alt_key_file"])
        if self.refuse is not None:
            raise self.refuse
        server_key = pkey(self.offered)
        if device.get("ssh_strict"):    # paramiko.RejectPolicy, then SSHClient.connect's comparison, both before _auth
            ours = host_keys.lookup(device["host"])
            if ours is None:
                raise NetmikoTimeoutException(netmiko_text(paramiko.SSHException(f"Server {device['host']!r} not found in known_hosts")))
            expected = ours.get(server_key.get_name())
            if expected != server_key:
                raise NetmikoTimeoutException(netmiko_text(paramiko.BadHostKeyException(device["host"], server_key,
                                                                                         expected or list(ours.values())[0])))
        self.logins += 1
        if self.during_login:
            self.during_login()
        return Session(self, server_key)

    def repoll(self, sid: int):
        self.repolls.append(sid)
        return asyncio.sleep(0)


@pytest.fixture
def world(tmp_path, monkeypatch) -> Paramikoish:
    """A fresh database under tmp_path (the app's own init_db); ConnectHandler recorded; fresh locks and R27 marks; re-polls recorded."""
    apifix.fresh_db(tmp_path, monkeypatch)
    recorder = Paramikoish()
    monkeypatch.setattr(sshcli, "ConnectHandler", recorder)
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    monkeypatch.setattr(changes, "_cfg_stale", set())
    monkeypatch.setattr(changes, "_repoll", recorder.repoll)
    return recorder


def query(sql: str, args: tuple = ()) -> list[sqlite3.Row]:
    with closing(sqlite3.connect(db.settings.db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, args).fetchall()
        conn.commit()
        return rows


def add_switch(host: str = HOST) -> int:
    """A ProCurve switches row with SSH access (manager / an encrypted password); its id."""
    with closing(sqlite3.connect(db.settings.db_path)) as conn:
        cur = conn.execute("INSERT INTO switches(name, host, driver, ssh_user, ssh_pass) VALUES ('SW-EK-01', ?, 'procurve', 'manager', ?)",
                           (host, crypto.encrypt("ssh-s3cret")))
        conn.commit()
        return cur.lastrowid


@pytest.fixture
def sid(world) -> int:
    return add_switch()


def row(sid: int) -> sqlite3.Row:
    return query("SELECT * FROM switches WHERE id = ?", (sid,))[0]


def pin(sid: int, key: str | None):
    query("UPDATE switches SET ssh_host_key = ? WHERE id = ?", (key, sid))


def change_row(cid: int) -> sqlite3.Row:
    return query("SELECT * FROM changes WHERE id = ?", (cid,))[0]


def last_audit_detail() -> str:
    """The detail of the newest audit row in the database the app uses now."""
    return query("SELECT detail FROM audit ORDER BY id DESC LIMIT 1")[0][0]


@pytest.fixture
def api(world, monkeypatch):
    """A TestClient on main.app (created without `with`: no lifespan, no scheduler), signed in as apifix.USER, on world's database."""
    with apifix.signed_in(monkeypatch) as client:
        yield client


def body(**fields) -> dict:
    return {"name": "SW-VK-02", "host": "203.0.113.42", "zone": "VK", **fields}


def create(api, **fields) -> int:
    r = api.post("/api/switches", json=body(**fields))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def listed(api, sid: int) -> dict:
    r = api.get("/api/switches")
    assert r.status_code == 200, r.text
    return next(s for s in r.json() if s["id"] == sid)


def mismatch_text(host: str, key: str, after_login: bool = False) -> str:
    """HostKeyMismatch's message, written out by hand: refused before the login (nothing sent), or after the AutoAdd login of a first
    contact, when meanwhile another key was pinned (the password went out, no command did)."""
    if after_login:
        return (f"SSH-Hostschlüssel von {host} passt nicht zum gemerkten ({pkey(key).fingerprint}): während der Anmeldung wurde ein "
                "anderer gemerkt. Möglicher Angriff oder neuer Schlüssel am Switch – Sitzung beendet, kein Befehl gesendet (das Kennwort "
                "ging schon hinaus). Ist der neue Schlüssel erwartet (Tausch, Firmware): Switch → Zugang bearbeiten → "
                "„SSH-Hostschlüssel vergessen“.")
    return (f"SSH-Hostschlüssel von {host} passt nicht zum gemerkten ({pkey(key).fingerprint}). Möglicher Angriff oder neuer Schlüssel "
            "am Switch – nichts gesendet. Ist der neue Schlüssel erwartet (Tausch, Firmware): Switch → Zugang bearbeiten → "
            "„SSH-Hostschlüssel vergessen“.")


# ── Trust on first use ────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_first_contact_pins_the_key(world, sid):
    other = add_switch("203.0.113.22")    # unpinned as well: the pin is this entry's only
    assert (await sshcli.test_ssh(row(sid)))["ok"]
    assert row(sid)["ssh_host_key"] == KEY_A and row(sid)["ssh_host_key_at"]
    assert (row(other)["ssh_host_key"], row(other)["ssh_host_key_at"]) == (None, None)


async def test_a_changed_key_is_refused_before_login(world, sid):            # NV, Eingabe: MITM mit anderem Schlüssel
    pin(sid, KEY_A)
    world.offer(KEY_B)
    res = await sshcli.test_ssh(row(sid))
    assert res["ok"] is False and "passt nicht zum gemerkten" in res["error"] and world.logins == 0 and row(sid)["ssh_host_key"] == KEY_A


async def test_a_row_read_before_the_pin_still_gets_checked(world, sid):    # die Zeile eines Aufrufers von vor dem Merken
    stale = row(sid)
    pin(sid, KEY_A)
    world.offer(KEY_B)
    assert (await sshcli.test_ssh(stale))["ok"] is False and world.logins == 0


async def test_a_pinned_connection_hands_the_pin_to_paramiko(world, sid):
    pin(sid, KEY_A)
    await sshcli.test_ssh(row(sid))
    p = world.params[-1]
    assert p["ssh_strict"] and p["alt_host_keys"] and world.known_hosts[-1] == f"203.0.113.21 {KEY_A}\n"


@pytest.mark.parametrize("host", ["203.0.113.21", "fe80::21", "sw-ek-01.example.org"])
def test_the_known_hosts_line_parses_with_paramiko(tmp_path, host):          # echtes paramiko.HostKeys, kein Netz
    (tmp_path / "kh").write_text(f"{host} {KEY_A}\n")
    keys = paramiko.HostKeys(str(tmp_path / "kh")).lookup(host)
    assert f"{keys['ssh-ed25519'].get_name()} {keys['ssh-ed25519'].get_base64()}" == KEY_A


async def test_run_change_with_a_changed_key_sends_nothing(world, sid):
    pin(sid, KEY_A)
    world.offer(KEY_B)
    cid = await changes.create_change(sid, "tester", "ports", "Port 1: Aus", {"ports": ["1"], "set": {"status": "off"}, "expert": False},
                                      {"shown": ["interface 1 disable"], "desired": {}, "before": {}, "mechanism": "ssh"})
    await changes.run_change(cid)
    ch = change_row(cid)
    assert ch["status"] == "failed" and "HostKeyMismatch" in ch["error"] and world.sent == []


def test_forgetting_the_key_lets_the_next_contact_pin_again(api, world):     # api wie in tests/test_switch_api.py
    sid = create(api, ssh_user="manager", ssh_pass="ssh-s3cret")
    pin(sid, KEY_A)
    fp = sshcli.fingerprints(KEY_A)["sha256"]
    assert api.delete(f"/api/switches/{sid}/ssh-host-key").json() == {"ok": True}
    assert listed(api, sid)["ssh_host_key_fp"] is None and fp in last_audit_detail()
    world.offer(KEY_B)      # sshcli.test_ssh directly, not POST /test: that would start a real snmpget
    assert asyncio.run(sshcli.test_ssh(row(sid)))["ok"] is True and row(sid)["ssh_host_key"] == KEY_B


def test_upgrade_adds_the_columns_and_pins_on_first_use(tmp_path, world, monkeypatch):    # Review Focus 2, Ruling R-D
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    conn = sqlite3.connect(legacy / "switchview.db")
    conn.executescript(db.SCHEMA)             # die DB, wie das alte Image sie hinterlässt
    old = conn.execute("INSERT INTO switches(name, host, ssh_user, ssh_pass) VALUES ('SW-ALT', '203.0.113.22', 'manager', ?)",
                       (crypto.encrypt("ssh-s3cret"),)).lastrowid
    conn.commit()
    conn.close()
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(legacy)))                 # world hat schon eine frische DB; sein Rekorder bleibt
    asyncio.run(db.init_db())
    assert row(old)["ssh_host_key"] is None and row(old)["driver"] == "procurve"
    assert asyncio.run(sshcli.test_ssh(row(old)))["ok"] is True and row(old)["ssh_host_key"] == KEY_A


def test_tls_verification_defaults_on_only_for_new_installs(api):
    s = api.get("/api/settings").json()
    assert s["pf_verify_tls"] is True and s["opnsense_verify_tls"] is True
    asyncio.run(db.set_setting("pf_verify_tls", "0"))
    assert api.get("/api/settings").json()["pf_verify_tls"] is False


# ── The parameters sshcli hands to netmiko ────────────────────────────────────────────────────────────────────────────────────────
async def test_an_unpinned_connection_auto_adds_and_reads_no_key_file(world, sid):
    """Without a pinned key: netmiko's AutoAddPolicy (ssh_strict False), and neither the system's known_hosts nor a key file."""
    await sshcli.test_ssh(row(sid))
    p = world.params[-1]
    assert (p["ssh_strict"], p["system_host_keys"], p["alt_host_keys"]) == (False, False, False) and world.known_hosts == []


async def test_a_pinned_connection_never_reads_the_system_known_hosts(world, sid):
    """Only the pinned key counts: the system's known_hosts (whatever the container has there) is not loaded, and the temporary key
    file is gone once the session is open."""
    pin(sid, KEY_A)
    assert (await sshcli.test_ssh(row(sid)))["ok"] is True
    p = world.params[-1]
    assert p["system_host_keys"] is False and not os.path.exists(p["alt_key_file"]) and world.logins == 1


async def test_the_pinned_key_is_checked_against_the_host_of_the_row(world):
    """The known_hosts line names the host the session goes to (a hostname as stored), so paramiko finds it."""
    sid = add_switch("sw-ek-01.example.org")
    pin(sid, KEY_A)
    assert (await sshcli.test_ssh(row(sid)))["ok"] is True
    assert world.known_hosts == [f"sw-ek-01.example.org {KEY_A}\n"]


# ── What a refusal says and does ──────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_changed_key_is_reported_with_the_remedy(world, sid):
    """The connection test shows HostKeyMismatch's whole text (the remedy at its end included) with the pinned SHA256."""
    pin(sid, KEY_A)
    world.offer(KEY_B)
    assert await sshcli.test_ssh(row(sid)) == {"ok": False, "error": f"HostKeyMismatch: {mismatch_text(HOST, KEY_A)}"}


async def test_a_key_missing_from_the_file_is_refused_too(world, sid):
    """paramiko's RejectPolicy ("not found in known_hosts", e.g. when the stored key line does not parse) is a refusal as well."""
    pin(sid, KEY_A)
    world.refuse = NetmikoTimeoutException(netmiko_text(paramiko.SSHException(f"Server {HOST!r} not found in known_hosts")))
    with pytest.raises(sshcli.HostKeyMismatch, match="passt nicht zum gemerkten"):
        await sshcli.run_shows(row(sid), ["show version"])


async def test_other_connection_errors_stay_what_they_are(world, sid):
    """A timeout or an unreachable switch is no key mismatch: netmiko's own exception goes through, with or without a pinned key."""
    for key in (None, KEY_A):
        pin(sid, key)
        world.refuse = NetmikoTimeoutException("TCP connection to device failed.")
        with pytest.raises(NetmikoTimeoutException, match="^TCP connection to device failed.$"):
            await sshcli.run_shows(row(sid), ["show version"])
    assert row(sid)["ssh_host_key"] == KEY_A


async def test_the_nightly_backup_refuses_a_changed_key(world, sid):
    """backup_config (nightly, manual, the preview's read): no login, no backup, the pin stays; the answer carries the whole text."""
    pin(sid, KEY_A)
    world.offer(KEY_B)
    assert await sshcli.backup_config(sid) == {"ok": False, "error": f"HostKeyMismatch: {mismatch_text(HOST, KEY_A)}", "host_key": True}
    assert world.logins == 0 and query("SELECT count(*) FROM config_backups")[0][0] == 0 and row(sid)["ssh_host_key"] == KEY_A


async def test_fresh_cfg_names_a_refused_host_key(world, sid):
    pin(sid, KEY_A)
    world.offer(KEY_B)
    with pytest.raises(changes.HostKeyRefused, match="passt nicht zum gemerkten"):
        await changes.fresh_cfg(sid)


async def test_other_failures_of_the_read_are_no_host_key_refusal(world, sid):
    """A switch that does not answer: backup_config's answer has no host_key, fresh_cfg raises a plain RuntimeError (main may then fall
    back to any write identity), with the message of the backup."""
    pin(sid, KEY_A)
    world.refuse = NetmikoTimeoutException("TCP connection to device failed.")
    assert await sshcli.backup_config(sid) == {"ok": False, "error": "NetmikoTimeoutException: TCP connection to device failed."}
    with pytest.raises(RuntimeError, match="^NetmikoTimeoutException: TCP connection to device failed.$") as caught:
        await changes.fresh_cfg(sid)
    assert not isinstance(caught.value, changes.HostKeyRefused)


async def test_fresh_cfg_refuses_with_the_whole_message(world, sid):
    """HostKeyRefused carries backup_config's error as it is: the remedy at its end included."""
    pin(sid, KEY_A)
    world.offer(KEY_B)
    with pytest.raises(changes.HostKeyRefused) as caught:
        await changes.fresh_cfg(sid)
    assert str(caught.value) == f"HostKeyMismatch: {mismatch_text(HOST, KEY_A)}"


async def test_a_long_host_keeps_the_remedy_in_the_change(world):
    sid = add_switch("sw-" + "a" * 57 + ".org")    # 64 characters: the message is longer than 300
    pin(sid, KEY_A)
    world.offer(KEY_B)
    cid = await changes.create_change(sid, "tester", "save", "Speichern", {}, {"shown": [], "desired": {}, "before": {}, "mechanism": "ssh"})
    await changes.run_change(cid)
    assert change_row(cid)["error"] == f"HostKeyMismatch: {mismatch_text('sw-' + 'a' * 57 + '.org', KEY_A)}"


def test_port_access_shows_the_whole_mismatch(api, world):
    sid = create(api, ssh_user="manager", ssh_pass="ssh-s3cret")
    pin(sid, KEY_A)
    world.offer(KEY_B)
    r = api.post(f"/api/switches/{sid}/port-access")
    assert (r.status_code, r.json()["detail"]) == (502, f"HostKeyMismatch: {mismatch_text('203.0.113.42', KEY_A)}")


def test_error_text_is_what_the_connection_test_and_the_backup_report():
    """sshcli.error_text (before: _error, which stays as an alias): type and text, the text cut to 200 characters, except for a
    HostKeyMismatch."""
    long_host = "sw-" + "a" * 57 + ".org"
    assert sshcli._error is sshcli.error_text
    assert sshcli.error_text(RuntimeError("x" * 250)) == "RuntimeError: " + "x" * 200
    assert sshcli.error_text(sshcli.HostKeyMismatch(long_host, KEY_A)) == f"HostKeyMismatch: {mismatch_text(long_host, KEY_A)}"


def test_the_error_of_a_change_is_masked_then_cut_except_for_a_host_key_mismatch():
    """changes._error_text, the error of a change that ends with an exception (run_change and _run_snmp): masked, then cut to 300
    characters, except for a HostKeyMismatch, whose end says what to do."""
    long_host = "sw-" + "a" * 57 + ".org"

    def mask(text: str) -> str:    # a stand-in for the change's mask
        return text.replace("s3cret", "***")
    assert changes._error_text(RuntimeError("s3cret " + "x" * 400), mask) == "RuntimeError: *** " + "x" * 296
    mismatch = sshcli.HostKeyMismatch(long_host, KEY_A)
    assert len(str(mismatch)) > 300
    assert changes._error_text(mismatch, mask) == f"HostKeyMismatch: {mismatch_text(long_host, KEY_A)}"


async def test_a_matching_key_lets_the_change_run(world, sid):
    """The positive control of the run_change test above: the pinned key offered, the session opens and reads the configuration."""
    pin(sid, KEY_A)
    cid = await changes.create_change(sid, "tester", "save", "Speichern", {}, {"shown": [], "desired": {}, "before": {}, "mechanism": "ssh"})
    await changes.run_change(cid)
    assert change_row(cid)["status"] == "ok" and world.logins == 1


# ── The first contact under concurrency ───────────────────────────────────────────────────────────────────────────────────────────
async def test_a_key_pinned_meanwhile_wins_over_the_first_contact(world, sid):
    """Between the AutoAdd login and the pin someone else pinned another key: the UPDATE (only where none is pinned) changes nothing,
    the session's key differs from the stored one, so the session is closed and refused."""
    world.during_login = lambda: pin(sid, KEY_B)
    res = await sshcli.test_ssh(row(sid))
    assert res == {"ok": False, "error": f"HostKeyMismatch: {mismatch_text(HOST, KEY_B, after_login=True)}"}
    assert row(sid)["ssh_host_key"] == KEY_B and world.disconnects == 1


async def test_no_pin_for_an_entry_whose_host_changed_meanwhile(world, sid):
    """The row's host is no longer the switch's (a PUT moved it during the login): its key is not pinned for the new host, and the
    session is closed and refused."""
    world.during_login = lambda: query("UPDATE switches SET host = '203.0.113.99' WHERE id = ?", (sid,))
    res = await sshcli.test_ssh(row(sid))
    assert res["ok"] is False and res["error"].startswith(f"HostKeyMismatch: SSH-Hostschlüssel von {HOST} ließ sich nicht merken")
    assert row(sid)["ssh_host_key"] is None and world.disconnects == 1


async def test_no_pin_for_the_entry_that_took_over_the_address_meanwhile(world, sid):
    """During the login the entry moves away and another one takes over its address (host is unique, so only this way does another
    row have the session's host): the key is pinned for neither, the other entry pins on its own first contact."""
    other = add_switch("203.0.113.22")

    def swap():
        query("UPDATE switches SET host = '203.0.113.99' WHERE id = ?", (sid,))
        query("UPDATE switches SET host = ? WHERE id = ?", (HOST, other))

    world.during_login = swap
    res = await sshcli.test_ssh(row(sid))
    assert res["ok"] is False and res["error"].startswith(f"HostKeyMismatch: SSH-Hostschlüssel von {HOST} ließ sich nicht merken")
    assert [(r["host"], r["ssh_host_key"], r["ssh_host_key_at"]) for r in (row(sid), row(other))] == [("203.0.113.99", None, None),
                                                                                                      (HOST, None, None)]


def test_a_driver_without_cli_fails_before_anything_else(world, monkeypatch):
    """NoCliError comes first, as in _device: the pin is not even read, and no session opens (R39)."""
    sid = add_switch("203.0.113.31")
    query("UPDATE switches SET driver = 'cisco' WHERE id = ?", (sid,))
    reads: list[tuple] = []
    monkeypatch.setattr(sshcli, "query_sync", lambda *args: reads.append(args) or [])
    with pytest.raises(sshcli.NoCliError, match="^Treiber cisco hat keine SSH-CLI$"):
        sshcli.connect(row(sid))
    assert reads == [] and world.params == []


async def test_no_session_for_a_switch_that_is_gone(world, sid):
    """A row whose switch was deleted after it was read: no session at all (there is no pin to decide on)."""
    stale = row(sid)
    query("DELETE FROM switches WHERE id = ?", (sid,))
    assert (await sshcli.test_ssh(stale)) == {"ok": False, "error": "RuntimeError: Switch nicht gefunden"}
    assert world.params == []


# ── The key over the API ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_the_switch_list_serves_the_fingerprints_of_the_pinned_key(api):
    sid = create(api)
    s = listed(api, sid)
    assert (s["ssh_host_key_fp"], s["ssh_host_key_md5"], s["ssh_host_key_at"]) == (None, None, None)
    query("UPDATE switches SET ssh_host_key = ?, ssh_host_key_at = '2026-11-06 08:00:00' WHERE id = ?", (KEY_A, sid))
    s = listed(api, sid)
    assert (s["ssh_host_key_fp"], s["ssh_host_key_md5"], s["ssh_host_key_at"]) == (
        pkey(KEY_A).fingerprint, ":".join(f"{b:02x}" for b in pkey(KEY_A).get_fingerprint()), "2026-11-06 08:00:00")
    assert "ssh_host_key" not in s and KEY_A.split()[1] not in api.get("/api/switches").text


def test_forgetting_clears_key_and_time_and_audits_the_old_fingerprint(api):
    sid, other = create(api), create(api, name="SW-VK-03", host="203.0.113.43")
    query("UPDATE switches SET ssh_host_key = ?, ssh_host_key_at = '2026-11-06 08:00:00' WHERE id = ?", (KEY_A, sid))
    query("UPDATE switches SET ssh_host_key = ?, ssh_host_key_at = '2026-11-06 09:00:00' WHERE id = ?", (KEY_B, other))
    assert api.delete(f"/api/switches/{sid}/ssh-host-key").json() == {"ok": True}
    assert (row(sid)["ssh_host_key"], row(sid)["ssh_host_key_at"]) == (None, None)
    assert (row(other)["ssh_host_key"], row(other)["ssh_host_key_at"]) == (KEY_B, "2026-11-06 09:00:00")    # only this switch's
    assert tuple(query("SELECT username, action, target, detail FROM audit ORDER BY id DESC LIMIT 1")[0]) == (
        "tester", "switch_hostkey_reset", "203.0.113.42", pkey(KEY_A).fingerprint)


def test_forgetting_the_key_of_a_missing_switch_is_404(api):
    r = api.delete("/api/switches/4711/ssh-host-key")
    assert (r.status_code, r.json()) == (404, {"detail": "Switch nicht gefunden"})


def test_a_new_address_keeps_the_pinned_key(api, world):
    """update_switch clears secrets on a new host (F2), never the key: a re-pointed entry still meets the device's key, so a different
    device behind the new address is refused until someone forgets the key."""
    sid = create(api, ssh_user="manager", ssh_pass="ssh-s3cret")
    query("UPDATE switches SET ssh_host_key = ?, ssh_host_key_at = '2026-11-06 08:00:00' WHERE id = ?", (KEY_A, sid))
    r = api.put(f"/api/switches/{sid}", json=body(host="203.0.113.43", ssh_user="manager", ssh_pass="ssh-s3cret"))
    assert r.status_code == 200, r.text
    assert (row(sid)["ssh_host_key"], row(sid)["ssh_host_key_at"]) == (KEY_A, "2026-11-06 08:00:00")
    world.offer(KEY_B)
    assert asyncio.run(sshcli.test_ssh(row(sid)))["ok"] is False and world.logins == 0
    assert world.known_hosts == [f"203.0.113.43 {KEY_A}\n"]


# ── Fingerprints ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("key", [KEY_A, _openssh(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())],
                         ids=["ed25519", "rsa"])
def test_fingerprints_are_written_as_openssh_writes_them(key):
    """SHA256 in base64 without padding, MD5 as colon-separated hex pairs, both over the key bytes (paramiko is the oracle)."""
    assert sshcli.fingerprints(key) == {"sha256": pkey(key).fingerprint, "md5": ":".join(f"{b:02x}" for b in pkey(key).get_fingerprint())}


@pytest.mark.parametrize("key", [None, "", "ssh-ed25519", "ssh-ed25519 not*base64"])
def test_no_fingerprints_without_a_readable_key(key):
    assert sshcli.fingerprints(key) is None


def test_host_key_of_reads_the_key_the_server_offered():
    conn = Session(Paramikoish(), pkey(KEY_B))
    assert sshcli.host_key_of(conn) == KEY_B


# ── TLS defaults ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
class EmptyArp(apifix.Remote):
    """An OPNsense with an empty ARP table: with {} names.opnsense_arp would take the answer for an unexpected one."""

    def reply(self, method: str, url: str):
        return []


def test_tls_verification_defaults_on_where_the_clients_are_made(world, monkeypatch):
    """pf.config and names.opnsense_arp read a missing row as on, and a stored "0" as off, as before."""
    remote = EmptyArp()
    monkeypatch.setattr(names, "httpx", apifix.fake_httpx(remote))
    for k, v in (("opnsense_url", "https://opnsense.example.org"), ("opnsense_key", crypto.encrypt("k")),
                 ("opnsense_secret", crypto.encrypt("s"))):
        asyncio.run(db.set_setting(k, v))
    assert asyncio.run(pf.config())["verify"] is True
    asyncio.run(names.opnsense_arp())
    for k in ("pf_verify_tls", "opnsense_verify_tls"):
        asyncio.run(db.set_setting(k, "0"))
    assert asyncio.run(pf.config())["verify"] is False
    asyncio.run(names.opnsense_arp())
    assert [k["verify"] for k in remote.made] == [True, False]


def test_a_settings_put_without_the_tls_fields_turns_verification_on(api):
    r = api.put("/api/settings", json={"poll_minutes": 15})
    assert r.status_code == 200, r.text
    stored = [tuple(r) for r in query("SELECT key, value FROM settings WHERE key LIKE '%verify_tls' ORDER BY key")]
    assert stored == [("opnsense_verify_tls", "1"), ("pf_verify_tls", "1")]


def test_change_rows_name_the_refusal(world, sid):
    """The error of a refused change, as GET /api/changes serves it: the type and the pinned fingerprint."""
    pin(sid, KEY_A)
    world.offer(KEY_B)
    cid = asyncio.run(changes.create_change(sid, "tester", "save", "Speichern", {}, {"shown": [], "desired": {}, "before": {},
                                                                                      "mechanism": "ssh"}))
    asyncio.run(changes.run_change(cid))
    ch = change_row(cid)
    assert ch["error"].startswith(f"HostKeyMismatch: SSH-Hostschlüssel von {HOST} passt nicht zum gemerkten ({pkey(KEY_A).fingerprint})")
    assert [s[1] for s in json.loads(ch["steps"])][-1] == ch["error"] and world.logins == 0
