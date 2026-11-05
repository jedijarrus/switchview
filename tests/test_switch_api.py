"""Switch CRUD over the HTTP API for the SNMP multivendor fields: driver, snmp_write and the separate SNMP read-write identity
(snmp_rw_*), in POST / PUT / GET /api/switches and the switch entries of /api/netmap (the data of the switch detail view).

What an operator relies on:
- the RW secrets (snmp_rw_community, snmp_rw_auth_pass, snmp_rw_priv_pass) are stored Fernet-encrypted like the read secrets, and a
  PUT that leaves one None keeps it ("" clears it);
- GET never serves a secret column, old or new, in any form: the serialization is an allowlist, of each secret only a *_set flag;
- a row from before this work is served as before, plus additions only (the current frontend keeps working), and a PUT from the
  current frontend, which knows none of the new fields, leaves them as they are;
- a host never starts with "-" (net-snmp would read it as an option), and the driver is one of drivers.DRIVERS.

The app runs in-process through FastAPI's TestClient, created without `with`, so its lifespan (init_db, the scheduler with the poll,
names, backup and pf jobs) never runs, and the scheduler is booby-trapped on top. Each test gets its own database under tmp_path.
auth.current_user is overridden (no session needed); every request still carries the CSRF header the app wants on non-GET requests.
"""
import asyncio
import base64
import hashlib
import json
import os
import sqlite3

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import auth
import config
import crypto
import db
import main
import poller

USER = {"username": "tester", "name": "Tester", "method": "local"}
# Written out by hand, not taken from main: every secret column of switches, the read ones and the RW ones.
SECRET_COLUMNS = ("snmp_community", "snmp_auth_pass", "snmp_priv_pass", "ssh_pass", "snmp_rw_community", "snmp_rw_auth_pass",
                  "snmp_rw_priv_pass")
# The keys GET /api/switches served for a row before this work (main._public as a denylist over the original schema).
OLD_KEYS = {"id", "name", "host", "zone", "sort", "enabled", "snmp_version", "snmp_user", "snmp_auth_proto", "snmp_priv_proto",
            "ssh_user", "sys_name", "sys_descr", "model", "firmware", "base_mac", "uptime", "last_poll", "last_poll_ok", "last_error",
            "created_at", "snmp_community_set", "snmp_auth_pass_set", "snmp_priv_pass_set", "ssh_pass_set"}
# ... and what this work adds to them, nothing else.
NEW_KEYS = {"driver", "caps", "snmp_write", "snmp_rw_user", "snmp_rw_auth_proto", "snmp_rw_priv_proto", "snmp_rw_community_set",
            "snmp_rw_auth_pass_set", "snmp_rw_priv_pass_set", "snmp_rw_insecure", "snmp_write_via", "snmp_write_error"}
PUBLIC = "Community 'public' wird nicht zum Schreiben verwendet – bitte eine eigene Schreib-Community hinterlegen"
CISCO_CAPS = ["snmp_admin", "snmp_name", "snmp_poe", "snmp_vlan"]
PROCURVE_CAPS = ["backup", "cli", "nac", "snmp_admin", "snmp_autosave", "snmp_name", "snmp_poe", "snmp_vlan"]
# Independent of crypto.py: the Fernet key the app must derive from SECRET_KEY (set by conftest.py).
TEST_FERNET = Fernet(base64.urlsafe_b64encode(hashlib.sha256(os.environ["SECRET_KEY"].encode()).digest()))

RW_V3 = {"snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA-256", "snmp_rw_auth_pass": "rw-auth-s3cret",
         "snmp_rw_priv_proto": "AES-256", "snmp_rw_priv_pass": "rw-priv-s3cret"}
ALL_SECRETS = {"snmp_community": "ro-s3cret", "snmp_auth_pass": "ro-auth-s3cret", "snmp_priv_pass": "ro-priv-s3cret",
               "ssh_pass": "ssh-s3cret", "snmp_rw_community": "rw-s3cret", "snmp_rw_auth_pass": "rw-auth-s3cret",
               "snmp_rw_priv_pass": "rw-priv-s3cret"}


def _never(*args, **kwargs):
    raise AssertionError("the scheduler must not start in a test (no background polling, no network)")


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient on main.app whose db() opens tmp_path/switchview.db (not created yet, see the api fixture)."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    monkeypatch.setattr(main.scheduler, "start", _never)
    main.app.dependency_overrides[auth.current_user] = lambda: USER
    try:
        yield TestClient(main.app, headers={"X-Requested-With": "SwitchView"})
    finally:
        main.app.dependency_overrides.pop(auth.current_user, None)


@pytest.fixture
def api(client):
    """The client against a fresh database, set up by the app's own init_db (schema plus migration)."""
    asyncio.run(db.init_db())
    return client


def stored(tmp_path, sid: int) -> sqlite3.Row:
    """The switches row as it sits in the database."""
    conn = sqlite3.connect(tmp_path / "switchview.db")
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)).fetchone()
    finally:
        conn.close()


def audits(tmp_path) -> list[tuple]:
    conn = sqlite3.connect(tmp_path / "switchview.db")
    try:
        return conn.execute("SELECT action, target, detail FROM audit ORDER BY id").fetchall()
    finally:
        conn.close()


def body(**fields) -> dict:
    return {"name": "SW-VK-02", "host": "203.0.113.42", "zone": "VK", **fields}


def old_ui_body(**fields) -> dict:
    """What the switch form of the current frontend (app.js editSwitch) sends: none of the new fields, both v3 selects filled."""
    return {"name": "SW-VK-02", "host": "203.0.113.42", "zone": "VK", "sort": 0, "enabled": True, "snmp_version": "2c",
            "snmp_community": None, "snmp_user": None, "snmp_auth_proto": "SHA", "snmp_auth_pass": None, "snmp_priv_proto": "AES",
            "snmp_priv_pass": None, "ssh_user": None, "ssh_pass": None, **fields}


def create(api, **fields) -> int:
    r = api.post("/api/switches", json=body(**fields))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def listed(api, sid: int) -> dict:
    r = api.get("/api/switches")
    assert r.status_code == 200, r.text
    return next(s for s in r.json() if s["id"] == sid)


def assert_encrypted(value, plain: str):
    """A Fernet token under the app's SECRET_KEY that decrypts to `plain` (and so is not `plain` itself)."""
    assert value and value != plain and plain not in value
    assert TEST_FERNET.decrypt(value.encode()).decode() == plain
    assert crypto.decrypt(value) == plain


# ── POST ──────────────────────────────────────────────────────────────────────
def test_create_cisco_with_snmp_write_and_a_rw_community(api, tmp_path):
    sid = create(api, driver="cisco", snmp_write=True, snmp_community="ro-s3cret", snmp_rw_community="rw-s3cret")

    row = stored(tmp_path, sid)
    assert row["driver"] == "cisco" and row["snmp_write"] == 1
    assert_encrypted(row["snmp_rw_community"], "rw-s3cret")
    assert_encrypted(row["snmp_community"], "ro-s3cret")
    assert not any("s3cret" in str(v) for v in tuple(row))      # no plain text anywhere in the row
    assert poller.creds_of(row, write=True)["snmp_community"] == "rw-s3cret"
    assert poller.creds_of(row)["snmp_community"] == "ro-s3cret"


def test_create_with_a_rw_v3_user(api, tmp_path):
    sid = create(api, driver="aruba_cx", snmp_write=True, **RW_V3)

    row = stored(tmp_path, sid)
    assert (row["snmp_rw_user"], row["snmp_rw_auth_proto"], row["snmp_rw_priv_proto"]) == ("svwrite", "SHA-256", "AES-256")
    assert_encrypted(row["snmp_rw_auth_pass"], "rw-auth-s3cret")
    assert_encrypted(row["snmp_rw_priv_pass"], "rw-priv-s3cret")
    assert row["snmp_rw_community"] is None
    assert poller.creds_of(row, write=True) == {
        "snmp_version": "3", "snmp_community": None, "snmp_user": "svwrite", "snmp_auth_proto": "SHA-256",
        "snmp_auth_pass": "rw-auth-s3cret", "snmp_priv_proto": "AES-256", "snmp_priv_pass": "rw-priv-s3cret"}


def test_create_as_the_current_frontend_does_is_procurve_without_snmp_write(api, tmp_path):
    r = api.post("/api/switches", json=old_ui_body(snmp_community="ro-s3cret"))
    assert r.status_code == 200, r.text

    row = stored(tmp_path, r.json()["id"])
    assert row["driver"] == "procurve" and row["snmp_write"] == 0
    assert all(row[k] is None for k in ("snmp_rw_community", "snmp_rw_user", "snmp_rw_auth_proto", "snmp_rw_auth_pass",
                                        "snmp_rw_priv_proto", "snmp_rw_priv_pass"))


def test_create_stores_empty_rw_fields_as_null(api, tmp_path):
    sid = create(api, snmp_rw_community="", snmp_rw_user="", snmp_rw_auth_proto="", snmp_rw_auth_pass="", snmp_rw_priv_proto="",
                 snmp_rw_priv_pass="")
    row = stored(tmp_path, sid)
    assert all(row[k] is None for k in ("snmp_rw_community", "snmp_rw_user", "snmp_rw_auth_proto", "snmp_rw_auth_pass",
                                        "snmp_rw_priv_proto", "snmp_rw_priv_pass"))


# ── PUT ───────────────────────────────────────────────────────────────────────
def test_update_keeps_rw_secrets_left_none_and_clears_them_with_empty(api, tmp_path):
    sid = create(api, driver="cisco", snmp_write=True, snmp_rw_community="rw-s3cret", **RW_V3)
    before = stored(tmp_path, sid)
    rw_plain = {k: v for k, v in RW_V3.items() if not k.endswith("_pass")}

    for secrets in ({}, {"snmp_rw_community": None, "snmp_rw_auth_pass": None, "snmp_rw_priv_pass": None}):  # absent, then null
        r = api.put(f"/api/switches/{sid}", json=body(driver="cisco", snmp_write=True, **rw_plain, **secrets))
        assert r.status_code == 200, r.text
        after = stored(tmp_path, sid)
        for k in ("snmp_rw_community", "snmp_rw_auth_pass", "snmp_rw_priv_pass"):
            assert after[k] == before[k], k            # the very same ciphertext, not re-encrypted, not cleared

    r = api.put(f"/api/switches/{sid}", json=body(driver="cisco", snmp_write=True, snmp_rw_community="rw-n3w", **RW_V3))
    assert r.status_code == 200, r.text
    after = stored(tmp_path, sid)
    assert_encrypted(after["snmp_rw_community"], "rw-n3w")
    assert_encrypted(after["snmp_rw_auth_pass"], "rw-auth-s3cret")
    assert after["snmp_rw_auth_pass"] != before["snmp_rw_auth_pass"]  # sent again, so stored anew

    r = api.put(f"/api/switches/{sid}", json=body(driver="cisco", snmp_write=True, snmp_rw_community="", snmp_rw_auth_pass="",
                                                  snmp_rw_priv_pass=""))
    assert r.status_code == 200, r.text
    after = stored(tmp_path, sid)
    assert (after["snmp_rw_community"], after["snmp_rw_auth_pass"], after["snmp_rw_priv_pass"]) == (None, None, None)


def test_update_from_the_current_frontend_leaves_the_new_fields_alone(api, tmp_path):
    """The form of today's app.js knows none of the new fields. Its PUT must neither reset the driver to procurve, nor switch SNMP
    writing off, nor drop the RW user (the write path would then silently fall back to the read identity)."""
    sid = create(api, driver="cisco", snmp_write=True, snmp_community="ro-s3cret", snmp_rw_community="rw-s3cret", **RW_V3)
    before = stored(tmp_path, sid)

    r = api.put(f"/api/switches/{sid}", json=old_ui_body(name="SW-VK-02a"))
    assert r.status_code == 200, r.text

    after = stored(tmp_path, sid)
    assert after["name"] == "SW-VK-02a"
    for k in ("driver", "snmp_write", "snmp_rw_community", "snmp_rw_user", "snmp_rw_auth_proto", "snmp_rw_auth_pass",
              "snmp_rw_priv_proto", "snmp_rw_priv_pass", "snmp_community"):
        assert after[k] == before[k], k
    assert poller.creds_of(after, write=True)["snmp_user"] == "svwrite"


def test_update_sets_and_clears_the_new_fields_when_sent(api, tmp_path):
    sid = create(api, driver="cisco", snmp_write=True, **RW_V3)

    r = api.put(f"/api/switches/{sid}", json=body(driver="juniper", snmp_write=False, snmp_rw_user=None, snmp_rw_auth_proto=None,
                                                  snmp_rw_priv_proto=None))
    assert r.status_code == 200, r.text

    row = stored(tmp_path, sid)
    assert (row["driver"], row["snmp_write"]) == ("juniper", 0)
    assert (row["snmp_rw_user"], row["snmp_rw_auth_proto"], row["snmp_rw_priv_proto"]) == (None, None, None)
    assert_encrypted(row["snmp_rw_auth_pass"], "rw-auth-s3cret")      # secrets: None keeps

    r = api.put(f"/api/switches/{sid}", json=body(snmp_write=True, snmp_rw_user="sv2", snmp_rw_auth_proto="SHA"))
    assert r.status_code == 200, r.text
    row = stored(tmp_path, sid)
    assert (row["driver"], row["snmp_write"], row["snmp_rw_user"], row["snmp_rw_auth_proto"]) == ("juniper", 1, "sv2", "SHA")


def test_update_of_a_missing_switch_is_404(api):
    assert api.put("/api/switches/4711", json=body(driver="cisco")).status_code == 404


# ── validation ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("driver", ["nonsense", "", "Cisco", "PROCURVE", "cisco ", "generic;", "x" * 33])
def test_unknown_driver_is_422(api, tmp_path, driver):
    assert api.post("/api/switches", json=body(driver=driver)).status_code == 422
    sid = create(api, driver="cisco", host="203.0.113.43")
    assert api.put(f"/api/switches/{sid}", json=body(driver=driver, host="203.0.113.43")).status_code == 422
    assert stored(tmp_path, sid)["driver"] == "cisco"
    assert [s["id"] for s in api.get("/api/switches").json()] == [sid]     # the refused POST stored nothing


@pytest.mark.parametrize("driver", ["procurve", "aruba_cx", "cisco", "cisco_sb", "comware", "juniper", "arista", "dell", "netgear",
                                    "mikrotik", "generic"])
def test_every_known_driver_is_accepted(api, tmp_path, driver):
    assert stored(tmp_path, create(api, driver=driver))["driver"] == driver


@pytest.mark.parametrize("host", ["-evil", "-", "--help", "-v3", "-1.2.3.4", "-Cr25", ".evil", "evil host", "a" * 65, ""])
def test_bad_host_is_422(api, tmp_path, host):
    """Above all a leading "-": net-snmp gets the host positionally and would parse it as an option."""
    assert api.post("/api/switches", json=body(host=host)).status_code == 422
    sid = create(api)
    assert api.put(f"/api/switches/{sid}", json=body(host=host)).status_code == 422
    assert stored(tmp_path, sid)["host"] == "203.0.113.42"


@pytest.mark.parametrize("host", ["sw-ek-01", "a", "9", "sw-ek-01.example.org", "sw-", "203.0.113.42", "fe80::1", "a" * 64])
def test_good_host_is_accepted(api, tmp_path, host):
    assert stored(tmp_path, create(api, host=host))["host"] == host


@pytest.mark.parametrize("field, value", [
    ("snmp_rw_auth_proto", "SHA1"), ("snmp_rw_auth_proto", "sha"), ("snmp_rw_priv_proto", "3DES"), ("snmp_rw_priv_proto", "aes"),
    ("snmp_rw_community", "c" * 65), ("snmp_rw_user", "u" * 65), ("snmp_rw_auth_pass", "p" * 129), ("snmp_rw_priv_pass", "p" * 129),
    ("snmp_write", "maybe"), ("snmp_write", None), ("driver", None),
])
def test_bad_rw_field_is_422(api, tmp_path, field, value):
    assert api.post("/api/switches", json=body(**{field: value})).status_code == 422
    sid = create(api)
    assert api.put(f"/api/switches/{sid}", json=body(**{field: value})).status_code == 422


def test_longest_rw_fields_are_accepted(api, tmp_path):
    sid = create(api, snmp_rw_community="c" * 64, snmp_rw_user="u" * 64, snmp_rw_auth_proto="SHA-512", snmp_rw_auth_pass="p" * 128,
                 snmp_rw_priv_proto="DES", snmp_rw_priv_pass="q" * 128)
    row = stored(tmp_path, sid)
    assert_encrypted(row["snmp_rw_community"], "c" * 64)
    assert_encrypted(row["snmp_rw_priv_pass"], "q" * 128)


# ── GET: what is served ───────────────────────────────────────────────────────
def test_list_never_serves_a_secret_column(api, tmp_path):
    sid = create(api, driver="cisco", snmp_write=True, snmp_version="3", snmp_user="monitor", snmp_auth_proto="SHA",
                 snmp_priv_proto="AES", ssh_user="manager", **ALL_SECRETS, **{k: v for k, v in RW_V3.items() if k not in ALL_SECRETS})
    bare = create(api, host="203.0.113.43")
    row = stored(tmp_path, sid)

    r = api.get("/api/switches")
    assert r.status_code == 200
    s, b = listed(api, sid), listed(api, bare)
    for k in SECRET_COLUMNS:
        assert k not in s and k not in b, k                         # the key itself, not just its plain text
        assert s[k + "_set"] is True and b[k + "_set"] is False, k
    for k, plain in ALL_SECRETS.items():                             # nor any value of it, under any key
        assert plain not in r.text and row[k] not in r.text, k


def test_list_serves_driver_caps_and_snmp_write(api):
    cisco = create(api, driver="cisco", snmp_write=True, snmp_rw_community="rw-s3cret")
    procurve = create(api, host="203.0.113.43")

    c, p = listed(api, cisco), listed(api, procurve)
    assert (c["driver"], c["caps"], c["snmp_write"]) == ("cisco", CISCO_CAPS, True)
    assert (p["driver"], p["caps"], p["snmp_write"]) == ("procurve", PROCURVE_CAPS, False)
    assert c["snmp_write"] is True and p["snmp_write"] is False
    assert set(c) == set(p) == OLD_KEYS | NEW_KEYS


def test_list_serves_the_non_secret_rw_fields(api):
    s = listed(api, create(api, snmp_write=True, **RW_V3))
    assert (s["snmp_rw_user"], s["snmp_rw_auth_proto"], s["snmp_rw_priv_proto"]) == ("svwrite", "SHA-256", "AES-256")
    assert (s["snmp_rw_community_set"], s["snmp_rw_auth_pass_set"], s["snmp_rw_priv_pass_set"]) == (False, True, True)


# (case, POST fields): how the write identity is described, without a secret
WRITE_INFO = [
    ("snmp_write off", {"snmp_community": "ro-s3cret", "snmp_rw_community": "rw-s3cret"},
     (False, None, "SNMP-Schreiben ist für diesen Switch nicht aktiviert")),
    ("rw v2c community", {"snmp_write": True, "snmp_rw_community": "rw-s3cret"}, (True, "rw", None)),
    ("rw v3 authPriv", {"snmp_write": True, **RW_V3}, (False, "rw", None)),
    ("rw v3 authNoPriv", {"snmp_write": True, "snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA",
                          "snmp_rw_auth_pass": "rw-auth-s3cret"}, (False, "rw", None)),
    ("rw v3 noAuthNoPriv", {"snmp_write": True, "snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA", "snmp_rw_priv_proto": "AES"},
     (True, "rw", None)),
    ("read v2c community", {"snmp_write": True, "snmp_community": "ro-s3cret"}, (True, "read", None)),
    ("read v3 authPriv", {"snmp_write": True, "snmp_version": "3", "snmp_user": "monitor", "snmp_auth_proto": "SHA",
                          "snmp_auth_pass": "ro-auth-s3cret", "snmp_priv_proto": "AES", "snmp_priv_pass": "ro-priv-s3cret"},
     (False, "read", None)),
    ("nothing to write with", {"snmp_write": True}, (False, None, "Keine SNMP-Schreib-Zugangsdaten hinterlegt")),
    ("rw v2c 'private'", {"snmp_write": True, "snmp_rw_community": "private"}, (True, "rw", None)),
    ("rw v2c 'public' (R25)", {"snmp_write": True, "snmp_community": "ro-s3cret", "snmp_rw_community": "public"}, (False, None, PUBLIC)),
    ("read v2c ' Public ' (R25)", {"snmp_write": True, "snmp_community": " Public "}, (False, None, PUBLIC)),
]


@pytest.mark.parametrize("fields, want", [c[1:] for c in WRITE_INFO], ids=[c[0] for c in WRITE_INFO])
def test_list_describes_the_write_identity(api, fields, want):
    """snmp_rw_insecure: writing would go out spoofable (v2c community in plain text, v3 without authentication), the UI warns
    loudly; snmp_write_via: which identity writes ("rw", or "read": the read identity must then be allowed to write on the device),
    None with the reason in snmp_write_error. All from poller.creds_of(row, write=True)'s rule."""
    s = listed(api, create(api, driver="cisco", **fields))
    assert (s["snmp_rw_insecure"], s["snmp_write_via"], s["snmp_write_error"]) == want


def test_a_legacy_row_is_served_as_before_plus_additions_only(client, tmp_path):
    """A switch stored by the release before this work: after the migration it is served with every key and value it had (the old
    denylist serializer, rebuilt here as the oracle, over the original schema), plus exactly the new keys."""
    conn = sqlite3.connect(tmp_path / "switchview.db")
    conn.row_factory = sqlite3.Row
    conn.executescript(db.SCHEMA)       # the original schema, without the migrated columns
    conn.execute("INSERT INTO switches(name, host, zone, sort, enabled, snmp_version, snmp_community, snmp_user, snmp_auth_proto, "
                 "snmp_auth_pass, snmp_priv_proto, snmp_priv_pass, ssh_user, ssh_pass, sys_name, sys_descr, model, firmware, base_mac, "
                 "uptime, last_poll, last_poll_ok, last_error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 ("SW-EK-01", "203.0.113.21", "EK", 3, 1, "2c", crypto.encrypt("ro-s3cret"), None, "SHA", None, "AES", None, "manager",
                  crypto.encrypt("ssh-s3cret"), "SW-EK-01", "HP J9729A 2920-48G Switch, revision WB.16.99.0001", "J9729A 2920-48G",
                  "WB.16.99.0001", "00:11:22:33:44:55", 123456, "2026-11-04 08:00:00", 1, None))
    conn.commit()
    legacy = conn.execute("SELECT * FROM switches").fetchone()
    old_secrets = ("snmp_community", "snmp_auth_pass", "snmp_priv_pass", "ssh_pass")
    old = {k: legacy[k] for k in legacy.keys() if k not in old_secrets} | {k + "_set": bool(legacy[k]) for k in old_secrets}
    conn.close()
    assert set(old) == OLD_KEYS

    asyncio.run(db.init_db())          # what the app does at start: the migration adds the new columns
    s = listed(client, old["id"])

    assert {k: s[k] for k in old} == old
    assert set(s) - set(old) == NEW_KEYS
    assert (s["driver"], s["caps"], s["snmp_write"], s["snmp_rw_insecure"], s["snmp_write_via"]) == (
        "procurve", PROCURVE_CAPS, False, False, None)
    assert not any(s[k + "_set"] for k in ("snmp_rw_community", "snmp_rw_auth_pass", "snmp_rw_priv_pass"))


def test_a_column_added_later_is_not_served_until_allowed(api, tmp_path):
    """Default deny: the serializers are allowlists, so a column some later migration adds (here a would-be secret) is served
    neither by GET /api/switches nor in the /api/netmap switch entries until it is listed explicitly. A denylist (every column but
    SECRET_FIELDS) serves today's schema identically and would only fail here."""
    sid = create(api, driver="cisco", snmp_write=True, snmp_rw_community="rw-s3cret")
    conn = sqlite3.connect(tmp_path / "switchview.db")
    try:
        conn.execute("ALTER TABLE switches ADD COLUMN snmp_future_secret TEXT")
        conn.execute("UPDATE switches SET snmp_future_secret = 'f-s3cret' WHERE id = ?", (sid,))
        conn.commit()
    finally:
        conn.close()

    for url in ("/api/switches", "/api/netmap"):
        r = api.get(url)
        assert r.status_code == 200, r.text
        assert "snmp_future_secret" not in r.text and "f-s3cret" not in r.text, url
    assert "snmp_future_secret" not in listed(api, sid)


def test_netmap_switch_entries_serve_driver_caps_and_snmp_write_but_no_secret(api, tmp_path):
    sid = create(api, driver="cisco", snmp_write=True, ssh_user="manager", **ALL_SECRETS)
    row = stored(tmp_path, sid)

    r = api.get("/api/netmap")
    assert r.status_code == 200, r.text
    s = next(x for x in r.json()["switches"] if x["id"] == sid)
    assert (s["driver"], s["caps"], s["snmp_write"]) == ("cisco", CISCO_CAPS, True)
    assert not set(s) & set(SECRET_COLUMNS)
    for k, plain in ALL_SECRETS.items():
        assert plain not in r.text and row[k] not in r.text, k


# ── audit ─────────────────────────────────────────────────────────────────────
def test_update_audit_names_the_changed_secrets_without_values(api, tmp_path):
    sid = create(api, driver="cisco", snmp_write=True)
    api.put(f"/api/switches/{sid}", json=body(snmp_rw_community="rw-s3cret", snmp_rw_auth_pass="rw-auth-s3cret", ssh_pass="ssh-s3cret"))
    api.put(f"/api/switches/{sid}", json=body(snmp_rw_priv_pass=""))
    api.put(f"/api/switches/{sid}", json=body())

    rows = audits(tmp_path)
    assert [(a, t) for a, t, _ in rows] == [("switch_create", "203.0.113.42")] + [("switch_update", "203.0.113.42")] * 3
    assert set(rows[1][2].split(", ")) == {"snmp_rw_community", "snmp_rw_auth_pass", "ssh_pass"}
    assert rows[2][2] == "snmp_rw_priv_pass"
    assert rows[3][2] == ""
    assert "s3cret" not in json.dumps(rows)


def test_audit_records_driver_and_snmp_write(api, tmp_path):
    """Switching SNMP writes on is a privilege change: create names the driver and snmp_write, an update every change of either
    (old → new), after the changed secret names; nothing when they are not sent or unchanged. Never a secret value."""
    sid = create(api)
    steps = [
        body(driver="cisco", snmp_write=True, snmp_rw_community="rw-s3cret"),
        body(driver="cisco", snmp_write=True),                 # sent, unchanged
        old_ui_body(),                                         # not sent
        body(snmp_write=False),
        body(driver="juniper", snmp_write=True, ssh_pass="ssh-s3cret"),
    ]
    for step in steps:
        assert api.put(f"/api/switches/{sid}", json=step).status_code == 200
    create(api, host="203.0.113.43", driver="arista", snmp_write=True)

    rows = audits(tmp_path)
    assert [d for _, _, d in rows] == [
        "SW-VK-02, driver: procurve, snmp_write: aus",
        "snmp_rw_community, driver: procurve → cisco, snmp_write: aus → an",
        "",
        "",
        "snmp_write: an → aus",
        "ssh_pass, driver: cisco → juniper, snmp_write: aus → an",
        "SW-VK-02, driver: arista, snmp_write: an",
    ]
    assert rows[-1][:2] == ("switch_create", "203.0.113.43")
    assert "s3cret" not in json.dumps(rows)


def test_audit_records_the_writing_identity(api, tmp_path):
    """M8: what decides the identity SNMP SETs go out with (poller.write_identity) is audited like driver and snmp_write: the RW v3 user
    and its protocols, and snmp_version / snmp_user (the read identity, which writes when no RW user is set), each as "old → new" when
    sent and changed, an empty value as "–". These fields hold no secret; the passwords stay names only. Clearing the RW user is
    recorded, so a silent switch of the writing identity to the read identity shows."""
    sid = create(api)
    rw = {"snmp_rw_user": "svwrite", "snmp_rw_auth_proto": "SHA-256", "snmp_rw_priv_proto": "AES-256"}
    steps = [
        body(snmp_version="3", snmp_user="svread"),
        body(snmp_version="3", snmp_user="svread", **rw, snmp_rw_auth_pass="rw-auth-s3cret", snmp_rw_priv_pass="rw-priv-s3cret"),
        body(snmp_version="3", snmp_user="svread", **rw),                                     # sent, unchanged
        body(snmp_version="3", snmp_user="svread", snmp_rw_auth_proto="SHA", snmp_rw_priv_proto=None),
        body(snmp_version="3", snmp_user="svread", snmp_rw_user=None),                        # the read identity writes from now on
        body(snmp_version="3", snmp_user="svread2", snmp_auth_pass="ro-auth-s3cret"),
        body(),                                                                               # back to v2c
    ]
    for step in steps:
        assert api.put(f"/api/switches/{sid}", json=step).status_code == 200

    assert [d for _, _, d in audits(tmp_path)][1:] == [
        "snmp_version: 2c → 3, snmp_user: – → svread",
        "snmp_rw_auth_pass, snmp_rw_priv_pass, snmp_rw_user: – → svwrite, snmp_rw_auth_proto: – → SHA-256, snmp_rw_priv_proto: – → AES-256",
        "",
        "snmp_rw_auth_proto: SHA-256 → SHA, snmp_rw_priv_proto: AES-256 → –",
        "snmp_rw_user: svwrite → –",
        "snmp_auth_pass, snmp_user: svread → svread2",
        "snmp_version: 3 → 2c, snmp_user: svread2 → –",
    ]
    assert "s3cret" not in json.dumps(audits(tmp_path))


# ── 422 never echoes a secret ─────────────────────────────────────────────────
MARK = "Zq7-secret-mark"


def too_long(limit: int) -> str:
    """A value one character over `limit`, starting with MARK."""
    return (MARK * 20)[:limit + 1]


# (secret field, a value pydantic rejects): too long, or not a string at all
SECRET_REJECTS = [(f, too_long(64)) for f in ("snmp_community", "snmp_rw_community")] + \
    [(f, too_long(128)) for f in ("snmp_auth_pass", "snmp_priv_pass", "ssh_pass", "snmp_rw_auth_pass", "snmp_rw_priv_pass")] + \
    [("snmp_rw_community", 7177324911), ("ssh_pass", {"nested": MARK}), ("snmp_rw_priv_pass", [MARK])]


@pytest.mark.parametrize("field, value", SECRET_REJECTS, ids=[f"{f}-{type(v).__name__}" for f, v in SECRET_REJECTS])
def test_422_does_not_echo_a_secret(api, field, value):
    sid = create(api, host="203.0.113.43")
    for r in (api.post("/api/switches", json=body(**{field: value})), api.put(f"/api/switches/{sid}", json=body(**{field: value}))):
        assert r.status_code == 422
        assert MARK not in r.text and json.dumps(value) not in r.text and str(value) not in r.text
        err = next(e for e in r.json()["detail"] if e["loc"] == ["body", field])
        assert set(err) == {"type", "loc", "msg"} and err["type"] and err["msg"]     # FastAPI's shape minus input / ctx


def test_422_for_other_fields_is_unchanged(api):
    """FastAPI's default body, exactly: a non-secret field keeps its input and ctx."""
    r = api.post("/api/switches", json=body(zone="Z" * 41))
    assert r.status_code == 422
    assert r.json() == {"detail": [{"type": "string_too_long", "loc": ["body", "zone"], "msg": "String should have at most 40 characters",
                                     "input": "Z" * 41, "ctx": {"max_length": 40}}]}
    r = api.post("/api/switches", json={"host": "203.0.113.42", "zone": "VK", "snmp_rw_user": "svwrite"})
    assert r.json() == {"detail": [{"type": "missing", "loc": ["body", "name"], "msg": "Field required",
                                     "input": {"host": "203.0.113.42", "zone": "VK", "snmp_rw_user": "svwrite"}}]}


def test_422_echoing_the_whole_body_drops_its_secrets(api):
    """A "missing" error carries the whole body as its input: the secret keys go, everything else stays. A body that is no object
    at all comes back without input (it can hold anything)."""
    sent = {"host": "203.0.113.42", "snmp_rw_user": "svwrite", "ssh_pass": MARK, "snmp_rw_community": MARK + "2", "snmp_community": None}
    r = api.post("/api/switches", json=sent)
    assert r.json() == {"detail": [{"type": "missing", "loc": ["body", "name"], "msg": "Field required",
                                     "input": {"host": "203.0.113.42", "snmp_rw_user": "svwrite"}}]}
    for raw in ("snmp_rw_community=" + MARK, [{"ssh_pass": MARK}]):
        r = api.post("/api/switches", json=raw)
        assert r.status_code == 422 and MARK not in r.text
        assert r.json()["detail"][0]["loc"] == ["body"]


@pytest.mark.parametrize("method, url, sent, field", [
    ("POST", "/api/auth/local", {"username": "admin", "password": too_long(200)}, "password"),
    ("PUT", "/api/settings", {"radius_key": too_long(64)}, "radius_key"),
    ("PUT", "/api/settings", {"pf_pass": too_long(200)}, "pf_pass"),
    ("PUT", "/api/settings", {"opnsense_secret": too_long(200)}, "opnsense_secret"),
])
def test_422_does_not_echo_the_secrets_of_other_forms(api, method, url, sent, field):
    """The handler serves the whole app: the login password and the settings secrets are not echoed either."""
    r = api.request(method, url, json=sent)
    assert r.status_code == 422 and MARK not in r.text
    assert [set(e) for e in r.json()["detail"] if e["loc"] == ["body", field]] == [{"type", "loc", "msg"}]
