"""Phase 3, credentials: a secret that no longer decrypts and an SNMPv3 identity that falls to a lower security level are told, not
hidden (Review §3, Baseline L19); each reader of a destination and its secret reads both in one SELECT (Phase 2 "Einstellungen lesen");
a PUT with the host of another switch is a 409; empty Entra allowlists warn at the start.

The read path keeps its fallback ("public", a lower level): a switch that answers to it today stays reachable. What changes is that
the switch list, the network map, the connection test and the log say so. SSH, which writes configuration, never sends an empty
password in place of one that does not decrypt.

No network: every test either never reaches an HTTP client or SNMP call (the secret check comes first), or replaces snmp.walk. Each
test that needs a database gets its own under tmp_path, set up by the app's own init_db. Expected messages are written out by hand.
"""
import asyncio
import dataclasses
import logging
import secrets
import sqlite3

import pytest
from cryptography.fernet import Fernet

import apifix
import cfgparse
import changes
import config
import crypto
import db
import dbfix
import main
import names
import pf
import poller
import radiusprep
import snmp
import sshcli

enc = crypto.encrypt


def foreign(value: str) -> str:
    """value encrypted under a key that is not SwitchView's: a token as one stored before SECRET_KEY changed."""
    return Fernet(Fernet.generate_key()).encrypt(value.encode()).decode()


V3_AUTHPRIV = {"snmp_version": "3", "snmp_user": "u", "snmp_auth_proto": "SHA", "snmp_auth_pass": enc("authpass1"), "snmp_priv_proto": "AES",
               "snmp_priv_pass": enc("privpass1")}
V2C_OK = {"snmp_version": "2c", "snmp_community": enc("ro-s3cret")}


def row_of(cols: dict) -> dict:
    """A switches row as the database hands it out, every column with None or its default (name and host a placeholder), cols on top:
    built in an in-memory database with the app's schema and its added columns, so a column added later is in it too."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(db.SCHEMA)
        for table, column, definition in db.ADDED_COLUMNS:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.execute("INSERT INTO switches(name, host) VALUES ('SW', '10.0.0.9')")
        return dict(conn.execute("SELECT * FROM switches").fetchone()) | cols
    finally:
        conn.close()


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app (no lifespan, scheduler booby-trapped) against a fresh database, signed in as apifix.USER."""
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def body(**fields) -> dict:
    return {"name": "SW-VK-02", "host": "203.0.113.42", "zone": "VK", **fields}


def create(api, **fields) -> int:
    r = api.post("/api/switches", json=body(**fields))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def record_read_settings(monkeypatch) -> list[list[str]]:
    """Records the keys of every db.read_settings call (and hands each on to the real one); the list of them."""
    reads: list[list[str]] = []
    original = db.read_settings

    async def recording(conn, keys):
        keys = list(keys)
        reads.append(keys)
        return await original(conn, keys)

    monkeypatch.setattr(db, "read_settings", recording)
    return reads


def test_an_undecryptable_community_is_reported_and_still_polled(api):           # Review Focus 3
    sid = dbfix.insert_switch(name="SW", host="10.0.0.9", driver="procurve", snmp_version="2c", snmp_community=foreign("ro"))
    row = next(s for s in api.get("/api/switches").json() if s["id"] == sid)
    assert row["cred_warnings"] == ["Lese-Community lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – SwitchView fragt mit „public“. "
                                    "Bitte neu eingeben."]
    assert next(s for s in api.get("/api/netmap").json()["switches"] if s["id"] == sid)["credWarnings"] == row["cred_warnings"]
    conn = dbfix.connect()
    try:
        assert poller.creds_of(conn.execute("SELECT * FROM switches").fetchone())["snmp_community"] is None    # the fallback stays
    finally:
        conn.close()


async def test_every_poll_logs_the_warnings_and_still_asks(api, monkeypatch, caplog):
    """The poll goes out as before, with "public" (snmp._conf_lines), and each warning stands in the log once per poll."""
    sid = dbfix.insert_switch(name="SW", host="10.0.0.9", driver="procurve", snmp_version="2c", snmp_community=foreign("ro"))
    asked: list[dict] = []

    async def walk(host, cred, oid, hex_values=False, **kwargs):
        asked.append(cred)
        raise snmp.SnmpError("Timeout")

    monkeypatch.setattr(snmp, "walk", walk)
    with caplog.at_level(logging.WARNING, logger="switchview.poller"):
        await poller.poll_switch(sid)
        await poller.poll_switch(sid)
    assert asked and all(snmp._conf_lines(c) == ['defCommunity "public"'] for c in asked)
    told = [r.getMessage() for r in caplog.records if "Lese-Community" in r.getMessage()]
    assert told == ["10.0.0.9: Lese-Community lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – SwitchView fragt mit „public“. "
                    "Bitte neu eingeben."] * 2


@pytest.mark.parametrize("cols, warning", [
    ({"snmp_version": "2c"}, "Keine Lese-Community hinterlegt – SwitchView fragt mit „public“."),
    ({"snmp_version": "3"}, "SNMPv3 ohne Benutzer – die Abfrage geht mit leerem Benutzernamen."),
    ({**V3_AUTHPRIV, "snmp_auth_pass": foreign("a")},
     "SNMPv3-Auth-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – SwitchView fragt ohne Authentifizierung (noAuthNoPriv). "
     "Bitte neu eingeben."),
    ({**V3_AUTHPRIV, "snmp_auth_proto": None, "snmp_priv_pass": None},
     "SNMPv3-Auth-Kennwort ohne Auth-Verfahren – SwitchView fragt ohne Authentifizierung (noAuthNoPriv)."),
    ({**V3_AUTHPRIV, "snmp_priv_pass": foreign("p")},
     "SNMPv3-Priv-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – SwitchView fragt ohne Verschlüsselung. Bitte neu eingeben."),
    ({**V3_AUTHPRIV, "snmp_priv_proto": None},
     "SNMPv3-Priv-Kennwort wird nicht benutzt (ohne Verschlüsselungsverfahren oder ohne Authentifizierung) – SwitchView fragt ohne "
     "Verschlüsselung."),
    ({**V2C_OK, "driver": "procurve", "ssh_user": "manager", "ssh_pass": foreign("s")},
     "SSH-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – SSH geht erst nach neuer Eingabe.")])
def test_credential_warnings_name_every_silent_fallback(cols, warning):
    assert warning in poller.credential_warnings(row_of(cols))


def test_a_complete_identity_has_no_warning():
    assert poller.credential_warnings(row_of(V3_AUTHPRIV)) == [] and poller.credential_warnings(row_of(V2C_OK)) == []


def test_the_warnings_come_in_their_order_and_ssh_only_where_it_is_used():
    """Every warning of a row, in the order of the interface (SNMP, then SSH); an undecryptable SSH password of a driver without CLI is
    never used, so it is no warning."""
    v3 = {**V3_AUTHPRIV, "snmp_user": None, "snmp_auth_pass": foreign("a"), "snmp_priv_pass": foreign("p"), "ssh_pass": foreign("s")}
    assert poller.credential_warnings(row_of(v3)) == [
        "SNMPv3 ohne Benutzer – die Abfrage geht mit leerem Benutzernamen.",
        "SNMPv3-Auth-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – SwitchView fragt ohne Authentifizierung (noAuthNoPriv). "
        "Bitte neu eingeben.",
        "SNMPv3-Priv-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – SwitchView fragt ohne Verschlüsselung. Bitte neu eingeben.",
        "SSH-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – SSH geht erst nach neuer Eingabe."]
    assert poller.credential_warnings(row_of({**V2C_OK, "driver": "cisco", "ssh_user": "manager", "ssh_pass": foreign("s")})) == []


def test_unreadable_means_stored_and_not_decryptable():
    assert [crypto.unreadable(v) for v in (None, "", enc("x"), foreign("x"), "kein-token")] == [False, False, False, True, True]


def test_an_undecryptable_ssh_password_never_goes_out_empty():
    with pytest.raises(sshcli.CredentialError, match="nichts gesendet"):
        sshcli._device(row_of({"driver": "procurve", "ssh_user": "manager", "ssh_pass": foreign("x")}))


def test_an_ssh_password_that_decrypts_still_goes_out():
    assert sshcli._device(row_of({"driver": "procurve", "ssh_user": "manager", "ssh_pass": enc("ssh-s3cret")}))["password"] == "ssh-s3cret"


def test_prepare_names_an_undecryptable_radius_key():
    plan = changes.plan_prepare(cfgparse.parse_config(""), {"server": "10.0.0.1", "key": "", "key_unreadable": True})
    assert plan["blocked"] == [{"port": "*", "reason": "Shared Secret lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – in den "
                                                       "Einstellungen neu eingeben"}]


def test_prepare_needs_no_key_where_the_host_line_stands():
    cfg = cfgparse.parse_config("radius-server host 10.0.0.1 key s3cret-key\n")
    assert changes.plan_prepare(cfg, {"server": "10.0.0.1", "key": "", "key_unreadable": True})["blocked"] == []


async def test_radius_settings_say_the_key_is_unreadable(api):
    await db.set_setting("radius_server", "10.0.0.1")
    await db.set_setting("radius_key", foreign("s3cret-key"))
    assert await changes.radius_settings() == {"server": "10.0.0.1", "key": "", "key_unreadable": True}
    await db.set_setting("radius_key", enc("s3cret-key"))
    assert await changes.radius_settings() == {"server": "10.0.0.1", "key": "s3cret-key", "key_unreadable": False}


async def test_packetfence_and_opnsense_say_their_secret_is_unreadable(api):
    for k, v in {"pf_url": "https://pf.example", "pf_user": "svc", "pf_pass": foreign("p"), "opnsense_url": "https://fw.example",
                 "opnsense_key": enc("k"), "opnsense_secret": foreign("s")}.items():
        await db.set_setting(k, v)
    assert (await pf.test())["error"].endswith("PacketFence-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – in den "
                                               "Einstellungen neu eingeben")
    res = await names.refresh_names()
    assert res["ok"] is False and "OPNsense-API-Key oder -Secret lässt sich nicht entschlüsseln" in res["error"]


async def test_an_unreadable_packetfence_password_counts_as_configured(api):
    """So a sync and a delete fail with the reason instead of passing over PacketFence in silence."""
    for k, v in {"pf_url": "https://pf.example", "pf_user": "svc", "pf_pass": foreign("p")}.items():
        await db.set_setting(k, v)
    assert (await pf.config())["password_unreadable"] is True and await pf.configured() is True
    with pytest.raises(RuntimeError, match="PacketFence-Kennwort lässt sich nicht entschlüsseln"):
        await pf.unregister("aa:bb:cc:dd:ee:ff")


def test_a_device_stays_when_packetfence_cannot_be_reached_for_an_unreadable_password(api):
    """Before, an unreadable password counted as "not set up": the device went from SwitchView and stayed registered in PacketFence."""
    for k, v in {"pf_url": "https://pf.example", "pf_user": "svc", "pf_pass": foreign("p")}.items():
        asyncio.run(db.set_setting(k, v))
    dbfix.query("INSERT INTO devices(mac, name, allowed) VALUES ('aa:bb:cc:dd:ee:ff', 'Drucker', 1)")
    r = api.delete("/api/devices/aa:bb:cc:dd:ee:ff")
    assert r.status_code == 502 and "PacketFence-Kennwort lässt sich nicht entschlüsseln" in r.json()["detail"]
    assert dbfix.query("SELECT mac FROM devices") == [("aa:bb:cc:dd:ee:ff",)]


def test_the_settings_name_their_unreadable_secrets(api):
    for k, v in {"pf_pass": foreign("p"), "radius_key": foreign("r"), "opnsense_key": enc("k")}.items():
        asyncio.run(db.set_setting(k, v))
    assert api.get("/api/settings").json()["unreadable"] == ["pf_pass", "radius_key"]


async def test_destination_and_secret_come_from_one_read(api, monkeypatch):
    reads = record_read_settings(monkeypatch)
    monkeypatch.setattr(db, "get_setting", dbfix.raising_async_fn(AssertionError("get_setting beside the one read")))
    assert not any(hasattr(m, "get_setting") for m in (pf, names, changes, radiusprep))    # none binds it by name: the trap covers them
    await pf.config()
    assert await names.opnsense_arp() == []    # without a stored OPNsense address: no HTTP
    await changes.radius_settings()
    assert reads == [["pf_url", "pf_user", "pf_pass", "pf_verify_tls"], ["opnsense_url", "opnsense_key", "opnsense_secret", "opnsense_verify_tls"],
                     ["radius_server", "radius_key"]]


async def test_the_tls_check_stays_on_without_a_stored_value(api):
    assert (await pf.config())["verify"] is True
    await db.set_setting("pf_verify_tls", "0")
    assert (await pf.config())["verify"] is False


def test_the_connection_test_names_the_warnings(api, monkeypatch):
    async def get(host, cred, oids, timeout=15):
        return {"1.3.6.1.2.1.1.5.0": "SW"}

    monkeypatch.setattr(snmp, "get", get)
    sid = dbfix.insert_switch(name="SW", host="10.0.0.9", driver="cisco", snmp_version="2c")
    assert api.post(f"/api/switches/{sid}/test").json()["warnings"] == ["Keine Lese-Community hinterlegt – SwitchView fragt mit „public“."]


def test_a_put_with_another_switchs_host_is_409(api):
    a, b = create(api, host="10.0.0.1"), create(api, host="10.0.0.2")
    r = api.put(f"/api/switches/{b}", json=body(host="10.0.0.1"))
    assert (r.status_code, r.json()["detail"]) == (409, "Ein Switch mit dieser Adresse existiert bereits")
    assert dbfix.query("SELECT id, host FROM switches ORDER BY id") == [(a, "10.0.0.1"), (b, "10.0.0.2")]


def test_empty_entra_allowlists_warn_at_start():
    s = config.Settings(secret_key=secrets.token_hex(32), entra_tenant_id="t", entra_client_id="c", entra_allowed_roles=[], entra_allowed_groups=[])
    assert "ENTRA_ALLOWED_ROLES und ENTRA_ALLOWED_GROUPS sind leer: jeder Benutzer des Tenants kann sich per SSO anmelden und alles ändern." in (
        main.check_startup_config(s))
    assert main.check_startup_config(dataclasses.replace(s, entra_allowed_roles=["SwitchView.Admin"])) == []
    assert main.check_startup_config(dataclasses.replace(s, entra_allowed_groups=["g-1"])) == []
    assert main.check_startup_config(dataclasses.replace(s, entra_tenant_id="")) == []
