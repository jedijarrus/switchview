"""The SNMPv3 user of PacketFence in "Switch vorbereiten": PacketFence re-evaluates a port over SNMP (deauthMethod SNMP), so a release
or its end reaches the port without the cable pulled; for that the switch needs an SNMPv3 user that may write.

- cfgparse reads "snmpv3 enable", the users and their groups of a running-config.
- readiness says whether the user of the settings is there and in the group managerpriv (None: none asked for, or the read does not
  tell), and whether SNMPv3 is off.
- plan_prepare adds what is missing: the user with its passphrases (SHA / AES, shown masked) and its group. A user that is there is
  never created anew; "snmpv3 enable" asks back at the CLI and is never sent; what must not reach a CLI line is refused.
- PUT /api/settings/pf-snmp stores the user plain and its passphrases encrypted; one not sent stays, an empty one goes; neither the
  answer of a 422 nor the audit ever names a passphrase.
- run_change sends the lines, checks the user afterwards and stores no passphrase (commands, steps, output, error).

No network: sshcli.connect is a fake session (ssh_env, tests/sshfix.py). Each test gets its own database under tmp_path.
"""
import asyncio
import json
import re

import pytest
from cryptography.fernet import Fernet
from netmiko.exceptions import ReadTimeout

import api_settings
import apifix
import cfgparse
import changes
import crypto
import db
import dbfix
import main
import sshcli
from cfgparse import parse_config

# Test values, valid as the switch CLI takes them. "Au7h" and "Pr1v" stay in every escaped form of them (re.escape, repr)
AUTH, PRIV = "Au7h.Pass-01", "Pr1v.Pass-02"
USER_LINE = f"snmpv3 user packetfence auth sha {AUTH} priv aes {PRIV}"
USER_SHOWN = "snmpv3 user packetfence auth sha *** priv aes ***"
GROUP_LINE = "snmpv3 group managerpriv user packetfence sec-model ver3"
BASICS = {"host": True, "coa": True, "tw": True, "eap": True, "active": True, "park": True}
LAST = "Wirkt switchweit, ändert aber noch keinen Port. Ports bleiben „Protected“, bis du sie umstellst."

# A switch prepared for RADIUS (server 10.0.0.1), SNMPv3 off; then with SNMPv3 on, with the user, with the user in its group
READY = ('hostname "SW-EK-01"\nradius-server host 10.0.0.1 key s3cret-key\nradius-server host 10.0.0.1 dyn-authorization\n'
         'radius-server host 10.0.0.1 time-window 0\naaa authentication port-access eap-radius\naaa port-access authenticator active\n'
         'vlan 1\n   name "DEFAULT_VLAN"\n   untagged 1-24\n   exit\nvlan 3999\n   name "Park"\n   exit\n')
V3_ON = READY + "snmpv3 enable\nsnmpv3 only\n"
HAS_USER = V3_ON + 'snmpv3 user "packetfence"\n'
OTHER_GROUP = HAS_USER + 'snmpv3 group operatorauth user "packetfence" sec-model ver3\n'
IN_GROUP = HAS_USER + 'snmpv3 group managerpriv user "packetfence" sec-model ver3\n'


@pytest.fixture
def api(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def rs(user: str = "packetfence", auth: str = AUTH, priv: str = PRIV, unreadable: bool = False) -> dict:
    """The RADIUS settings as changes.radius_settings hands them out."""
    return {"server": "10.0.0.1", "key": "s3cret-key", "key_unreadable": False,
            "snmp": {"user": user, "auth": auth, "priv": priv, "unreadable": unreadable}}


def plan(running: str, **snmp) -> dict:
    return changes.plan_prepare(parse_config(running), rs(**snmp))


def clean(*texts: str) -> bool:
    """No text carries a passphrase, whole or escaped."""
    return not any(part in t for t in texts for part in ("Au7h", "Pr1v"))


# ── cfgparse ────────────────────────────────────────────────────────────────────────────────────────────
def test_the_parser_reads_snmpv3_its_users_and_their_groups():
    text = ('snmpv3 enable\nsnmpv3 only\nsnmpv3 group operatorauth user "checkmk" sec-model ver3\n'
            'snmpv3 group ManagerPriv user packetfence sec-model ver3\nsnmpv3 group managerpriv user "packetfence" sec-model ver3\n'
            'snmpv3 user "checkmk"\nsnmpv3 user "initial"\nsnmpv3 user packetfence\nsnmpv3 user "packetfence"\n')
    assert parse_config(text)["snmpv3"] == {"enabled": True, "users": ["checkmk", "initial", "packetfence"],
                                            "groups": {"checkmk": ["operatorauth"], "packetfence": ["managerpriv"]}}


def test_a_config_without_snmpv3_reads_as_off_and_empty():
    assert parse_config(READY)["snmpv3"] == {"enabled": False, "users": [], "groups": {}}


# ── readiness ───────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("running, snmp, off", [
    (READY, False, True), (V3_ON, False, False), (HAS_USER, False, False), (OTHER_GROUP, False, False), (IN_GROUP, True, False),
    (V3_ON + 'snmpv3 group managerpriv user "packetfence" sec-model ver3\n', False, False),    # a group line without its user
    (IN_GROUP.replace("snmpv3 enable\n", ""), True, True)])
def test_readiness_says_whether_the_snmp_user_is_there_and_may_write(running, snmp, off):
    r = changes.readiness(parse_config(running), "10.0.0.1", "packetfence")
    assert (r["snmp"], r["snmp_off"]) == (snmp, off) and all(r[k] for k in BASICS)


@pytest.mark.parametrize("cfg, user", [
    (parse_config(IN_GROUP), ""),                                                        # no user in the settings
    ({**parse_config(IN_GROUP), "snmpv3": None}, "packetfence"),                         # read over SNMP
    ({k: v for k, v in parse_config(IN_GROUP).items() if k != "snmpv3"}, "packetfence")],    # stored before SNMPv3 was parsed
    ids=["no user", "read over SNMP", "old read"])
def test_readiness_does_not_tell_without_a_user_or_a_read_that_knows_snmpv3(cfg, user):
    r = changes.readiness(cfg, "10.0.0.1", user)
    assert r["snmp"] is None and r["snmp_off"] is False


def test_readiness_asks_for_the_user_of_the_settings_only():
    assert changes.readiness(parse_config(IN_GROUP), "10.0.0.1", "checkmk")["snmp"] is False
    assert changes.readiness(parse_config(IN_GROUP), "10.0.0.1")["snmp"] is None


def test_the_netmap_tells_the_switch_view_whether_the_snmp_user_is_there(api):
    sid = dbfix.insert_switch(name="SW-EK-01", host="203.0.113.21", driver="procurve", snmp_version="2c")
    dbfix.query("INSERT INTO switch_cfg(switch_id, taken_at, parsed) VALUES (?, '2026-11-06 08:00:00', ?)", (sid, json.dumps(parse_config(HAS_USER))))
    asyncio.run(db.set_setting("radius_server", "10.0.0.1"))

    def ready() -> dict:
        return api.get("/api/netmap").json()["switches"][0]["ready"]

    assert ready()["snmp"] is None and ready()["host"] is True
    asyncio.run(db.set_setting("pf_snmp_user", "packetfence"))
    assert (ready()["snmp"], ready()["snmp_off"]) == (False, False)


# ── plan_prepare ────────────────────────────────────────────────────────────────────────────────────────
def test_prepare_creates_the_missing_user_and_puts_it_into_its_group():
    p = plan(V3_ON)
    assert p["commands"] == [USER_LINE, GROUP_LINE] and p["shown"] == [USER_SHOWN, GROUP_LINE]
    assert p["blocked"] == [] and p["warnings"] == [LAST] and p["expected"] == BASICS | {"snmp": True}
    assert clean(json.dumps(p["shown"]), json.dumps(p["warnings"]))


@pytest.mark.parametrize("snmp", [{}, {"auth": "", "priv": ""}, {"unreadable": True, "auth": "", "priv": ""}],
                         ids=["passphrases set", "none set", "unreadable"])
@pytest.mark.parametrize("running", [HAS_USER, OTHER_GROUP], ids=["no group", "another group"])
def test_prepare_never_creates_a_user_anew_and_needs_no_passphrase_for_its_group(running, snmp):
    """The switch would take the passphrases of the settings; whoever set others on purpose (PacketFence knows those) would lose them."""
    p = plan(running, **snmp)
    assert p["commands"] == p["shown"] == [GROUP_LINE] and p["blocked"] == [] and p["expected"] == BASICS | {"snmp": True}


def test_prepare_leaves_a_user_alone_that_is_there_and_may_write():
    p = plan(IN_GROUP)
    assert (p["commands"], p["blocked"], p["warnings"], p["expected"]) == ([], [], [LAST], BASICS)


def test_prepare_never_switches_snmpv3_on():
    """The line "snmpv3 enable" asks back at the CLI: it stays a step by hand, and the plan says so instead of creating a user that
    does nothing."""
    p = plan(READY)
    assert (p["commands"], p["blocked"], p["expected"]) == ([], [], BASICS)
    assert p["warnings"] == ["SNMPv3 ist am Switch ausgeschaltet. Der SNMP-Benutzer „packetfence“ wird nicht angelegt: „snmpv3 enable“ fragt an "
                             "der CLI nach und muss einmal von Hand laufen.", LAST]


UNREADABLE = "SNMP-Passwörter für PacketFence lassen sich nicht entschlüsseln (SECRET_KEY geändert?) – in den Einstellungen neu eingeben"
BAD_PASS = ("SNMP-Passwörter für PacketFence fehlen oder enthalten unzulässige Zeichen (je 8–32 Zeichen, ohne Leerzeichen, Anführungszeichen, "
            "Backslash, ? und ~)")
BAD_USER = "SNMP-Benutzer für PacketFence enthält unzulässige Zeichen – in den Einstellungen neu eingeben"


@pytest.mark.parametrize("snmp, reason", [
    ({"unreadable": True, "auth": "", "priv": PRIV}, UNREADABLE), ({"auth": ""}, BAD_PASS), ({"priv": ""}, BAD_PASS), ({"auth": "short"}, BAD_PASS),
    ({"priv": "x" * 33}, BAD_PASS), ({"auth": "with space 12"}, BAD_PASS), ({"priv": "quest?ion-12"}, BAD_PASS), ({"auth": "tilde~pass-1"}, BAD_PASS),
    ({"auth": 'quo"te-pass1'}, BAD_PASS), ({"priv": "apo'strophe1"}, BAD_PASS), ({"auth": "back\\slash-1"}, BAD_PASS),
    ({"priv": "line\nbreak-12"}, BAD_PASS), ({"user": "pf user"}, BAD_USER), ({"user": 'pf"x'}, BAD_USER), ({"user": "x" * 33}, BAD_USER),
    ({"user": "pf\nreload"}, BAD_USER)])
def test_prepare_refuses_what_must_not_reach_a_cli_line(snmp, reason):
    p = plan(V3_ON, **snmp)
    assert p["blocked"] == [{"port": "*", "reason": reason}] and p["commands"] == [] and "snmp" not in p["expected"]


def test_prepare_leaves_snmpv3_alone_without_a_user_in_the_settings():
    for settings in (rs(user=""), {"server": "10.0.0.1", "key": "s3cret-key"}):    # the second: as from before the SNMP user
        p = changes.plan_prepare(parse_config(V3_ON), settings)
        assert (p["commands"], p["blocked"], p["warnings"], p["expected"]) == ([], [], [LAST], BASICS)


def test_prepare_plans_no_snmp_line_on_a_read_that_does_not_know_snmpv3():
    p = changes.plan_prepare({**parse_config(V3_ON), "snmpv3": None}, rs())
    assert (p["commands"], p["blocked"], p["expected"]) == ([], [], BASICS)


def test_on_a_bare_switch_the_snmp_lines_follow_the_radius_basics():
    p = plan('hostname "SW-EK-01"\nsnmpv3 enable\n')
    assert p["commands"] == ["radius-server host 10.0.0.1 key s3cret-key", "radius-server host 10.0.0.1 dyn-authorization",
                             "radius-server host 10.0.0.1 time-window 0", "aaa authentication port-access eap-radius",
                             "aaa port-access authenticator active", 'vlan 3999 name "Park"', USER_LINE, GROUP_LINE]
    assert p["shown"][0] == "radius-server host 10.0.0.1 key ***" and p["shown"][1:-2] == p["commands"][1:-2]
    assert p["shown"][-2:] == [USER_SHOWN, GROUP_LINE] and clean(json.dumps(p["shown"])) and "s3cret-key" not in json.dumps(p["shown"])


def test_without_a_radius_server_nothing_is_planned_for_snmp_either():
    p = changes.plan_prepare(parse_config(V3_ON), rs() | {"server": ""})
    assert (p["commands"], p["shown"], p["expected"]) == ([], [], {}) and len(p["blocked"]) == 1


# ── The secrets of a change ─────────────────────────────────────────────────────────────────────────────────
def test_the_passphrases_are_secrets_of_every_change():
    assert changes._secrets_of(None, rs()) == ["s3cret-key", AUTH, PRIV]
    assert changes._secrets_of(None, rs(priv="")) == ["s3cret-key", AUTH] and changes._secrets_of(None, {"key": "k"}) == ["k"]


def test_a_user_line_is_masked_even_where_switchview_does_not_know_its_passphrases():
    assert cfgparse.mask_secrets(f"SW-EK-01(config)# {USER_LINE}") == 'SW-EK-01(config)# snmpv3 user packetfence auth sha "***" priv aes "***"'


async def test_radius_settings_carry_the_snmp_user_and_say_when_a_passphrase_is_unreadable(api):
    for k, v in {"pf_snmp_user": "packetfence", "pf_snmp_auth": crypto.encrypt(AUTH), "pf_snmp_priv": crypto.encrypt(PRIV)}.items():
        await db.set_setting(k, v)
    assert (await changes.radius_settings())["snmp"] == {"user": "packetfence", "auth": AUTH, "priv": PRIV, "unreadable": False}
    await db.set_setting("pf_snmp_priv", Fernet(Fernet.generate_key()).encrypt(b"x").decode())    # a token of another SECRET_KEY
    assert (await changes.radius_settings())["snmp"] == {"user": "packetfence", "auth": AUTH, "priv": "", "unreadable": True}


# ── PUT /api/settings/pf-snmp ───────────────────────────────────────────────────────────────────────────
URL = "/api/settings/pf-snmp"
USER_422 = "SNMP-Benutzer: 1–32 Zeichen aus Buchstaben, Ziffern, Punkt, Bindestrich und Unterstrich"
PASS_422 = "SNMP-Passwort: 8–32 Zeichen, ohne Leerzeichen, Anführungszeichen, Backslash, ? und ~ (die versteht die Switch-CLI nicht)"


def stored() -> dict:
    return dict(dbfix.query("SELECT key, value FROM settings WHERE key LIKE 'pf_snmp%'"))


def audited() -> list[tuple]:
    return dbfix.query("SELECT username, action, detail, role FROM audit WHERE action = 'pf_snmp_settings' ORDER BY id")


def test_the_settings_store_the_user_plain_and_its_passphrases_encrypted(api):
    r = api.put(URL, json={"user": "packetfence", "auth_pass": AUTH, "priv_pass": PRIV})
    assert (r.status_code, r.json()) == (200, {"ok": True})
    s = stored()
    assert s["pf_snmp_user"] == "packetfence" and clean(json.dumps(s))
    assert (crypto.decrypt(s["pf_snmp_auth"]), crypto.decrypt(s["pf_snmp_priv"])) == (AUTH, PRIV)
    got = api.get("/api/settings")
    assert [got.json()[k] for k in ("pf_snmp_user", "pf_snmp_auth_set", "pf_snmp_priv_set", "unreadable")] == ["packetfence", True, True, []]
    assert clean(got.text)


def test_a_passphrase_not_sent_stays_and_an_empty_one_goes(api):
    api.put(URL, json={"user": "packetfence", "auth_pass": AUTH, "priv_pass": PRIV})
    before = stored()
    assert api.put(URL, json={"user": "pf2"}).status_code == 200 and stored() == before | {"pf_snmp_user": "pf2"}
    assert api.put(URL, json={"user": "pf2", "auth_pass": None, "priv_pass": ""}).status_code == 200
    assert stored() == before | {"pf_snmp_user": "pf2", "pf_snmp_priv": None}
    assert api.put(URL, json={"user": "", "auth_pass": "", "priv_pass": ""}).status_code == 200
    assert stored() == {"pf_snmp_user": "", "pf_snmp_auth": None, "pf_snmp_priv": None}
    s = api.get("/api/settings").json()
    assert (s["pf_snmp_user"], s["pf_snmp_auth_set"], s["pf_snmp_priv_set"]) == ("", False, False)


def test_saving_the_other_settings_leaves_the_snmp_user_alone(api):
    """PUT /api/settings sets every field it is not sent to its default; the SNMP user has its own PUT for that reason."""
    api.put(URL, json={"user": "packetfence", "auth_pass": AUTH, "priv_pass": PRIV})
    before = stored()
    assert api.put("/api/settings", json={"poll_minutes": 20}).status_code == 200 and stored() == before


@pytest.mark.parametrize("body, detail", [
    ({"user": "pf user"}, USER_422), ({"user": 'pf"x'}, USER_422), ({"user": "pf\nreload"}, USER_422), ({"user": "pf;x"}, USER_422),
    ({"user": "pf", "auth_pass": "short"}, PASS_422), ({"user": "pf", "priv_pass": "with space 12"}, PASS_422),
    ({"user": "pf", "auth_pass": "quest?ion-12"}, PASS_422), ({"user": "pf", "priv_pass": "tilde~pass-1"}, PASS_422),
    ({"user": "pf", "auth_pass": 'quo"te-pass1'}, PASS_422), ({"user": "pf", "priv_pass": "back\\slash-1"}, PASS_422),
    ({"user": "", "auth_pass": "line\nbreak-12"}, PASS_422)])
def test_the_settings_refuse_what_the_switch_cli_cannot_take(api, body, detail):
    r = api.put(URL, json=body)
    assert (r.status_code, r.json()["detail"]) == (422, detail) and stored() == {} and audited() == []


@pytest.mark.parametrize("field", ["auth_pass", "priv_pass"])
def test_a_422_never_sends_a_passphrase_back(api, field):
    """pydantic refuses a passphrase over 32 characters and one without a user, and would put what it got into "input"."""
    long = AUTH + "x" * 30
    r = api.put(URL, json={"user": "pf", field: long})
    assert r.status_code == 422 and clean(r.text) and stored() == {}
    r = api.put(URL, json={field: AUTH})    # the user is missing: the error carries the whole body
    assert r.status_code == 422 and clean(r.text) and stored() == {}


def test_the_passphrase_fields_count_as_secret_inputs():
    names = [n for n in api_settings.PfSnmpIn.model_fields if n != "user"]
    assert names == ["auth_pass", "priv_pass"] and set(names) <= main.SECRET_INPUTS


def test_the_audit_names_the_user_and_what_became_of_each_passphrase_never_one(api):
    api.put(URL, json={"user": "packetfence", "auth_pass": AUTH})
    api.put(URL, json={"user": "", "auth_pass": "", "priv_pass": PRIV})
    assert audited() == [("tester", "pf_snmp_settings", "Benutzer: packetfence, Auth-Passwort: neu gesetzt, Priv-Passwort: unverändert", "admin"),
                         ("tester", "pf_snmp_settings", "Benutzer: –, Auth-Passwort: gelöscht, Priv-Passwort: neu gesetzt", "admin")]
    assert clean(json.dumps(dbfix.query("SELECT * FROM audit")))


def test_only_an_admin_sets_the_snmp_user(api):
    apifix.become(apifix.user("freigeben", "anna"))
    assert api.put(URL, json={"user": "packetfence"}).status_code == 403 and stored() == {}


# ── A preparation from its preview to its end ──────────────────────────────────────────────────────────────────
class Taking:
    """A session whose switch takes the lines sent: from then on every show answers with `after`, and the session's echo names each
    line as typed (so the stored output would carry a passphrase unless it is masked)."""

    def __init__(self, env, after: str):
        self.env, self.after = env, after

    def send_command(self, cmd, read_timeout=None):
        return self.env.running

    def send_config_set(self, commands, **kwargs):
        self.env.sent.append(list(commands))
        self.env.running = self.after
        return "\n".join(f"SW-EK-01(config)# {c}" for c in commands)

    def save_config(self):
        self.env.saves += 1

    def disconnect(self):
        pass


async def previewed(env, running: str) -> int:
    """The settings stored as the two PUTs store them and the preparation queued as /prepare previews it on `running`, which the
    switch answers from now on; the id of the change."""
    for k, v in {"radius_server": "10.0.0.1", "radius_key": crypto.encrypt("s3cret-key"), "pf_snmp_user": "packetfence",
                 "pf_snmp_auth": crypto.encrypt(AUTH), "pf_snmp_priv": crypto.encrypt(PRIV)}.items():
        await db.set_setting(k, v)
    env.running = running
    shown = changes.plan_prepare(parse_config(running), await changes.radius_settings())
    return await changes.create_change(env.sid, "tester", "prepare", "RADIUS vorbereiten", {}, shown | {"mechanism": "ssh"})


async def run(env, running: str) -> dict:
    """The preparation previewed on `running` and run to its end; its changes row."""
    cid = await previewed(env, running)
    await changes.run_change(cid)
    return env.change(cid)


def texts(row: dict) -> list[str]:
    return [str(v) for v in row.values()] + [json.dumps(dbfix.query("SELECT * FROM audit"))]


async def test_a_preparation_creates_the_user_checks_it_and_stores_no_passphrase(ssh_env, monkeypatch):
    monkeypatch.setattr(sshcli, "connect", lambda row: Taking(ssh_env, IN_GROUP))
    row = await run(ssh_env, V3_ON)
    assert (row["status"], row["saved"], row["error"], ssh_env.saves) == ("ok", 1, None, 1)
    assert ssh_env.sent == [[USER_LINE, GROUP_LINE]] and json.loads(row["commands"]) == [USER_SHOWN, GROUP_LINE]
    assert 'auth sha "***" priv aes "***"' in row["output"] and clean(*texts(row))


async def test_a_user_missing_from_its_group_afterwards_leaves_the_change_unclear(ssh_env, monkeypatch):
    monkeypatch.setattr(sshcli, "connect", lambda row: Taking(ssh_env, HAS_USER))
    row = await run(ssh_env, V3_ON)
    assert (row["status"], row["saved"], ssh_env.saves) == ("unclear", 0, 0)
    assert row["error"] == "Prüfung nach der Änderung passt nicht: snmp" and clean(*texts(row))


async def test_with_snmpv3_off_the_basics_alone_are_sent_and_checked(ssh_env, monkeypatch):
    """The user is in the settings, but the plan did not set it up: its absence afterwards is no failed check."""
    monkeypatch.setattr(sshcli, "connect", lambda row: Taking(ssh_env, READY))
    row = await run(ssh_env, 'hostname "SW-EK-01"\n')
    assert (row["status"], row["saved"]) == ("ok", 1) and not any(c.startswith("snmpv3") for c in ssh_env.sent[0])


async def test_a_user_created_since_the_preview_stops_the_run_before_anything_goes_out(ssh_env):
    """The preview showed two lines, the switch now needs one: the stored preview, with its passphrases masked, no longer matches."""
    cid = await previewed(ssh_env, V3_ON)
    ssh_env.running = HAS_USER
    await changes.run_change(cid)
    row = ssh_env.change(cid)
    assert row["status"] == "aborted" and "seit der Vorschau geändert" in row["error"] and ssh_env.sent == []


async def test_a_read_timeout_does_not_leak_a_passphrase(ssh_env):
    """netmiko writes the line it waited for into its ReadTimeout, escaped: repr(re.escape(cmd))."""
    ssh_env.on_send = ReadTimeout(f"\n\nPattern not detected: {re.escape(USER_LINE)!r} in output.")
    row = await run(ssh_env, V3_ON)
    assert row["status"] == "unclear" and "***" in row["error"] and clean(*texts(row))
