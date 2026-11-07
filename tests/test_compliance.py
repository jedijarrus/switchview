"""Phase 4b, Task 5: security rules (app/compliance.py, table findings). Built-in rules on the unmasked running-config where it is
read (sshcli.store_backup): telnet on, a community "public" or "private", every v2c write community, a manager without password, the
web interface over HTTP, missing RADIUS basics (radiusprep); rules on the SNMP access of every switch after a good poll (a read
community "public" or "private", writing without protection); custom rules as plain text on the masked configuration. A finding
points at its masked line, never at a value; the first check of a switch per source is the baseline and tells nothing, later ones
tell what is new; a rule an Admin switches off still checks but hides its findings. Routes: GET /api/switches/{sid}/findings,
GET /api/compliance, GET and PUT /api/compliance/rules.

SAMPLE_RUNNING_CONFIG of tests/conftest.py (CFG): `snmp-server community "public" Unrestricted`, no `no telnet-server`, no
`web-management`, 802.1X at A1, the RADIUS host 203.0.113.10 with dyn-authorization. A fresh database per test (apifix.fresh_db); the
SNMP rules through a poll use the network of tests/netfix.py (fixture `net`).
"""
import asyncio
import json

import pytest
from conftest import SAMPLE_RUNNING_CONFIG as CFG

import apifix
import cfgparse
import compliance
import crypto
import db
import dbfix
import history
import poller
import snmp
import sshcli
from netfix import add
from switchfix import W_SAMPLE


@pytest.fixture
def database(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)


@pytest.fixture
def api(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def found(raw, server=""):
    return [(rule, n, line, detail) for rule, n, line, detail in compliance.check_config(raw, server)]


def line_of(text: str, raw: str = CFG) -> int:
    """The 1-based number of the first line of raw that contains text."""
    return next(i for i, x in enumerate(raw.splitlines(), 1) if text in x)


def open_rules(sid: int) -> list[str]:
    """The rules of the open findings of the switch sid as the table holds them (also those of a rule switched off), by rule."""
    return [r for (r,) in dbfix.query("SELECT rule FROM findings WHERE switch_id = ? AND resolved_at IS NULL ORDER BY rule", (sid,))]


def put_rules(api, off=(), custom=()):
    return api.put("/api/compliance/rules", json={"off": list(off), "custom": list(custom)})


TABLE = [
    ("telnet", "Telnet-Server an", "crit", "config", "Ab Werk an. Abschalten: no telnet-server (SSH bleibt)."),
    ("snmp_default_community", "SNMP-Community „public“ oder „private“", "crit", "config",
     "Die Standard-Communities kennt jeder. Eigene Community setzen oder SNMPv3 nutzen."),
    ("snmp_write_community", "SNMPv2c-Community mit Schreibrecht", "warn", "config",
     "unrestricted erlaubt Schreiben per SNMPv2c; die Community geht im Klartext übers Netz."),
    ("manager_password", "Manager ohne Kennwort", "crit", "config",
     "Die Konfiguration zeigt Kennwörter (include-credentials), aber keins für manager."),
    ("web_plaintext", "Web-Oberfläche per HTTP", "warn", "config", "Ab Werk an. Nur HTTPS: web-management ssl und no web-management plaintext."),
    ("radius_prereq", "RADIUS-Voraussetzungen fehlen", "warn", "config", "An Ports mit 802.1X oder MAC-Auth fehlt, was „Vorbereiten“ einrichtet."),
    ("snmp_read_default", "SwitchView liest mit „public“ oder „private“", "warn", "snmp", "Der Switch antwortet auf eine Standard-Community."),
    ("snmp_write_insecure", "SNMP-Schreiben ohne Schutz", "warn", "snmp", "Empfohlen: SNMPv3 mit authPriv für den Schreib-Zugang."),
]


def test_the_rules_are_the_plan_s_table():
    assert [(r.id, r.label, r.severity, r.source, r.hint) for r in compliance.RULES.values()] == TABLE
    assert all(rid == r.id for rid, r in compliance.RULES.items())


def test_the_sample_config_shows_telnet_http_and_the_public_write_community():
    got = found(CFG)
    line = next(i for i, x in enumerate(CFG.splitlines(), 1) if "snmp-server community" in x)
    assert ("telnet", None, "", "") in got and ("web_plaintext", None, "", "") in got
    assert ("snmp_default_community", line, 'snmp-server community "***" Unrestricted', "Community „public“") in got
    assert ("snmp_write_community", line, 'snmp-server community "***" Unrestricted', "") in got


def test_a_secret_community_is_never_shown():
    raw = CFG.replace('"public" Unrestricted', '"s3cret-rw" unrestricted')
    assert not any("s3cret-rw" in line or "s3cret-rw" in detail for _, _, line, detail in found(raw))
    assert "snmp_default_community" not in [r[0] for r in found(raw)]


def test_a_community_in_capitals_is_masked_in_its_finding():
    raw = CFG.replace('snmp-server community "public" Unrestricted', 'SNMP-Server Community "s3cret" Unrestricted') + "SNMP-SERVER COMMUNITY Private\n"
    assert [f for f in found(raw) if f[0].startswith("snmp_")] == [
        ("snmp_default_community", len(raw.splitlines()), 'SNMP-SERVER COMMUNITY "***"', "Community „private“"),
        ("snmp_write_community", line_of("SNMP-Server Community", raw), 'SNMP-Server Community "***" Unrestricted', "")]


@pytest.mark.parametrize("extra, gone", [("no telnet-server\n", "telnet"), ("no web-management plaintext\n", "web_plaintext"),
                                         ("no web-management\n", "web_plaintext")])
def test_switching_a_default_off_clears_its_rule(extra, gone):
    assert gone not in [r[0] for r in found(CFG + extra)]


def test_https_beside_http_is_named():
    assert [d for r, _, _, d in found(CFG + "web-management ssl\n") if r == "web_plaintext"] == ["HTTPS ist zusätzlich an"]


@pytest.mark.parametrize("extra, flagged", [("", False), ("include-credentials\n", True),
                                            ('include-credentials\npassword manager user-name "admin" sha1 "x"\n', False)])
def test_a_manager_without_password_only_where_the_config_shows_passwords(extra, flagged):
    assert ("manager_password" in [r[0] for r in found(CFG + extra)]) == flagged


def test_the_radius_rule_names_what_is_missing_on_a_switch_with_port_access():
    [detail] = [d for r, _, _, d in found(CFG, "203.0.113.10") if r == "radius_prereq"]
    assert detail == "Fehlt: time-window 0, Park-VLAN 3999"         # the sample has the host with dyn-authorization, eap-radius and 802.1X active


@pytest.mark.parametrize("server, raw", [("", CFG), ("203.0.113.10", 'hostname "X"\nvlan 1\n   untagged 1-4\n   exit\n')])
def test_no_radius_rule_without_a_server_or_without_port_access(server, raw):
    assert "radius_prereq" not in [r[0] for r in found(raw, server)]


ROW = {"snmp_version": "2c", "snmp_community": None, "snmp_write": 0, "snmp_rw_user": None, "snmp_rw_community": None, "snmp_user": None}


def apifix_row() -> dict:
    """The other columns of a switches row, each None, as poller.write_identity and credential_warnings read them."""
    return dict.fromkeys(("id", "name", "host", "driver", "ssh_user", "ssh_pass", "snmp_auth_proto", "snmp_auth_pass", "snmp_priv_proto",
                          "snmp_priv_pass", "snmp_rw_auth_proto", "snmp_rw_auth_pass", "snmp_rw_priv_proto", "snmp_rw_priv_pass"))


@pytest.mark.parametrize("cols, rules", [({"snmp_community": "public"}, ["snmp_read_default"]), ({"snmp_community": " PRIVATE "}, ["snmp_read_default"]),
                                         ({}, ["snmp_read_default"]), ({"snmp_community": "lesen-42"}, []), ({"snmp_version": "3", "snmp_user": "sv"}, []),
                                         ({"snmp_community": "lesen-42", "snmp_write": 1, "snmp_rw_community": "rw-42"}, ["snmp_write_insecure"])])
def test_the_snmp_rules(cols, rules):
    row = {**apifix_row(), **ROW, **{k: crypto.encrypt(v) if k.endswith("community") and v else v for k, v in cols.items()}}
    assert [r[0] for r in compliance.check_snmp(row)] == rules


@pytest.mark.parametrize("cols, want", [
    ({"snmp_write": 1, "snmp_rw_community": "rw-42"}, [("snmp_write_insecure", None, "", "per SNMPv2c: die Schreib-Community geht im Klartext übers Netz")]),
    ({"snmp_write": 1, "snmp_rw_user": "sv-rw"}, [("snmp_write_insecure", None, "", "per SNMPv3 ohne Authentifizierung")]),
    ({"snmp_version": "3", "snmp_user": "sv", "snmp_write": 1}, [("snmp_write_insecure", None, "", "per SNMPv3 ohne Authentifizierung")]),  # the read identity
    ({"snmp_write": 1, "snmp_rw_user": "sv-rw", "snmp_rw_auth_proto": "SHA", "snmp_rw_auth_pass": "auth-pass-42", "snmp_rw_priv_proto": "AES",
      "snmp_rw_priv_pass": "priv-pass-42"}, []),                                                  # authPriv: protected
])
def test_writing_without_protection_names_how_the_set_would_go_out(cols, want):
    secret = ("snmp_rw_community", "snmp_rw_auth_pass", "snmp_rw_priv_pass")
    row = {**apifix_row(), **ROW, "snmp_community": crypto.encrypt("lesen-42"), **{k: crypto.encrypt(v) if k in secret else v for k, v in cols.items()}}
    assert compliance.check_snmp(row) == want


@pytest.mark.parametrize("stored", ["gAAAAA-not-a-token", None])                                 # one that does not decrypt, none at all
def test_a_read_community_switchview_cannot_read_reads_as_public(stored):
    row = {**apifix_row(), **ROW, "snmp_community": stored}
    assert compliance.check_snmp(row) == [("snmp_read_default", None, "", "SwitchView liest per SNMPv2c mit der Community „public“")]


def test_a_custom_rule_matches_text_and_never_a_secret():
    raw = CFG + 'radius-server host 203.0.113.11 key s3cret\n'
    must_not = {"id": "c1", "name": "Kein Gast", "mode": "must_not", "text": 'VLAN 99'}
    guess = {"id": "c2", "name": "Rate", "mode": "must_not", "text": "s3cret"}
    must = {"id": "c3", "name": "NTP", "mode": "must", "text": "sntp server"}
    got = compliance.check_custom(cfgparse.mask_secrets(raw), [must_not, guess, must])
    assert [r[0] for r in got].count("c1") >= 1 and "c2" not in [r[0] for r in got] and ("c3", None, "", "Keine Zeile enthält „sntp server“") in got


async def test_the_custom_rules_of_a_read_see_its_masked_text_only(database):
    # The path of every read (sshcli.store_backup -> evaluate_config): a rule that names a secret neither finds it nor misses it
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await db.set_setting(compliance.SETTINGS_KEY, json.dumps({"off": [], "custom": [
        {"id": "c1", "name": "Rate", "mode": "must_not", "text": "s3cret"}, {"id": "c2", "name": "Gegenprobe", "mode": "must", "text": "s3cret"},
        {"id": "c3", "name": "Schlüssel", "mode": "must_not", "text": "S3cr3tRadiusKey"}]}))                  # the RADIUS key of the sample
    assert await sshcli.store_backup(sid, CFG + "radius-server host 203.0.113.11 key s3cret\n", "nightly") is True
    assert dbfix.query("SELECT rule, line_no, line, detail FROM findings WHERE source = 'custom'") == [("c2", None, "", "Keine Zeile enthält „s3cret“")]
    assert not any("s3cret" in line.lower() for (line,) in dbfix.query("SELECT line FROM findings"))


async def test_the_first_check_is_the_baseline_and_later_ones_tell_what_is_new(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    assert await compliance.evaluate_config(sid, CFG) == []                                   # baseline: stored, not told
    assert len(dbfix.query("SELECT 1 FROM findings WHERE resolved_at IS NULL")) == len(found(CFG))
    new = await compliance.evaluate_config(sid, CFG + "include-credentials\n")
    assert [f["rule"] for f in new] == ["manager_password"]
    await compliance.evaluate_config(sid, CFG + "no telnet-server\n")
    assert dbfix.query("SELECT rule FROM findings WHERE resolved_at IS NOT NULL ORDER BY rule") == [("manager_password",), ("telnet",)]


async def test_a_rule_switched_off_hides_its_findings(api):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await compliance.evaluate_config(sid, CFG)
    assert "telnet" in [f["rule"] for f in api.get(f"/api/switches/{sid}/findings").json()["findings"]]
    assert api.get("/api/compliance").json() == {"total": 4, "crit": 2, "switches": [{"id": sid, "name": "SW", "count": 4, "crit": 2}]}
    assert put_rules(api, off=["telnet"]).status_code == 200
    assert "telnet" not in [f["rule"] for f in api.get(f"/api/switches/{sid}/findings").json()["findings"]]
    assert api.get("/api/compliance").json() == {"total": 3, "crit": 1, "switches": [{"id": sid, "name": "SW", "count": 3, "crit": 1}]}
    assert "telnet" in open_rules(sid)                                                          # stored still: hidden, not resolved
    assert put_rules(api).status_code == 200                                                    # on again: back at once
    assert "telnet" in [f["rule"] for f in api.get(f"/api/switches/{sid}/findings").json()["findings"]]
    assert api.get("/api/compliance").json()["total"] == 4


async def test_a_rule_switched_off_still_checks_but_tells_nothing(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await compliance.evaluate_config(sid, CFG)
    await db.set_setting(compliance.SETTINGS_KEY, '{"off": ["manager_password"], "custom": []}')
    assert await compliance.evaluate_config(sid, CFG + "include-credentials\n") == []           # new, but its rule is off
    assert "manager_password" in open_rules(sid) and "manager_password" not in [f["rule"] for f in await compliance.open_findings(sid)]
    await db.set_setting(compliance.SETTINGS_KEY, '{"off": [], "custom": []}')
    assert "manager_password" in [f["rule"] for f in await compliance.open_findings(sid)]


async def test_an_unknown_rule_and_an_empty_text_are_refused(api):
    before = api.get("/api/compliance/rules").json()
    for off, custom, detail in [(["x"], [], "Unbekannte Regel: x"), (["c1"], [{"id": "c1", "name": "N", "mode": "must", "text": "a"}], "Unbekannte Regel: c1"),
                                ([], [{"id": None, "name": "N", "mode": "must", "text": "   "}], "Eigene Regel ohne Text"),
                                ([], [{"id": None, "name": "  ", "mode": "must", "text": "sntp"}], "Eigene Regel ohne Namen")]:
        r = put_rules(api, off, custom)
        assert (r.status_code, r.json()["detail"]) == (422, detail)
    assert api.get("/api/compliance/rules").json() == before and dbfix.query("SELECT 1 FROM audit") == []


@pytest.mark.parametrize("custom", [{"id": "telnet", "name": "N", "mode": "must", "text": "a"}, {"id": None, "name": "N", "mode": "should", "text": "a"},
                                    {"id": None, "name": "N", "mode": "must", "text": "a" * 201}, {"id": None, "name": "N" * 81, "mode": "must", "text": "a"}])
def test_a_custom_rule_out_of_bounds_is_a_422(api, custom):
    assert put_rules(api, custom=[custom]).status_code == 422


def test_more_than_the_limits_is_a_422(api):
    assert put_rules(api, off=["telnet"] * 21).status_code == 422
    assert put_rules(api, custom=[{"id": None, "name": "N", "mode": "must", "text": "a"}] * 51).status_code == 422


def test_a_custom_rule_without_id_gets_the_next_number_and_the_audit_names_no_text(api):
    old = [{"id": "c1", "name": "Kein Gast", "mode": "must_not", "text": "vlan 99"}, {"id": "c4", "name": "NTP", "mode": "must", "text": "sntp server"}]
    assert put_rules(api, custom=old).status_code == 200
    r = put_rules(api, off=["web_plaintext", "telnet"], custom=[old[1], {"id": None, "name": " Banner ", "mode": "must", "text": " banner motd "},
                                                               {"id": "c4", "name": "Doppelt", "mode": "must", "text": "x"}])
    assert r.status_code == 200 and r.json() == api.get("/api/compliance/rules").json()
    assert [(x["id"], x["label"], x["mode"], x["text"]) for x in r.json()["rules"] if x["custom"]] == [
        ("c4", "NTP", "must", "sntp server"), ("c5", "Banner", "must", "banner motd"), ("c6", "Doppelt", "must", "x")]
    assert dbfix.query("SELECT action, target, detail, role FROM audit ORDER BY id") == [
        ("compliance_rules", "", "aus: – · eigene: 2", "admin"), ("compliance_rules", "", "aus: telnet, web_plaintext · eigene: 3", "admin")]


def test_the_next_number_of_a_custom_rule_stays_within_its_pattern(api):
    top = {"id": "c999999999", "name": "Oben", "mode": "must", "text": "a"}
    assert put_rules(api, custom=[top]).status_code == 200
    r = put_rules(api, custom=[top, {"id": None, "name": "Neu", "mode": "must", "text": "b"}, {"id": None, "name": "Noch", "mode": "must", "text": "c"}])
    custom = [x for x in r.json()["rules"] if x["custom"]]
    assert [x["id"] for x in custom] == ["c999999999", "c1", "c2"]                               # past the largest: the smallest free numbers
    assert put_rules(api, custom=[{"id": x["id"], "name": x["label"], "mode": x["mode"], "text": x["text"]} for x in custom]).status_code == 200


def test_the_rules_view_lists_every_rule_with_its_state(api):
    r = api.get("/api/compliance/rules").json()
    assert [x["id"] for x in r["rules"]] == list(compliance.RULES) and all(x["on"] for x in r["rules"])
    assert r["rules"][0] == {"id": "telnet", "label": "Telnet-Server an", "severity": "crit", "source": "config",
                             "hint": "Ab Werk an. Abschalten: no telnet-server (SSH bleibt).", "on": True, "custom": False}
    put_rules(api, off=["telnet"], custom=[{"id": None, "name": "NTP", "mode": "must", "text": "sntp server"}])
    r = api.get("/api/compliance/rules").json()
    assert [x["id"] for x in r["rules"] if not x["on"]] == ["telnet"]
    assert r["rules"][-1] == {"id": "c1", "label": "NTP", "severity": "warn", "source": "custom", "hint": "", "on": True, "custom": True,
                              "mode": "must", "text": "sntp server"}


async def test_saving_custom_rules_checks_the_latest_backup_and_drops_removed_ones(api):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await sshcli.store_backup(sid, CFG, "manual")
    assert put_rules(api, custom=[{"id": None, "name": "Kein Gast", "mode": "must_not", "text": "vlan 99"}]).status_code == 200
    [finding] = [f for f in api.get(f"/api/switches/{sid}/findings").json()["findings"] if f["rule"] == "c1"]
    assert (finding["label"], finding["line_no"], finding["line"], finding["detail"]) == ("Kein Gast", line_of("vlan 99"), "vlan 99",
                                                                                           "Zeile enthält „vlan 99“")
    assert put_rules(api).status_code == 200
    assert dbfix.query("SELECT 1 FROM findings WHERE source = 'custom'") == []


async def test_a_custom_rule_finds_no_secret_in_an_old_backup(api):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    dbfix.query("INSERT INTO config_backups(switch_id, taken_at, sha, content) VALUES (?, '2026-01-01 02:30:00', 'x', ?)",
                (sid, CFG + 'radius-server host 203.0.113.11 key s3cret\n'))                      # unmasked, as before Phase 2
    assert put_rules(api, custom=[{"id": None, "name": "Rate", "mode": "must_not", "text": "s3cret"},
                                  {"id": None, "name": "Host", "mode": "must_not", "text": "203.0.113.11"}]).status_code == 200
    assert dbfix.query("SELECT rule, line FROM findings") == [("c2", 'radius-server host 203.0.113.11 key "***"')]


async def test_saving_rules_checks_the_latest_backup_of_switches_whose_driver_backs_up(api):
    a, b = dbfix.insert_switch(name="A", host="10.0.0.1"), dbfix.insert_switch(name="B", host="10.0.0.2", driver="cisco")
    for sid, content in ((a, CFG), (a, 'hostname "A"\nvlan 1\n'), (b, CFG)):                     # A: the second one is the latest
        dbfix.query("INSERT INTO config_backups(switch_id, taken_at, sha, content) VALUES (?, '2026-01-01 02:30:00', 'x', ?)", (sid, content))
    put_rules(api, custom=[{"id": None, "name": "NTP", "mode": "must", "text": "sntp server"},
                           {"id": None, "name": "Gast", "mode": "must_not", "text": "guest"}])
    assert dbfix.query("SELECT switch_id, rule FROM findings ORDER BY rule") == [(a, "c1")]     # no "Guest" in A's latest; B has no backup driver


async def test_every_backup_read_runs_the_rules_and_a_failing_check_never_fails_the_backup(database, monkeypatch, caplog):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    assert await sshcli.store_backup(sid, CFG, "nightly") is True
    assert len(open_rules(sid)) == len(found(CFG))
    await db.set_setting("radius_server", "203.0.113.10")
    assert await sshcli.store_backup(sid, CFG, "nightly") is False                              # no new row: the rules run all the same
    assert "radius_prereq" in open_rules(sid)
    monkeypatch.setattr(compliance, "evaluate_config", dbfix.raising_async_fn(RuntimeError("kaputt")))
    assert await sshcli.store_backup(sid, CFG + "no telnet-server\n", "nightly") is True
    assert "Sicherheitsregeln" in caplog.text and "telnet" in open_rules(sid)


async def test_the_rules_run_after_the_backup_is_committed(database, monkeypatch):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    seen = []

    async def spy(switch_id, raw):
        seen.append((switch_id, raw, dbfix.query("SELECT count(*) FROM config_backups")))     # a connection of its own sees the commit
        return []

    monkeypatch.setattr(compliance, "evaluate_config", spy)
    assert await sshcli.store_backup(sid, CFG, "nightly") is True and seen == [(sid, CFG, [(1,)])]


async def test_a_good_poll_runs_the_snmp_rules(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)      # community "read-s3cret": the baseline, with the v2c write community
    assert [f["rule"] for f in await compliance.open_findings(sid)] == ["snmp_write_insecure"]
    dbfix.query("UPDATE switches SET snmp_community = ? WHERE id = ?", (crypto.encrypt("public"), sid))
    assert (await poller.poll_switch(sid))["ok"] is True
    assert [f["rule"] for f in await compliance.open_findings(sid)] == ["snmp_read_default", "snmp_write_insecure"]


async def test_a_failing_snmp_check_never_fails_the_poll(net, monkeypatch, caplog):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    monkeypatch.setattr(compliance, "evaluate_snmp", dbfix.raising_async_fn(RuntimeError("kaputt")))
    assert (await poller.poll_switch(sid))["ok"] is True and "Sicherheitsregeln 10.0.0.1" in caplog.text


async def test_a_failed_poll_runs_no_snmp_rules(net, monkeypatch):                              # Pin: only the good path checks
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    called = []

    async def spy(row):
        called.append(row["id"])
        return []

    monkeypatch.setattr(compliance, "evaluate_snmp", spy)
    monkeypatch.setattr(snmp, "walk", dbfix.raising_async_fn(snmp.SnmpError("Timeout")))
    assert (await poller.poll_switch(sid))["ok"] is False and called == []


async def test_the_snmp_check_tells_what_is_new_after_its_baseline(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1", snmp_community=crypto.encrypt("lesen-42"))
    row = {**apifix_row(), **ROW, "id": sid, "snmp_community": crypto.encrypt("lesen-42")}
    assert await compliance.evaluate_snmp(row) == [] and open_rules(sid) == []
    [new] = await compliance.evaluate_snmp({**row, "snmp_community": crypto.encrypt("private")})
    assert new == {"id": new["id"], "rule": "snmp_read_default", "label": "SwitchView liest mit „public“ oder „private“", "severity": "warn",
                   "line_no": None, "line": "", "detail": "SwitchView liest per SNMPv2c mit der Community „private“", "first_seen": new["first_seen"]}
    assert await compliance.evaluate_snmp({**row, "snmp_community": crypto.encrypt("private")}) == []     # still there: nothing new
    assert await compliance.evaluate_snmp(row) == [] and open_rules(sid) == []
    assert await compliance.evaluate_config(sid, CFG) == []                                        # the configuration has a baseline of its own


async def test_a_finding_seen_again_keeps_its_row_and_takes_the_new_line_and_detail(database, monkeypatch):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    monkeypatch.setattr(compliance, "_now", lambda: "2026-11-01 02:30:00")
    await compliance.evaluate_config(sid, CFG)
    monkeypatch.setattr(compliance, "_now", lambda: "2026-11-02 02:30:00")
    await compliance.evaluate_config(sid, "; one line more\n" + CFG + "web-management ssl\n")
    assert dbfix.query("SELECT rule, line_no, detail, first_seen, last_seen FROM findings WHERE rule IN ('snmp_write_community', 'web_plaintext') "
                       "ORDER BY rule") == [("snmp_write_community", line_of("snmp-server") + 1, "", "2026-11-01 02:30:00", "2026-11-02 02:30:00"),
                                            ("web_plaintext", None, "HTTPS ist zusätzlich an", "2026-11-01 02:30:00", "2026-11-02 02:30:00")]
    assert dbfix.query("SELECT count(*) FROM findings") == [(len(found(CFG)),)]
    assert dbfix.query("SELECT compliance_cfg_at, compliance_snmp_at FROM switches") == [("2026-11-02 02:30:00", None)]


async def test_the_same_line_twice_is_a_finding_each_matched_in_order(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await db.set_setting(compliance.SETTINGS_KEY, '{"off": [], "custom": [{"id": "c1", "name": "Exit", "mode": "must_not", "text": "exit"}]}')
    exits = [i for i, x in enumerate(CFG.splitlines(), 1) if "exit" in x]
    await compliance.evaluate_config(sid, CFG)
    rows = dbfix.query("SELECT id, line_no, line FROM findings WHERE rule = 'c1' ORDER BY id")
    assert [(n, line) for _, n, line in rows] == [(n, "exit") for n in exits] and len(exits) == CFG.count("exit") > 1
    new = await compliance.evaluate_config(sid, CFG + "exit\n")                                   # one more: told
    assert [(f["rule"], f["line_no"], f["line"]) for f in new] == [("c1", len(CFG.splitlines()) + 1, "exit")]
    assert await compliance.evaluate_config(sid, CFG.replace('   disable\n   name "unused"\n   exit\n', "")) == []    # the last but one gone
    assert dbfix.query("SELECT id, line_no FROM findings WHERE rule = 'c1' AND resolved_at IS NULL ORDER BY id") == [
        (fid, n) for (fid, _, _), n in zip(rows, exits[:-1])]                                      # the rows in order, the later ones resolved


async def test_communities_masked_alike_are_a_finding_each_and_one_more_is_told(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")

    def community(name):
        return f'snmp-server community "{name}" unrestricted\n'

    two = CFG.replace('snmp-server community "public" Unrestricted\n', community("public") + community("private"))
    n, masked = line_of('"public"', two), 'snmp-server community "***" unrestricted'
    await compliance.evaluate_config(sid, two)
    assert dbfix.query("SELECT rule, line_no, line, detail FROM findings WHERE rule LIKE 'snmp%' ORDER BY id") == [
        ("snmp_default_community", n, masked, "Community „public“"), ("snmp_default_community", n + 1, masked, "Community „private“"),
        ("snmp_write_community", n, masked, ""), ("snmp_write_community", n + 1, masked, "")]
    new = await compliance.evaluate_config(sid, two.replace(community("private"), community("private") + community("hinterher")))
    assert [(f["rule"], f["line_no"], f["line"]) for f in new] == [("snmp_write_community", n + 2, masked)]
    ids = [fid for (fid,) in dbfix.query("SELECT id FROM findings WHERE rule LIKE 'snmp%' ORDER BY id")]
    assert await compliance.evaluate_config(sid, two.replace(community("public"), "")) == []      # one of each left: the first rows stay
    assert dbfix.query("SELECT id, rule, line_no, detail FROM findings WHERE rule LIKE 'snmp%' AND resolved_at IS NULL ORDER BY id") == [
        (ids[0], "snmp_default_community", n, "Community „private“"), (ids[2], "snmp_write_community", n, "")]


def test_a_custom_rule_shows_its_first_lines_and_counts_the_rest():
    rule = {"id": "c1", "name": "Ports", "mode": "must_not", "text": "INTERFACE"}
    raw = CFG + "".join(f"interface {i}\n   exit\n" for i in range(1, 151))
    hits = [i for i, x in enumerate(raw.splitlines(), 1) if "interface" in x]
    got, limit = compliance.check_custom(raw, [rule]), compliance.CUSTOM_LINES
    assert len(hits) == 152 > limit and [n for _, n, _, _ in got] == hits[:limit]
    more = f"Zeile enthält „INTERFACE“ (und {152 - limit} weitere, nicht einzeln aufgeführt)"
    assert [d for *_, d in got] == ["Zeile enthält „INTERFACE“"] * (limit - 1) + [more]
    assert len(compliance.check_custom(raw, [{**rule, "mode": "must"}])) == 0
    just = "\n".join(raw.splitlines()[:hits[limit - 1]])                                           # exactly limit lines: no count
    assert [d for *_, d in compliance.check_custom(just, [rule])] == ["Zeile enthält „INTERFACE“"] * limit


async def test_open_findings_come_critical_first_then_by_line_each_line_masked_again(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await compliance.evaluate_config(sid, CFG)
    dbfix.query("UPDATE findings SET line = 'snmp-server community \"geheim\" Unrestricted' WHERE rule = 'snmp_write_community'")
    got, n = await compliance.open_findings(sid), line_of("snmp-server community")
    assert [(f["rule"], f["severity"], f["line_no"]) for f in got] == [("telnet", "crit", None), ("snmp_default_community", "crit", n),
                                                                         ("web_plaintext", "warn", None), ("snmp_write_community", "warn", n)]
    assert got[3]["line"] == 'snmp-server community "***" Unrestricted' and got[0]["label"] == "Telnet-Server an"
    assert set(got[0]) == {"id", "rule", "label", "severity", "line_no", "line", "detail", "first_seen"}


async def test_the_summary_counts_the_open_findings_of_the_rules_on_by_switch_name(database):
    c, b, a = (dbfix.insert_switch(name=n, host=f"10.0.0.{i}") for i, n in enumerate(("C-SW", "b-sw", "a"), 1))
    await compliance.evaluate_config(b, CFG)
    await compliance.evaluate_config(c, CFG + "no telnet-server\nno web-management\n")
    await compliance.evaluate_config(a, 'hostname "a"\nno telnet-server\nno web-management\n')
    assert await compliance.summary() == {"total": 6, "crit": 3, "switches": [{"id": b, "name": "b-sw", "count": 4, "crit": 2},
                                                                             {"id": c, "name": "C-SW", "count": 2, "crit": 1}]}
    await db.set_setting(compliance.SETTINGS_KEY, '{"off": ["snmp_default_community", "snmp_write_community"], "custom": []}')
    assert await compliance.summary() == {"total": 2, "crit": 1, "switches": [{"id": b, "name": "b-sw", "count": 2, "crit": 1}]}


def test_the_findings_of_a_switch_that_is_not_there_are_a_404(api):
    r = api.get("/api/switches/999/findings")
    assert (r.status_code, r.json()["detail"]) == (404, "Switch nicht gefunden")


def test_a_switch_without_findings_has_an_empty_list(api):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    assert api.get(f"/api/switches/{sid}/findings").json() == {"findings": []}
    assert api.get("/api/compliance").json() == {"total": 0, "crit": 0, "switches": []}


def test_a_deleted_switch_takes_its_findings(api):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    asyncio.run(compliance.evaluate_config(sid, CFG))
    assert api.delete(f"/api/switches/{sid}").status_code == 200                              # through the route: dbfix has no foreign keys on
    assert dbfix.query("SELECT count(*) FROM findings") == [(0,)]


async def test_the_purge_deletes_old_resolved_findings_only(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    for first, resolved in (("2000-01-01 00:00:00", "2000-01-02 00:00:00"), ("2000-01-01 00:00:00", None), ("2000-01-01 00:00:00", "2999-01-01 00:00:00")):
        dbfix.query("INSERT INTO findings(switch_id, rule, source, first_seen, last_seen, resolved_at) VALUES (?, 'telnet', 'config', ?, ?, ?)",
                    (sid, first, first, resolved))
    assert await history.purge(180) == {"findings": 1}
    assert dbfix.query("SELECT resolved_at FROM findings ORDER BY id") == [(None,), ("2999-01-01 00:00:00",)]


@pytest.mark.parametrize("extra, want", [
    ("NO TELNET-SERVER\n", []),
    ("SNMP-Server Community PRIVATE operator\n", [("telnet", ""), ("snmp_default_community", "Community „private“")]),
    ('  snmp-server community "rw-42" manager UNRESTRICTED\n', [("telnet", ""), ("snmp_write_community", "")]),
    ("snmp-server community unrestricted operator restricted\n", [("telnet", "")]),              # a community of that name does not write
    ('no snmp-server community "public"\n', [("telnet", "")]),
])
def test_keywords_are_read_without_case_on_trimmed_lines(extra, want):
    raw = CFG.replace('snmp-server community "public" Unrestricted\n', "") + extra
    assert [(r[0], r[3]) for r in found(raw) if r[0] == "telnet" or r[0].startswith("snmp_")] == want


def test_a_config_parse_config_refuses_checks_no_radius_rule_but_the_others():
    big = CFG + "interface 1-1024\n   untagged vlan 1-4094\n   exit\n"                          # more port x VLAN entries than cfgparse.MAX_REFS
    with pytest.raises(ValueError):
        cfgparse.parse_config(big)
    got = [r[0] for r in found(big, "203.0.113.10")]
    assert "radius_prereq" not in got and "telnet" in got


def test_the_radius_rule_names_the_server_when_its_host_line_is_missing():
    [detail] = [d for r, _, _, d in found(CFG, "203.0.113.99") if r == "radius_prereq"]
    assert detail == "Fehlt: RADIUS-Server 203.0.113.99, CoA (dyn-authorization), time-window 0, Park-VLAN 3999"
