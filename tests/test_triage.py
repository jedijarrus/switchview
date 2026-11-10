"""Phase 4c, Task 10: the triage of unknown devices (app/triage.py, app/api_devices.py). Every entry of GET /api/devices/unknown
carries a suggestion (device type, the PacketFence role released devices of that type have most, the port mode) from what SwitchView
has already: the vendor (the ARP table or a small prefix table), the name, the LLDP text of a port with one device and its PoE; with
its first sighting (history) and whether it is new. Several devices or a CSV list are released through POST /api/devices/import
(preview by default, all or nothing, at most 200 rows, the way of one device), and POST /api/devices/{mac}/reevaluate asks
PacketFence for a CoA. A suggestion is never applied by itself.

The pure cases need no fixture; the list runs the real poller against the recorded walks of tests/switchfix.py (the `net` fixture of
tests/conftest.py); PacketFence is patched or a fake httpx (apifix.fake_httpx). Nothing leaves the process.
"""
import asyncio
import re
from datetime import datetime, timedelta, timezone

import pytest

import api_devices
import apifix
import config
import crypto
import db
import dbfix
import history
import main
import pf
import poller
import triage
from netfix import add, fdb, merge
from switchfix import W_POE
from test_lldp_trust import bp, entry, unknown


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app against a fresh database under tmp_path, signed in as apifix.USER (Admin)."""
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


# ── The suggestion ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_the_vendor_table_is_the_one_checked_against_the_ieee_registry():
    assert len(triage.OUI) == 86 and all(re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){2}", k) for k in triage.OUI)
    assert (triage.OUI["80:5e:c0"], triage.OUI["00:40:8c"], triage.OUI["d4:f0:c9"], triage.OUI["00:a0:57"]) == ("Yealink", "Axis", "Kyocera", "LANCOM")
    assert all(any(word in label.lower() for word in triage.VENDOR_KIND) for label in triage.OUI.values())


def test_every_kind_the_triage_names_is_one_of_the_device_database():
    kinds = set(triage.KIND_ORDER)
    assert kinds == set(triage.VENDOR_KIND.values()) == set(triage.NAME_HINTS) == set(triage.KIND_LABEL) and kinds <= set(api_devices.KINDS)
    assert triage.POE_KINDS <= kinds and triage.KNOWN_MODE <= kinds


def entry_(mac="aa:bb:cc:00:00:01", name="", vendor="", lldp="", mc=1, st="known"):
    return {"mac": mac, "name": name, "vendor": vendor, "lldp": lldp, "mc": mc, "st": st}


POE = {"poe": {"on": True, "status": 3, "mw": 4200}}


@pytest.mark.parametrize("entry, port, kind, why", [
    (entry_(mac="80:5e:c0:11:22:33"), {}, "telefon", ["Hersteller Yealink (MAC-Präfix)"]),
    (entry_(name="NPI8A1B2C"), {}, "drucker", ["Name „NPI8A1B2C“"]),
    (entry_(lldp="SIP-T10X"), POE, "telefon", ["LLDP „SIP-T10X“", "PoE: liefert Strom"]),
    (entry_(lldp="SIP-T10X", mc=2), {}, None, []),                                     # two devices at the port: whose LLDP?
    (entry_(mac="ac:cc:8e:00:00:01", name="axis-accc8e000001"), POE, "kamera",
     ["Hersteller Axis (MAC-Präfix)", "Name „axis-accc8e000001“", "PoE: liefert Strom"]),
    (entry_(vendor="YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD."), {}, "telefon", ["Hersteller YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD."]),
    (entry_(vendor="Hewlett Packard"), {}, None, []),
    (entry_(name="Drucker-VK", lldp="UAP-AC-Pro"), {}, "drucker", ["Name „Drucker-VK“"]),   # a tie goes by KIND_ORDER; why: the winner's
    (entry_(name="Drucker-VK", lldp="UAP-AC-Pro"), POE, "netzwerk", ["LLDP „UAP-AC-Pro“", "PoE: liefert Strom"]),    # PoE breaks the tie
    (entry_(mac="00:80:77:00:00:01"), POE, "drucker", ["Hersteller Brother (MAC-Präfix)"]),    # PoE says nothing about a printer
    (entry_(mac="00:15:65:00:00:01"), None, "telefon", ["Hersteller Yealink (MAC-Präfix)"]),   # a port the map does not have
    (entry_(mac="80:5e:c0:11:22:33"), {"poe": {"on": True, "status": 2, "mw": 0}}, "telefon", ["Hersteller Yealink (MAC-Präfix)"]),
])
def test_suggest(entry, port, kind, why):
    s = triage.suggest(entry, port, {}, nac=True)
    assert (s["kind"], s["why"]) == (kind, why)


def test_poe_alone_suggests_nothing_but_says_so():
    s = triage.suggest(entry_(), POE, {}, nac=True)
    assert (s["kind"], s["why"], s["hint"]) == (None, ["PoE: liefert Strom"], "Gerät mit PoE – Telefon, Kamera oder Access Point?")
    assert (s["label"], s["role"], s["role_count"], s["port_mode"]) == (None, None, 0, None)


def test_the_role_follows_the_known_devices_of_that_kind():
    s = triage.suggest(entry_(mac="80:5e:c0:11:22:33"), {}, {"telefon": ("voice", 7)}, nac=True)
    assert (s["kind"], s["label"], s["role"], s["role_count"], s["port_mode"]) == ("telefon", "Telefon", "voice", 7, "known")
    other = triage.suggest(entry_(mac="80:5e:c0:11:22:33"), {}, {"drucker": ("print", 3)}, nac=True)    # no phone released yet
    assert (other["kind"], other["role"], other["role_count"]) == ("telefon", None, 0)


def test_the_role_of_a_kind_is_the_one_released_devices_have_most(api):               # roles_by_kind: released, with a role; a tie alphabetically
    dbfix.query("INSERT INTO devices(mac, name, kind, role, allowed) VALUES "
                "('aa:00:00:00:00:01', 'a', 'telefon', 'voice', 1), ('aa:00:00:00:00:02', 'b', 'telefon', 'voice', 1), "
                "('aa:00:00:00:00:03', 'c', 'telefon', 'sip', 1), ('aa:00:00:00:00:04', 'd', 'telefon', 'x', 0), "
                "('aa:00:00:00:00:05', 'e', 'telefon', 'x', 0), ('aa:00:00:00:00:06', 'f', 'telefon', 'x', 0), "
                "('aa:00:00:00:00:07', 'g', 'telefon', '', 1), ('aa:00:00:00:00:08', 'h', 'drucker', 'print', 1), "
                "('aa:00:00:00:00:09', 'i', 'drucker', 'büro', 1)")
    assert asyncio.run(api_devices.roles_by_kind()) == {"telefon": ("voice", 2), "drucker": ("büro", 1)}


@pytest.mark.parametrize("st, nac, hint", [
    ("protected", True, "Port steht auf „Protected“: eine Freigabe wirkt erst an einem Port „Bekannte Geräte“ oder „RADIUS“"),
    ("on", True, "Port steht auf „An“: eine Freigabe wirkt erst an einem Port „Bekannte Geräte“ oder „RADIUS“"),
    ("known", True, None), ("radius", True, None), ("", True, None), ("protected", False, None)])
def test_the_port_hint_names_a_port_that_does_not_ask(st, nac, hint):
    assert triage.suggest(entry_(mac="80:5e:c0:11:22:33", st=st), {}, {}, nac=nac)["hint"] == hint


def test_a_device_without_a_suggestion_has_no_port_hint():
    assert triage.suggest(entry_(st="protected"), {}, {}, nac=True)["hint"] is None


def test_the_vendor_label_says_where_it_comes_from():                                    # the ARP table, triage.OUI, then names.OUI
    assert triage.vendor_label("80:5e:c0:00:00:01", "YEALINK") == ("YEALINK", False) and triage.vendor_label("80:5e:c0:00:00:01", "") == ("Yealink", True)
    assert triage.vendor_label("b8:27:eb:00:00:01", "") == ("Raspberry Pi", True) and triage.vendor_label("aa:bb:cc:00:00:01", "") == ("", False)
    assert triage.vendor_label("80:5E:C0:00:00:01", "") == ("Yealink", True)


# ── The list of unknown devices ───────────────────────────────────────────────────────────────────────────────────────────────────
async def test_the_unknown_list_carries_a_suggestion_its_first_sighting_and_poe(net, monkeypatch):
    sid = await add(net, "SW-A", "10.0.0.3", "procurve", W_POE, fdb(bp("3"), "80:5e:c0:00:00:01"))
    e = entry(await unknown(), "80:5e:c0:00:00:01")
    assert e["suggest"]["kind"] == "telefon" and e["first_seen"] and e["new"] is False and "poe" in e    # the first recording is the baseline
    net.rec["10.0.0.3"] = merge(net.rec["10.0.0.3"], fdb(bp("6"), "aa:bb:cc:00:00:05"))    # port 6: ports 4 and 5 are Trk1's
    later = (datetime.now(timezone.utc) + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
    monkeypatch.setattr(poller, "utc_now", lambda: later)
    await poller.poll_switch(sid)
    out = await unknown()
    assert entry(out, "aa:bb:cc:00:00:05")["new"] is True and out[0]["mac"] == "aa:bb:cc:00:00:05"


async def test_an_entry_names_the_poe_of_its_port_and_asks_with_the_arp_vendor_alone(net):
    await add(net, "SW-A", "10.0.0.3", "procurve", W_POE, fdb(bp("1"), "00:15:65:00:00:01"), fdb(bp("3"), "aa:bb:cc:00:00:03"))
    out = await unknown()
    phone, other = entry(out, "00:15:65:00:00:01"), entry(out, "aa:bb:cc:00:00:03")
    assert phone["poe"] == {"on": True, "status": 3, "mw": phone["poe"]["mw"]} and other["poe"]["status"] == 1
    # names.OUI knows the prefix too and fills the entry's vendor; the suggestion still says it is from the prefix
    assert phone["vendor"] == "Yealink" and phone["suggest"]["why"] == ["Hersteller Yealink (MAC-Präfix)", "PoE: liefert Strom"]
    assert (other["suggest"]["kind"], other["suggest"]["why"], other["first_seen"] is not None, other["new"]) == (None, [], True, False)


async def test_an_old_sighting_is_not_new_and_the_newest_first_sighting_leads(net, monkeypatch):
    sid = await add(net, "SW-A", "10.0.0.3", "procurve", W_POE, fdb(bp("3"), "aa:bb:cc:00:00:03"))
    now = datetime.now(timezone.utc)
    for minutes, port, mac in ((1, "2", "aa:bb:cc:00:00:05"), (2, "6", "aa:bb:cc:00:00:06")):
        net.rec["10.0.0.3"] = merge(net.rec["10.0.0.3"], fdb(bp(port), mac))
        at = (now + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        monkeypatch.setattr(poller, "utc_now", lambda at=at: at)
        await poller.poll_switch(sid)
    assert [e["mac"] for e in await unknown()] == ["aa:bb:cc:00:00:06", "aa:bb:cc:00:00:05", "aa:bb:cc:00:00:03"]
    old = (now - timedelta(hours=25)).strftime("%Y-%m-%d %H:%M:%S")
    dbfix.query("UPDATE sightings SET first_seen = ? WHERE mac = 'aa:bb:cc:00:00:05'", (old,))
    dbfix.query("UPDATE sightings SET first_seen = ? WHERE mac = 'aa:bb:cc:00:00:03'", ((now - timedelta(hours=30)).strftime("%Y-%m-%d %H:%M:%S"),))
    out = await unknown()
    assert [(e["mac"], e["new"]) for e in out] == [("aa:bb:cc:00:00:06", True), ("aa:bb:cc:00:00:05", False), ("aa:bb:cc:00:00:03", False)]
    assert entry(out, "aa:bb:cc:00:00:05")["first_seen"] == old
    dbfix.query("DELETE FROM sightings WHERE mac = 'aa:bb:cc:00:00:06'")                  # never recorded: last, and not new
    out = await unknown()
    assert [e["mac"] for e in out][-1] == "aa:bb:cc:00:00:06" and (out[-1]["first_seen"], out[-1]["new"]) == (None, False)


async def test_a_new_device_leads_before_the_stock_of_a_switch_added_later(net, monkeypatch):
    now = datetime.now(timezone.utc)
    at = lambda minutes: (now + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")    # noqa: E731
    sid = await add(net, "SW-A", "10.0.0.3", "procurve", W_POE, fdb(bp("3"), "aa:bb:cc:00:00:03"))
    net.rec["10.0.0.3"] = merge(net.rec["10.0.0.3"], fdb(bp("6"), "aa:bb:cc:00:00:06"))
    monkeypatch.setattr(poller, "utc_now", lambda: at(1))
    await poller.poll_switch(sid)
    monkeypatch.setattr(poller, "utc_now", lambda: at(2))
    await add(net, "SW-B", "10.0.0.4", "procurve", W_POE, fdb(bp("3"), "aa:bb:cc:00:00:0b"))    # its stock: seen later, but not new
    assert [(e["mac"], e["new"]) for e in await unknown()] == [("aa:bb:cc:00:00:06", True), ("aa:bb:cc:00:00:0b", False), ("aa:bb:cc:00:00:03", False)]


@pytest.mark.parametrize("driver, ssh, nac", [("procurve", False, False), ("procurve", True, True), ("generic", True, False)])
async def test_the_port_hint_is_asked_only_where_switchview_sets_the_port_mode(net, monkeypatch, driver, ssh, nac):
    asked = []
    real = triage.suggest
    monkeypatch.setattr(triage, "suggest", lambda entry, port, kinds, nac: asked.append((port["n"], kinds, nac)) or real(entry, port, kinds, nac))
    sid = await add(net, "SW-A", "10.0.0.3", "procurve", W_POE, fdb(bp("3"), "80:5e:c0:00:00:01"))
    dbfix.query("UPDATE switches SET driver = ? WHERE id = ?", (driver, sid))            # a driver without the port modes: no hint
    if ssh:
        dbfix.query("UPDATE switches SET ssh_user = 'admin', ssh_pass = ? WHERE id = ?", (crypto.encrypt("pw"), sid))
    dbfix.query("INSERT INTO devices(mac, name, kind, role, allowed) VALUES ('aa:00:00:00:00:01', 'a', 'telefon', 'voice', 1)")
    assert entry(await unknown(), "80:5e:c0:00:00:01")["suggest"]["role"] == "voice"
    assert asked == [("3", {"telefon": ("voice", 1)}, nac)]


async def test_the_first_sighting_is_the_earliest_of_a_mac_and_of_a_switch(net):
    assert await history.first_seen(set()) == {} and await history.baselines() == {}
    sid = await add(net, "SW-A", "10.0.0.3", "procurve", W_POE)
    rows = [("aa:bb:cc:00:00:01", sid, "3", "2026-11-02 10:00:00"), ("aa:bb:cc:00:00:01", sid, "5", "2026-11-01 09:00:00"),
            ("aa:bb:cc:00:00:02", sid, "5", "2026-11-03 08:00:00")]
    async with db.db() as conn:
        await conn.executemany("INSERT INTO sightings(mac, switch_id, switch_name, port, vlan, first_seen, last_seen) "
                               "VALUES (?, ?, 'SW-A', ?, '1', ?, '2026-11-04 00:00:00')", rows)
        await conn.commit()
    macs = {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:09"}
    assert await history.first_seen(macs) == {"aa:bb:cc:00:00:01": "2026-11-01 09:00:00", "aa:bb:cc:00:00:02": "2026-11-03 08:00:00"}
    assert await history.baselines() == {sid: "2026-11-01 09:00:00"}


async def test_the_first_sightings_are_read_in_chunks(net, monkeypatch):
    sid = await add(net, "SW-A", "10.0.0.3", "procurve", W_POE)
    macs = [f"aa:bb:cc:00:00:{i:02x}" for i in range(5)]
    async with db.db() as conn:
        await conn.executemany("INSERT INTO sightings(mac, switch_id, switch_name, port, vlan, first_seen, last_seen) "
                               "VALUES (?, ?, 'SW-A', '3', '1', '2026-11-01 09:00:00', '2026-11-04 00:00:00')", [(m, sid) for m in macs])
        await conn.commit()
    monkeypatch.setattr(history, "IN_CHUNK", 2)
    assert await history.first_seen(set(macs)) == dict.fromkeys(macs, "2026-11-01 09:00:00")


# ── Import: several devices or a CSV list ─────────────────────────────────────────────────────────────────────────────────────────
def test_the_import_reads_what_people_send(api):                                         # Review Focus 5
    text = ("\ufeffMAC;Rolle;Name;Typ\r\n\r\n80:5E:C0:00:00:01;voice;Telefon 1;telefon\r\n805ec0000002;;;\r\n80-5e-c0-00-00-01;voice;;\r\n"
            "zz;voice;;\r\n80:5e:c0:00:00:03;voice;x;fax\r\n")
    r = api.post("/api/devices/import", json={"csv": text}).json()
    assert [(x["line"], x["mac"], x["status"], x["reason"]) for x in r["rows"]] == [
        (3, "80:5e:c0:00:00:01", "ok", ""), (4, "80:5e:c0:00:00:02", "ok", ""), (5, "80:5e:c0:00:00:01", "error", "doppelt (wie Zeile 3)"),
        (6, "zz", "error", api_devices.BAD_MAC), (7, "80:5e:c0:00:00:03", "error", "Typ „fax“ unbekannt")]
    assert (r["ok"], r["errors"], r["roles_checked"]) == (2, 3, False) and r["note"].startswith("Rollen nicht geprüft: ")
    assert r["rows"][1]["name"] == "Yealink 00:00:02" and dbfix.query("SELECT count(*) FROM devices") == [(0,)]
    assert (r["exists"], "created" in r, r["note"]) == (0, False, "Rollen nicht geprüft: PacketFence-API ist nicht eingerichtet")
    assert (r["rows"][0]["name"], r["rows"][0]["role"], r["rows"][0]["kind"], r["rows"][1]["kind"]) == ("Telefon 1", "voice", "telefon", "sonstiges")
    comma = api.post("/api/devices/import", json={"csv": "aa:bb:cc:00:00:09,default,Drucker EK\n"}).json()
    assert [(x["mac"], x["role"], x["name"], x["status"]) for x in comma["rows"]] == [("aa:bb:cc:00:00:09", "default", "Drucker EK", "ok")]


def test_the_csv_reader_keeps_the_line_numbers_and_the_first_four_cells():
    assert triage.parse_csv("") == [] and triage.parse_csv("\ufeffMAC-Adresse;Rolle\n") == []
    assert triage.parse_csv('aa:bb:cc:00:00:01 ; voice ;"Drucker; EK";drucker;mehr\n\naa:bb:cc:00:00:02\n') == [
        {"line": 1, "mac": "aa:bb:cc:00:00:01", "role": "voice", "name": "Drucker; EK", "kind": "drucker"},
        {"line": 3, "mac": "aa:bb:cc:00:00:02", "role": "", "name": "", "kind": ""}]
    # the first line with content decides: no ";" in it, so "," separates
    assert [r["name"] for r in triage.parse_csv("aa:bb:cc:00:00:01,voice,A\naa:bb:cc:00:00:02,voice,A;B\n")] == ["A", "A;B"]
    assert triage.mac_of("AABB.CC00.0001") == "aa:bb:cc:00:00:01" and triage.mac_of("aa:bb:cc:00:00") is None and triage.mac_of("") is None
    assert [triage.unformula(t) for t in ("'=x", "'-a", "'a", "=x", "a", "'")] == ["=x", "-a", "'a", "=x", "a", "'"]


def test_a_formula_name_is_refused_and_an_exported_one_comes_back(api):                 # Review Focus 5
    r = api.post("/api/devices/import", json={"csv": "aa:bb:cc:00:00:01;;=HYPERLINK(\"x\")\naa:bb:cc:00:00:02;;'-Drucker\n"
                                                     "aa:bb:cc:00:00:03;;'=x\naa:bb:cc:00:00:04;;" + "x" * 65 + "\n"}).json()
    assert [(x["status"], x["reason"], x["name"]) for x in r["rows"]] == [
        ("error", api_devices.FORMULA_NAME, '=HYPERLINK("x")'), ("error", api_devices.FORMULA_NAME, "-Drucker"),
        ("error", api_devices.FORMULA_NAME, "=x"), ("error", api_devices.LONG_NAME, "x" * 65)]


def test_a_name_of_the_selection_is_checked_like_one_of_a_csv(api):
    r = api.post("/api/devices/import", json={"rows": [{"mac": "aa:bb:cc:00:00:01", "name": "@SUM(1)"}, {"mac": "aa:bb:cc:00:00:02", "name": "'ok"},
                                                       {"mac": "aa:bb:cc:00:00:03", "name": " x" * 32}]}).json()
    assert [(x["line"], x["status"], x["reason"], x["name"]) for x in r["rows"]] == [
        (1, "error", api_devices.FORMULA_NAME, "@SUM(1)"), (2, "ok", "", "'ok"), (3, "ok", "", ("x " * 32).strip())]


def test_nothing_is_stored_while_a_row_is_wrong(api):                                    # Review Focus 5
    r = api.post("/api/devices/import", json={"csv": "aa:bb:cc:00:00:01;;A\nzz;;B\n", "dry_run": False})
    assert (r.status_code, r.json()["detail"]) == (422, api_devices.IMPORT_ERRORS.format(n="1 fehlerhafte Zeile"))
    assert dbfix.query("SELECT count(*) FROM devices") == [(0,)]
    r = api.post("/api/devices/import", json={"csv": "aa:bb:cc:00:00:01;;A\nzz;;B\nyy;;C\n", "dry_run": False})
    assert r.json()["detail"] == "Die Liste hat 2 fehlerhafte Zeilen – nichts übernommen"
    assert dbfix.query("SELECT count(*) FROM devices") == [(0,)] and dbfix.query("SELECT count(*) FROM audit") == [(0,)]


def test_an_import_takes_the_way_of_one_device(api, monkeypatch):
    synced = []
    monkeypatch.setattr(api_devices, "schedule_sync", synced.append)
    monkeypatch.setattr(api_devices, "_sessions", {"at": 0.0, "items": []})
    dbfix.query("INSERT INTO devices(mac, name, role, allowed) VALUES ('aa:bb:cc:00:00:07', 'Alt', 'x', 0)")
    r = api.post("/api/devices/import", json={"rows": [{"mac": "AA-BB-CC-00-00-01"}, {"mac": "aa:bb:cc:00:00:07", "name": "Neu"}],
                                              "kind": "telefon", "role": "voice", "valid_until": "2027-01-31", "dry_run": False}).json()
    assert (r["created"], r["exists"]) == (1, 1) and synced == [["aa:bb:cc:00:00:01"]] and api_devices._sessions["items"] is None
    assert dbfix.query("SELECT mac, kind, role, allowed, valid_until, created_by FROM devices ORDER BY mac") == [
        ("aa:bb:cc:00:00:01", "telefon", "voice", 1, "2027-01-31", apifix.USER["username"]), ("aa:bb:cc:00:00:07", "sonstiges", "x", 0, None, None)]
    assert dbfix.query("SELECT action, target, detail FROM audit") == [("device_create", "aa:bb:cc:00:00:01", "Gerät 00:00:01 freigegeben=1 (Sammel-Freigabe)")]
    assert [(x["mac"], x["status"], x["reason"]) for x in r["rows"]] == [("aa:bb:cc:00:00:01", "ok", ""), ("aa:bb:cc:00:00:07", "exists", api_devices.EXISTS)]
    assert dbfix.query("SELECT name, notes FROM devices WHERE mac = 'aa:bb:cc:00:00:01'") == [("Gerät 00:00:01", "Sammel-Freigabe")]


def test_a_csv_import_stores_each_row_as_it_reads_and_audits_the_role_of_the_request(api, monkeypatch):
    synced = []
    monkeypatch.setattr(api_devices, "schedule_sync", synced.append)
    apifix.become(apifix.user("aendern", "anna"))
    r = api.post("/api/devices/import", json={"csv": "aa:bb:cc:00:00:01;voice;Telefon 1;telefon\naa:bb:cc:00:00:02;;;\n", "kind": "drucker",
                                              "role": "print", "dry_run": False}).json()
    assert (r["created"], r["ok"], r["errors"]) == (2, 2, 0) and synced == [["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]]
    assert dbfix.query("SELECT mac, name, kind, role, allowed, notes, created_by FROM devices ORDER BY mac") == [
        ("aa:bb:cc:00:00:01", "Telefon 1", "telefon", "voice", 1, "CSV-Import", "anna"),
        ("aa:bb:cc:00:00:02", "Gerät 00:00:02", "drucker", "print", 1, "CSV-Import", "anna")]
    assert dbfix.query("SELECT username, action, target, detail, role FROM audit ORDER BY id") == [
        ("anna", "device_create", "aa:bb:cc:00:00:01", "Telefon 1 freigegeben=1 (CSV-Import)", "aendern"),
        ("anna", "device_create", "aa:bb:cc:00:00:02", "Gerät 00:00:02 freigegeben=1 (CSV-Import)", "aendern")]


def test_an_import_with_nothing_new_starts_no_sync(api, monkeypatch):
    synced = []
    monkeypatch.setattr(api_devices, "schedule_sync", synced.append)
    monkeypatch.setattr(api_devices, "_sessions", {"at": 0.0, "items": []})
    dbfix.query("INSERT INTO devices(mac, name) VALUES ('aa:bb:cc:00:00:07', 'Alt')")
    r = api.post("/api/devices/import", json={"rows": [{"mac": "aa:bb:cc:00:00:07"}], "dry_run": False}).json()
    assert (r["created"], r["exists"], synced, api_devices._sessions["items"]) == (0, 1, [], [])


def test_a_device_stored_since_the_check_stays_as_it_is(api, monkeypatch):
    synced, real = [], api_devices._checked_rows

    def checked(*args):                                                                  # someone releases the same device meanwhile
        rows = real(*args)
        dbfix.query("INSERT INTO devices(mac, name, role) VALUES ('aa:bb:cc:00:00:01', 'Annas Drucker', 'print')")
        return rows
    monkeypatch.setattr(api_devices, "_checked_rows", checked)
    monkeypatch.setattr(api_devices, "schedule_sync", synced.append)
    r = api.post("/api/devices/import", json={"rows": [{"mac": "aa:bb:cc:00:00:01", "name": "Neu"}, {"mac": "aa:bb:cc:00:00:02", "name": "B"}],
                                              "dry_run": False}).json()
    assert (r["created"], r["ok"], r["exists"], synced) == (1, 1, 1, [["aa:bb:cc:00:00:02"]])
    assert [(x["status"], x["reason"]) for x in r["rows"]] == [("exists", api_devices.EXISTS), ("ok", "")]
    assert dbfix.query("SELECT name, role, allowed FROM devices WHERE mac = 'aa:bb:cc:00:00:01'") == [("Annas Drucker", "print", 0)]
    assert dbfix.query("SELECT target FROM audit") == [("aa:bb:cc:00:00:02",)]


def test_a_preview_stores_and_drops_nothing(api, monkeypatch):
    synced = []
    monkeypatch.setattr(api_devices, "schedule_sync", synced.append)
    monkeypatch.setattr(api_devices, "_sessions", {"at": 0.0, "items": []})
    dbfix.query("INSERT INTO devices(mac, name) VALUES ('aa:bb:cc:00:00:07', 'Alt')")
    r = api.post("/api/devices/import", json={"rows": [{"mac": "aa:bb:cc:00:00:01"}, {"mac": "aa:bb:cc:00:00:07", "name": "=x"}]}).json()
    assert (r["ok"], r["exists"], r["errors"], "created" in r, synced) == (1, 1, 0, False, []) and api_devices._sessions["items"] == []    # the default
    assert [(x["status"], x["reason"]) for x in r["rows"]] == [("ok", ""), ("exists", api_devices.EXISTS)]    # a known device is not checked further
    assert dbfix.query("SELECT mac, name FROM devices") == [("aa:bb:cc:00:00:07", "Alt")] and dbfix.query("SELECT count(*) FROM audit") == [(0,)]


@pytest.mark.parametrize("body, status, detail", [
    ({}, 422, api_devices.IMPORT_ONE_OF), ({"csv": "x", "rows": [{"mac": "x"}]}, 422, api_devices.IMPORT_ONE_OF),
    ({"csv": "".join(f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}\n" for i in range(201))}, 422, api_devices.IMPORT_TOO_MANY),
    ({"rows": [{"mac": "aa:bb:cc:00:00:01"}], "valid_until": "2026-02-30"}, 422, "Gültig bis: kein gültiges Datum (JJJJ-MM-TT)")])
def test_the_limits_of_an_import(api, body, status, detail):
    r = api.post("/api/devices/import", json=body)
    assert (r.status_code, r.json()["detail"]) == (status, detail)


def test_two_hundred_rows_are_the_most(api):
    text = "".join(f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}\n" for i in range(200))
    assert api.post("/api/devices/import", json={"csv": text}).json()["ok"] == 200 == triage.IMPORT_MAX
    rows = [{"mac": f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}"} for i in range(201)]
    assert api.post("/api/devices/import", json={"rows": rows}).status_code == 422       # the model's own limit


async def test_the_sync_of_an_import_drops_the_kept_sessions(monkeypatch):               # PacketFence bounces the ports once it has the releases
    seen = []

    async def sync(macs):
        seen.append(macs)
    monkeypatch.setattr(pf, "sync", sync)
    monkeypatch.setattr(api_devices, "_sessions", {"at": 0.0, "items": []})
    await api_devices.sync_job(["aa:bb:cc:00:00:01"])
    assert seen == [["aa:bb:cc:00:00:01"]] and api_devices._sessions["items"] is None


def test_the_sync_of_an_import_is_a_job_of_the_one_scheduler(monkeypatch):
    added = []
    monkeypatch.setattr(main.scheduler, "add_job", lambda *args, **kwargs: added.append((args, kwargs)))
    api_devices.schedule_sync(["aa:bb:cc:00:00:01"])
    assert added == [((api_devices.sync_job, "date"), {"args": [["aa:bb:cc:00:00:01"]], "misfire_grace_time": None})]


def test_a_row_without_a_name_takes_the_arp_name_without_its_domain(api):                # as the form of one device does
    dbfix.query("INSERT INTO names(mac, ip, name) VALUES ('aa:bb:cc:00:00:01', '10.0.0.9', 'pc-17.example.local')")
    dbfix.query("INSERT INTO names(mac, ip, name, vendor) VALUES ('aa:bb:cc:00:00:02', '10.0.0.8', '', 'Hewlett Packard')")
    rows = api.post("/api/devices/import", json={"rows": [{"mac": "aa:bb:cc:00:00:01"}, {"mac": "aa:bb:cc:00:00:02"}]}).json()["rows"]
    assert [x["name"] for x in rows] == ["pc-17", "Hewlett Packard 00:00:02"]


@pytest.mark.parametrize("roles, checked, note, reasons", [
    ([{"name": "voice"}, {"name": "default"}], True, None, ["", "Rolle „fax“ gibt es in PacketFence nicht", ""]),
    (RuntimeError("Anmeldung an PacketFence fehlgeschlagen (HTTP 401)"), False,
     "Rollen nicht geprüft: Anmeldung an PacketFence fehlgeschlagen (HTTP 401)", ["", "", ""])])
def test_with_packetfence_the_roles_are_checked(api, monkeypatch, roles, checked, note, reasons):
    async def pf_roles():
        if isinstance(roles, Exception):
            raise roles
        return roles
    monkeypatch.setattr(pf, "configured", lambda: asyncio.sleep(0, True))
    monkeypatch.setattr(pf, "roles", pf_roles)
    r = api.post("/api/devices/import", json={"csv": "aa:bb:cc:00:00:01;voice\naa:bb:cc:00:00:02;fax\naa:bb:cc:00:00:03\n"}).json()
    assert (r["roles_checked"], r["note"], [x["reason"] for x in r["rows"]]) == (checked, note, reasons)
    assert r["errors"] == sum(1 for reason in reasons if reason)


# ── „Neu bewerten“ ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("answer, status, detail", [
    (None, 200, None),
    ("PacketFence kennt dieses Gerät nicht (HTTP 404)", 502, "Neubewertung (CoA) fehlgeschlagen: PacketFence kennt dieses Gerät nicht (HTTP 404)")])
def test_reevaluate_one_mac(api, monkeypatch, answer, status, detail):
    asked = []
    monkeypatch.setattr(pf, "configured", lambda: asyncio.sleep(0, True))

    async def reevaluate(mac):
        asked.append(mac)
        return answer
    monkeypatch.setattr(pf, "reevaluate", reevaluate)
    monkeypatch.setattr(api_devices, "_sessions", {"at": 0.0, "items": []})
    r = api.post("/api/devices/AA-BB-CC-00-00-01/reevaluate")
    assert r.status_code == status and (detail is None or r.json()["detail"] == detail) and asked == ["aa:bb:cc:00:00:01"]
    assert (api_devices._sessions["items"] is None) is (answer is None)                  # the port switches: the kept sessions go
    assert dbfix.query("SELECT action, target, detail FROM audit") == [("device_reevaluate", "aa:bb:cc:00:00:01", answer or "ok")]
    assert answer is not None or r.json() == {"ok": True}


def test_reevaluate_without_packetfence_is_409(api):
    r = api.post("/api/devices/aa:bb:cc:00:00:01/reevaluate")
    assert (r.status_code, r.json()["detail"]) == (409, api_devices.PF_OFF)
    assert api.post("/api/devices/zz/reevaluate").status_code == 422 and dbfix.query("SELECT count(*) FROM audit") == [(0,)]


class PacketFence(apifix.Remote):
    """PacketFence's API as far as a re-evaluation needs it: /login answers a token."""

    def reply(self, method, url):
        return {"token": "t"} if url == "/login" else {}


CoA = ("POST", "/node/aa:bb:cc:00:00:01/reevaluate_access")


@pytest.mark.parametrize("status, raises, said", [
    (200, None, None), (204, None, None), (404, None, "PacketFence kennt dieses Gerät nicht (HTTP 404)"), (500, None, "HTTP 500"),
    (200, OSError("keine Verbindung " + "x" * 300), ("keine Verbindung " + "x" * 300)[:200])])
async def test_pf_reevaluate_names_what_packetfence_says(tmp_path, monkeypatch, status, raises, said):
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    await db.init_db()
    remote = PacketFence()
    monkeypatch.setattr(pf, "httpx", apifix.fake_httpx(remote))
    assert await pf.reevaluate("aa:bb:cc:00:00:01") == "PacketFence-API ist nicht eingerichtet" and remote.calls == []
    async with db.db() as conn:
        await db.write_settings(conn, {"pf_url": "https://pf.example.com:9999", "pf_user": "webapi", "pf_pass": crypto.encrypt("pf-secret")})
        await conn.commit()
    remote.status[CoA] = status
    if raises:
        remote.raises[CoA] = raises
    assert await pf.reevaluate("aa:bb:cc:00:00:01") == said and remote.calls == [("POST", "/login"), CoA]
    remote.status[("POST", "/login")] = 401                                               # the login fails: session's reason
    assert await pf.reevaluate("aa:bb:cc:00:00:01") == "Anmeldung an PacketFence fehlgeschlagen (HTTP 401)"
