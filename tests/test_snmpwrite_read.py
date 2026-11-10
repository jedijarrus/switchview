"""Tests for snmpwrite.build_cfg / snmpwrite.read_cfg: the live SNMP read the SNMP write path plans and verifies against.

read_cfg is the SNMP twin of `show running-config` + cfgparse.parse_config on the SSH path: it walks the switch (inside the change
lock its caller holds) and synthesises the same cfg dict, so changes.plan_ports / verify_ports work unchanged, plus `raw`: the PortList
bytes and index maps the write engine needs to flip single bits and to read back. A bug here plans or verifies a write against the
wrong state of a live switch, so the tests pin three things:

  * the semantics, on a fixture modelled on a ProCurve walk: the port key is ifName, a port's VLAN membership is the bit of its
    EFFECTIVE bridge port (a trunk member uses its trunk's bridge port), and pvid / the PortLists are indexed by bridge port while
    ifAdminStatus / ifAlias are indexed by ifIndex. The bridge-port numbers deliberately differ from the ifIndexes, so mixing the
    two index spaces up gives a visibly wrong answer;
  * agreement with the display poller: the same walk rows fed to poller._build give the same untagged / tagged / admin / alias /
    pvid for every port (on the fixture, on odd agent rows and on a few hundred random switches), so the UI, the inventory and
    the write path see one and the same switch;
  * fail closed: a failed walk (read_cfg walks strictly, so a walk cut short or a stray line behind any value counts as failed), or
    rows that cannot describe the switch safely (a port name twice, a VLAN table or ifAdminStatus read incompletely, a malformed
    index), raise SnmpError instead of returning a partial cfg. A port the cfg cannot describe on its own only takes that port
    out: untagged in more than one VLAN (hybrid / general port), or a PVID that differs from its untagged VLAN. It is listed in
    raw["unmanaged"] with the reason and has no u;
  * cisco_vmps: a port with a vmVlan row is an access port; its VLAN comes from vmVlan, the very object the write path sets for
    it (so verify reads back what was written), and it has no tagged VLANs.

Nothing here touches net-snmp, the network, a switch or the app database: snmp.walk is replaced by a fake agent that answers from
the fixture by OID. Modules are imported flat (app/ is on sys.path via pytest.ini), exactly as the app imports them.
"""
import asyncio
import copy
import json
import random
from collections import defaultdict

import aiosqlite
import pytest
from cryptography.fernet import Fernet

import cfgparse
import changes
import crypto
import db
import poller
import snmp
import snmpwrite
import sshcli
from drivers import DRIVERS
from switchfix import (BASES, EXPECTED_PORTS, FREE_TEXT, HEX_WALKS, HOST, IF_ALIAS, IF_STACK, IF_TYPE, IFTYPE_SAMPLE, NAC, RECORDING,
                       ROW, VLAN_EGRESS, VLAN_NAME, VLAN_UNTAGGED, VMVLAN, VMVLAN_SAMPLE, W_CISCO, W_ODD, W_SAMPLE, WALK_BASES, FakeProcess,
                       edit_walks, hex_text, netsnmp_hex, random_procurve_switch, walk_answer, walk_rows)

DRIVER = DRIVERS["procurve"]


CFG_KEYS = ["hostname", "primary_vlan", "mgmt_vlan", "auth_active", "eap_radius", "login_radius", "addr_format", "trunks", "vlans",
            "voice_vlans", "radius", "snmpv3", "ports"]
PORT_KEYS = {"u", "t", "name", "en", "x", "m", "cl", "al", "xuv", "muv", "poe"}
RAW_KEYS = {"egress", "untagged", "pvid", "admin", "alias", "poe", "poe_unmapped", "port2bp", "bp2port", "ifindex", "unmanaged", "vmvlan"}
POE_BASES = {WALK_BASES[k] for k in ("poeAdmin", "poeStatus")}    # walked only for a change that touches PoE (R34, tests/test_poe.py)

def _variant(**edits) -> dict:
    return edit_walks(W_SAMPLE, **edits)


def _assert_same_switch_as_the_poller(W: dict, cfg: dict, raw: dict):
    """The oracle: poller._build on the very same rows (the walks read_cfg does not do are empty) must describe every port alike.
    Only for Q-BRIDGE reads: the poller knows nothing of vmVlan. The ports build_cfg lists as unmanaged, without u, are the ones
    the poller sees untagged in several VLANs, or untagged in one VLAN with a PVID that differs from it; everything else matches."""
    assert "vmVlan" not in W
    built = poller._build({k: W.get(k, []) for k in poller.O})
    assert list(cfg["ports"]) == [p["name"] for p in built["ports"]]    # the same ports, under the same names, in the same order
    assert list(cfg["vlans"].items()) == list(built["vlans"].items())

    def unmanaged(p):
        return len(p["untagged"]) > 1 or (len(p["untagged"]) == 1 and p["pvid"] not in ("", p["untagged"][0]))

    assert set(raw["unmanaged"]) == {p["name"] for p in built["ports"] if unmanaged(p)}
    for p in built["ports"]:
        n = p["name"]
        st = cfg["ports"][n]
        assert st["u"] == (None if unmanaged(p) or not p["untagged"] else p["untagged"][0]), n
        assert st["t"] == p["tagged"], n
        assert st["en"] is (p["admin"] == 1), n
        assert (raw["admin"][n] == 1) is (p["admin"] == 1), n
        assert st["name"] == p["alias"] == raw["alias"].get(n, ""), n
        assert raw["pvid"].get(n, "") == p["pvid"], n
        assert raw["ifindex"][n] == p["if"], n
        if n.startswith("Trk"):
            assert cfg["trunks"].get(n, []) == p["members"], n
        elif p["trunk"]:
            assert n in cfg["trunks"][p["trunk"]], n


# ── build_cfg: the semantics ─────────────────────────────────────────────────────────────────────────────────────────────────
def test_fixture_bases_are_what_the_poller_walks():
    """The fixture's OIDs are the poller's (poller._tbl strips exactly these bases), and the PortLists are the hex walks."""
    for key, base in BASES.items():
        assert poller.O[key] == base, key
    assert HEX_WALKS == {k for k in BASES if k in poller.HEX}


def test_build_cfg_vlans_and_trunks():
    cfg, _ = snmpwrite.build_cfg(W_SAMPLE)
    assert list(cfg["vlans"].items()) == [("1", "DEFAULT_VLAN"), ("20", "Clients"), ("30", "Voice"), ("99", "Guest")]
    assert cfg["trunks"] == {"Trk1": ["4", "5"]}


def test_build_cfg_ports():
    """Every port with u / t / name / en from its own index space; VLAN interfaces and the loopback are no ports."""
    cfg, _ = snmpwrite.build_cfg(W_SAMPLE)
    assert cfg["ports"] == EXPECTED_PORTS
    assert list(cfg["ports"]) == ["1", "2", "3", "4", "5", "6", "Trk1"]    # ifIndex order, like the poller


def test_build_cfg_has_the_shape_of_parse_config():
    """Same top-level keys as parse_config (in the same order), the per-port keys of _empty_port plus poe, safe defaults."""
    cfg, _ = snmpwrite.build_cfg(W_SAMPLE)
    assert list(cfg) == CFG_KEYS == list(cfgparse.parse_config(""))
    assert {k: cfg[k] for k in CFG_KEYS if k not in ("trunks", "vlans", "ports")} == {
        "hostname": "", "primary_vlan": "1", "mgmt_vlan": None, "auth_active": False, "eap_radius": False, "login_radius": False,
        "addr_format": None, "voice_vlans": [], "radius": {}, "snmpv3": None,
    }
    for name, st in cfg["ports"].items():
        assert set(st) == PORT_KEYS == set(cfgparse._empty_port()) | {"poe"}, name
        assert {k: st[k] for k in NAC} == NAC, name
        assert st["poe"] is None, name
    json.dumps(cfg)    # plain data, like a parsed running-config


def test_build_cfg_raw():
    """raw: the PortLists as the switch sent them (length kept), pvid via the effective bridge port, both index maps."""
    _, raw = snmpwrite.build_cfg(W_SAMPLE)
    assert set(raw) == RAW_KEYS
    assert raw["egress"] == {
        "1": bytes.fromhex("0A00000000000000"), "20": bytes.fromhex("6200000000000000"),
        "30": bytes.fromhex("6200000000000000"), "99": bytes.fromhex("8200000000000000"),
    }
    assert raw["untagged"] == {
        "1": bytes.fromhex("0A00000000000000"), "20": bytes.fromhex("2000000000000000"),
        "30": bytes.fromhex("0000000000000000"), "99": bytes.fromhex("8000000000000000"),
    }
    # dot1qPvid is indexed by bridge port: port 1 is bridge port 3 (PVID 20), not bridge port 1 (that is port 2, PVID 99)
    assert raw["pvid"] == {"1": "20", "2": "99", "3": "1", "4": "1", "5": "1", "6": "1", "Trk1": "1"}
    assert raw["admin"] == {"1": 1, "2": 1, "3": 1, "4": 1, "5": 1, "6": 2, "Trk1": 1}
    assert raw["alias"] == {"1": "Platz-107", "2": "", "3": "", "4": "", "5": "", "6": "unused", "Trk1": ""}
    assert raw["poe"] == {} and raw["poe_unmapped"] == []    # no PoE rows: no PoE (tests/test_poe.py)
    # the trunk members' effective bridge port is Trk1's (7); they own none themselves, so bp2port has no entry for them
    assert raw["port2bp"] == {"1": 3, "2": 1, "3": 2, "4": 7, "5": 7, "6": 5, "Trk1": 7}
    assert raw["bp2port"] == {1: "2", 2: "3", 3: "1", 5: "6", 7: "Trk1"}
    assert raw["ifindex"] == {"1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "Trk1": 289}
    assert raw["unmanaged"] == {} and raw["vmvlan"] == {}    # always there, empty here: no hybrid port, no vmVlan walk


def test_build_cfg_is_pure():
    """build_cfg leaves its input alone, takes the poller's full W as well (it reads only its walks) and gives fresh objects."""
    W = copy.deepcopy(W_SAMPLE)
    first = snmpwrite.build_cfg(W)
    assert W == W_SAMPLE
    full = {**{k: [] for k in poller.O}, **W}
    assert snmpwrite.build_cfg(full) == first
    first[0]["ports"]["1"]["t"].append("99")
    first[1]["egress"]["1"] = b""
    cfg, raw = snmpwrite.build_cfg(W)
    assert cfg["ports"]["1"]["t"] == ["30"] and raw["egress"]["1"] == bytes.fromhex("0A00000000000000")


def test_cfg_feeds_plan_ports_and_verify_ports():
    """The consumers run on the SNMP cfg without a KeyError. NAC is not readable over SNMP, so a RADIUS request is blocked
    switch-wide (the readiness defaults say: not prepared) instead of being planned on a guess."""
    cfg, _ = snmpwrite.build_cfg(W_SAMPLE)
    inv = {"ports": {n: {"n": n, "tr": "Trk1" if n in ("4", "5") else "", "l": [], "o": False} for n in cfg["ports"]},
           "uplinks": set()}
    plan = changes.plan_ports("K.15.99.0001", inv, cfg, {"ports": ["1", "6"], "set": {"untagged": "99", "tagged_add": ["20"]}})
    assert plan["blocked"] == []
    assert plan["desired"] == {"1": {"u": "99", "t": ["20", "30"]}, "6": {"u": "99", "t": ["20"]}}
    assert plan["before"] == {"1": {"u": "20", "t": ["30"]}, "6": {"u": "1", "t": []}}
    assert changes.verify_ports(cfg, plan["before"]) == []
    assert len(changes.verify_ports(cfg, plan["desired"])) == 4
    nac = changes.plan_ports("K.15.99.0001", inv, cfg, {"ports": ["2"], "set": {"status": "radius"}})
    assert nac["blocked"] == [{"port": "*", "reason": "Switch ist nicht für RADIUS vorbereitet: "
                                                      "RADIUS-Server, 802.1X-Methode eap-radius, 802.1X global aktiv"}]


# ── build_cfg against the display poller ─────────────────────────────────────────────────────────────────────────────────────
def test_build_cfg_agrees_with_the_poller():
    cfg, raw = snmpwrite.build_cfg(W_SAMPLE)
    _assert_same_switch_as_the_poller(W_SAMPLE, cfg, raw)


def test_build_cfg_on_odd_agent_rows():
    cfg, raw = snmpwrite.build_cfg(W_ODD)
    assert cfg["ports"] == {
        "A1": {"u": "7", "t": ["5"], "name": "uplink-core", "en": True, **NAC, "poe": None},
        "A2": {"u": None, "t": ["5", "7"], "name": "", "en": True, **NAC, "poe": None},    # Trk2's bit, not its own bp 11
        "A3": {"u": None, "t": [], "name": "", "en": False, **NAC, "poe": None},          # no bridge port, no ifAlias row
        "A4": {"u": None, "t": ["5", "7"], "name": "", "en": True, **NAC, "poe": None},
        "Trk2": {"u": None, "t": ["5", "7"], "name": "to-core", "en": True, **NAC, "poe": None},
        "Trk3": {"u": None, "t": [], "name": "", "en": True, **NAC, "poe": None},           # an empty trunk is still a port
        "A99": {"u": "5", "t": [], "name": "edge", "en": True, **NAC, "poe": None},       # ifIndex 999 is a port, 1000 is not
    }
    assert cfg["trunks"] == {"Trk2": ["A2", "A4"]}                             # Trk3 has no members, "291.0" is not one
    assert cfg["vlans"] == {"5": "Servers", "7": ""}
    assert raw["port2bp"] == {"A1": 10, "A2": 12, "A4": 12, "Trk2": 12, "A99": 13}
    assert raw["bp2port"] == {10: "A1", 11: "A2", 12: "Trk2", 13: "A99"}      # bp 14 belongs to a dropped interface
    assert raw["pvid"] == {"A1": "7", "A2": "1", "A4": "1", "Trk2": "1"}       # A3 has no bridge port, bp 13 no PVID row
    assert raw["alias"] == {"A1": "uplink-core", "A2": "", "Trk2": "to-core", "A99": "edge"}
    assert raw["ifindex"] == {"A1": 1, "A2": 2, "A3": 3, "A4": 4, "Trk2": 290, "Trk3": 291, "A99": 999}
    assert raw["egress"]["7"] == bytes.fromhex("007000000001")               # the bit nobody owns is kept as read
    _assert_same_switch_as_the_poller(W_ODD, cfg, raw)


def test_build_cfg_on_random_switches():
    """build_cfg on 400 random switches against two oracles: the generator's own truth (it shares nothing with build_cfg: no
    bitmap_ports, no copy of the port loop) and the display poller (which sees the switch through the same rows)."""
    rng = random.Random(20261104)
    for case in range(400):
        W, truth = random_procurve_switch(rng)
        cfg, raw = snmpwrite.build_cfg(W)
        assert list(cfg["ports"]) == list(truth["ports"]), case
        for n, want in truth["ports"].items():
            assert {k: cfg["ports"][n][k] for k in ("u", "t", "name", "en")} == {k: want[k] for k in ("u", "t", "name", "en")}, (case, n)
        assert raw == truth["raw"], case
        assert cfg["trunks"] == truth["trunks"], case
        assert list(cfg["vlans"].items()) == list(truth["vlans"].items()), case
        _assert_same_switch_as_the_poller(W, cfg, raw)


# ── build_cfg fails closed ───────────────────────────────────────────────────────────────────────────────────────────────────
def test_a_port_name_twice_fails_closed():
    """Two interfaces named "1": a write to port 1 could hit either of them."""
    with pytest.raises(snmp.SnmpError, match=r"Portname 1 kommt doppelt vor \(ifIndex 1 und 3\)"):
        snmpwrite.build_cfg(_variant(ifName={"3": "1"}))


HYBRID = "ungetaggt in mehreren VLANs (1, 20): Hybrid-/General-Port, per SNMP nicht verwaltbar"


def test_a_hybrid_port_is_unmanaged_not_fatal():
    """Port 3 (bridge port 2 = 0x40) untagged in VLAN 1 and 20, tagged in 30: cfg has room for one u only, so the port is listed as
    unmanaged with the reason (the write path refuses it) and has no u; it keeps its tagged VLANs and raw keeps its facts. The
    switch as a whole stays readable: every other port reads exactly as before."""
    W = _variant(vlanEgress={"1": "4A 00 00 00 00 00 00 00"},
                 vlanUntagged={"1": "4A 00 00 00 00 00 00 00", "20": "60 00 00 00 00 00 00 00"})
    cfg, raw = snmpwrite.build_cfg(W)
    assert raw["unmanaged"] == {"3": HYBRID}
    assert cfg["ports"]["3"] == {"u": None, "t": ["30"], "name": "", "en": True, **NAC, "poe": None}
    assert {n: st for n, st in cfg["ports"].items() if n != "3"} == {n: st for n, st in EXPECTED_PORTS.items() if n != "3"}
    assert raw["pvid"]["3"] == "1" and raw["port2bp"]["3"] == 2
    _assert_same_switch_as_the_poller(W, cfg, raw)


def test_trunk_members_of_a_hybrid_trunk_are_unmanaged_too():
    """A member's membership is its trunk's (bridge port 7 = 0x02), so a hybrid trunk takes its members along."""
    W = _variant(vlanUntagged={"99": "82 00 00 00 00 00 00 00"})    # Trk1 now untagged in VLAN 1 and 99
    _, raw = snmpwrite.build_cfg(W)
    reason = "ungetaggt in mehreren VLANs (1, 99): Hybrid-/General-Port, per SNMP nicht verwaltbar"
    assert raw["unmanaged"] == {"4": reason, "5": reason, "Trk1": reason}


def test_a_port_whose_pvid_differs_from_its_untagged_vlan_is_unmanaged():
    """A general port: port 1 egresses untagged in VLAN 20, but its PVID (bridge port 3) says 1, so untagged ingress lands in VLAN 1.
    cfg cannot say that with one u; the port is unmanaged until it is cleaned up on the switch. The tagged-only port 3 (no
    untagged VLAN, PVID 1 as ProCurve reports it) is not affected, nor is any other port."""
    W = _variant(pvid={"3": "1"})
    cfg, raw = snmpwrite.build_cfg(W)
    assert raw["unmanaged"] == {"1": "PVID 1 weicht vom ungetaggten VLAN 20 ab (Fehlkonfiguration oder dynamisch per 802.1X/RADIUS "
                                     "zugewiesen) – per SNMP nicht verwaltbar"}
    assert cfg["ports"]["1"] == {**EXPECTED_PORTS["1"], "u": None}
    assert {n: st for n, st in cfg["ports"].items() if n != "1"} == {n: st for n, st in EXPECTED_PORTS.items() if n != "1"}
    assert raw["pvid"]["1"] == "1" and raw["pvid"]["3"] == "1"
    _assert_same_switch_as_the_poller(W, cfg, raw)


def test_a_trunk_with_a_differing_pvid_takes_its_members_along():
    W = _variant(pvid={"7": "99"})    # Trk1: untagged 1, PVID 99
    _, raw = snmpwrite.build_cfg(W)
    reason = ("PVID 99 weicht vom ungetaggten VLAN 1 ab (Fehlkonfiguration oder dynamisch per 802.1X/RADIUS zugewiesen) – per SNMP "
              "nicht verwaltbar")
    assert raw["unmanaged"] == {"4": reason, "5": reason, "Trk1": reason}


def test_a_port_without_a_pvid_row_is_not_judged_by_it():
    _, raw = snmpwrite.build_cfg(_variant(pvid={"3": None}))    # port 1 untagged in 20, no PVID row: nothing to compare
    assert raw["unmanaged"] == {} and "1" not in raw["pvid"]


@pytest.mark.parametrize("edits", [
    {"bp2if": {"3": None, "3.0": "1"}},                                                      # a bridge-port index "3.0"
    {"vlanName": {"x": "Gast"}, "vlanEgress": {"x": "00"}, "vlanUntagged": {"x": "00"}},     # a VLAN index "x"
], ids=["bridge-port", "vlan"])
def test_a_malformed_index_fails_closed_as_snmp_error(edits):
    """A malformed index surfaces as SnmpError with context (what callers of read_cfg handle), never as a bare ValueError."""
    with pytest.raises(snmp.SnmpError, match=r"^Unerwartete SNMP-Daten \(Index oder Wert nicht lesbar\): .*'(3\.0|x)'"):
        snmpwrite.build_cfg(_variant(**edits))


def test_a_programming_error_is_not_reported_as_bad_switch_data(monkeypatch):
    """Only a ValueError (an index or value that int() cannot read) means bad switch data. Every lookup of switch data in build_cfg
    is guarded, so a KeyError can only be a bug in the code: it surfaces as itself, not disguised as an unreadable switch."""
    def broken():
        raise KeyError("u")

    monkeypatch.setattr(cfgparse, "_empty_port", broken)
    with pytest.raises(KeyError, match="'u'"):
        snmpwrite.build_cfg(W_SAMPLE)


@pytest.mark.parametrize("walk", ["vlanName", "vlanEgress", "vlanUntagged"])
def test_an_incomplete_vlan_table_fails_closed(walk):
    """Name, egress and untagged list are columns of one dot1qVlanStaticEntry: a VLAN in one walk but not the others means a walk
    stopped early (a port untagged in VLAN 99 would look like a port in no untagged VLAN)."""
    with pytest.raises(snmp.SnmpError, match=r"VLAN-Tabelle unvollständig gelesen.*\(VLAN 99\)"):
        snmpwrite.build_cfg(_variant(**{walk: {"99": None}}))


def test_a_vlan_table_read_consistently_is_accepted():
    cfg, raw = snmpwrite.build_cfg(_variant(vlanName={"99": None}, vlanEgress={"99": None}, vlanUntagged={"99": None}))
    assert list(cfg["vlans"]) == ["1", "20", "30"] and set(raw["egress"]) == set(raw["untagged"]) == {"1", "20", "30"}
    assert cfg["ports"]["2"]["u"] is None


@pytest.mark.parametrize("value", [None, "", "down"])
def test_a_port_without_readable_admin_status_fails_closed(value):
    """Without ifAdminStatus the port would read as disabled: `before` (the revert source) would then switch an up port off."""
    with pytest.raises(snmp.SnmpError, match=r"Port 6: ifAdminStatus fehlt oder ist unlesbar"):
        snmpwrite.build_cfg(_variant(ifAdmin={"6": value}))


def test_admin_status_is_only_required_for_ports():
    cfg, _ = snmpwrite.build_cfg(_variant(ifAdmin={"1001": None, "4097": "garbage"}))    # VLAN interface and loopback: no ports
    assert cfg["ports"] == EXPECTED_PORTS


# ── cisco_vmps: a port with a vmVlan row is an access port ──────────────────────────────────────────────────────────────────────

CISCO = {"vmvlan_base": VMVLAN}    # build_cfg filters the vmVlan rows by the base they were walked from, like every other walk


def test_vmvlan_base_is_the_cisco_drivers_oid():
    assert DRIVERS["cisco"].vlan_strategy == "cisco_vmps" and DRIVERS["cisco"].oids["vmvlan"] == VMVLAN


def test_vmvlan_decides_the_access_vlan():
    cfg, raw = snmpwrite.build_cfg(W_CISCO, **CISCO)
    assert cfg["ports"] == {
        "Gi1/0/1": {"u": "10", "t": [], "name": "Drucker", "en": True, **NAC, "poe": None},
        "Gi1/0/2": {"u": "10", "t": [], "name": "", "en": True, **NAC, "poe": None},
        "Gi1/0/3": {"u": "1", "t": ["10", "20"], "name": "uplink", "en": True, **NAC, "poe": None},
        "Gi1/0/4": {"u": None, "t": [], "name": "", "en": False, **NAC, "poe": None},
    }
    assert raw["vmvlan"] == {"Gi1/0/1": "10", "Gi1/0/2": "10", "Gi1/0/4": "0"}    # as read, per port; the trunk port has none
    # Gi1/0/1 has PVID 1 next to vmVlan 10: a single disagreement goes to vmVlan, the PVID is not judged on a vmVlan port
    assert raw["pvid"]["Gi1/0/1"] == "1" and raw["unmanaged"] == {}


def test_vmvlan_rows_only_change_u_and_t_of_their_ports():
    """Without the vmVlan rows build_cfg is the plain Q-BRIDGE read (and agrees with the poller). With them only the ports that have
    a row differ: u from vmVlan and no tagged VLANs; plus raw["vmvlan"]. Everything else stays the Q-BRIDGE view."""
    qbridge = {k: rows for k, rows in W_CISCO.items() if k != "vmVlan"}
    cfg_q, raw_q = snmpwrite.build_cfg(qbridge)
    _assert_same_switch_as_the_poller(qbridge, cfg_q, raw_q)
    assert {n: (st["u"], st["t"]) for n, st in cfg_q["ports"].items()} == {
        "Gi1/0/1": ("1", ["10"]), "Gi1/0/2": ("10", []), "Gi1/0/3": ("1", ["10", "20"]), "Gi1/0/4": ("1", [])}
    cfg, raw = snmpwrite.build_cfg(W_CISCO, **CISCO)
    assert {k: v for k, v in cfg.items() if k != "ports"} == {k: v for k, v in cfg_q.items() if k != "ports"}
    for n, st in cfg["ports"].items():
        if n in raw["vmvlan"]:
            assert st["t"] == [] and {**st, "u": "-", "t": "-"} == {**cfg_q["ports"][n], "u": "-", "t": "-"}, n
        else:
            assert st == cfg_q["ports"][n], n
    assert {k: v for k, v in raw.items() if k != "vmvlan"} == {k: v for k, v in raw_q.items() if k != "vmvlan"}
    assert raw_q["vmvlan"] == {}


def test_a_hybrid_port_stays_unmanaged_even_with_a_vmvlan_row():
    """Q-BRIDGE has Gi1/0/2 untagged in VLAN 10 and 20, vmVlan says 10: the two views disagree about what the port is, so it stays
    unmanaged without u (vmVlan does not overrule that); raw still shows what vmVlan said."""
    cfg, raw = snmpwrite.build_cfg(edit_walks(W_CISCO, vlanUntagged={"20": "00 40"}, vlanEgress={"20": "00 60"}), **CISCO)
    assert raw["unmanaged"] == {"Gi1/0/2": "ungetaggt in mehreren VLANs (10, 20): Hybrid-/General-Port, per SNMP nicht verwaltbar"}
    assert cfg["ports"]["Gi1/0/2"]["u"] is None and cfg["ports"]["Gi1/0/2"]["t"] == [] and raw["vmvlan"]["Gi1/0/2"] == "10"


def test_a_pvid_mismatch_on_a_port_without_vmvlan_row_still_counts():
    """The trunk port Gi1/0/3 (no vmVlan row) is a Q-BRIDGE port: native VLAN 1 with PVID 20 makes it unmanaged."""
    _, raw = snmpwrite.build_cfg(edit_walks(W_CISCO, pvid={"11": "20"}), **CISCO)
    assert raw["unmanaged"] == {"Gi1/0/3": "PVID 20 weicht vom ungetaggten VLAN 1 ab (Fehlkonfiguration oder dynamisch per "
                                           "802.1X/RADIUS zugewiesen) – per SNMP nicht verwaltbar"}


@pytest.mark.parametrize("value", ["", "zehn", "-1"])
def test_an_unreadable_vmvlan_fails_closed(value):
    """The access VLAN of a cisco_vmps port is not readable: like a missing ifAdminStatus, no cfg for this switch."""
    with pytest.raises(snmp.SnmpError, match=r"^Port Gi1/0/1: vmVlan unlesbar"):
        snmpwrite.build_cfg(edit_walks(W_CISCO, vmVlan={"1": value}), **CISCO)


def test_vmvlan_rows_of_other_interfaces_are_ignored():
    """vmVlan rows of interfaces that are no port here change nothing, not even an unreadable value: ifIndex 1005 is in ifName but
    dropped by the port filter, 10101 is not in ifName at all."""
    cfg, raw = snmpwrite.build_cfg(edit_walks(W_CISCO, ifName={"1005": "Vlan5"}, vmVlan={"1005": "abc", "10101": "20"}), **CISCO)
    assert (cfg, raw) == snmpwrite.build_cfg(W_CISCO, **CISCO)


def test_vmvlan_rows_count_only_under_their_base():
    """Like every other walk, vmVlan rows are taken only under the OID they were walked from: a row of another column of the same
    table (vmPortStatus of ifIndex 1) is not read as an access VLAN."""
    W = {**W_CISCO, "vmVlan": W_CISCO["vmVlan"] + [(f"{VMVLAN.rsplit('.', 1)[0]}.3.1", "2")]}
    assert snmpwrite.build_cfg(W, **CISCO) == snmpwrite.build_cfg(W_CISCO, **CISCO)


def test_a_vmvlan_base_on_the_table_entry_fails_closed():
    """A driver whose vmvlan OID pointed at the table entry instead of the vmVlan column would walk every column of the table; under
    that base the index is column.ifIndex, never a plain ifIndex, so the read refuses instead of mixing the columns up."""
    entry = VMVLAN.rsplit(".", 1)[0]
    W = {**W_CISCO, "vmVlan": walk_rows(entry, {"1.1": "1", "2.1": "10", "3.1": "2"})}    # vmVlanType, vmVlan, vmPortStatus of ifIndex 1
    with pytest.raises(snmp.SnmpError, match=r"^vmVlan: Index 1\.1 ist kein ifIndex"):
        snmpwrite.build_cfg(W, vmvlan_base=entry)


def test_vmvlan_rows_need_their_base():
    with pytest.raises(TypeError, match="vmvlan_base"):
        snmpwrite.build_cfg(W_CISCO)


# ── read_cfg: the live read ──────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def agent(monkeypatch):
    """Replace snmp.walk by a fake agent that answers from RECORDING by base OID and records every call."""
    calls = []

    async def fake_walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        calls.append({"host": host, "cred": cred, "oid": oid, "hex": hex_values, "strict": strict})
        assert oid in RECORDING, f"read_cfg walked an OID the agent does not serve: {oid}"
        return walk_answer(RECORDING[oid], oid, hex_values)

    monkeypatch.setattr(snmp, "walk", fake_walk)
    return calls


async def _switch_row(**cols):
    """A switches row as the app hands it over (SELECT * after the migration, an aiosqlite.Row), from an in-memory database."""
    async with aiosqlite.connect(":memory:") as conn:
        conn.row_factory = aiosqlite.Row
        await conn.executescript(db.SCHEMA)
        await db.migrate(conn)
        await conn.execute(f"INSERT INTO switches ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(cols.values()))
        async with conn.execute("SELECT * FROM switches") as cur:
            return await cur.fetchone()


async def test_read_cfg_walks_live_with_the_read_identity(monkeypatch, agent):
    """Nine walks (the PortLists and, since R18, the free text ifAlias / vlanName in hex), all strict, at the switch's host, all
    with the READ identity, never the RW one; the result is build_cfg of what the agent answered (the text, decoded), with the
    polled sys_name as hostname. No PoE walk: the PoE tables are read only for a change that touches PoE (R34)."""
    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))
    row = await _switch_row(name="SW-EK-01", host=HOST, sys_name="SW-EK-01", driver="procurve", snmp_version="2c",
                            snmp_community=crypto.encrypt("ro-s3cret"), snmp_write=1, snmp_rw_community=crypto.encrypt("rw-s3cret"))

    cfg, raw = await snmpwrite.read_cfg(row, DRIVER)

    want_cfg, want_raw = snmpwrite.build_cfg(W_SAMPLE)
    assert cfg == {**want_cfg, "hostname": "SW-EK-01"}
    assert raw == want_raw
    assert len(agent) == len(BASES)
    assert {c["oid"]: c["hex"] for c in agent} == {base: key in HEX_WALKS | FREE_TEXT for key, base in BASES.items()}
    for c in agent:
        assert c["strict"] is True    # a walk cut short must be an error, not a shorter table
        assert c["host"] == HOST
        assert c["cred"] == poller.creds_of(row)
        assert c["cred"]["snmp_version"] == "2c" and c["cred"]["snmp_community"] == "ro-s3cret"
    assert "rw-s3cret" not in repr(agent)


@pytest.mark.parametrize("name", list(DRIVERS))
async def test_read_cfg_walks_vmvlan_only_for_cisco_vmps(agent, name):
    """Every driver reads the nine Q-BRIDGE / IF-MIB walks. Every driver but procurve also walks ifType (it selects its ports by it,
    see tests/test_port_discovery.py), and a cisco_vmps driver its vmVlan OID; both strict, not hex. No driver walks PoE for a change
    that does not touch it (R34; with_poe in tests/test_poe.py). The result is build_cfg for that driver on what the agent answered,
    with the vmVlan rows under their base: ports 1 and 6 are access ports in VLAN 99 and in none, untagged. On this ProCurve-shaped
    switch the ifType rule selects the same ports as the ProCurve rule."""
    driver = DRIVERS[name]
    cfg, raw = await snmpwrite.read_cfg(ROW, driver)

    walked = {base: key in HEX_WALKS | FREE_TEXT for key, base in BASES.items()}
    W, base = dict(W_SAMPLE), None
    if name != "procurve":
        walked[IF_TYPE] = False
        W["ifType"] = IFTYPE_SAMPLE
    if driver.vlan_strategy == "cisco_vmps":
        walked[VMVLAN] = False
        W["vmVlan"], base = VMVLAN_SAMPLE, VMVLAN
    assert len(agent) == len(walked)
    assert {c["oid"]: c["hex"] for c in agent} == walked
    assert all(c["strict"] is True for c in agent)
    want_cfg, want_raw = snmpwrite.build_cfg(W, name, vmvlan_base=base)
    assert (cfg, raw) == ({**want_cfg, "hostname": "SW-EK-01"}, want_raw)
    assert (want_cfg, want_raw) == snmpwrite.build_cfg(W, "procurve", vmvlan_base=base)
    if driver.vlan_strategy == "cisco_vmps":
        assert (cfg["ports"]["1"]["u"], cfg["ports"]["1"]["t"], cfg["ports"]["6"]["u"]) == ("99", [], None)
        assert raw["vmvlan"] == {"1": "99", "6": "0"}


@pytest.mark.parametrize("sys_name, hostname", [("SW-EK-01", "SW-EK-01"), (None, ""), ("", "")])
async def test_read_cfg_hostname_is_the_polled_sys_name(agent, sys_name, hostname):
    cfg, _ = await snmpwrite.read_cfg({**ROW, "sys_name": sys_name}, DRIVER)
    assert cfg["hostname"] == hostname


async def test_read_cfg_does_not_touch_the_database_or_take_a_lock(monkeypatch, agent):
    """No db() and no sqlite connection at all; and it completes while the caller holds both the poll lock and the change lock of
    the switch (run_change calls it inside sshcli.lock; an asyncio.Lock is not reentrant, taking either would hang)."""
    def no_database(*args, **kwargs):
        raise AssertionError("read_cfg must not open the database")

    monkeypatch.setattr(db, "db", no_database)
    monkeypatch.setattr(poller, "db", no_database)
    monkeypatch.setattr(aiosqlite, "connect", no_database)
    monkeypatch.setattr(poller, "_locks", {})
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    poll_lock = poller._locks.setdefault(ROW["id"], asyncio.Lock())

    async with poll_lock, sshcli.lock(ROW["id"]):
        cfg, raw = await asyncio.wait_for(snmpwrite.read_cfg(ROW, DRIVER), timeout=5)

    assert (cfg, raw) == ({**snmpwrite.build_cfg(W_SAMPLE)[0], "hostname": "SW-EK-01"}, snmpwrite.build_cfg(W_SAMPLE)[1])
    assert list(poller._locks) == [ROW["id"]]


@pytest.mark.parametrize("driver, failing", [("procurve", key) for key in BASES] + [("cisco", "ifType"), ("cisco", "vmVlan")])
async def test_read_cfg_fails_closed_when_one_walk_fails(monkeypatch, driver, failing):
    """Stricter than the display poller (which skips a failed walk): any failed walk raises that very error, and only once every
    other walk has finished, so nothing is still talking to the switch when read_cfg returns. For cisco the ifType and vmVlan walks
    too. (The PoE walks of a change that touches PoE: tests/test_poe.py.)"""
    err = snmp.SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
    finished = []

    async def fake_walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        if oid == WALK_BASES[failing]:
            raise err
        await asyncio.sleep(0.01)    # the healthy walks take longer than the failing one
        finished.append(oid)
        return walk_answer(RECORDING[oid], oid, hex_values)

    monkeypatch.setattr(snmp, "walk", fake_walk)
    with pytest.raises(snmp.SnmpError) as caught:
        await snmpwrite.read_cfg(ROW, DRIVERS[driver])
    assert caught.value is err
    walked = [*BASES.values()] + ([IF_TYPE, VMVLAN] if driver == "cisco" else [])
    assert sorted(finished) == sorted(base for base in walked if base != WALK_BASES[failing])


async def test_read_cfg_passes_other_walk_errors_through(monkeypatch):
    """Not only SnmpError: e.g. snmpbulkwalk missing on the host comes out unchanged as well."""
    err = FileNotFoundError(2, "No such file or directory", "snmpbulkwalk")

    async def fake_walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        if oid == VLAN_UNTAGGED:
            raise err
        return walk_answer(RECORDING[oid], oid, hex_values)

    monkeypatch.setattr(snmp, "walk", fake_walk)
    with pytest.raises(FileNotFoundError) as caught:
        await snmpwrite.read_cfg(ROW, DRIVER)
    assert caught.value is err


# ── read_cfg end to end: the real snmp.walk / _run / _parse, only the snmpbulkwalk processes faked (switchfix.FakeProcess) ─────────
def _as_printed(key: str, rows) -> str:
    """Walk rows as snmpbulkwalk prints them for read_cfg with -On -Oq: ifName in quotes, numbers bare; with -Ox the PortLists (hex
    in the fixture already) and the free text (R18: its UTF-8 bytes as hex pairs, 16 to a line)."""
    if key in FREE_TEXT:
        return "".join(f".{oid} {netsnmp_hex(val.encode())}\n" for oid, val in rows)
    quoted = key == "ifName"
    return "".join(f'.{oid} "{val}"\n' if quoted else f".{oid} {val}\n" for oid, val in rows)


@pytest.fixture
def net_snmp(monkeypatch):
    """snmpbulkwalk answers with W_SAMPLE as text, picked by the OID at the end of its argv. `net_snmp[oid] = (stdout, exit code)`
    changes one walk; a non-zero exit comes with a timeout message on stderr. The sample switch has no PoE: its PoE walks (only for a
    change that touches PoE, R34) find no row under the OID and print what net-snmp prints then (the GET on the OID itself), exit 0."""
    answers = {BASES[k]: (_as_printed(k, rows), 0) for k, rows in W_SAMPLE.items()}
    answers |= {base: (f".{base} No Such Object available on this agent at this OID\n", 0) for base in POE_BASES}

    async def fake_exec(*argv, **kwargs):
        out, rc = answers[argv[-1]]
        return FakeProcess(out.encode(), f"Timeout: No Response from {HOST}\n".encode() if rc else b"", rc)

    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", fake_exec)
    return answers


async def test_read_cfg_end_to_end_through_the_real_walk(net_snmp):
    cfg, raw = await snmpwrite.read_cfg(ROW, DRIVER)
    want_cfg, want_raw = snmpwrite.build_cfg(W_SAMPLE)
    assert (cfg, raw) == ({**want_cfg, "hostname": "SW-EK-01"}, want_raw)


async def test_read_cfg_end_to_end_reads_poe(net_snmp):
    """PoE through the real walk / _run / _parse (Task 12), read for a change that touches PoE (with_poe, R34): the two columns as
    net-snmp prints them (-Oe: the TruthValue and the status as numbers), ports 1-6 by their ifIndex (group 1); a PoE walk cut short
    (exit 2) fails that read, while a read without PoE never walks it and goes through."""
    poe_admin, poe_status = WALK_BASES["poeAdmin"], WALK_BASES["poeStatus"]
    net_snmp[poe_admin] = ("".join(f".{poe_admin}.1.{i} {'2' if i == 3 else '1'}\n" for i in range(1, 7)), 0)
    net_snmp[poe_status] = ("".join(f".{poe_status}.1.{i} {'3' if i == 1 else '2'}\n" for i in range(1, 7)), 0)
    cfg, raw = await snmpwrite.read_cfg(ROW, DRIVER, with_poe=True)
    assert {n: st["poe"] for n, st in cfg["ports"].items()} == {"1": True, "2": True, "3": False, "4": True, "5": True, "6": True,
                                                                 "Trk1": None}
    assert raw["poe"]["1"] == {"group": 1, "index": 1, "admin": 1, "status": 3} and raw["poe_unmapped"] == []
    text, _ = net_snmp[poe_status]
    net_snmp[poe_status] = ("".join(text.splitlines(keepends=True)[:3]), 2)
    with pytest.raises(snmp.SnmpError, match=f"^Timeout: No Response from {HOST}$"):
        await snmpwrite.read_cfg(ROW, DRIVER, with_poe=True)
    cfg, raw = await snmpwrite.read_cfg(ROW, DRIVER)
    assert raw["poe"] == {} and {st["poe"] for st in cfg["ports"].values()} == {None}


async def test_read_cfg_end_to_end_refuses_a_walk_cut_short(net_snmp):
    """ifStack stops after its first five rows (before Trk1's members) and snmpbulkwalk exits 2. Read leniently, ports 4 and 5 would
    turn into ports of their own without a bridge port; read strictly, the whole read fails."""
    text, _ = net_snmp[IF_STACK]
    net_snmp[IF_STACK] = ("".join(text.splitlines(keepends=True)[:5]), 2)
    with pytest.raises(snmp.SnmpError, match=f"^Timeout: No Response from {HOST}$"):
        await snmpwrite.read_cfg(ROW, DRIVER)


async def test_read_cfg_end_to_end_refuses_a_stray_line_in_a_portlist(net_snmp):
    """A line that is not hex behind the last egress PortList would turn into phantom bridge ports; the strict hex walk refuses it."""
    text, _ = net_snmp[VLAN_EGRESS]
    net_snmp[VLAN_EGRESS] = (text + "End of MIB\n", 0)
    with pytest.raises(snmp.SnmpError, match="Hex-Wert"):
        await snmpwrite.read_cfg(ROW, DRIVER)


@pytest.mark.parametrize("key", ["ifName", "ifAdmin", "bp2if", "pvid", "ifStack"])
async def test_read_cfg_end_to_end_refuses_a_stray_line_in_a_text_walk(net_snmp, key):
    """The same behind the last row of a text walk, a quoted string or a bare number: read leniently, the line would be glued to
    that value (an ifAlias a revert would write back, a bridge port or PVID that is no number any more); the strict text walk
    refuses it."""
    text, _ = net_snmp[BASES[key]]
    net_snmp[BASES[key]] = (text + "End of MIB\n", 0)
    with pytest.raises(snmp.SnmpError, match=r"^Unerwartete Zeile hinter dem Wert von "):
        await snmpwrite.read_cfg(ROW, DRIVER)


@pytest.mark.parametrize("key", sorted(FREE_TEXT))
async def test_read_cfg_end_to_end_refuses_a_stray_line_in_free_text(net_snmp, key):
    """The free text is a hex walk since R18: a line that is not hex behind the last name would end up in a name that a revert
    writes back; the strict hex walk refuses it, like behind a PortList."""
    text, _ = net_snmp[BASES[key]]
    net_snmp[BASES[key]] = (text + "End of MIB\n", 0)
    with pytest.raises(snmp.SnmpError, match=r"^Unerwartete Ausgabe in einem Hex-Wert"):
        await snmpwrite.read_cfg(ROW, DRIVER)


# ── R18: free text with umlauts ─────────────────────────────────────────────────────────────────────────────────────────────────
# Without MIBs (MIBS="") net-snmp prints an OCTET STRING that holds a byte it does not count as printable, such as each byte of an
# umlaut in UTF-8, as bare hex wrapped every 16 bytes, and a strict text walk refuses that continuation (R15): one "Büro" alias
# would make every SNMP change on the switch fail. So read_cfg walks ifAlias and vlanName with -Ox (always hex, under R14's rules)
# and build_cfg(text_hex=True) decodes them, UTF-8 first, latin-1 if that fails. The display poller still reads them as text.
ALIAS = "Büro Erdgeschoss"    # 17 bytes in UTF-8: a line of 16 bytes and a line of 1


def _free_text_as_hex(W: dict) -> dict:
    """W as read_cfg walks it: the free-text walks in hex (UTF-8), everything else as it is."""
    return {k: walk_answer(rows, BASES[k], True) for k, rows in W.items()}


def test_build_cfg_decodes_the_free_text_read_as_hex():
    """text_hex=True: ifAlias and vlanName are decoded, UTF-8 first; port 6's alias is latin-1 ("Büro" with the single byte FC, no
    valid UTF-8) and decodes through the fallback. The result is exactly build_cfg of the same switch read as text."""
    texts = edit_walks(W_SAMPLE, ifAlias={"1": ALIAS, "6": "Büro"}, vlanName={"99": "Gäste"})
    W = edit_walks(_free_text_as_hex(texts), ifAlias={"6": hex_text("Büro", "latin-1")})
    assert dict(W["ifAlias"])[f"{IF_ALIAS}.6"] == "42 FC 72 6F"
    cfg, raw = snmpwrite.build_cfg(W, text_hex=True)
    assert (cfg["ports"]["1"]["name"], cfg["ports"]["6"]["name"], cfg["vlans"]["99"]) == (ALIAS, "Büro", "Gäste")
    assert (cfg, raw) == snmpwrite.build_cfg(texts)


def test_build_cfg_leaves_the_free_text_alone_by_default():
    """Without text_hex (the display poller's rows) nothing is decoded, exactly as before: hex stays hex."""
    cfg, raw = snmpwrite.build_cfg(_free_text_as_hex(W_SAMPLE))
    assert cfg["ports"]["1"]["name"] == raw["alias"]["1"] == hex_text("Platz-107") == "50 6C 61 74 7A 2D 31 30 37"
    assert cfg["vlans"]["20"] == hex_text("Clients")


@pytest.mark.parametrize("value", ["52 6", "52 XY", "5 2"])
def test_free_text_that_is_no_hex_fails_closed(value):
    """Not whole bytes of hex (cannot come out of a strict hex walk, but build_cfg does not rely on that): SnmpError, no guess."""
    W = edit_walks(_free_text_as_hex(W_SAMPLE), ifAlias={"1": value})
    with pytest.raises(snmp.SnmpError, match=r"^Unerwartete SNMP-Daten \(Index oder Wert nicht lesbar\): ifAlias\.1 ist kein Hex-Text"):
        snmpwrite.build_cfg(W, text_hex=True)


async def test_read_cfg_reads_umlauts_through_the_real_walk(net_snmp):
    """End to end, the real walk / _run / _parse: port 1's 17-byte alias comes as hex over two lines, port 6's alias is latin-1,
    VLAN 99 is called "Gäste". read_cfg reads all of it, decoded, and the rest of the switch as before."""
    texts = edit_walks(W_SAMPLE, ifAlias={"1": ALIAS}, vlanName={"99": "Gäste"})
    printed = {oid: value.encode() for oid, value in texts["ifAlias"]} | {f"{IF_ALIAS}.6": "Büro".encode("latin-1")}
    net_snmp[IF_ALIAS] = ("".join(f".{oid} {netsnmp_hex(data)}\n" for oid, data in printed.items()), 0)
    net_snmp[VLAN_NAME] = (_as_printed("vlanName", texts["vlanName"]), 0)
    assert f".{IF_ALIAS}.1 42 C3 BC 72 6F 20 45 72 64 67 65 73 63 68 6F 73 \n73 \n" in net_snmp[IF_ALIAS][0]    # wrapped as net-snmp does

    cfg, raw = await snmpwrite.read_cfg(ROW, DRIVER)

    assert cfg["ports"]["1"]["name"] == raw["alias"]["1"] == ALIAS
    assert cfg["ports"]["6"]["name"] == raw["alias"]["6"] == "Büro"
    assert cfg["vlans"]["99"] == "Gäste"
    want_cfg, want_raw = snmpwrite.build_cfg(edit_walks(texts, ifAlias={"6": "Büro"}))
    assert (cfg, raw) == ({**want_cfg, "hostname": "SW-EK-01"}, want_raw)
