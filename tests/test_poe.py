"""Task 12: PoE on / off over SNMP (pethPsePortAdminEnable, POWER-ETHERNET-MIB / RFC 3621) end to end, and the PoE state and power per
port for the display.

A PoE SET cuts or restores the power of a phone, an access point or a camera on a live switch, and a SET on the wrong PoE entry powers
off another device. RFC 3621 indexes a PoE entry by <pethPsePortGroupIndex>.<pethPsePortIndex> and does not relate that to any
ifIndex. So what these tests pin hardest is poller.poe_ports, the one mapping from PoE entries to ports, shared by the display poller
(poller._build) and the write path (snmpwrite.build_cfg / read_cfg). It fails closed: an entry it cannot map with certainty belongs to
no port, and a port without a mapped entry has no PoE: no state on display, and every PoE write is refused with the reason
(snmpwrite.snmp_block_reason).
  * driver.poe_index "ifindex" (procurve only, R35; HP uses the ifIndex as the PoE port index): group 1 and pethPsePortIndex = the
    ifIndex of a physical port. An entry of another group (a stack member, a module) belongs to no port. If an entry of group 1 points
    at no physical port (no interface, a VLAN interface, a trunk), the assumption does not hold on this switch (port numbers instead of
    ifIndexes, say) and NO entry is mapped.
  * "cisco_entity" (driver cisco): CISCO-POWER-ETHERNET-EXT-MIB cpeExtPsePortEntPhyIndex names the entry's port entity, ENTITY-MIB
    entAliasMappingIdentifier maps that to ifIndex.N. Missing, zero, not an ifIndex, several ifIndexes, no physical port: no port.
  * two entries on one port: neither counts.
  * every other driver has no snmp_poe: mikrotik (R31) and all the rest (R35: without a sourced mapping, an offset numbering could map
    every entry to SOME physical port, the wrong one, and the read-back would confirm it). No PoE walk, no PoE state, PoE refused.
Around it: the display poll (lenient, ports.poe_admin / poe_status / poe_power, mW from hpicfPoePethPsePortPower or
cpeExtPsePortPwrConsumption), the strict live read, only for a change that touches PoE (R34: read_cfg(with_poe=True); an absent PoE
table is no PoE, a present but inconsistent one fails closed, while a change without PoE never walks it), render_ops
(pethPsePortAdminEnable.<group>.<port> i 1 / 2), planning (PortChange.poe, needed_ops, the SSH branch never plans PoE), routing R30 (PoE
goes over SNMP, ProCurve included, or 422 with the reason), run_change verifying PoE on read-back and a revert that restores it.

No network, no switch: snmp.walk / snmp.set_vars answer from the simulated agent of tests/switchfix.py (store refuses what a switch
would refuse), the SSH side is a trap that must never be touched on these paths. Expected lines, varbinds and reasons are written out
by hand.
"""
import asyncio
import json
import random
import re
from collections import defaultdict

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

import cfgparse
import changes
import config
import crypto
import db
import drivers
import main
import poller
import snmp
import snmpwrite
import sshcli
from drivers import DRIVERS, Driver
from switchfix import (BASES, CATALYST_VMVLAN, CISCO_POE_ENTPHY, CISCO_POE_POWER, CISCO_POWER_CATALYST, ENT_ALIAS, HOST, HP_POE_POWER,
                       HP_POWER_SAMPLE, IF_ADMIN, IF_ALIAS, IF_INDEX, IF_TYPE, IFTYPE_SAMPLE, POE_ADMIN, POE_EXPECTED, POE_STATUS,
                       POE_WALKS, PVID, VLAN_EGRESS, VLAN_UNTAGGED, VMVLAN, W_CATALYST, W_CATALYST_POE, W_ODD, W_POE, W_SAMPLE,
                       WALK_BASES, agent, edit_walks, random_multivendor_switch, random_procurve_switch, store, walk_rows)

PROCURVE, CISCO, GENERIC, MIKROTIK = DRIVERS["procurve"], DRIVERS["cisco"], DRIVERS["generic"], DRIVERS["mikrotik"]
NO_POE_DRIVERS = [name for name in DRIVERS if name not in ("procurve", "cisco")]    # R31 (mikrotik), R35 (the rest)
FW = "WB.16.99.0001"
PAD = "00" * 7

# Reasons and messages, written out by hand.
NO_POE_AT_ALL = "hat kein PoE (der Switch meldet keine PoE-Ports)"
NO_POE = "hat kein PoE"
POE_TRUNK = "PoE nur an einzelnen Ports: nicht am Trunk und noch nicht an Trunk-Mitgliedern"
POE_OVER_SSH = "PoE geht nur per SNMP, nicht über die SSH-CLI"
DELIVERING = "Port 1: versorgt gerade ein Gerät mit Strom (PoE), es verliert die Stromversorgung"
MIKROTIK_NO_POE = "Treiber mikrotik kann PoE nicht per SNMP schreiben"
WRITE_DISABLED = "SNMP-Schreiben ist für diesen Switch nicht aktiviert"
NO_WRITE_CREDS = "Keine SNMP-Schreib-Zugangsdaten hinterlegt"
STALE = "Die Vorschau ist veraltet, bitte neu laden"
RADIUS_CLI = "Zustand „RADIUS“ geht nur mit SSH/ProCurve, nicht per SNMP"
MISMATCH = "Prüfung nach der Änderung passt nicht: "
UNREADABLE = "Unerwartete SNMP-Daten (Index oder Wert nicht lesbar): "


def unmappable(entries: str) -> str:
    return f"hat kein PoE, oder sein PoE-Eintrag lässt sich nicht sicher zuordnen (Einträge ohne Port: {entries})"


def needs_snmp(reason: str) -> str:
    return f"PoE erfordert SNMP-Schreibzugriff ({reason})"


def entry(g: int, i: int, admin: int, status: int) -> dict:
    """raw["poe"][port] of a read: the PoE entry <g>.<i> with what it says."""
    return {"group": g, "index": i, "admin": admin, "status": status}


# What build_cfg makes of the PoE entries of W_POE (tests/switchfix.py): ports 1-6 by their ifIndex, Trk1 none.
POE_RAW = {"1": entry(1, 1, 1, 3), "2": entry(1, 2, 1, 2), "3": entry(1, 3, 2, 1), "4": entry(1, 4, 1, 2), "5": entry(1, 5, 1, 2),
           "6": entry(1, 6, 1, 2)}
# The Catalyst with PoE as the cisco driver reads it (cisco_entity): Gi1/0/1-4 through their entities, Po1 none.
CATALYST_POE_RAW = {"Gi1/0/1": entry(1, 1, 1, 3), "Gi1/0/2": entry(1, 2, 2, 1), "Gi1/0/3": entry(1, 3, 1, 2), "Gi1/0/4": entry(1, 4, 1, 2)}


def read(W: dict, selection: str = "procurve", **kw) -> tuple[dict, dict]:
    """The switch W (walk rows, free text as text) as build_cfg reads it for the driver `selection`."""
    return snmpwrite.build_cfg(W, selection, vmvlan_base=VMVLAN if "vmVlan" in W else None, **kw)


def poe_of(cfg: dict) -> dict:
    return {n: st["poe"] for n, st in cfg["ports"].items()}


def tables(**cols) -> dict:
    """PoE tables as poller.poe_ports takes them (walk key -> {index: value}), every walk key missing here empty."""
    return {k: dict(v) for k, v in cols.items()}


def physical(*ifis: str) -> tuple[dict, list, dict]:
    """(ifname, ports, members) as poller.select_ports gives them for a switch whose ports are these ifIndexes, all physical (named
    "p<ifIndex>", no trunk), whatever the driver."""
    return {i: f"p{i}" for i in ifis}, list(ifis), {}


def display(W: dict, driver: str = "procurve") -> list[tuple]:
    """What the display poller stores per port, PoE columns only: (name, poe_admin, poe_status, poe_power)."""
    full = {k: W.get(k, []) for k in poller.O} | {k: W[k] for k in W if k not in poller.O}
    return [(p["name"], p["poe_admin"], p["poe_status"], p["poe_power"]) for p in poller._build(full, driver)["ports"]]


# ── The mapping: poller.poe_ports ────────────────────────────────────────────────────────────────────────────────────────────────
def test_poe_walks_per_driver():
    """What the poller and read_cfg walk for PoE, from the driver's OIDs (R4): the two RFC 3621 columns for the two drivers with
    snmp_poe, the entity mapping for cisco, the power column (display only); nothing for every other driver (R31, R35)."""
    std = {"poeAdmin": POE_ADMIN, "poeStatus": POE_STATUS}
    entity = {"poeEntPhy": CISCO_POE_ENTPHY, "entAlias": ENT_ALIAS}
    assert poller.poe_walks(PROCURVE) == std
    assert poller.poe_walks(PROCURVE, power=True) == {**std, "poePower": HP_POE_POWER}
    assert poller.poe_walks(CISCO) == {**std, **entity}
    assert poller.poe_walks(CISCO, power=True) == {**std, **entity, "poePower": CISCO_POE_POWER}
    for name in NO_POE_DRIVERS:
        assert poller.poe_walks(DRIVERS[name]) == poller.poe_walks(DRIVERS[name], power=True) == {}, name


def test_default_mapping_group_1_index_is_the_ifindex():
    """ProCurve, modular naming (W_ODD: A1 = ifIndex 1, A99 = ifIndex 999): entry 1.<n> belongs to the port with ifIndex n, whatever its
    name, and the result is keyed by ifIndex; admin / status / power come from the entry's own rows."""
    got, unmapped = poller.poe_ports(PROCURVE, tables(poeAdmin={"1.1": "1", "1.999": "2"}, poeStatus={"1.1": "3", "1.999": "1"},
                                                      poePower={"1.1": "4100", "1.999": "0"}), *physical("1", "2", "3", "4", "999"))
    assert got == {"1": {"group": 1, "index": 1, "admin": 1, "status": 3, "power": 4100},
                   "999": {"group": 1, "index": 999, "admin": 2, "status": 1, "power": 0}}
    assert unmapped == []
    cfg, raw = read({**W_ODD, "poeAdmin": walk_rows(POE_ADMIN, {"1.1": "1", "1.999": "2"}),
                     "poeStatus": walk_rows(POE_STATUS, {"1.1": "3", "1.999": "1"})})
    assert raw["poe"] == {"A1": entry(1, 1, 1, 3), "A99": entry(1, 999, 2, 1)}
    assert poe_of(cfg) == {"A1": True, "A2": None, "A3": None, "A4": None, "Trk2": None, "Trk3": None, "A99": False}


def test_poe_mapping_procurve():
    """The sample ProCurve (bridge ports permuted against the ifIndexes): every PoE port by its ifIndex, the trunk without PoE; the
    display shows the same, with the power of hpicfPoePethPsePortPower."""
    cfg, raw = read(W_POE)
    assert poe_of(cfg) == POE_EXPECTED
    assert raw["poe"] == POE_RAW and raw["poe_unmapped"] == []
    assert display({**W_POE, "poePower": HP_POWER_SAMPLE}) == [
        ("1", 1, 3, 5400), ("2", 1, 2, 0), ("3", 2, 1, 0), ("4", 1, 2, 0), ("5", 1, 2, 0), ("6", 1, 2, 0), ("Trk1", None, None, None)]


def test_another_group_is_unmappable():
    """A second stack member's (or module's) entries, group 2: no port of their own, and never port 1 / 2 by their index. Group 1 still
    maps."""
    W = edit_walks(W_POE, poeAdmin={"2.1": "2", "2.2": "2"}, poeStatus={"2.1": "1", "2.2": "1"})
    cfg, raw = read(W)
    assert raw["poe"] == POE_RAW and poe_of(cfg) == POE_EXPECTED    # port 1 is 1.1 (on), not 2.1 (off)
    assert raw["poe_unmapped"] == ["2.1", "2.2"]
    assert display(W)[:2] == [("1", 1, 3, None), ("2", 1, 2, None)]


@pytest.mark.parametrize("index", ["7", "289", "1001", "4097"], ids=["no-interface", "trunk", "vlan-interface", "loopback"])
def test_an_index_that_is_no_physical_port_voids_the_default(index):
    """Entry 1.<n> where n is the ifIndex of no physical port (nothing, Trk1, a VLAN interface, the loopback): the index is evidently not
    the ifIndex on this switch, so none of its entries is mapped, not even 1.1-1.6. Every port shows no PoE, every PoE write is refused
    with the unmapped entries."""
    W = edit_walks(W_POE, poeAdmin={f"1.{index}": "1"}, poeStatus={f"1.{index}": "2"})
    cfg, raw = read(W)
    assert raw["poe"] == {} and set(poe_of(cfg).values()) == {None}
    assert raw["poe_unmapped"] == ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6", f"1.{index}"]
    assert {p[1:] for p in display(W)} == {(None, None, None)}
    assert snmpwrite.snmp_block_reason(PROCURVE, cfg, raw, "1", {"poe": False}) == unmappable("1.1, 1.2, 1.3, 1.4, 1.5, ...")


def test_catalyst_numbering_is_unmappable_by_the_default():
    """Classic IOS numbers PoE entries by the port number on the stack member (1.1-1.4) while the ports have ifIndex 10101-10104;
    1.1 even is an ifIndex, of Vl1. The default mapping (ProCurve's "ifindex") maps none of them, never Vl1 or a wrong port; a generic
    driver does not even read them (R35)."""
    cols = {k: poller._tbl(rows, WALK_BASES[k]) for k, rows in W_CATALYST_POE.items() if k in POE_WALKS}
    assert poller.poe_ports(PROCURVE, cols, *physical("10101", "10102", "10103", "10104"), strict=True) == ({}, ["1.1", "1.2", "1.3", "1.4"])
    cfg, raw = read(W_CATALYST_POE, "generic")
    assert (raw["poe"], raw["poe_unmapped"]) == ({}, []) and set(poe_of(cfg).values()) == {None}
    assert {p[1:] for p in display(W_CATALYST_POE, "generic")} == {(None, None, None)}


def test_catalyst_cisco_entity_mapping():
    """The cisco driver maps through CISCO-POWER-ETHERNET-EXT-MIB and ENTITY-MIB: 1.n -> entPhysicalIndex -> ifIndex.10101+... The
    alias row of entity 1001 (Po1) belongs to no PoE entry and changes nothing. The display adds cpeExtPsePortPwrConsumption."""
    W = {**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}
    cfg, raw = read(W, "cisco")
    assert raw["poe"] == CATALYST_POE_RAW and raw["poe_unmapped"] == []
    assert poe_of(cfg) == {"Po1": None, "Gi1/0/1": True, "Gi1/0/2": False, "Gi1/0/3": True, "Gi1/0/4": True}
    assert display({**W, "poePower": CISCO_POWER_CATALYST}, "cisco") == [
        ("Po1", None, None, None), ("Gi1/0/1", 1, 3, 6200), ("Gi1/0/2", 2, 1, 0), ("Gi1/0/3", 1, 2, 0), ("Gi1/0/4", 1, 2, 0)]


@pytest.mark.parametrize("edits, mapped", [
    pytest.param({"poeEntPhy": {"1.2": "0"}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"], id="no-entity"),
    pytest.param({"poeEntPhy": {"1.2": "0"}, "entAlias": {"0.0": f".{IF_INDEX}.10102"}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"],
                 id="no-entity-even-with-an-alias-row-0"),
    pytest.param({"entAlias": {"1014.0": None}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"], id="no-alias"),
    pytest.param({"entAlias": {"1014.0": ".1.3.6.1.2.1.16.1.1.1.1.5"}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"], id="not-an-ifindex"),
    pytest.param({"entAlias": {"1014.0": ".0.0"}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"], id="null-pointer"),
    pytest.param({"entAlias": {"1014.0": f".{IF_INDEX}.5001"}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"], id="a-lag"),
    pytest.param({"entAlias": {"1014.0": f".{IF_INDEX}.10"}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"], id="an-svi"),
    pytest.param({"entAlias": {"1014.0": f".{IF_INDEX}.77"}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"], id="no-interface"),
    pytest.param({"entAlias": {"1014.3": f".{IF_INDEX}.10103"}}, ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"], id="two-ifindexes"),
    pytest.param({"entAlias": {"1014.0": f".{IF_INDEX}.10101"}}, ["Gi1/0/3", "Gi1/0/4"], id="two-entries-one-port"),
    pytest.param({"entAlias": {"1014.3": f".{IF_INDEX}.10102"}}, ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"], id="same-ifindex-twice"),
    pytest.param({"entAlias": {"1014.0": f"{IF_INDEX}.10102"}}, ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"], id="without-leading-dot"),
    # a row that points at no ifTable row is ignored: next to the entity's ifIndex row that one decides (as in RFC 6933's example)
    pytest.param({"entAlias": {"1014.3": ".1.3.6.1.2.1.16.1.1.1.1.5"}}, ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"],
                 id="a-non-iftable-row-next-to-the-iftable-row"),
])
def test_cisco_entity_mapping_fails_closed(edits, mapped):
    """Each way the entity chain can be incomplete or ambiguous leaves exactly the affected entry without a port (two entries claiming
    one port: both), and the rest mapped; the display maps the same. (An entry without its cpeExtPsePortEntPhyIndex row at all is an
    incomplete table, which the write path refuses as a whole, see below; the display then maps that entry to nothing.)"""
    W = edit_walks({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, **edits)
    cfg, raw = read(W, "cisco")
    assert list(raw["poe"]) == mapped
    assert raw["poe"] == {p: CATALYST_POE_RAW[p] for p in mapped}
    assert [n for n, on in poe_of(cfg).items() if on is not None] == mapped
    assert len(raw["poe_unmapped"]) == 4 - len(mapped)
    built = {p[0]: p[1:] for p in display(W, "cisco")}
    assert [n for n, (admin, _, _) in built.items() if admin is not None] == mapped


def test_display_of_an_entry_without_its_entity_row():
    W = edit_walks({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, poeEntPhy={"1.2": None})
    assert [p[0] for p in display(W, "cisco") if p[1] is not None] == ["Gi1/0/1", "Gi1/0/3", "Gi1/0/4"]


def test_cisco_entity_mapping_without_the_cisco_tables():
    """An IOS without cpeExtPsePortEntPhyIndex (or without ENTITY-MIB rows): no PoE entry can be mapped, no error."""
    for missing in ("poeEntPhy", "entAlias"):
        W = {k: v for k, v in {**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}.items() if k != missing}
        cfg, raw = read(W, "cisco")
        assert raw["poe"] == {} and raw["poe_unmapped"] == ["1.1", "1.2", "1.3", "1.4"], missing
        assert set(poe_of(cfg).values()) == {None}


def test_the_mapping_ignores_tables_of_another_strategy():
    """The default mapping never looks at Cisco's entity tables, the cisco driver never at the index alone: the entity rows of a
    ProCurve change nothing, and a Catalyst whose entries happen to carry the ifIndex as index stays unmapped without entity rows."""
    W = {**W_POE, "poeEntPhy": walk_rows(CISCO_POE_ENTPHY, {"1.1": "9"}), "entAlias": walk_rows(ENT_ALIAS, {"9.0": f".{IF_INDEX}.6"})}
    assert read(W)[1]["poe"] == POE_RAW
    by_ifindex = {"1.10101": "1", "1.10102": "2"}
    W = {**W_CATALYST, "vmVlan": CATALYST_VMVLAN, "poeAdmin": walk_rows(POE_ADMIN, by_ifindex),
         "poeStatus": walk_rows(POE_STATUS, dict.fromkeys(by_ifindex, "2"))}
    assert read(W, "cisco")[1]["poe"] == {}
    cols = {"poeAdmin": by_ifindex, "poeStatus": dict.fromkeys(by_ifindex, "2")}
    assert list(poller.poe_ports(PROCURVE, cols, *physical("10101", "10102", "10103", "10104"))[0]) == ["10101", "10102"]


@pytest.mark.parametrize("name", NO_POE_DRIVERS)
def test_a_driver_without_snmp_poe_has_no_poe(name):
    """R31 / R35: no PoE walks, so neither the display nor the write path sees PoE on such a switch, whatever its agent would answer
    (here the sample's entries, which ProCurve's mapping would take); a PoE write is refused up front with the driver's name."""
    W = {**W_POE, "ifType": IFTYPE_SAMPLE}
    cfg, raw = read(W, name)
    assert raw["poe"] == {} and raw["poe_unmapped"] == [] and set(poe_of(cfg).values()) == {None}
    assert {p[1:] for p in display({**W, "poePower": HP_POWER_SAMPLE}, name)} == {(None, None, None)}
    assert snmpwrite.snmp_block_reason(DRIVERS[name], cfg, raw, "1", {"poe": False}) == f"Treiber {name} kann PoE nicht per SNMP schreiben"
    assert main._snmp_unwritable({"snmp_write": 1}, DRIVERS[name], {"snmp_poe"}) == f"Treiber {name} kann PoE nicht per SNMP schreiben"


def test_an_unknown_mapping_strategy_maps_nothing():
    odd = Driver("odd", GENERIC.caps, "qbridge", dict(GENERIC.oids), "", poe_index="by-name")
    got, unmapped = poller.poe_ports(odd, tables(poeAdmin={"1.1": "1"}, poeStatus={"1.1": "2"}), *physical("1"))
    assert (got, unmapped) == ({}, ["1.1"])


def _random_poe(rng: random.Random, ifindexes: list[str]) -> tuple[dict, dict]:
    """Random PoE tables over a switch with these interface ifIndexes: entries mostly of group 1, now and then 2 or 3, their index
    mostly an ifIndex of the switch, now and then any number; plus cisco entity tables that map some entries to some ifIndexes (also to
    one twice, also through a second logical index, also to nothing). Returns (walk rows by walk key, the same as _tbl tables)."""
    entries = {}
    for _ in range(rng.randint(0, 8)):
        group = rng.choice((1, 1, 1, 1, 2, 3))
        index = rng.choice(ifindexes) if ifindexes and rng.random() < 0.8 else str(rng.randint(1, 60))
        entries[f"{group}.{index}"] = (rng.choice("12"), rng.choice("123456"))
    entity = {k: str(rng.choice((0, 1001, 1002, 1003, 1004, 1005))) for k in entries if rng.random() < 0.9}
    targets = ifindexes + [str(rng.randint(1, 60))]
    alias = {f"{e}.{rng.choice((0, 0, 0, 3))}": f".{IF_INDEX}.{rng.choice(targets)}" for e in (1001, 1002, 1003, 1004) if rng.random() < 0.9}
    cols = {"poeAdmin": {k: a for k, (a, _) in entries.items()}, "poeStatus": {k: s for k, (_, s) in entries.items()}}
    if len(entity) == len(entries) or rng.random() < 0.3:    # a complete cpeExt table, or (lenient only) any
        cols["poeEntPhy"] = entity
    cols["entAlias"] = alias
    bases = {"poeAdmin": POE_ADMIN, "poeStatus": POE_STATUS, "poeEntPhy": CISCO_POE_ENTPHY, "entAlias": ENT_ALIAS}
    return {k: walk_rows(bases[k], v) for k, v in cols.items()}, cols


def _expected_mapping(strategy: str, cols: dict, physical: set[str]) -> dict[str, str]:
    """The test's own reading of the mapping rules, written independently of poller.poe_ports: PoE entry -> ifIndex of its port."""
    entries = set(cols["poeAdmin"]) | set(cols["poeStatus"])
    target = {}
    if strategy == "ifindex":
        group1 = {k: k.split(".")[1] for k in entries if k.split(".")[0] == "1"}
        target = group1 if all(ifi in physical for ifi in group1.values()) else {}
    elif strategy == "cisco_entity":
        for k in entries:
            e = cols.get("poeEntPhy", {}).get(k)
            ifis = {v.split(".")[-1] for a, v in cols["entAlias"].items() if a.split(".")[0] == e and v.lstrip(".").startswith(IF_INDEX + ".")}
            if e not in (None, "0") and len(ifis) == 1 and ifis <= physical:
                target[k] = ifis.pop()
    taken = [ifi for ifi in target.values()]
    return {k: ifi for k, ifi in target.items() if taken.count(ifi) == 1}


def test_poe_mapping_properties_on_random_switches():
    """800 random switches (ProCurve, and other vendors read as cisco) with random PoE tables, through both mappings ("ifindex" and
    "cisco_entity"; the strategy does not care for the vendor, only for the tables, so each switch also runs through the other one under
    its own port rule, the driver's name). poe_ports gets the port selection as in production (poller.select_ports for that name); the
    oracle uses the generator's OWN physical ports. Whatever the tables say:
      * the mapping is exactly the test's own reading of the rules (_expected_mapping), so in particular a mapped entry belongs to a
        physical port (never a trunk, a VLAN interface, nothing), no port has two entries, no entry two ports, ifindex maps every entry
        of group 1 or none, cisco_entity never entity 0;
      * mapped and unmapped entries are disjoint and together all entries;
      * for the switch's own driver the display (lenient) and the write path (strict, when it does not refuse the read) see the same
        PoE on every port."""
    rng = random.Random(1212)
    seen = {"mapped": 0, "voided": 0, "entity": 0, "refused": 0}
    for case in range(800):
        if rng.random() < 0.5:
            W, truth = random_procurve_switch(rng)
            selection = "procurve"
            other = Driver("procurve", PROCURVE.caps, "qbridge", dict(PROCURVE.oids), "", poe_index="cisco_entity")
        else:
            W, truth = random_multivendor_switch(rng)
            selection = "cisco"
            other = Driver("cisco", CISCO.caps, "cisco_vmps", dict(CISCO.oids), "", poe_index="ifindex")
        truly_physical = set(truth["physical"])
        ifname = poller._tbl(W["ifName"], WALK_BASES["ifName"])
        ports, _, members = poller.select_ports(ifname, poller._tbl(W.get("ifType", []), IF_TYPE),
                                                poller._tbl(W["ifStack"], WALK_BASES["ifStack"]), selection)
        # half the time a clean switch whose PoE indexes are physical ports' ifIndexes, else any interface (or none) of the switch
        rows, cols = _random_poe(rng, truth["physical"] if rng.random() < 0.5 else [i for i in ifname if i.isdigit()])
        W = {**W, **rows}
        entries = set(cols["poeAdmin"])
        for driver in (DRIVERS[selection], other):
            found, unmapped = poller.poe_ports(driver, cols, ifname, ports, members)
            mapped = {f"{e['group']}.{e['index']}": ifi for ifi, e in found.items()}
            assert len(mapped) == len(found) and set(found) <= truly_physical, case
            assert mapped == _expected_mapping(driver.poe_index, cols, truly_physical), case
            assert not set(mapped) & set(unmapped) and set(mapped) | set(unmapped) == entries, case
            if driver.poe_index == "ifindex":
                seen["voided"] += any(k.startswith("1.") for k in entries) and not mapped
                seen["mapped"] += len(mapped)
            else:
                seen["entity"] += len(mapped)
        found, unmapped = poller.poe_ports(DRIVERS[selection], cols, ifname, ports, members)
        display_poe = {p["name"]: p["poe_admin"] for p in poller._build({k: W.get(k, []) for k in poller.O} | rows, selection)["ports"]}
        try:
            cfg, raw = snmpwrite.build_cfg(W, selection)
        except snmp.SnmpError:
            seen["refused"] += 1
            continue
        assert {n: (None if st["poe"] is None else 1 if st["poe"] else 2) for n, st in cfg["ports"].items()} == display_poe, case
        assert raw["poe_unmapped"] == unmapped, case
    assert seen["mapped"] > 300 and seen["voided"] > 20 and seen["entity"] > 50 and seen["refused"] > 5, seen


def test_display_mapping_is_lenient():
    """The display takes what it can read: an entry with only a status row (the admin walk failed) still shows its status, unreadable
    values show as None, a malformed index is skipped; the write path refuses the same rows (below)."""
    got, unmapped = poller.poe_ports(PROCURVE, tables(poeAdmin={"1.1": "1", "1.2": "x", "1.x": "1"}, poeStatus={"1.1": "3", "1.3": "2"},
                                                      poePower={"1.1": "-5", "1.2": "abc"}), *physical("1", "2", "3"))
    assert got == {"1": {"group": 1, "index": 1, "admin": 1, "status": 3, "power": None},
                   "2": {"group": 1, "index": 2, "admin": None, "status": None, "power": None},
                   "3": {"group": 1, "index": 3, "admin": None, "status": 2, "power": None}}
    assert unmapped == []


# ── The live read: strict ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_read_cfg_poe_absent_table():
    """A switch without PoE (both PoE walks without a row): every port poe None, no error, raw["poe"] empty."""
    cfg, raw = read({**W_SAMPLE, "poeAdmin": [], "poeStatus": []})
    assert set(poe_of(cfg).values()) == {None}
    assert (raw["poe"], raw["poe_unmapped"]) == ({}, [])
    assert read(W_SAMPLE) == read({**W_SAMPLE, "poeAdmin": [], "poeStatus": []})    # no PoE walk at all reads the same


@pytest.mark.parametrize("edits, message", [
    ({"poeStatus": {"1.6": None}}, r"^PoE-Tabelle unvollständig gelesen: Admin- und Status-Spalte passen nicht zusammen \(Eintrag 1\.6\)$"),
    ({"poeAdmin": {"1.2": None, "1.4": None}},
     r"^PoE-Tabelle unvollständig gelesen: Admin- und Status-Spalte passen nicht zusammen \(Eintrag 1\.2, 1\.4\)$"),
    ({"poeAdmin": {"1.7": "1"}}, r"^PoE-Tabelle unvollständig gelesen: Admin- und Status-Spalte passen nicht zusammen \(Eintrag 1\.7\)$"),
    ({"poeAdmin": {"1.3": "3"}}, "^" + re.escape(UNREADABLE) + r"pethPsePortAdminEnable\.1\.3 ist weder 1 \(an\) noch 2 \(aus\): '3'$"),
    ({"poeAdmin": {"1.3": ""}}, "^" + re.escape(UNREADABLE) + r"pethPsePortAdminEnable\.1\.3 ist weder 1 \(an\) noch 2 \(aus\): ''$"),
    ({"poeStatus": {"1.3": "busy"}}, "^" + re.escape(UNREADABLE) + r"pethPsePortDetectionStatus\.1\.3 ist keine Zahl: 'busy'$"),
    ({"poeAdmin": {"7": "1"}, "poeStatus": {"7": "2"}}, "^" + re.escape(UNREADABLE) + r"PoE-Index '7' ist nicht <Gruppe>\.<Port>$"),
    ({"poeAdmin": {"1.2.3": "1"}, "poeStatus": {"1.2.3": "2"}}, "^" + re.escape(UNREADABLE) + r"PoE-Index '1\.2\.3' ist nicht <Gruppe>\.<Port>$"),
    ({"poeAdmin": {"1.05": "1"}, "poeStatus": {"1.05": "2"}}, "^" + re.escape(UNREADABLE) + r"PoE-Index '1\.05' ist nicht <Gruppe>\.<Port>$"),
], ids=["status-row-missing", "admin-rows-missing", "admin-row-extra", "admin-3", "admin-empty", "status-text", "one-part", "three-parts",
        "leading-zero"])
def test_read_cfg_poe_truncated_fails_closed(edits, message):
    """A PoE table that is there but cannot describe the switch safely refuses the whole read (SnmpError, like the VLAN table check):
    admin and status are columns of one pethPsePortEntry, so an entry in one walk but not the other means a walk stopped early; an admin
    value that is no TruthValue, a status that is no number and an index that is not <group>.<port> are unreadable data."""
    with pytest.raises(snmp.SnmpError, match=message):
        read(edit_walks(W_POE, **edits))


@pytest.mark.parametrize("edits, message", [
    ({"poeEntPhy": {"1.4": None}},
     r"^PoE-Tabelle unvollständig gelesen: cpeExtPsePortEntPhyIndex passt nicht zu den PoE-Einträgen \(Eintrag 1\.4\)$"),
    ({"poeEntPhy": {"1.9": "1019"}},
     r"^PoE-Tabelle unvollständig gelesen: cpeExtPsePortEntPhyIndex passt nicht zu den PoE-Einträgen \(Eintrag 1\.9\)$"),
    ({"poeEntPhy": {"1.2": "Gi1/0/2"}}, "^" + re.escape(UNREADABLE) + r"cpeExtPsePortEntPhyIndex\.1\.2 ist keine Zahl: 'Gi1/0/2'$"),
    ({"entAlias": {"1014.0": None, "1014": f".{IF_INDEX}.10102"}},
     "^" + re.escape(UNREADABLE) + r"entAliasMappingIdentifier: Index '1014' ist nicht <entPhysicalIndex>\.<logisch>$"),
], ids=["entity-row-missing", "entity-row-extra", "entity-text", "alias-index"])
def test_read_cfg_cisco_entity_tables_fail_closed(edits, message):
    """The same for cisco's mapping tables: cpeExtPsePortEntry AUGMENTS pethPsePortEntry (one row each, or none at all on an IOS without
    it), its values and the alias index must be readable."""
    with pytest.raises(snmp.SnmpError, match=message):
        read(edit_walks({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, **edits), "cisco")


class FakeAgent:
    """snmp.walk for read_cfg: answers from W (agent format) by base OID and records (OID, hex, strict) of every walk; `failing`: the
    walk of that base OID raises."""

    def __init__(self, W: dict, failing: str | None = None):
        self.by_oid = {WALK_BASES[k]: rows for k, rows in W.items()}
        self.failing, self.calls = failing, []

    async def walk(self, host, cred, oid, hex_values=False, timeout=60, strict=False):
        self.calls.append((oid, hex_values, strict))
        if oid == self.failing:
            raise snmp.SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
        assert oid in self.by_oid or oid in {WALK_BASES[k] for k in POE_WALKS}, f"read_cfg walked {oid}"
        return list(self.by_oid.get(oid, []))


ROW = {"id": 7, "name": "SW-EK-01", "host": HOST, "sys_name": "SW-EK-01", "driver": "procurve", "snmp_version": "2c", "snmp_community": None,
       "snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None, "snmp_priv_proto": None, "snmp_priv_pass": None}


@pytest.mark.parametrize("name, W, poe", [
    ("procurve", W_POE, [POE_ADMIN, POE_STATUS]),
    ("cisco", {**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, [POE_ADMIN, POE_STATUS, CISCO_POE_ENTPHY, ENT_ALIAS]),
    ("generic", {**W_POE, "ifType": IFTYPE_SAMPLE}, []),       # R35
    ("mikrotik", {**W_POE, "ifType": IFTYPE_SAMPLE}, []),      # R31
])
@pytest.mark.parametrize("with_poe", [True, False])
async def test_read_cfg_walks_poe_strictly(monkeypatch, name, W, poe, with_poe):
    """read_cfg(with_poe=True), the read of a change that touches PoE, walks the PoE tables of the driver (never the power: display
    only), strictly and as text, next to every other walk; without with_poe (R34) no driver walks any PoE table, and no port has PoE.
    The result is build_cfg of what the agent answered."""
    fake = FakeAgent(agent(W))
    monkeypatch.setattr(snmp, "walk", fake.walk)
    cfg, raw = await snmpwrite.read_cfg({**ROW, "driver": name}, DRIVERS[name], with_poe=with_poe)
    walked = [oid for oid, _, _ in fake.calls]
    poe_ish = {POE_ADMIN, POE_STATUS, CISCO_POE_ENTPHY, ENT_ALIAS, HP_POE_POWER, CISCO_POE_POWER}
    poe = poe if with_poe else []
    assert sorted(oid for oid in walked if oid in poe_ish) == sorted(poe)
    assert all(strict for _, _, strict in fake.calls) and not any(hx for oid, hx, _ in fake.calls if oid in poe)
    assert len(walked) == len(set(walked))
    selection = {k: rows for k, rows in agent(W).items() if k not in POE_WALKS or WALK_BASES[k] in poe}
    assert (cfg, raw) == ({**read(selection, name, text_hex=True)[0], "hostname": "SW-EK-01"}, read(selection, name, text_hex=True)[1])
    if not with_poe:
        assert raw["poe"] == {} and set(poe_of(cfg).values()) == {None}


@pytest.mark.parametrize("driver, W, failing", [
    ("procurve", W_POE, POE_ADMIN), ("procurve", W_POE, POE_STATUS),
    ("cisco", {**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, CISCO_POE_ENTPHY), ("cisco", {**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, ENT_ALIAS),
])
async def test_read_cfg_fails_closed_when_a_poe_walk_fails(monkeypatch, driver, W, failing):
    """For a change that touches PoE, a PoE walk cut short (snmp.walk strict raises) fails the read like any other walk: no cfg
    without PoE state. A read without PoE (R34) does not walk it and goes through."""
    monkeypatch.setattr(snmp, "walk", FakeAgent(agent(W), failing).walk)
    with pytest.raises(snmp.SnmpError, match="Zeitüberschreitung"):
        await snmpwrite.read_cfg({**ROW, "driver": driver}, DRIVERS[driver], with_poe=True)
    cfg, raw = await snmpwrite.read_cfg({**ROW, "driver": driver}, DRIVERS[driver])
    assert raw["poe"] == {} and cfg["ports"]


async def test_build_cfg_uses_the_driver_it_is_given(monkeypatch):
    """read_cfg hands build_cfg its own driver object (no second lookup by name): a driver of that name with another PoE strategy than
    the registered one is the one that counts. A driver whose name is not driver_name is a caller bug (TypeError)."""
    no_mapping = Driver("procurve", PROCURVE.caps, "qbridge", dict(PROCURVE.oids), "", poe_index="none")
    cfg, raw = snmpwrite.build_cfg(W_POE, "procurve", driver=no_mapping)
    assert raw["poe"] == {} and raw["poe_unmapped"] == ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6"]
    assert snmpwrite.build_cfg(W_POE, "procurve", driver=PROCURVE) == snmpwrite.build_cfg(W_POE) == read(W_POE)
    with pytest.raises(TypeError, match=r"^build_cfg: Treiber 'cisco' zu driver_name 'procurve'$"):
        snmpwrite.build_cfg(W_POE, "procurve", driver=CISCO)
    monkeypatch.setattr(snmp, "walk", FakeAgent(agent(W_POE)).walk)
    cfg, raw = await snmpwrite.read_cfg(ROW, no_mapping, with_poe=True)
    assert raw["poe"] == {} and raw["poe_unmapped"] == ["1.1", "1.2", "1.3", "1.4", "1.5", "1.6"]


# ── render_ops: pethPsePortAdminEnable ───────────────────────────────────────────────────────────────────────────────────────────
POE_SW = agent(W_POE)


def render_and_store(W: dict, driver, desired: dict, selection: str = "procurve") -> tuple[list, list, dict]:
    """render_ops on the switch W (agent format); the simulated agent takes the varbinds; returns ops, shown and the read-back cfg, after
    checking that the read-back verify passes and that nothing but the desired fields changed."""
    cfg, raw = read(W, selection, text_hex=True)
    ops, shown = snmpwrite.render_ops(driver, cfg, raw, desired)
    cfg2, raw2 = read(store(W, ops), selection, text_hex=True)
    assert changes.verify_ports(cfg2, desired) == []
    want = {p: dict(st) for p, st in cfg["ports"].items()}
    for p, d in desired.items():
        want[p].update(d)
    assert {p: {k: v for k, v in st.items() if k not in ("u", "t")} for p, st in cfg2["ports"].items()} == {
        p: {k: v for k, v in st.items() if k not in ("u", "t")} for p, st in want.items()}
    return ops, shown, cfg2


def test_poe_render_op():
    """PoE off on port 1 (entry 1.1): ONE varbind pethPsePortAdminEnable.1.1 = INTEGER 2, the line with before and after; the switch
    reads port 1 as off afterwards and nothing else changed."""
    ops, shown, after = render_and_store(POE_SW, PROCURVE, {"1": {"poe": False}})
    assert ops == [(f"{POE_ADMIN}.1.1", "i", "2")]
    assert shown == ["Port 1: PoE an → aus"]
    assert poe_of(after) == {**POE_EXPECTED, "1": False}


def test_poe_render_on():
    ops, shown, after = render_and_store(POE_SW, PROCURVE, {"3": {"poe": True}})
    assert (ops, shown) == ([(f"{POE_ADMIN}.1.3", "i", "1")], ["Port 3: PoE aus → an"])
    assert poe_of(after)["3"] is True


def test_poe_render_index_is_the_entry_not_the_port():
    """On the Catalyst the varbind goes to the PoE entry the mapping found (1.2), never to the ifIndex (10102) or the bridge port."""
    W = agent({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN})
    ops, shown, after = render_and_store(W, CISCO, {"Gi1/0/2": {"poe": True}}, "cisco")
    assert (ops, shown) == ([(f"{POE_ADMIN}.1.2", "i", "1")], ["Port Gi1/0/2: PoE aus → an"])
    assert poe_of(after)["Gi1/0/2"] is True


def test_poe_already_so_renders_nothing():
    assert snmpwrite.render_ops(PROCURVE, *read(POE_SW, text_hex=True), {"1": {"poe": True}, "3": {"poe": False}}) == ([], [])


def test_poe_with_every_other_field():
    """The fixed orders: lines per port u, pvid, t, en, name, poe; varbinds PortLists, PVID, ifAdminStatus, ifAlias, then PoE by group and
    port. Port 6 (bp 5, ifIndex 6, entry 1.6): 1 -> 20, up, named, PoE off; port 3: PoE on."""
    ops, shown, _ = render_and_store(POE_SW, PROCURVE, {"6": {"u": "20", "en": True, "name": "AP", "poe": False}, "3": {"poe": True}})
    assert shown == ["Port 3: PoE aus → an", "Port 6: VLAN ungetaggt 1 → 20", "Port 6: aus → an", 'Port 6: Name "unused" → "AP"',
                     "Port 6: PoE an → aus"]
    assert ops == [(f"{VLAN_EGRESS}.1", "x", "02" + PAD), (f"{VLAN_EGRESS}.20", "x", "6A" + PAD), (f"{VLAN_UNTAGGED}.1", "x", "02" + PAD),
                   (f"{VLAN_UNTAGGED}.20", "x", "28" + PAD), (f"{PVID}.5", "u", "20"), (f"{IF_ADMIN}.6", "i", "1"),
                   (f"{IF_ALIAS}.6", "x", "4150"), (f"{POE_ADMIN}.1.3", "i", "1"), (f"{POE_ADMIN}.1.6", "i", "2")]


@pytest.mark.parametrize("W, selection, driver, port, value, reason", [
    pytest.param(POE_SW, "procurve", PROCURVE, "Trk1", False, POE_TRUNK, id="trunk"),
    pytest.param(POE_SW, "procurve", PROCURVE, "4", False, "gehört zu Trk1, bitte Trk1 wählen", id="trunk-member"),
    pytest.param(POE_SW, "procurve", PROCURVE, "1", "off", "poe ist nicht wahr oder falsch ('off')", id="text"),
    pytest.param(POE_SW, "procurve", PROCURVE, "1", 0, "poe ist nicht wahr oder falsch (0)", id="zero"),
    pytest.param(POE_SW, "procurve", PROCURVE, "1", None, "poe ist nicht wahr oder falsch (None)", id="none"),
    pytest.param(POE_SW, "procurve", PROCURVE, "9", False, "gibt es auf diesem Switch nicht", id="no-port"),
    pytest.param(agent(W_SAMPLE), "procurve", PROCURVE, "1", False, NO_POE_AT_ALL, id="switch-without-poe"),
    pytest.param(agent(edit_walks(W_POE, poeAdmin={"1.2": None}, poeStatus={"1.2": None})), "procurve", PROCURVE, "2", True, NO_POE,
                 id="port-without-poe"),
    pytest.param(agent(edit_walks(W_POE, poeAdmin={"1.2": None, "2.1": "1", "2.2": "1"}, poeStatus={"1.2": None, "2.1": "2", "2.2": "2"})),
                 "procurve", PROCURVE, "2", True, unmappable("2.1, 2.2"), id="unmapped-entries"),
    pytest.param(agent({**W_POE, "ifType": IFTYPE_SAMPLE}), "mikrotik", MIKROTIK, "1", False, MIKROTIK_NO_POE, id="mikrotik"),
])
def test_poe_refused(W, selection, driver, port, value, reason):
    """Every PoE refusal comes from snmp_block_reason: render_ops raises it for the port, nothing rendered."""
    cfg, raw = read(W, selection, text_hex=True)
    assert snmpwrite.snmp_block_reason(driver, cfg, raw, port, {"poe": value}) == reason
    with pytest.raises(ValueError) as refused:
        snmpwrite.render_ops(driver, cfg, raw, {port: {"poe": value}})
    assert str(refused.value) == f"Port {port}: {reason}"


def test_poe_on_a_port_without_a_bridge_port_is_refused():
    """A port the mapping gives a PoE entry, but that is no bridge port, is never written: the bridge-port rule of snmp_block_reason
    refuses it (the mapping cannot demand a bridge port: a ProCurve trunk member has none of its own). A Catalyst run as procurve: the
    ProCurve rule takes the SVIs Vl1 / Vl10 (ifIndex 1, 10) as ports and the entries 1.1 / 1.10 map onto them; and W_ODD's A3 (ifIndex
    3) is a port without a bridge port."""
    reason = "kein Bridge-Port (etwa ein Management-Port), per SNMP nur zur Anzeige"
    W = {**W_CATALYST, "poeAdmin": walk_rows(POE_ADMIN, {"1.1": "1", "1.10": "2"}),
         "poeStatus": walk_rows(POE_STATUS, {"1.1": "3", "1.10": "1"})}
    cfg, raw = read(W, "procurve")
    assert list(raw["poe"]) == ["Vl1", "Vl10"] and not {"Vl1", "Vl10"} & set(raw["port2bp"])
    assert snmpwrite.snmp_block_reason(PROCURVE, cfg, raw, "Vl1", {"poe": False}) == reason
    W = {**W_ODD, "poeAdmin": walk_rows(POE_ADMIN, {"1.3": "1"}), "poeStatus": walk_rows(POE_STATUS, {"1.3": "2"})}
    cfg, raw = read(W)
    assert raw["poe"] == {"A3": entry(1, 3, 1, 2)} and "A3" not in raw["port2bp"]
    assert snmpwrite.snmp_block_reason(PROCURVE, cfg, raw, "A3", {"poe": False}) == reason
    with pytest.raises(ValueError, match=r"^Port A3: kein Bridge-Port"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"A3": {"poe": False}})


def test_two_ports_on_one_poe_entry_are_refused_by_render_ops():
    """Cannot come out of build_cfg (the mapping drops both), so raw is edited by hand: two ports writing one PoE entry would switch
    the same device twice and the other one never."""
    cfg, raw = read(POE_SW, text_hex=True)
    raw = {**raw, "poe": {**raw["poe"], "2": dict(raw["poe"]["1"])}}
    with pytest.raises(ValueError, match=r"^Port 2: PoE-Eintrag 1\.1 gehört auch zu Port 1$"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"1": {"poe": False}, "2": {"poe": False}})


def test_poe_has_a_capability_label():
    """T10 carry: the label the refusals name a missing cap with."""
    assert snmpwrite.FIELD_CAPS["poe"] == "snmp_poe" and snmpwrite._CAP_LABEL["snmp_poe"] == "PoE"
    bare = Driver("nopoe", GENERIC.caps - {"snmp_poe"}, "qbridge", dict(GENERIC.oids), "")
    assert main._snmp_unwritable({"snmp_write": 0}, bare, {"snmp_poe"}) == "Treiber nopoe kann PoE nicht per SNMP schreiben"


# ── Planning ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def inv_of(cfg: dict) -> dict:
    """changes.inventory() as far as plan_ports looks at it: every port, tr = the trunk of a member or the trunk's own name, no
    neighbour, no link, no uplink."""
    member_of = {m: t for t, members in cfg["trunks"].items() for m in members}
    return {"ports": {n: {"n": n, "tr": n if n in cfg["trunks"] else member_of.get(n, ""), "l": [], "o": False} for n in cfg["ports"]},
            "uplinks": set()}


def plan_snmp(req: dict, W: dict = POE_SW, driver=PROCURVE, selection: str = "procurve") -> dict:
    cfg, raw = read(W, selection, text_hex=True)
    return changes.plan_ports(FW, inv_of(cfg), cfg, req, mechanism="snmp", driver=driver, raw=raw)


def test_desired_from_set_carries_poe():
    cfg, _ = read(W_POE)
    assert changes._desired_from_set(cfg, ["1", "3"], {"poe": False}) == {"1": {"poe": False}, "3": {}}
    assert changes._desired_from_set(cfg, ["1"], {"poe": None, "name": "AP"}) == {"1": {"name": "AP"}}
    ssh = cfgparse.parse_config(SSH_CONFIG)    # a running-config knows no PoE: the field is kept, the SSH branch refuses it
    assert changes._desired_from_set(ssh, ["2"], {"poe": True}) == {"2": {"poe": True}}


def test_plan_ports_snmp_poe():
    """Port 1 off over SNMP: desired / before carry poe, the line and the one varbind; port 1 is delivering power, a warning says so."""
    plan = plan_snmp({"ports": ["1"], "set": {"poe": False}})
    assert plan == {"commands": [], "shown": ["Port 1: PoE an → aus"], "ops": [(f"{POE_ADMIN}.1.1", "i", "2")],
                    "desired": {"1": {"poe": False}}, "before": {"1": {"poe": True}}, "blocked": [], "warnings": [DELIVERING],
                    "expert": False, "mechanism": "snmp"}
    assert plan_snmp({"ports": ["2"], "set": {"poe": False}})["warnings"] == []    # searching: nothing powered
    assert plan_snmp({"ports": ["1"], "set": {"poe": True}})["shown"] == []        # already on: nothing to do
    blocked = plan_snmp({"ports": ["1", "Trk1"], "set": {"poe": False}, "expert": True})
    assert blocked["blocked"] == [{"port": "Trk1", "reason": POE_TRUNK}] and blocked["desired"] == {"1": {"poe": False}}


def test_lag_members_keep_their_poe_state_read_only():
    """R36: a trunk member is a physical port and its PoE entry maps to it, so display, cfg and raw show its state (ports 4 / 5, Trk1's
    members; Gi1/0/3 / Gi1/0/4, Po1's). Writing it stays refused by the member rule; the trunk itself has no PoE."""
    cfg, raw = read(W_POE)
    assert (poe_of(cfg)["4"], poe_of(cfg)["5"], raw["poe"]["4"], raw["poe"]["5"]) == (True, True, entry(1, 4, 1, 2), entry(1, 5, 1, 2))
    assert display(W_POE)[3:5] == [("4", 1, 2, None), ("5", 1, 2, None)]
    assert snmpwrite.snmp_block_reason(PROCURVE, cfg, raw, "4", {"poe": False}) == "gehört zu Trk1, bitte Trk1 wählen"
    plan = plan_snmp({"ports": ["4"], "set": {"poe": False}})
    assert (plan["blocked"], plan["ops"]) == ([{"port": "4", "reason": "gehört zu Trk1, bitte Trk1 wählen"}], [])
    cfg, raw = read({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, "cisco")
    assert {p: raw["poe"][p] for p in ("Gi1/0/3", "Gi1/0/4")} == {p: CATALYST_POE_RAW[p] for p in ("Gi1/0/3", "Gi1/0/4")}
    assert snmpwrite.snmp_block_reason(CISCO, cfg, raw, "Gi1/0/3", {"poe": True}) == "gehört zu Po1, bitte Po1 wählen"


def test_verify_snmp_checks_the_poe_entry():
    """The read-back must map the port to the very entry the SET went to (raw["poe"] of the read the change was rendered against):
    same entry and state ok; another entry, even in the wanted state, a mismatch; no entry any more: poe None; none planned: never ok."""
    cfg, raw = read(POE_SW, text_hex=True)
    cfg2, raw2 = read(store(POE_SW, [(f"{POE_ADMIN}.1.1", "i", "2")]), text_hex=True)
    off = {"1": {"poe": False}}
    assert changes.verify_snmp(PROCURVE, cfg, cfg2, raw2, off, raw=raw) == []
    moved = {**raw2, "poe": {**raw2["poe"], "1": {**raw2["poe"]["1"], "index": 7}}}
    assert changes.verify_snmp(PROCURVE, cfg, cfg2, moved, off, raw=raw) == ["Port 1: PoE-Eintrag ist jetzt 1.7, geschrieben wurde 1.1"]
    gone = {**raw2, "poe": {k: v for k, v in raw2["poe"].items() if k != "1"}}
    cfg_gone = {**cfg2, "ports": {**cfg2["ports"], "1": {**cfg2["ports"]["1"], "poe": None}}}
    assert changes.verify_snmp(PROCURVE, cfg, cfg_gone, gone, off, raw=raw) == ["Port 1: poe ist None, erwartet False"]
    assert changes.verify_snmp(PROCURVE, cfg, cfg2, raw2, off, raw={**raw, "poe": {}}) == ["Port 1: PoE ohne geplanten Eintrag"]


def test_plan_ports_snmp_poe_revert():
    """The revert of a PoE change (desired = before) against the read after it: back on."""
    cfg, raw = read(store(POE_SW, [(f"{POE_ADMIN}.1.1", "i", "2")]), text_hex=True)
    plan = changes.plan_ports(FW, inv_of(cfg), cfg, {"desired": {"1": {"poe": True}}}, mechanism="snmp", driver=PROCURVE, raw=raw)
    assert (plan["shown"], plan["ops"], plan["before"]) == (["Port 1: PoE aus → an"], [(f"{POE_ADMIN}.1.1", "i", "1")], {"1": {"poe": False}})


# The sample switch's running-config as the SSH path reads it (tests/test_run_change_snmp.py has the same): no PoE in it.
SSH_CONFIG = """\
Running configuration:

; J9729A Configuration Editor; Created on release #WB.16.99.0001
hostname "SW-EK-01"
trunk 4-5 Trk1 LACP
vlan 1
   name "DEFAULT_VLAN"
   untagged 6,Trk1
   no untagged 1-3
   exit
vlan 20
   name "Clients"
   untagged 1
   tagged 3,Trk1
   exit
vlan 30
   name "Voice"
   tagged 1,3,Trk1
   exit
vlan 99
   name "Guest"
   untagged 2
   tagged Trk1
   exit
interface 1
   name "Platz-107"
   exit
interface 6
   disable
   name "unused"
   exit
"""


@pytest.mark.parametrize("req", [
    {"ports": ["2"], "set": {"poe": False}},
    {"ports": ["2"], "set": {"untagged": "20", "poe": False}},
    {"desired": {"2": {"poe": True}}},
    {"desired": {"2": {"u": "20", "poe": True}}},
], ids=["poe", "poe-and-vlan", "desired-poe", "desired-poe-and-vlan"])
def test_ssh_branch_never_plans_poe(req):
    """Defensive (R30): the SSH planner refuses a port with PoE instead of planning the rest (_commands has no PoE and would drop it
    silently, the change would end ok with the PoE part never sent); nothing of the port is planned."""
    cfg = cfgparse.parse_config(SSH_CONFIG)
    plan = changes.plan_ports(FW, inv_of(cfg), cfg, req)
    assert plan["blocked"] == [{"port": "2", "reason": POE_OVER_SSH}]
    assert (plan["commands"], plan["shown"], plan["desired"], plan["mechanism"]) == ([], [], {}, "ssh")


def test_ssh_plans_without_poe_unchanged():
    cfg = cfgparse.parse_config(SSH_CONFIG)
    plan = changes.plan_ports(FW, inv_of(cfg), cfg, {"ports": ["2"], "set": {"untagged": "20", "poe": None}})
    assert plan == {"commands": ["vlan 20 untagged 2"], "shown": ["vlan 20 untagged 2"], "desired": {"2": {"u": "20"}},
                    "before": {"2": {"u": "99"}}, "blocked": [], "warnings": [], "expert": False, "mechanism": "ssh"}


@pytest.mark.parametrize("change, ops", [
    ({"poe": False}, {"snmp_poe"}), ({"poe": True}, {"snmp_poe"}), ({"poe": None}, set()),
    ({"poe": True, "untagged": "20", "status": "off"}, {"snmp_poe", "snmp_vlan", "snmp_admin"}),
])
def test_needed_ops_poe(change, ops):
    assert main.needed_ops(main.PlanIn(ports=["1"], change=change)) == ops


@pytest.mark.parametrize("value", ["yes", "true", 1, 0, "on", "off", "1"])
def test_portchange_poe_is_a_strict_bool(value):
    """Only JSON true / false (or null): nothing a client may mean differently."""
    with pytest.raises(ValidationError):
        main.PortChange(poe=value)
    assert main.PortChange(poe=False).poe is False and main.PortChange().poe is None


def test_summary_names_poe():
    assert main._summary(main.PlanIn(ports=["1"], change={"poe": False})) == "Port 1: PoE aus"
    assert main._summary(main.PlanIn(ports=["1", "2"], change={"untagged": "20", "poe": True})) == "Port 1-2: VLAN 20, PoE an"


# ── The world of the routing and run tests: a database, the simulated switch behind SNMP, no SSH ─────────────────────────────────────
READ, RW = "read-s3cret", "rw-s3cret"
NO_V3 = {"snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None, "snmp_priv_proto": None, "snmp_priv_pass": None}
READ_CRED = {"snmp_version": "2c", "snmp_community": READ, **NO_V3}
RW_CRED = {"snmp_version": "2c", "snmp_community": RW, **NO_V3}
BY_OID = {base: key for key, base in WALK_BASES.items()}


class World:
    """One test's switch: snmp.walk answers from W (agent format), snmp.set_vars goes through switchfix.store (set_mode "ignore": the
    switch answers but takes nothing; after_set: what else changes right after the SET; failing: base OIDs whose walk times out, a
    PoE MIB that fails, say). Records walks, SETs, the with_poe of every snmpwrite.read_cfg (reads) and every SSH-side call."""

    def __init__(self):
        self.W: dict = {}
        self.selection = "procurve"
        self.walks: list = []
        self.sets: list = []
        self.reads: list[bool] = []
        self.ssh: list = []
        self.failing: set[str] = set()
        self.set_mode, self.after_set = "apply", None

    async def walk(self, host, cred, oid, hex_values=False, timeout=60, strict=False):
        assert (host, strict) == (HOST, True), (host, strict)
        self.walks.append((oid, cred))
        if oid in self.failing:
            raise snmp.SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
        key = BY_OID[oid]
        assert key in self.W or key in POE_WALKS, f"walk of {key}, which this switch does not answer"
        return list(self.W.get(key, []))

    async def set_vars(self, host, cred, varbinds, timeout=20):
        self.sets.append((host, cred, list(varbinds)))
        if self.set_mode == "apply":
            self.W = store(self.W, varbinds)
            if self.after_set:
                self.W = self.after_set(self.W)
        return "".join(f".{oid} = {typ}: {value}\n" for oid, typ, value in varbinds)

    async def fresh_cfg(self, sid, max_age_s=600):
        self.ssh.append(("fresh_cfg", sid))
        return cfgparse.parse_config(SSH_CONFIG)

    async def inventory(self, sid):
        return inv_of(read(self.W, self.selection, text_hex=True)[0])

    async def switch(self, driver: str, W: dict, *, ssh: bool = True, snmp_write: bool = True, rw: bool = True) -> dict:
        """A switches row (read community READ, RW community RW unless rw is False, SSH access if ssh) and the switch W behind it; the
        row as the app reads it (SELECT *)."""
        cols = {"name": "SW-EK-01", "host": HOST, "driver": driver, "snmp_write": int(snmp_write), "snmp_version": "2c",
                "snmp_community": crypto.encrypt(READ), "sys_name": "SW-EK-01", "firmware": FW}
        if rw:
            cols["snmp_rw_community"] = crypto.encrypt(RW)
        if ssh:
            cols |= {"ssh_user": "manager", "ssh_pass": crypto.encrypt("ssh-s3cret")}
        async with db.db() as conn:
            cur = await conn.execute(f"INSERT INTO switches ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(cols.values()))
            await conn.commit()
            sid = cur.lastrowid
        self.W, self.selection = W, driver
        return await switch_row(sid)


async def switch_row(sid: int):
    async with db.db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)) as cur:
            return await cur.fetchone()


@pytest.fixture
async def world(tmp_path, monkeypatch) -> World:
    """A fresh database under tmp_path; SNMP answered by the World's switch, snmpwrite.read_cfg spied on (its with_poe); changes.fresh_cfg
    (the SSH read of a preview) recorded; re-polls never run; fresh locks; every SSH entry point a trap that records and raises."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    await db.init_db()
    w = World()

    def repoll(sid):
        async def nothing():
            return None
        return nothing()

    def trap(name):
        def raise_(*args, **kwargs):
            w.ssh.append((name,))
            raise AssertionError(f"{name} on a PoE path")
        return raise_

    real_read = snmpwrite.read_cfg

    async def read_cfg(row, driver, *, with_poe=False):
        w.reads.append(with_poe)
        return await real_read(row, driver, with_poe=with_poe)

    monkeypatch.setattr(snmp, "walk", w.walk)
    monkeypatch.setattr(snmp, "set_vars", w.set_vars)
    monkeypatch.setattr(snmpwrite, "read_cfg", read_cfg)
    monkeypatch.setattr(changes, "fresh_cfg", w.fresh_cfg)
    monkeypatch.setattr(changes, "inventory", w.inventory)
    monkeypatch.setattr(changes, "_repoll", repoll)
    monkeypatch.setattr(changes, "_cfg_stale", set())
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    monkeypatch.setattr(poller, "_locks", {})
    for mod, name in ((sshcli, "connect"), (sshcli, "disconnect"), (sshcli, "run_shows"), (sshcli, "backup_config"),
                      (sshcli, "store_backup"), (changes, "store_cfg")):
        monkeypatch.setattr(mod, name, trap(name))
    return w


async def make_plan(row, payload: dict):
    return await main._make_plan(row, main.PlanIn(**payload))


async def refused_with(row, payload: dict) -> tuple[int, str]:
    with pytest.raises(HTTPException) as e:
        await make_plan(row, payload)
    return e.value.status_code, e.value.detail


# ── Routing (R30): PoE over SNMP for every driver ────────────────────────────────────────────────────────────────────────────────
OFF1 = {"ports": ["1"], "change": {"poe": False}}


async def test_poe_on_a_procurve_with_working_ssh_goes_snmp(world):
    """ProCurve with SSH access (which would carry a VLAN change): a request with PoE never reads or plans over SSH, it is planned over
    SNMP against a live read, and with it the rest of the request (here a VLAN): the preview shows mechanism snmp."""
    row = await world.switch("procurve", POE_SW)
    plan, req, kind, summary = await make_plan(row, OFF1)
    assert (plan["mechanism"], plan["shown"], plan["ops"], plan["blocked"]) == ("snmp", ["Port 1: PoE an → aus"],
                                                                                [(f"{POE_ADMIN}.1.1", "i", "2")], [])
    assert (kind, summary, req["set"]["poe"]) == ("ports", "Port 1: PoE aus", False)
    plan, _, _, _ = await make_plan(row, {"ports": ["1"], "change": {"poe": False, "untagged": "99"}})
    assert (plan["mechanism"], plan["shown"]) == ("snmp", ["Port 1: VLAN ungetaggt 20 → 99", "Port 1: PoE an → aus"])
    assert world.ssh == [] and world.sets == []
    assert {cred["snmp_community"] for _, cred in world.walks} == {READ}


async def test_requests_without_poe_still_prefer_ssh(world):
    row = await world.switch("procurve", POE_SW)
    plan, _, _, _ = await make_plan(row, {"ports": ["2"], "change": {"untagged": "20"}})
    assert (plan["mechanism"], plan["shown"]) == ("ssh", ["vlan 20 untagged 2"])
    assert world.ssh == [("fresh_cfg", row["id"])] and world.walks == []


@pytest.mark.parametrize("driver, kw, reason", [
    ("procurve", {"snmp_write": False}, WRITE_DISABLED),
    ("procurve", {"rw": False, "snmp_write": True}, None),            # the read community writes (it must be allowed to): no refusal
    ("cisco", {"snmp_write": False}, WRITE_DISABLED),
    ("mikrotik", {}, MIKROTIK_NO_POE),
    ("generic", {}, "Treiber generic kann PoE nicht per SNMP schreiben"),      # R35
], ids=["procurve-snmp-off", "procurve-read-community", "cisco-snmp-off", "mikrotik", "generic"])
async def test_poe_without_snmp_write_access_is_422(world, driver, kw, reason):
    """No way to write PoE over SNMP: 422 with the reason, before any read; never an SSH attempt."""
    W = {"procurve": POE_SW, "cisco": agent({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}),
         "mikrotik": agent({**W_POE, "ifType": IFTYPE_SAMPLE}), "generic": agent({**W_POE, "ifType": IFTYPE_SAMPLE})}[driver]
    row = await world.switch(driver, W, **kw)
    payload = {"ports": ["Gi1/0/2" if driver == "cisco" else "1"], "change": {"poe": True}}
    if reason is None:
        assert (await make_plan(row, payload))[0]["mechanism"] == "snmp"
        return
    assert await refused_with(row, payload) == (422, needs_snmp(reason))
    assert world.walks == [] and world.ssh == []


async def test_poe_without_any_write_identity_is_422(world):
    row = await world.switch("procurve", POE_SW, rw=False)
    async with db.db() as conn:
        await conn.execute("UPDATE switches SET snmp_community = NULL WHERE id = ?", (row["id"],))
        await conn.commit()
    assert await refused_with(await switch_row(row["id"]), OFF1) == (422, needs_snmp(NO_WRITE_CREDS))


async def test_poe_with_a_cli_only_part_is_409(world):
    """PoE needs SNMP, RADIUS the CLI: no mechanism carries both, nothing is read or planned."""
    row = await world.switch("procurve", POE_SW)
    status, detail = await refused_with(row, {"ports": ["1"], "change": {"poe": False, "status": "radius"}})
    assert (status, detail) == (409, f"{RADIUS_CLI}. PoE geht nur per SNMP: bitte getrennt ändern")
    assert world.walks == [] and world.ssh == []


async def test_poe_with_an_echoed_ssh_mechanism_is_stale(world):
    """/apply echoing "ssh" for a PoE request: the preview can never have said so; 409, nothing read."""
    row = await world.switch("procurve", POE_SW)
    assert await refused_with(row, {**OFF1, "mechanism": "ssh"}) == (409, f"{STALE} (PoE geht nur per SNMP)")
    plan, _, _, _ = await make_plan(row, {**OFF1, "mechanism": "snmp"})
    assert plan["mechanism"] == "snmp" and world.ssh == []


async def test_prepare_ignores_a_poe_field(world):
    """RADIUS prepare is CLI and has no ports: a PoE value in its body changes nothing (still SSH, nothing over SNMP)."""
    row = await world.switch("procurve", POE_SW)
    plan, _, kind, _ = await make_plan(row, {"mode": "prepare", "change": {"poe": True}})
    assert (kind, plan["mechanism"]) == ("prepare", "ssh") and world.walks == []


# ── run_change: SET, read back, verify; revert ───────────────────────────────────────────────────────────────────────────────────
async def change_row(cid: int) -> dict:
    async with db.db() as conn:
        async with conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)) as cur:
            ch = dict(await cur.fetchone())
    for k in ("request", "ports", "desired", "before", "commands", "steps"):
        ch[k] = json.loads(ch[k]) if ch[k] else ch[k]
    return ch


async def apply(world: World, row, payload: dict) -> tuple[int, dict]:
    """What POST /apply does once the token matches: plan (main._make_plan) and create the change."""
    plan, req, kind, summary = await make_plan(row, payload)
    assert plan["blocked"] == [] and plan["shown"], plan
    revert_of = payload["of"] if payload.get("mode") == "revert" else None
    return await changes.create_change(row["id"], "tester", kind, summary, req, plan, revert_of=revert_of), plan


async def run(cid: int) -> dict:
    await changes.run_change(cid)
    await asyncio.sleep(0)
    return await change_row(cid)


async def test_poe_change_runs_over_snmp(world):
    """PoE off on port 1 of a ProCurve with SSH: the run reads live, sends ONE SET with the write identity, reads back and finds port
    1 off: ok, saved (ProCurve stores every SNMP set itself). Never SSH."""
    row = await world.switch("procurve", POE_SW)
    cid, plan = await apply(world, row, OFF1)
    world.walks.clear()
    ch = await run(cid)
    assert (ch["status"], ch["saved"], ch["error"], ch["mechanism"]) == ("ok", 1, None, "snmp")
    assert world.sets == [(HOST, RW_CRED, [(f"{POE_ADMIN}.1.1", "i", "2")])]
    assert {cred["snmp_community"] for _, cred in world.walks} == {READ}
    assert ch["before"] == {"1": {"poe": True}} and ch["desired"] == {"1": {"poe": False}}
    assert poe_of(read(world.W, text_hex=True)[0]) == {**POE_EXPECTED, "1": False}
    assert world.ssh == []


async def test_poe_verify(world):
    """The switch answers the SET but takes nothing: port 1 still on -> unclear, with what differs."""
    row = await world.switch("procurve", POE_SW)
    cid, _ = await apply(world, row, OFF1)
    world.set_mode = "ignore"
    ch = await run(cid)
    assert (ch["status"], ch["saved"], ch["error"]) == ("unclear", 0, MISMATCH + "Port 1: poe ist True, erwartet False")
    assert len(world.sets) == 1


async def test_poe_unmappable_after_the_write_is_a_mismatch(world):
    """Right after the SET the switch reports an entry that voids the mapping (1.7: no such port): the read-back has no PoE state for
    port 1, which never counts as the wanted state."""
    row = await world.switch("procurve", POE_SW)
    cid, _ = await apply(world, row, OFF1)
    world.after_set = lambda W: edit_walks(W, poeAdmin={"1.7": "1"}, poeStatus={"1.7": "2"})
    ch = await run(cid)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 1: poe ist None, erwartet False")


async def test_poe_round_trip_with_revert(world):
    """plan -> run_change -> revert: the revert is planned over SNMP from `before`, switches port 1 back on, verifies it, and the
    switch is exactly what it was."""
    row = await world.switch("procurve", POE_SW)
    cid, _ = await apply(world, row, {"ports": ["1", "3"], "change": {"poe": True}})
    assert (await run(cid))["status"] == "ok"
    assert poe_of(read(world.W, text_hex=True)[0])["3"] is True
    cid, _ = await apply(world, row, OFF1)
    assert (await run(cid))["status"] == "ok"
    after_forward = world.W
    rid, plan = await apply(world, row, {"mode": "revert", "of": cid})
    assert (plan["mechanism"], plan["shown"], plan["desired"]) == ("snmp", ["Port 1: PoE aus → an"], {"1": {"poe": True}})
    ch = await run(rid)
    assert (ch["status"], ch["saved"], ch["revert_of"], ch["before"]) == ("ok", 1, cid, {"1": {"poe": False}})
    assert world.sets[-1] == (HOST, RW_CRED, [(f"{POE_ADMIN}.1.1", "i", "1")])
    assert world.W == store(after_forward, [(f"{POE_ADMIN}.1.1", "i", "1")])
    assert poe_of(read(world.W, text_hex=True)[0]) == {**POE_EXPECTED, "3": True}
    assert world.ssh == []


# Ports the write path reads as unmanaged (their VLAN slot is ambiguous), with PoE:
#   R12: port 2 (bridge port 1, untagged 99) with PVID 1, as a RADIUS-assigned VLAN may show up (R16); PoE entry 1.2, on
#   R9:  port 3 (bridge port 2) untagged in VLAN 1 and 20, a hybrid / general port; PoE entry 1.3, off
R12_POE = agent(edit_walks(W_POE, pvid={"1": "1"}))
R9_POE = agent(edit_walks(W_POE, vlanEgress={"1": "4A" + " 00" * 7}, vlanUntagged={"1": "4A" + " 00" * 7, "20": "60" + " 00" * 7}))


@pytest.mark.parametrize("W, port, entry, on", [(R12_POE, "2", "1.2", True), (R9_POE, "3", "1.3", False)], ids=["R12", "R9"])
async def test_poe_on_an_unmanaged_port_round_trip(world, W, port, entry, on):
    """R41: PoE never reads the VLAN slot, so it is switched on an unmanaged port too, the main PoE use case on a NAC port whose VLAN
    RADIUS assigned: planned, written, verified (the port is still unmanaged afterwards, which counts only for a VLAN change), and the
    revert restores exactly PoE. VLAN changes on the port stay refused with the unmanaged reason."""
    row = await world.switch("procurve", W)
    assert port in read(W, text_hex=True)[1]["unmanaged"]
    cid, plan = await apply(world, row, {"ports": [port], "change": {"poe": not on}})
    assert (plan["mechanism"], plan["ops"], plan["before"]) == ("snmp", [(f"{POE_ADMIN}.{entry}", "i", "2" if on else "1")], {port: {"poe": on}})
    ch = await run(cid)
    assert (ch["status"], ch["saved"], ch["error"]) == ("ok", 1, None)
    assert poe_of(read(world.W, text_hex=True)[0])[port] is (not on)
    rid, plan = await apply(world, row, {"mode": "revert", "of": cid})
    assert (plan["desired"], plan["ops"]) == ({port: {"poe": on}}, [(f"{POE_ADMIN}.{entry}", "i", "1" if on else "2")])
    assert (await run(rid))["status"] == "ok"
    assert world.W == W
    plan, _, _, _ = await make_plan(row, {"ports": [port], "change": {"poe": not on, "untagged": "30"}})
    assert (plan["blocked"], plan["ops"]) == ([{"port": port, "reason": read(W, text_hex=True)[1]["unmanaged"][port]}], [])
    assert world.ssh == []


async def test_poe_verify_checks_the_entry_it_wrote(world):
    """Hardening: right after the SET the entity table maps Gi1/0/2 to entry 1.1 and Gi1/0/1 to 1.2 (PoE hardware changed between read
    and SET, say). Gi1/0/2 then reads as on, as wanted, because entry 1.1 is on, but the SET went to 1.2: unclear, never ok."""
    row = await world.switch("cisco", agent({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}))
    cid, _ = await apply(world, row, {"ports": ["Gi1/0/2"], "change": {"poe": True}})
    world.after_set = lambda W: edit_walks(W, entAlias={"1013.0": f".{IF_INDEX}.10102", "1014.0": f".{IF_INDEX}.10101"})
    ch = await run(cid)
    assert world.sets == [(HOST, RW_CRED, [(f"{POE_ADMIN}.1.2", "i", "1")])]
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port Gi1/0/2: PoE-Eintrag ist jetzt 1.1, geschrieben wurde 1.2")


async def test_poe_change_on_the_catalyst(world):
    """cisco: the entry found through the entity tables (Gi1/0/2 = 1.2), saved=0 with the R26 warning (no autosave)."""
    row = await world.switch("cisco", agent({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}))
    cid, plan = await apply(world, row, {"ports": ["Gi1/0/2"], "change": {"poe": True}})
    assert plan["shown"] == ["Port Gi1/0/2: PoE aus → an"]
    ch = await run(cid)
    assert (ch["status"], ch["saved"]) == ("ok", 0)
    assert world.sets == [(HOST, RW_CRED, [(f"{POE_ADMIN}.1.2", "i", "1")])]


# ── R34: the PoE tables are read only for a change that touches PoE ───────────────────────────────────────────────────────────
VLAN2 = {"ports": ["2"], "change": {"untagged": "20"}}
POE_OIDS = {POE_ADMIN, POE_STATUS, CISCO_POE_ENTPHY, ENT_ALIAS}


@pytest.mark.parametrize("req, want", [
    ({"ports": ["1"], "set": {"poe": False}}, True),
    ({"ports": ["1"], "set": {"poe": True, "untagged": "20"}}, True),
    ({"ports": ["1"], "set": {"poe": None, "untagged": "20"}}, False),
    ({"ports": ["1"], "set": {}}, False),
    ({"desired": {"1": {"poe": True}}}, True),                                     # the revert of a PoE change
    ({"desired": {"2": {"u": "20"}, "1": {"poe": False, "name": "x"}}}, True),
    ({"desired": {"2": {"u": "20", "pvid": "20"}}}, False),                        # the revert of a VLAN change
    ({"of": 3}, False), ({}, False),
])
def test_touches_poe(req, want):
    """The one flag (changes.touches_poe) the preview and both reads of a run compute from the same request."""
    assert changes.touches_poe(req) is want


async def test_a_vlan_change_never_walks_poe(world):
    """A VLAN change over SNMP (a ProCurve without SSH access) on a PoE switch whose PoE MIB fails: preview, read before and read-back
    never walk a PoE table, and the change plans, applies and verifies. Before R34 one failing PoE walk blocked every SNMP write."""
    row = await world.switch("procurve", POE_SW, ssh=False)
    world.failing = set(POE_OIDS)
    cid, plan = await apply(world, row, VLAN2)
    assert (plan["mechanism"], plan["shown"]) == ("snmp", ["Port 2: VLAN ungetaggt 99 → 20"])
    ch = await run(cid)
    assert (ch["status"], ch["saved"], ch["error"]) == ("ok", 1, None)
    assert world.reads == [False, False, False]                          # preview, read before, read back
    assert not {oid for oid, _ in world.walks} & POE_OIDS and len(world.sets) == 1
    rid, plan = await apply(world, row, {"mode": "revert", "of": cid})    # its revert does not touch PoE either
    assert (await run(rid))["status"] == "ok"
    assert world.reads == [False] * 6 and not {oid for oid, _ in world.walks} & POE_OIDS


async def test_a_poe_change_with_a_failing_poe_mib_fails_closed(world):
    """The same failing PoE MIB and a PoE change: the preview reads PoE, the walk fails -> 502, nothing planned; and a run whose live
    read fails the same way ends failed, without a SET."""
    row = await world.switch("procurve", POE_SW)
    world.failing = {POE_STATUS}
    assert await refused_with(row, OFF1) == (502, "Konfiguration des Switches per SNMP nicht lesbar: Zeitüberschreitung bei der SNMP-Abfrage")
    world.failing = set()
    cid, _ = await apply(world, row, OFF1)
    world.failing = {POE_ADMIN}
    ch = await run(cid)
    assert (ch["status"], ch["error"]) == ("failed", "Zustand per SNMP nicht lesbar: Zeitüberschreitung bei der SNMP-Abfrage")
    assert world.sets == [] and world.ssh == []


async def test_both_reads_of_a_poe_change_and_of_its_revert_read_poe(world):
    """A PoE change reads PoE in its preview and in both reads of its run (the flag comes from the stored request); its revert, planned
    from `before` (which holds poe), reads PoE by itself, again in the preview and in both reads. Each of those reads walks both PoE
    columns."""
    row = await world.switch("procurve", POE_SW)
    cid, _ = await apply(world, row, OFF1)
    assert (await run(cid))["status"] == "ok"
    rid, plan = await apply(world, row, {"mode": "revert", "of": cid})
    assert plan["shown"] == ["Port 1: PoE aus → an"]
    assert (await run(rid))["status"] == "ok"
    assert world.reads == [True] * 6
    assert sorted(oid for oid, _ in world.walks if oid in POE_OIDS) == sorted([POE_ADMIN, POE_STATUS] * 6)


async def test_the_read_back_of_a_poe_change_reads_poe_even_when_the_change_has_more(world):
    """PoE and a VLAN in one change: one flag for the whole change, both reads with PoE; the read-back verifies both fields."""
    row = await world.switch("procurve", POE_SW)
    cid, plan = await apply(world, row, {"ports": ["1"], "change": {"poe": False, "untagged": "99"}})
    assert plan["shown"] == ["Port 1: VLAN ungetaggt 20 → 99", "Port 1: PoE an → aus"]
    world.set_mode = "ignore"
    ch = await run(cid)
    assert ch["status"] == "unclear" and "Port 1: poe ist True, erwartet False" in ch["error"] and "Port 1: u ist '20'" in ch["error"]
    assert world.reads == [True, True, True]


# ── The display poll and the map ─────────────────────────────────────────────────────────────────────────────────────────────────
class PollAgent:
    """snmp.walk of the display poller: answers from a recording by base OID (nothing for any other walk) and records the OIDs; the walks
    in `failing` time out."""

    def __init__(self, recording: dict, failing: tuple = ()):
        self.recording, self.failing, self.oids = recording, failing, []

    async def walk(self, host, cred, oid, hex_values=False, timeout=60, strict=False):
        assert strict is False
        self.oids.append(oid)
        if oid in self.failing:
            raise snmp.SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
        return list(self.recording.get(oid, []))


def recording(W: dict) -> dict:
    """W (walk rows, text as text, the way the display poller walks) by base OID."""
    return {WALK_BASES[k]: rows for k, rows in W.items()}


async def stored_poe(sid: int) -> list[tuple]:
    async with db.db() as conn:
        async with conn.execute("SELECT name, poe_admin, poe_status, poe_power FROM ports WHERE switch_id = ? ORDER BY ifindex", (sid,)) as cur:
            return [tuple(r) for r in await cur.fetchall()]


async def test_poll_reads_poe(world, monkeypatch):
    """The display poll of the PoE ProCurve: the PoE columns of each mapped port (power from hpicfPoePethPsePortPower, mW), the trunk
    without; the walks are the poller's plus the driver's PoE walks, power included."""
    row = await world.switch("procurve", W_POE)
    poll = PollAgent(recording(W_POE) | {HP_POE_POWER: HP_POWER_SAMPLE})
    monkeypatch.setattr(snmp, "walk", poll.walk)
    assert (await poller.poll_switch(row["id"]))["ok"] is True
    assert await stored_poe(row["id"]) == [("1", 1, 3, 5400), ("2", 1, 2, 0), ("3", 2, 1, 0), ("4", 1, 2, 0), ("5", 1, 2, 0),
                                           ("6", 1, 2, 0), ("Trk1", None, None, None)]
    assert sorted(poll.oids) == sorted([*poller.O.values(), POE_ADMIN, POE_STATUS, HP_POE_POWER])


async def test_poll_unmappable_poe_is_not_shown(world, monkeypatch):
    """A stack member's entries (group 2) next to the ProCurve's own: shown only where mapped; with a voiding entry nothing is shown."""
    W = edit_walks(W_POE, poeAdmin={"1.2": None, "2.2": "2"}, poeStatus={"1.2": None, "2.2": "1"})
    row = await world.switch("procurve", W)
    monkeypatch.setattr(snmp, "walk", PollAgent(recording(W)).walk)
    await poller.poll_switch(row["id"])
    got = await stored_poe(row["id"])
    assert got[:3] == [("1", 1, 3, None), ("2", None, None, None), ("3", 2, 1, None)]
    W = edit_walks(W_POE, poeAdmin={"1.4097": "1"}, poeStatus={"1.4097": "2"})
    monkeypatch.setattr(snmp, "walk", PollAgent(recording(W)).walk)
    await poller.poll_switch(row["id"])
    assert {r[1:] for r in await stored_poe(row["id"])} == {(None, None, None)}


# The sample ProCurve's ports rows as the display poll stores them, worked out by hand from W_SAMPLE: the recording has no ifOper,
# ifHighSpeed, LLDP or FDB rows (oper 0, speed 0, no neighbours, no MACs); pvid / untagged / tagged are those of the port's EFFECTIVE
# bridge port (1 -> bp 3, 2 -> bp 1, 3 -> bp 2, 4 / 5 -> Trk1's bp 7, 6 -> bp 5); the lists as json.dumps writes them.
#   ifindex, name, alias, oper, admin, speed, pvid, untagged, tagged, trunk, members, lldp, mac_count, poe_admin, poe_status, poe_power
SAMPLE_STORED = [
    (1, "1", "Platz-107", 0, 1, 0, "20", '["20"]', '["30"]', "", "[]", "[]", 0, None, None, None),
    (2, "2", "", 0, 1, 0, "99", '["99"]', "[]", "", "[]", "[]", 0, None, None, None),
    (3, "3", "", 0, 1, 0, "1", "[]", '["20", "30"]', "", "[]", "[]", 0, None, None, None),
    (4, "4", "", 0, 1, 0, "1", '["1"]', '["20", "30", "99"]', "Trk1", "[]", "[]", 0, None, None, None),
    (5, "5", "", 0, 1, 0, "1", '["1"]', '["20", "30", "99"]', "Trk1", "[]", "[]", 0, None, None, None),
    (6, "6", "unused", 0, 0, 0, "1", '["1"]', "[]", "", "[]", "[]", 0, None, None, None),
    (289, "Trk1", "", 0, 1, 0, "1", '["1"]', '["20", "30", "99"]', "Trk1", '["4", "5"]', "[]", 0, None, None, None),
]


async def test_poll_without_poe_rows_stores_what_it_did_before(world, monkeypatch):
    """A ProCurve without PoE (the PoE walks answer nothing): every port row exactly as before Task 12, pinned by hand (the PoE columns
    stay NULL); and a PoE walk that fails changes nothing either: the display poll is lenient."""
    row = await world.switch("procurve", W_SAMPLE)
    for failing in ((), (POE_ADMIN, POE_STATUS, HP_POE_POWER)):
        monkeypatch.setattr(snmp, "walk", PollAgent(recording(W_SAMPLE), failing).walk)
        assert await poller.poll_switch(row["id"]) == {"ok": True, "ports": 7, "macs": 0}
        async with db.db() as conn:
            async with conn.execute("SELECT ifindex, name, alias, oper, admin, speed, pvid, untagged, tagged, trunk, members, lldp, "
                                    "mac_count, poe_admin, poe_status, poe_power FROM ports WHERE switch_id = ? ORDER BY ifindex",
                                    (row["id"],)) as cur:
                assert [tuple(r) for r in await cur.fetchall()] == SAMPLE_STORED, failing


async def test_poll_tolerates_a_failed_poe_walk(world, monkeypatch):
    """Lenient like every display walk: the admin walk times out, the poll still succeeds and shows the detection status it read."""
    row = await world.switch("procurve", W_POE)
    monkeypatch.setattr(snmp, "walk", PollAgent(recording(W_POE), (POE_ADMIN,)).walk)
    assert (await poller.poll_switch(row["id"]))["ok"] is True
    assert (await stored_poe(row["id"]))[:3] == [("1", None, 3, None), ("2", None, 2, None), ("3", None, 1, None)]


async def test_poll_cisco_poe_through_the_entity_tables(world, monkeypatch):
    W = {**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}
    row = await world.switch("cisco", W)
    poll = PollAgent(recording(W) | {CISCO_POE_POWER: CISCO_POWER_CATALYST})
    monkeypatch.setattr(snmp, "walk", poll.walk)
    await poller.poll_switch(row["id"])
    assert await stored_poe(row["id"]) == [("Po1", None, None, None), ("Gi1/0/1", 1, 3, 6200), ("Gi1/0/2", 2, 1, 0), ("Gi1/0/3", 1, 2, 0),
                                           ("Gi1/0/4", 1, 2, 0)]
    assert {POE_ADMIN, POE_STATUS, CISCO_POE_ENTPHY, ENT_ALIAS, CISCO_POE_POWER} <= set(poll.oids)


@pytest.mark.parametrize("name", ["mikrotik", "generic", "arista"])
async def test_poll_of_a_driver_without_snmp_poe_walks_no_poe(world, monkeypatch, name):
    """R31 / R35: the display poller walks no PoE table for such a switch and shows no PoE state, whatever its agent would answer. (Its
    other walks: poller.O and, its ports being selected by ifType, LLDP-MIB's lldpLocPortTable, R40.)"""
    W = {**W_POE, "ifType": IFTYPE_SAMPLE}
    row = await world.switch(name, W)
    poll = PollAgent(recording(W) | {HP_POE_POWER: HP_POWER_SAMPLE})
    monkeypatch.setattr(snmp, "walk", poll.walk)
    await poller.poll_switch(row["id"])
    assert sorted(poll.oids) == sorted([*poller.O.values(), "1.0.8802.1.1.2.1.3.7.1.3", "1.0.8802.1.1.2.1.3.7.1.4"])
    assert {r[1:] for r in await stored_poe(row["id"])} == {(None, None, None)}


async def test_map_shows_poe_only_where_there_is_some(world, monkeypatch):
    """build_map (the display API): a port with PoE gets "poe" {on, status, mw}; a port without has exactly the keys it had before
    and "uc" (F3, every port) and "bm" (Phase 3 Task 9, every port)."""
    row = await world.switch("procurve", W_POE)
    monkeypatch.setattr(snmp, "walk", PollAgent(recording(W_POE) | {HP_POE_POWER: HP_POWER_SAMPLE}).walk)
    await poller.poll_switch(row["id"])
    ports = {p["n"]: p for p in (await main.build_map())["switches"][0]["ports"]}
    assert ports["1"]["poe"] == {"on": True, "status": 3, "mw": 5400}
    assert ports["3"]["poe"] == {"on": False, "status": 1, "mw": 0}
    assert set(ports["Trk1"]) == {"st", "lim", "n", "a", "o", "ad", "s", "pv", "u", "t", "tr", "mb", "l", "mc", "d", "uc", "bm"}
    assert set(ports["1"]) == set(ports["Trk1"]) | {"poe"}


async def test_map_shows_no_poe_after_the_driver_lost_it(world, monkeypatch):
    """A ProCurve polled with PoE, then switched to driver generic (no snmp_poe, R35) before the next poll: the old poll's PoE columns
    are still in the ports table, but /api/netmap shows no PoE for that switch."""
    row = await world.switch("procurve", W_POE)
    monkeypatch.setattr(snmp, "walk", PollAgent(recording(W_POE) | {HP_POE_POWER: HP_POWER_SAMPLE}).walk)
    await poller.poll_switch(row["id"])
    assert any("poe" in p for p in (await main.netmap(user={"username": "tester"}))["switches"][0]["ports"])
    async with db.db() as conn:
        await conn.execute("UPDATE switches SET driver = 'generic' WHERE id = ?", (row["id"],))
        await conn.commit()
    assert (await stored_poe(row["id"]))[0] == ("1", 1, 3, 5400)    # still stored
    assert not any("poe" in p for p in (await main.netmap(user={"username": "tester"}))["switches"][0]["ports"])


def test_poll_walk_set_of_every_driver():
    """The display poller walks poller.O for every switch, plus the PoE walks (with power) of drivers with snmp_poe."""
    for name, driver in DRIVERS.items():
        extra = poller.poe_walks(driver, power=True)
        assert set(extra.values()).isdisjoint(poller.O.values()), name
        assert bool(extra) is drivers.can(driver, "snmp_poe"), name
    assert set(BASES.values()) <= set(poller.O.values())
    assert IF_TYPE in poller.O.values()
