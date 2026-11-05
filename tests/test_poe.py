"""Task 12: PoE on / off over SNMP (pethPsePortAdminEnable, POWER-ETHERNET-MIB / RFC 3621) end to end, and the PoE state and power per
port for the display.

A PoE SET cuts or restores the power of a phone, an access point or a camera on a live switch, and a SET on the wrong PoE entry powers
off another device. RFC 3621 indexes a PoE entry by <pethPsePortGroupIndex>.<pethPsePortIndex> and does not relate that to any
ifIndex. So what these tests pin hardest is poller.poe_ports, the one mapping from PoE entries to ports, shared by the display poller
(poller._build) and the write path (snmpwrite.build_cfg / read_cfg). It fails closed: an entry it cannot map with certainty belongs to
no port, and a port without a mapped entry has no PoE: no state on display, and every PoE write is refused with the reason
(snmpwrite.snmp_block_reason).
  * driver.poe_index "ifindex" (the default; ProCurve / AOS-S use the ifIndex as the PoE port index): group 1 and pethPsePortIndex =
    the ifIndex of a physical port. An entry of another group (a stack member, a module) belongs to no port. If an entry of group 1
    points at no physical port (no interface, a VLAN interface, a trunk), the assumption does not hold on this switch (port numbers
    instead of ifIndexes, say) and NO entry is mapped.
  * "cisco_entity" (driver cisco): CISCO-POWER-ETHERNET-EXT-MIB cpeExtPsePortEntPhyIndex names the entry's port entity, ENTITY-MIB
    entAliasMappingIdentifier maps that to ifIndex.N. Missing, zero, not an ifIndex, several ifIndexes, no physical port: no port.
  * two entries on one port: neither counts.
  * mikrotik has no snmp_poe (R31): no PoE walk, no PoE state, PoE writes refused.
Around it: the display poll (lenient, ports.poe_admin / poe_status / poe_power, mW from hpicfPoePethPsePortPower or
cpeExtPsePortPwrConsumption), the strict live read (an absent PoE table is no PoE, a present but inconsistent one fails closed),
render_ops (pethPsePortAdminEnable.<group>.<port> i 1 / 2), planning (PortChange.poe, needed_ops, the SSH branch never plans PoE),
routing R30 (PoE goes over SNMP for every driver, ProCurve included, or 422 with the reason), run_change verifying PoE on read-back and
a revert that restores it.

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


def display(W: dict, driver: str = "procurve") -> list[tuple]:
    """What the display poller stores per port, PoE columns only: (name, poe_admin, poe_status, poe_power)."""
    full = {k: W.get(k, []) for k in poller.O} | {k: W[k] for k in W if k not in poller.O}
    return [(p["name"], p["poe_admin"], p["poe_status"], p["poe_power"]) for p in poller._build(full, driver)["ports"]]


# ── The mapping: poller.poe_ports ────────────────────────────────────────────────────────────────────────────────────────────────
def test_poe_walks_per_driver():
    """What the poller and read_cfg walk for PoE, from the driver's OIDs (R4): the two RFC 3621 columns for every driver with
    snmp_poe, the entity mapping for cisco, the power column (display only) where a vendor MIB has one; nothing for mikrotik (R31)."""
    std = {"poeAdmin": POE_ADMIN, "poeStatus": POE_STATUS}
    entity = {"poeEntPhy": CISCO_POE_ENTPHY, "entAlias": ENT_ALIAS}
    assert poller.poe_walks(PROCURVE) == std
    assert poller.poe_walks(PROCURVE, power=True) == {**std, "poePower": HP_POE_POWER}
    assert poller.poe_walks(CISCO) == {**std, **entity}
    assert poller.poe_walks(CISCO, power=True) == {**std, **entity, "poePower": CISCO_POE_POWER}
    for name, driver in DRIVERS.items():
        if name in ("procurve", "cisco", "mikrotik"):
            continue
        assert poller.poe_walks(driver) == poller.poe_walks(driver, power=True) == std, name    # no power OID sourced for them
    assert poller.poe_walks(MIKROTIK) == poller.poe_walks(MIKROTIK, power=True) == {}


def test_default_mapping_group_1_index_is_the_ifindex():
    """ProCurve, modular naming (W_ODD: A1 = ifIndex 1, A99 = ifIndex 999): entry 1.<n> belongs to the port with ifIndex n, whatever its
    name, and the result is keyed by ifIndex; admin / status / power come from the entry's own rows."""
    got, unmapped = poller.poe_ports(PROCURVE, tables(poeAdmin={"1.1": "1", "1.999": "2"}, poeStatus={"1.1": "3", "1.999": "1"},
                                                      poePower={"1.1": "4100", "1.999": "0"}), ["1", "2", "3", "4", "999"])
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


def test_catalyst_numbering_is_unmappable_by_default():
    """Classic IOS numbers PoE entries by the port number on the stack member (1.1-1.4) while the ports have ifIndex 10101-10104;
    1.1 even is an ifIndex, of Vl1. With the default mapping (here: generic) nothing is mapped, never Vl1 or a wrong port."""
    cfg, raw = read(W_CATALYST_POE, "generic")
    assert raw["poe"] == {} and set(poe_of(cfg).values()) == {None}
    assert raw["poe_unmapped"] == ["1.1", "1.2", "1.3", "1.4"]
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
    assert list(read(W, "generic")[1]["poe"]) == ["Gi1/0/1", "Gi1/0/2"]    # by ifIndex: the default holds here


def test_mikrotik_has_no_poe():
    """R31: no PoE walks, so neither the display nor the write path sees PoE on a mikrotik, whatever its agent would answer."""
    W = {**W_POE, "ifType": IFTYPE_SAMPLE}
    cfg, raw = read(W, "mikrotik")
    assert raw["poe"] == {} and raw["poe_unmapped"] == [] and set(poe_of(cfg).values()) == {None}
    assert {p[1:] for p in display({**W, "poePower": HP_POWER_SAMPLE}, "mikrotik")} == {(None, None, None)}
    assert snmpwrite.snmp_block_reason(MIKROTIK, cfg, raw, "1", {"poe": False}) == MIKROTIK_NO_POE


def test_an_unknown_mapping_strategy_maps_nothing():
    odd = Driver("odd", GENERIC.caps, "qbridge", dict(GENERIC.oids), "", poe_index="by-name")
    got, unmapped = poller.poe_ports(odd, tables(poeAdmin={"1.1": "1"}, poeStatus={"1.1": "2"}), ["1"])
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


def test_poe_mapping_properties_on_random_switches():
    """800 random switches (ProCurve and other vendors) with random PoE tables, every driver with PoE. Whatever the tables say:
      * a mapped entry belongs to a PHYSICAL port (never a trunk, a VLAN interface, nothing), no port has two entries, no entry two ports;
      * mapped and unmapped entries are disjoint and together all entries;
      * ifindex maps only group 1 with index = the port's ifIndex, and either every entry of group 1 or none;
      * cisco_entity maps only along cpeExtPsePortEntPhyIndex -> exactly one ifIndex.N of that entity (never entity 0);
      * the display (lenient) and the write path (strict, when it does not refuse the read) see the same PoE on every port."""
    rng = random.Random(1212)
    seen = {"mapped": 0, "voided": 0, "refused": 0}
    for case in range(800):
        if rng.random() < 0.5:
            W, _ = random_procurve_switch(rng)
            selection = "procurve"
        else:
            W, _ = random_multivendor_switch(rng)
            selection = rng.choice(["generic", "cisco", "cisco", "arista", "juniper"])
        driver = DRIVERS[selection]
        ifname = poller._tbl(W["ifName"], WALK_BASES["ifName"])
        ports, _, members = poller.select_ports(ifname, poller._tbl(W.get("ifType", []), IF_TYPE),
                                                poller._tbl(W["ifStack"], WALK_BASES["ifStack"]), selection)
        physical = [i for i in ports if i not in poller.trunk_ports(ifname, ports, members, selection)]
        # half the time a clean switch whose PoE indexes are physical ports' ifIndexes, else any interface (or none) of the switch
        rows, cols = _random_poe(rng, physical if rng.random() < 0.5 else [i for i in ifname if i.isdigit()])
        W = {**W, **rows}
        found, unmapped = poller.poe_ports(driver, cols, physical)
        entries = set(cols["poeAdmin"])
        assert set(found) <= set(physical), case
        mapped = {f"{e['group']}.{e['index']}": ifi for ifi, e in found.items()}
        assert len(mapped) == len(found) and not set(mapped) & set(unmapped) and set(mapped) | set(unmapped) == entries, case
        if driver.poe_index == "ifindex":
            assert all(k == f"1.{ifi}" for k, ifi in mapped.items()), case
            group1 = {k for k in entries if k.startswith("1.")}
            assert set(mapped) in (group1, set()), case
            seen["voided"] += bool(group1) and not mapped
        else:
            alias = cols["entAlias"]
            for k, ifi in mapped.items():
                e = cols.get("poeEntPhy", {}).get(k)
                assert e not in (None, "0"), case
                assert {v.rpartition(".")[2] for a, v in alias.items() if a.partition(".")[0] == e} == {ifi}, case
        seen["mapped"] += len(mapped)
        display_poe = {p["name"]: p["poe_admin"] for p in poller._build({k: W.get(k, []) for k in poller.O} | rows, selection)["ports"]}
        try:
            cfg, raw = snmpwrite.build_cfg(W, selection)
        except snmp.SnmpError:
            seen["refused"] += 1
            continue
        assert {n: (None if st["poe"] is None else 1 if st["poe"] else 2) for n, st in cfg["ports"].items()} == display_poe, case
        assert raw["poe_unmapped"] == unmapped, case
    assert seen["mapped"] > 300 and seen["voided"] > 20 and seen["refused"] > 5, seen


def test_display_mapping_is_lenient():
    """The display takes what it can read: an entry with only a status row (the admin walk failed) still shows its status, unreadable
    values show as None, a malformed index is skipped; the write path refuses the same rows (below)."""
    got, unmapped = poller.poe_ports(PROCURVE, tables(poeAdmin={"1.1": "1", "1.2": "x", "1.x": "1"}, poeStatus={"1.1": "3", "1.3": "2"},
                                                      poePower={"1.1": "-5", "1.2": "abc"}), ["1", "2", "3"])
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
    ("generic", {**W_POE, "ifType": IFTYPE_SAMPLE}, [POE_ADMIN, POE_STATUS]),
    ("cisco", {**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, [POE_ADMIN, POE_STATUS, CISCO_POE_ENTPHY, ENT_ALIAS]),
    ("mikrotik", {**W_POE, "ifType": IFTYPE_SAMPLE}, []),
])
async def test_read_cfg_walks_poe_strictly(monkeypatch, name, W, poe):
    """read_cfg walks the PoE tables of the driver (never the power: display only), strictly and as text, with every other walk; the
    result is build_cfg of what the agent answered."""
    fake = FakeAgent(agent(W))
    monkeypatch.setattr(snmp, "walk", fake.walk)
    cfg, raw = await snmpwrite.read_cfg({**ROW, "driver": name}, DRIVERS[name])
    walked = [oid for oid, _, _ in fake.calls]
    poe_ish = {POE_ADMIN, POE_STATUS, CISCO_POE_ENTPHY, ENT_ALIAS, HP_POE_POWER, CISCO_POE_POWER}
    assert sorted(oid for oid in walked if oid in poe_ish) == sorted(poe)
    assert all(strict for _, _, strict in fake.calls) and not any(hx for oid, hx, _ in fake.calls if oid in poe)
    assert len(walked) == len(set(walked))
    selection = {k: rows for k, rows in agent(W).items() if k not in POE_WALKS or WALK_BASES[k] in poe}
    assert (cfg, raw) == ({**read(selection, name, text_hex=True)[0], "hostname": "SW-EK-01"}, read(selection, name, text_hex=True)[1])


@pytest.mark.parametrize("failing", [POE_ADMIN, POE_STATUS])
async def test_read_cfg_fails_closed_when_a_poe_walk_fails(monkeypatch, failing):
    """A PoE walk cut short (snmp.walk strict raises) fails the read like any other walk: no cfg without PoE state, even for a change
    that is not about PoE (the write path never works from partial data)."""
    monkeypatch.setattr(snmp, "walk", FakeAgent(agent(W_POE), failing).walk)
    with pytest.raises(snmp.SnmpError, match="Zeitüberschreitung"):
        await snmpwrite.read_cfg(ROW, PROCURVE)


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
    pytest.param(agent(edit_walks(W_POE, pvid={"3": "1"})), "procurve", PROCURVE, "1", False,
                 "PVID 1 weicht vom ungetaggten VLAN 20 ab (Fehlkonfiguration oder dynamisch per 802.1X/RADIUS zugewiesen) – per SNMP nicht "
                 "verwaltbar", id="unmanaged"),
])
def test_poe_refused(W, selection, driver, port, value, reason):
    """Every PoE refusal comes from snmp_block_reason: render_ops raises it for the port, nothing rendered."""
    cfg, raw = read(W, selection, text_hex=True)
    assert snmpwrite.snmp_block_reason(driver, cfg, raw, port, {"poe": value}) == reason
    with pytest.raises(ValueError) as refused:
        snmpwrite.render_ops(driver, cfg, raw, {port: {"poe": value}})
    assert str(refused.value) == f"Port {port}: {reason}"


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
    switch answers but takes nothing; after_set: what else changes right after the SET). Records walks, SETs and every SSH-side call."""

    def __init__(self):
        self.W: dict = {}
        self.selection = "procurve"
        self.walks: list = []
        self.sets: list = []
        self.ssh: list = []
        self.set_mode, self.after_set = "apply", None

    async def walk(self, host, cred, oid, hex_values=False, timeout=60, strict=False):
        assert (host, strict) == (HOST, True), (host, strict)
        self.walks.append((oid, cred))
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
    """A fresh database under tmp_path; SNMP answered by the World's switch; changes.fresh_cfg (the SSH read of a preview) recorded;
    re-polls never run; fresh locks; every SSH entry point a trap that records and raises."""
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

    monkeypatch.setattr(snmp, "walk", w.walk)
    monkeypatch.setattr(snmp, "set_vars", w.set_vars)
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
], ids=["procurve-snmp-off", "procurve-read-community", "cisco-snmp-off", "mikrotik"])
async def test_poe_without_snmp_write_access_is_422(world, driver, kw, reason):
    """No way to write PoE over SNMP: 422 with the reason, before any read; never an SSH attempt."""
    W = {"procurve": POE_SW, "cisco": agent({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}),
         "mikrotik": agent({**W_POE, "ifType": IFTYPE_SAMPLE})}[driver]
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


async def test_poe_change_on_the_catalyst(world):
    """cisco: the entry found through the entity tables (Gi1/0/2 = 1.2), saved=0 with the R26 warning (no autosave)."""
    row = await world.switch("cisco", agent({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}))
    cid, plan = await apply(world, row, {"ports": ["Gi1/0/2"], "change": {"poe": True}})
    assert plan["shown"] == ["Port Gi1/0/2: PoE aus → an"]
    ch = await run(cid)
    assert (ch["status"], ch["saved"]) == ("ok", 0)
    assert world.sets == [(HOST, RW_CRED, [(f"{POE_ADMIN}.1.2", "i", "1")])]


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


async def test_poll_without_poe_rows_stores_what_it_did_before(world, monkeypatch):
    """A ProCurve without PoE (the PoE walks answer nothing): every port row exactly as before Task 12 (the PoE columns stay NULL, all
    other columns what _build gives), and a PoE walk that fails changes nothing either: the display poll is lenient."""
    row = await world.switch("procurve", W_SAMPLE)
    for failing in ((), (POE_ADMIN, POE_STATUS, HP_POE_POWER)):
        monkeypatch.setattr(snmp, "walk", PollAgent(recording(W_SAMPLE), failing).walk)
        assert await poller.poll_switch(row["id"]) == {"ok": True, "ports": 7, "macs": 0}
        async with db.db() as conn:
            async with conn.execute("SELECT * FROM ports WHERE switch_id = ? ORDER BY ifindex", (row["id"],)) as cur:
                rows = [dict(r) for r in await cur.fetchall()]
        built = poller._build({k: recording(W_SAMPLE).get(base, []) for k, base in poller.O.items()})["ports"]
        assert [(r["poe_admin"], r["poe_status"], r["poe_power"]) for r in rows] == [(None, None, None)] * 7
        assert [{k: v for k, v in r.items() if not k.startswith("poe_")} for r in rows] == [
            {"switch_id": row["id"], "ifindex": p["if"], "name": p["name"], "alias": p["alias"], "oper": p["oper"], "admin": p["admin"],
             "speed": p["speed"], "pvid": p["pvid"], "untagged": json.dumps(p["untagged"]), "tagged": json.dumps(p["tagged"]),
             "trunk": p["trunk"], "members": json.dumps(p["members"]), "lldp": json.dumps(p["lldp"]), "mac_count": p["mac_count"]}
            for p in built]


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


async def test_poll_mikrotik_walks_no_poe(world, monkeypatch):
    W = {**W_POE, "ifType": IFTYPE_SAMPLE}
    row = await world.switch("mikrotik", W)
    poll = PollAgent(recording(W) | {HP_POE_POWER: HP_POWER_SAMPLE})
    monkeypatch.setattr(snmp, "walk", poll.walk)
    await poller.poll_switch(row["id"])
    assert sorted(poll.oids) == sorted(poller.O.values())
    assert {r[1:] for r in await stored_poe(row["id"])} == {(None, None, None)}


async def test_map_shows_poe_only_where_there_is_some(world, monkeypatch):
    """build_map (the display API): a port with PoE gets "poe" {on, status, mw}; a port without has exactly the keys it had before."""
    row = await world.switch("procurve", W_POE)
    monkeypatch.setattr(snmp, "walk", PollAgent(recording(W_POE) | {HP_POE_POWER: HP_POWER_SAMPLE}).walk)
    await poller.poll_switch(row["id"])
    ports = {p["n"]: p for p in (await main.build_map())["switches"][0]["ports"]}
    assert ports["1"]["poe"] == {"on": True, "status": 3, "mw": 5400}
    assert ports["3"]["poe"] == {"on": False, "status": 1, "mw": 0}
    assert set(ports["Trk1"]) == {"st", "lim", "n", "a", "o", "ad", "s", "pv", "u", "t", "tr", "mb", "l", "mc", "d"}
    assert set(ports["1"]) == set(ports["Trk1"]) | {"poe"}


def test_poll_walk_set_of_every_driver():
    """The display poller walks poller.O for every switch, plus the PoE walks (with power) of drivers with snmp_poe."""
    for name, driver in DRIVERS.items():
        extra = poller.poe_walks(driver, power=True)
        assert set(extra.values()).isdisjoint(poller.O.values()), name
        assert bool(extra) is drivers.can(driver, "snmp_poe"), name
    assert set(BASES.values()) <= set(poller.O.values())
    assert IF_TYPE in poller.O.values()
