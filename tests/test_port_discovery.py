"""Tests for driver-aware port discovery: poller.select_ports, the one place that decides which interfaces of a switch are ports and
which trunks (LAGs) they form. The display poller (poller._build, run for every switch on every poll) and the SNMP write path
(snmpwrite.build_cfg / read_cfg) both go through it, so the UI, the inventory and the write path cannot see two different switches.

  * procurve keeps the selection it always had, unchanged: ifIndex below 1000, no name containing VLAN / starting with LO /
    containing LOOPBACK, and trunk members are the interfaces stacked below one named Trk... The oracle is that old code, copied
    here verbatim, run on the Task 7 ProCurve fixtures (sample, odd agent rows, 400 random switches) and on other vendors' layouts,
    with any ifType rows at all: procurve never looks at them.
  * every other driver selects by ifType (IANAifType). 6 ethernetCsmacd and 117 gigabitEthernet are physical ports, 161
    ieee8023adLag is a trunk (Port-channel, ae, Bridge-Aggregation, lag), and its members are the interfaces stacked below it in
    ifStack. So is an interface of type 53 propVirtual or 54 propMultiplexor with a LAG name (in any case) and at least one
    physical port stacked below it (rulings R17 / R17b: classic IOS reports its Port-channels that way). Every other type (VLAN
    interfaces, loopback, null, tunnels, subinterfaces, ...) and every other 53 / 54 is no port, whatever its name. There is no
    ifIndex ceiling (a classic Catalyst numbers its ports from 10101).
  * for a non-ProCurve switch the display and the write path agree on every port, on fixtures and on random switches, and both
    match the random generator's own truth.
  * the wiring: poll_switch walks ifType for every switch and hands the row's driver to _build (empty means procurve). A failed
    ifType walk fails the poll of a switch whose ports depend on it. read_cfg walks ifType (strictly) only for the drivers that
    select by it, so the ProCurve write path gets no new way to fail.

Nothing here touches net-snmp, the network or a switch: snmp.walk is faked, and the poll_switch tests run against an in-memory
database built from db.SCHEMA. Modules are imported flat (app/ is on sys.path via pytest.ini), exactly as the app imports them. The
walk rows, fixtures and generators come from tests/switchfix.py, shared with the other SNMP tests.
"""
import json
import random
from contextlib import asynccontextmanager

import aiosqlite
import pytest

import db
import poller
import snmp
import snmpwrite
from drivers import DRIVERS
from switchfix import (BASES, BP2IF, CATALYST_DISPLAY, CATALYST_PORTS, CATALYST_RECORDING, CATALYST_VMVLAN, ETHERNET, GIGABIT,
                       IF_ADMIN, IF_ALIAS, IF_NAME, IF_STACK, IF_TYPE, L2VLAN, L3IPVLAN, LAG, LOOPBACK, OTHER, PROP_MULTIPLEXOR,
                       PROP_VIRTUAL, PVID, RECORDING, ROW, TUNNEL, VLAN_EGRESS, VLAN_NAME, VLAN_UNTAGGED, VMVLAN, W_CATALYST, W_ODD,
                       W_SAMPLE, edit_walks, random_multivendor_switch, random_procurve_switch, walk_rows)


# Every driver except procurve selects by ifType, and so does a driver name the registry does not know (drivers.driver_for makes it
# generic; poll_switch passes the row's name through as it is).
NON_PROCURVE = [name for name in DRIVERS if name != "procurve"] + ["no-such-driver"]


def _tables(W: dict) -> tuple[dict, dict, dict]:
    """ifName, ifType and ifStack of W as the index tables select_ports takes (poller._tbl strips the base OID)."""
    return poller._tbl(W["ifName"], IF_NAME), poller._tbl(W.get("ifType", []), IF_TYPE), poller._tbl(W["ifStack"], IF_STACK)


def _full(W: dict) -> dict:
    """W with every walk of the display poller (the ones W leaves out are empty), as poll_switch hands it to _build."""
    return {k: W.get(k, []) for k in poller.O}


def _legacy_selection(ifname: dict, ifstack: dict) -> tuple[list, dict, dict]:
    """The port selection of poller._build and snmpwrite.build_cfg before driver-aware discovery (commit fdb02d9), copied verbatim:
    the oracle for procurve."""
    member_of: dict[str, str] = {}
    members: dict[str, list[str]] = {}
    for k in ifstack:
        hi, _, lo = k.partition(".")
        if hi != "0" and lo != "0" and ifname.get(hi, "").startswith("Trk"):
            member_of[lo] = hi
            members.setdefault(hi, []).append(lo)
    ports = []
    for ifi in sorted(ifname, key=lambda x: int(x) if x.isdigit() else 10**9):
        if not ifi.isdigit() or int(ifi) >= 1000:
            continue
        name = ifname[ifi]
        up = name.upper()
        if "VLAN" in up or up.startswith("LO") or "LOOPBACK" in up:
            continue
        ports.append(ifi)
    return ports, member_of, members


def _display(W: dict, *driver: str) -> list[tuple]:
    return [(p["if"], p["name"], p["trunk"], p["members"]) for p in poller._build(_full(W), *driver)["ports"]]


def test_iftype_is_a_poller_walk():
    """ifType is one of the display poller's walks, under the OID the fixtures use, and read as text (not as hex)."""
    assert poller.O["ifType"] == IF_TYPE
    assert "ifType" not in poller.HEX


# ── procurve: exactly the old selection ──────────────────────────────────────────────────────────────────────────────────────────
def _fixtures_for_procurve():
    """(name, W): the ProCurve fixtures of Task 7 (sample, odd agent rows, 400 random switches), and other vendors' layouts (the
    Catalyst, 100 random multivendor switches), which a switch configured as procurve must read exactly as before as well."""
    yield "sample", W_SAMPLE
    yield "odd rows", W_ODD
    yield "catalyst", W_CATALYST
    rng = random.Random(20261104)
    for case in range(400):
        yield f"random procurve {case}", random_procurve_switch(rng)[0]
    for case in range(100):
        yield f"random multivendor {case}", random_multivendor_switch(rng)[0]


def test_procurve_selection_unchanged():
    """select_ports(..., "procurve") is the legacy selection: the same ports in the same order, the same trunk members, and the
    dicts in the same order too (members is the order of cfg["trunks"]). ifType rows change nothing: none, the real ones, every
    interface a LAG, or random types."""
    rng = random.Random(11)
    for name, W in _fixtures_for_procurve():
        ifname, iftype, ifstack = _tables(W)
        ports, member_of, members = _legacy_selection(ifname, ifstack)
        for types in ({}, iftype, {i: LAG for i in ifname}, {i: rng.choice((ETHERNET, LAG, PROP_VIRTUAL, OTHER)) for i in ifname}):
            got = poller.select_ports(ifname, types, ifstack, "procurve")
            assert got[0] == ports, name
            assert list(got[1].items()) == list(member_of.items()), name
            assert list(got[2].items()) == list(members.items()), name


def test_procurve_display_keeps_its_trunk_fields():
    """What the poller stores per ProCurve port: the default driver is procurve; every Trk... port is its own trunk, an empty one
    too (Trk3), and a member names its trunk."""
    assert _display(W_SAMPLE) == _display(W_SAMPLE, "procurve") == [
        (1, "1", "", []), (2, "2", "", []), (3, "3", "", []), (4, "4", "Trk1", []), (5, "5", "Trk1", []), (6, "6", "", []),
        (289, "Trk1", "Trk1", ["4", "5"])]
    assert _display(W_ODD) == [
        (1, "A1", "", []), (2, "A2", "Trk2", []), (3, "A3", "", []), (4, "A4", "Trk2", []), (290, "Trk2", "Trk2", ["A2", "A4"]),
        (291, "Trk3", "Trk3", []), (999, "A99", "", [])]


def test_procurve_display_and_cfg_do_not_depend_on_iftype_rows():
    """A ProCurve's ifType rows (now walked by every poll) change neither the display nor build_cfg, whatever they say; and a W
    without the ifType walk at all (as callers built it before) still works for procurve."""
    W = {**W_SAMPLE, "ifType": walk_rows(IF_TYPE, {"1": LAG, "2": PROP_VIRTUAL, "289": ETHERNET, "1001": ETHERNET, "4097": LAG})}
    assert poller._build(_full(W)) == poller._build(_full(W_SAMPLE))
    assert snmpwrite.build_cfg(W) == snmpwrite.build_cfg(W_SAMPLE)
    without = {k: rows for k, rows in _full(W_SAMPLE).items() if k != "ifType"}
    assert poller._build(without) == poller._build(without, "procurve") == poller._build(_full(W_SAMPLE))


@pytest.mark.parametrize("driver", ["procurve", "cisco"])
def test_ports_come_in_ifindex_order_whatever_the_row_order(driver):
    """The ports are sorted by ifIndex as a number, not taken in the order the ifName / ifType rows came (reversed here; as strings
    "10101" would also sort before "5001"), for the display and for build_cfg alike. (Trunk members keep the ifStack order.)"""
    W = W_CATALYST if driver == "cisco" else W_SAMPLE
    backwards = {k: list(reversed(rows)) if k in ("ifName", "ifType") else rows for k, rows in W.items()}
    assert poller.select_ports(*_tables(backwards), driver)[0] == poller.select_ports(*_tables(W), driver)[0]
    assert _display(backwards, driver) == _display(W, driver)
    assert list(snmpwrite.build_cfg(backwards, driver)[0]["ports"]) == list(snmpwrite.build_cfg(W, driver)[0]["ports"])
    if driver == "cisco":
        assert [name for _, name, _, _ in _display(backwards, driver)] == list(CATALYST_PORTS)


# ── every other driver: by ifType ─────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("driver", NON_PROCURVE)
def test_catalyst_high_ifindex(driver):
    """Every port of a classic Catalyst is found: Po1 at ifIndex 5001 and the Gigabit ports from 10101 on, in ifIndex order, by the
    display and by build_cfg alike. Under the ProCurve rule the ifIndex ceiling drops all of them, and only the SVIs Vl1 and Vl10
    pass its name filter: the defect this fixes."""
    ifname, iftype, ifstack = _tables(W_CATALYST)
    assert poller.select_ports(ifname, iftype, ifstack, driver)[0] == ["5001", "10101", "10102", "10103", "10104"]
    assert poller.select_ports(ifname, iftype, ifstack, "procurve")[0] == ["1", "10"]
    cfg, raw = snmpwrite.build_cfg(W_CATALYST, driver)
    assert cfg["ports"] == CATALYST_PORTS and list(cfg["ports"]) == list(CATALYST_PORTS)
    assert raw["ifindex"] == {"Po1": 5001, "Gi1/0/1": 10101, "Gi1/0/2": 10102, "Gi1/0/3": 10103, "Gi1/0/4": 10104}
    assert raw["unmanaged"] == {}
    assert _display(W_CATALYST, driver) == CATALYST_DISPLAY


def test_catalyst_vmvlan_rows_now_reach_their_ports():
    """With the Catalyst's ports selected, the cisco driver's vmVlan rows (indexed by the ifIndex 10101+) take effect: Gi1/0/1 and
    Gi1/0/2 are access ports (u from vmVlan, no tagged VLANs), the LAG and its members stay Q-BRIDGE ports."""
    cfg, raw = snmpwrite.build_cfg({**W_CATALYST, "vmVlan": CATALYST_VMVLAN}, "cisco", vmvlan_base=VMVLAN)
    assert raw["vmvlan"] == {"Gi1/0/1": "10", "Gi1/0/2": "1"}
    assert {n: (st["u"], st["t"]) for n, st in cfg["ports"].items()} == {
        "Po1": ("1", ["10", "20"]), "Gi1/0/1": ("10", []), "Gi1/0/2": ("1", []), "Gi1/0/3": ("1", ["10", "20"]),
        "Gi1/0/4": ("1", ["10", "20"])}


def _with_interface(name: str, iftype: str | None, stack: dict | None = None) -> dict:
    """A small switch: Gi1/0/1 and Gi1/0/2 (ifIndex 1, 2; bridge ports 1, 2; untagged in VLAN 1), plus one more interface at ifIndex 30,
    well below the ProCurve ceiling, with the given name and ifType (None: no ifType row) and, if given, ifStack rows."""
    return {
        "ifName": walk_rows(IF_NAME, {"1": "Gi1/0/1", "2": "Gi1/0/2", "30": name}),
        "ifType": walk_rows(IF_TYPE, {"1": ETHERNET, "2": ETHERNET, **({"30": iftype} if iftype else {})}),
        "ifAlias": walk_rows(IF_ALIAS, {}),
        "ifAdmin": walk_rows(IF_ADMIN, {"1": "1", "2": "1", "30": "1"}),
        "bp2if": walk_rows(BP2IF, {"1": "1", "2": "2"}),
        "vlanName": walk_rows(VLAN_NAME, {"1": "default"}),
        "vlanEgress": walk_rows(VLAN_EGRESS, {"1": "C0"}),
        "vlanUntagged": walk_rows(VLAN_UNTAGGED, {"1": "C0"}),
        "pvid": walk_rows(PVID, {"1": "1", "2": "1"}),
        "ifStack": walk_rows(IF_STACK, stack or {}),
    }


@pytest.mark.parametrize("name, iftype", [
    ("Vl10", PROP_VIRTUAL),         # a Cisco SVI: the ProCurve name filter lets it through
    ("Nu0", OTHER),                 # Null0: so does it
    ("Lo0", LOOPBACK),
    ("vlan20", L3IPVLAN),           # an AOS-CX / Comware VLAN interface
    ("Gi1/0/1.100", L2VLAN),        # a subinterface
    ("Tunnel0", TUNNEL),
    ("StackPort1", PROP_VIRTUAL),
    ("Fa0", None),                  # an interface without an ifType row: its type is unknown, so it is no port
])
def test_iftype_excludes_virtual(name, iftype):
    """These are no ports for any non-ProCurve driver: not for select_ports, not in build_cfg, not in the display. Stacked over
    Gi1/0/1 (as a VLAN interface or a subinterface is), they make it no member of anything either. (A 53 needs a LAG name as well
    to be a trunk, see the R17 tests; Vl10 and StackPort1 have a physical port below them, but no LAG name.)"""
    W = _with_interface(name, iftype, stack={"30.1": "1"})
    for driver in NON_PROCURVE:
        assert poller.select_ports(*_tables(W), driver) == (["1", "2"], {}, {}), driver
        cfg, _ = snmpwrite.build_cfg(W, driver)
        assert list(cfg["ports"]) == ["Gi1/0/1", "Gi1/0/2"] and cfg["trunks"] == {}, driver
        assert _display(W, driver) == [(1, "Gi1/0/1", "", []), (2, "Gi1/0/2", "", [])], driver


@pytest.mark.parametrize("name, iftype", [
    ("lobby-ap", ETHERNET),         # a renamed port (RouterOS allows any name): the ProCurve filter drops "LO..."
    ("VLAN-Uplink", GIGABIT),       # ... and anything with "VLAN" in it
    ("Trk7", ETHERNET),             # a physical port named Trk... is no trunk outside ProCurve, not even with a port below it
])
def test_the_iftype_decides_not_the_name(name, iftype):
    W = _with_interface(name, iftype, stack={"30.1": "1"})
    for driver in NON_PROCURVE:
        assert poller.select_ports(*_tables(W), driver) == (["1", "2", "30"], {}, {}), driver
        cfg, _ = snmpwrite.build_cfg(W, driver)
        assert list(cfg["ports"]) == ["Gi1/0/1", "Gi1/0/2", name] and cfg["trunks"] == {}, driver
        assert _display(W, driver) == [(1, "Gi1/0/1", "", []), (2, "Gi1/0/2", "", []), (30, name, "", [])], driver


@pytest.mark.parametrize("lag", ["Po1", "ae0", "Bridge-Aggregation1", "lag1"])
def test_lag_members(lag):
    """An ifType-161 interface is a trunk under any vendor's name, and its members are the interfaces stacked below it. build_cfg
    gives each member the LAG's bridge port (56) for its VLANs and PVID, never the one it may own (Gi1/0/4: bp 4, untagged in VLAN
    20, PVID 20). The display names the LAG as its own trunk with its members, and each member's trunk is the LAG."""
    W = edit_walks(W_CATALYST, ifName={"5001": lag})
    _, member_of, members = poller.select_ports(*_tables(W), "cisco")
    assert member_of == {"10103": "5001", "10104": "5001"}
    assert members == {"5001": ["10103", "10104"]}

    cfg, raw = snmpwrite.build_cfg(W, "cisco")
    assert cfg["trunks"] == {lag: ["Gi1/0/3", "Gi1/0/4"]}
    assert raw["port2bp"] == {lag: 56, "Gi1/0/1": 1, "Gi1/0/2": 2, "Gi1/0/3": 56, "Gi1/0/4": 56}
    assert raw["bp2port"] == {1: "Gi1/0/1", 2: "Gi1/0/2", 4: "Gi1/0/4", 56: lag}    # bp 4 is still Gi1/0/4's, just not its effective one
    for member in ("Gi1/0/3", "Gi1/0/4"):
        assert (cfg["ports"][member]["u"], cfg["ports"][member]["t"], raw["pvid"][member]) == ("1", ["10", "20"], "1"), member

    built = {p["name"]: p for p in poller._build(_full(W), "cisco")["ports"]}
    assert (built[lag]["trunk"], built[lag]["members"]) == (lag, ["Gi1/0/3", "Gi1/0/4"])
    assert [(built[m]["trunk"], built[m]["members"], built[m]["untagged"], built[m]["pvid"]) for m in ("Gi1/0/3", "Gi1/0/4")] == [
        (lag, [], ["1"], "1")] * 2


def test_an_empty_lag_is_a_trunk_and_other_stacking_makes_no_members():
    """A LAG without members (Po2: nothing stacked below it) is still a trunk: select_ports lists it with [], and so do
    cfg["trunks"] and the display, so the planner can protect it like any trunk once it checks cfg["trunks"] (Task 9; on ProCurve
    an empty Trk is a trunk by its name). Interfaces
    stacked below something that is no LAG (Gi1/0/1 below the subinterface Gi1/0/1.100, Po1 below the logical unit Po1.0) are no
    members: only what sits directly below a LAG is."""
    W = edit_walks(W_CATALYST, ifName={"5002": "Po2", "10105": "Gi1/0/1.100", "10106": "Po1.0"},
                   ifType={"5002": LAG, "10105": L2VLAN, "10106": PROP_VIRTUAL}, ifAdmin={"5002": "1", "10105": "1", "10106": "1"},
                   ifStack={"0.5002": "1", "5002.0": "1", "0.10105": "1", "10105.10101": "1", "0.10106": "1", "10106.5001": "1"})
    ports, member_of, members = poller.select_ports(*_tables(W), "cisco")
    assert ports == ["5001", "5002", "10101", "10102", "10103", "10104"]
    assert member_of == {"10103": "5001", "10104": "5001"}
    assert list(members.items()) == [("5001", ["10103", "10104"]), ("5002", [])]
    cfg, _ = snmpwrite.build_cfg(W, "cisco")
    assert list(cfg["trunks"].items()) == [("Po1", ["Gi1/0/3", "Gi1/0/4"]), ("Po2", [])]
    assert _display(W, "cisco")[:3] == [(5001, "Po1", "Po1", ["Gi1/0/3", "Gi1/0/4"]), (5002, "Po2", "Po2", []), (10101, "Gi1/0/1", "", [])]


# ── R17: a Port-channel of type 53 (propVirtual) or 54 (propMultiplexor), as classic IOS reports it ─────────────────────────────────
# An interface of ifType 53 or 54 is a LAG when its name is a LAG name and at least one selected physical port (ifType 6 / 117, with
# ifName and numeric ifIndex) is stacked directly below it; then it is a trunk exactly like a 161 LAG. LAG names, in any case, each
# directly followed by a digit: Po, Port-channel (Cisco, Arista, Dell), ae (Juniper), Bridge-Aggregation, BAGG (Comware), lag
# (AOS-CX), ch, Trk. The name and the physical member keep everything else of these types out: SVIs (Vl10), stack ports, logical
# units (ge-0/0/0.0, ae0.0 on its LAG), and a Port-channel that has nothing physical below it.
LAG_NAMES = ["Po1", "Port-channel2", "Port-Channel2", "ae0", "Bridge-Aggregation1", "BAGG1", "lag1", "ch1", "Trk1"]
# The case does not matter (Dell OS10 "port-channel1"), and 54 counts like 53
NAMED_LAGS = ([(name, PROP_VIRTUAL) for name in LAG_NAMES]
              + [("port-channel1", PROP_VIRTUAL), ("po1", PROP_VIRTUAL), ("PO2", PROP_VIRTUAL), ("AE0", PROP_VIRTUAL),
                 ("bridge-aggregation3", PROP_VIRTUAL), ("LAG4", PROP_VIRTUAL), ("CH5", PROP_VIRTUAL), ("trk6", PROP_VIRTUAL),
                 ("Po3", PROP_MULTIPLEXOR), ("Port-Channel7", PROP_MULTIPLEXOR), ("lag8", PROP_MULTIPLEXOR)])


@pytest.mark.parametrize("lag, kind", NAMED_LAGS)
def test_a_propvirtual_port_channel_with_physical_members_is_a_trunk(lag, kind):
    """The Catalyst with its Po1 reported as ifType 53 or 54, under each LAG name in any case: a trunk exactly as with 161. Its
    members are protected (member_of / members, the display names the LAG as their trunk), and build_cfg gives them the LAG's bridge
    port 56 for VLANs and PVID, never Gi1/0/4's own bridge port 4."""
    W = edit_walks(W_CATALYST, ifName={"5001": lag}, ifType={"5001": kind})
    ports, member_of, members = poller.select_ports(*_tables(W), "cisco")
    assert ports == ["5001", "10101", "10102", "10103", "10104"]
    assert member_of == {"10103": "5001", "10104": "5001"} and members == {"5001": ["10103", "10104"]}

    cfg, raw = snmpwrite.build_cfg(W, "cisco")
    assert cfg["trunks"] == {lag: ["Gi1/0/3", "Gi1/0/4"]}
    assert raw["port2bp"] == {lag: 56, "Gi1/0/1": 1, "Gi1/0/2": 2, "Gi1/0/3": 56, "Gi1/0/4": 56}
    assert cfg["ports"] == {(lag if n == "Po1" else n): st for n, st in CATALYST_PORTS.items()}
    assert _display(W, "cisco") == [(5001, lag, lag, ["Gi1/0/3", "Gi1/0/4"]), *CATALYST_DISPLAY[1:3], (10103, "Gi1/0/3", lag, []),
                                    (10104, "Gi1/0/4", lag, [])]
    _assert_agrees_with_the_display(W, "cisco", cfg, raw)


def _catalyst_with(name: str, iftype: str, stack: dict, **edits) -> dict:
    """The Catalyst plus one more interface at ifIndex 30 (admin up) with the given name, ifType and ifStack rows."""
    return edit_walks(W_CATALYST, ifName={"30": name, **edits.pop("ifName", {})}, ifType={"30": iftype, **edits.pop("ifType", {})},
                      ifAdmin={"30": "1"}, ifStack=stack, **edits)


@pytest.mark.parametrize("kind", [PROP_VIRTUAL, PROP_MULTIPLEXOR])
@pytest.mark.parametrize("name, stack, extra", [
    ("Po9", {}, {}),                                      # a Port-channel name, but nothing stacked below it
    ("port-channel9", {"30.0": "1"}, {}),                 # ... and said so explicitly
    ("Po9", {"30.1": "1", "30.10": "1"}, {}),             # only the SVIs Vl1 and Vl10 below it (type 53, no physical ports)
    ("Po9.0", {"30.5001": "1"}, {}),                      # a logical unit on the LAG Po1: a LAG name, but only a LAG below it
    ("ae0.0", {"30.5001": "1"}, {}),                      # the same as Junos names it
    ("Po9", {"30.77": "1"}, {"ifType": {"77": ETHERNET}}),    # ifIndex 77 says ethernet, but has no ifName: no selected port
])
def test_a_propvirtual_lag_name_without_a_physical_member_is_no_trunk(name, stack, extra, kind):
    """A LAG name is not enough: an interface of type 53 or 54 without a selected physical port directly below it is no trunk and no
    port, for every non-ProCurve driver, and the switch reads exactly as without it."""
    W = _catalyst_with(name, kind, stack, **extra)
    for driver in NON_PROCURVE:
        assert poller.select_ports(*_tables(W), driver) == poller.select_ports(*_tables(W_CATALYST), driver), driver
        assert snmpwrite.build_cfg(W, driver) == snmpwrite.build_cfg(W_CATALYST, driver), driver
        assert _display(W, driver) == CATALYST_DISPLAY, driver


@pytest.mark.parametrize("name, iftype", [
    ("Vl10", PROP_VIRTUAL),            # an SVI
    ("StackPort1", PROP_VIRTUAL),
    ("ge-0/0/1.0", PROP_VIRTUAL),      # a logical unit (Junos)
    ("Gi1/0/1.100", PROP_VIRTUAL),     # a subinterface
    ("Port-channel", PROP_VIRTUAL),    # a LAG word, but no digit right after it
    ("PORT-CHANNEL", PROP_VIRTUAL),
    ("Po", PROP_VIRTUAL),
    ("Pool1", PROP_VIRTUAL),
    ("chassis1", PROP_VIRTUAL),
    ("CHASSIS1", PROP_VIRTUAL),
    ("Trunk1", PROP_VIRTUAL),
    ("uplink-Po1", PROP_VIRTUAL),      # a LAG name has to start the name
    ("Vl10", PROP_MULTIPLEXOR),        # the same for type 54
    ("ge-0/0/1.0", PROP_MULTIPLEXOR),
    ("mux1", PROP_MULTIPLEXOR),
    ("Po1", OTHER),                    # a LAG name on any other type than 53, 54 or 161 counts for nothing
    ("Po1", L2VLAN),
    ("port-channel1", TUNNEL),
    ("Trk1", LOOPBACK),
])
def test_a_physical_member_alone_makes_no_trunk(name, iftype):
    """Gi1/0/1 is stacked below each of these, yet none is a trunk or a port: of type 53 or 54 they lack a LAG name, and the LAG
    names count only for types 53 and 54. Gi1/0/1 stays an ordinary port, a member of nothing."""
    W = _with_interface(name, iftype, stack={"30.1": "1"})
    for driver in NON_PROCURVE:
        assert poller.select_ports(*_tables(W), driver) == (["1", "2"], {}, {}), driver
        assert _display(W, driver) == [(1, "Gi1/0/1", "", []), (2, "Gi1/0/2", "", [])], driver


def test_a_junos_logical_unit_is_no_trunk_and_its_port_stays_a_port():
    """Junos: the logical unit ge-0/0/0.0 (ifType 53) sits on the physical port ge-0/0/0, and ae0.0 (53) on the LAG ae0 (161), whose
    members are ge-0/0/1 and ge-0/0/2. Neither unit is a trunk or a port: ge-0/0/0.0 has no LAG name, ae0.0 has only the LAG below
    it. ge-0/0/0 stays an ordinary port with its own bridge port and VLANs; ge-0/0/1 and ge-0/0/2 are members of ae0 and use its
    bridge port."""
    W = {
        "ifName": walk_rows(IF_NAME, {"513": "ge-0/0/0", "514": "ge-0/0/1", "515": "ge-0/0/2", "530": "ge-0/0/0.0", "600": "ae0",
                                      "601": "ae0.0"}),
        "ifType": walk_rows(IF_TYPE, {"513": ETHERNET, "514": ETHERNET, "515": ETHERNET, "530": PROP_VIRTUAL, "600": LAG,
                                      "601": PROP_VIRTUAL}),
        "ifAlias": walk_rows(IF_ALIAS, {"513": "Drucker", "600": "uplink"}),
        "ifAdmin": walk_rows(IF_ADMIN, {"513": "1", "514": "1", "515": "1", "530": "1", "600": "1", "601": "1"}),
        "bp2if": walk_rows(BP2IF, {"1": "513", "2": "600"}),
        "vlanName": walk_rows(VLAN_NAME, {"10": "Daten", "20": "Voice"}),
        "vlanEgress": walk_rows(VLAN_EGRESS, {"10": "C0", "20": "40"}),      # bp 1 (ge-0/0/0) and bp 2 (ae0) in VLAN 10, bp 2 in VLAN 20
        "vlanUntagged": walk_rows(VLAN_UNTAGGED, {"10": "C0", "20": "00"}),
        "pvid": walk_rows(PVID, {"1": "10", "2": "10"}),
        "ifStack": walk_rows(IF_STACK, {"0.530": "1", "530.513": "1", "513.0": "1", "0.601": "1", "601.600": "1", "600.514": "1",
                                        "600.515": "1", "514.0": "1", "515.0": "1"}),
    }
    assert poller.select_ports(*_tables(W), "juniper") == (["513", "514", "515", "600"], {"514": "600", "515": "600"},
                                                           {"600": ["514", "515"]})
    cfg, raw = snmpwrite.build_cfg(W, "juniper")
    assert cfg["trunks"] == {"ae0": ["ge-0/0/1", "ge-0/0/2"]}
    assert raw["port2bp"] == {"ge-0/0/0": 1, "ge-0/0/1": 2, "ge-0/0/2": 2, "ae0": 2}
    assert {n: (st["u"], st["t"], st["name"]) for n, st in cfg["ports"].items()} == {
        "ge-0/0/0": ("10", [], "Drucker"), "ge-0/0/1": ("10", ["20"], ""), "ge-0/0/2": ("10", ["20"], ""), "ae0": ("10", ["20"], "uplink")}
    assert _display(W, "juniper") == [(513, "ge-0/0/0", "", []), (514, "ge-0/0/1", "ae0", []), (515, "ge-0/0/2", "ae0", []),
                                      (600, "ae0", "ae0", ["ge-0/0/1", "ge-0/0/2"])]
    _assert_agrees_with_the_display(W, "juniper", cfg, raw)


@pytest.mark.parametrize("driver", ["cisco", "juniper"])
def test_without_iftype_rows_a_non_procurve_switch_is_a_caller_bug(driver):
    """For a driver that selects by ifType, a W without the ifType walk is a bug of the caller (read_cfg and poll_switch always walk
    it), not a switch without ports: KeyError, like for any other missing walk."""
    W = {k: rows for k, rows in W_CATALYST.items() if k != "ifType"}
    with pytest.raises(KeyError, match="ifType"):
        snmpwrite.build_cfg(W, driver)
    with pytest.raises(KeyError, match="ifType"):
        poller._build({k: W.get(k, []) for k in poller.O if k != "ifType"}, driver)


# ── display and write path agree, also for other vendors ──────────────────────────────────────────────────────────────────────────
def _assert_agrees_with_the_display(W: dict, driver: str, cfg: dict, raw: dict):
    """The oracle of Task 7 for any non-ProCurve driver: poller._build on the very same rows describes every port alike. Q-BRIDGE
    reads only (the poller knows nothing of vmVlan). A trunk is driver-neutral here: the display names a LAG port as its own trunk,
    and exactly those ports are the keys of cfg["trunks"], an empty LAG included."""
    assert "vmVlan" not in W
    built = poller._build(_full(W), driver)
    assert list(cfg["ports"]) == [p["name"] for p in built["ports"]]
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
        assert st["name"] == p["alias"] == raw["alias"].get(n, ""), n
        assert raw["pvid"].get(n, "") == p["pvid"], n
        assert raw["ifindex"][n] == p["if"], n
        if p["trunk"] == n:
            assert cfg["trunks"][n] == p["members"], n
        elif p["trunk"]:
            assert n in cfg["trunks"][p["trunk"]] and p["members"] == [], n
        else:
            assert n not in cfg["trunks"] and p["members"] == [], n
    assert list(cfg["trunks"]) == [p["name"] for p in built["ports"] if p["trunk"] == p["name"]]


@pytest.mark.parametrize("driver", NON_PROCURVE)
def test_build_cfg_agrees_with_poller_non_procurve(driver):
    cfg, raw = snmpwrite.build_cfg(W_CATALYST, driver)
    _assert_agrees_with_the_display(W_CATALYST, driver, cfg, raw)


def test_build_cfg_agrees_with_poller_non_procurve_on_random_switches():
    """build_cfg on 400 random switches of other vendors, each read with a random non-ProCurve driver, against the generator's truth
    (ports, trunks, effective bridge ports, u / t) and against the display poller on the same rows."""
    rng = random.Random(15)
    for case in range(400):
        driver = rng.choice(NON_PROCURVE)
        W, truth = random_multivendor_switch(rng)
        cfg, raw = snmpwrite.build_cfg(W, driver)
        assert list(cfg["ports"]) == truth["ports"], case
        assert list(cfg["trunks"].items()) == list(truth["trunks"].items()), case
        assert raw["port2bp"] == truth["port2bp"] and raw["ifindex"] == truth["ifindex"], case
        assert {n: {"u": st["u"], "t": st["t"]} for n, st in cfg["ports"].items()} == truth["state"], case
        _assert_agrees_with_the_display(W, driver, cfg, raw)


# ── read_cfg: ifType only where it selects ────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", list(DRIVERS))
async def test_read_cfg_walks_iftype_strictly_only_for_drivers_that_select_by_it(monkeypatch, name):
    """procurve: the walks of Task 7 and no ifType walk, so the ProCurve write path has no new way to fail. Every other driver walks
    ifType, strictly like every walk of read_cfg and as text (not hex), and gets its ports from it: on the Catalyst Po1 and the
    Gigabit ports from 10101 on, with Po1 as a trunk."""
    calls = []

    async def fake_walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        calls.append((oid, hex_values, strict))
        return list(CATALYST_RECORDING[oid])

    monkeypatch.setattr(snmp, "walk", fake_walk)
    driver = DRIVERS[name]
    cfg, _ = await snmpwrite.read_cfg(ROW, driver)

    assert all(strict is True for _, _, strict in calls)
    assert len(calls) == len({oid for oid, _, _ in calls})    # no walk twice
    if name == "procurve":
        assert IF_TYPE not in {oid for oid, _, _ in calls}
        assert len(calls) == len(BASES)
        assert list(cfg["ports"]) == ["Vl1", "Vl10"]    # what the ProCurve rule makes of a Catalyst: unchanged, and not our case
    else:
        assert [c for c in calls if c[0] == IF_TYPE] == [(IF_TYPE, False, True)]
        assert len(calls) == len(BASES) + 1 + (driver.vlan_strategy == "cisco_vmps")
        assert list(cfg["ports"]) == list(CATALYST_PORTS)
        assert cfg["trunks"] == {"Po1": ["Gi1/0/3", "Gi1/0/4"]}


# ── poll_switch: ifType for every switch, the row's driver for _build ─────────────────────────────────────────────────────────────
@pytest.fixture
async def app_db(monkeypatch):
    """poller.db() hands out one in-memory database (db.SCHEMA plus the migration, so switches has the driver column), which stays
    open for the whole test; poll locks start empty."""
    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row
    await conn.executescript(db.SCHEMA)
    await db.migrate(conn)

    @asynccontextmanager
    async def one_connection():
        yield conn

    monkeypatch.setattr(poller, "db", one_connection)
    monkeypatch.setattr(poller, "_locks", {})
    yield conn
    await conn.close()


async def _add_switch(conn, driver: str) -> int:
    """A switches row as the UI creates it (no secrets, so poller.creds_of needs no SECRET_KEY), with the given driver value."""
    cur = await conn.execute("INSERT INTO switches (name, host, driver) VALUES (?, ?, ?)", ("SW-TEST", "203.0.113.31", driver))
    await conn.commit()
    return cur.lastrowid


async def _stored_ports(conn, sid: int) -> list[tuple]:
    async with conn.execute("SELECT name, trunk, members FROM ports WHERE switch_id = ? ORDER BY ifindex", (sid,)) as cur:
        return [(r["name"], r["trunk"], json.loads(r["members"])) for r in await cur.fetchall()]


def _agent(monkeypatch, recording: dict, failing: str | None = None) -> list[dict]:
    """snmp.walk answers from `recording` by base OID (nothing for the other walks of the poller); the walk of `failing` times out."""
    calls = []

    async def fake_walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        calls.append({"oid": oid, "hex": hex_values, "strict": strict})
        if oid == failing:
            raise snmp.SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
        return list(recording.get(oid, []))

    monkeypatch.setattr(snmp, "walk", fake_walk)
    return calls


CATALYST_STORED = [(name, trunk, members) for _, name, trunk, members in CATALYST_DISPLAY]


@pytest.mark.parametrize("stored, used", [("cisco", "cisco"), ("juniper", "juniper"), ("no-such-driver", "no-such-driver"),
                                          ("procurve", "procurve"), ("", "procurve")])
async def test_poll_switch_hands_the_rows_driver_to_build(app_db, monkeypatch, stored, used):
    """The display poll of the Catalyst: every walk of poller.O (ifType included) leniently as always, and _build gets the driver
    of the switches row, an empty one meaning procurve. With a non-ProCurve driver its ports land in the ports table; read as
    procurve, the very same answers give only the two SVIs, as before this change."""
    sid = await _add_switch(app_db, stored)
    calls = _agent(monkeypatch, CATALYST_RECORDING)
    seen, build = [], poller._build

    def spy(W, driver_name="procurve"):
        seen.append(driver_name)
        return build(W, driver_name)

    monkeypatch.setattr(poller, "_build", spy)
    result = await poller.poll_switch(sid)

    assert result["ok"] is True and seen == [used]
    assert IF_TYPE in {c["oid"] for c in calls}
    assert sorted(c["oid"] for c in calls) == sorted(poller.O.values())
    assert not any(c["strict"] for c in calls)
    assert {c["oid"]: c["hex"] for c in calls}[IF_TYPE] is False
    want = [("Vl1", "", []), ("Vl10", "", [])] if used == "procurve" else CATALYST_STORED
    assert await _stored_ports(app_db, sid) == want


@pytest.mark.parametrize("driver", ["cisco", "procurve"])
async def test_a_failed_iftype_walk_fails_the_poll_only_where_the_ports_depend_on_it(app_db, monkeypatch, driver):
    """Without ifType a non-ProCurve switch would have no ports at all, so the poll fails like on a failed ifName walk (error on the
    switch, the ports of the last good poll stay). A ProCurve does not use ifType: the poll goes through as before."""
    sid = await _add_switch(app_db, driver)
    await app_db.execute("INSERT INTO ports (switch_id, ifindex, name) VALUES (?, ?, ?)", (sid, 10101, "Gi1/0/1"))    # last good poll
    await app_db.commit()
    recording = CATALYST_RECORDING if driver == "cisco" else RECORDING
    _agent(monkeypatch, recording, failing=IF_TYPE)

    result = await poller.poll_switch(sid)

    async with app_db.execute("SELECT last_poll_ok, last_error FROM switches WHERE id = ?", (sid,)) as cur:
        status = tuple(await cur.fetchone())
    async with app_db.execute("SELECT name FROM ports WHERE switch_id = ? ORDER BY ifindex", (sid,)) as cur:
        names = [r["name"] for r in await cur.fetchall()]
    if driver == "cisco":
        assert result == {"ok": False, "error": "Zeitüberschreitung bei der SNMP-Abfrage"}
        assert status == (0, "Zeitüberschreitung bei der SNMP-Abfrage")
        assert names == ["Gi1/0/1"]    # the ports of the last good poll stay
    else:
        assert result["ok"] is True and status == (1, None)
        assert names == ["1", "2", "3", "4", "5", "6", "Trk1"]
