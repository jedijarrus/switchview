"""Tests for app/drivers.py, the vendor driver registry.

The registry is plain data, yet it decides two things that matter on a live switch: which paths exist for a device at all (the
SSH-CLI path, NAC and config backup are ProCurve-only and must never show up on a SNMP-only driver) and which OID a SNMP write
is sent to (a wrong OID base is a write to the wrong object). So the tests pin the capability table, the VLAN strategy per
driver, every OID value and the way a switches row becomes a driver.

The expected values are written out here by hand, independent of app/drivers.py. The OID bases were checked against the MIB
definitions: Q-BRIDGE-MIB (RFC 2674 / 4363), IF-MIB (RFC 2863), POWER-ETHERNET-MIB (RFC 3621), CISCO-VLAN-MEMBERSHIP-MIB, and for PoE
(Task 12) HP-ICF-POE-MIB, CISCO-POWER-ETHERNET-EXT-MIB (Cisco's own cisco-mibs repository) and ENTITY-MIB (RFC 6933).
Nothing here needs net-snmp, a network or an environment. The modules are imported flat (app/ is on sys.path via pytest.ini),
exactly as the app imports them.
"""
import dataclasses
import re
import sqlite3

import pytest

import poller
from drivers import DRIVERS, Driver, can, driver_for

# The drivers the registry has to offer (spec 1), in the order a driver dropdown would show them.
NAMES = ["procurve", "aruba_cx", "cisco", "cisco_sb", "comware", "juniper", "arista", "dell", "netgear", "mikrotik", "generic"]

SNMP_CAPS = {"snmp_vlan", "snmp_admin", "snmp_name"}
# PoE only where the mapping of a PoE entry to its port is sourced (R35): ProCurve (index = ifIndex) and Cisco (ENTITY-MIB). Every other
# driver has none: mikrotik is not known to expose PoE through POWER-ETHERNET-MIB at all (R31), and for the rest an offset numbering
# could map every entry to SOME physical port, the wrong one, and the read-back would confirm it (it reads through the same mapping).
POE_CAPS = {"snmp_poe"}
POE_DRIVERS = {"procurve", "cisco"}
CLI_CAPS = {"cli", "nac", "backup"}    # only reachable through the SSH CLI, so only the ProCurve driver may have them
# R26: whether an SNMP set persists depends on the device. ProCurve / AOS-S saves it by itself (implicit write memory); for no other
# driver is that confirmed, so only ProCurve has it.
AUTOSAVE_CAPS = {"snmp_autosave"}
ALL_CAPS = SNMP_CAPS | POE_CAPS | CLI_CAPS | AUTOSAVE_CAPS
STRATEGIES = {"qbridge", "cisco_vmps"}

# Base OIDs: no instance index (callers append ".<index>"), no leading dot (snmp._parse and poller.O work without one).
# Every driver starts from this standard profile; the comment names the MIB object, its type and the instance index.
STANDARD_OIDS = {
    "pvid": "1.3.6.1.2.1.17.7.1.4.5.1.1",         # dot1qPvid, Unsigned32, .<bridge port> (dot1dBasePort, not the ifIndex)
    "egress": "1.3.6.1.2.1.17.7.1.4.3.1.2",       # dot1qVlanStaticEgressPorts, PortList, .<vlan id>
    "untagged": "1.3.6.1.2.1.17.7.1.4.3.1.4",     # dot1qVlanStaticUntaggedPorts, PortList, .<vlan id>
    "ifadmin": "1.3.6.1.2.1.2.2.1.7",             # ifAdminStatus, 1 = up / 2 = down, .<ifIndex>
    "ifalias": "1.3.6.1.2.1.31.1.1.1.18",         # ifAlias, DisplayString, .<ifIndex>
    # POWER-ETHERNET-MIB: pethPsePortEntry is 1.3.6.1.2.1.105.1.1.1 and its columns follow directly (AdminEnable = 3,
    # DetectionStatus = 6), instance .<group>.<port> (R4). Not ...105.1.1.1.1.3 / ...1.6 with one ".1" more: ...105.1.1.1.1 is the
    # index column pethPsePortGroupIndex (not-accessible), so a SET to that OID could never take effect.
    "poe_admin": "1.3.6.1.2.1.105.1.1.1.3",       # pethPsePortAdminEnable, TruthValue 1 = on / 2 = off
    "poe_status": "1.3.6.1.2.1.105.1.1.1.6",      # pethPsePortDetectionStatus
}
VMVLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"    # vmVlan (CISCO-VLAN-MEMBERSHIP-MIB), INTEGER 0..4095, .<ifIndex>
# PoE beyond RFC 3621 (Task 12), only where a vendor MIB defines it. Both power tables AUGMENT pethPsePortEntry (index .<group>.<port>).
#   HP-ICF-POE-MIB: hpicfCommon = 1.3.6.1.4.1.11.2.14.11.1 (HP-ICF-OID), hpicfPOE = { hpicfCommon 9 }, hpicfPoe = { hpicfPOE 1 },
#   hpicfPoePethPsePortTable = { hpicfPoe 1 }, its entry .1, hpicfPoePethPsePortPower = { entry 3 }: "Power supplied at this port", mW
HP_POE_POWER = "1.3.6.1.4.1.11.2.14.11.1.9.1.1.1.3"
#   CISCO-POWER-ETHERNET-EXT-MIB = { ciscoMgmt 402 } = 1.3.6.1.4.1.9.9.402, cpeExtPsePortTable = { cpeExtMIBObjects 2 }, entry .1:
#   cpeExtPsePortPwrConsumption = { entry 9 } (Unsigned32, milliwatts), cpeExtPsePortEntPhyIndex = { entry 11 } (entPhysicalIndex of the
#   PSE port, 0 = none). (One third-party MIB browser lists them as .8 and .10; Cisco's own MIB file says 9 and 11.)
CISCO_POE_POWER = "1.3.6.1.4.1.9.9.402.1.2.1.9"
CISCO_POE_ENTPHY = "1.3.6.1.4.1.9.9.402.1.2.1.11"
#   ENTITY-MIB (RFC 6933): entAliasMappingIdentifier = { entAliasMappingEntry 2 }, entry = entAliasMappingTable.1 = entityMapping.2.1,
#   entityMapping = entityMIBObjects.3 = mib-2.47.1.3; index .<entPhysicalIndex>.<entAliasLogicalIndexOrZero>, value ifIndex.<N>
ENT_ALIAS = "1.3.6.1.2.1.47.1.3.2.1.2"
# The extra OIDs per driver, on top of STANDARD_OIDS
EXTRA_OIDS = {
    "procurve": {"poe_power": HP_POE_POWER},
    "cisco": {"vmvlan": VMVLAN, "poe_power": CISCO_POE_POWER, "poe_entphy": CISCO_POE_ENTPHY, "ent_alias": ENT_ALIAS},
}
# How a PoE entry finds its port (poller.poe_ports): by ifIndex on procurve, through ENTITY-MIB on cisco, not at all elsewhere
POE_INDEX = {"procurve": "ifindex", "cisco": "cisco_entity"}


def _sqlite_rows(sql: str, *rows: tuple) -> list[sqlite3.Row]:
    """Insert one switches row per tuple (just its driver value) and return what `sql` selects, as db.py hands rows to the app.

    db.py sets row_factory = aiosqlite.Row, and aiosqlite.Row is sqlite3.Row, so this is the type driver_for really receives."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE switches (id INTEGER PRIMARY KEY, driver TEXT)")
    conn.executemany("INSERT INTO switches (driver) VALUES (?)", rows)
    result = conn.execute(sql).fetchall()
    conn.close()
    return result


def test_registry_has_the_planned_drivers():
    assert set(DRIVERS) == set(NAMES)
    for key, driver in DRIVERS.items():
        assert driver.name == key


def test_driver_shape():
    assert [f.name for f in dataclasses.fields(Driver)] == ["name", "caps", "vlan_strategy", "oids", "notes", "poe_index"]
    assert Driver(name="x", caps=frozenset(), vlan_strategy="qbridge", oids={}, notes="n").poe_index == "none"    # the default maps nothing
    for key, driver in DRIVERS.items():
        assert isinstance(driver.caps, frozenset), key
        assert isinstance(driver.notes, str) and driver.notes.strip(), key
    # frozen: checked on a throwaway instance, so a failure here cannot leak a changed driver into the other tests
    fresh = Driver(name="x", caps=frozenset(), vlan_strategy="qbridge", oids={}, notes="n")
    with pytest.raises(dataclasses.FrozenInstanceError):
        fresh.name = "y"


def test_procurve_caps():
    procurve = DRIVERS["procurve"]
    assert can(procurve, "cli") and can(procurve, "nac") and can(procurve, "snmp_vlan")
    assert procurve.caps == ALL_CAPS
    assert procurve.vlan_strategy == "qbridge"


def test_cisco_is_snmp_only():
    cisco = DRIVERS["cisco"]
    assert not can(cisco, "cli")
    assert can(cisco, "snmp_vlan")
    assert cisco.vlan_strategy == "cisco_vmps"
    assert not can(cisco, "nac") and not can(cisco, "backup")


@pytest.mark.parametrize("name", NAMES)
def test_capability_table(name):
    # all eight capabilities asked through can(), not only read from .caps: ProCurve has all, everyone else the three snmp_* write ones
    # (no snmp_autosave: R26), cisco with snmp_poe as well (R35)
    driver = DRIVERS[name]
    expected = ALL_CAPS if name == "procurve" else SNMP_CAPS | POE_CAPS if name in POE_DRIVERS else SNMP_CAPS
    assert {op for op in ALL_CAPS if can(driver, op)} == expected
    assert driver.caps == expected


def test_can_answers_no_for_unknown_operations():
    procurve = DRIVERS["procurve"]
    assert can(procurve, "cli") is True
    assert can(procurve, "reboot") is False
    assert can(procurve, "") is False


def test_vlan_strategy_per_driver():
    # only classic Cisco IOS writes the access VLAN through vmVlan; Small Business is not IOS and uses Q-BRIDGE like the rest
    assert {n for n, d in DRIVERS.items() if d.vlan_strategy == "cisco_vmps"} == {"cisco"}
    assert {d.vlan_strategy for d in DRIVERS.values()} <= STRATEGIES


def test_driver_for_defaults():
    # an unknown driver name falls back to generic: standard MIBs only, no CLI
    assert driver_for({"driver": "no_such_vendor"}) is DRIVERS["generic"]
    # legacy rows (NULL or empty, from before the driver column existed) stay on procurve, i.e. keep the SSH behaviour they had
    assert driver_for({"driver": None}) is DRIVERS["procurve"]
    assert driver_for({"driver": ""}) is DRIVERS["procurve"]


@pytest.mark.parametrize("name", NAMES)
def test_driver_for_resolves_every_registered_name(name):
    assert driver_for({"driver": name}) is DRIVERS[name]


def test_driver_for_reads_a_real_sqlite_row():
    rows = _sqlite_rows("SELECT * FROM switches ORDER BY id", (None,), ("",), ("cisco",), ("no_such_vendor",))
    assert [driver_for(r).name for r in rows] == ["procurve", "procurve", "cisco", "generic"]


def test_driver_for_does_not_guess_when_the_column_is_missing():
    # NULL / empty mean "legacy row: procurve". A row without any driver column is a query that forgot it, and quietly answering
    # procurve there would send a SNMP-only switch down the SSH path, so it has to fail instead.
    (row,) = _sqlite_rows("SELECT id FROM switches", (None,))
    with pytest.raises(IndexError):
        driver_for(row)
    with pytest.raises(KeyError):
        driver_for({"id": 1})


def test_all_drivers_have_required_oids():
    required = ("pvid", "egress", "untagged", "ifadmin", "ifalias", "poe_admin", "poe_status")
    for name, driver in DRIVERS.items():
        if not can(driver, "snmp_vlan"):
            continue
        for key in required:
            assert key in driver.oids, f"{name} lacks the {key} OID"
        if driver.vlan_strategy == "cisco_vmps":
            assert "vmvlan" in driver.oids, f"{name} uses cisco_vmps but has no vmvlan OID"
        if driver.poe_index == "cisco_entity":
            assert {"poe_entphy", "ent_alias"} <= set(driver.oids), f"{name} maps PoE through ENTITY-MIB but lacks its OIDs"


@pytest.mark.parametrize("name", NAMES)
def test_oid_profile_is_pinned(name):
    # exact keys and values: vmvlan only on a cisco_vmps driver, a PoE power OID only where a vendor MIB has one (ProCurve, Cisco), the
    # entity mapping only on cisco, no stray entries, no typo in any OID
    assert DRIVERS[name].oids == {**STANDARD_OIDS, **EXTRA_OIDS.get(name, {})}
    assert ("vmvlan" in DRIVERS[name].oids) is (DRIVERS[name].vlan_strategy == "cisco_vmps")


@pytest.mark.parametrize("name", NAMES)
def test_poe_index_per_driver(name):
    # RFC 3621 does not relate <group>.<port> to an ifIndex: procurve by "group 1, index = ifIndex" (HP uses the ifIndex as the PoE port
    # index), cisco through ENTITY-MIB (classic IOS numbers the PoE entries by the port number on the stack member, its ifIndexes start
    # at 10101), every other driver "none" (R35) - and only the two drivers with a mapping have the cap
    assert DRIVERS[name].poe_index == POE_INDEX.get(name, "none")
    assert can(DRIVERS[name], "snmp_poe") is (DRIVERS[name].poe_index != "none")
    assert {d.poe_index for d in DRIVERS.values()} <= {"ifindex", "cisco_entity", "none"}


def test_oids_are_plain_numeric_bases():
    for name, driver in DRIVERS.items():
        for key, oid in driver.oids.items():
            assert re.fullmatch(r"[0-9]+(\.[0-9]+)+", oid), f"{name}.{key} = {oid!r}"


def test_drivers_do_not_share_oid_dicts():
    # editing (or monkeypatching) one driver's profile must not change another's
    assert len({id(d.oids) for d in DRIVERS.values()}) == len(DRIVERS)


def test_standard_oids_are_what_the_poller_reads():
    # the read-back verify re-walks what was written: the registry has to name the very objects the poller already reads
    for driver in DRIVERS.values():
        assert driver.oids["pvid"] == poller.O["pvid"]
        assert driver.oids["egress"] == poller.O["vlanEgress"]
        assert driver.oids["untagged"] == poller.O["vlanUntagged"]
        assert driver.oids["ifadmin"] == poller.O["ifAdmin"]
        assert driver.oids["ifalias"] == poller.O["ifAlias"]
