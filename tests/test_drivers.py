"""Tests for app/drivers.py, the vendor driver registry.

The registry is plain data, yet it decides two things that matter on a live switch: which paths exist for a device at all (the
SSH-CLI path, NAC and config backup are ProCurve-only and must never show up on a SNMP-only driver) and which OID a SNMP write
is sent to (a wrong OID base is a write to the wrong object). So the tests pin the capability table, the VLAN strategy per
driver, every OID value and the way a switches row becomes a driver.

The expected values are written out here by hand, independent of app/drivers.py. The OID bases were checked against the MIB
definitions: Q-BRIDGE-MIB (RFC 2674 / 4363), IF-MIB (RFC 2863), POWER-ETHERNET-MIB (RFC 3621) and CISCO-VLAN-MEMBERSHIP-MIB.
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

SNMP_CAPS = {"snmp_vlan", "snmp_admin", "snmp_name", "snmp_poe"}
CLI_CAPS = {"cli", "nac", "backup"}    # only reachable through the SSH CLI, so only the ProCurve driver may have them
ALL_CAPS = SNMP_CAPS | CLI_CAPS
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
    # DetectionStatus = 6), instance .<group>.<port>. Spec 3 writes ...105.1.1.1.1.3 and ...1.6, one ".1" too many:
    # ...105.1.1.1.1 is the index column pethPsePortGroupIndex (not-accessible), so a SET to that OID could never take effect.
    "poe_admin": "1.3.6.1.2.1.105.1.1.1.3",       # pethPsePortAdminEnable, TruthValue 1 = on / 2 = off
    "poe_status": "1.3.6.1.2.1.105.1.1.1.6",      # pethPsePortDetectionStatus
}
VMVLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"    # vmVlan (CISCO-VLAN-MEMBERSHIP-MIB), INTEGER 0..4095, .<ifIndex>


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
    assert [f.name for f in dataclasses.fields(Driver)] == ["name", "caps", "vlan_strategy", "oids", "notes"]
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
    # all seven operations asked through can(), not only read from .caps: ProCurve has all, everyone else the four snmp_* ones
    driver = DRIVERS[name]
    expected = ALL_CAPS if name == "procurve" else SNMP_CAPS
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


@pytest.mark.parametrize("name", NAMES)
def test_oid_profile_is_pinned(name):
    # exact keys and values: vmvlan only on a cisco_vmps driver, no stray entries, no typo in any OID
    expected = dict(STANDARD_OIDS)
    if DRIVERS[name].vlan_strategy == "cisco_vmps":
        expected["vmvlan"] = VMVLAN
    assert DRIVERS[name].oids == expected


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
