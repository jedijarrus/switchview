"""Tests for changes.plan_ports with a write mechanism (Task 9): "ssh", the default, plans ProCurve CLI lines exactly as before; "snmp"
plans against a live SNMP read (cfg and raw as snmpwrite.read_cfg / build_cfg give them) and renders with snmpwrite.render_ops.

What has to hold:
  * SSH is unchanged: its plan is the dict of before Task 9 plus "mechanism": "ssh", nothing else; driver and raw make no difference.
    The one deliberate difference: a port the LIVE configuration lists as a trunk member is refused even where the poll (inventory) does
    not know it as one yet.
  * SNMP: commands [], ops = the varbinds of render_ops, shown = its lines (the token basis); the ProCurve CLI rendering
    (changes._commands, cfgparse.compress_ports) is never called: it cannot even name a port like Gi1/0/1.
  * The rules that block a port hold on both paths: uplink / trunk only in expert mode, no NAC on uplinks and trunks, a trunk member only
    through its trunk, a non-ProCurve LAG (Po1, ...) counts as a trunk. Over SNMP snmpwrite.snmp_block_reason adds its reasons (unmanaged,
    no bridge port, a field SNMP cannot write, Cisco trunk VLANs, a PVID whose VLAN is missing, ...) as blocked entries, never as an
    exception, and the other ports of the change are still planned, with exactly their own varbinds.
  * R21: `before` holds the PVID of a Q-BRIDGE port whose u changes (from raw, only if it is a VLAN ID), so that the revert restores it
    byte for byte; never on cisco_vmps, where render_ops refuses any pvid (and so would refuse every Cisco revert).

The SNMP switches come from tests/switchfix.py, held as its simulated agent holds them: a change is stored into the walk rows (store),
read back with snmpwrite.build_cfg, and its revert is planned against that read, the way main._make_plan plans one (desired = before).
The SSH switch is `sample_running_config` (tests/conftest.py). Expected bytes are worked out by hand in the comments.
"""
import re

import pytest

import cfgparse
import changes
import snmpwrite
from drivers import DRIVERS, Driver
from switchfix import (CATALYST_VMVLAN, IF_ADMIN, IF_ALIAS, PVID, VLAN_EGRESS, VLAN_UNTAGGED, VMVLAN, W_CATALYST, W_CISCO, W_ODD,
                       W_SAMPLE, agent, edit_walks, store)

FW = "K.15.99.0001"
PROCURVE, CISCO, ARISTA, GENERIC = DRIVERS["procurve"], DRIVERS["cisco"], DRIVERS["arista"], DRIVERS["generic"]
LIMITED = Driver("limited", PROCURVE.caps - {"snmp_name"}, "qbridge", dict(PROCURVE.oids), "")    # no ifAlias writes
R_EXPERT = "Uplink/Trunk: nur im Expertenmodus"
R_NAC = "RADIUS/bekannte Geräte gehen nicht auf Uplinks und Trunks"
R_TRK1 = "gehört zu Trk1, bitte Trk1 wählen"
R_PO1 = "gehört zu Po1, bitte Po1 wählen"

# The SNMP switches (tests/switchfix.py), as the simulated agent holds them.
# SAMPLE, a ProCurve: port (ifIndex) -> bridge port 1 -> 3, 2 -> 1, 3 -> 2, 6 -> 5, Trk1 (289) -> 7; ports 4 and 5 are Trk1's members.
#   port 1: u 20, t [30], "Platz-107"   port 2: u 99   port 3: u None, t [20, 30]   port 6: u 1, "unused", down   Trk1: u 1, t [20, 30, 99]
#   PVIDs: bp 1 -> 99, 2 -> 1, 3 -> 20, 5 -> 1, 7 -> 1.  First byte of its 8-byte PortLists (the other seven are 00):
#   egress     1: 0A (bp 5, 7)   20: 62 (bp 2, 3, 7)   30: 62 (bp 2, 3, 7)   99: 82 (bp 1, 7)
#   untagged   1: 0A (bp 5, 7)   20: 20 (bp 3)         30: 00                99: 80 (bp 1)
# CATALYST, read for a Q-BRIDGE driver: Po1 (ifIndex 5001, bp 56) = LAG of Gi1/0/3 + Gi1/0/4, u 1, t [10, 20]; Gi1/0/1 (10101, bp 1)
#   u 10, "Drucker", PVID 10; Gi1/0/2 (10102, bp 2) u 1, t [20], down. CATALYST_VM: the same with vmVlan rows, read for cisco: Gi1/0/1
#   and Gi1/0/2 are access ports (vmVlan 10 / 1). CISCO_SW (W_CISCO, ProCurve port selection): Gi1/0/1, Gi1/0/2 access ports (vmVlan 10),
#   Gi1/0/3 a trunk port (no vmVlan row, u 1, t [10, 20]), Gi1/0/4 vmVlan 0. ODD (W_ODD): among others A3, a port without bridge port.
SAMPLE, ODD, CISCO_SW, CATALYST = agent(W_SAMPLE), agent(W_ODD), agent(W_CISCO), agent(W_CATALYST)
CATALYST_VM = agent({**W_CATALYST, "vmVlan": CATALYST_VMVLAN})
# port 3 (bp 2 = 0x40) untagged in VLAN 1 and 20: a hybrid port, unmanaged over SNMP (its t is [30])
HYBRID = edit_walks(SAMPLE, vlanEgress={"1": "4A" + " 00" * 7}, vlanUntagged={"1": "4A" + " 00" * 7, "20": "60" + " 00" * 7})
PVID_OFF = edit_walks(SAMPLE, pvid={"3": "1"})    # port 1 (bp 3): PVID 1 next to untagged VLAN 20, unmanaged over SNMP (R12)
R_HYBRID = "ungetaggt in mehreren VLANs (1, 20): Hybrid-/General-Port, per SNMP nicht verwaltbar"
PAD = "00" * 7


def eg(vid: str, first: str) -> tuple[str, str, str]:
    """The varbind of VLAN vid's egress PortList whose first byte is `first` (the other seven 00)."""
    return (f"{VLAN_EGRESS}.{vid}", "x", first + PAD)


def un(vid: str, first: str) -> tuple[str, str, str]:
    return (f"{VLAN_UNTAGGED}.{vid}", "x", first + PAD)


def read(W: dict, selection: str = "procurve") -> tuple[dict, dict]:
    """The switch as read_cfg reads it (without the walks): the port selection of `selection` (a driver name), the free text decoded from
    hex and, if W has vmVlan rows, their base."""
    return snmpwrite.build_cfg(W, selection, vmvlan_base=VMVLAN if "vmVlan" in W else None, text_hex=True)


def inv_of(cfg: dict, uplinks=(), stale=(), extra=()) -> dict:
    """What changes.inventory() gives for the switch read as cfg, as far as plan_ports looks at it: every port with tr = the trunk of a
    member, the trunk's own name on the trunk (as poller._build stores it), no LLDP neighbour, no link. stale: members the poll does not
    know as such yet (tr ""); extra: ports the poll still shows but the live read no longer has."""
    member_of = {m: t for t, members in cfg["trunks"].items() for m in members}
    tr = {n: "" if n in stale else n if n in cfg["trunks"] else member_of.get(n, "") for n in [*cfg["ports"], *extra]}
    return {"ports": {n: {"n": n, "tr": t, "l": [], "o": False} for n, t in tr.items()}, "uplinks": set(uplinks)}


def plan_snmp(W: dict, driver, req: dict, selection: str = "procurve", **inv_kw) -> dict:
    cfg, raw = read(W, selection)
    return changes.plan_ports(FW, inv_of(cfg, **inv_kw), cfg, req, mechanism="snmp", driver=driver, raw=raw)


def forbid_cli_rendering(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("ProCurve CLI rendering on the SNMP path")
    monkeypatch.setattr(changes, "_commands", forbidden)
    monkeypatch.setattr(cfgparse, "compress_ports", forbidden)


# ── SSH: the plan of before, plus the mechanism ───────────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def cfg(sample_running_config):
    return cfgparse.parse_config(sample_running_config)


def make_inv(uplinks=(), stale=()) -> dict:
    """changes.inventory() of the sample config, as tests/test_changes_plan.py builds it: A1-A24 plus Trk1, A5 / A6 its members (unless
    in `stale`: the poll does not know them as members yet)."""
    names = [f"A{i}" for i in range(1, 25)] + ["Trk1"]
    ports = {n: {"n": n, "tr": "Trk1" if n in ("A5", "A6") and n not in stale else "", "l": [], "o": False} for n in names}
    return {"ports": ports, "uplinks": set(uplinks)}


NOT_READY = {"radius": {}, "eap_radius": False, "auth_active": False}    # the sample switch without its RADIUS setup
RADIUS_A2 = ["aaa port-access authenticator A2", "aaa port-access authenticator A2 client-limit 1", "aaa port-access mac-based A2",
             "aaa port-access mac-based A2 addr-limit 1"]


@pytest.mark.parametrize("req, inv_kw, cfg_edit, pre", [
    pytest.param({"ports": ["A2"], "set": {"untagged": "20"}}, {}, {}, {
        "commands": ["vlan 20 untagged A2"], "shown": ["vlan 20 untagged A2"], "desired": {"A2": {"u": "20"}},
        "before": {"A2": {"u": "1"}}, "blocked": [], "warnings": [], "expert": False}, id="untagged"),
    pytest.param({"ports": ["A2"], "set": {"status": "radius"}}, {}, {}, {
        "commands": RADIUS_A2, "shown": RADIUS_A2, "desired": {"A2": {"x": True, "m": True, "cl": 1, "al": 1}},
        "before": {"A2": {"x": False, "m": False, "cl": None, "al": None}}, "blocked": [], "warnings": [], "expert": False}, id="radius"),
    # a switch-level block drops no port: the commands stay (apply and run_change refuse while blocked is not empty)
    pytest.param({"ports": ["A2"], "set": {"status": "radius"}}, {}, NOT_READY, {
        "commands": RADIUS_A2, "shown": RADIUS_A2, "desired": {"A2": {"x": True, "m": True, "cl": 1, "al": 1}},
        "before": {"A2": {"x": False, "m": False, "cl": None, "al": None}},
        "blocked": [{"port": "*", "reason": "Switch ist nicht für RADIUS vorbereitet: RADIUS-Server, 802.1X-Methode eap-radius, "
                                            "802.1X global aktiv"}],
        "warnings": [], "expert": False}, id="switch-not-ready"),
    pytest.param({"ports": ["Trk1", "A2"], "set": {"status": "off"}}, {}, {}, {
        "commands": ["interface A2 disable"], "shown": ["interface A2 disable"], "desired": {"A2": {"en": False}},
        "before": {"A2": {"en": True}}, "blocked": [{"port": "Trk1", "reason": R_EXPERT}], "warnings": [], "expert": False},
        id="trunk-needs-expert"),
    pytest.param({"ports": ["A24"], "set": {"untagged": "20"}, "expert": True}, {"uplinks": {"A24"}}, {}, {
        "commands": ["vlan 20 untagged A24"], "shown": ["vlan 20 untagged A24"], "desired": {"A24": {"u": "20"}},
        "before": {"A24": {"u": "1"}}, "blocked": [], "warnings": [], "expert": True}, id="expert-uplink"),
    # the revert form; A1 runs 802.1X and goes to VLAN 1
    pytest.param({"desired": {"A1": {"u": "1", "t": ["99"], "name": ""}}}, {}, {}, {
        "commands": ["vlan 1 untagged A1", "vlan 99 tagged A1", "no vlan 30 tagged A1", "no interface A1 name"],
        "shown": ["vlan 1 untagged A1", "vlan 99 tagged A1", "no vlan 30 tagged A1", "no interface A1 name"],
        "desired": {"A1": {"u": "1", "t": ["99"], "name": ""}}, "before": {"A1": {"u": "20", "t": ["30"], "name": "Platz-107"}},
        "blocked": [], "warnings": ["Port A1: läuft gerade eine Anmeldung, greift das neue VLAN erst nach der Abmeldung",
                                    "Port A1: VLAN 1 ist das Standard-VLAN"], "expert": False}, id="revert-form"),
])
def test_ssh_plan_unchanged(cfg, req, inv_kw, cfg_edit, pre):
    """The default mechanism gives the plan of before Task 9 (`pre`, as the Task 2 goldens pin it) plus "mechanism": "ssh"; there is no
    "ops". The SSH path neither needs nor reads a driver or an SNMP read: passing them changes nothing, even a raw that would block
    every port over SNMP."""
    cfg = {**cfg, **cfg_edit}
    plan = changes.plan_ports(FW, make_inv(**inv_kw), cfg, req)
    assert plan == {**pre, "mechanism": "ssh"}
    poison = {"unmanaged": {p: "per SNMP gesperrt" for p in make_inv()["ports"]}, "pvid": {"A1": "7", "A2": "7"}, "vmvlan": {}}
    assert changes.plan_ports(FW, make_inv(**inv_kw), cfg, req, mechanism="ssh", driver=GENERIC, raw=poison) == plan


def test_ssh_blocks_a_member_only_the_running_config_knows(cfg):
    """The running-config (read live) has A5 in Trk1, the poll does not know it as a member yet: A5 is refused all the same (VLANs only on
    TrkX, never on a member). Before Task 9 the plan was `vlan 20 untagged A2,A5`."""
    plan = changes.plan_ports(FW, make_inv(stale={"A5"}), cfg, {"ports": ["A5", "A2"], "set": {"untagged": "20"}})
    assert plan["blocked"] == [{"port": "A5", "reason": R_TRK1}]
    assert plan["commands"] == ["vlan 20 untagged A2"] and plan["desired"] == {"A2": {"u": "20"}}


def test_one_blocked_port_leaves_the_others_planned_ssh(cfg):
    """A5 (a member of Trk1) between two ports that can move: only A5 drops out, A2 and A7 are planned with exactly their own line."""
    plan = changes.plan_ports(FW, make_inv(), cfg, {"ports": ["A2", "A5", "A7"], "set": {"untagged": "20"}})
    assert plan == {
        "commands": ["vlan 20 untagged A2,A7"], "shown": ["vlan 20 untagged A2,A7"],
        "desired": {"A2": {"u": "20"}, "A7": {"u": "20"}}, "before": {"A2": {"u": "1"}, "A7": {"u": "1"}},
        "blocked": [{"port": "A5", "reason": R_TRK1}], "warnings": [], "expert": False, "mechanism": "ssh",
    }


def test_plan_ports_refuses_an_unknown_mechanism_or_a_missing_snmp_read(cfg):
    req = {"ports": ["A2"], "set": {"untagged": "20"}}
    with pytest.raises(ValueError, match=r"^Unbekannter Schreibweg: 'telnet'$"):
        changes.plan_ports(FW, make_inv(), cfg, req, mechanism="telnet")
    cfg_s, raw = read(SAMPLE)
    for kw in ({"driver": PROCURVE}, {"raw": raw}):
        with pytest.raises(TypeError, match=r"driver und raw"):
            changes.plan_ports(FW, inv_of(cfg_s), cfg_s, {"ports": ["2"], "set": {"untagged": "30"}}, mechanism="snmp", **kw)


# ── SNMP: ops and shown from render_ops ───────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("W, selection, driver, plan", [
    # Gi1/0/1 (bridge port 1 = 0x80) from VLAN 10 to 20 over Q-BRIDGE: VLAN 10 loses its bit in egress (80..01 -> 00..01) and untagged
    # (80 -> 00), VLAN 20 gets it (egress 50..01 -> D0..01, untagged 10 -> 90), PVID of bridge port 1 = 20; before keeps PVID 10 (R21)
    pytest.param(CATALYST, "arista", ARISTA, {
        "commands": [], "shown": ["Port Gi1/0/1: VLAN ungetaggt 10 → 20"],
        "ops": [(f"{VLAN_EGRESS}.10", "x", "0000000000000100"), (f"{VLAN_EGRESS}.20", "x", "D000000000000100"),
                (f"{VLAN_UNTAGGED}.10", "x", "0000000000000000"), (f"{VLAN_UNTAGGED}.20", "x", "9000000000000000"),
                (f"{PVID}.1", "u", "20")],
        "desired": {"Gi1/0/1": {"u": "20"}}, "before": {"Gi1/0/1": {"u": "10", "pvid": "10"}},
        "blocked": [], "warnings": [], "expert": False, "mechanism": "snmp"}, id="qbridge"),
    # the same on classic IOS: the access VLAN through vmVlan of ifIndex 10101, nothing on Q-BRIDGE, and no PVID in before
    pytest.param(CATALYST_VM, "cisco", CISCO, {
        "commands": [], "shown": ["Port Gi1/0/1: Access-VLAN 10 → 20"], "ops": [(f"{VMVLAN}.10101", "i", "20")],
        "desired": {"Gi1/0/1": {"u": "20"}}, "before": {"Gi1/0/1": {"u": "10"}},
        "blocked": [], "warnings": [], "expert": False, "mechanism": "snmp"}, id="cisco-vmvlan"),
])
def test_snmp_plan_has_ops(monkeypatch, W, selection, driver, plan):
    """A switch of another vendor, a port name the ProCurve CLI could not even write: the plan carries the varbinds of render_ops and its
    lines, commands is empty, and nothing renders CLI (changes._commands and cfgparse.compress_ports would fail the test)."""
    forbid_cli_rendering(monkeypatch)
    got = plan_snmp(W, driver, {"ports": ["Gi1/0/1"], "set": {"untagged": "20"}}, selection)
    assert got == plan
    assert re.fullmatch(r"[0-9a-f]{16}", changes.cmd_token(got["shown"]))    # the token of the preview, as for SSH


def test_a_lag_of_another_vendor_is_a_trunk(monkeypatch):
    """Po1 is in cfg["trunks"] like a TrkN: its VLANs change in expert mode only (and the inventory naming Po1 as its own trunk does not
    make it a 'member of itself'). Po1 (bridge port 56 = 0x01 of byte 6) drops VLAN 20: 50 .. 01 00 -> 50 .. 00 00."""
    forbid_cli_rendering(monkeypatch)
    req = {"ports": ["Po1"], "set": {"tagged_remove": ["20"]}}
    assert plan_snmp(CATALYST, ARISTA, req, "arista")["blocked"] == [{"port": "Po1", "reason": R_EXPERT}]
    plan = plan_snmp(CATALYST, ARISTA, {**req, "expert": True}, "arista")
    assert plan["blocked"] == []
    assert plan["ops"] == [(f"{VLAN_EGRESS}.20", "x", "5000000000000000")]
    assert plan["shown"] == ["Port Po1: VLAN getaggt 10, 20 → 10"]
    assert plan["before"] == {"Po1": {"t": ["10", "20"]}}


# ── SNMP: blocked ports ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("W, selection, driver, inv_kw, expert, desired, port, reason", [
    # the rules of both paths
    pytest.param(SAMPLE, "procurve", PROCURVE, {"uplinks": {"6"}}, False, {"6": {"u": "30"}, "2": {"u": "30"}}, "6", R_EXPERT,
                 id="uplink-needs-expert"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {"uplinks": {"6"}}, True, {"6": {"x": True}, "2": {"u": "30"}}, "6", R_NAC,
                 id="no-nac-on-uplinks"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {}, False, {"Trk1": {"t": ["20", "30"]}, "2": {"u": "30"}}, "Trk1", R_EXPERT,
                 id="trunk-needs-expert"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {}, False, {"4": {"u": "30"}, "2": {"u": "30"}}, "4", R_TRK1, id="trunk-member"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {"stale": {"4"}}, False, {"4": {"u": "30"}, "2": {"u": "30"}}, "4", R_TRK1,
                 id="trunk-member-the-poll-does-not-know"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {}, False, {"7": {"en": False}, "2": {"u": "30"}}, "7",
                 "Port gibt es auf diesem Switch nicht", id="not-in-the-inventory"),
    pytest.param(CATALYST, "arista", ARISTA, {}, False, {"Po1": {"t": ["10"]}, "Gi1/0/1": {"name": "Etage"}}, "Po1", R_EXPERT,
                 id="lag-needs-expert"),
    pytest.param(CATALYST, "arista", ARISTA, {}, True, {"Po1": {"m": True}, "Gi1/0/1": {"name": "Etage"}}, "Po1", R_NAC,
                 id="no-nac-on-a-lag"),
    pytest.param(CATALYST, "arista", ARISTA, {}, True, {"Po1": {"name": "core"}, "Gi1/0/1": {"name": "Etage"}}, "Po1",
                 "Name und An/Aus nur an den Mitglied-Ports des Trunks", id="lag-no-name"),
    pytest.param(CATALYST, "arista", ARISTA, {}, False, {"Gi1/0/3": {"u": "20"}, "Gi1/0/1": {"name": "Etage"}}, "Gi1/0/3", R_PO1,
                 id="lag-member"),
    pytest.param(CATALYST, "arista", ARISTA, {"stale": {"Gi1/0/3"}}, False, {"Gi1/0/3": {"u": "20"}, "Gi1/0/1": {"name": "Etage"}},
                 "Gi1/0/3", R_PO1, id="lag-member-the-poll-does-not-know"),
    # snmp_block_reason
    pytest.param(SAMPLE, "procurve", PROCURVE, {"extra": {"7"}}, False, {"7": {"en": False}, "2": {"u": "30"}}, "7",
                 "gibt es auf diesem Switch nicht", id="not-in-the-live-read"),
    pytest.param(HYBRID, "procurve", PROCURVE, {}, False, {"3": {"t": ["30", "99"]}, "2": {"u": "30"}}, "3", R_HYBRID,
                 id="unmanaged-hybrid"),
    pytest.param(PVID_OFF, "procurve", PROCURVE, {}, False, {"1": {"u": "99", "en": False}, "2": {"u": "30"}}, "1",
                 "PVID 1 weicht vom ungetaggten VLAN 20 ab (Fehlkonfiguration oder dynamisch per 802.1X/RADIUS zugewiesen) – per SNMP nicht "
                 "verwaltbar", id="unmanaged-pvid"),
    pytest.param(ODD, "procurve", PROCURVE, {}, False, {"A3": {"en": True}, "A1": {"name": "core"}}, "A3",
                 "kein Bridge-Port (etwa ein Management-Port), per SNMP nur zur Anzeige", id="no-bridge-port"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {}, False, {"6": {"x": True, "m": True, "cl": 1, "al": 1}, "2": {"u": "30"}}, "6",
                 "per SNMP nicht änderbar: al, cl, m, x", id="cli-only-fields"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {}, False, {"3": {"pvid": "4000"}, "2": {"u": "30"}}, "3",
                 "PVID 4000: das VLAN gibt es auf diesem Switch nicht", id="r23-pvid-vlan-missing"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {}, False, {"6": {"name": "a\x01b"}, "2": {"u": "30"}}, "6", "Name enthält Steuerzeichen",
                 id="name-with-a-control-character"),
    pytest.param(SAMPLE, "procurve", LIMITED, {}, False, {"6": {"name": "x"}, "2": {"u": "30"}}, "6",
                 "Treiber limited kann Portnamen nicht per SNMP schreiben", id="driver-without-the-capability"),
    pytest.param(CISCO_SW, "procurve", CISCO, {}, False, {"Gi1/0/3": {"t": ["10"]}, "Gi1/0/1": {"u": "20"}}, "Gi1/0/3",
                 "Trunk-VLANs auf Cisco per SNMP noch nicht unterstützt (CISCO-VTP-MIB)", id="cisco-trunk-vlans"),
    pytest.param(CISCO_SW, "procurve", CISCO, {}, False, {"Gi1/0/2": {"t": ["20"]}, "Gi1/0/1": {"u": "20"}}, "Gi1/0/2",
                 "Access-Port (vmVlan), getaggte VLANs gibt es dort nicht", id="cisco-access-port-tagged"),
])
def test_snmp_plan_respects_blocked(monkeypatch, W, selection, driver, inv_kw, expert, desired, port, reason):
    """Each case blocks one port (one entry, its reason, never an exception) next to one the change can make: that one is still planned,
    with exactly the varbinds and lines render_ops gives for it alone. No case adds a switch-level entry: over SNMP every NAC field is
    already refused per port, and cfg there knows nothing of the RADIUS setup (it would always read 'not prepared')."""
    forbid_cli_rendering(monkeypatch)
    cfg, raw = read(W, selection)
    plan = changes.plan_ports(FW, inv_of(cfg, **inv_kw), cfg, {"desired": desired, "expert": expert}, mechanism="snmp", driver=driver,
                              raw=raw)
    assert plan["blocked"] == [{"port": port, "reason": reason}]
    rest = {p: d for p, d in desired.items() if p != port}
    assert plan["desired"] == rest
    assert (plan["ops"], plan["shown"]) == snmpwrite.render_ops(driver, cfg, raw, rest)
    assert plan["ops"] and plan["commands"] == [] and plan["mechanism"] == "snmp"


# port 2 (bp 1): untagged 99 and no tagged VLAN, PVID 1 since (R12): unmanaged, and cfg shows it in no VLAN at all (u None is a placeholder)
PVID_OFF_2 = edit_walks(SAMPLE, pvid={"1": "1"})
R12_2 = ("PVID 1 weicht vom ungetaggten VLAN 99 ab (Fehlkonfiguration oder dynamisch per 802.1X/RADIUS zugewiesen) – per SNMP nicht "
         "verwaltbar")


OFF_AND_NAMED = {"status": "off", "name": "Telefon"}
TELEFON = "54656C65666F6E"    # "Telefon" as the hex of an ifAlias varbind


@pytest.mark.parametrize("W, req, ops, before", [
    pytest.param(HYBRID, {"ports": ["3"], "set": OFF_AND_NAMED}, [(f"{IF_ADMIN}.3", "i", "2"), (f"{IF_ALIAS}.3", "x", TELEFON)],
                 {"3": {"en": True, "name": ""}}, id="hybrid"),
    pytest.param(PVID_OFF, {"ports": ["1"], "set": {"status": "off"}}, [(f"{IF_ADMIN}.1", "i", "2")], {"1": {"en": True}},
                 id="pvid-mismatch"),
    # L17: cfg shows port 2 in no VLAN (u None is only the placeholder of an unmanaged port), yet en / name are no VLAN change: not
    # "Port wäre in keinem VLAN mehr"
    pytest.param(PVID_OFF_2, {"ports": ["2"], "set": OFF_AND_NAMED}, [(f"{IF_ADMIN}.2", "i", "2"), (f"{IF_ALIAS}.2", "x", TELEFON)],
                 {"2": {"en": True, "name": ""}}, id="pvid-mismatch-in-no-vlan"),
    pytest.param(PVID_OFF_2, {"desired": {"2": {"en": False}}}, [(f"{IF_ADMIN}.2", "i", "2")], {"2": {"en": True}}, id="revert-form"),
])
def test_snmp_unmanaged_port_takes_en_and_name(monkeypatch, W, req, ops, before):
    """R41: an unmanaged port (R9 hybrid, R12 PVID != untagged) is refused only for its VLAN fields; on / off and the name are planned
    like on any port, with exactly their own varbinds, and before holds just those fields (a revert restores only them)."""
    forbid_cli_rendering(monkeypatch)
    plan = plan_snmp(W, PROCURVE, req)
    (port,) = before
    assert port in read(W)[1]["unmanaged"]
    assert (plan["blocked"], plan["ops"], plan["before"]) == ([], ops, before)


def test_snmp_unmanaged_port_still_refuses_its_vlan_fields():
    """u / t on the unmanaged port 2 keep the R12 reason; nothing of the port is planned (also not its en, which alone would go)."""
    for change in ({"untagged": "20"}, {"tagged_add": ["30"]}, {"untagged": "20", "status": "off"}):
        plan = plan_snmp(PVID_OFF_2, PROCURVE, {"ports": ["2"], "set": change})
        assert (plan["blocked"], plan["ops"]) == ([{"port": "2", "reason": R12_2}], [])


def test_snmp_no_vlan_left_still_blocks_a_vlan_change():
    """L17 gates only the en / name / PoE requests: a VLAN change that would leave a managed port in no VLAN is still refused (port 3,
    tagged in 20 and 30, no untagged VLAN, drops both)."""
    plan = plan_snmp(SAMPLE, PROCURVE, {"desired": {"3": {"t": []}}})
    assert plan["blocked"] == [{"port": "3", "reason": "wäre in keinem VLAN mehr"}]


@pytest.mark.parametrize("change, fields", [
    ({"status": "radius"}, "al, cl, m, x"),
    ({"status": "known"}, "al, m"),
    ({"status": "known", "guest": "99", "limit": 3}, "al, m, muv"),
])
def test_cli_only_requests_over_snmp_are_blocked_not_raised(monkeypatch, change, fields):
    """802.1X / MAC auth go over the CLI only. Over SNMP such a request blocks every port it touches, with the fields it cannot write, and
    plans nothing (port 6 would also be switched on: en can be written, but the change as a whole cannot)."""
    forbid_cli_rendering(monkeypatch)
    plan = plan_snmp(SAMPLE, PROCURVE, {"ports": ["6", "2"], "set": change})
    assert plan["blocked"] == [{"port": p, "reason": f"per SNMP nicht änderbar: {fields}"} for p in ("6", "2")]
    assert (plan["desired"], plan["ops"], plan["shown"], plan["before"]) == ({}, [], [], {})


def test_a_revert_over_snmp_never_drops_what_snmp_cannot_read():
    """SNMP reads no 802.1X / MAC auth: cfg shows their defaults. A revert that wants x / m off must not compare against those (they would
    count as 'already so' and the revert would quietly put back only the VLAN); the port is blocked as a whole."""
    plan = plan_snmp(SAMPLE, PROCURVE, {"desired": {"2": {"u": "1", "x": False, "m": False, "cl": None, "al": None}}})
    assert plan["blocked"] == [{"port": "2", "reason": "per SNMP nicht änderbar: al, cl, m, x"}]
    assert (plan["desired"], plan["ops"], plan["shown"], plan["before"]) == ({}, [], [], {})


def test_a_revert_compares_the_pvid_with_raw():
    """cfg has no PVID: a revert's pvid is compared with raw. Port 3 (bridge port 2) is tagged-only with PVID 1 already: nothing to do.
    PVID 20 instead: only that varbind, and before holds the PVID it replaces."""
    plan = plan_snmp(SAMPLE, PROCURVE, {"desired": {"3": {"u": None, "pvid": "1"}}})
    assert (plan["blocked"], plan["desired"], plan["ops"], plan["shown"]) == ([], {}, [], [])
    plan = plan_snmp(SAMPLE, PROCURVE, {"desired": {"3": {"u": None, "pvid": "20"}}})
    assert plan["desired"] == {"3": {"pvid": "20"}} and plan["before"] == {"3": {"pvid": "1"}}
    assert plan["ops"] == [(f"{PVID}.2", "u", "20")] and plan["shown"] == ["Port 3: PVID 1 → 20"]


# ── the multi-port pin ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("W, ports, blocked, ops", [
    # ports 6 (bridge port 5 = 0x08) and 2 (bp 1 = 0x80) move to VLAN 30 around member 4: egress.30 = 62 | 08 | 80 = EA, untagged.30 = 88;
    # VLAN 1 loses bp 5 (0A -> 02), VLAN 99 loses bp 1 (egress 82 -> 02, untagged 80 -> 00)
    pytest.param(SAMPLE, ["6", "4", "2"], {"port": "4", "reason": R_TRK1},
                 [eg("1", "02"), eg("30", "EA"), eg("99", "02"), un("1", "02"), un("30", "88"), un("99", "00"), (f"{PVID}.1", "u", "30"),
                  (f"{PVID}.5", "u", "30")], id="neutral-block"),
    # the same around hybrid port 3, which snmp_block_reason refuses; VLAN 1 is 4A here (bp 2, 5, 7): it loses bp 5 -> 42
    pytest.param(HYBRID, ["6", "3", "2"], {"port": "3", "reason": R_HYBRID},
                 [eg("1", "42"), eg("30", "EA"), eg("99", "02"), un("1", "42"), un("30", "88"), un("99", "00"), (f"{PVID}.1", "u", "30"),
                  (f"{PVID}.5", "u", "30")], id="snmp-block"),
])
def test_one_blocked_port_leaves_the_others_planned_snmp(W, ports, blocked, ops):
    plan = plan_snmp(W, PROCURVE, {"ports": ports, "set": {"untagged": "30"}})
    assert plan == {
        "commands": [], "shown": ["Port 2: VLAN ungetaggt 99 → 30", "Port 6: VLAN ungetaggt 1 → 30"], "ops": ops,
        "desired": {"6": {"u": "30"}, "2": {"u": "30"}}, "before": {"6": {"u": "1", "pvid": "1"}, "2": {"u": "99", "pvid": "99"}},
        "blocked": [blocked], "warnings": [], "expert": False, "mechanism": "snmp",
    }


# ── R21: the PVID in before, and the revert ───────────────────────────────────────────────────────────────────────────────────────────
def test_snmp_revert_round_trip_restores_the_pvid():
    """Port 3 (bridge port 2 = 0x40) is tagged-only with PVID 1 and becomes untagged in VLAN 99: egress.99 82 -> C2, untagged.99 80 -> C0,
    PVID 99. before records the PVID 1 (u changes, Q-BRIDGE, raw has a VLAN ID). The revert, planned from before against the switch as it
    is now, takes the bit out again and writes PVID 1 back: the switch is byte for byte the one of the start."""
    plan = plan_snmp(SAMPLE, PROCURVE, {"ports": ["3"], "set": {"untagged": "99"}})
    assert plan == {
        "commands": [], "shown": ["Port 3: VLAN ungetaggt – → 99"], "ops": [eg("99", "C2"), un("99", "C0"), (f"{PVID}.2", "u", "99")],
        "desired": {"3": {"u": "99"}}, "before": {"3": {"u": None, "pvid": "1"}}, "blocked": [], "warnings": [], "expert": False,
        "mechanism": "snmp",
    }
    W1 = store(SAMPLE, plan["ops"])
    revert = plan_snmp(W1, PROCURVE, {"desired": plan["before"]})
    assert revert["blocked"] == [] and revert["desired"] == {"3": {"u": None, "pvid": "1"}}
    assert revert["ops"] == [eg("99", "82"), un("99", "80"), (f"{PVID}.2", "u", "1")]
    assert revert["shown"] == ["Port 3: VLAN ungetaggt 99 → –", "Port 3: PVID 99 → 1"]
    assert revert["before"] == {"3": {"u": "99", "pvid": "99"}}
    assert store(W1, revert["ops"]) == SAMPLE


def test_snmp_revert_round_trip_on_another_vendor():
    """Gi1/0/1 (bridge port 1) from VLAN 10 to 20 and back on a Q-BRIDGE driver: before holds u 10 and PVID 10, the revert writes both."""
    plan = plan_snmp(CATALYST, ARISTA, {"ports": ["Gi1/0/1"], "set": {"untagged": "20"}}, "arista")
    assert plan["before"] == {"Gi1/0/1": {"u": "10", "pvid": "10"}}
    W1 = store(CATALYST, plan["ops"])
    revert = plan_snmp(W1, ARISTA, {"desired": plan["before"]}, "arista")
    assert revert["blocked"] == [] and revert["desired"] == plan["before"]
    assert (f"{PVID}.1", "u", "10") in revert["ops"]
    assert store(W1, revert["ops"]) == CATALYST


@pytest.mark.parametrize("W, selection, port, back", [
    (CATALYST_VM, "cisco", "Gi1/0/1", "10"),    # vmVlan 10, bridge port 1 with dot1qPvid 10
    (CISCO_SW, "procurve", "Gi1/0/2", "10"),    # vmVlan 10, bridge port 10 with dot1qPvid 10
])
def test_cisco_access_port_revert_is_not_refused(W, selection, port, back):
    """A Cisco access port has a dot1qPvid row too, but cisco_vmps writes no PVID: before records none (render_ops refuses any pvid there,
    so a recorded one would get every Cisco revert refused). The revert goes through, through vmVlan, and restores the switch."""
    cfg, raw = read(W, selection)
    assert raw["pvid"][port] == back    # the row is there, and deliberately not taken
    plan = plan_snmp(W, CISCO, {"ports": [port], "set": {"untagged": "20"}}, selection)
    assert plan["before"] == {port: {"u": back}} and plan["blocked"] == []
    W1 = store(W, plan["ops"])
    revert = plan_snmp(W1, CISCO, {"desired": plan["before"]}, selection)
    assert revert["blocked"] == [] and revert["desired"] == {port: {"u": back}}
    assert revert["ops"] == [(f"{VMVLAN}.{raw['ifindex'][port]}", "i", back)]
    assert revert["shown"] == [f"Port {port}: Access-VLAN 20 → {back}"]
    assert store(W1, revert["ops"]) == W


@pytest.mark.parametrize("W, selection, driver, req, before", [
    pytest.param(SAMPLE, "procurve", PROCURVE, {"ports": ["1"], "set": {"untagged": "99"}}, {"1": {"u": "20", "pvid": "20"}}, id="recorded"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {"ports": ["6"], "set": {"name": "Kopierer"}}, {"6": {"name": "unused"}}, id="u-unchanged"),
    pytest.param(SAMPLE, "procurve", PROCURVE, {"ports": ["1"], "set": {"status": "off"}}, {"1": {"en": True}}, id="en-only"),
    pytest.param(edit_walks(SAMPLE, pvid={"2": "0"}), "procurve", PROCURVE, {"ports": ["3"], "set": {"untagged": "99"}}, {"3": {"u": None}},
                 id="raw-pvid-0"),
    pytest.param(ODD, "procurve", PROCURVE, {"ports": ["A99"], "set": {"untagged": "7"}}, {"A99": {"u": "5"}}, id="no-pvid-row"),
    pytest.param(CATALYST_VM, "cisco", CISCO, {"ports": ["Gi1/0/1"], "set": {"untagged": "20"}}, {"Gi1/0/1": {"u": "10"}}, id="cisco-vmps"),
])
def test_before_records_the_pvid_only_where_a_revert_can_write_it(W, selection, driver, req, before):
    """R21: before gets the PVID only on Q-BRIDGE, for a port without vmVlan row whose u changes, and only a VLAN ID 1..4094 from raw. A
    "0" or a missing row (A99, bridge port 13, has none) would be refused by render_ops and block the whole revert."""
    plan = plan_snmp(W, driver, req, selection)
    assert plan["blocked"] == [] and plan["before"] == before


def test_the_pvid_rule_of_before_does_not_lean_on_the_refusals():
    """Through plan_ports, both guards of R21 are also covered by snmp_block_reason (it refuses VLAN changes on a Cisco trunk port and a
    vmVlan port under a Q-BRIDGE driver). They hold on their own, so that relaxing a refusal later (Cisco trunk VLANs over VTP-MIB, say)
    cannot start recording a PVID no revert could write: on cisco_vmps none, and none for a port the read describes by vmVlan."""
    cfg, raw = read(CISCO_SW)
    assert raw["pvid"]["Gi1/0/3"] == "1" and raw["pvid"]["Gi1/0/1"] == "1"    # both have a dot1qPvid row with a VLAN ID
    assert changes._snmp_before(CISCO, cfg, raw, "Gi1/0/3", {"u": "10"}) == {"u": "1"}       # trunk port, no vmVlan row, cisco_vmps
    assert changes._snmp_before(GENERIC, cfg, raw, "Gi1/0/1", {"u": "20"}) == {"u": "10"}    # vmVlan row, Q-BRIDGE driver
    assert changes._snmp_before(GENERIC, cfg, raw, "Gi1/0/3", {"u": "10"}) == {"u": "1", "pvid": "1"}
