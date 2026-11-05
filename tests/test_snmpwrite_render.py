"""Tests for snmpwrite.render_ops: a planned per-port target state (`desired`, as changes.plan_ports builds it) -> the exact snmpset
varbinds sent to a LIVE switch, plus `shown`, the human-readable lines the change token is built from.

A wrong bit here silently moves the wrong port into the wrong VLAN. So the central check is a simulated switch, the oracle. The switch
is held the way read_cfg walks it (the agent format: PortLists as hex, the free text ifAlias / vlanName as hex too, R18, numbers bare);
every rendered varbind is stored in the walk row of exactly its OID, the switch is read again with snmpwrite.build_cfg(text_hex=True),
and then
  * changes.verify_ports(cfg_after, desired) == []: the read-back verify of the real change passes; an explicit pvid (R21), which
    cfg has no field for, is read back from raw;
  * cfg_after is the old cfg with exactly the desired fields changed: nothing else, except that a trunk's members follow its VLANs
    (they share its bridge port);
  * raw: every PortList bit of a bridge port that did not change is untouched, no list changed length (unless a bit had to be set
    behind its end), the changed bridge ports carry exactly the bits their new u / t mean (untagged also in egress), and PVID,
    ifAdminStatus, ifAlias and vmVlan of every other port are untouched;
  * the varbinds: only OIDs the change may touch (the PortLists of the VLANs it touches, the PVID of its ports' effective bridge
    ports, ifAdminStatus / ifAlias / vmVlan of its ports' ifIndexes), one per OID, of the object's own type, each PortList only if it
    changed, in the documented order.
It runs on hand-checked cases (the expected bytes are worked out by hand in the comments), on changes planned with changes.plan_ports
and reverted the way the app reverts them, and on random switches with random, partly invalid requests, where the test's own reading
of the rules decides whether render_ops has to refuse.

Nothing here talks to net-snmp, a network or a database; the fixtures and the simulated agent (agent, store) come from
tests/switchfix.py. Modules are imported flat (app/ is on sys.path via pytest.ini), exactly as the app imports them.
"""
import copy
import random
import re

import pytest

import changes
import snmpwrite
from drivers import DRIVERS, Driver
from switchfix import (BP2IF, CATALYST_VMVLAN, ETHERNET, IF_ADMIN, IF_ALIAS, IF_NAME, IF_STACK, IF_TYPE, PORTLISTS, PVID, VLAN_EGRESS,
                       VLAN_NAME, VLAN_UNTAGGED, VMVLAN, W_CATALYST, W_CISCO, W_ODD, W_SAMPLE, WALK_BASES, agent, edit_walks, hex_text,
                       portlist_hex, random_multivendor_switch, random_procurve_switch, store, walk_rows)

PROCURVE, CISCO, GENERIC, ARISTA = DRIVERS["procurve"], DRIVERS["cisco"], DRIVERS["generic"], DRIVERS["arista"]
NON_PROCURVE = [name for name in DRIVERS if name != "procurve"]

# The documented varbind order: memberships first (egress, then untagged, by VLAN), then the PVIDs (by bridge port), then vmVlan,
# ifAdminStatus and ifAlias (by ifIndex).
ORDER = [VLAN_EGRESS, VLAN_UNTAGGED, PVID, VMVLAN, IF_ADMIN, IF_ALIAS]


# W_SAMPLE (tests/switchfix.py), a ProCurve: port (ifIndex) -> bridge port: 1 -> 3, 2 -> 1, 3 -> 2, 6 -> 5, Trk1 (289) -> 7; ports
# 4 and 5 are Trk1's members. Its 8-byte PortLists, first byte (the other seven are 00):
#   egress     1: 0A (bp 5, 7)   20: 62 (bp 2, 3, 7)   30: 62 (bp 2, 3, 7)   99: 82 (bp 1, 7)
#   untagged   1: 0A (bp 5, 7)   20: 20 (bp 3)         30: 00                99: 80 (bp 1)
# Bits: bp 1 = 0x80, 2 = 0x40, 3 = 0x20, 5 = 0x08, 7 = 0x02 of byte 0. PVIDs: bp 1 -> 99, 2 -> 1, 3 -> 20, 5 -> 1, 7 -> 1.
#   port 1: u 20, t [30], "Platz-107", up    port 2: u 99, up    port 3: u None, t [20, 30], up    port 6: u 1, "unused", down
#   Trk1: u 1, t [20, 30, 99], up
SAMPLE, ODD, CISCO_SW, CATALYST = agent(W_SAMPLE), agent(W_ODD), agent(W_CISCO), agent(W_CATALYST)
CATALYST_VM = agent({**W_CATALYST, "vmVlan": CATALYST_VMVLAN})
PAD = "00" * 7


def eg(vid: str, first: str) -> tuple[str, str, str]:
    """The varbind of VLAN vid's egress PortList whose first byte is `first` (the other seven 00)."""
    return (f"{VLAN_EGRESS}.{vid}", "x", first + PAD)


def un(vid: str, first: str) -> tuple[str, str, str]:
    return (f"{VLAN_UNTAGGED}.{vid}", "x", first + PAD)


def _read(W: dict, selection: str = "procurve") -> tuple[dict, dict]:
    """The switch (agent format) as the write path reads it: build_cfg with the port selection of `selection` (a driver name), the free
    text decoded from hex, and, if W has vmVlan rows, their base."""
    return snmpwrite.build_cfg(W, selection, vmvlan_base=VMVLAN if "vmVlan" in W else None, text_hex=True)


def _bits(data: bytes) -> set[int]:
    """Bridge ports in a PortList, bit math written out here: bridge port n is bit 0x80 >> (n - 1) % 8 of byte (n - 1) // 8."""
    return {i * 8 + j + 1 for i, byte in enumerate(data) for j in range(8) if byte & (0x80 >> j)}


def _vlans_change(cfg: dict, p: str, d: dict) -> bool:
    st = cfg["ports"][p]
    return d.get("u", st["u"]) != st["u"] or set(d.get("t", st["t"])) != set(st["t"])


def _allowed_oids(cfg: dict, raw: dict, desired: dict) -> set[str]:
    """Every OID a correct rendering of `desired` may write: the PortLists of the VLANs a port's change touches (old and new untagged,
    tagged in or out), the PVID of the effective bridge port of a port whose u becomes a VLAN or that carries an explicit pvid, its
    vmVlan if it is a vmVlan port whose u is given, its ifAdminStatus / ifAlias if en / name is given."""
    allowed = set()
    for p, d in desired.items():
        if not d:
            continue
        st, ifi = cfg["ports"][p], raw["ifindex"][p]
        u, t = d.get("u", st["u"]), d.get("t", st["t"])
        if p in raw["vmvlan"]:
            if "u" in d:
                allowed.add(f"{VMVLAN}.{ifi}")
        else:
            touched = ({st["u"], u} - {None} if u != st["u"] else set()) | (set(st["t"]) ^ set(t))
            allowed |= {f"{base}.{v}" for v in touched for base in PORTLISTS}
            if (u != st["u"] and u is not None) or "pvid" in d:
                allowed.add(f"{PVID}.{raw['port2bp'][p]}")
        if "en" in d:
            allowed.add(f"{IF_ADMIN}.{ifi}")
        if "name" in d:
            allowed.add(f"{IF_ALIAS}.{ifi}")
    return allowed


def _expected_cfg(cfg: dict, raw: dict, desired: dict) -> dict:
    """cfg with the desired fields set (pvid is no cfg field). A trunk whose VLANs change over Q-BRIDGE takes its members along: they
    have no bridge port of their own (a member's VLANs are its trunk's), unless the member is an access port read from vmVlan."""
    want = copy.deepcopy(cfg)
    for p, d in desired.items():
        for k, v in d.items():
            if k != "pvid":
                want["ports"][p][k] = sorted(v, key=int) if k == "t" else v
    for trunk, members in cfg["trunks"].items():
        if trunk in desired and trunk not in raw["vmvlan"] and _vlans_change(cfg, trunk, desired[trunk]):
            for m in members:
                if m in want["ports"] and m not in raw["vmvlan"]:
                    want["ports"][m]["u"], want["ports"][m]["t"] = want["ports"][trunk]["u"], list(want["ports"][trunk]["t"])
    return want


def _assert_raw(raw: dict, raw2: dict, cfg: dict, want: dict, desired: dict):
    """raw2 (read back) against raw (before), see the module docstring."""
    vlan_ports = [p for p, d in desired.items() if d and _vlans_change(cfg, p, d)]
    moved = {raw["port2bp"][p] for p in vlan_ports if p not in raw["vmvlan"]}    # the bridge ports whose bits had to change
    assert raw2["egress"].keys() == raw["egress"].keys() and raw2["untagged"].keys() == raw["untagged"].keys()
    for kind in ("egress", "untagged"):
        for v, old in raw[kind].items():
            new = raw2[kind][v]
            assert _bits(new) - moved == _bits(old) - moved, (kind, v)
            # the length is kept; it only grows as far as a bit that had to be set behind the end of the list
            assert len(new) == max([len(old)] + [(bp - 1) // 8 + 1 for bp in moved & _bits(new)]), (kind, v)
    for p in vlan_ports:
        if p in raw["vmvlan"]:
            continue
        bp, st = raw["port2bp"][p], want["ports"][p]
        for v in raw["egress"]:
            assert (bp in _bits(raw2["egress"][v])) is (v == st["u"] or v in st["t"]), (p, v)
            assert (bp in _bits(raw2["untagged"][v])) is (v == st["u"]), (p, v)
    expected = {k: copy.deepcopy(val) for k, val in raw.items() if k not in ("egress", "untagged")}
    for p, d in desired.items():
        if not d:
            continue
        st = cfg["ports"][p]
        if "en" in d and d["en"] != st["en"]:
            expected["admin"][p] = 1 if d["en"] else 2
        if "name" in d and d["name"] != st["name"]:
            expected["alias"][p] = d["name"]
        u = d.get("u", st["u"])
        if p in raw["vmvlan"]:
            if u != st["u"]:
                expected["vmvlan"][p] = u
        else:
            # R21: an explicit pvid, otherwise the new untagged VLAN; a revert to no untagged VLAN without pvid leaves the PVID alone
            pvid = d.get("pvid", u if u != st["u"] else None)
            if pvid is not None:
                for q, bp in raw["port2bp"].items():
                    if bp == raw["port2bp"][p]:
                        expected["pvid"][q] = pvid
    assert {k: v for k, v in raw2.items() if k not in ("egress", "untagged")} == expected


def _assert_ops_shape(ops: list, shown: list, raw: dict, cfg2: dict, raw2: dict):
    assert all(isinstance(op, tuple) and len(op) == 3 and all(isinstance(x, str) for x in op) for op in ops), ops
    assert ops == sorted(ops, key=lambda op: (ORDER.index(op[0].rpartition(".")[0]), int(op[0].rpartition(".")[2])))
    for oid, typ, value in ops:
        base, _, index = oid.rpartition(".")
        if base in PORTLISTS:
            assert bytes.fromhex(value) != raw[PORTLISTS[base]][index], f"{oid} written unchanged"
            assert not any(value in line for line in shown), "raw PortList bytes in shown"
        if base == PVID:    # a port that has an untagged VLAN afterwards has it as its PVID, never one of its tagged VLANs
            for q, bp in raw2["port2bp"].items():
                if bp == int(index) and cfg2["ports"][q]["u"] is not None:
                    assert cfg2["ports"][q]["u"] == value and value not in cfg2["ports"][q]["t"], (q, value)


def _render_and_store(W: dict, driver, desired: dict, selection: str = "procurve") -> tuple[list, list]:
    """render_ops on the switch W (agent format), stored by the simulated agent and read back; asserts what the oracle promises (module
    docstring)."""
    cfg, raw = _read(W, selection)
    ops, shown = snmpwrite.render_ops(driver, cfg, raw, desired)
    assert {op[0] for op in ops} <= _allowed_oids(cfg, raw, desired), "a varbind outside what the change may touch"
    cfg2, raw2 = _read(store(W, ops), selection)
    assert changes.verify_ports(cfg2, {p: {k: v for k, v in d.items() if k != "pvid"} for p, d in desired.items()}) == []
    for p, d in desired.items():
        if "pvid" in d:    # R21: what verify_ports cannot see, read back from raw
            assert raw2["pvid"][p] == d["pvid"], p
    want = _expected_cfg(cfg, raw, desired)
    assert cfg2 == want
    _assert_raw(raw, raw2, cfg, want, desired)
    _assert_ops_shape(ops, shown, raw, cfg2, raw2)
    return ops, shown


@pytest.mark.parametrize("stray", [
    (f"{IF_ADMIN}.1001", "i", "2"),          # ifAdminStatus of the VLAN interface DEFAULT_VLAN: no port, build_cfg never shows it
    (f"{IF_ALIAS}.4097", "x", "41"),         # ifAlias of lo0
    (f"{PVID}.7", "u", "1"),                 # Trk1's PVID, rewritten with the value it has: no port of the change
    (f"{VLAN_EGRESS}.30", "x", "62" + PAD),  # a VLAN the change does not touch, written unchanged
], ids=["ifadmin-of-a-vlan-interface", "ifalias-of-a-loopback", "pvid-of-another-port", "untouched-portlist"])
def test_the_oracle_catches_a_stray_varbind(monkeypatch, stray):
    """The oracle itself: a varbind the change has no business with fails it, even one that leaves every port the read shows as it was.
    The stray varbind is put in its documented place, so only the content checks can catch it."""
    real = snmpwrite.render_ops

    def with_stray(*args):
        ops, shown = real(*args)
        return sorted([*ops, stray], key=lambda op: (ORDER.index(op[0].rpartition(".")[0]), int(op[0].rpartition(".")[2]))), shown

    monkeypatch.setattr(snmpwrite, "render_ops", with_stray)
    with pytest.raises(AssertionError):
        _render_and_store(SAMPLE, PROCURVE, {"6": {"u": "20"}})


# ── Q-BRIDGE: untagged ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_untagged_move():
    """Port 6 (ifIndex 6, BRIDGE PORT 5 = 0x08) from VLAN 1 to 20: dot1qPvid.5 (not .6) = 20; its bit set in VLAN 20's egress (62 -> 6A)
    and untagged list (20 -> 28), cleared in VLAN 1's untagged list (0A -> 02) and, since VLAN 1 is not tagged on it afterwards, in
    VLAN 1's egress list (0A -> 02). Trk1 (0x02) stays in VLAN 1, ports 3 and 1 and Trk1 stay in VLAN 20."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"6": {"u": "20"}})
    assert ops == [eg("1", "02"), eg("20", "6A"), un("1", "02"), un("20", "28"), (f"{PVID}.5", "u", "20")]
    assert shown == ["Port 6: VLAN ungetaggt 1 → 20"]


def test_untagged_move_keeps_the_old_vlan_tagged():
    """The same move, but VLAN 1 stays on port 6 as a tagged VLAN: its egress bit stays (no varbind for egress.1 at all), only the
    untagged bit goes."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"6": {"u": "20", "t": ["1"]}})
    assert ops == [eg("20", "6A"), un("1", "02"), un("20", "28"), (f"{PVID}.5", "u", "20")]
    assert shown == ["Port 6: VLAN ungetaggt 1 → 20", "Port 6: VLAN getaggt – → 1"]


def test_untagged_from_none():
    """Port 3 (bridge port 2 = 0x40) is tagged-only: there is no old untagged VLAN to clear. Bit set in VLAN 99's egress (82 -> C2) and
    untagged list (80 -> C0), PVID of bridge port 2 = 99; its tagged VLANs 20 and 30 stay."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"3": {"u": "99"}})
    assert ops == [eg("99", "C2"), un("99", "C0"), (f"{PVID}.2", "u", "99")]
    assert shown == ["Port 3: VLAN ungetaggt – → 99"]


def _port3_in_99() -> dict:
    """SAMPLE after test_untagged_from_none's change: port 3 untagged in VLAN 99, PVID 99 (it was 1)."""
    return store(SAMPLE, snmpwrite.render_ops(PROCURVE, *_read(SAMPLE), {"3": {"u": "99"}})[0])


def test_revert_to_no_untagged_vlan_restores_the_pvid():
    """R21, the revert of the change above as the planner will send it (desired = before = {u: None, pvid: "1"}, against the switch as
    it is now): the bit leaves VLAN 99's untagged list and, since 99 is not tagged on port 3, its egress list, and the explicit PVID
    goes back to 1. The switch is byte for byte the one before the change, PVID included."""
    W1 = _port3_in_99()
    ops, shown = _render_and_store(W1, PROCURVE, {"3": {"u": None, "pvid": "1"}})
    assert ops == [eg("99", "82"), un("99", "80"), (f"{PVID}.2", "u", "1")]
    assert shown == ["Port 3: VLAN ungetaggt 99 → –", "Port 3: PVID 99 → 1"]
    W2 = store(W1, ops)
    assert _read(W2)[1]["pvid"]["3"] == "1" and W2 == SAMPLE


def test_without_an_explicit_pvid_u_to_none_writes_no_pvid():
    """The same revert without pvid (as the planner sent it before R21): no PVID is written, it stays at 99, the VLAN the port just left
    (untagged ingress would land there). cfg cannot see that: it reads exactly as before the change."""
    W1 = _port3_in_99()
    ops, shown = _render_and_store(W1, PROCURVE, {"3": {"u": None}})
    assert ops == [eg("99", "82"), un("99", "80")]
    assert shown == ["Port 3: VLAN ungetaggt 99 → –"]
    cfg2, raw2 = _read(store(W1, ops))
    assert cfg2 == _read(SAMPLE)[0]
    assert raw2["pvid"]["3"] == "99" and raw2["unmanaged"] == {}


def test_revert_to_no_untagged_vlan_keeps_it_tagged():
    """u -> None while the old untagged VLAN becomes tagged: only the untagged bit goes (0A -> 02), the egress bit stays."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"6": {"u": None, "t": ["1"]}})
    assert ops == [un("1", "02")]
    assert shown == ["Port 6: VLAN ungetaggt 1 → –", "Port 6: VLAN getaggt – → 1"]


# ── R21: the explicit PVID ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_an_explicit_pvid_goes_before_the_implicit_one():
    """With u -> None the implicit rule writes no PVID; an explicit pvid is written (test_revert_to_no_untagged_vlan_restores_the_pvid).
    With a new untagged VLAN the PVID written is the explicit one, and it has to be that VLAN: one varbind, plus its line. An explicit
    pvid next to a different untagged VLAN is refused: build_cfg would read the port as unmanaged afterwards (PVID != untagged, R12),
    verify could not find u again and no change, not even a revert, could touch the port any more."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"6": {"u": "20", "pvid": "20"}})
    assert ops == [eg("1", "02"), eg("20", "6A"), un("1", "02"), un("20", "28"), (f"{PVID}.5", "u", "20")]
    assert shown == ["Port 6: VLAN ungetaggt 1 → 20", "Port 6: PVID 1 → 20"]
    cfg, raw = _read(SAMPLE)
    for desired, message in (({"6": {"u": "20", "pvid": "1"}}, "PVID 1 wiche vom ungetaggten VLAN 20 ab"),
                             ({"6": {"pvid": "20"}}, "PVID 20 wiche vom ungetaggten VLAN 1 ab"),
                             ({"3": {"u": "99", "pvid": "1"}}, "PVID 1 wiche vom ungetaggten VLAN 99 ab")):
        with pytest.raises(ValueError, match=rf"^Port \d: {message}, der Port wäre danach per SNMP nicht verwaltbar$"):
            snmpwrite.render_ops(PROCURVE, cfg, raw, desired)


def test_an_explicit_pvid_alone_repairs_it():
    """A pvid on its own: port 3 (tagged-only, PVID 99 left over) gets PVID 1 back, nothing else is written. On a port without a
    dot1qPvid row (W_ODD's A99, bridge port 13) the row is written: "–" before."""
    ops, shown = _render_and_store(store(SAMPLE, [(f"{PVID}.2", "u", "99")]), PROCURVE, {"3": {"pvid": "1"}})
    assert (ops, shown) == ([(f"{PVID}.2", "u", "1")], ["Port 3: PVID 99 → 1"])
    ops, shown = _render_and_store(ODD, PROCURVE, {"A99": {"pvid": "5"}})
    assert (ops, shown) == ([(f"{PVID}.13", "u", "5")], ["Port A99: PVID – → 5"])


def test_a_pvid_already_in_place_writes_nothing():
    cfg, raw = _read(SAMPLE)
    assert snmpwrite.render_ops(PROCURVE, cfg, raw, {"6": {"pvid": "1"}, "3": {"pvid": "1"}, "1": {"pvid": "20"}}) == ([], [])


@pytest.mark.parametrize("pvid", ["0", "4095", "020", "1a", "", " 1", "\u0661", 20, None], ids=repr)
def test_a_pvid_that_is_no_vlan_id_is_refused(pvid):
    """A VLAN ID 1..4094 as a walk shows it: decimal, no leading zero, ASCII digits only; also None is no PVID."""
    cfg, raw = _read(SAMPLE)
    with pytest.raises(ValueError, match=r"^Port 3: pvid ist keine VLAN-ID 1–4094 "):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"3": {"u": None, "pvid": pvid}})


@pytest.mark.parametrize("port, d", [("Gi1/0/1", {"pvid": "10"}), ("Gi1/0/1", {"u": "20", "pvid": "20"}), ("Gi1/0/3", {"pvid": "1"})])
def test_a_pvid_is_refused_on_cisco(port, d):
    """cisco_vmps writes the access VLAN through vmVlan and nothing on Q-BRIDGE (R20), so no PVID either, on access ports or trunks."""
    cfg, raw = _read(CISCO_SW)
    with pytest.raises(ValueError, match=rf"^Port {re.escape(port)}: PVID per SNMP nur über Q-BRIDGE, nicht bei Cisco \(vmVlan\)$"):
        snmpwrite.render_ops(CISCO, cfg, raw, {port: d})


@pytest.mark.parametrize("W, port, d", [
    (SAMPLE, "3", {"pvid": "4000"}),                           # PVID only: before R23 no VLAN check saw it
    (SAMPLE, "3", {"u": None, "pvid": "42"}),
    (SAMPLE, "6", {"u": None, "t": ["30"], "pvid": "4094"}),   # a revert to tagged-only whose PVID's VLAN is gone since
    (ODD, "A99", {"u": None, "t": ["7"], "pvid": "9"}),        # a port without dot1qPvid row (bridge port 13)
], ids=["pvid-only", "u-none", "u-to-none", "no-pvid-row"])
def test_a_pvid_whose_vlan_the_switch_does_not_have_is_refused(W, port, d):
    """R23: an explicit pvid must name a VLAN of the switch (cfg["vlans"]); a revert to a PVID whose VLAN is gone gets this reason
    instead of a SET that verify would only find unclear. One rule in snmp_block_reason, so plan_ports blocks with the same text."""
    cfg, raw = _read(W)
    reason = f"PVID {d['pvid']}: das VLAN gibt es auf diesem Switch nicht"
    with pytest.raises(ValueError, match=rf"^Port {port}: {reason}$"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {port: d})
    assert snmpwrite.snmp_block_reason(PROCURVE, cfg, raw, port, d) == reason


def test_r23_comes_after_every_reason_of_before():
    """R23 is checked last: a request render_ops refused before R23 keeps its reason (here a pvid next to another untagged VLAN, R21),
    R23 only refuses what was rendered before."""
    cfg, raw = _read(SAMPLE)
    assert snmpwrite.snmp_block_reason(PROCURVE, cfg, raw, "6", {"u": "20", "pvid": "4000"}) == \
        "PVID 4000 wiche vom ungetaggten VLAN 20 ab, der Port wäre danach per SNMP nicht verwaltbar"
    assert snmpwrite.snmp_block_reason(PROCURVE, cfg, raw, "6", {"name": "a\nb", "u": None, "t": ["30"], "pvid": "4000"}) == \
        "PVID 4000: das VLAN gibt es auf diesem Switch nicht"    # but among the VLAN checks, i.e. before en / name, as always


# ── Q-BRIDGE: tagged, and both together ────────────────────────────────────────────────────────────────────────────────────────────
def test_tagged_add_and_remove_only_touch_egress():
    """Port 1 (bridge port 3 = 0x20): VLAN 30 off (62 -> 42), VLAN 99 on (82 -> A2). No untagged list, no PVID."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"1": {"t": ["99"]}})
    assert ops == [eg("30", "42"), eg("99", "A2")]
    assert shown == ["Port 1: VLAN getaggt 30 → 99"]


def test_vlans_count_as_numbers_and_t_as_a_set():
    """With a VLAN 100 (egress 00) next to 30, text order and number order differ: varbinds and shown go by number (30 before 100).
    t is a set: given unsorted, it shows sorted, and a t that only differs in order from the current one is no change (no line)."""
    W = edit_walks(SAMPLE, vlanName={"100": hex_text("Kameras")}, vlanEgress={"100": "00" + " 00" * 7},
                   vlanUntagged={"100": "00" + " 00" * 7})
    ops, shown = _render_and_store(W, PROCURVE, {"6": {"u": "20", "t": ["100", "30"]}, "3": {"u": "100", "t": ["30", "20"]}})
    # port 6 (bp 5 = 0x08) to 20 with 30 and 100 tagged, port 3 (bp 2 = 0x40) untagged into 100: egress.100 = 08 | 40 = 48
    assert ops == [eg("1", "02"), eg("20", "6A"), eg("30", "6A"), eg("100", "48"), un("1", "02"), un("20", "28"), un("100", "40"),
                   (f"{PVID}.2", "u", "100"), (f"{PVID}.5", "u", "20")]
    assert shown == ["Port 3: VLAN ungetaggt – → 100", "Port 6: VLAN ungetaggt 1 → 20", "Port 6: VLAN getaggt – → 30, 100"]


def test_a_tagged_vlan_becomes_the_untagged_one():
    """Port 1: u 20 -> 30, and 30 leaves the tagged set in the same change. VLAN 30's egress bit must stay (it is the new untagged VLAN),
    although 30 is 'removed' from t: untagged.30 00 -> 20, untagged.20 20 -> 00, egress.20 62 -> 42, PVID of bridge port 3 = 30."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"1": {"u": "30", "t": []}})
    assert ops == [eg("20", "42"), un("20", "00"), un("30", "20"), (f"{PVID}.3", "u", "30")]
    assert shown == ["Port 1: VLAN ungetaggt 20 → 30", "Port 1: VLAN getaggt 30 → –"]


def test_untagged_and_tagged_swap():
    """Port 1: untagged 20 / tagged 30 becomes untagged 30 / tagged 20. Both egress bits stay; only the untagged bits and the PVID move.
    Flipping the fields one by one would clear egress.30 ('30 removed from t') and leave the port untagged in a VLAN it no longer
    egresses."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"1": {"u": "30", "t": ["20"]}})
    assert ops == [un("20", "00"), un("30", "20"), (f"{PVID}.3", "u", "30")]
    assert shown == ["Port 1: VLAN ungetaggt 20 → 30", "Port 1: VLAN getaggt 30 → 20"]


def test_procurve_pvid_never_lands_in_the_tagged_set():
    """ProCurve: the PVID must not be one of the port's tagged VLANs. A desired state that would make the untagged VLAN (which the PVID
    follows) tagged as well is refused, whether u and t change together or t alone takes in the current untagged VLAN. Every PVID
    render_ops writes for a port with an untagged VLAN is that VLAN (_assert_ops_shape checks that on every rendered change)."""
    cfg, raw = _read(SAMPLE)
    for desired in ({"6": {"u": "20", "t": ["20"]}}, {"1": {"t": ["20", "30"]}}, {"Trk1": {"u": "20"}}):
        with pytest.raises(ValueError, match=r"VLAN 20 kann nicht ungetaggt und getaggt zugleich sein"):
            snmpwrite.render_ops(PROCURVE, cfg, raw, desired)


def test_two_ports_joining_one_vlan_share_one_varbind_per_list():
    """Ports 2 (bp 1 = 0x80) and 6 (bp 5 = 0x08) both move to VLAN 30. All bit flips of one PortList go into ONE copy of the read
    bytes and ONE varbind: egress.30 = 62 | 80 | 08 = EA, untagged.30 = 00 | 80 | 08 = 88. One varbind per port and list would let the
    second overwrite the first in the PDU (the last writer wins), and port 2 would never join VLAN 30."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"6": {"u": "30"}, "2": {"u": "30"}})
    assert ops == [eg("1", "02"), eg("30", "EA"), eg("99", "02"), un("1", "02"), un("30", "88"), un("99", "00"),
                   (f"{PVID}.1", "u", "30"), (f"{PVID}.5", "u", "30")]
    assert shown == ["Port 2: VLAN ungetaggt 99 → 30", "Port 6: VLAN ungetaggt 1 → 30"]


def test_every_field_of_one_port():
    """u, pvid, t, en and name of port 6 at once, given in another order: the varbinds in the documented order (egress, untagged, PVID,
    ifAdminStatus, ifAlias; ifAdminStatus / ifAlias of IFINDEX 6, the PVID of bridge port 5), shown in the fixed field order."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"6": {"name": "Kopierer", "en": True, "t": ["30"], "pvid": "20", "u": "20"}})
    assert ops == [eg("1", "02"), eg("20", "6A"), eg("30", "6A"), un("1", "02"), un("20", "28"), (f"{PVID}.5", "u", "20"),
                   (f"{IF_ADMIN}.6", "i", "1"), (f"{IF_ALIAS}.6", "x", "4B6F706965726572")]
    assert shown == ["Port 6: VLAN ungetaggt 1 → 20", "Port 6: PVID 1 → 20", "Port 6: VLAN getaggt – → 30", "Port 6: aus → an",
                     'Port 6: Name "unused" → "Kopierer"']


def test_a_portlist_too_short_for_the_port_grows_only_to_set_its_bit():
    """VLAN 30's lists are a single byte here and port 6 sits on bridge port 12 (byte 1, 0x10). Moving it into VLAN 30 has to set a
    bit behind the end: the list grows by exactly that byte (62 -> 62 10, 00 -> 00 10). Clearing in VLAN 1 keeps its 8 bytes."""
    W = edit_walks(SAMPLE, bp2if={"5": None, "12": "6"}, pvid={"5": None, "12": "1"},
                   vlanEgress={"1": "02 10 00 00 00 00 00 00", "30": "62"}, vlanUntagged={"1": "02 10 00 00 00 00 00 00", "30": "00"})
    assert _read(W)[1]["port2bp"]["6"] == 12
    ops, _ = _render_and_store(W, PROCURVE, {"6": {"u": "30"}})
    assert ops == [eg("1", "02"), (f"{VLAN_EGRESS}.30", "x", "6210"), un("1", "02"), (f"{VLAN_UNTAGGED}.30", "x", "0010"),
                   (f"{PVID}.12", "u", "30")]
    ops, _ = _render_and_store(W, PROCURVE, {"6": {"t": ["30"]}})    # tagged only: the untagged list is not touched (nor grown)
    assert ops == [(f"{VLAN_EGRESS}.30", "x", "6210")]


# ── IF-MIB: admin status and name ──────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("port, en, op, line", [
    ("1", False, (f"{IF_ADMIN}.1", "i", "2"), "Port 1: an → aus"),
    ("6", True, (f"{IF_ADMIN}.6", "i", "1"), "Port 6: aus → an"),        # ifIndex 6, not bridge port 5
    ("Trk1", False, (f"{IF_ADMIN}.289", "i", "2"), "Port Trk1: an → aus"),
])
def test_admin_status(port, en, op, line):
    assert _render_and_store(SAMPLE, PROCURVE, {port: {"en": en}}) == ([op], [line])


@pytest.mark.parametrize("port, name, value, line", [
    ("2", "Drucker", "447275636B6572", 'Port 2: Name "" → "Drucker"'),
    ("1", "", "", 'Port 1: Name "Platz-107" → ""'),                              # an empty name clears the alias
    ("6", "Büro Erdgeschoss", "42C3BC726F2045726467657363686F7373", 'Port 6: Name "unused" → "Büro Erdgeschoss"'),
    ("6", "x" * 64, "78" * 64, f'Port 6: Name "unused" → "{"x" * 64}"'),        # 64 bytes: the most ifAlias takes
    ("6", "ä" * 32, "C3A4" * 32, f'Port 6: Name "unused" → "{"ä" * 32}"'),      # 32 characters, 64 bytes in UTF-8
    ("6", 'a"b\\c', "6122625C63", 'Port 6: Name "unused" → "a\\"b\\\\c"'),     # quote and backslash escaped in shown
    ("2", "--frei--", "2D2D667265692D2D", 'Port 2: Name "" → "--frei--"'),      # R22: as hex, getopt never sees the dashes
    ("2", "-", "2D", 'Port 2: Name "" → "-"'),
])
def test_name(port, name, value, line):
    """R22: ifAlias of the port's IFINDEX, as hex (type x) of the name's UTF-8 bytes; read back (as hex, decoded) it is the name."""
    ifindex = {"1": 1, "2": 2, "6": 6}[port]
    assert _render_and_store(SAMPLE, PROCURVE, {port: {"name": name}}) == ([(f"{IF_ALIAS}.{ifindex}", "x", value)], [line])


def test_a_name_lands_as_its_utf8_bytes_and_goes_back_byte_exact():
    """"Büro" is stored as 42 C3 BC 72 6F, exactly what read_cfg walks back and decodes; renaming back to the old name restores the old
    bytes exactly: the switch is the one of the start."""
    ops, _ = _render_and_store(SAMPLE, PROCURVE, {"1": {"name": "Büro"}})
    assert ops == [(f"{IF_ALIAS}.1", "x", "42C3BC726F")]
    W1 = store(SAMPLE, ops)
    assert dict(W1["ifAlias"])[f"{IF_ALIAS}.1"] == "42 C3 BC 72 6F"
    ops2, shown2 = _render_and_store(W1, PROCURVE, {"1": {"name": "Platz-107"}})
    assert shown2 == ['Port 1: Name "Büro" → "Platz-107"'] and store(W1, ops2) == SAMPLE


def test_an_old_name_with_control_characters_is_shown_escaped():
    """The old name comes from the switch and may hold anything; shown stays one printable line per change."""
    W = edit_walks(SAMPLE, ifAlias={"2": hex_text("a\nb\x7f\u2028")})
    _, shown = _render_and_store(W, PROCURVE, {"2": {"name": "Drucker"}})
    assert shown == ['Port 2: Name "a\\u000ab\\u007f\\u2028" → "Drucker"']


def test_fields_already_as_desired_render_nothing():
    cfg, raw = _read(SAMPLE)
    desired = {"1": {"u": "20", "t": ["30"], "en": True, "name": "Platz-107", "pvid": "20"}, "3": {"u": None, "t": ["30", "20"]},
               "6": {}, "4": {}}
    assert snmpwrite.render_ops(PROCURVE, cfg, raw, desired) == ([], [])


# ── trunks ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_the_trunk_interface_itself_is_one_bridge_port():
    """Trk1 (bridge port 7 = 0x02) loses VLAN 99 (82 -> 80); its members 4 and 5 follow (the oracle reads them back with Trk1's VLANs)."""
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"Trk1": {"t": ["20", "30"]}})
    assert ops == [eg("99", "80")]
    assert shown == ["Port Trk1: VLAN getaggt 20, 30, 99 → 20, 30"]
    ops, shown = _render_and_store(SAMPLE, PROCURVE, {"Trk1": {"u": "20", "t": ["30", "99"]}})
    assert ops == [eg("1", "08"), un("1", "08"), un("20", "22"), (f"{PVID}.7", "u", "20")]
    assert shown == ["Port Trk1: VLAN ungetaggt 1 → 20", "Port Trk1: VLAN getaggt 20, 30, 99 → 30, 99"]


@pytest.mark.parametrize("d", [{"u": "20"}, {"t": ["20"]}, {"en": False}, {"name": "x"}, {"en": True}, {"pvid": "1"}], ids=str)
@pytest.mark.parametrize("port", ["4", "5"])
def test_a_trunk_member_is_refused(port, d):
    """A member has no bridge port of its own: any write to it is refused, even one that would change nothing."""
    cfg, raw = _read(SAMPLE)
    with pytest.raises(ValueError, match=rf"^Port {port}: gehört zu Trk1, bitte Trk1 wählen$"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {port: d})


def test_a_lag_of_another_vendor():
    """W_CATALYST read for a Q-BRIDGE driver: Po1 (bridge port 56 = 0x01 of byte 6) drops VLAN 20; VLAN 20's egress list loses only
    that bit (50 00 00 00 00 00 01 00 -> 50 00 ...). The 0x10 of member Gi1/0/4's own bridge port 4 stays: it is no effective one.
    The members are refused, the LAG can also be renamed (ifIndex 5001)."""
    ops, shown = _render_and_store(CATALYST, ARISTA, {"Po1": {"t": ["10"]}}, "arista")
    assert ops == [(f"{VLAN_EGRESS}.20", "x", "5000000000000000")]
    assert shown == ["Port Po1: VLAN getaggt 10, 20 → 10"]
    ops, _ = _render_and_store(CATALYST, ARISTA, {"Po1": {"u": "20", "t": ["10"]}, "Gi1/0/1": {"name": "Etage"}}, "arista")
    assert ops == [(f"{VLAN_EGRESS}.1", "x", "4000000000000000"), (f"{VLAN_UNTAGGED}.1", "x", "4000000000000000"),
                   (f"{VLAN_UNTAGGED}.20", "x", "1000000000000100"), (f"{PVID}.56", "u", "20"), (f"{IF_ALIAS}.10101", "x", "4574616765")]
    assert _render_and_store(CATALYST, ARISTA, {"Po1": {"name": "core"}}, "arista")[0] == [(f"{IF_ALIAS}.5001", "x", "636F7265")]
    cfg, raw = _read(CATALYST, "arista")
    for member in ("Gi1/0/3", "Gi1/0/4"):
        with pytest.raises(ValueError, match=rf"^Port {re.escape(member)}: gehört zu Po1, bitte Po1 wählen$"):
            snmpwrite.render_ops(ARISTA, cfg, raw, {member: {"en": False}})


# ── refused: the port ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
HYBRID = edit_walks(SAMPLE, vlanEgress={"1": "4A 00 00 00 00 00 00 00"},
                    vlanUntagged={"1": "4A 00 00 00 00 00 00 00", "20": "60 00 00 00 00 00 00 00"})    # port 3 untagged in 1 and 20


PVID_MISMATCH = edit_walks(SAMPLE, pvid={"3": "1"})    # port 1 (bp 3): untagged 20, PVID 1 (R12)


@pytest.mark.parametrize("W, selection, desired, message", [
    (HYBRID, "procurve", {"3": {"u": "99"}},
     r"^Port 3: ungetaggt in mehreren VLANs \(1, 20\): Hybrid-/General-Port, per SNMP nicht verwaltbar$"),
    (HYBRID, "procurve", {"3": {"t": ["30", "99"], "en": False}}, r"^Port 3: ungetaggt in mehreren VLANs"),
    (PVID_MISMATCH, "procurve", {"1": {"u": "99"}}, r"^Port 1: PVID 1 weicht vom ungetaggten VLAN 20 ab"),
    (PVID_MISMATCH, "procurve", {"1": {"pvid": "20"}}, r"^Port 1: PVID 1 weicht vom ungetaggten VLAN 20 ab"),
    (ODD, "procurve", {"A3": {"en": False}}, r"^Port A3: kein Bridge-Port \(etwa ein Management-Port\), per SNMP nur zur Anzeige$"),
    (ODD, "procurve", {"Trk3": {"name": "x"}}, r"^Port Trk3: kein Bridge-Port"),    # an empty trunk without a bridge port
    (ODD, "procurve", {"A2": {"u": "5"}}, r"^Port A2: gehört zu Trk2, bitte Trk2 wählen$"),
    (SAMPLE, "procurve", {"7": {"en": False}}, r"^Port 7: gibt es auf diesem Switch nicht$"),
    (SAMPLE, "procurve", {"DEFAULT_VLAN": {"en": False}}, r"^Port DEFAULT_VLAN: gibt es auf diesem Switch nicht$"),
], ids=["hybrid", "hybrid-tagged", "pvid-mismatch", "pvid-mismatch-pvid", "no-bridge-port", "empty-trunk", "member", "unknown",
        "vlan-interface"])
def test_a_port_the_write_path_must_not_touch_is_refused(W, selection, desired, message):
    """An unmanaged port (R9 hybrid, R12 PVID != untagged) is refused for its VLAN fields (u, t, pvid): those are what cfg cannot
    describe with its one u."""
    cfg, raw = _read(W, selection)
    with pytest.raises(ValueError, match=message):
        snmpwrite.render_ops(PROCURVE, cfg, raw, desired)


@pytest.mark.parametrize("W, port, old_name", [(HYBRID, "3", ""), (PVID_MISMATCH, "1", "Platz-107")], ids=["hybrid", "pvid-mismatch"])
def test_an_unmanaged_port_still_takes_en_and_name(W, port, old_name):
    """R41: only the VLAN slot of an unmanaged port is ambiguous; on / off and the name never read u. They are written as on any port
    (ifAdminStatus / ifAlias by ifIndex, here = the port number), and the VLAN bits of the port stay untouched (the oracle of
    _render_and_store checks every bit and the read-back)."""
    cfg, raw = _read(W, "procurve")
    assert port in raw["unmanaged"]
    assert snmpwrite.snmp_block_reason(PROCURVE, cfg, raw, port, {"en": False, "name": "Telefon"}) is None
    ops, shown = _render_and_store(W, PROCURVE, {port: {"en": False, "name": "Telefon"}})
    assert ops == [(f"{IF_ADMIN}.{port}", "i", "2"), (f"{IF_ALIAS}.{port}", "x", "54656C65666F6E")]
    assert shown == [f"Port {port}: an → aus", f'Port {port}: Name "{old_name}" → "Telefon"']


def test_a_port_without_an_ifindex_is_refused():
    """Cannot come out of build_cfg (every port has its ifIndex), so raw is edited by hand."""
    cfg, raw = _read(SAMPLE)
    raw = {**raw, "ifindex": {p: i for p, i in raw["ifindex"].items() if p != "2"}}
    with pytest.raises(ValueError, match=r"^Port 2: kein Bridge-Port"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"2": {"en": False}})


@pytest.mark.parametrize("edit, message", [
    ({"bp2port": {3: "2"}}, r"^Port 1: Bridge-Port 3 gehört laut bp2port zu Port 2$"),
    ({"bp2port": {3: None}}, r"^Port 1: Bridge-Port 3 gehört laut bp2port zu keinem Port$"),
    ({"port2bp": {"2": 3}}, r"^Port 2: Bridge-Port 3 gehört laut bp2port zu Port 1$"),    # two ports of one change on one bridge port
    ({"ifindex": {"2": 1}}, r"^Port 2: ifIndex 1 gehört auch zu Port 1$"),
], ids=["bp-owned-by-another", "bp-owned-by-none", "two-ports-one-bp", "two-ports-one-ifindex"])
def test_a_raw_whose_indexes_do_not_fit_together_is_refused(edit, message):
    """A port's effective bridge port must belong to it (raw["bp2port"]), and no two ports of one change may share an ifIndex: otherwise
    a bit or a varbind would land on another port. Cannot come out of build_cfg, so raw is edited by hand."""
    cfg, raw = _read(SAMPLE)
    raw = {**raw, **{k: {i: v for i, v in {**raw[k], **e}.items() if v is not None} for k, e in edit.items()}}
    with pytest.raises(ValueError, match=message):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"1": {"en": False}, "2": {"en": False}})


def test_one_refused_port_refuses_the_whole_change():
    cfg, raw = _read(SAMPLE)
    with pytest.raises(ValueError, match=r"^Port 4: gehört zu Trk1"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"6": {"u": "20"}, "4": {"u": "20"}, "1": {"en": False}})


# ── refused: the field or value ────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("fields", [{"x": True}, {"m": True}, {"cl": 2}, {"al": 2}, {"xuv": "99"}, {"muv": None}, {"vlan": "20"},
                                    {"u": "20", "m": True}, {"poe": False, "x": True}], ids=str)
def test_a_field_the_snmp_write_path_does_not_have_is_refused(fields):
    """Fail closed: 802.1X / MAC auth only go over the CLI, anything unknown is refused, also next to a valid u or a PoE value (PoE
    itself is a field of the write path since Task 12, tests/test_poe.py)."""
    cfg, raw = _read(SAMPLE)
    odd = ", ".join(sorted(k for k in fields if k not in ("u", "poe")))
    with pytest.raises(ValueError, match=rf"^Port 6: per SNMP nicht änderbar: {odd}$"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"6": fields})


@pytest.mark.parametrize("name, message", [
    ("x" * 65, r"Name zu lang \(65 Bytes in UTF-8, ifAlias erlaubt höchstens 64\)"),
    ("ä" * 33, r"Name zu lang \(66 Bytes in UTF-8"),          # 33 characters, but 66 bytes
    ("a\x00b", r"Name enthält Steuerzeichen"),
    ("a\nb", r"Name enthält Steuerzeichen"),
    ("\t", r"Name enthält Steuerzeichen"),
    ("x\x7f", r"Name enthält Steuerzeichen"),
    ("x\x85", r"Name enthält Steuerzeichen"),                 # C1, e.g. from a latin-1 decoded alias
    ("x\ud800", r"Name enthält Zeichen, die sich nicht als UTF-8 schreiben lassen"),
    (None, r"Name ist kein Text"),
    (5, r"Name ist kein Text"),
])
def test_a_name_that_cannot_be_written_is_refused(name, message):
    cfg, raw = _read(SAMPLE)
    with pytest.raises(ValueError, match=r"^Port 2: " + message):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"2": {"name": name}})


@pytest.mark.parametrize("d, message", [
    ({"u": "42"}, r"VLAN 42 gibt es auf diesem Switch nicht"),
    ({"t": ["42"]}, r"VLAN 42 gibt es auf diesem Switch nicht"),
    ({"u": "020"}, r"VLAN 020 gibt es auf diesem Switch nicht"),
    ({"u": None}, r"wäre in keinem VLAN mehr"),
    ({"u": 20}, r"u ist keine VLAN-ID \(20\)"),
    ({"t": "30"}, r"t ist keine Liste verschiedener VLAN-IDs \('30'\)"),
    ({"t": ["30", "30"]}, r"t ist keine Liste verschiedener VLAN-IDs"),
    ({"t": [30]}, r"t ist keine Liste verschiedener VLAN-IDs"),
    ({"en": "false"}, r"en ist nicht wahr oder falsch \('false'\)"),
    ({"en": 0}, r"en ist nicht wahr oder falsch \(0\)"),
], ids=str)
def test_a_vlan_or_value_that_cannot_be_written_is_refused(d, message):
    cfg, raw = _read(SAMPLE)
    with pytest.raises(ValueError, match=r"^Port 6: " + message):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"6": d})


def test_a_port_left_in_no_vlan_is_refused():
    cfg, raw = _read(SAMPLE)
    with pytest.raises(ValueError, match=r"^Port 3: wäre in keinem VLAN mehr$"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {"3": {"t": []}})


@pytest.mark.parametrize("field, value, cap, label", [("u", "20", "snmp_vlan", "VLANs"), ("t", ["30"], "snmp_vlan", "VLANs"),
                                                      ("pvid", "1", "snmp_vlan", "VLANs"), ("en", True, "snmp_admin", "An/Aus"),
                                                      ("name", "x", "snmp_name", "Portnamen")])
def test_a_driver_without_the_capability_refuses_the_field(field, value, cap, label):
    """drivers.can decides per field; a field that needs another capability still works."""
    limited = Driver("limited", PROCURVE.caps - {cap}, "qbridge", dict(PROCURVE.oids), "")
    cfg, raw = _read(SAMPLE)
    with pytest.raises(ValueError, match=rf"^Port 6: Treiber limited kann {label} nicht per SNMP schreiben$"):
        snmpwrite.render_ops(limited, cfg, raw, {"6": {field: value}})
    other = {"snmp_vlan": {"en": True}, "snmp_admin": {"name": "x"}, "snmp_name": {"u": "20"}}[cap]
    assert snmpwrite.render_ops(limited, cfg, raw, {"6": other})[0]


def test_an_unknown_vlan_strategy_refuses_vlan_changes_only():
    odd = Driver("odd", PROCURVE.caps, "vtp", dict(PROCURVE.oids), "")
    cfg, raw = _read(SAMPLE)
    for d in ({"u": "20"}, {"pvid": "20"}):
        with pytest.raises(ValueError, match=r"^Port 6: VLAN-Strategie 'vtp' des Treibers odd ist unbekannt$"):
            snmpwrite.render_ops(odd, cfg, raw, {"6": d})
    assert snmpwrite.render_ops(odd, cfg, raw, {"6": {"en": True}}) == ([(f"{IF_ADMIN}.6", "i", "1")], ["Port 6: aus → an"])


# ── cisco_vmps (R20): the access VLAN via vmVlan, nothing else ─────────────────────────────────────────────────────────────────────
# W_CISCO (read with the ProCurve port selection plus its vmVlan rows): Gi1/0/1 (ifIndex 1, vmVlan 10), Gi1/0/2 (2, vmVlan 10),
# Gi1/0/3 (3, no vmVlan row: a trunk, u 1, t [10, 20]), Gi1/0/4 (4, vmVlan 0: u None, down).
def test_cisco_access_port_via_vmvlan():
    ops, shown = _render_and_store(CISCO_SW, CISCO, {"Gi1/0/1": {"u": "20"}})
    assert ops == [(f"{VMVLAN}.1", "i", "20")]                  # vmVlan of ifIndex 1, an INTEGER; no Q-BRIDGE varbind at all
    assert shown == ["Port Gi1/0/1: Access-VLAN 10 → 20"]
    ops, shown = _render_and_store(CISCO_SW, CISCO, {"Gi1/0/4": {"u": "10", "en": True}, "Gi1/0/2": {"u": "1"}})
    assert ops == [(f"{VMVLAN}.2", "i", "1"), (f"{VMVLAN}.4", "i", "10"), (f"{IF_ADMIN}.4", "i", "1")]
    assert shown == ["Port Gi1/0/2: Access-VLAN 10 → 1", "Port Gi1/0/4: Access-VLAN – → 10", "Port Gi1/0/4: aus → an"]


def test_cisco_catalyst_access_port():
    """W_CATALYST with its vmVlan rows, read for the cisco driver: Gi1/0/1 is ifIndex 10101."""
    ops, shown = _render_and_store(CATALYST_VM, CISCO, {"Gi1/0/1": {"u": "20"}, "Po1": {"name": "core"}}, "cisco")
    assert ops == [(f"{VMVLAN}.10101", "i", "20"), (f"{IF_ALIAS}.5001", "x", "636F7265")]
    assert shown == ["Port Gi1/0/1: Access-VLAN 10 → 20", 'Port Po1: Name "uplink-core" → "core"']


@pytest.mark.parametrize("W, selection, port, d, message", [
    (CISCO_SW, "procurve", "Gi1/0/3", {"u": "10"}, r"Trunk-VLANs auf Cisco per SNMP noch nicht unterstützt \(CISCO-VTP-MIB\)$"),
    (CISCO_SW, "procurve", "Gi1/0/3", {"t": ["10"]}, r"Trunk-VLANs auf Cisco per SNMP noch nicht unterstützt \(CISCO-VTP-MIB\)$"),
    (CATALYST_VM, "cisco", "Po1", {"t": ["10"]}, r"Trunk-VLANs auf Cisco per SNMP noch nicht unterstützt"),
    (CISCO_SW, "procurve", "Gi1/0/1", {"t": ["20"]}, r"Access-Port \(vmVlan\), getaggte VLANs gibt es dort nicht$"),
    (CISCO_SW, "procurve", "Gi1/0/1", {"u": "20", "t": ["10"]}, r"Access-Port \(vmVlan\), getaggte VLANs gibt es dort nicht$"),
    (CISCO_SW, "procurve", "Gi1/0/2", {"u": None}, r"Access-Port \(vmVlan\) ohne VLAN lässt sich per SNMP nicht setzen$"),
    (CISCO_SW, "procurve", "Gi1/0/1", {"u": "42"}, r"VLAN 42 gibt es auf diesem Switch nicht$"),
], ids=["trunk-u", "trunk-t", "lag-t", "access-t", "access-u-and-t", "access-none", "no-such-vlan"])
def test_cisco_vlan_changes_outside_the_access_vlan_are_refused(W, selection, port, d, message):
    cfg, raw = _read(W, selection)
    with pytest.raises(ValueError, match=rf"^Port {re.escape(port)}: " + message):
        snmpwrite.render_ops(CISCO, cfg, raw, {port: d})


def test_cisco_admin_and_name_work_on_every_port():
    ops, shown = _render_and_store(CISCO_SW, CISCO, {"Gi1/0/3": {"en": False, "name": "Core"}})
    assert ops == [(f"{IF_ADMIN}.3", "i", "2"), (f"{IF_ALIAS}.3", "x", "436F7265")]
    assert shown == ["Port Gi1/0/3: an → aus", 'Port Gi1/0/3: Name "uplink" → "Core"']


def test_a_vmvlan_port_is_refused_by_a_qbridge_driver():
    """A raw read with vmVlan rows describes the access ports by vmVlan; a Q-BRIDGE write (VLANs or PVID) would start from the wrong
    VLAN."""
    cfg, raw = _read(CISCO_SW)
    for d in ({"u": "20"}, {"pvid": "10"}):
        with pytest.raises(ValueError, match=r"^Port Gi1/0/1: als Access-Port per vmVlan gelesen, Treiber generic schreibt aber Q-BRIDGE$"):
            snmpwrite.render_ops(GENERIC, cfg, raw, {"Gi1/0/1": d})


# ── shown: deterministic, natural port order, the token (R6) ──────────────────────────────────────────────────────────────────────
def _tiny_switch(names: list[str]) -> dict:
    """Ports with these names at ifIndex = bridge port = 1, 2, ... (ifType 6, so every driver selects them), all untagged in VLAN 1, in
    the agent format."""
    idx = {str(i + 1): name for i, name in enumerate(names)}
    size = (len(names) + 7) // 8
    return agent({
        "ifName": walk_rows(IF_NAME, idx), "ifType": walk_rows(IF_TYPE, {i: ETHERNET for i in idx}),
        "ifAlias": walk_rows(IF_ALIAS, {i: "" for i in idx}), "ifAdmin": walk_rows(IF_ADMIN, {i: "1" for i in idx}),
        "bp2if": walk_rows(BP2IF, {i: i for i in idx}), "vlanName": walk_rows(VLAN_NAME, {"1": "default", "10": "Daten"}),
        "vlanEgress": walk_rows(VLAN_EGRESS, {"1": portlist_hex(range(1, len(names) + 1), size), "10": portlist_hex([], size)}),
        "vlanUntagged": walk_rows(VLAN_UNTAGGED, {"1": portlist_hex(range(1, len(names) + 1), size), "10": portlist_hex([], size)}),
        "pvid": walk_rows(PVID, {i: "1" for i in idx}), "ifStack": walk_rows(IF_STACK, {}),
    })


@pytest.mark.parametrize("selection, names", [
    ("procurve", ["1", "2", "10", "24", "A1", "A2", "A10", "B1", "Trk1", "Trk2", "Trk10"]),
    ("generic", ["Gi1/0/1", "Gi1/0/2", "Gi1/0/10", "Gi2/0/1", "Po1", "Po2", "Po10", "Te1/1/1", "ae0", "ae1", "ge-0/0/1", "ge-0/0/2",
                 "ge-0/0/10", "ge-1/0/0"]),
    ("procurve", ["2", "0" * 4400 + "3", "10", "1" * 5000]),    # more digits than int() takes: still sorted, nothing raises
], ids=["procurve", "other-vendors", "huge-numbers"])
def test_shown_is_in_natural_port_order(selection, names):
    """Numbers inside a port name count as numbers (2 before 10), for ProCurve names and those of other vendors alike, however many
    digits they have; the order in which the request lists the ports does not matter."""
    rng = random.Random(len(names))
    W = _tiny_switch(rng.sample(names, len(names)))
    cfg, raw = _read(W, selection)
    shuffled = rng.sample(names, len(names))
    ops, shown = snmpwrite.render_ops(PROCURVE if selection == "procurve" else GENERIC, cfg, raw, {p: {"en": False} for p in shuffled})
    assert shown == [f"Port {p}: an → aus" for p in names]
    assert [op[0] for op in ops] == [f"{IF_ADMIN}.{i}" for i in range(1, len(names) + 1)]    # varbinds by ifIndex


def test_a_port_name_with_huge_numbers_is_refused_like_any_unknown_port():
    """Sorting the request never raises (int() would, beyond 4300 digits): such a port that does not exist gets the usual reason."""
    huge = "1" * 5000
    cfg, raw = _read(SAMPLE)
    with pytest.raises(ValueError, match=rf"^Port {huge}: gibt es auf diesem Switch nicht$"):
        snmpwrite.render_ops(PROCURVE, cfg, raw, {huge: {"en": False}, "1": {"en": False}})


def test_render_ops_is_deterministic_and_leaves_its_input_alone():
    desired = {"6": {"name": "K", "en": True, "t": ["30"], "u": "20"}, "2": {"u": "30"}, "Trk1": {"t": ["20", "30"]},
               "3": {"pvid": "20"}}
    cfg, raw = _read(SAMPLE)
    before = copy.deepcopy((cfg, raw, desired))
    first = snmpwrite.render_ops(PROCURVE, cfg, raw, desired)
    assert (cfg, raw, desired) == before
    assert snmpwrite.render_ops(PROCURVE, cfg, raw, desired) == first
    backwards = {p: dict(reversed(list(d.items()))) for p, d in reversed(list(desired.items()))}
    assert snmpwrite.render_ops(PROCURVE, cfg, raw, backwards) == first


def test_the_token_ignores_other_ports_in_the_same_portlist_but_not_the_port_itself():
    """R6: shown holds before -> after of the changed ports, never PortList bytes. Port 3 leaving VLAN 20 after the preview (egress.20
    62 -> 22) changes no line, so the token holds, and the varbinds are rendered from the fresh bytes: port 6 joins (22 | 08 = 2A)
    and port 3 stays out. Port 6 itself having moved to VLAN 99 meanwhile changes its line, so the token breaks."""
    desired = {"6": {"u": "20"}}
    ops, shown = _render_and_store(SAMPLE, PROCURVE, desired)
    drifted = edit_walks(SAMPLE, vlanEgress={"20": "22 00 00 00 00 00 00 00"})
    ops2, shown2 = _render_and_store(drifted, PROCURVE, desired)
    assert shown2 == shown and changes.cmd_token(shown2) == changes.cmd_token(shown)
    assert ops2 == [eg("20", "2A") if op[0] == f"{VLAN_EGRESS}.20" else op for op in ops]
    moved = edit_walks(SAMPLE, vlanEgress={"1": "02" + " 00" * 7, "99": "8A" + " 00" * 7},
                       vlanUntagged={"1": "02" + " 00" * 7, "99": "88" + " 00" * 7}, pvid={"5": "99"})
    _, shown3 = _render_and_store(moved, PROCURVE, desired)
    assert shown3 == ["Port 6: VLAN ungetaggt 99 → 20"] and changes.cmd_token(shown3) != changes.cmd_token(shown)


# ── with the planner: a change and its revert ─────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("W, selection, driver, ports, change", [
    (SAMPLE, "procurve", PROCURVE, ["1", "3", "6"], {"untagged": "99", "tagged_add": ["20"], "name": "Raum-1"}),
    (SAMPLE, "procurve", PROCURVE, ["1", "2"], {"tagged_remove": ["30"], "tagged_add": ["1"], "status": "off"}),
    (SAMPLE, "procurve", PROCURVE, ["2", "6"], {"name": "--frei--"}),
    (edit_walks(SAMPLE, ifAlias={"2": hex_text("--frei--"), "6": hex_text("Büro")}), "procurve", PROCURVE, ["2", "6"],
     {"name": "Drucker"}),
    (CISCO_SW, "procurve", CISCO, ["Gi1/0/1", "Gi1/0/2"], {"untagged": "20", "status": "off", "name": "Kasse"}),
], ids=["procurve-untagged", "procurve-tagged", "rename-to-dashes", "revert-dashes-and-umlaut", "cisco-access"])
def test_a_planned_change_and_its_revert_round_trip(monkeypatch, W, selection, driver, ports, change):
    """End to end with the SNMP planner (changes.plan_ports, mechanism "snmp"), which builds `desired`, records `before` (with the PVID
    of a Q-BRIDGE port whose u changes, R21) and renders with render_ops: the change is planned on the switch as read, and its varbinds
    pass the simulated switch. The revert is planned the way main._make_plan plans one (R7: desired = the change's `before`, against a
    fresh read) and stored as well: afterwards the switch is byte for byte the one of the start (PortLists, PVIDs, admin status,
    aliases, vmVlan). The ProCurve CLI rendering never runs on this path (it could not even name a port like Gi1/0/1)."""
    def no_cli(*args):
        raise AssertionError("ProCurve CLI rendering on the SNMP path")
    monkeypatch.setattr(changes, "_commands", no_cli)
    cfg0, raw0 = _read(W, selection)
    inv = {"ports": {n: {"n": n, "tr": next((t for t, ms in cfg0["trunks"].items() if n in ms), ""), "l": [], "o": False}
                     for n in cfg0["ports"]}, "uplinks": set()}
    plan = changes.plan_ports("K.15.99.0001", inv, cfg0, {"ports": ports, "set": change}, mechanism="snmp", driver=driver, raw=raw0)
    assert plan["blocked"] == [] and plan["desired"]
    assert (plan["ops"], plan["shown"]) == _render_and_store(W, driver, plan["desired"], selection)
    W1 = store(W, plan["ops"])
    cfg1, raw1 = _read(W1, selection)
    revert = changes.plan_ports("K.15.99.0001", inv, cfg1, {"desired": plan["before"]}, mechanism="snmp", driver=driver, raw=raw1)
    assert revert["blocked"] == [] and revert["desired"] == plan["before"]
    assert (revert["ops"], revert["shown"]) == _render_and_store(W1, driver, revert["desired"], selection)
    assert store(W1, revert["ops"]) == W


# ── property: random switches, random requests ─────────────────────────────────────────────────────────────────────────────────────
GOOD_NAMES = ["", "Drucker", "Büro 2.1", "AP Flur 3", "x" * 64, "ä" * 32, 'a"b', "a-b", "--frei--", "-x"]
BAD_NAMES = ["x" * 65, "ä" * 33, "Tab\there", "nul\x00", "c1\x85", "\ud800", None]
BAD_PVIDS = ["0", "4095", "020", None, 5]
NO_SUCH_VLAN = "4095"    # the generators draw VLANs from 1..4094
LINE_START = {"u": ("VLAN ungetaggt ", "Access-VLAN "), "pvid": ("PVID ",), "t": ("VLAN getaggt ",), "en": ("an → ", "aus → "),
              "name": ("Name ",)}


def _natural(name: str):
    """The test's own natural sort key (digit runs as numbers), written independently of the code under test."""
    return [(0, int(part), "") if part.isdigit() else (1, 0, part) for part in re.findall(r"\d+|\D+", name)], name


def _bad_name(name) -> bool:
    if not isinstance(name, str):
        return True
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError:
        return True
    return size > 64 or any(ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0 for c in name)


def _good_pvid(pvid) -> bool:
    return isinstance(pvid, str) and pvid.isascii() and pvid.isdigit() and pvid[0] != "0" and 1 <= int(pvid) <= 4094


def _must_refuse(driver, cfg: dict, raw: dict, desired: dict) -> bool:
    """The test's own reading of the rules: must render_ops refuse this request?"""
    members = {m for ms in cfg["trunks"].values() for m in ms}
    for p, d in desired.items():
        if not d:
            continue
        if p not in cfg["ports"] or set(d) - {"u", "pvid", "t", "en", "name"}:
            return True
        # R45: on cisco_vmps a port with a vmVlan row needs no bridge port, unless the request has a Q-BRIDGE field (t, pvid)
        switchport = driver.vlan_strategy == "cisco_vmps" and p in raw["vmvlan"] and not {"t", "pvid"} & set(d)
        # R41: an unmanaged port is refused for its VLAN fields only
        if (p in raw["unmanaged"] and {"u", "t", "pvid"} & set(d)) or p in members or (p not in raw["port2bp"] and not switchport) \
                or p not in raw["ifindex"]:
            return True
        if "name" in d and _bad_name(d["name"]):
            return True
        st = cfg["ports"][p]
        u, t = d.get("u", st["u"]), d.get("t", st["t"])
        if "pvid" in d and (not _good_pvid(d["pvid"]) or driver.vlan_strategy != "qbridge" or p in raw["vmvlan"]
                            or d["pvid"] not in cfg["vlans"] or (u is not None and d["pvid"] != u)):
            return True
        if u == st["u"] and set(t) == set(st["t"]):
            continue
        if driver.vlan_strategy == "cisco_vmps":
            if p not in raw["vmvlan"] or set(t) != set(st["t"]) or u is None or u not in cfg["vlans"]:
                return True
        elif (u is not None and u not in cfg["vlans"]) or not set(t) <= set(cfg["vlans"]) or (u is not None and u in t) or (u is None and not t):
            return True
    return False


def _random_switch(rng: random.Random) -> tuple[dict, object, str]:
    """(W in the agent format, driver, port selection): a ProCurve, or a switch of another vendor with a random non-ProCurve driver;
    cisco (cisco_vmps) often, with vmVlan rows on a random part of its ports (0 = no VLAN)."""
    if rng.random() < 0.4:
        return agent(random_procurve_switch(rng)[0]), PROCURVE, "procurve"
    W = agent(random_multivendor_switch(rng)[0])
    driver = CISCO if rng.random() < 0.3 else DRIVERS[rng.choice(NON_PROCURVE)]
    if driver.vlan_strategy == "cisco_vmps":
        cfg, raw = _read(W, driver.name)
        W = {**W, "vmVlan": walk_rows(VMVLAN, {str(i): rng.choice([*cfg["vlans"], "0"]) for i in raw["ifindex"].values()
                                                if rng.random() < 0.6})}
    return W, driver, driver.name


def _random_desired(rng: random.Random, cfg: dict, raw: dict, driver) -> dict:
    """A random request. Mostly (clean) one the planner could send: ports the write path may touch, u from the switch's VLANs, t without
    u and never leaving the port in no VLAN, a pvid only on Q-BRIDGE and only the untagged VLAN (or any VLAN without one), names that
    can be written, on cisco VLAN changes only as the access VLAN of a vmVlan port. Otherwise (wild) anything: any port, no or a missing
    VLAN, u in t, a pvid that is no VLAN ID, not the untagged VLAN or one the switch does not have, bad names, a CLI-only field, a port
    that does not exist."""
    vids, desired = list(cfg["vlans"]), {}
    missing = next(str(v) for v in range(1, 4095) if str(v) not in cfg["vlans"])    # a VLAN ID, but no VLAN of this switch
    members = {m for ms in cfg["trunks"].values() for m in ms}
    switchport = {p for p in raw["vmvlan"] if driver.vlan_strategy == "cisco_vmps"}    # R45: no bridge port needed (clean: no t / pvid)
    # an unmanaged port is writable for en / name (R41): a clean request leaves its VLANs alone
    writable = [p for p in cfg["ports"] if p not in members and (p in raw["port2bp"] or p in switchport)]
    clean = bool(writable) and rng.random() < 0.7
    qbridge = driver.vlan_strategy == "qbridge"
    pool = writable if clean else list(cfg["ports"])
    for p in rng.sample(pool, rng.randint(1, min(4, len(pool)))):
        st, d = cfg["ports"][p], {}
        access = driver.vlan_strategy == "cisco_vmps" and p in raw["vmvlan"]
        vlans = not (clean and p in raw["unmanaged"])
        if vlans and clean and qbridge and rng.random() < 0.15:
            # a revert to no untagged VLAN, as for a port that was tagged-only: at least one tagged VLAN, maybe the old untagged one,
            # mostly with the PVID the planner recorded (R21)
            d["u"], d["t"] = None, sorted(rng.sample(vids, rng.randint(1, len(vids))), key=int)
            if rng.random() < 0.6:
                d["pvid"] = rng.choice(vids)
        elif vlans and rng.random() < 0.6 and (not clean or qbridge or access):
            d["u"] = rng.choice(vids) if clean else rng.choice([*vids, *vids, None, NO_SUCH_VLAN])
            if clean and qbridge and rng.random() < 0.2:
                d["pvid"] = d["u"]
        if vlans and "t" not in d and rng.random() < 0.5 and (not clean or qbridge):
            u = d.get("u", st["u"])
            choices = [v for v in vids if v != u] if clean or rng.random() < 0.85 else [*vids, NO_SUCH_VLAN]
            least = 1 if clean and u is None else 0
            d["t"] = sorted(rng.sample(choices, rng.randint(min(least, len(choices)), len(choices))), key=int)
        if vlans and clean and qbridge and "pvid" not in d and rng.random() < 0.08:    # a PVID repair
            u = d.get("u", st["u"])
            d["pvid"] = u if u is not None else rng.choice(vids)
        if not clean and rng.random() < 0.08:
            d["pvid"] = rng.choice([*vids, *BAD_PVIDS, missing])
        if rng.random() < 0.3:
            d["en"] = rng.random() < 0.5
        if rng.random() < 0.3:
            d["name"] = rng.choice(GOOD_NAMES if clean or rng.random() < 0.5 else BAD_NAMES)
        if not clean and rng.random() < 0.05:
            d[rng.choice(["x", "m", "cl", "al", "xuv", "muv", "poe"])] = True
        if not clean and rng.random() < 0.06:    # a revert to tagged-only whose PVID's VLAN is gone since (R23)
            d.update(u=None, t=[rng.choice(vids)], pvid=missing)
        desired[p] = d
    if not clean and rng.random() < 0.05:
        desired["no-such-port"] = {"en": False}
    return desired


def _flip(W: dict, key: str, vid: str, bp: int) -> dict:
    """A copy of W with bridge port bp's bit toggled in VLAN vid's PortList of walk `key`, printed as the walk prints it."""
    data = bytearray(bytes.fromhex(dict(W[key])[f"{WALK_BASES[key]}.{vid}"].replace(" ", "")))
    data[(bp - 1) // 8] ^= 0x80 >> ((bp - 1) % 8)
    return edit_walks(W, **{key: {vid: " ".join(f"{b:02X}" for b in data)}})


def _flipped(raw: dict, op: tuple[str, str, str]) -> set[int]:
    """The bridge ports whose bit a PortList varbind flips against the list as read."""
    base, _, vid = op[0].rpartition(".")
    return _bits(bytes.fromhex(op[2])) ^ _bits(raw[PORTLISTS[base]][vid])


def test_snmp_block_reason_is_the_one_source_of_the_refusals():
    """The refusal rules per port exist once, in snmp_block_reason: render_ops raises "Port X: <reason>" with its reason, and
    changes.plan_ports lists the same reason as a blocked entry. On random switches and requests (the clean and the wild ones of the
    property test below), render_ops of a single port refuses exactly when snmp_block_reason gives a reason, and with exactly that text;
    a refusal render_ops made up somewhere else, or a reason it would not act on, fails here."""
    rng = random.Random(9)
    seen = {"refused": 0, "rendered": 0, "R23": 0}
    for case in range(800):
        W, driver, selection = _random_switch(rng)
        cfg, raw = _read(W, selection)
        for p, d in _random_desired(rng, cfg, raw, driver).items():
            reason = snmpwrite.snmp_block_reason(driver, cfg, raw, p, d)
            if reason is None:
                snmpwrite.render_ops(driver, cfg, raw, {p: d})
                seen["rendered"] += 1
                continue
            with pytest.raises(ValueError) as refused:
                snmpwrite.render_ops(driver, cfg, raw, {p: d})
            assert str(refused.value) == f"Port {p}: {reason}", case
            seen["refused"] += 1
            seen["R23"] += reason == f"PVID {d.get('pvid')}: das VLAN gibt es auf diesem Switch nicht"
    assert min(seen["refused"], seen["rendered"]) > 400 and seen["R23"] > 10, seen


def test_render_ops_on_random_switches_against_the_simulated_switch():
    """1500 random switches (ProCurve, other vendors with every driver, cisco with vmVlan access ports) and random requests. Whatever
    the rules refuse, render_ops refuses (ValueError, nothing rendered); everything else passes the simulated switch (module
    docstring). Then the R6 property on the same request: one random bit of a bridge port the request does not touch flips in one
    PortList (another port's VLANs drift after the preview); the lines and so the token stay the same, and the varbinds rendered on
    the drifted switch pass the oracle there, i.e. they keep the drift. The counters at the end make sure the random cases keep
    reaching what matters."""
    rng = random.Random(8)
    seen: dict[str, int] = dict.fromkeys(("rendered", "refused", "drifted", "shared PortList", "trunk VLANs", "u -> None",
                                          "tagged -> untagged", "vmVlan", "explicit pvid", "no bridge port", "unmanaged"), 0)
    for case in range(1500):
        W, driver, selection = _random_switch(rng)
        cfg, raw = _read(W, selection)
        desired = _random_desired(rng, cfg, raw, driver)
        if _must_refuse(driver, cfg, raw, desired):
            with pytest.raises(ValueError):
                snmpwrite.render_ops(driver, cfg, raw, desired)
            seen["refused"] += 1
            continue
        ops, shown = _render_and_store(W, driver, desired, selection)

        def changes_field(p: str, k: str) -> bool:
            if k == "pvid":
                return desired[p]["pvid"] != raw["pvid"].get(p)
            return set(desired[p][k]) != set(cfg["ports"][p][k]) if k == "t" else desired[p][k] != cfg["ports"][p][k]

        changed = [(p, k) for p in sorted(desired, key=_natural) for k in ("u", "pvid", "t", "en", "name")
                   if k in desired[p] and changes_field(p, k)]
        assert len(shown) == len(changed), case    # one line per port and changed field, ports in natural order, fields u pvid t en name
        for line, (p, k) in zip(shown, changed):
            assert line.startswith(f"Port {p}: ") and line[len(f"Port {p}: "):].startswith(LINE_START[k]), (case, line, p, k)
        assert snmpwrite.render_ops(driver, cfg, raw, {p: desired[p] for p in reversed(list(desired))}) == (ops, shown), case
        seen["rendered"] += 1
        for key, hit in (
            ("shared PortList", any(len(_flipped(raw, op)) > 1 for op in ops if op[0].rpartition(".")[0] in PORTLISTS)),
            ("trunk VLANs", any((p, "u") in changed or (p, "t") in changed for p in cfg["trunks"])),
            ("u -> None", any(k == "u" and desired[p]["u"] is None for p, k in changed)),
            ("tagged -> untagged", any(k == "u" and desired[p]["u"] in cfg["ports"][p]["t"] for p, k in changed)),
            ("vmVlan", any(oid.startswith(VMVLAN + ".") for oid, _, _ in ops)),
            ("explicit pvid", any(k == "pvid" for _, k in changed)),
            ("no bridge port", any(p not in raw["port2bp"] for p, _ in changed)),    # R45: a cisco vmVlan port, written all the same
            ("unmanaged", any(p in raw["unmanaged"] for p, _ in changed)),           # R41: on / off or name of an unmanaged port
        ):
            seen[key] += hit
        own = {raw["port2bp"][p] for p, d in desired.items() if d and p in raw["port2bp"]}
        lists = [(key, v, bp) for key, kind in (("vlanEgress", "egress"), ("vlanUntagged", "untagged")) for v in raw[kind]
                 for bp in range(1, 8 * len(raw[kind][v]) + 1) if bp not in own]
        if lists:
            W2 = _flip(W, *rng.choice(lists))
            assert _render_and_store(W2, driver, desired, selection)[1] == shown, case
            seen["drifted"] += 1
    assert min(seen["rendered"], seen["drifted"]) > 800 and seen["refused"] > 400, seen
    assert min(seen[k] for k in ("shared PortList", "trunk VLANs", "u -> None", "tagged -> untagged", "vmVlan", "explicit pvid")) > 50, seen
    assert seen["no bridge port"] > 10 and seen["unmanaged"] > 5, seen
