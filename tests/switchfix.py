"""Walk fixtures shared by the SNMP tests (tests/test_snmpwrite_read.py, tests/test_port_discovery.py and the write-path tests
after them): the base OIDs, hand-written walk rows of sample switches with what they mean, random switch generators that return
their own truth, small helpers to build and edit walk rows, and the simulated agent the write-path tests set and read back (agent,
store). W is always walk key -> [(oid, value), ...], as poller.poll_switch collects it and snmpwrite.build_cfg reads it.

A plain module, not a conftest: the tests import it by name (`from switchfix import ...`), which works because pytest puts tests/
on sys.path for the test modules there (default prepend import mode); pytest.ini forbids a root-level conftest.py. Nothing here
imports app code: OIDs, expected values and the generators' truth are written out by hand, so they stay independent of the code
under test.
"""
import copy
import random
import re

HOST = "203.0.113.21"

# Base OIDs of the nine walks, written out by hand, without the leading dot (snmp._parse drops it).
#   object                          instance index        meaning here
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"             # ifName                         .<ifIndex>            the port key
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"           # ifAlias                        .<ifIndex>            the port description ("name")
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"               # ifAdminStatus                  .<ifIndex>            1 up, 2 down ("en")
BP2IF = "1.3.6.1.2.1.17.1.4.1.2"               # dot1dBasePortIfIndex           .<bridge port>        -> ifIndex
VLAN_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"       # dot1qVlanStaticName            .<vid>
VLAN_EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"     # dot1qVlanStaticEgressPorts     .<vid>                PortList over bridge ports (hex)
VLAN_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.3.1.4"   # dot1qVlanStaticUntaggedPorts   .<vid>                PortList over bridge ports (hex)
PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"            # dot1qPvid                      .<bridge port>
IF_STACK = "1.3.6.1.2.1.31.1.2.1.3"            # ifStackStatus                  .<higher>.<lower>     a trunk's members sit below TrkN
BASES = {
    "ifName": IF_NAME, "ifAlias": IF_ALIAS, "ifAdmin": IF_ADMIN, "bp2if": BP2IF, "vlanName": VLAN_NAME,
    "vlanEgress": VLAN_EGRESS, "vlanUntagged": VLAN_UNTAGGED, "pvid": PVID, "ifStack": IF_STACK,
}
HEX_WALKS = {"vlanEgress", "vlanUntagged"}    # the two PortLists are walked with -Ox (hex), like the poller does
# The free text read_cfg walks with -Ox as well (R18): an OCTET STRING with a non-ASCII byte (an umlaut) would otherwise come out as
# bare hex wrapped every 16 bytes, which a strict text walk refuses. The display poller reads them as text, as it always did.
FREE_TEXT = {"ifAlias", "vlanName"}
# Only for drivers that select their ports by ifType (every driver but procurve, see poller.select_ports), one more walk:
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"               # ifType (IANAifType)  .<ifIndex>   6 / 117 physical port, 161 LAG, anything else no port
# Only for drivers with vlan_strategy cisco_vmps, one more:
VMVLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"       # vmVlan (CISCO-VLAN-MEMBERSHIP-MIB)  .<ifIndex>   access VLAN, 0 = none; trunk ports have no row
WALK_BASES = {**BASES, "ifType": IF_TYPE, "vmVlan": VMVLAN}


def walk_rows(base: str, values: dict) -> list[tuple[str, str]]:
    """Walk rows as snmp.walk returns them: (numeric OID without leading dot, value without quotes), in the order given."""
    return [(f"{base}.{index}", value) for index, value in values.items()]


def hex_text(text: str, encoding: str = "utf-8") -> str:
    """A free-text value as snmp.walk returns it from a walk with -Ox: the bytes as hex pairs ("" stays "")."""
    return " ".join(f"{byte:02X}" for byte in text.encode(encoding))


def walk_answer(rows: list[tuple[str, str]], oid: str, hex_values: bool) -> list[tuple[str, str]]:
    """What a fake snmp.walk returns for recorded text rows of `oid`: the rows as they are, except that the free text (FREE_TEXT)
    comes as hex when walked with hex_values, as net-snmp prints every OCTET STRING with -Ox. The PortLists are recorded as hex
    already."""
    if hex_values and oid in {BASES[k] for k in FREE_TEXT}:
        return [(row_oid, hex_text(value)) for row_oid, value in rows]
    return list(rows)


def netsnmp_hex(data: bytes) -> str:
    """An OCTET STRING as snmpbulkwalk -Oq -Ox prints it: hex pairs, each followed by a space, 16 to a line; empty as \"\"."""
    if not data:
        return '""'
    return "\n".join("".join(f"{byte:02X} " for byte in data[i:i + 16]) for i in range(0, len(data), 16))


# ── The sample switch ────────────────────────────────────────────────────────────────────────────────────────────────────────
# Modelled on a ProCurve: ports 1-6, Trk1 = ports 4 + 5 (ifStack 289.4 / 289.5), VLAN interfaces and a loopback the port filter
# drops (ifIndex >= 1000). Like on a ProCurve the trunk members have no bridge port of their own; the trunk has one.
# The bridge ports are permuted against the ifIndexes on purpose:
#   port (ifIndex)   bridge port   VLANs                              ifAdminStatus   ifAlias
#   1    (1)         3             untagged 20, tagged 30             up              "Platz-107"
#   2    (2)         1             untagged 99                        up
#   3    (3)         2             tagged 20 + 30, no untagged VLAN   up
#   4, 5 (4, 5)      - (Trk1: 7)   as Trk1                            up
#   6    (6)         5             untagged 1                         down            "unused"
#   Trk1 (289)       7             untagged 1, tagged 20 + 30 + 99    up
# PortList bits: bridge port n is bit 0x80 >> ((n - 1) % 8) of byte (n - 1) // 8, so bp 1 = 0x80, 2 = 0x40, 3 = 0x20, 5 = 0x08, 7 = 0x02.
W_SAMPLE = {
    "ifName": walk_rows(IF_NAME, {"1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "289": "Trk1", "1001": "DEFAULT_VLAN",
                                  "1020": "VLAN20", "1030": "VLAN30", "1099": "VLAN99", "4097": "lo0"}),
    "ifAlias": walk_rows(IF_ALIAS, {"1": "Platz-107", "2": "", "3": "", "4": "", "5": "", "6": "unused", "289": "", "1001": "",
                                    "1020": "", "1030": "", "1099": "", "4097": ""}),
    "ifAdmin": walk_rows(IF_ADMIN, {"1": "1", "2": "1", "3": "1", "4": "1", "5": "1", "6": "2", "289": "1", "1001": "1", "1020": "1",
                                    "1030": "1", "1099": "1", "4097": "1"}),
    "bp2if": walk_rows(BP2IF, {"1": "2", "2": "3", "3": "1", "5": "6", "7": "289"}),
    "vlanName": walk_rows(VLAN_NAME, {"1": "DEFAULT_VLAN", "20": "Clients", "30": "Voice", "99": "Guest"}),
    "vlanEgress": walk_rows(VLAN_EGRESS, {
        "1": "0A 00 00 00 00 00 00 00",     # bp 5 (port 6) + bp 7 (Trk1)
        "20": "62 00 00 00 00 00 00 00",    # bp 2 (port 3) + bp 3 (port 1) + bp 7 (Trk1)
        "30": "62 00 00 00 00 00 00 00",    # the same three
        "99": "82 00 00 00 00 00 00 00",    # bp 1 (port 2) + bp 7 (Trk1)
    }),
    "vlanUntagged": walk_rows(VLAN_UNTAGGED, {
        "1": "0A 00 00 00 00 00 00 00",     # port 6, Trk1
        "20": "20 00 00 00 00 00 00 00",    # port 1
        "30": "00 00 00 00 00 00 00 00",    # nobody
        "99": "80 00 00 00 00 00 00 00",    # port 2
    }),
    "pvid": walk_rows(PVID, {"1": "99", "2": "1", "3": "20", "5": "1", "7": "1"}),
    "ifStack": walk_rows(IF_STACK, {"0.1": "1", "0.2": "1", "0.3": "1", "0.6": "1", "0.289": "1", "1.0": "1", "2.0": "1", "3.0": "1",
                                    "4.0": "1", "5.0": "1", "6.0": "1", "289.4": "1", "289.5": "1"}),
}
# The sample switch's ifType rows, for the drivers that select by them: ports 1-6 Ethernet, Trk1 a LAG, the VLAN interfaces virtual,
# lo0 a loopback. So the ifType rule selects the very ports the ProCurve rule does.
IFTYPE_SAMPLE = walk_rows(IF_TYPE, {"1": "6", "2": "6", "3": "6", "4": "6", "5": "6", "6": "6", "289": "161", "1001": "53", "1020": "53",
                                    "1030": "53", "1099": "53", "4097": "24"})
# The sample switch as a cisco_vmps driver would read it: vmVlan puts port 1 into VLAN 99 (Q-BRIDGE: 20) and port 6 into none.
VMVLAN_SAMPLE = walk_rows(VMVLAN, {"1": "99", "6": "0"})
RECORDING = {BASES[k]: rows for k, rows in W_SAMPLE.items()} | {IF_TYPE: IFTYPE_SAMPLE, VMVLAN: VMVLAN_SAMPLE}    # the fake agent, by OID

NAC = {"x": False, "m": False, "cl": None, "al": None, "xuv": None, "muv": None}    # 802.1X / MAC auth: not readable here, defaulted
EXPECTED_PORTS = {
    "1": {"u": "20", "t": ["30"], "name": "Platz-107", "en": True, **NAC, "poe": None},
    "2": {"u": "99", "t": [], "name": "", "en": True, **NAC, "poe": None},
    "3": {"u": None, "t": ["20", "30"], "name": "", "en": True, **NAC, "poe": None},
    "4": {"u": "1", "t": ["20", "30", "99"], "name": "", "en": True, **NAC, "poe": None},     # trunk member: Trk1's VLANs
    "5": {"u": "1", "t": ["20", "30", "99"], "name": "", "en": True, **NAC, "poe": None},
    "6": {"u": "1", "t": [], "name": "unused", "en": False, **NAC, "poe": None},
    "Trk1": {"u": "1", "t": ["20", "30", "99"], "name": "", "en": True, **NAC, "poe": None},
}

# A switches row as far as read_cfg looks at it; no secrets set, so poller.creds_of needs no SECRET_KEY.
ROW = {"id": 7, "name": "SW-EK-01", "host": HOST, "sys_name": "SW-EK-01", "driver": "procurve", "snmp_version": "2c",
       "snmp_community": None, "snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None, "snmp_priv_proto": None,
       "snmp_priv_pass": None}


def oid_order(row: tuple[str, str]) -> list[tuple[int, int | str]]:
    """Walk order: numeric OID components compared as numbers (a malformed, non-numeric one sorts behind them)."""
    return [(0, int(part)) if part.isdigit() else (1, part) for part in row[0].split(".")]


def edit_walks(W: dict, **edits) -> dict:
    """A copy of W with single rows changed: walk key -> {index: new value, or None to drop the row}. Rows stay in walk order."""
    W = copy.deepcopy(W)
    for key, changed in edits.items():
        rows = dict(W[key])
        for index, value in changed.items():
            oid = f"{WALK_BASES[key]}.{index}"
            if value is None:
                del rows[oid]
            else:
                rows[oid] = value
        W[key] = sorted(rows.items(), key=oid_order)
    return W

# Rows a real agent can send besides the clean case, on a second switch: the port filter's edges (a VLAN interface, loopbacks and
# a non-numeric index below 1000, the 999/1000 boundary), a trunk member that keeps a bridge port of its own with conflicting bits
# (bp 11: untagged in VLAN 5) next to one that has none, an empty trunk (Trk3: nothing below it, ifStack 291.0, no bridge port),
# a port that is no bridge port (A3), missing ifAlias rows (A3, A4), a bridge port owned by a dropped interface (bp 14), a bridge
# port without a PVID row (bp 13), a bit for a bridge port nobody owns (bp 48 in VLAN 7's egress) and a stack row of a VLAN
# interface over a port.
#   bridge port -> ifIndex: 10 -> 1 (A1), 11 -> 2 (A2), 12 -> 290 (Trk2), 13 -> 999 (A99), 14 -> 5 (vlan5, dropped)
#   bits in byte 1: bp 10 = 0x40, 11 = 0x20, 12 = 0x10, 13 = 0x08, 14 = 0x04; bp 48 = 0x01 in byte 5
W_ODD = {
    "ifName": walk_rows(IF_NAME, {"1": "A1", "2": "A2", "3": "A3", "4": "A4", "5": "vlan5", "6": "Loopback0", "7": "InLoopBack0",
                                  "8.0": "ghost", "290": "Trk2", "291": "Trk3", "999": "A99", "1000": "A100", "1005": "VLAN5"}),
    "ifAlias": walk_rows(IF_ALIAS, {"1": "uplink-core", "2": "", "290": "to-core", "999": "edge"}),
    "ifAdmin": walk_rows(IF_ADMIN, {"1": "1", "2": "1", "3": "2", "4": "1", "5": "1", "290": "1", "291": "1", "999": "1", "1000": "1"}),
    "bp2if": walk_rows(BP2IF, {"10": "1", "11": "2", "12": "290", "13": "999", "14": "5"}),
    "vlanName": walk_rows(VLAN_NAME, {"5": "Servers", "7": ""}),
    "vlanEgress": walk_rows(VLAN_EGRESS, {
        "5": "00 7C 00 00 00 00",           # bp 10 (A1), 11 (A2's own), 12 (Trk2), 13 (A99), 14 (vlan5)
        "7": "00 70 00 00 00 01",           # bp 10 (A1), 11 (A2's own), 12 (Trk2), 48 (nobody)
    }),
    "vlanUntagged": walk_rows(VLAN_UNTAGGED, {
        "5": "00 2C 00 00 00 00",           # bp 11 (A2's own), 13 (A99), 14 (vlan5)
        "7": "00 40 00 00 00 00",           # bp 10 (A1)
    }),
    "pvid": walk_rows(PVID, {"10": "7", "11": "5", "12": "1", "14": "5"}),
    "ifStack": walk_rows(IF_STACK, {"0.1": "1", "0.3": "1", "0.290": "1", "0.291": "1", "1.0": "1", "290.2": "1", "290.4": "1",
                                    "291.0": "1", "1005.1": "1"}),
}


def portlist_hex(bridge_ports, size: int) -> str:
    """A PortList as net-snmp prints it with -Ox, bit math written out here: bridge port n = bit 0x80 >> (n-1)%8 of byte (n-1)//8."""
    buf = bytearray(size)
    for bp in bridge_ports:
        buf[(bp - 1) // 8] |= 0x80 >> ((bp - 1) % 8)
    return " ".join(f"{b:02X}" for b in buf)


def random_procurve_switch(rng: random.Random) -> tuple[dict, dict]:
    """A random but well-formed switch: W in walk order, plus the generator's own ground truth. Well-formed means unique port names
    and the VLAN table and ifAdminStatus read completely (build_cfg refuses anything else, see the fail-closed tests below); now and
    then a port is untagged in two VLANs (hybrid) or has a PVID other than its untagged VLAN.

    The truth comes from the sets the generator drew, not through bitmap_ports or a copy of the port loop: per port u / t / name /
    en and the unmanaged reason, and the raw maps (effective bridge port, owner per bridge port, PVID, ...), trunks and VLANs."""
    phys = [str(i) for i in rng.sample(range(1, 300), rng.randint(1, 10))]
    names = {ifi: rng.choice(("", "A", "B")) + str(k + 1) for k, ifi in enumerate(phys)}
    free, trunks = list(phys), {}                            # trunk ifIndex -> member ifIndexes
    for n, ifi in enumerate(str(i) for i in rng.sample(range(300, 900), rng.randint(0, 2))):
        trunks[ifi] = rng.sample(free, rng.randint(0, min(3, len(free))))    # now and then an empty trunk
        free = [p for p in free if p not in trunks[ifi]]
        names[ifi] = f"Trk{n + 1}"
    kept = dict(names)                                       # ifIndex -> port name: everything so far is a port
    dropped = dict(rng.sample([("900", "vlan7"), ("901", "lo0"), ("902", "Loopback1"), ("903", "InLoopBack0"), ("1000", "A100"),
                               ("1007", "VLAN7"), ("4097", "lo1")], rng.randint(0, 4)))
    names.update(dropped)
    member_of = {m: t for t, mem in trunks.items() for m in mem}
    owners = [i for i in kept if (i not in member_of or rng.random() < 0.3) and rng.random() < 0.85]    # members rarely own one
    owners += [i for i in dropped if rng.random() < 0.3]
    bp_of = dict(zip(owners, rng.sample(range(1, 48), len(owners))))
    vids = [str(v) for v in rng.sample(range(1, 4095), rng.randint(1, 5))]
    egress, untagged, pvids = {v: set() for v in vids}, {v: set() for v in vids}, {}
    for ifi, bp in bp_of.items():
        if ifi in member_of or ifi in dropped:               # nobody's effective bridge port: any bits, even untagged everywhere
            for v in rng.sample(vids, rng.randint(0, len(vids))):
                egress[v].add(bp)
                untagged[v].add(bp)
            if rng.random() < 0.85:
                pvids[bp] = rng.choice([*vids, "1"])
            continue
        u = rng.choice([None, *vids])
        for v in rng.sample([v for v in vids if v != u], rng.randint(0, len(vids) - (u is not None))):
            egress[v].add(bp)
        if u:
            egress[u].add(bp)
            untagged[u].add(bp)
            if len(vids) > 1 and rng.random() < 0.1:         # a hybrid / general port: untagged in a second VLAN as well
                second = rng.choice([v for v in vids if v != u])
                egress[second].add(bp)
                untagged[second].add(bp)
        roll = rng.random()                                  # the PVID: as a rule the untagged VLAN, now and then another, or no row
        if u and roll < 0.75:
            pvids[bp] = u
        elif roll < 0.9:
            pvids[bp] = rng.choice([*vids, "1"])
    for bp in rng.sample(range(48, 65), rng.randint(0, 2)):    # bits for bridge ports nobody owns
        egress[rng.choice(vids)].add(bp)
        untagged[rng.choice(vids)].add(bp)
    size = 8 + rng.randint(0, 2)
    stack = {f"{t}.{m}": "1" for t, mem in trunks.items() for m in mem}
    stack.update({f"{t}.0": "1" for t, mem in trunks.items() if not mem})    # nothing below an empty trunk
    stack.update({f"0.{i}": "1" for i in kept if i not in member_of})
    stack.update({f"{i}.0": "1" for i in phys})
    if "900" in dropped:
        stack[f"900.{phys[0]}"] = "1"                        # a VLAN interface over a port: not a trunk
    ifname_rows = walk_rows(IF_NAME, names)
    if rng.random() < 0.3:
        ifname_rows.append((f"{IF_NAME}.{phys[0]}.0", "ghost"))    # a non-numeric index
    aliases = {i: rng.choice(("", "uplink", "Platz-107", "AP Flur 3")) for i in names if rng.random() < 0.75}
    admins = {i: rng.choice(("1", "2", "3")) for i in names if i in kept or rng.random() < 0.5}    # 3 = testing
    vnames = {v: rng.choice(("", f"VLAN-{v}", "Clients")) for v in vids}
    W = {
        "ifName": ifname_rows,
        "ifAlias": walk_rows(IF_ALIAS, aliases),
        "ifAdmin": walk_rows(IF_ADMIN, admins),
        "bp2if": walk_rows(BP2IF, {str(bp): ifi for ifi, bp in bp_of.items()}),
        "vlanName": walk_rows(VLAN_NAME, vnames),
        "vlanEgress": walk_rows(VLAN_EGRESS, {v: portlist_hex(egress[v], size) for v in vids}),
        "vlanUntagged": walk_rows(VLAN_UNTAGGED, {v: portlist_hex(untagged[v], size) for v in vids}),
        "pvid": walk_rows(PVID, {str(bp): v for bp, v in pvids.items()}),
        "ifStack": walk_rows(IF_STACK, stack),
    }
    W = {k: sorted(rows, key=oid_order) for k, rows in W.items()}

    ports, port2bp, pvid_of = {}, {}, {}
    for ifi in sorted(kept, key=int):
        name, bp = kept[ifi], bp_of.get(member_of.get(ifi, ifi))    # a member counts with its trunk's bridge port, never its own
        un = sorted((v for v in vids if bp in untagged[v]), key=int)
        tagged = sorted((v for v in vids if bp in egress[v] and bp not in untagged[v]), key=int)
        u, reason = (un[0] if len(un) == 1 else None), None
        if len(un) > 1:
            reason = f"ungetaggt in mehreren VLANs ({', '.join(un)}): Hybrid-/General-Port, per SNMP nicht verwaltbar"
        elif u is not None and bp in pvids and pvids[bp] != u:
            reason, u = (f"PVID {pvids[bp]} weicht vom ungetaggten VLAN {u} ab (Fehlkonfiguration oder dynamisch per 802.1X/RADIUS "
                         f"zugewiesen) – per SNMP nicht verwaltbar"), None
        ports[name] = {"u": u, "t": tagged, "name": aliases.get(ifi, ""), "en": admins[ifi] == "1", "unmanaged": reason}
        if bp:
            port2bp[name] = bp
            if bp in pvids:
                pvid_of[name] = pvids[bp]
    truth = {
        "ports": ports,
        "raw": {
            "port2bp": port2bp, "pvid": pvid_of, "bp2port": {bp: kept[i] for i, bp in bp_of.items() if i in kept},
            "ifindex": {kept[i]: int(i) for i in kept}, "admin": {kept[i]: int(admins[i]) for i in kept},
            "alias": {kept[i]: aliases[i] for i in kept if i in aliases},
            "egress": {v: bytes.fromhex(portlist_hex(egress[v], size).replace(" ", "")) for v in vids},
            "untagged": {v: bytes.fromhex(portlist_hex(untagged[v], size).replace(" ", "")) for v in vids},
            "unmanaged": {n: st["unmanaged"] for n, st in ports.items() if st["unmanaged"]}, "poe": {}, "vmvlan": {},
        },
        "trunks": {names[t]: [names[m] for m in sorted(mem, key=int)] for t, mem in trunks.items() if mem},
        "vlans": {v: vnames[v] for v in sorted(vids, key=int)},
    }
    return W, truth

# A Catalyst-like switch (small ifIndexes as on IOS-XE), bridge port = ifIndex + 8. Q-BRIDGE and vmVlan disagree on purpose:
#   port (ifIndex)   bridge port   Q-BRIDGE                      vmVlan   cfg u / t
#   Gi1/0/1 (1)      9             untagged 1, egress 10         10       10 / []        vmVlan wins; an access port has no tagged VLAN
#   Gi1/0/2 (2)      10            untagged 10                   10       10 / []
#   Gi1/0/3 (3)      11            untagged 1, tagged 10 + 20    -        1 / [10, 20]   a trunk port has no vmVlan row: Q-BRIDGE stays
#   Gi1/0/4 (4)      12            untagged 1                    0        None / []      vmVlan 0 = assigned to no VLAN
# bits in byte 1: bp 9 = 0x80, 10 = 0x40, 11 = 0x20, 12 = 0x10
W_CISCO = {
    "ifName": walk_rows(IF_NAME, {"1": "Gi1/0/1", "2": "Gi1/0/2", "3": "Gi1/0/3", "4": "Gi1/0/4"}),
    "ifAlias": walk_rows(IF_ALIAS, {"1": "Drucker", "2": "", "3": "uplink", "4": ""}),
    "ifAdmin": walk_rows(IF_ADMIN, {"1": "1", "2": "1", "3": "1", "4": "2"}),
    "bp2if": walk_rows(BP2IF, {"9": "1", "10": "2", "11": "3", "12": "4"}),
    "vlanName": walk_rows(VLAN_NAME, {"1": "default", "10": "Daten", "20": "Voice"}),
    "vlanEgress": walk_rows(VLAN_EGRESS, {"1": "00 B0", "10": "00 E0", "20": "00 20"}),
    "vlanUntagged": walk_rows(VLAN_UNTAGGED, {"1": "00 B0", "10": "00 40", "20": "00 00"}),
    "pvid": walk_rows(PVID, {"9": "1", "10": "10", "11": "1", "12": "1"}),
    "ifStack": walk_rows(IF_STACK, {"0.1": "1", "0.2": "1", "0.3": "1", "0.4": "1", "1.0": "1", "2.0": "1", "3.0": "1", "4.0": "1"}),
    "vmVlan": walk_rows(VMVLAN, {"1": "10", "2": "10", "4": "0"}),
}

# IANAifType values. Ports: physical (6, 117) and LAG (161). Never ports: everything else, e.g. these.
ETHERNET, GIGABIT, LAG = "6", "117", "161"    # ethernetCsmacd, gigabitEthernet (deprecated, still in use), ieee8023adLag
OTHER, LOOPBACK, PROP_VIRTUAL, PROP_MULTIPLEXOR, TUNNEL, L2VLAN, L3IPVLAN = "1", "24", "53", "54", "131", "135", "136"


# ── A classic Catalyst (IOS 12.2 / 15.x) ─────────────────────────────────────────────────────────────────────────────────────────
# Ports from ifIndex 10101 on, Port-channels from 5001, the SVIs at their VLAN ID. Like on a ProCurve, members of a LAG have no
# bridge port of their own, except Gi1/0/4 here: it keeps one (bp 4, untagged in VLAN 20, PVID 20) that must not count.
#   interface (ifIndex)   ifType           bridge port   VLANs                                 ifAdminStatus   ifAlias
#   Vl1 (1), Vl10 (10)    53 propVirtual   -             (SVIs: no ports)                      up
#   Po1 (5001)            161 LAG          56            untagged 1, tagged 10 + 20            up              "uplink-core"
#   Gi1/0/1 (10101)       6                1             untagged 10                           up              "Drucker"
#   Gi1/0/2 (10102)       6                2             untagged 1, tagged 20                 down
#   Gi1/0/3 (10103)       6                -             as Po1 (member)                       up
#   Gi1/0/4 (10104)       6                4 (its own)   as Po1 (member)                       up
#   Nu0 (14501)           1 other          -             (Null0: no port)                      up
#   Lo0 (20567)           24 loopback      -             (no port)                             up
# PortList bits: bp 1 = 0x80, bp 2 = 0x40, bp 4 = 0x10 in byte 0; bp 56 = 0x01 in byte 6.
W_CATALYST = {
    "ifName": walk_rows(IF_NAME, {"1": "Vl1", "10": "Vl10", "5001": "Po1", "10101": "Gi1/0/1", "10102": "Gi1/0/2", "10103": "Gi1/0/3",
                                  "10104": "Gi1/0/4", "14501": "Nu0", "20567": "Lo0"}),
    "ifType": walk_rows(IF_TYPE, {"1": PROP_VIRTUAL, "10": PROP_VIRTUAL, "5001": LAG, "10101": ETHERNET, "10102": ETHERNET,
                                  "10103": ETHERNET, "10104": ETHERNET, "14501": OTHER, "20567": LOOPBACK}),
    "ifAlias": walk_rows(IF_ALIAS, {"1": "", "10": "Clients", "5001": "uplink-core", "10101": "Drucker", "10102": "", "10103": "",
                                    "10104": "", "14501": "", "20567": ""}),
    "ifAdmin": walk_rows(IF_ADMIN, {"1": "1", "10": "1", "5001": "1", "10101": "1", "10102": "2", "10103": "1", "10104": "1", "14501": "1",
                                    "20567": "1"}),
    "bp2if": walk_rows(BP2IF, {"1": "10101", "2": "10102", "4": "10104", "56": "5001"}),
    "vlanName": walk_rows(VLAN_NAME, {"1": "default", "10": "Daten", "20": "Voice"}),
    "vlanEgress": walk_rows(VLAN_EGRESS, {
        "1": "40 00 00 00 00 00 01 00",     # bp 2 (Gi1/0/2), bp 56 (Po1)
        "10": "80 00 00 00 00 00 01 00",    # bp 1 (Gi1/0/1), bp 56
        "20": "50 00 00 00 00 00 01 00",    # bp 2, bp 4 (Gi1/0/4's own), bp 56
    }),
    "vlanUntagged": walk_rows(VLAN_UNTAGGED, {
        "1": "40 00 00 00 00 00 01 00",     # Gi1/0/2, Po1
        "10": "80 00 00 00 00 00 00 00",    # Gi1/0/1
        "20": "10 00 00 00 00 00 00 00",    # bp 4 only
    }),
    "pvid": walk_rows(PVID, {"1": "10", "2": "1", "4": "20", "56": "1"}),
    "ifStack": walk_rows(IF_STACK, {"0.1": "1", "0.10": "1", "0.5001": "1", "0.10101": "1", "0.10102": "1", "0.14501": "1", "0.20567": "1",
                                    "1.0": "1", "10.0": "1", "5001.10103": "1", "5001.10104": "1", "10101.0": "1", "10102.0": "1",
                                    "10103.0": "1", "10104.0": "1", "14501.0": "1", "20567.0": "1"}),
}
CATALYST_PORTS = {    # in ifIndex order
    "Po1": {"u": "1", "t": ["10", "20"], "name": "uplink-core", "en": True, **NAC, "poe": None},
    "Gi1/0/1": {"u": "10", "t": [], "name": "Drucker", "en": True, **NAC, "poe": None},
    "Gi1/0/2": {"u": "1", "t": ["20"], "name": "", "en": False, **NAC, "poe": None},
    "Gi1/0/3": {"u": "1", "t": ["10", "20"], "name": "", "en": True, **NAC, "poe": None},    # a member: Po1's VLANs
    "Gi1/0/4": {"u": "1", "t": ["10", "20"], "name": "", "en": True, **NAC, "poe": None},    # Po1's, not those of its own bp 4
}
# What the display poller stores per port: (ifIndex, name, trunk, members)
CATALYST_DISPLAY = [(5001, "Po1", "Po1", ["Gi1/0/3", "Gi1/0/4"]), (10101, "Gi1/0/1", "", []), (10102, "Gi1/0/2", "", []),
                    (10103, "Gi1/0/3", "Po1", []), (10104, "Gi1/0/4", "Po1", [])]
# vmVlan for the cisco driver: Gi1/0/1 and Gi1/0/2 are access ports, Po1 and its members are no access ports (no row)
CATALYST_VMVLAN = walk_rows(VMVLAN, {"10101": "10", "10102": "1"})
CATALYST_RECORDING = {WALK_BASES[k]: rows for k, rows in W_CATALYST.items()} | {VMVLAN: CATALYST_VMVLAN}    # by base OID

# Port and LAG names per vendor, and interfaces that are never ports (name pattern, ifType)
STYLES = [("Gi1/0/{}", "Po{}"), ("ge-0/0/{}", "ae{}"), ("1/1/{}", "lag{}"), ("GigabitEthernet1/0/{}", "Bridge-Aggregation{}"),
          ("ether{}", "bond{}")]
NO_PORTS = [("Vl{}", PROP_VIRTUAL), ("Nu{}", OTHER), ("Lo{}", LOOPBACK), ("vlan{}", L3IPVLAN), ("Tunnel{}", TUNNEL), ("unit{}", L2VLAN),
            ("StackPort{}", PROP_VIRTUAL)]


def random_multivendor_switch(rng: random.Random) -> tuple[dict, dict]:
    """A random, well-formed switch of another vendor: W in walk order (ifType included) and the generator's own truth.

    Its physical ports (ifType 6 or 117) are numbered from wherever the vendor starts (1, 1001, 10101 or 49153). It has up to two
    LAGs with members stacked below them, now and then none. A LAG is mostly of type 161; now and then it is of type 53 or 54 as on
    classic IOS (only for the LAG names of R17, in any case, not "bond"), and then it is a trunk only with a member, otherwise no
    port at all.
    There are interfaces that are no ports, under any name and at any ifIndex (VLAN interfaces, loopback, null, tunnel,
    subinterface, stack port), some of them stacked over a port or a LAG, and logical units of type 53 named after a port or LAG
    ("Po1.0", "ge-0/0/1.0") stacked on it. Now and then there is a non-numeric index (even with a physical type) and an ifType row
    of an interface without ifName (of a type that can be no port). Every numeric ifName row has its ifType row and every ifType row
    of a type that could be a port its ifName row: an agent's ifXTable augments its ifTable, and the write path refuses a switch
    where one is missing (R19), so such a switch would not be well-formed. Bridge
    ports and VLAN bits as in the ProCurve generator of Task 7: members and dropped interfaces may own a bridge port with arbitrary
    bits, which must not count.

    The truth comes from what the generator drew, not from select_ports: the ports in ifIndex order, every LAG that is a trunk with
    its members (an empty 161 LAG too), and per port the effective bridge port (a member uses its LAG's) with u / t from the drawn
    VLAN sets."""
    taken: set[int] = set()

    def fresh(low: int, high: int) -> str:
        while True:
            i = rng.randint(low, high)
            if i not in taken:
                taken.add(i)
                return str(i)

    port_fmt, lag_fmt = rng.choice(STYLES)
    first = rng.choice((1, 1001, 10101, 49153))
    phys = [fresh(first, first + 300) for _ in range(rng.randint(1, 10))]
    names = {ifi: port_fmt.format(k + 1) for k, ifi in enumerate(phys)}
    types = {ifi: rng.choice((ETHERNET, ETHERNET, GIGABIT)) for ifi in phys}
    free, drawn = list(phys), {}                             # LAG ifIndex -> member ifIndexes (all physical)
    for n in range(rng.randint(0, 2)):
        ifi = fresh(1, 6000)
        drawn[ifi] = rng.sample(free, rng.randint(0, min(3, len(free))))
        free = [p for p in free if p not in drawn[ifi]]
        names[ifi] = rng.choice((str, str.lower, str.upper))(lag_fmt.format(n + 1))    # a LAG name counts in any case
        types[ifi] = rng.choice((PROP_VIRTUAL, PROP_MULTIPLEXOR)) if lag_fmt != "bond{}" and rng.random() < 0.35 else LAG
    lags = {lag: mem for lag, mem in drawn.items() if types[lag] == LAG or mem}    # the trunks: a 53 / 54 LAG needs a member
    kept = {i: name for i, name in names.items() if i in phys or i in lags}       # ifIndex -> port name
    dropped = {i: name for i, name in names.items() if i not in kept}             # a 53 / 54 LAG without members: no port
    noise = {}
    for _ in range(rng.randint(0, 4)):
        fmt, kind = rng.choice(NO_PORTS)
        ifi = fresh(1, 30000)
        noise[ifi], types[ifi] = fmt.format(ifi), kind
    units = {}                                               # logical unit (53) -> the port or LAG it sits on
    for target in rng.sample(list(kept), rng.randint(0, min(2, len(kept)))):
        ifi = fresh(40001, 50000)
        units[ifi], names[ifi], types[ifi] = target, f"{kept[target]}.0", PROP_VIRTUAL
        dropped[ifi] = names[ifi]
    dropped.update(noise)
    names.update(noise)
    member_of = {m: lag for lag, mem in lags.items() for m in mem}
    owners = [i for i in kept if (i not in member_of or rng.random() < 0.3) and rng.random() < 0.85]
    owners += [i for i in dropped if rng.random() < 0.3]
    bp_of = dict(zip(owners, rng.sample(range(1, 64), len(owners))))
    vids = [str(v) for v in rng.sample(range(1, 4095), rng.randint(1, 5))]
    egress, untagged, pvids = {v: set() for v in vids}, {v: set() for v in vids}, {}
    for ifi, bp in bp_of.items():
        if ifi in member_of or ifi in dropped:               # nobody's effective bridge port: any bits
            for v in rng.sample(vids, rng.randint(0, len(vids))):
                egress[v].add(bp)
                untagged[v].add(bp)
            if rng.random() < 0.85:
                pvids[bp] = rng.choice([*vids, "1"])
            continue
        u = rng.choice([None, *vids])
        for v in rng.sample([v for v in vids if v != u], rng.randint(0, len(vids) - (u is not None))):
            egress[v].add(bp)
        if u:
            egress[u].add(bp)
            untagged[u].add(bp)
        roll = rng.random()                                  # the PVID: as a rule the untagged VLAN, now and then another, or no row
        if u and roll < 0.75:
            pvids[bp] = u
        elif roll < 0.9:
            pvids[bp] = rng.choice([*vids, "1"])
    size = 8 + rng.randint(0, 2)                             # bridge ports up to 63 fit into 8 bytes
    stack = {f"{lag}.{m}": "1" for lag, mem in lags.items() for m in mem}
    stack.update({f"{lag}.0": "1" for lag, mem in drawn.items() if not mem})
    stack.update({f"0.{i}": "1" for i in kept if i not in member_of})
    stack.update({f"{i}.0": "1" for i in phys})
    for i in noise:
        if rng.random() < 0.5:                               # a virtual interface over a port or a LAG: no membership
            stack[f"{i}.{rng.choice(list(kept))}"] = "1"
    stack.update({f"{unit}.{target}": "1" for unit, target in units.items()})    # nor is a unit a LAG of what it sits on
    ifname_rows, type_rows = walk_rows(IF_NAME, names), walk_rows(IF_TYPE, types)
    if rng.random() < 0.3:
        ifname_rows.append((f"{IF_NAME}.{phys[0]}.0", "ghost"))    # a non-numeric index, with a port type even
        type_rows.append((f"{IF_TYPE}.{phys[0]}.0", rng.choice((ETHERNET, LAG))))
    if rng.random() < 0.3:
        # an ifType row without an ifName row: only of a type that can be no port (one that could, the write path refuses, R19)
        type_rows.append((f"{IF_TYPE}.{fresh(30001, 40000)}", rng.choice((LOOPBACK, OTHER, TUNNEL))))
    W = {
        "ifName": ifname_rows,
        "ifType": type_rows,
        "ifAlias": walk_rows(IF_ALIAS, {i: rng.choice(("", "uplink", "AP Flur 3")) for i in names if rng.random() < 0.75}),
        "ifAdmin": walk_rows(IF_ADMIN, {i: rng.choice(("1", "2", "3")) for i in names if i in kept or rng.random() < 0.5}),
        "bp2if": walk_rows(BP2IF, {str(bp): ifi for ifi, bp in bp_of.items()}),
        "vlanName": walk_rows(VLAN_NAME, {v: rng.choice(("", f"VLAN-{v}", "Clients")) for v in vids}),
        "vlanEgress": walk_rows(VLAN_EGRESS, {v: portlist_hex(egress[v], size) for v in vids}),
        "vlanUntagged": walk_rows(VLAN_UNTAGGED, {v: portlist_hex(untagged[v], size) for v in vids}),
        "pvid": walk_rows(PVID, {str(bp): v for bp, v in pvids.items()}),
        "ifStack": walk_rows(IF_STACK, stack),
    }
    W = {k: sorted(rows, key=oid_order) for k, rows in W.items()}

    order = sorted(kept, key=int)
    port2bp, state = {}, {}
    for ifi in order:
        name, bp = kept[ifi], bp_of.get(member_of.get(ifi, ifi))    # a member counts with its LAG's bridge port, never its own
        un = sorted((v for v in vids if bp in untagged[v]), key=int)
        u = un[0] if len(un) == 1 else None
        if u is not None and bp in pvids and pvids[bp] != u:
            u = None                                         # a PVID that is not the untagged VLAN: unmanaged, no u
        state[name] = {"u": u, "t": sorted((v for v in vids if bp in egress[v] and bp not in untagged[v]), key=int)}
        if bp:
            port2bp[name] = bp
    truth = {
        "ports": [kept[i] for i in order],
        "trunks": {kept[lag]: [kept[m] for m in sorted(lags[lag], key=int)] for lag in sorted(lags, key=int)},
        "port2bp": port2bp,
        "ifindex": {kept[i]: int(i) for i in order},
        "state": state,
    }
    return W, truth


# ── The simulated agent: the oracle of the write-path tests ──────────────────────────────────────────────────────────────────────────
# A switch held the way read_cfg walks it (agent), which takes one SET of rendered varbinds (store) and is then read back. WRITABLE:
# the walk a written base OID lands in and the snmpset type of its object (dot1qPvid is VlanIndex = Unsigned32, the PortLists and
# ifAlias are OCTET STRINGs written as hex (ifAlias since R22), ifAdminStatus and vmVlan INTEGERs).
WRITABLE = {VLAN_EGRESS: ("vlanEgress", "x"), VLAN_UNTAGGED: ("vlanUntagged", "x"), PVID: ("pvid", "u"), IF_ADMIN: ("ifAdmin", "i"),
            IF_ALIAS: ("ifAlias", "x"), VMVLAN: ("vmVlan", "i")}
PORTLISTS = {VLAN_EGRESS: "egress", VLAN_UNTAGGED: "untagged"}


def agent(W: dict) -> dict:
    """A fixture switch as the simulated agent holds it and read_cfg walks it: the free text (ifAlias, vlanName) as hex (R18), every
    other row as it is."""
    return {k: walk_answer(rows, WALK_BASES[k], True) for k, rows in W.items()}


def store(W: dict, ops) -> dict:
    """The simulated agent: W after one SET of `ops`. Each varbind replaces the row of exactly its OID, in the format the walk prints:
    hex pairs for a PortList and for ifAlias, numbers bare (or adds it: an agent has a PVID / ifAlias for every bridge port /
    interface even where a fixture leaves the row out). Refused like on a switch: an object that is not one of the six writable ones,
    a type that is not the object's, a PortList of a VLAN the switch does not have, a number or hex value that is none, an
    ifAdminStatus other than up / down, an OID twice in one PDU."""
    edits: dict[str, dict[str, str]] = {}
    for oid, typ, value in ops:
        base, _, index = oid.rpartition(".")
        assert base in WRITABLE, f"write to an object the switch does not have: {oid}"
        key, want = WRITABLE[base]
        assert typ == want, (oid, typ)
        assert index.isascii() and index.isdigit(), oid
        assert index not in edits.setdefault(key, {}), f"{oid} twice in one PDU"
        if typ == "x":
            assert re.fullmatch(r"(?:[0-9A-F]{2})*", value), (oid, value)
            if base in PORTLISTS:
                assert value and oid in dict(W[key]), f"PortList of a VLAN the switch does not have: {oid}"
            value = " ".join(value[i:i + 2] for i in range(0, len(value), 2))
        else:
            assert value.isascii() and value.isdigit(), (oid, value)
        if base == IF_ADMIN:
            assert value in ("1", "2"), (oid, value)
        edits[key][index] = value
    return edit_walks(W, **edits)
