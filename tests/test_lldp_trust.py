"""F3: LLDP and MAC tables from an access port no longer decide on their own what SwitchView treats as trusted.

Vector A (the audit): one LLDP frame, or a flood of five or more MACs, on an access port hid every device behind it from the list of
unknown devices. Vector B: a forged LLDP frame naming another managed switch made the port an uplink, and the netmap showed a link no
switch confirms. Now main.confirmed_endpoints keeps only what both switches report (LLDP from both sides naming exactly this port pair,
or base MACs learned mutually); build_map marks every port "uc" and every link "confirmed"; the unknown list skips only trunks and
confirmed uplinks and flags the rest ("uplink_lldp", "lldp", "many"), unflagged entries first. The uplink protection itself
(changes.inventory, plan_ports) stays exactly as it was (R40, E21).

End to end with the real poller (poll_switch) and the real build_map / inventory / unknown_devices against the recorded walks of
tests/switchfix.py behind a fake snmp.walk; no network. The test network (lldp, fdb, add and the `net` fixture of tests/conftest.py) is
tests/netfix.py, shared with tests/test_uplinks.py.
"""
import changes
import db
import main
from cfgparse import parse_config
from netfix import add, fdb, lldp
from switchfix import CATALYST_VMVLAN, W_CATALYST, W_SAMPLE

USER = {"username": "tester", "name": "Tester", "method": "local"}
MAC1, MAC2 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"
A_BASE, B_BASE = "00:1a:2b:00:00:0a", "00:1a:2b:00:00:0b"


def bp(port: str) -> str:
    """The bridge port of a port of W_SAMPLE (dot1dBasePortIfIndex over the port's ifIndex)."""
    ifindex = next(oid.rsplit(".", 1)[1] for oid, name in W_SAMPLE["ifName"] if name == port)
    return next(oid.rsplit(".", 1)[1] for oid, ifi in W_SAMPLE["bp2if"] if ifi == ifindex)


async def unknown() -> list[dict]:
    return await main.unknown_devices(user=USER)


def entry(out: list[dict], mac: str) -> dict:
    return next(e for e in out if e["mac"] == mac)


def port(m: dict, k: str, n: str) -> dict:
    return next(p for s in m["switches"] if s["k"] == k for p in s["ports"] if p["n"] == n)


def link(m: dict, a: str, b: str) -> dict:
    """The link between the switches named a and b (a link carries the ids in "a" / "b", the names in "an" / "bn")."""
    return next(x for x in m["links"] if {x["an"], x["bn"]} == {a, b})


async def register(*macs: str) -> None:
    """The devices are in SwitchView's database (registered, not allowed)."""
    async with db.db() as conn:
        await conn.executemany("INSERT INTO devices(mac, name) VALUES (?, ?)", [(mac, f"dev-{i}") for i, mac in enumerate(macs)])
        await conn.commit()


async def named(mac: str, ip: str) -> None:
    """The router knows the device (the names table, as names.refresh_names fills it from the OPNsense ARP table)."""
    async with db.db() as conn:
        await conn.execute("INSERT INTO names(mac, ip, name, source) VALUES (?, ?, '', 'arp')", (mac, ip))
        await conn.commit()


async def test_one_lldp_frame_no_longer_hides_a_device(net):
    """F3 vector A, the audit's input: one LLDP frame of a device that is no managed switch on the access port 3."""
    await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("3", "evil-ap", "x", "x"), fdb(bp("3"), MAC1))
    e = entry(await unknown(), MAC1)
    assert e["port"] == "3" and e["flags"] == ["lldp"] and e["lldp"] == "evil-ap"


async def test_a_mac_flood_no_longer_hides_a_device_and_pushes_no_one_out(net):
    """Vector A, the audit's other input: six MACs on port 3. They are listed, flagged and after the unflagged device on port 6."""
    await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, *(fdb(bp("3"), f"aa:bb:cc:00:03:{i:02x}") for i in range(6)),
              fdb(bp("6"), MAC1))
    out = await unknown()
    assert out[0]["mac"] == MAC1 and out[0]["flags"] == []
    assert {e["port"] for e in out[1:]} == {"3"} and all(e["flags"] == ["many"] and e["mc"] == 6 for e in out[1:])


async def test_a_forged_switch_neighbour_is_an_unconfirmed_uplink(net):
    """F3 vector B, the audit's input: the device on SW-A port 3 claims to be SW-B port 6; SW-B port 6 names no SW-A. The link and both
    ports stay uplinks (the protection is unchanged), but none of them is confirmed, and the device is listed with both flags."""
    a = await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("3", "SW-B", "6", "6"), fdb(bp("3"), MAC1))
    await add(net, "SW-B", "10.0.0.4", "procurve", W_SAMPLE)                   # SW-B port 6 does not name SW-A back
    m = await main.build_map()
    p3 = port(m, "SW-A", "3")
    assert p3["up"] and p3["uc"] is False and link(m, "SW-A", "SW-B")["confirmed"] is False
    assert port(m, "SW-B", "6")["up"] and port(m, "SW-B", "6")["uc"] is False       # the foreign port it names is not confirmed
    inv = await changes.inventory(a)
    assert "3" in inv["uplinks"]                                                   # protection unchanged (R40)
    req = {"ports": ["3"], "set": {"status": "radius"}, "expert": True}
    plan = changes.plan_ports("", inv, parse_config("vlan 1\n   untagged 1-6\n   exit\n"), req)
    assert plan["blocked"] == [{"port": "3", "reason": "RADIUS/bekannte Geräte gehen nicht auf Uplinks und Trunks"}]
    assert entry(await unknown(), MAC1)["flags"] == ["uplink_lldp", "lldp"]


async def test_lldp_from_both_sides_confirms_and_hides(net):
    await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("6", "SW-B", "6", "6"), fdb(bp("6"), MAC1))
    await add(net, "SW-B", "10.0.0.4", "procurve", W_SAMPLE, lldp("6", "SW-A", "6", "6"))
    m = await main.build_map()
    assert port(m, "SW-A", "6")["uc"] and link(m, "SW-A", "SW-B")["confirmed"] and MAC1 not in {e["mac"] for e in await unknown()}


async def test_mac_links_are_confirmed(net):
    """Base MACs learned on both sides, as HP-B <-> HP-C in the oracle test of tests/test_uplinks.py."""
    await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, fdb(bp("6"), "00:1a:2b:00:00:0b"), base_mac="00:1a:2b:00:00:0a")
    await add(net, "SW-B", "10.0.0.4", "procurve", W_SAMPLE, fdb(bp("6"), "00:1a:2b:00:00:0a"), base_mac="00:1a:2b:00:00:0b")
    m = await main.build_map()
    ab = link(m, "SW-A", "SW-B")
    assert ab["src"] == "mac" and ab["confirmed"] is True and port(m, "SW-A", "6")["uc"] and port(m, "SW-B", "6")["uc"]


async def test_a_trunk_confirmed_from_both_sides_marks_the_trunk_and_its_members(net):
    """Trk1 (members 4 and 5) <-> Trk1, LLDP on both members from both sides: every member and both trunks are confirmed."""
    await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("4", "SW-B", "4", "4"), lldp("5", "SW-B", "5", "5"))
    await add(net, "SW-B", "10.0.0.4", "procurve", W_SAMPLE, lldp("4", "SW-A", "4", "4"), lldp("5", "SW-A", "5", "5"))
    m = await main.build_map()
    assert link(m, "SW-A", "SW-B")["confirmed"] is True
    assert all(port(m, k, n)["uc"] for k in ("SW-A", "SW-B") for n in ("4", "5", "Trk1"))
    assert not any(port(m, k, n)["uc"] for k in ("SW-A", "SW-B") for n in ("1", "2", "3", "6"))


def test_confirmed_endpoints_take_only_what_both_switches_report():
    """The rule itself, on plain inputs as _links takes them. A:3 claims B:6 (forged, B:6 names A:6): B:6 is confirmed by the real
    pair A:6 <-> B:6 (PortDesc padded), never by the forged claim, and A:3 not at all. A:7 <-> B:7 is found by the PortId (element 2).
    A learns B's base MAC on port 8, B never A's: nothing; once B learns A's base MAC on port 8 as well, A:8 and B:8 are confirmed.
    Switches by id (A = 1, B = 2), MACs and endpoints by (id, port)."""
    def sw(sid, k, base, ports):
        return {"id": sid, "k": k, "sys": f"{k.lower()}.example", "baseMac": base,
                "ports": [{"n": n, "tr": "", "mb": [], "l": entries} for n, entries in ports]}
    a = sw(1, "A", "mac-a", [("3", [["B", "6", "6"]]), ("6", [["b.example", " 6 ", "x"]]), ("7", [["B", "to-core", "7"]]), ("8", [])])
    b = sw(2, "B", "mac-b", [("6", [["A", "6", "6"]]), ("7", [["a.example", "uplink", "7 "]]), ("8", [])])
    macs = {(1, "8"): {"mac-b", "aa:bb:cc:00:00:01"}}
    pairs = {(1, "6"), (2, "6"), (1, "7"), (2, "7")}
    assert main.confirmed_endpoints([a, b], macs) == pairs
    assert main.confirmed_endpoints([a, b], {**macs, (2, "8"): {"mac-a"}}) == pairs | {(1, "8"), (2, "8")}


# ── Review round 1 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_spoofed_base_mac_does_not_confirm_a_forged_uplink(net):
    """The reviewer's probe. SW-A port 6 <-> SW-B port 6 is real: LLDP from both sides, base MACs learned mutually in VLAN 1. The device
    on SW-A's access port 3 claims to be SW-B port 6 by LLDP and sends frames with SW-B's base MAC as source in its own VLAN 20: the FDB
    is per VLAN, so that is a second row and SW-B's management in VLAN 1 is untouched (nothing is loud). A port whose switch-LLDP claim
    the other switch does not make back gets no confirmation from base MACs: port 3 stays an unconfirmed uplink (protected as before),
    the link the forged pair joins is unconfirmed, and the device stays listed with both flags."""
    a = await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("6", "SW-B", "6", "6"), lldp("3", "SW-B", "6", "6"),
                  fdb(bp("6"), B_BASE), fdb(bp("3"), MAC1, vlan="20"), fdb(bp("3"), B_BASE, vlan="20"), base_mac=A_BASE)
    await add(net, "SW-B", "10.0.0.4", "procurve", W_SAMPLE, lldp("6", "SW-A", "6", "6"), fdb(bp("6"), A_BASE), base_mac=B_BASE)
    m = await main.build_map()
    p3 = port(m, "SW-A", "3")
    assert p3["up"] and p3["uc"] is False
    assert port(m, "SW-A", "6")["uc"] and port(m, "SW-B", "6")["uc"]
    ab = link(m, "SW-A", "SW-B")
    assert (ab["A"]["ports"], ab["B"]["ports"], ab["confirmed"]) == (["3", "6"], ["6", "6"], False)
    assert {"3", "6"} <= (await changes.inventory(a))["uplinks"]                  # protection unchanged (R40)
    out = await unknown()
    e = entry(out, MAC1)
    assert (e["port"], e["vlan"], e["flags"]) == ("3", "20", ["uplink_lldp", "lldp"])
    assert B_BASE not in {e["mac"] for e in out}                                   # a switch's base MAC is no unknown device


def test_base_macs_confirm_no_port_whose_switch_lldp_claim_is_one_sided():
    """The rule on plain inputs: A:6 <-> B:6 by LLDP from both sides, base MACs learned mutually (B's on A:6 and, spoofed, on A:3; A's
    on B:6). A:3 claims B:6, B:6 does not name A:3: A:3 is not confirmed. A:8, with B's base MAC and no LLDP claim, is (rule (b)).
    Switches by id (A = 1, B = 2), MACs and endpoints by (id, port)."""
    def sw(sid, k, base, ports):
        return {"id": sid, "k": k, "sys": k, "baseMac": base, "ports": [{"n": n, "tr": "", "mb": [], "l": entries} for n, entries in ports]}
    a = sw(1, "A", "mac-a", [("3", [["B", "6", "6"]]), ("6", [["B", "6", "6"]]), ("8", [])])
    b = sw(2, "B", "mac-b", [("6", [["A", "6", "6"]])])
    macs = {(1, "3"): {"mac-b"}, (1, "6"): {"mac-b"}, (2, "6"): {"mac-a"}}
    assert main.confirmed_endpoints([a, b], macs) == {(1, "6"), (2, "6")}
    assert main.confirmed_endpoints([a, b], {**macs, (1, "8"): {"mac-b"}}) == {(1, "6"), (2, "6"), (1, "8")}


async def test_registered_devices_do_not_push_an_unknown_one_off_the_list(net):
    """Twelve registered devices and MAC1 on port 3. build_map shows twelve devices of a port, registered ones first, so MAC1 was never
    listed; the list is built from every device the port has learned."""
    reg = [f"aa:bb:cc:00:03:{i:02x}" for i in range(12)]
    await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, *(fdb(bp("3"), mac) for mac in reg), fdb(bp("3"), MAC1))
    await register(*reg)
    assert [(e["mac"], e["port"], e["flags"], e["mc"]) for e in await unknown()] == [(MAC1, "3", ["many"], 13)]


async def test_a_flood_lists_its_port_and_pushes_no_other_port_out(net):
    """600 MACs flood port 1, ahead of MAC1 in poll order; an LLDP device sits on port 3 with MAC2 behind it. Port 1 is listed with
    main.UNKNOWN_PER_PORT (12) entries, flagged "many" with the port's count, the first in poll order (MAC1 is not among them: its port
    is what the list shows). The flood takes no more than its 12 places, so MAC2, flagged too and later in poll order, stays listed."""
    flood = [f"00:00:00:00:{i >> 8:02x}:{i & 0xff:02x}" for i in range(1, 601)]
    await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, *(fdb(bp("1"), mac) for mac in flood), fdb(bp("1"), MAC1),
              lldp("3", "evil-ap", "x", "x"), fdb(bp("3"), MAC2))
    out = await unknown()
    assert main.UNKNOWN_PER_PORT == 12
    assert [e["mac"] for e in out if e["port"] == "1"] == flood[:12]
    assert all(e["flags"] == ["many"] and e["mc"] == 601 for e in out if e["port"] == "1")
    assert entry(out, MAC2)["flags"] == ["lldp"] and len(out) == 13


async def test_a_flood_does_not_push_out_a_device_the_router_knows(net):
    """The same flood on port 1, but the router knows MAC1 (an IP in the ARP table, which a flood of made-up MACs does not get): of a
    port's devices, those with an IP or a name come first, so MAC1 is listed, then the flood in poll order."""
    flood = [f"00:00:00:00:00:{i:02x}" for i in range(1, 21)]
    await add(net, "SW-A", "10.0.0.3", "procurve", W_SAMPLE, *(fdb(bp("1"), mac) for mac in flood), fdb(bp("1"), MAC1))
    await named(MAC1, "198.51.100.50")
    out = await unknown()
    assert [e["mac"] for e in out] == [MAC1, *flood[:11]]
    assert out[0]["ip"] == "198.51.100.50" and all(e["flags"] == ["many"] and e["mc"] == 21 for e in out)


async def test_a_port_the_uplink_backstop_protects_is_flagged_as_an_unconfirmed_uplink(net):
    """CAT-A's Gi1/0/2 sees CAT-B by LLDP but names no port of it (PortId a MAC address): no link, so build_map marks it neither "up"
    nor "uc". The backstop of changes.inventory protects it all the same, and the port table shows "Uplink (unbestätigt)" (app.js:
    not up, its LLDP neighbour a managed switch). The device behind it is flagged the same way; the one behind an access point is not."""
    cat = {**W_CATALYST, "vmVlan": CATALYST_VMVLAN}
    a = await add(net, "CAT-A", "10.0.0.1", "cisco", cat, lldp("2", "CAT-B", "00 1A 2B 3C 4D 5E", "to-core"),
                  lldp("1", "ap-1.example", "eth0", "AP"), fdb("2", MAC1), fdb("1", MAC2))
    await add(net, "CAT-B", "10.0.0.2", "cisco", cat)
    m = await main.build_map()
    assert m["links"] == [] and not port(m, "CAT-A", "Gi1/0/2").get("up")
    assert "Gi1/0/2" in (await changes.inventory(a))["uplinks"]
    out = await unknown()
    assert (entry(out, MAC1)["port"], entry(out, MAC1)["flags"]) == ("Gi1/0/2", ["uplink_lldp", "lldp"])
    assert (entry(out, MAC2)["port"], entry(out, MAC2)["flags"]) == ("Gi1/0/1", ["lldp"])
