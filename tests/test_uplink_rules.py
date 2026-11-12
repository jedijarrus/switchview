"""Task 9 of Phase 3: the uplink protection no longer hangs on what a device on an access port says.

Phase 2 found ("Gefälschte Basis-MAC") that on a switch pair linked by base MACs only, one forged LLDP frame
naming a real port of the neighbour displaced the MAC pair in main._links, and the real uplink lost its protection (T6-F1c); and that a
device sending a switch's base MAC as its source made its own port the link's port, so the real uplink lost it as well (T6-RR1c).
Phase 1 left the inventory backstop (a port whose LLDP neighbour is a managed switch is an uplink) out for ProCurve (R48). Now:
  * main._links: only an LLDP pair both sides report (A:P names B:Q and B:Q names A:P) and its ports displace a MAC pair; a pair
    only one side reports stays a link next to it;
  * main.confirmed_endpoints, MAC rule: (A, P) only when A learns B's base MAC on exactly one port (P; a trunk counts as one) and B
    learns A's on exactly one port, and as before no one-sided LLDP claim sits on P;
  * build_map marks every port "bm": the base MAC of another managed switch is learned on it (on a member: on its trunk);
  * changes.inventory, for every driver: every port whose LLDP neighbour is another managed switch and every "bm" port is an
    uplink, each with its trunk, and so is the trunk of every port of a link; then, as before, the members of the uplink trunks.

End to end with the real poller, build_map, inventory and main._make_plan against the recorded walks of tests/switchfix.py behind a
fake snmp.walk (tests/netfix.py, the `net` fixture of tests/conftest.py); no network.
"""
import changes
import main
from netfix import add, fdb, lldp
from switchfix import W_CATALYST, W_SAMPLE, edit_walks

MAC_A, MAC_B = "00:1a:2b:00:00:0a", "00:1a:2b:00:00:0b"    # base MACs, as A_BASE / B_BASE in tests/test_lldp_trust.py
EXPERT = "Uplink/Trunk: nur im Expertenmodus"
OFF = main.PortChange(status="off")
# W_SAMPLE with a second trunk: Trk2 (ifIndex 290) over ports 2 and 3, on bridge port 1 (VLAN 99 untagged); ports 2 and 3 lose
# their own bridge ports, as trunk members do on a ProCurve. Trk1 (ports 4 + 5, bridge port 7) stays.
W_TWO_TRUNKS = edit_walks(W_SAMPLE, ifName={"290": "Trk2"}, ifAlias={"290": ""}, ifAdmin={"290": "1"}, bp2if={"1": "290", "2": None},
                          ifStack={"0.2": None, "0.3": None, "0.290": "1", "290.2": "1", "290.3": "1"})


def port(m: dict, k: str, n: str) -> dict:
    return next(p for s in m["switches"] if s["k"] == k for p in s["ports"] if p["n"] == n)


async def plan_off(sid: int, port: str, expert: bool = False) -> dict:
    plan, _, _, _ = await main._make_plan(await main._row(sid), main.PlanIn(ports=[port], change=OFF, expert=expert))
    return plan


def sw(sid: int, k: str, base: str, ports: list[tuple]) -> dict:
    """A switch as build_map hands it to _links and confirmed_endpoints; a port is (name, LLDP entries) or (name, entries, trunk)."""
    return {"id": sid, "k": k, "sys": k, "baseMac": base,
            "ports": [{"n": p[0], "tr": p[2] if len(p) > 2 else "", "mb": [], "u": ["1"], "t": [], "s": 1000, "l": p[1]} for p in ports]}


# ── T6-F1c: a forged LLDP frame ──────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_forged_lldp_frame_no_longer_unprotects_a_mac_uplink(net):     # T6-F1c
    # W_SAMPLE: bridge port 1 = port 2, bridge port 2 = port 3. Real: A:2 <-> B:3 by base MACs only. Forged: A:3 reports "B port 6"
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb("1", MAC_B), lldp("3", "B", "6", "6"), base_mac=MAC_A)
    b = await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, fdb("2", MAC_A), base_mac=MAC_B)
    [ab] = (await main.build_map())["links"]
    assert "2" in ab["A"]["ports"] and "3" in ab["B"]["ports"]                    # the MAC link stands next to the unconfirmed LLDP pair
    assert "2" in (await changes.inventory(a))["uplinks"] and "3" in (await changes.inventory(b))["uplinks"]


def test_only_a_confirmed_lldp_pair_displaces_a_mac_pair():
    """The rule on plain inputs. A:2 <-> B:3 by base MACs. A:3 names B:6, which does not name A:3 back: both pairs are links. Once B:6
    names A:3 back, the pair is confirmed and displaces the MAC pair, as every LLDP pair did before."""
    macs = {(1, "2"): {"mac-b"}, (2, "3"): {"mac-a"}}
    a = sw(1, "A", "mac-a", [("2", []), ("3", [["B", "6", "6"]])])
    one_sided = [a, sw(2, "B", "mac-b", [("3", []), ("6", [])])]
    [link] = main._links(one_sided, macs)
    assert (link["A"]["ports"], link["B"]["ports"], link["src"]) == (["2", "3"], ["3", "6"], "lldp")
    both = [a, sw(2, "B", "mac-b", [("3", []), ("6", [["A", "3", "3"]])])]
    [link] = main._links(both, macs)
    assert (link["A"]["ports"], link["B"]["ports"], link["src"]) == (["3"], ["6"], "lldp")


def test_a_mac_pair_on_the_ports_of_an_unconfirmed_lldp_pair_keeps_the_lldp_label():
    """A:3 names B:6 one-sided, and the base MACs see the very same ports: one pair, one port each side, still labelled LLDP."""
    switches = [sw(1, "A", "mac-a", [("3", [["B", "6", "6"]])]), sw(2, "B", "mac-b", [("6", [])])]
    [link] = main._links(switches, {(1, "3"): {"mac-b"}, (2, "6"): {"mac-a"}})
    assert (link["A"]["ports"], link["B"]["ports"], link["src"]) == (["3"], ["6"], "lldp")


# ── T6-RR1c: a base MAC on more than one port ────────────────────────────────────────────────────────────────────────────────────
def test_a_base_mac_on_two_ports_confirms_neither():                            # T6-RR1c rule (b)
    switches = [sw(1, "A", "mac-a", [("2", []), ("5", [])]), sw(2, "B", "mac-b", [("3", [])])]
    assert main.confirmed_endpoints(switches, {(1, "2"): {"mac-b"}, (1, "5"): {"mac-b"}, (2, "3"): {"mac-a"}}) == set()


def test_rule_b_needs_one_port_on_both_sides():
    """A learns B's base MAC on one port, B learns A's on two: no side is confirmed. With one each, both are."""
    switches = [sw(1, "A", "mac-a", [("2", [])]), sw(2, "B", "mac-b", [("3", []), ("6", [])])]
    assert main.confirmed_endpoints(switches, {(1, "2"): {"mac-b"}, (2, "3"): {"mac-a"}, (2, "6"): {"mac-a"}}) == set()
    assert main.confirmed_endpoints(switches, {(1, "2"): {"mac-b"}, (2, "3"): {"mac-a"}}) == {(1, "2"), (2, "3")}


def test_a_trunk_counts_as_one_port_for_rule_b():
    """B's base MAC on Trk1 and on its member 4 is one port (the poller files a member's MACs under its trunk; an input that names
    both still means one link): both endpoints are confirmed."""
    switches = [sw(1, "A", "mac-a", [("4", [], "Trk1"), ("5", [], "Trk1"), ("Trk1", [], "Trk1")]), sw(2, "B", "mac-b", [("3", [])])]
    macs = {(1, "Trk1"): {"mac-b"}, (1, "4"): {"mac-b"}, (2, "3"): {"mac-a"}}
    assert main.confirmed_endpoints(switches, macs) == {(1, "Trk1"), (1, "4"), (2, "3")}


async def test_every_port_with_a_neighbours_base_mac_is_an_uplink(net):         # T6-RR1c
    # The FDB is per VLAN: the second sighting of MAC_B (bridge port 2 = port 3) is in VLAN 20, as a device would send it
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb("1", MAC_B), fdb("2", MAC_B, vlan="20"), base_mac=MAC_A)
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, fdb("2", MAC_A), base_mac=MAC_B)
    assert {"2", "3"} <= (await changes.inventory(a))["uplinks"]
    assert (await plan_off(a, "3"))["blocked"] == [{"port": "3", "reason": EXPERT}]    # Logik Phase 3, Später: on to the plan


async def test_the_map_flags_base_mac_ports(net):                                # the network of the first test: A learns MAC_B on port 2
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb("1", MAC_B), lldp("3", "B", "6", "6"), base_mac=MAC_A)
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, fdb("2", MAC_A), base_mac=MAC_B)
    m = await main.build_map()
    assert port(m, "A", "2")["bm"] is True and port(m, "A", "1")["bm"] is False
    assert port(m, "B", "3")["bm"] is True and port(m, "A", "3")["bm"] is False


async def test_a_base_mac_port_is_an_uplink_on_a_driver_that_picks_ports_by_iftype(net):   # Logik Phase 3, Später
    a = await add(net, "A", "10.0.0.1", "cisco", W_CATALYST, fdb("1", MAC_B), base_mac=MAC_A)   # bridge port 1 = Gi1/0/1
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, base_mac=MAC_B)
    m = await main.build_map()
    assert port(m, "A", "Gi1/0/1")["bm"] is True and "Gi1/0/1" in (await changes.inventory(a))["uplinks"]


async def test_a_base_mac_on_a_trunk_flags_the_trunk_and_its_members(net):
    """A learns B's base MAC on Trk1 (bridge port 7): Trk1 and its members 4 and 5 are "bm" and uplinks, also without a link (B
    does not learn A's base MAC, so _links finds none)."""
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb("7", MAC_B), base_mac=MAC_A)
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, base_mac=MAC_B)
    m = await main.build_map()
    assert m["links"] == [] and all(port(m, "A", n)["bm"] for n in ("4", "5", "Trk1"))
    assert (await changes.inventory(a))["uplinks"] == {"4", "5", "Trk1"}


async def test_only_another_managed_switchs_base_mac_flags_a_port(net):
    """The switch's own base MAC (a loop) and a MAC no managed switch carries make no "bm" and no uplink."""
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb("1", MAC_A), fdb("2", "aa:bb:cc:00:00:01"), base_mac=MAC_A)
    m = await main.build_map()
    assert not any(p["bm"] for p in m["switches"][0]["ports"])
    assert (await changes.inventory(a))["uplinks"] == set()


# ── R48: the backstop for every driver ───────────────────────────────────────────────────────────────────────────────────────────
async def test_a_procurve_port_facing_a_managed_switch_is_an_uplink(net):        # Phase 1, R48; port 1 is up (W_SAMPLE)
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("1", "B", "24", "24"))
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE)                         # B has no port 24: no link
    assert "1" in (await changes.inventory(a))["uplinks"]
    assert (await plan_off(a, "1"))["blocked"] == [{"port": "1", "reason": EXPERT}]


async def test_the_procurve_backstop_takes_the_trunk_of_a_member(net):
    """LLDP on member 4 names a managed switch, no port of it: 4, its trunk Trk1 and the other member 5 are uplinks."""
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("4", "B", "24", "24"))
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE)
    assert (await changes.inventory(a))["uplinks"] == {"4", "5", "Trk1"}


# ── The trunk of every link port ─────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_link_side_in_two_trunks_keeps_both_trunks_uplinks(net):
    """A:2 names B's port 2, a member of B's Trk2; B:2 names nothing back (one-sided). A:3 <-> B:Trk1 by base MACs. The link's B side
    is then [2, Trk1] and names one trunk only (Trk1): Trk2 and its other member 3 stay uplinks all the same, as they were while the
    LLDP pair displaced the MAC pair."""
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "B", "2", "2"), fdb("2", MAC_B), base_mac=MAC_A)
    b = await add(net, "B", "10.0.0.2", "procurve", W_TWO_TRUNKS, fdb("7", MAC_A), base_mac=MAC_B)
    [ab] = (await main.build_map())["links"]
    assert (ab["B"]["ports"], ab["B"]["trunk"]) == (["2", "Trk1"], "Trk1")
    assert {"2", "3", "Trk2", "4", "5", "Trk1"} <= (await changes.inventory(b))["uplinks"]
