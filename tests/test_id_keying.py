"""Task 8 of Phase 3 (Review §4 "Switch `name` is not unique but is used as an identity key"): the netmap, the inventory and the UI key
switches by their id, not by their name. Before, build_map looked a switch up by name in a dict and in `next(x for x in switches if
x["k"] == k)`, so of two switches with one name the first shadowed the second: the second lost its uplink ports, and the links of both
were drawn to one. Now main.switch_keys maps every non-empty sysName and name to the set of ids so named (an LLDP name two switches
share counts for both: R40, rather one uplink too many), main._links and main.confirmed_endpoints work on (id, port), every link
carries the ids in "a" / "b" and the names in "an" / "bn", unknown devices carry "sid", and changes.inventory takes the links of its
id.

Same root cause, found while reading: a port name of 5000 digits (int() refuses more than 4300) or a VLAN row that is no number made
build_map raise, and with it the netmap, the inventory and every change. main._port_num and main._vid_num are the bounded sort keys.

End to end with the real poller, build_map, inventory and unknown_devices against the recorded walks of tests/switchfix.py behind a
fake snmp.walk (tests/netfix.py, the `net` fixture of tests/conftest.py); no network.
"""
import pytest

import changes
import db
import main
from netfix import add, fdb, lldp
from switchfix import CATALYST_VMVLAN, W_CATALYST, W_SAMPLE, edit_walks

USER = {"username": "tester", "name": "Tester", "method": "local"}
MAC1, MAC2 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"
BP3 = "2"    # W_SAMPLE: port 3 (ifIndex 3) is bridge port 2 (dot1dBasePortIfIndex)


def sw(sid: int, k: str, port: str, entry: list[str], u: list[str] | None = None, t: list[str] | None = None) -> dict:
    """A switch as build_map hands it to _links: one port with one LLDP entry."""
    return {"id": sid, "k": k, "sys": k, "baseMac": "",
            "ports": [{"n": port, "tr": "", "mb": [], "u": u or ["1"], "t": t or [], "s": 1000, "l": [entry]}]}


# ── Two switches with one name (Review Focus 2) ───────────────────────────────────────────────────────────────────────────────────
async def test_two_switches_with_one_name_keep_their_own_uplinks(net):
    # Only CORE reports LLDP. The first "SW" calls ifIndex 6 "24", the second has a port "6": build_map looked the name "SW" up in a
    # dict, one shadowed the other, and its uplink port found no link (ProCurve: no backstop)
    core = await add(net, "CORE", "10.0.0.1", "procurve", W_SAMPLE, lldp("1", "SW", "24", "24"), lldp("2", "SW", "6", "6"))
    sw1 = await add(net, "SW", "10.0.0.2", "procurve", edit_walks(W_SAMPLE, ifName={"6": "24"}))
    sw2 = await add(net, "SW", "10.0.0.3", "procurve", W_SAMPLE)
    m = await main.build_map()
    assert sorted(s["id"] for s in m["switches"]) == sorted([core, sw1, sw2])
    assert "24" in (await changes.inventory(sw1))["uplinks"] and "6" in (await changes.inventory(sw2))["uplinks"]


async def test_two_switches_with_one_name_get_their_own_links_and_marks(net):
    """The same network: one link to each "SW", by id, each with the port it has; the uplink mark ("up") lands on the port of the
    switch the link names, not on a port of the first switch of that name."""
    core = await add(net, "CORE", "10.0.0.1", "procurve", W_SAMPLE, lldp("1", "SW", "24", "24"), lldp("2", "SW", "6", "6"))
    sw1 = await add(net, "SW", "10.0.0.2", "procurve", edit_walks(W_SAMPLE, ifName={"6": "24"}))
    sw2 = await add(net, "SW", "10.0.0.3", "procurve", W_SAMPLE)
    m = await main.build_map()
    assert sorted((x["a"], x["A"]["ports"], x["b"], x["B"]["ports"], x["an"], x["bn"]) for x in m["links"]) == [
        (core, ["1"], sw1, ["24"], "CORE", "SW"), (core, ["2"], sw2, ["6"], "CORE", "SW")]
    up = {(s["id"], p["n"]) for s in m["switches"] for p in s["ports"] if p.get("up")}
    assert up == {(core, "1"), (core, "2"), (sw1, "24"), (sw2, "6")}
    assert (await changes.inventory(sw1))["uplinks"] == {"24"} and (await changes.inventory(sw2))["uplinks"] == {"6"}


async def test_links_carry_ids_and_names(net):
    """HP-A:6 <-> HP-B:6 by LLDP from both sides."""
    a = await add(net, "HP-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("6", "HP-B", "6", "6"))
    b = await add(net, "HP-B", "10.0.0.4", "procurve", W_SAMPLE, lldp("6", "HP-A", "6", "6"))
    [link] = (await main.build_map())["links"]
    assert (link["a"], link["b"], link["an"], link["bn"]) == (a, b, "HP-A", "HP-B")
    assert link["confirmed"] is True


async def test_unknown_devices_name_their_switch_by_id(net):
    """A foreign MAC on an access port of HP-A (port 3)."""
    a = await add(net, "HP-A", "10.0.0.3", "procurve", W_SAMPLE, fdb(BP3, MAC1))
    await add(net, "HP-B", "10.0.0.4", "procurve", W_SAMPLE)
    out = await main.unknown_devices(USER)
    assert out
    assert all(d["sid"] == a for d in out)


async def test_unknown_devices_of_two_switches_with_one_name_keep_their_switch(net):
    a = await add(net, "SW", "10.0.0.3", "procurve", W_SAMPLE, fdb(BP3, MAC1))
    b = await add(net, "SW", "10.0.0.4", "procurve", W_SAMPLE, fdb(BP3, MAC2))
    assert sorted((d["mac"], d["sid"], d["sw"], d["port"]) for d in await main.unknown_devices(USER)) == [
        (MAC1, a, "SW", "3"), (MAC2, b, "SW", "3")]


async def test_the_backstop_counts_a_switch_that_shares_the_name(net):
    """By_iftype backstop: CAT's Gi1/0/2 sees "CAT" by LLDP, a name two managed switches carry, and names no port of either (PortId a
    MAC address). One of them is another managed switch, so the port is an uplink (the decision: a name two switches share counts for
    both). A switch alone with its name stays as before (tests/test_uplinks.py: a neighbour named like the switch itself is none)."""
    cat = {**W_CATALYST, "vmVlan": CATALYST_VMVLAN}
    a = await add(net, "CAT", "10.0.0.1", "cisco", cat, lldp("2", "CAT", "00 1A 2B 3C 4D 5E", "to-core"))
    await add(net, "CAT", "10.0.0.2", "cisco", cat)
    assert (await main.build_map())["links"] == []
    assert (await changes.inventory(a))["uplinks"] == {"Gi1/0/2"}


# ── The rules on plain inputs ─────────────────────────────────────────────────────────────────────────────────────────────────────
def test_switch_keys_map_each_non_empty_name_to_every_id():
    switches = [{"id": 1, "k": "A", "sys": "core.example"}, {"id": 2, "k": "SW", "sys": ""}, {"id": 3, "k": "SW", "sys": "SW"},
                {"id": 4, "k": "B", "sys": "SW"}]
    assert main.switch_keys(switches) == {"A": {1}, "core.example": {1}, "SW": {2, 3, 4}, "B": {4}}


def test_an_lldp_name_two_switches_carry_is_tried_at_each():
    """CORE:1 names "SW" port 6. Switch 2 (SW) has a port 6, switch 3 (SW) has none, switch 4 (SW) has one: a link to 2 and to 4."""
    switches = [sw(1, "CORE", "1", ["SW", "6", "6"]), sw(2, "SW", "6", ["x", "1", "1"]), sw(3, "SW", "24", ["x", "1", "1"]),
                sw(4, "SW", "6", ["x", "1", "1"])]
    assert [(x["a"], x["A"]["ports"], x["b"], x["B"]["ports"]) for x in main._links(switches, {})] == [(1, ["1"], 2, ["6"]), (1, ["1"], 4, ["6"])]


def test_links_join_by_id_and_order_a_before_b_by_id():
    """Switch 1 is named "Z", switch 2 "A": a is the lower id, whatever the names; base MACs learned mutually by (id, port)."""
    z = {"id": 1, "k": "Z", "sys": "Z", "baseMac": "mac-z", "ports": [{"n": "5", "tr": "", "u": ["1"], "t": [], "s": 1000, "l": []}]}
    a = {"id": 2, "k": "A", "sys": "A", "baseMac": "mac-a", "ports": [{"n": "7", "tr": "", "u": ["1"], "t": [], "s": 1000, "l": []}]}
    [link] = main._links([a, z], {(1, "5"): {"mac-a"}, (2, "7"): {"mac-z"}})
    assert (link["a"], link["an"], link["A"]["ports"], link["b"], link["bn"], link["B"]["ports"], link["src"]) == (1, "Z", ["5"], 2, "A", ["7"], "mac")


def test_confirmed_endpoints_count_a_shared_name_for_each_switch():
    """CORE:3 names "SW" port 6; the first SW names CORE port 3 back, the second SW names someone else: only the first pair is
    confirmed, by (id, port). The base MAC of switch 2 learned on CORE:4, CORE's on switch 2's port 6: (1, 4) by rule (b)."""
    def s(sid, k, base, ports):
        return {"id": sid, "k": k, "sys": k, "baseMac": base, "ports": [{"n": n, "tr": "", "mb": [], "l": e} for n, e in ports]}
    switches = [s(1, "CORE", "mac-core", [("3", [["SW", "6", "6"]]), ("4", [])]), s(2, "SW", "mac-sw1", [("6", [["CORE", "3", "3"]])]),
                s(3, "SW", "mac-sw2", [("6", [["OTHER", "1", "1"]])])]
    assert main.confirmed_endpoints(switches, {}) == {(1, "3"), (2, "6")}
    macs = {(1, "4"): {"mac-sw1"}, (2, "6"): {"mac-core"}}
    assert main.confirmed_endpoints(switches, macs) == {(1, "3"), (1, "4"), (2, "6")}


# ── Bounded sort keys ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_a_port_name_of_5000_digits_breaks_no_map():
    switches = [sw(1, "A", "1" * 5000, ["B", "2"]), sw(2, "B", "2", ["A", "1" * 5000])]
    assert main._links(switches, {})[0]["A"]["ports"] == ["1" * 5000]


def test_vlan_text_that_is_no_number_breaks_no_link():
    """onlyA / onlyB / native were sorted with key=int: a VLAN "x" or one of 5000 digits raised. They sort last now."""
    big = "1" * 5000
    switches = [sw(1, "A", "1", ["B", "2"], u=["x"], t=["20", big, "3"]), sw(2, "B", "2", ["A", "1"], u=["1"], t=[])]
    [link] = main._links(switches, {})
    assert link["onlyA"][:2] == ["3", "20"] and set(link["onlyA"][2:]) == {"x", big}
    assert link["onlyB"] == ["1"] and link["native"] == ["1", "x"]


async def test_a_vlan_row_that_is_no_number_breaks_no_map(net):
    a = await add(net, "HP-A", "10.0.0.3", "procurve", W_SAMPLE)
    async with db.db() as conn:
        await conn.executemany("INSERT INTO vlans(switch_id, vid, name) VALUES (?, ?, ?)", [(a, "x", "kaputt"), (a, "1" * 5000, "lang")])
        await conn.commit()
    m = await main.build_map()
    assert list(m["vlans"])[:4] == ["1", "20", "30", "99"] and set(list(m["vlans"])[4:]) == {"x", "1" * 5000}
    assert (await changes.inventory(a))["sw"]["id"] == a


@pytest.mark.parametrize("text, port, vid", [
    ("7", 7, 7), ("0042", 42, 42), ("123456789", 123456789, 123456789),
    ("1234567890", 999, 10**9),                     # ten digits: no number of a port or a VLAN
    pytest.param("1" * 5000, 999, 10**9, id="5000-digits"),    # int() refuses more than 4300 digits
    ("²", 999, 10**9),                              # "²".isdigit() is True, int("²") raises
    ("٣", 999, 10**9),                              # an Arabic-Indic three: a digit, but not ASCII
    ("", 999, 10**9), ("Trk1", 999, 10**9), (" 7", 999, 10**9), ("-1", 999, 10**9)])
def test_bounded_sort_keys(text, port, vid):
    assert (main._port_num(text), main._vid_num(text)) == (port, vid)
