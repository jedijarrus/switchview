"""R40 / I2: uplink protection for every driver. plan_ports refuses a change on an uplink or trunk outside expert mode ("Uplink/Trunk:
nur im Expertenmodus"); which ports are uplinks says changes.inventory()["uplinks"]: the ports of the links main._links finds from the
poll's LLDP entries (and base MACs). For switches of other vendors that found nothing, so a single-link uplink could be switched off by
anyone (the review's probe_e2e.py). Three things changed, all scoped so that a ProCurve keeps exactly what it had:
  * which local port an LLDP entry belongs to (poller._build). LLDP-MIB numbers local ports by LldpPortNumber, for a bridge the
    dot1dBasePort, not the ifIndex; a ProCurve uses the ifIndex and keeps exactly that. For every other driver (poller.by_iftype) an entry
    with local port number n belongs to the union of bp2if[n], the port with ifIndex n, and the port whose ifName is lldpLocPortId[n]
    or lldpLocPortDesc[n] (LLDP-MIB lldpLocPortTable, walked for these drivers only; a unique match only);
  * which port of the neighbour it names: the poller stores lldpRemPortId as a third element (element 1 stays PortDesc, else PortId),
    and _links matches PortDesc, then PortId, against the neighbour's port names. A pair only the PortId finds is added after the base-MAC
    pairs, so it adds a link and never takes one away; rows stored before the upgrade (two elements) still work;
  * a backstop in inventory() for those drivers: a port whose LLDP neighbour is another managed switch (the sysName / name lookup of
    _links) is an uplink, plus its trunk if it is a member.
ProCurve-only networks keep the links and uplinks of before: the oracle is the code of 5aa8e90 (_links, inventory's uplink loop and
_build's attribution), copied verbatim below.

End to end with the real poller (poll_switch, lenient walks), the real build_map / inventory and the real main._make_plan (the strict
live SNMP read of the Catalyst) against recorded walks of tests/switchfix.py behind a fake snmp.walk; no network. The test network
(lldp, fdb, merge, add and the `net` fixture of tests/conftest.py) is tests/netfix.py, shared with tests/test_lldp_trust.py.
"""
import random
from collections import defaultdict

import pytest

import changes
import db
import main
import poller
from netfix import add, fdb, lldp, merge
from switchfix import CATALYST_VMVLAN, W_CATALYST, W_SAMPLE, WALK_BASES, edit_walks

OIDS = poller.O
LOC_ID, LOC_DESC = "1.0.8802.1.1.2.1.3.7.1.3", "1.0.8802.1.1.2.1.3.7.1.4"    # lldpLocPortId / lldpLocPortDesc (LLDP-MIB), .<lldpLocPortNum>
EXPERT = "Uplink/Trunk: nur im Expertenmodus"
OFF = main.PortChange(status="off")
# The Catalyst of switchfix (Po1 = 5001 bp 56 with members Gi1/0/3 + Gi1/0/4; Gi1/0/1 = 10101 bp 1; Gi1/0/2 = 10102 bp 2; Gi1/0/4 keeps
# its own bp 4), with Gi1/0/2 up and its vmVlan rows (the cisco driver reads them).
CATALYST = edit_walks({**W_CATALYST, "vmVlan": CATALYST_VMVLAN}, ifAdmin={"10102": "1"})


def loc_port(num: str, port_id: str, port_desc: str) -> dict:
    """The lldpLocPortTable row of the local port number num: its PortId and PortDesc as the switch sends them."""
    return {LOC_ID: [(f"{LOC_ID}.{num}", port_id)], LOC_DESC: [(f"{LOC_DESC}.{num}", port_desc)]}


def link_ports(m: dict) -> list[tuple]:
    """The links by switch name ("an" / "bn"; "a" < "b" are the ids)."""
    return [(link["an"], link["A"]["ports"], link["A"]["trunk"], link["bn"], link["B"]["ports"], link["B"]["trunk"], link["src"])
            for link in m["links"]]


async def plan_off(sid: int, port: str, expert: bool = False) -> dict:
    plan, _, _, _ = await main._make_plan(await main._row(sid), main.PlanIn(ports=[port], change=OFF, expert=expert))
    return plan


# ── Two Catalysts, linked Gi1/0/2 <-> Gi1/0/2 ─────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("local, loc", [
    pytest.param("2", {}, id="bridge-port"),                   # LldpPortNumber of a bridge: Gi1/0/2's dot1dBasePort (the review's probe)
    pytest.param("10102", {}, id="ifindex"),                   # what a ProCurve does
    pytest.param("7", loc_port("7", "Gi1/0/2", "GigabitEthernet1/0/2"), id="lldp-loc-port-table"),    # a numbering of its own
])
async def test_an_lldp_uplink_between_two_catalysts_needs_expert_mode(net, local, loc):
    """Each Catalyst sees the other by LLDP with the local port number `local`, the PortId the ifName (Gi1/0/2), the PortDesc the long
    name, which matches no port. The link is found, Gi1/0/2 is an uplink on both, and switching it off is refused outside expert mode;
    in expert mode it is planned (ifAdminStatus of ifIndex 10102)."""
    a = await add(net, "CAT-A", "10.0.0.1", "cisco", CATALYST, lldp(local, "CAT-B", "Gi1/0/2", "GigabitEthernet1/0/2"), loc)
    b = await add(net, "CAT-B", "10.0.0.2", "cisco", CATALYST, lldp(local, "CAT-A", "Gi1/0/2", "GigabitEthernet1/0/2"), loc)
    m = await main.build_map()
    assert link_ports(m) == [("CAT-A", ["Gi1/0/2"], "", "CAT-B", ["Gi1/0/2"], "", "lldp")]
    for sid in (a, b):
        assert (await changes.inventory(sid))["uplinks"] == {"Gi1/0/2"}
    plan = await plan_off(a, "Gi1/0/2")
    assert (plan["mechanism"], plan["blocked"], plan["ops"]) == ("snmp", [{"port": "Gi1/0/2", "reason": EXPERT}], [])
    plan = await plan_off(a, "Gi1/0/2", expert=True)
    assert (plan["blocked"], plan["ops"]) == ([], [("1.3.6.1.2.1.2.2.1.7.10102", "i", "2")])


async def test_the_entry_goes_to_every_port_its_number_can_mean(net):
    """By_iftype: the union of the three readings. Local number 1 is bridge port 1 (Gi1/0/1) and ifIndex 1 (Vl1, no port): Gi1/0/1.
    Number 10102 is an ifIndex (Gi1/0/2) and no bridge port: Gi1/0/2. Number 4 is bridge port 4 (Gi1/0/4) and, by lldpLocPortTable,
    Gi1/0/2: both. The same neighbour on several ports is accepted (more protection, never less)."""
    await add(net, "CAT-A", "10.0.0.1", "cisco", CATALYST, lldp("1", "AP-1", "eth0", "AP"), lldp("10102", "AP-2", "eth0", "AP"),
              lldp("4", "AP-3", "eth0", "AP"), loc_port("4", "Gi1/0/2", ""))
    ports = {p["n"]: p["l"] for p in (await main.build_map())["switches"][0]["ports"]}
    assert ports == {"Po1": [], "Gi1/0/1": [["AP-1", "AP", "eth0"]], "Gi1/0/2": [["AP-2", "AP", "eth0"], ["AP-3", "AP", "eth0"]],
                     "Gi1/0/3": [], "Gi1/0/4": [["AP-3", "AP", "eth0"]]}


@pytest.mark.parametrize("loc", [
    pytest.param(loc_port("7", "Gi1/0/1", "Gi1/0/2"), id="id-and-desc-name-two-ports"),
    pytest.param(loc_port("7", "Gi1/0/9", "uplink"), id="no-such-port"),
])
async def test_lldp_loc_port_table_counts_only_a_unique_match(net, loc):
    await add(net, "CAT-A", "10.0.0.1", "cisco", CATALYST, lldp("7", "AP-1", "eth0", "AP"), loc)
    assert all(p["l"] == [] for p in (await main.build_map())["switches"][0]["ports"])


async def test_lldp_loc_port_table_is_walked_only_where_ports_are_selected_by_iftype(net):
    await add(net, "CAT-A", "10.0.0.1", "cisco", CATALYST)
    await add(net, "HP-A", "10.0.0.3", "procurve", W_SAMPLE)
    assert {LOC_ID, LOC_DESC} <= set(net.walked["10.0.0.1"])
    assert not {LOC_ID, LOC_DESC} & set(net.walked["10.0.0.3"])


# ── The inventory backstop (by_iftype drivers) ────────────────────────────────────────────────────────────────────────────────────
async def test_a_port_whose_lldp_neighbour_is_a_managed_switch_is_an_uplink(net):
    """No port of CAT-B carries a name CAT-A's entries give (PortId a MAC address, PortDesc a description): no link. Still Gi1/0/2 sees a
    switch SwitchView manages, so it is an uplink (the backstop, the UI's isPeer rule); so is the LAG member Gi1/0/4 (bridge port 4),
    with its trunk Po1 and Po1's other member. The access point on Gi1/0/1 makes no uplink."""
    a = await add(net, "CAT-A", "10.0.0.1", "cisco", CATALYST, lldp("2", "CAT-B", "00 1A 2B 3C 4D 5E", "to-core"),
                  lldp("4", "CAT-B", "00 1A 2B 3C 4D 5F", "to-core-2"), lldp("1", "ap-1.example", "eth0", "AP"))
    await add(net, "CAT-B", "10.0.0.2", "cisco", CATALYST)
    assert (await main.build_map())["links"] == []
    assert (await changes.inventory(a))["uplinks"] == {"Gi1/0/2", "Gi1/0/4", "Po1", "Gi1/0/3"}
    assert (await plan_off(a, "Gi1/0/2"))["blocked"] == [{"port": "Gi1/0/2", "reason": EXPERT}]
    assert (await plan_off(a, "Gi1/0/1"))["blocked"] == []


async def test_the_backstop_counts_only_another_managed_switch(net):
    """A neighbour named like the switch itself (a loop, a bad sysName) or like no managed switch makes no uplink."""
    a = await add(net, "CAT-A", "10.0.0.1", "cisco", CATALYST, lldp("2", "CAT-A", "Gi1/0/1", "x"), lldp("1", "CAT-Z", "Gi1/0/2", "y"))
    assert (await changes.inventory(a))["uplinks"] == set()


async def test_no_backstop_for_procurve(net):
    """A ProCurve keeps exactly its uplinks: an LLDP neighbour that is a managed switch but names no port of it makes none."""
    hp = await add(net, "HP-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("6", "CAT-B", "00 1A 2B 3C 4D 5E", "to-core"))
    await add(net, "CAT-B", "10.0.0.2", "cisco", CATALYST)
    assert (await changes.inventory(hp))["uplinks"] == set()


# ── A ProCurve <-> Cisco link ─────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_procurve_cisco_link_protects_both_ends(net):
    """HP-A port 6 <-> CAT-B Gi1/0/2. HP-A (ifIndex numbering, as always) sees CAT-B's PortDesc "GigabitEthernet1/0/2", no port of CAT-B,
    and its PortId "Gi1/0/2"; CAT-B sees HP-A on its bridge port 2 with PortDesc and PortId "6". One link, an uplink at both ends, and
    the Catalyst's end needs expert mode."""
    hp = await add(net, "HP-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("6", "CAT-B", "Gi1/0/2", "GigabitEthernet1/0/2"))
    cat = await add(net, "CAT-B", "10.0.0.2", "cisco", CATALYST, lldp("2", "HP-A", "6", "6"))
    m = await main.build_map()
    assert link_ports(m) == [("HP-A", ["6"], "", "CAT-B", ["Gi1/0/2"], "", "lldp")]    # "a" is the lower id: HP-A is added first
    assert (await changes.inventory(hp))["uplinks"] == {"6"}
    assert (await changes.inventory(cat))["uplinks"] == {"Gi1/0/2"}
    assert (await plan_off(cat, "Gi1/0/2"))["blocked"] == [{"port": "Gi1/0/2", "reason": EXPERT}]


# ── ProCurve only: exactly the links and uplinks of before ────────────────────────────────────────────────────────────────────────
def legacy_links(switches: list[dict], all_macs: dict) -> list[dict]:
    """main._links of 5aa8e90, copied verbatim but for two lines split at their ";" (the oracle; rows of two elements, which is all
    it can unpack)."""
    by_name = {s["k"]: s for s in switches}
    sys2 = {}
    for s in switches:
        sys2[s["sys"]] = s["k"]
        sys2[s["k"]] = s["k"]
    base2 = {s["baseMac"]: s["k"] for s in switches if s["baseMac"]}

    def port(k, n):
        return next((p for p in by_name[k]["ports"] if p["n"] == n), None)

    pairs: dict[tuple, str] = {}
    lldp_ports = set()
    for s in switches:
        for p in s["ports"]:
            if p["n"].startswith("Trk"):
                continue
            for nsys, nport in p["l"]:
                nk = sys2.get(nsys)
                np_ = port(nk, nport.strip()) if nk else None
                if nk and nk != s["k"] and np_:
                    pairs[tuple(sorted([(s["k"], p["n"]), (nk, nport.strip())]))] = "lldp"
                    for kk, pp in ((s["k"], p), (nk, np_)):
                        lldp_ports.add((kk, pp["n"]))
                        if pp["tr"]:
                            lldp_ports.add((kk, pp["tr"]))
    seen_at: dict[tuple, str] = {}
    for (k, pname), macset in all_macs.items():
        for mac in macset:
            other = base2.get(mac)
            if other and other != k:
                seen_at[(k, other)] = pname
    for (a, b), pa in seen_at.items():
        pb = seen_at.get((b, a))
        if not pb or a > b:
            continue
        if (a, pa) in lldp_ports or (b, pb) in lldp_ports:
            continue
        if any({a, b} == {x[0][0], x[1][0]} for x in pairs):
            continue
        pairs[tuple(sorted([(a, pa), (b, pb)]))] = "mac"

    groups: dict[tuple, dict] = {}
    for (x, y), src in pairs.items():
        key = tuple(sorted([x[0], y[0]]))
        g = groups.setdefault(key, {"a": key[0], "b": key[1], "ap": [], "bp": [], "src": src})
        px, py = (x, y) if x[0] == key[0] else (y, x)
        g["ap"].append(px[1])
        g["bp"].append(py[1])
    out = []
    for g in groups.values():
        def side(k, plist):
            ps = [port(k, n) for n in plist if port(k, n)]
            trk = sorted({p["tr"] for p in ps if p["tr"]})
            rep = port(k, trk[0]) if trk else (ps[0] if ps else None)
            return {"ports": sorted(plist, key=lambda v: int(v) if v.isdigit() else 999), "trunk": trk[0] if trk else "",
                    "u": rep["u"] if rep else [], "t": rep["t"] if rep else [], "speed": rep["s"] if rep else 0}
        A, B = side(g["a"], g["ap"]), side(g["b"], g["bp"])
        va, vb = set(A["u"]) | set(A["t"]), set(B["u"]) | set(B["t"])
        out.append({"a": g["a"], "b": g["b"], "A": A, "B": B, "src": g["src"], "onlyA": sorted(va - vb, key=int),
                    "onlyB": sorted(vb - va, key=int), "native": sorted(set(A["u"]) ^ set(B["u"]), key=int)})
    return out


def named(links: list[dict], switches: list[dict]) -> list[dict]:
    """main._links' output in the oracle's form: "a" / "b" back to the switch names, without "an" / "bn". The callers number their
    switches in name order, so "a" < "b" by id is "a" < "b" by name, as the oracle sorts them."""
    name = {s["id"]: s["k"] for s in switches}
    return [{**{k: v for k, v in link.items() if k not in ("an", "bn")}, "a": name[link["a"]], "b": name[link["b"]]} for link in links]


def by_id(switches: list[dict], macs: dict) -> dict:
    """The base-MAC input by (switch id, port), as build_map hands it to main._links, from the oracle's (switch name, port)."""
    sid = {s["k"]: s["id"] for s in switches}
    return {(sid[k], port): v for (k, port), v in macs.items()}


def legacy_uplinks(sw: dict, links: list[dict]) -> set[str]:
    """The uplink set changes.inventory() of 5aa8e90 built from the links (the oracle)."""
    uplinks: set[str] = set()
    for link in links:
        for k, side in ((link["a"], link["A"]), (link["b"], link["B"])):
            if k == sw["k"]:
                uplinks |= set(side["ports"])
                if side["trunk"]:
                    uplinks.add(side["trunk"])
    for p in sw["ports"]:
        if p["tr"] and p["tr"] in uplinks:
            uplinks.add(p["n"])
    return uplinks


def end_pairs(links: list[dict]) -> set[tuple]:
    """(switch, port, the switch at the other end) of every port of every link, in the oracle's form (names)."""
    return ({(link["a"], p, link["b"]) for link in links for p in link["A"]["ports"]}
            | {(link["b"], p, link["a"]) for link in links for p in link["B"]["ports"]})


def two_elements(switches: list[dict]) -> list[dict]:
    """The switches as the poller of before stored their LLDP entries: [sysName, PortDesc or PortId]."""
    return [{**s, "ports": [{**p, "l": [e[:2] for e in p["l"]]} for p in s["ports"]]} for s in switches]


async def all_macs() -> dict:
    """The oracle's base-MAC input (legacy_links): (switch name, port) -> MACs."""
    out: dict = defaultdict(set)
    async with db.db() as conn:
        async with conn.execute("SELECT s.name, m.port, m.mac FROM macs m JOIN switches s ON s.id = m.switch_id") as cur:
            for name, port, mac in await cur.fetchall():
                out[(name, port)].add(mac)
    return out


async def test_procurve_only_links_and_uplinks_are_what_they_were(net):
    """Three ProCurves as they report LLDP (local port number = ifIndex; PortDesc and PortId the port name): HP-A port 6 <-> HP-B port
    6, HP-A Trk1 <-> HP-C Trk1 by LLDP on the members 4 and 5, HP-B <-> HP-C by base MAC only (HP-B learns HP-C's on port 2 = bridge port
    1, HP-C HP-B's on port 3 = bridge port 2). Links and uplinks are exactly those of 5aa8e90 on the same poll, and the stored entries
    carry the PortId as a third element (element 1 as before)."""
    ids = [await add(net, "HP-A", "10.0.0.3", "procurve", W_SAMPLE, lldp("6", "HP-B", "6", "6"), lldp("4", "HP-C", "4", "4"),
                     lldp("5", "HP-C", "5", "5"), base_mac="00:1a:2b:00:00:0a"),
           await add(net, "HP-B", "10.0.0.4", "procurve", W_SAMPLE, lldp("6", "HP-A", "6", "6"), fdb("1", "00:1a:2b:00:00:0c"),
                     base_mac="00:1a:2b:00:00:0b"),
           await add(net, "HP-C", "10.0.0.5", "procurve", W_SAMPLE, lldp("4", "HP-A", "4", "4"), lldp("5", "HP-A", "5", "5"),
                     fdb("2", "00:1a:2b:00:00:0b"), base_mac="00:1a:2b:00:00:0c")]
    m = await main.build_map()
    old = legacy_links(two_elements(m["switches"]), await all_macs())
    assert named([{k: v for k, v in link.items() if k != "confirmed"} for link in m["links"]], m["switches"]) == old    # F3 adds "confirmed" (Task 6)
    assert all(link["confirmed"] for link in m["links"])    # both sides report every one of them
    assert link_ports(m) == [("HP-A", ["4", "5"], "Trk1", "HP-C", ["4", "5"], "Trk1", "lldp"), ("HP-A", ["6"], "", "HP-B", ["6"], "", "lldp"),
                             ("HP-B", ["2"], "", "HP-C", ["3"], "", "mac")]
    for sid, sw in zip(ids, m["switches"]):
        assert (await changes.inventory(sid))["uplinks"] == legacy_uplinks(sw, old)
    assert {p["n"]: p["l"] for p in m["switches"][0]["ports"] if p["l"]} == {"4": [["HP-C", "4", "4"]], "5": [["HP-C", "5", "5"]],
                                                                              "6": [["HP-B", "6", "6"]]}


def test_procurve_attribution_stays_by_ifindex():
    """poller._build for procurve: local port number = ifIndex, as before, whatever else the number could mean. Number 1 is also bridge
    port 1 (port 2) and lldpLocPortTable names port 3 for it: the entry still goes to port 1 (ifIndex 1) alone; number 7 is no ifIndex
    of a port: no port."""
    W = merge({WALK_BASES[k]: rows for k, rows in W_SAMPLE.items()}, lldp("1", "SW-X", "24", "24"), lldp("7", "SW-Y", "24", "24"),
              loc_port("1", "3", "3"))
    walks = {k: W.get(base, []) for k, base in OIDS.items()} | {k: W.get(base, []) for k, base in poller.LLDP_LOC.items()}
    ports = {p["name"]: p["lldp"] for p in poller._build(walks, "procurve")["ports"]}
    assert ports == {"1": [["SW-X", "24", "24"]], "2": [], "3": [], "4": [], "5": [], "6": [], "Trk1": []}


def test_links_accept_rows_from_before_the_upgrade():
    """Entries of two elements (ports rows from before the third element) are matched as they always were."""
    def sw(sid, k, port, entry):
        return {"id": sid, "k": k, "sys": k, "baseMac": "", "ports": [{"n": port, "tr": "", "u": ["1"], "t": [], "s": 1000, "l": [entry]}]}
    switches = [sw(1, "A", "24", ["B", "23"]), sw(2, "B", "23", ["A", "24"])]
    assert named(main._links(switches, {}), switches) == legacy_links(switches, {})
    assert [(link["an"], link["A"]["ports"], link["bn"], link["B"]["ports"]) for link in main._links(switches, {})] == [("A", ["24"], "B", ["23"])]


def test_port_id_only_adds_links_on_random_networks():
    """On random networks (random LLDP entries whose PortDesc and PortId may or may not name a port of the neighbour, random base-MAC
    sightings, trunks), _links finds every link pair the code of 5aa8e90 found on the same entries cut to two elements, and so every
    uplink of before stays one. With PortId never matching more than PortDesc, it finds exactly the same links."""
    rng = random.Random(40)
    grew = 0
    for case in range(400):
        names = [f"SW{i}" for i in range(rng.randint(2, 4))]
        switches, macs = [], defaultdict(set)
        for sid, k in enumerate(names, 1):
            ports = [{"n": str(i), "tr": "", "u": ["1"], "t": [], "s": 1000, "l": []} for i in range(1, 7)]
            trunk = {"n": "Trk1", "tr": "Trk1", "u": ["1"], "t": [], "s": 2000, "l": []}
            for p in rng.sample(ports, rng.randint(0, 2)):
                p["tr"] = "Trk1"
            switches.append({"id": sid, "k": k, "sys": k.lower() if rng.random() < 0.3 else k, "baseMac": f"mac-{k}", "ports": ports + [trunk]})
        for s in switches:
            for p in s["ports"][:-1]:
                if rng.random() < 0.35:
                    other = rng.choice(names)
                    desc = rng.choice([str(rng.randint(1, 8)), "to-core", ""])
                    pid = rng.choice([str(rng.randint(1, 8)), "00 1A 2B 3C 4D 5E"])
                    p["l"].append([rng.choice([other, other.lower(), "ap-1"]), desc or pid, pid])
                if rng.random() < 0.15:
                    macs[(s["k"], p["n"])].add(f"mac-{rng.choice(names)}")
        old, new = legacy_links(two_elements(switches), macs), named(main._links(switches, by_id(switches, macs)), switches)
        assert end_pairs(old) <= end_pairs(new), case
        for s in switches:
            assert legacy_uplinks(s, old) <= legacy_uplinks(s, new), case
        grew += end_pairs(old) != end_pairs(new)
        same = [{**s, "ports": [{**p, "l": [[e[0], e[1], e[1]] for e in p["l"]]} for p in s["ports"]]} for s in switches]
        assert named(main._links(same, by_id(same, macs)), same) == legacy_links(two_elements(same), macs), case
    assert grew > 40, grew


def test_a_shared_sys_name_only_adds_links_on_random_networks():
    """The random networks of the test above, with unique names but sysNames from a small pool the switches share (the factory sysName
    of one model, "HP-2530", until someone sets one): the code of 5aa8e90 took the last switch of a shared name, _links tries each,
    and a pair from a name several switches carry is added after the base-MAC pairs. So every link pair and every uplink of before
    stays, and a MAC link between two switches is not hidden by an LLDP pair the shared name gives to one of them."""
    rng = random.Random(41)
    pool = ["HP-2530", "HP-2920"]
    grew = 0
    for case in range(400):
        names = [f"SW{i}" for i in range(rng.randint(2, 5))]
        switches, macs = [], defaultdict(set)
        for sid, k in enumerate(names, 1):
            ports = [{"n": str(i), "tr": "", "u": ["1"], "t": [], "s": 1000, "l": []} for i in range(1, 7)]
            trunk = {"n": "Trk1", "tr": "Trk1", "u": ["1"], "t": [], "s": 2000, "l": []}
            for p in rng.sample(ports, rng.randint(0, 2)):
                p["tr"] = "Trk1"
            switches.append({"id": sid, "k": k, "sys": rng.choice([*pool, k]), "baseMac": f"mac-{k}", "ports": ports + [trunk]})
        for s in switches:
            for p in s["ports"][:-1]:
                if rng.random() < 0.3:
                    other = rng.choice(switches)
                    desc = rng.choice([str(rng.randint(1, 8)), "to-core", ""])
                    pid = rng.choice([str(rng.randint(1, 8)), "00 1A 2B 3C 4D 5E"])
                    p["l"].append([rng.choice([other["sys"], other["sys"], other["k"], "ap-1"]), desc or pid, pid])
                if rng.random() < 0.25:
                    macs[(s["k"], p["n"])].add(f"mac-{rng.choice(names)}")
        old, new = legacy_links(two_elements(switches), macs), named(main._links(switches, by_id(switches, macs)), switches)
        assert end_pairs(old) <= end_pairs(new), case
        for s in switches:
            assert legacy_uplinks(s, old) <= legacy_uplinks(s, new), case
        grew += end_pairs(old) != end_pairs(new)
    assert grew > 100, grew
