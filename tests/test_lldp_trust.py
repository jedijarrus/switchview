"""F3: LLDP and MAC tables from an access port no longer decide on their own what SwitchView treats as trusted.

Vector A (the audit): one LLDP frame, or a flood of five or more MACs, on an access port hid every device behind it from the list of
unknown devices. Vector B: a forged LLDP frame naming another managed switch made the port an uplink, and the netmap showed a link no
switch confirms. Now main.confirmed_endpoints keeps only what both switches report (LLDP from both sides naming exactly this port pair,
or base MACs learned mutually); build_map marks every port "uc" and every link "confirmed"; the unknown list skips only trunks and
confirmed uplinks and flags the rest ("uplink_lldp", "lldp", "many"), unflagged entries first. The uplink protection itself
(changes.inventory, plan_ports) stays exactly as it was (R40, E21).

End to end with the real poller (poll_switch) and the real build_map / inventory / unknown_devices against the recorded walks of
tests/switchfix.py behind a fake snmp.walk; no network. The network helpers are copies of those in tests/test_uplinks.py
(tests/switchfix.py imports no app code, and an imported fixture would trip ruff F401/F811).
"""
import asyncio
from collections import defaultdict

import pytest

import changes
import config
import crypto
import db
import main
import poller
import snmp
import sshcli
from cfgparse import parse_config
from switchfix import W_SAMPLE, WALK_BASES, walk_answer

OIDS = poller.O
USER = {"username": "tester", "name": "Tester", "method": "local"}
MAC1 = "aa:bb:cc:00:00:01"


def lldp(local: str, neighbour: str, port_id: str, port_desc: str, rem: int = 1) -> dict:
    """The lldpRemTable rows of one neighbour by base OID, index <timemark 0>.<lldpRemLocalPortNum>.<lldpRemIndex>."""
    i = f"0.{local}.{rem}"
    return {OIDS["lldpSys"]: [(f"{OIDS['lldpSys']}.{i}", neighbour)], OIDS["lldpPortId"]: [(f"{OIDS['lldpPortId']}.{i}", port_id)],
            OIDS["lldpPortDesc"]: [(f"{OIDS['lldpPortDesc']}.{i}", port_desc)]}


def fdb(bridge_port: str, mac: str) -> dict:
    """A MAC learned on a bridge port in VLAN 1 (dot1qTpFdbPort .<fid>.<mac as 6 decimals>, fid 1 = VLAN 1)."""
    octets = ".".join(str(int(x, 16)) for x in mac.split(":"))
    return {OIDS["fdb"]: [(f"{OIDS['fdb']}.1.{octets}", bridge_port)], OIDS["fid"]: [(f"{OIDS['fid']}.0.1", "1")]}


def merge(*recordings: dict) -> dict:
    out: dict = defaultdict(list)
    for recording in recordings:
        for oid, rows in recording.items():
            out[oid] += rows
    return dict(out)


class Network:
    """The switches behind SNMP, per host their recorded walks by base OID (switchfix.walk_answer)."""

    def __init__(self):
        self.rec: dict[str, dict] = {}

    async def walk(self, host, cred, oid, hex_values=False, timeout=60, strict=False):
        return walk_answer(self.rec[host].get(oid, []), oid, hex_values)


@pytest.fixture
async def net(tmp_path, monkeypatch) -> Network:
    """A fresh database (the app's own init_db); snmp.walk answered by the Network; fresh poll and change locks."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    await db.init_db()
    network = Network()
    monkeypatch.setattr(snmp, "walk", network.walk)
    monkeypatch.setattr(poller, "_locks", {})
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    return network


async def add(net: Network, name: str, host: str, driver: str, W: dict, *extra: dict, base_mac: str = "") -> int:
    """A managed switch (SNMP writing on, with a RW community), its walks (W and the extra rows, sysName = name), polled once."""
    rec = merge({WALK_BASES[k]: rows for k, rows in W.items()}, {OIDS["sysName"]: [(f"{OIDS['sysName']}.0", name)]}, *extra)
    if base_mac:
        rec[OIDS["baseMac"]] = [(f"{OIDS['baseMac']}.0", base_mac.replace(":", " ").upper())]
    net.rec[host] = rec
    async with db.db() as conn:
        cur = await conn.execute("INSERT INTO switches(name, host, driver, snmp_write, snmp_version, snmp_community, snmp_rw_community) "
                                 "VALUES (?,?,?,1,'2c',?,?)", (name, host, driver, crypto.encrypt("read-s3cret"), crypto.encrypt("rw-s3cret")))
        await conn.commit()
        sid = cur.lastrowid
    assert (await poller.poll_switch(sid))["ok"] is True
    return sid


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
    return next(x for x in m["links"] if {x["a"], x["b"]} == {a, b})


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
    A learns B's base MAC on port 8, B never A's: nothing; once B learns A's base MAC on port 8 as well, A:8 and B:8 are confirmed."""
    def sw(k, base, ports):
        return {"k": k, "sys": f"{k.lower()}.example", "baseMac": base, "ports": [{"n": n, "tr": "", "mb": [], "l": entries} for n, entries in ports]}
    a = sw("A", "mac-a", [("3", [["B", "6", "6"]]), ("6", [["b.example", " 6 ", "x"]]), ("7", [["B", "to-core", "7"]]), ("8", [])])
    b = sw("B", "mac-b", [("6", [["A", "6", "6"]]), ("7", [["a.example", "uplink", "7 "]]), ("8", [])])
    macs = {("A", "8"): {"mac-b", "aa:bb:cc:00:00:01"}}
    pairs = {("A", "6"), ("B", "6"), ("A", "7"), ("B", "7")}
    assert main.confirmed_endpoints([a, b], macs) == pairs
    assert main.confirmed_endpoints([a, b], {**macs, ("B", "8"): {"mac-a"}}) == pairs | {("A", "8"), ("B", "8")}
