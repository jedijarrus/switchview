"""The test network of tests/test_uplinks.py and tests/test_lldp_trust.py: managed switches behind a fake snmp.walk that answers from
recorded walks (tests/switchfix.py), polled by the real poller into a fresh database of the app's own init_db; no network.

Unlike tests/switchfix.py this module imports app code. The `net` fixture that sets the network up lives in tests/conftest.py (it calls
fresh_network), so a test file takes it without importing it: an imported fixture trips ruff F401/F811.
"""
import asyncio
from collections import defaultdict

import config
import crypto
import db
import poller
import snmp
import sshcli
from switchfix import WALK_BASES, walk_answer

OIDS = poller.O


def lldp(local: str, neighbour: str, port_id: str, port_desc: str, rem: int = 1) -> dict:
    """The lldpRemTable rows of one neighbour by base OID, index <timemark 0>.<lldpRemLocalPortNum>.<lldpRemIndex>."""
    i = f"0.{local}.{rem}"
    return {OIDS["lldpSys"]: [(f"{OIDS['lldpSys']}.{i}", neighbour)], OIDS["lldpPortId"]: [(f"{OIDS['lldpPortId']}.{i}", port_id)],
            OIDS["lldpPortDesc"]: [(f"{OIDS['lldpPortDesc']}.{i}", port_desc)]}


def fdb(bridge_port: str, mac: str, vlan: str = "1") -> dict:
    """A MAC learned on a bridge port in a VLAN (dot1qTpFdbPort .<fid>.<mac as 6 decimals>; the fid is the VLAN ID, mapped back by
    dot1qVlanFdbId .0.<vlan> = <fid>). Default VLAN 1."""
    octets = ".".join(str(int(x, 16)) for x in mac.split(":"))
    return {OIDS["fdb"]: [(f"{OIDS['fdb']}.{vlan}.{octets}", bridge_port)], OIDS["fid"]: [(f"{OIDS['fid']}.0.{vlan}", vlan)]}


def merge(*recordings: dict) -> dict:
    out: dict = defaultdict(list)
    for recording in recordings:
        for oid, rows in recording.items():
            out[oid] += rows
    return dict(out)


class Network:
    """The switches behind SNMP, per host their recorded walks by base OID: snmp.walk answers the lenient display poll and the strict
    live read alike, the free text as hex for a walk with -Ox (switchfix.walk_answer). Records every walked OID per host."""

    def __init__(self):
        self.rec: dict[str, dict] = {}
        self.walked: dict[str, list[str]] = defaultdict(list)

    async def walk(self, host, cred, oid, hex_values=False, timeout=60, strict=False):
        self.walked[host].append(oid)
        return walk_answer(self.rec[host].get(oid, []), oid, hex_values)


async def fresh_network(tmp_path, monkeypatch) -> Network:
    """What the `net` fixture returns: a fresh database (the app's own init_db); snmp.walk answered by the Network; fresh poll and
    change locks."""
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
