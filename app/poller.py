"""SNMP-Abfrage eines Switches und Ablage in der DB (nur lesend)."""
import asyncio
import json
import logging
import re
from datetime import datetime, timezone

import snmp
from crypto import decrypt
from db import db

log = logging.getLogger("switchview.poller")

O = {
    "sysDescr": "1.3.6.1.2.1.1.1",
    "sysUpTime": "1.3.6.1.2.1.1.3",
    "sysName": "1.3.6.1.2.1.1.5",
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ifOper": "1.3.6.1.2.1.2.2.1.8",
    "ifAdmin": "1.3.6.1.2.1.2.2.1.7",
    "bp2if": "1.3.6.1.2.1.17.1.4.1.2",
    "baseMac": "1.3.6.1.2.1.17.1.1",
    "vlanName": "1.3.6.1.2.1.17.7.1.4.3.1.1",
    "vlanEgress": "1.3.6.1.2.1.17.7.1.4.3.1.2",
    "vlanUntagged": "1.3.6.1.2.1.17.7.1.4.3.1.4",
    "pvid": "1.3.6.1.2.1.17.7.1.4.5.1.1",
    "fid": "1.3.6.1.2.1.17.7.1.4.2.1.3",
    "fdb": "1.3.6.1.2.1.17.7.1.2.2.1.2",
    "ifStack": "1.3.6.1.2.1.31.1.2.1.3",
    "lldpSys": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "lldpPortId": "1.0.8802.1.1.2.1.4.1.1.7",
}
HEX = {"baseMac", "vlanEgress", "vlanUntagged"}

_locks: dict[int, asyncio.Lock] = {}


def creds_of(row) -> dict:
    return {
        "snmp_version": row["snmp_version"],
        "snmp_community": decrypt(row["snmp_community"]),
        "snmp_user": row["snmp_user"],
        "snmp_auth_proto": row["snmp_auth_proto"],
        "snmp_auth_pass": decrypt(row["snmp_auth_pass"]),
        "snmp_priv_proto": row["snmp_priv_proto"],
        "snmp_priv_pass": decrypt(row["snmp_priv_pass"]),
    }


def parse_descr(descr: str) -> tuple[str, str]:
    m = re.search(r"\b(J\w{4,5}|JL\w{3,4})\s+(?:Switch\s+)?([\w\-+]+)", descr or "")
    model = f"{m.group(1)} {m.group(2)}" if m else (descr or "")[:40]
    f = re.search(r"revision\s+([\w.]+)", descr or "")
    return model, (f.group(1) if f else "")


def _tbl(rows: list[tuple[str, str]], base: str) -> dict[str, str]:
    p = base + "."
    return {oid[len(p):]: val for oid, val in rows if oid.startswith(p)}


async def poll_switch(switch_id: int) -> dict:
    lock = _locks.setdefault(switch_id, asyncio.Lock())
    async with lock:
        async with db() as conn:
            async with conn.execute("SELECT * FROM switches WHERE id = ?", (switch_id,)) as cur:
                row = await cur.fetchone()
        if not row:
            raise ValueError("Switch nicht gefunden")
        host, cred = row["host"], creds_of(row)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            keys = list(O)
            results = await asyncio.gather(*(snmp.walk(host, cred, O[k], hex_values=k in HEX) for k in keys), return_exceptions=True)
            W = {}
            for k, r in zip(keys, results):
                if isinstance(r, Exception):
                    if k in ("sysName", "ifName"):
                        raise r
                    log.warning("%s: Walk %s fehlgeschlagen: %s", host, k, r)
                    r = []
                W[k] = r
            data = _build(W)
        except Exception as e:  # noqa: BLE001
            async with db() as conn:
                await conn.execute("UPDATE switches SET last_poll = ?, last_poll_ok = 0, last_error = ? WHERE id = ?", (now, str(e)[:300], switch_id))
                await conn.commit()
            log.warning("Abfrage %s fehlgeschlagen: %s", host, e)
            return {"ok": False, "error": str(e)}

        async with db() as conn:
            await conn.execute(
                "UPDATE switches SET sys_name=?, sys_descr=?, model=?, firmware=?, base_mac=?, uptime=?, last_poll=?, last_poll_ok=1, last_error=NULL WHERE id=?",
                (data["sysName"], data["sysDescr"], data["model"], data["firmware"], data["baseMac"], data["uptime"], now, switch_id),
            )
            await conn.execute("DELETE FROM ports WHERE switch_id = ?", (switch_id,))
            await conn.execute("DELETE FROM vlans WHERE switch_id = ?", (switch_id,))
            await conn.execute("DELETE FROM macs WHERE switch_id = ?", (switch_id,))
            await conn.executemany(
                "INSERT INTO ports(switch_id, ifindex, name, alias, oper, admin, speed, pvid, untagged, tagged, trunk, members, lldp, mac_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(switch_id, p["if"], p["name"], p["alias"], p["oper"], p["admin"], p["speed"], p["pvid"], json.dumps(p["untagged"]), json.dumps(p["tagged"]),
                  p["trunk"], json.dumps(p["members"]), json.dumps(p["lldp"]), p["mac_count"]) for p in data["ports"]],
            )
            await conn.executemany("INSERT INTO vlans(switch_id, vid, name) VALUES (?,?,?)", [(switch_id, v, n) for v, n in data["vlans"].items()])
            await conn.executemany(
                "INSERT OR REPLACE INTO macs(switch_id, port, mac, vlan, last_seen) VALUES (?,?,?,?,?)",
                [(switch_id, port, mac, vlan, now) for port, mac, vlan in data["macs"]],
            )
            await conn.commit()
        return {"ok": True, "ports": len(data["ports"]), "macs": len(data["macs"])}


def _build(W: dict) -> dict:
    sysName = (W["sysName"][0][1] if W["sysName"] else "")
    sysDescr = (W["sysDescr"][0][1] if W["sysDescr"] else "")
    model, fw = parse_descr(sysDescr)
    uptime = int(W["sysUpTime"][0][1]) // 100 if W["sysUpTime"] and W["sysUpTime"][0][1].isdigit() else None
    base = snmp.fmt_mac(snmp.hex_to_bytes(W["baseMac"][0][1])) if W["baseMac"] else ""

    ifname = _tbl(W["ifName"], O["ifName"]); alias = _tbl(W["ifAlias"], O["ifAlias"])
    speed = _tbl(W["ifHighSpeed"], O["ifHighSpeed"]); oper = _tbl(W["ifOper"], O["ifOper"]); admin = _tbl(W["ifAdmin"], O["ifAdmin"])
    bp2if = _tbl(W["bp2if"], O["bp2if"]); if2bp = {v: k for k, v in bp2if.items()}
    vname = _tbl(W["vlanName"], O["vlanName"])
    egress = {k: snmp.bitmap_ports(v) for k, v in _tbl(W["vlanEgress"], O["vlanEgress"]).items()}
    untag = {k: snmp.bitmap_ports(v) for k, v in _tbl(W["vlanUntagged"], O["vlanUntagged"]).items()}
    pvid = _tbl(W["pvid"], O["pvid"])

    member_of: dict[str, str] = {}
    members: dict[str, list[str]] = {}
    for k, _v in _tbl(W["ifStack"], O["ifStack"]).items():
        hi, _, lo = k.partition(".")
        if hi != "0" and lo != "0" and ifname.get(hi, "").startswith("Trk"):
            member_of[lo] = hi
            members.setdefault(hi, []).append(lo)

    lldp: dict[str, list[list[str]]] = {}
    l_desc = _tbl(W["lldpPortDesc"], O["lldpPortDesc"]); l_id = _tbl(W["lldpPortId"], O["lldpPortId"])
    for k, v in _tbl(W["lldpSys"], O["lldpSys"]).items():
        parts = k.split(".")
        if len(parts) < 3 or not v.strip():
            continue
        lp = parts[1]
        pd = l_desc.get(k, "") or l_id.get(k, "")
        lldp.setdefault(lp, []).append([v.strip(), pd.strip()])

    fid2vlan = {}
    for k, v in _tbl(W["fid"], O["fid"]).items():
        fid2vlan[v] = k.split(".")[-1]
    fdb_by_bp: dict[str, list[tuple[str, str]]] = {}
    for k, bp in _tbl(W["fdb"], O["fdb"]).items():
        parts = k.split(".")
        if len(parts) != 7:
            continue
        mac = ":".join(f"{int(x):02x}" for x in parts[1:7])
        fdb_by_bp.setdefault(bp, []).append((mac, fid2vlan.get(parts[0], parts[0])))

    ports, macs = [], []
    for ifi in sorted(ifname, key=lambda x: int(x) if x.isdigit() else 10**9):
        if not ifi.isdigit() or int(ifi) >= 1000:
            continue
        name = ifname[ifi]
        up = name.upper()
        if "VLAN" in up or up.startswith("LO") or "LOOPBACK" in up:
            continue
        is_trk = name.startswith("Trk")
        trk = member_of.get(ifi)
        eff = if2bp.get(trk) if trk else if2bp.get(ifi)
        b = int(eff) if eff else None
        un = sorted([v for v in vname if b and b in untag.get(v, set())], key=int)
        tg = sorted([v for v in vname if b and b in egress.get(v, set()) and b not in untag.get(v, set())], key=int)
        fdb = fdb_by_bp.get(eff, []) if eff else []
        if not trk:  # MACs nur einmal ablegen (am Trunk bzw. am Einzelport)
            macs += [(name, m, v) for m, v in fdb]
        ports.append({
            "if": int(ifi), "name": name, "alias": alias.get(ifi, ""),
            "oper": 1 if oper.get(ifi) == "1" else 0, "admin": 1 if admin.get(ifi) == "1" else 0,
            "speed": int(speed.get(ifi, "0") or 0), "pvid": pvid.get(eff, "") if eff else "",
            "untagged": un, "tagged": tg,
            "trunk": ifname.get(trk, "") if trk else (name if is_trk else ""),
            "members": [ifname.get(m, m) for m in members.get(ifi, [])] if is_trk else [],
            "lldp": lldp.get(ifi, []), "mac_count": len(fdb),
        })
    return {"sysName": sysName, "sysDescr": sysDescr, "model": model, "firmware": fw, "uptime": uptime, "baseMac": base,
            "vlans": {k: vname[k] for k in sorted(vname, key=int)}, "ports": ports, "macs": macs}


async def poll_all():
    async with db() as conn:
        async with conn.execute("SELECT id FROM switches WHERE enabled = 1") as cur:
            ids = [r["id"] for r in await cur.fetchall()]
    sem = asyncio.Semaphore(4)

    async def one(i):
        async with sem:
            try:
                await poll_switch(i)
            except Exception:  # noqa: BLE001
                log.exception("Abfrage Switch %s", i)

    await asyncio.gather(*(one(i) for i in ids))
