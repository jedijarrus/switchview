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
    "ifType": "1.3.6.1.2.1.2.2.1.3",
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

# Portauswahl nach ifType (IANAifType; der Walk liefert die Zahl), siehe select_ports
PHYS_IFTYPES = frozenset({"6", "117"})  # ethernetCsmacd, gigabitEthernet: physische Ports
LAG_IFTYPE = "161"  # ieee8023adLag: Trunk / LAG (Port-channel, ae, Bridge-Aggregation, lag, ...)
# propVirtual (53) und propMultiplexor (54): als LAG nur mit LAG_NAME und physischem Port darunter (klassisches IOS meldet
# Port-channels so)
NAMED_LAG_IFTYPES = frozenset({"53", "54"})
# Namen, die ein LAG dieser Typen haben muss, jeweils direkt gefolgt von einer Ziffer 0-9, Gross-/Kleinschreibung egal:
#   Po, Port-channel           Cisco (IOS-ifName "Po1"), Arista ("Port-Channel1"), Dell ("Po1", OS10 "port-channel1")
#   ae                         Juniper ("ae0")
#   Bridge-Aggregation, BAGG   HPE/H3C Comware (lang und kurz)
#   lag                        Aruba AOS-CX ("lag1")
#   ch                         Channel-Gruppen mancher Smart-Switches ("ch1")
#   Trk                        HPE ProCurve / AOS-S ("Trk1"), falls so ein Switch unter einem anderen Treiber laeuft
LAG_NAME = re.compile(r"(?:Po|Port-channel|ae|Bridge-Aggregation|BAGG|lag|ch|Trk)[0-9]", re.IGNORECASE)

_locks: dict[int, asyncio.Lock] = {}


WRITE_DISABLED = "SNMP-Schreiben ist für diesen Switch nicht aktiviert"
NO_WRITE_CREDS = "Keine SNMP-Schreib-Zugangsdaten hinterlegt"
PUBLIC_COMMUNITY = "Community 'public' wird nicht zum Schreiben verwendet – bitte eine eigene Schreib-Community hinterlegen"


def creds_of(row, write: bool = False) -> dict:
    """Die SNMP-Identitaet einer switches-Zeile als cred fuer snmp.walk / get / set_vars (Schluessel, wie snmp._auth_args sie liest).

    write=False: die Lese-Identitaet (snmp_version, snmp_community bzw. snmp_user ...), unveraendert wie seit jeher.
    write=True: die Schreib-Identitaet fuer SNMP-SETs, oder snmp.SnmpError mit dem Grund; Regel und Gruende siehe write_identity.
    """
    if write:
        return write_identity(row)[1]
    return {
        "snmp_version": row["snmp_version"],
        "snmp_community": decrypt(row["snmp_community"]),
        "snmp_user": row["snmp_user"],
        "snmp_auth_proto": row["snmp_auth_proto"],
        "snmp_auth_pass": decrypt(row["snmp_auth_pass"]),
        "snmp_priv_proto": row["snmp_priv_proto"],
        "snmp_priv_pass": decrypt(row["snmp_priv_pass"]),
    }


def write_identity(row) -> tuple[str, dict]:
    """Mit welcher Identitaet SNMP-SETs an diesen Switch gehen: ("rw" | "read", cred). Die EINE Stelle, die das entscheidet
    (creds_of(row, write=True) ist ihr cred, die Anzeige in main._public ihre Quelle). Read-only-Zugangsdaten werden nie still
    schreibfaehig, darum snmp.SnmpError mit dem Grund statt eines Ersatzes:

    1. snmp_write aus: Fehler, auch wenn Schreib-Zugangsdaten hinterlegt sind.
    2. eine eigene RW-Identitaet ("rw"): der v3-Benutzer snmp_rw_user mit snmp_rw_auth_* / snmp_rw_priv_*, sonst die v2c-Community
       snmp_rw_community. Der v3-Benutzer gewinnt, wenn beide gesetzt sind (die Community bleibt dann ungelesen).
    3. sonst die Lese-Identitaet ("read", muss am Geraet schreiben duerfen), nach snmp_version und nur eine echte: v3 mit Benutzer,
       v2c mit nicht leerer Community. Aus einer leeren Community machte snmp._auth_args "public".
    4. sonst Fehler: keine Schreib-Zugangsdaten.
    Die Community "public" (gleich welche Schreibweise, Leerraum aussen egal) schreibt nie (R25), weder als snmp_rw_community noch
    ueber die Lese-Identitaet: Fehler statt eines Rueckgriffs auf die naechste Identitaet. Sticht der v3-Benutzer eine RW-Community
    "public" aus, schreibt sie nicht und ist kein Grund zur Ablehnung.
    Ein Geheimnis der gewaehlten Identitaet, das sich nicht entschluesseln laesst, und ein v3-Kennwort, das _auth_args nicht verwenden
    wuerde, sind ebenfalls Fehler: sonst ginge der SET still mit einer anderen Identitaet oder einer schwaecheren Stufe hinaus. Ein
    Protokoll ohne Kennwort ist dagegen kein Fehler (das Switch-Formular schickt die Protokoll-Auswahl immer mit), es heisst: unbenutzt.
    """
    if not row["snmp_write"]:
        raise snmp.SnmpError(WRITE_DISABLED)
    if row["snmp_rw_user"]:
        return "rw", _write_v3(row, "snmp_rw_")
    if row["snmp_rw_community"]:
        return "rw", _write_v2c(row, "snmp_rw_community")
    if row["snmp_version"] == "3":
        if row["snmp_user"]:
            return "read", _write_v3(row, "snmp_")
    elif row["snmp_community"]:
        return "read", _write_v2c(row, "snmp_community")
    raise snmp.SnmpError(NO_WRITE_CREDS)


def _write_secret(row, key: str) -> str | None:
    """Das Geheimnis row[key] im Klartext fuer die Schreib-Identitaet, None wenn keins gespeichert ist. Ein gespeichertes, das sich nicht
    entschluesseln laesst (decrypt gibt dann None), ist ein Fehler und nie "nicht gesetzt"."""
    if not row[key]:
        return None
    value = decrypt(row[key])
    if not value:
        raise snmp.SnmpError(f"SNMP-Schreib-Zugangsdaten nicht lesbar: {key} lässt sich nicht entschlüsseln (SECRET_KEY geändert?)")
    return value


def _write_v2c(row, key: str) -> dict:
    """v2c mit der Community row[key]; nur fuer einen gesetzten key, also nie leer und nie "public" per Vorgabe. Eine gespeicherte
    Community "public" ist ein Fehler (R25)."""
    community = _write_secret(row, key)
    if community.strip().lower() == "public":
        raise snmp.SnmpError(PUBLIC_COMMUNITY)
    return {"snmp_version": "2c", "snmp_community": community, "snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None,
            "snmp_priv_proto": None, "snmp_priv_pass": None}


def _write_v3(row, prefix: str) -> dict:
    """v3 mit dem Benutzer row[prefix + "user"] und dessen auth/priv-Spalten (prefix "snmp_rw_" oder "snmp_"). Stufe wie snmp._auth_args:
    authPriv mit beiden Paaren, authNoPriv mit Auth-Paar, sonst noAuthNoPriv."""
    ap, apass = row[prefix + "auth_proto"], _write_secret(row, prefix + "auth_pass")
    pp, ppass = row[prefix + "priv_proto"], _write_secret(row, prefix + "priv_pass")
    auth = bool(ap and apass)
    if apass and not auth:
        raise snmp.SnmpError("SNMPv3-Schreib-Zugang unvollständig: Auth-Kennwort ohne Auth-Verfahren")
    if ppass and not (auth and pp):
        raise snmp.SnmpError("SNMPv3-Schreib-Zugang unvollständig: Priv-Kennwort ohne Verschlüsselungsverfahren oder ohne Authentifizierung")
    return {"snmp_version": "3", "snmp_community": None, "snmp_user": row[prefix + "user"], "snmp_auth_proto": ap, "snmp_auth_pass": apass,
            "snmp_priv_proto": pp, "snmp_priv_pass": ppass}


def parse_descr(descr: str) -> tuple[str, str]:
    m = re.search(r"\b(J\w{4,5}|JL\w{3,4})\s+(?:Switch\s+)?([\w\-+]+)", descr or "")
    model = f"{m.group(1)} {m.group(2)}" if m else (descr or "")[:40]
    f = re.search(r"revision\s+([\w.]+)", descr or "")
    return model, (f.group(1) if f else "")


def _tbl(rows: list[tuple[str, str]], base: str) -> dict[str, str]:
    p = base + "."
    return {oid[len(p):]: val for oid, val in rows if oid.startswith(p)}


def by_iftype(driver_name: str) -> bool:
    """Waehlt select_ports die Ports dieses Treibers nach ifType? Ja fuer jeden ausser procurve, auch fuer einen unbekannten Namen
    (drivers.driver_for nimmt dafuer generic). Nur dann braucht es den ifType-Walk."""
    return driver_name != "procurve"


def select_ports(ifname: dict[str, str], iftype: dict[str, str], ifstack: dict[str, str], driver_name: str
                 ) -> tuple[list[str], dict[str, str], dict[str, list[str]]]:
    """Welche Interfaces Ports sind und welche Trunks sie bilden. Die eine Stelle, an der Anzeige (_build) und Schreibweg
    (snmpwrite.build_cfg) das entscheiden, damit beide denselben Switch sehen.

    Eingaben sind _tbl-Tabellen: ifname {ifIndex: ifName}, iftype {ifIndex: ifType}, ifstack {"hoeher.tiefer": Status}. Ergebnis, alles
    als ifIndex: (Ports in ifIndex-Reihenfolge, member_of {Mitglied: Trunk}, members {Trunk: [Mitglieder in ifStack-Reihenfolge]}).
    Ein Port braucht in jedem Fall einen ifName und einen ganzzahligen ifIndex.

    procurve, genau wie seit jeher (iftype bleibt ungenutzt): Port ist ein Interface mit ifIndex < 1000, dessen Name weder VLAN
    enthaelt noch mit LO beginnt noch LOOPBACK enthaelt (Gross-/Kleinschreibung egal). Mitglied ist, was im ifStack unter einem
    Interface namens Trk... steht; members fuehrt nur Trunks mit Mitgliedern (ein leerer TrkN ist ueber seinen Namen Trunk).

    Jeder andere Treiber, nach ifType, ohne ifIndex-Grenze: Port ist ein Interface vom Typ 6 / 117 (physisch) oder ein LAG. LAG
    ist ein Interface vom Typ 161, und eines vom Typ 53 (propVirtual) oder 54 (propMultiplexor), dessen Name zu LAG_NAME passt und
    unter dem im ifStack direkt mindestens ein physischer Port steht (so meldet klassisches IOS seine Port-channels; Name und
    physisches Mitglied halten SVIs, Stack-Ports und logische Units wie ge-0/0/0.0 oder ae0.0 heraus). Alles andere ist kein Port,
    auch ein Interface ohne ifType-Zeile: VLAN-Interfaces, Loopback, Null, Tunnel, Subinterfaces, Stack-Ports, ... Trunk ist jeder
    LAG-Port: members fuehrt ihn, ein 161er auch ohne Mitglieder (dann mit []). Mitglied ist, was im ifStack direkt unter ihm steht;
    was unter einem anderen Interface steht (unter einem Subinterface oder einer logischen Unit), ist kein Mitglied.
    """
    member_of: dict[str, str] = {}
    members: dict[str, list[str]] = {}
    order = sorted(ifname, key=lambda x: int(x) if x.isdigit() else 10**9)
    if not by_iftype(driver_name):
        for k in ifstack:
            hi, _, lo = k.partition(".")
            if hi != "0" and lo != "0" and ifname.get(hi, "").startswith("Trk"):
                member_of[lo] = hi
                members.setdefault(hi, []).append(lo)
        ports = []
        for ifi in order:
            if not ifi.isdigit() or int(ifi) >= 1000:
                continue
            up = ifname[ifi].upper()
            if "VLAN" in up or up.startswith("LO") or "LOOPBACK" in up:
                continue
            ports.append(ifi)
        return ports, member_of, members
    physical = {ifi for ifi in ifname if ifi.isdigit() and iftype.get(ifi) in PHYS_IFTYPES}
    over_physical = set()  # Interfaces, unter denen im ifStack direkt ein physischer Port steht (wie unten ein Mitglied)
    for k in ifstack:
        hi, _, lo = k.partition(".")
        if hi != "0" and lo != "0" and lo in physical:
            over_physical.add(hi)

    def is_lag(ifi: str) -> bool:
        if iftype.get(ifi) == LAG_IFTYPE:
            return True
        return iftype.get(ifi) in NAMED_LAG_IFTYPES and ifi in over_physical and LAG_NAME.match(ifname[ifi]) is not None

    ports = [ifi for ifi in order if ifi in physical or (ifi.isdigit() and is_lag(ifi))]
    members = {ifi: [] for ifi in ports if ifi not in physical}
    for k in ifstack:
        hi, _, lo = k.partition(".")
        if hi != "0" and lo != "0" and hi in members:
            member_of[lo] = hi
            members[hi].append(lo)
    return ports, member_of, members


async def poll_switch(switch_id: int) -> dict:
    lock = _locks.setdefault(switch_id, asyncio.Lock())
    async with lock:
        async with db() as conn:
            async with conn.execute("SELECT * FROM switches WHERE id = ?", (switch_id,)) as cur:
                row = await cur.fetchone()
        if not row:
            raise ValueError("Switch nicht gefunden")
        host, cred = row["host"], creds_of(row)
        driver_name = row["driver"] or "procurve"
        # Walks, ohne die es kein Ergebnis gibt: sysName und ifName, dazu ifType, wo select_ports nach ihm waehlt (ohne ifType
        # stuende der Switch sonst bis zum naechsten Poll ohne Ports da)
        needed = ("sysName", "ifName", "ifType") if by_iftype(driver_name) else ("sysName", "ifName")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            keys = list(O)
            results = await asyncio.gather(*(snmp.walk(host, cred, O[k], hex_values=k in HEX) for k in keys), return_exceptions=True)
            W = {}
            for k, r in zip(keys, results):
                if isinstance(r, Exception):
                    if k in needed:
                        raise r
                    log.warning("%s: Walk %s fehlgeschlagen: %s", host, k, r)
                    r = []
                W[k] = r
            if by_iftype(driver_name) and _tbl(W["ifName"], O["ifName"]) and not _tbl(W["ifType"], O["ifType"]):
                # Kein Fehler, aber keine einzige Zeile (leere oder verbotene View): ohne ifType kaemen keine Ports heraus, und das
                # Speichern unten loeschte die des letzten guten Polls. Also wie ein gescheiterter Pflicht-Walk.
                raise snmp.SnmpError("ifType-Walk lieferte keine Zeile, ifName schon: ohne ifType lassen sich die Ports nicht bestimmen")
            data = _build(W, driver_name)
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


def _build(W: dict, driver_name: str = "procurve") -> dict:
    """Die Anzeige-Daten aus den Walks W (Schluessel wie O). Welche Interfaces Ports und Trunks sind, entscheidet select_ports nach
    dem Treiber; ifType wird nur gelesen, wenn er danach waehlt."""
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

    iftype = _tbl(W["ifType"], O["ifType"]) if by_iftype(driver_name) else {}
    port_ifis, member_of, members = select_ports(ifname, iftype, _tbl(W["ifStack"], O["ifStack"]), driver_name)
    ports, macs = [], []
    for ifi in port_ifis:
        name = ifname[ifi]
        # Trunk: bei ProCurve jedes Trk-Interface (auch ohne Mitglieder), sonst jeder LAG-Port (select_ports fuehrt ihn in members)
        is_trk = ifi in members if by_iftype(driver_name) else name.startswith("Trk")
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
