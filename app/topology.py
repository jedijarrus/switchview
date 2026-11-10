"""The netmap: every enabled switch with its ports, VLANs and learned devices, and the links between the switches (LLDP and base
MACs), by switch id. changes.inventory takes its uplink protection from it. Split from main.py (Phase 3, Task 11), the code as it
was."""
import json
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

import auth
import cfgparse
import changes
import drivers
import names as names_mod
import poller
import roles
from db import db, load_settings

router = APIRouter()


# ── Netzplan ──────────────────────────────────────────────────────────────────
@router.get("/api/netmap")
async def netmap(user=Depends(auth.require(roles.LESEN))):
    return await build_map()


async def build_map() -> dict:
    st = await load_settings(["radius_server", "pf_snmp_user"])
    server, snmp_user = st["radius_server"] or "", st["pf_snmp_user"] or ""
    async with db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE enabled = 1 ORDER BY zone, sort, name") as cur:
            sws = await cur.fetchall()
        async with conn.execute("SELECT * FROM ports ORDER BY switch_id, ifindex") as cur:
            prows = await cur.fetchall()
        async with conn.execute("SELECT switch_id, vid, name FROM vlans") as cur:
            vrows = await cur.fetchall()
        async with conn.execute("SELECT m.switch_id, m.port, m.mac, m.vlan, n.ip, n.name, n.vendor, dv.name AS dname, dv.allowed "
                                "FROM macs m LEFT JOIN names n ON n.mac = m.mac LEFT JOIN devices dv ON dv.mac = m.mac") as cur:
            mrows = await cur.fetchall()
        async with conn.execute("SELECT switch_id, taken_at, parsed, stale FROM switch_cfg") as cur:
            cfgs = {r["switch_id"]: (r["taken_at"], json.loads(r["parsed"]), bool(r["stale"])) for r in await cur.fetchall()}
    # R39: ein Read der running-config zaehlt nur fuer einen Treiber mit SSH-CLI. Bei jedem anderen waere er eine Fehldeutung durch den
    # ProCurve-Parser (jeder Port "Protected") oder von vor einem Treiberwechsel: der Switch gilt als nicht gelesen.
    with_cli = {s["id"] for s in sws if drivers.can(drivers.driver_for(s), "cli")}
    cfgs = {sid: v for sid, v in cfgs.items() if sid in with_cli}

    vlans: dict[str, str] = {}
    vl_by: dict[int, list[str]] = defaultdict(list)
    for v in sorted(vrows, key=lambda r: _vid_num(r["vid"])):
        vlans.setdefault(v["vid"], v["name"])
        vl_by[v["switch_id"]].append(v["vid"])
    devs: dict[tuple, list] = defaultdict(list)
    for m in mrows:
        known = 0 if m["dname"] is None else (2 if m["allowed"] else 1)
        devs[(m["switch_id"], m["port"])].append([m["mac"], m["vlan"], m["ip"] or "", m["dname"] or m["name"] or "",
                                                  m["vendor"] or names_mod.vendor_of(m["mac"]), known])
    ports_by: dict[int, list] = defaultdict(list)
    # PoE nur, wo der Treiber des Switches es jetzt kann: PoE-Spalten eines Polls von vor einem Treiberwechsel zeigen nichts mehr
    poe_ok = {s["id"]: drivers.can(drivers.driver_for(s), "snmp_poe") for s in sws}
    for p in prows:
        key = (p["switch_id"], p["trunk"] or p["name"])
        d = sorted(devs.get(key, []), key=lambda x: -x[5])
        _, cfg, stale = cfgs.get(p["switch_id"], (None, None, False))
        st = cfgparse.port_state(cfg, p["name"]) if cfg else None
        if st and stale:    # the read is older than the switch's last change (switch_cfg.stale): on / off from the poll
            st = st | {"en": bool(p["admin"])}
        port = {
            "st": changes.status_of(st) if st else ("off" if not p["admin"] else ""),
            "lim": ((st["cl"] if st["x"] else None) or (st["al"] if st["m"] else None)) if st else None,
            "n": p["name"], "a": p["alias"] or "", "o": bool(p["oper"]), "ad": bool(p["admin"]), "s": p["speed"] or 0,
            "pv": p["pvid"] or "", "u": json.loads(p["untagged"] or "[]"), "t": json.loads(p["tagged"] or "[]"),
            "tr": p["trunk"] or "", "mb": json.loads(p["members"] or "[]"), "l": json.loads(p["lldp"] or "[]"),
            "mc": p["mac_count"], "d": d[:12]}
        if poe_ok.get(p["switch_id"]) and (p["poe_admin"] is not None or p["poe_status"] is not None):
            # nur ein Port mit sicher zugeordnetem PoE-Eintrag (poller.poe_ports): an / aus, Erkennungsstatus (RFC 3621), Leistung in mW
            port["poe"] = {"on": None if p["poe_admin"] is None else p["poe_admin"] == 1, "status": p["poe_status"], "mw": p["poe_power"]}
        ports_by[p["switch_id"]].append(port)

    # Switches by id (Review §4): a name is not unique, and two switches of one name looked up by it shadowed one another
    enabled = {s["id"] for s in sws}
    all_macs: dict[tuple[int, str], set[str]] = defaultdict(set)  # (switch id, port) -> every MAC, for the link detection
    for m in mrows:
        if m["switch_id"] in enabled:
            all_macs[(m["switch_id"], m["port"])].add(m["mac"])
    switches = []
    for s in sws:
        switches.append({"k": s["name"], "id": s["id"], "sys": s["sys_name"] or "", "model": s["model"] or "", "fw": s["firmware"] or "",
                         "zone": s["zone"] or "", "host": s["host"], "lastPoll": s["last_poll"], "ok": bool(s["last_poll_ok"]),
                         "error": s["last_error"] or "", "baseMac": s["base_mac"] or "", "ports": ports_by.get(s["id"], []),
                         "ssh": bool(s["ssh_user"] and s["ssh_pass"]), "driver": s["driver"], "caps": sorted(drivers.driver_for(s).caps),
                         "snmp_write": bool(s["snmp_write"]), "cfgAt": cfgs.get(s["id"], (None,))[0],
                         "cfgStale": cfgs.get(s["id"], (None, None, False))[2],
                         "ready": changes.readiness(cfgs[s["id"]][1], server or None, snmp_user) if s["id"] in cfgs else None,
                         "limitMax": changes.limit_max(s["firmware"] or ""), "vl": vl_by.get(s["id"], []),
                         "credWarnings": poller.credential_warnings(s)})
    links = _links(switches, all_macs)
    by_id = {s["id"]: s for s in switches}
    for link in links:  # Uplink-Ports markieren (inkl. Trunk-Mitglieder)
        for sid, side in ((link["a"], link["A"]), (link["b"], link["B"])):
            ups = set(side["ports"]) | ({side["trunk"]} if side["trunk"] else set())
            for p in by_id[sid]["ports"]:
                if p["n"] in ups or (p["tr"] and p["tr"] in ups):
                    p["up"] = True
    # F3: "uc" = the port, its trunk or (for a trunk) one of its members is an endpoint both switches confirm; a link is confirmed
    # when every port of both sides is. Display and the unknown-device list only: the uplink protection (changes.inventory) is unchanged.
    confirmed = confirmed_endpoints(switches, all_macs)
    for s in switches:
        for p in s["ports"]:
            p["uc"] = any((s["id"], n) in confirmed for n in (p["n"], p["tr"], *p["mb"]) if n)
    uc = {(s["id"], p["n"]) for s in switches for p in s["ports"] if p["uc"]}
    for link in links:
        link["confirmed"] = all((sid, n) in uc for sid, side in ((link["a"], link["A"]), (link["b"], link["B"])) for n in side["ports"])
    # "bm" = the base MAC of another managed switch is learned on the port (on a member: on its trunk, where the poller files a member's
    # MACs). changes.inventory counts every such port as an uplink (T6-RR1c), whichever port _links takes for the link.
    base_of = {s["baseMac"]: s["id"] for s in switches if s["baseMac"]}
    for s in switches:
        for p in s["ports"]:
            p["bm"] = any(base_of.get(mac) not in (None, s["id"]) for mac in all_macs.get((s["id"], p["tr"] or p["n"]), ()))
    return {"generated": datetime.now(timezone.utc).isoformat(), "vlans": vlans, "switches": switches, "links": links}


def _port_num(v: str) -> int:
    """Sort key of a port name: its number for ASCII digits up to nine places, else 999. int() alone raised on a name of more than 4300
    digits and on a digit isdigit() takes but int() does not ("²"), and with it build_map, the netmap, the inventory and every change."""
    return int(v) if v.isascii() and v.isdigit() and len(v) <= 9 else 999


def _vid_num(v: str) -> int:
    """Sort key of a VLAN id as text (vlans.vid, a port's u / t): as _port_num, else 10**9 (after every number)."""
    return int(v) if v.isascii() and v.isdigit() and len(v) <= 9 else 10**9


def switch_keys(switches: list[dict]) -> dict[str, set[int]]:
    """Non-empty sysName and name (k) of every switch -> the ids of the switches so named: how _links and confirmed_endpoints tell an
    LLDP neighbour that is a managed switch. A name two switches carry names both (LLDP gives only the name; R40, rather one uplink too
    many). changes.inventory takes the same mapping for its uplink backstop (R40)."""
    keys: dict[str, set[int]] = defaultdict(set)
    for s in switches:
        for name in (s["sys"], s["k"]):
            if name:
                keys[name].add(s["id"])
    return dict(keys)


def device_port(p: dict) -> bool:
    """Whether devices are listed at port p of build_map (the access-port rule, F3): not a Trk port, no trunk or LAG and no member of
    one ("tr"), not a confirmed uplink (up and uc). An unconfirmed uplink is a device port: one forged LLDP frame or a MAC flood on an
    access port must not hide the devices behind it. api_devices.unknown_devices and history.record take it."""
    return not (p["n"].startswith("Trk") or p["tr"] or (p.get("up") and p["uc"]))


def suspect_port(p: dict, keys: dict[str, set[int]]) -> bool:
    """Whether port p of build_map may be an uplink (keys: switch_keys of the map's switches): a link ends there (up; at a device
    port one nobody confirms), an LLDP neighbour is named like a managed switch, or another managed switch's base MAC is learned there
    (bm). history.record records the devices of such a device port, but marked; api_devices.unknown_devices flags them in the same
    cases."""
    return bool(p.get("up") or any(e[0] in keys for e in p["l"]) or p["bm"])


def _lldp_claims(switches: list[dict], keys: dict[str, set[int]]) -> set[tuple[tuple[int, str], tuple[int, str]]]:
    """((A, P), (B, Q)) for every LLDP entry on port P of switch A whose sysName maps (keys, switch_keys) to another switch B and whose
    element 1 or 2 (stripped) is B's port Q; a name several switches carry maps to each of them. A pair is reported by both sides
    when ((B, Q), (A, P)) is a claim as well (confirmed_endpoints, _links)."""
    names = {s["id"]: {p["n"] for p in s["ports"]} for s in switches}
    claims = set()
    for s in switches:
        for p in s["ports"]:
            for entry in p["l"]:
                for nid in sorted(keys.get(entry[0], ())):
                    if nid != s["id"]:
                        claims |= {((s["id"], p["n"]), (nid, q)) for q in (e.strip() for e in entry[1:3]) if q in names[nid]}
    return claims


def confirmed_endpoints(switches: list[dict], all_macs: dict[tuple[int, str], set[str]]) -> set[tuple[int, str]]:
    """(switch id, port name) of every link endpoint both switches report themselves (F3); inputs as for _links.
    LLDP: port P of A names B's port Q (_lldp_claims), and Q names A and P back in the same way: P and Q. MAC (rule (b)): B's base MAC is
    learned on P (all_macs[(A, P)], a trunk under its own name), A learns B's base MAC on exactly one port (P; a trunk and its members
    count as one port) and B learns A's on exactly one port: P, unless P carries an LLDP claim like the above that the other switch
    does not make back. A claim only one side makes confirms nothing, not even the foreign port an LLDP entry names: otherwise a device
    on an access port would decide which port of another switch counts as confirmed. A base MAC learned on a second port confirms
    neither port (T6-RR1c): one of them is a device sending it."""
    claims = _lldp_claims(switches, switch_keys(switches))
    out = {end for here, there in claims if (there, here) in claims for end in (here, there)}
    # A device on an access port can send another switch's base MAC as its source in its own VLAN: the FDB is per VLAN, so that is a
    # second row and the switch's management is untouched. So base MACs confirm no port whose switch-LLDP claim is one-sided.
    one_sided = {here for here, _ in claims} - out
    base = {s["baseMac"]: s["id"] for s in switches if s["baseMac"]}
    trunk_of = {(s["id"], p["n"]): p["tr"] or p["n"] for s in switches for p in s["ports"]}
    seen: dict[tuple[int, int], set[str]] = defaultdict(set)    # (A, B) -> the ports (a trunk as one) on which A learns B's base MAC
    for (sid, pname), macs in all_macs.items():
        for mac in macs:
            if base.get(mac) not in (None, sid):
                seen[(sid, base[mac])].add(trunk_of.get((sid, pname), pname))

    def one_port_each(a: int, b: int) -> bool:
        return len(seen.get((a, b), ())) == 1 and len(seen.get((b, a), ())) == 1
    out |= {(sid, pname) for (sid, pname), macs in all_macs.items()
            if (sid, pname) not in one_sided and any(one_port_each(sid, base[mac]) for mac in macs if base.get(mac) not in (None, sid))}
    return out


def _links(switches: list[dict], all_macs: dict[tuple[int, str], set[str]]) -> list[dict]:
    """The links between the switches, by switch id (a name is not unique): per link the ids in "a" < "b", their names in "an" / "bn"
    for display; all_macs by (id, port). An LLDP entry of a port is [sysName, PortDesc (else PortId), PortId] (R40; a row from before
    the upgrade has only the first two). A sysName several switches carry (switch_keys; the factory sysName of one model, or two
    switches of one name) is tried at each of them that has the port it names, in id order. The neighbour's port is looked up by the
    PortDesc first, then by the PortId: with other vendors the PortDesc is often the long name or the description of the port, the
    PortId its ifName. A pair only the PortId finds, and every pair from a name more than one switch carries (the own one counted), is
    added after the base-MAC pairs and displaces none of them: it only adds links. Otherwise a shared name's pair to a switch that has
    the named port only by chance hid that switch's real link, one only base MACs see, and its real uplink lost its protection (R40).
    Of the other LLDP pairs only a confirmed one, which both sides report (A:P names B:Q and B:Q names A:P, as in _lldp_claims), and
    its ports (with their trunks) displace a base-MAC pair: the MAC pair of the same switch pair, or one on those ports. A pair only
    one side reports stays a link next to the MAC pair: otherwise one forged LLDP frame on an access port, naming a real port of the
    neighbour, hid a link only base MACs see, and the real uplink lost its protection (T6-F1c)."""
    by_id = {s["id"]: s for s in switches}
    sys2 = switch_keys(switches)
    base2 = {s["baseMac"]: s["id"] for s in switches if s["baseMac"]}
    claims = _lldp_claims(switches, sys2)

    def port(sid, n):
        return next((p for p in by_id[sid]["ports"] if p["n"] == n), None)

    pairs: dict[tuple, str] = {}
    late: dict[tuple, str] = {}    # pairs that only add links: found by the PortId, or from a name several switches carry
    confirmed: set[tuple] = set()  # the LLDP pairs in pairs that both sides report
    lldp_ports = set()             # their ports and trunks
    for s in switches:
        for p in s["ports"]:
            if p["n"].startswith("Trk"):
                continue
            for entry in p["l"]:
                nsys, nport = entry[0], entry[1]
                nids = sys2.get(nsys, set())
                for nid in sorted(nids - {s["id"]}):
                    np_ = port(nid, nport.strip())
                    if np_ and len(nids) == 1:
                        here, there = (s["id"], p["n"]), (nid, np_["n"])
                        key = tuple(sorted([here, there]))
                        pairs[key] = "lldp"
                        if (there, here) in claims:
                            confirmed.add(key)
                            for kk, pp in ((s["id"], p), (nid, np_)):
                                lldp_ports.add((kk, pp["n"]))
                                if pp["tr"]:
                                    lldp_ports.add((kk, pp["tr"]))
                    elif np_:
                        late[tuple(sorted([(s["id"], p["n"]), (nid, nport.strip())]))] = "lldp"
                    elif len(entry) > 2 and entry[2].strip() and port(nid, entry[2].strip()):
                        late[tuple(sorted([(s["id"], p["n"]), (nid, entry[2].strip())]))] = "lldp"
    # Ohne LLDP: Port, an dem die Basis-MAC eines anderen Switches gelernt wird, und umgekehrt
    seen_at: dict[tuple, str] = {}
    for (sid, pname), macset in all_macs.items():
        for mac in macset:
            other = base2.get(mac)
            if other is not None and other != sid:
                seen_at[(sid, other)] = pname
    for (a, b), pa in seen_at.items():
        pb = seen_at.get((b, a))
        if not pb or a > b:
            continue
        if (a, pa) in lldp_ports or (b, pb) in lldp_ports:
            continue
        if any({a, b} == {x[0][0], x[1][0]} for x in confirmed):
            continue
        pairs.setdefault(tuple(sorted([(a, pa), (b, pb)])), "mac")    # an unconfirmed LLDP pair on the very same ports keeps its label
    for key, src in late.items():
        pairs.setdefault(key, src)

    groups: dict[tuple, dict] = {}
    for (x, y), src in pairs.items():
        key = tuple(sorted([x[0], y[0]]))
        g = groups.setdefault(key, {"a": key[0], "b": key[1], "ap": [], "bp": [], "src": src})
        px, py = (x, y) if x[0] == key[0] else (y, x)
        g["ap"].append(px[1])
        g["bp"].append(py[1])
    out = []
    for g in groups.values():
        def side(sid, plist):
            ps = [port(sid, n) for n in plist if port(sid, n)]
            trk = sorted({p["tr"] for p in ps if p["tr"]})
            rep = port(sid, trk[0]) if trk else (ps[0] if ps else None)
            return {"ports": sorted(plist, key=_port_num), "trunk": trk[0] if trk else "",
                    "u": rep["u"] if rep else [], "t": rep["t"] if rep else [], "speed": rep["s"] if rep else 0}
        A, B = side(g["a"], g["ap"]), side(g["b"], g["bp"])
        va, vb = set(A["u"]) | set(A["t"]), set(B["u"]) | set(B["t"])
        out.append({"a": g["a"], "b": g["b"], "an": by_id[g["a"]]["k"], "bn": by_id[g["b"]]["k"], "A": A, "B": B, "src": g["src"],
                    "onlyA": sorted(va - vb, key=_vid_num), "onlyB": sorted(vb - va, key=_vid_num),
                    "native": sorted(set(A["u"]) ^ set(B["u"]), key=_vid_num)})
    return out
