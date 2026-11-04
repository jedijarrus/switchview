"""Phase 2: Ports aendern. Planen (Vorschau) und Ausfuehren mit Read-back.

Regeln aus docs/procurve-cli-referenz.md (3.3-3.13):
- untagged wechseln nur per 'vlan <neu> untagged <p>', nie entfernen+hinzufuegen
- VLANs nur auf TrkX, nie auf Trunk-Mitglieder; 802.1X/MAC nie auf Trunks
- Ablauf: running-config lesen, erneut planen (muss der Vorschau entsprechen), senden,
  zuruecklesen und pruefen, erst dann 'write memory'
- switchweite Befehle nur beim ausdruecklichen 'Vorbereiten' und nur hinzufuegend
"""
import asyncio
import hashlib
import ipaddress
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone

from netmiko.exceptions import ConfigInvalidException

import cfgparse
import poller
import snmpwrite
import sshcli
from crypto import decrypt
from db import audit, db, get_setting

log = logging.getLogger("switchview.changes")

# Port-Zustaende wie bei macmon: aus / protected (festes VLAN) / known (nur bekannte Geraete) / radius
STATUS = {
    "protected": {"x": False, "m": False},
    "known": {"x": False, "m": True},
    "radius": {"x": True, "m": True},
}
PORTNAME_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,64}$")
# Druckbares ASCII ohne Leerzeichen. Ausgeschlossen: ? (startet die CLI-Hilfe), ~ (J.15 kennt es nicht), Quotes, Backslash
RADIUS_KEY_RE = re.compile(r"""^(?!.*[?~"'\\])[!-~]{8,64}$""")
ERROR_PATTERN = r"(Invalid input|Incomplete input|Ambiguous input|Module not present|invalid port|cannot|Error|Unable|denied)"
ORDER = ["dot1x_off", "mac_off", "vlan_untagged", "vlan_tagged", "no_vlan_tagged", "name", "no_name", "enable", "disable",
         "dot1x_on", "dot1x_cl", "dot1x_uv", "dot1x_no_uv", "mac_on", "mac_al", "mac_uv", "mac_no_uv"]
TERMINAL = {"ok", "unclear", "failed", "aborted"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def limit_max(fw: str) -> int:
    fw = (fw or "").upper()
    return 2 if fw.startswith(("J.", "YA.15", "YB.15")) else 32


def status_of(st: dict) -> str:
    if not st.get("en", True):
        return "off"
    if st.get("x"):
        return "radius"
    if st.get("m"):
        return "known"
    return "protected"


# ── Inventar (aus der SNMP-Abfrage) ───────────────────────────────────────────
async def inventory(sid: int) -> dict:
    """Ports des Switches plus Uplinks (LLDP-Nachbar ist ein bekannter Switch oder MAC-Link)."""
    from main import build_map  # spaete Bindung, vermeidet Zyklus
    m = await build_map()
    sw = next((s for s in m["switches"] if s["id"] == sid), None)
    if not sw:
        raise LookupError("Switch nicht gefunden oder nicht aktiv")
    uplinks: set[str] = set()
    for l in m["links"]:
        for k, side in ((l["a"], l["A"]), (l["b"], l["B"])):
            if k == sw["k"]:
                uplinks |= set(side["ports"])
                if side["trunk"]:
                    uplinks.add(side["trunk"])
    for p in sw["ports"]:
        if p["tr"] and p["tr"] in uplinks:
            uplinks.add(p["n"])
    return {"sw": sw, "ports": {p["n"]: p for p in sw["ports"]}, "uplinks": uplinks}


# ── Planen ────────────────────────────────────────────────────────────────────
def _desired_from_set(cfg: dict, ports: list[str], s: dict) -> dict:
    out = {}
    for p in ports:
        cur = cfgparse.port_state(cfg, p)
        d: dict = {}
        if s.get("untagged"):
            d["u"] = str(s["untagged"])
        add, rem = [str(v) for v in s.get("tagged_add") or []], [str(v) for v in s.get("tagged_remove") or []]
        if add or rem:
            d["t"] = sorted((set(cur["t"]) | set(add)) - set(rem), key=int)
        if s.get("name") is not None:
            d["name"] = s["name"]
        status = s.get("status")
        if status == "off":
            d["en"] = False
        elif status in STATUS:
            d["en"] = True
            d.update(STATUS[status])
        x_new, m_new = d.get("x", cur["x"]), d.get("m", cur["m"])
        # Beim Einschalten immer ein Limit setzen: ohne client-limit arbeitet 802.1X port-basiert,
        # dann waere der Port nach einer Anmeldung fuer jedes weitere Geraet offen.
        lim = int(s["limit"]) if s.get("limit") else None
        if x_new and (lim or (d.get("x") and not cur["x"] and not cur["cl"])):
            d["cl"] = lim or cur["al"] or 1
        if m_new and (lim or (d.get("m") and not cur["m"] and not cur["al"])):
            d["al"] = lim or cur["cl"] or 1
        if s.get("guest") is not None and (x_new or m_new):
            g = str(s["guest"]) or None
            if x_new and not m_new:
                d["xuv"] = g
            if m_new:
                d["muv"] = g
        # Laufen 802.1X und MAC-Anmeldung zusammen, darf nur die MAC-Anmeldung ein unauth-vid haben
        # (J.15 meldet sonst: "Only Web or MAC-authenticator can have unauthenticated VLAN enabled ...")
        if x_new and m_new and cur["xuv"]:
            d["xuv"] = None
        out[p] = {k: v for k, v in d.items() if (sorted(cur[k], key=int) if k == "t" else cur[k]) != v}
    return out


def plan_ports(fw: str, inv: dict, cfg: dict, req: dict, *, mechanism: str = "ssh", driver=None, raw: dict | None = None) -> dict:
    """req: {ports:[..], set:{..}, expert:bool} oder {desired:{port:{feld:wert}}, expert:bool}

    mechanism ist der Schreibweg. "ssh" (Vorgabe): cfg aus der running-config, commands = shown = ProCurve-CLI-Zeilen (_commands).
    "snmp": cfg und raw aus demselben Live-Read (snmpwrite.read_cfg), driver der Treiber des Switches; ops (die Varbinds) und shown
    (je Port und Feld vorher -> nachher) kommen aus snmpwrite.render_ops, commands ist leer. _commands und cfgparse.compress_ports laufen
    dort nie: sie kennen nur ProCurve-Portnamen.

    Gesperrt wird auf beiden Wegen gleich (Uplink / Trunk nur im Expertenmodus, kein NAC auf Uplinks und Trunks, ein Trunk-Mitglied nur
    ueber seinen Trunk, VLANs muss es geben, ...). Trunk ist TrkN oder jeder Trunk / LAG in cfg["trunks"] (Po1, ae0, ...); Mitglied ist
    ein Port laut Inventar (Poll) oder laut cfg["trunks"], dem frischen Read. Per SNMP kommt fuer jeden Port, der diese Regeln besteht,
    snmpwrite.snmp_block_reason dazu (nicht verwaltbar, ohne Bridge-Port, ein Feld, das SNMP nicht schreiben kann, ...). Ein gesperrter
    Port steht mit Grund in blocked und faellt aus desired / before / commands / ops heraus, die anderen werden weiter geplant;
    ausgefuehrt wird nichts, solange blocked nicht leer ist (main.apply_change, run_change).

    before haelt die Werte der geplanten Felder vor der Aenderung (die Quelle eines Reverts: plan_ports mit desired = before), per SNMP
    dazu die PVID (R21, siehe _snmp_before). Ergebnis: commands, shown, desired, before, blocked, warnings, expert, mechanism; per SNMP
    dazu ops. ValueError fuer eine ungueltige Anfrage oder einen unbekannten mechanism (per SNMP auch aus render_ops, wenn raw in sich
    nicht stimmt: zwei Ports auf einem ifIndex, was read_cfg nie liefert), TypeError fuer "snmp" ohne driver oder raw."""
    if mechanism not in ("ssh", "snmp"):
        raise ValueError(f"Unbekannter Schreibweg: {mechanism!r}")
    over_snmp = mechanism == "snmp"
    if over_snmp and (driver is None or raw is None):
        raise TypeError("plan_ports: der SNMP-Weg braucht driver und raw (aus snmpwrite.read_cfg)")
    blocked, warnings = [], []
    expert = bool(req.get("expert"))
    vlans = cfg.get("vlans") or {}
    if req.get("desired") is not None:
        ports = list(req["desired"])
        desired = {}
        for p, d in req["desired"].items():
            cur = cfgparse.port_state(cfg, p)
            if over_snmp:
                desired[p] = {k: v for k, v in d.items() if _snmp_differs(raw, p, cur, k, v)}
            else:
                desired[p] = {k: v for k, v in d.items() if (sorted(cur[k], key=int) if k == "t" else cur[k]) != v}
    else:
        ports = [str(p) for p in req.get("ports") or []]
        s = req.get("set") or {}
        if s.get("name") and not PORTNAME_RE.fullmatch(s["name"]):
            raise ValueError("Beschreibung: 1–64 Zeichen, nur Buchstaben, Ziffern und . _ : @ - (keine Leerzeichen)")
        if s.get("status") not in (None, "off", *STATUS):
            raise ValueError("Unbekannter Port-Status")
        if s.get("limit") is not None and not (1 <= int(s["limit"]) <= limit_max(fw)):
            raise ValueError(f"Geräte pro Port: 1–{limit_max(fw)} auf dieser Firmware")
        desired = _desired_from_set(cfg, ports, s)
    if not ports:
        raise ValueError("Keine Ports gewählt")

    trunks = cfg.get("trunks") or {}
    member_of = {m: t for t, members in trunks.items() for m in members}  # frisch gelesen; das Inventar (Poll) kann aelter sein
    needs_radius = False
    for p in ports:
        ip = inv["ports"].get(p)
        d = desired.get(p, {})
        cur = cfgparse.port_state(cfg, p)
        if not ip:
            blocked.append({"port": p, "reason": "Port gibt es auf diesem Switch nicht"})
            continue
        is_trk = p.startswith("Trk") or p in trunks  # auch der LAG eines anderen Herstellers (Po1, ae0, Bridge-Aggregation1, ...)
        trk = ip["tr"] or member_of.get(p, "")
        if trk and not is_trk:
            blocked.append({"port": p, "reason": f"gehört zu {trk}, bitte {trk} wählen"})
            continue
        if not d:
            continue
        x_new, m_new = d.get("x", cur["x"]), d.get("m", cur["m"])
        if (d.get("x") or d.get("m")) and (is_trk or p in inv["uplinks"]):
            blocked.append({"port": p, "reason": "RADIUS/bekannte Geräte gehen nicht auf Uplinks und Trunks"})
            continue
        if (p in inv["uplinks"] or is_trk) and not expert:
            blocked.append({"port": p, "reason": "Uplink/Trunk: nur im Expertenmodus"})
            continue
        if is_trk and ("name" in d or "en" in d):
            blocked.append({"port": p, "reason": "Name und An/Aus nur an den Mitglied-Ports des Trunks"})
            continue
        if over_snmp:
            # Vor den VLAN-Pruefungen unten: ein nicht verwaltbarer Port (u None ist dort nur ein Platzhalter) oder einer ohne Bridge-Port
            # bekommt so seinen eigentlichen Grund, und ein NAC-Feld (per SNMP immer abgelehnt) kommt nie bis needs_radius: cfg aus SNMP
            # kennt die RADIUS-Einrichtung nicht, "nicht vorbereitet" waere dort immer falsch.
            reason = snmpwrite.snmp_block_reason(driver, cfg, raw, p, d)
            if reason:
                blocked.append({"port": p, "reason": reason})
                continue
        for vid in [d.get("u")] + [v for v in d.get("t", []) if v not in cur["t"]] + [d.get("xuv"), d.get("muv")]:
            if vid and vid not in vlans:
                blocked.append({"port": p, "reason": f"VLAN {vid} gibt es auf diesem Switch nicht"})
                break
        u_new, t_new = d.get("u", cur["u"]), d.get("t", cur["t"])
        if u_new and u_new in t_new:
            blocked.append({"port": p, "reason": f"VLAN {u_new} kann nicht ungetaggt und getaggt zugleich sein"})
        if not u_new and not t_new:
            blocked.append({"port": p, "reason": "Port wäre in keinem VLAN mehr"})
        if (d.get("x") or d.get("m")) or ((x_new or m_new) and ("cl" in d or "al" in d or "xuv" in d or "muv" in d)):
            needs_radius = True
        if (cur["x"] or cur["m"]) and ("u" in d or "t" in d):
            warnings.append(f"Port {p}: läuft gerade eine Anmeldung, greift das neue VLAN erst nach der Abmeldung")
        if (d.get("x") or d.get("m")) and t_new:
            warnings.append(f"Port {p}: hat getaggte VLANs ({', '.join(t_new)}). Bei MAC-Anmeldung können sie wegfallen")
        if (d.get("x") or d.get("m")) and ip["l"]:
            warnings.append(f"Port {p}: dort hängt {ip['l'][0][0]} (LLDP). Muss sich danach selbst anmelden können")
        if d.get("en") is False and ip["o"]:
            warnings.append(f"Port {p}: hat Link, das Gerät verliert die Verbindung")
        if d.get("u") == "1":
            warnings.append(f"Port {p}: VLAN 1 ist das Standard-VLAN")

    if needs_radius:
        miss = readiness_missing(cfg, None)
        if miss:
            blocked.append({"port": "*", "reason": "Switch ist nicht für RADIUS vorbereitet: " + ", ".join(miss)})

    skip = {b["port"] for b in blocked}
    desired = {p: d for p, d in desired.items() if d and p not in skip}
    if over_snmp:
        ops, shown = snmpwrite.render_ops(driver, cfg, raw, desired)
        return {"commands": [], "shown": shown, "ops": ops, "desired": desired,
                "before": {p: _snmp_before(driver, cfg, raw, p, d) for p, d in desired.items()}, "blocked": blocked,
                "warnings": list(dict.fromkeys(warnings)), "expert": expert, "mechanism": "snmp"}
    before = {p: {k: cfgparse.port_state(cfg, p)[k] for k in d} for p, d in desired.items()}
    cmds = _commands(cfg, desired)
    return {"commands": cmds, "shown": cmds, "desired": desired, "before": before, "blocked": blocked,
            "warnings": list(dict.fromkeys(warnings)), "expert": expert, "mechanism": "ssh"}


def _snmp_differs(raw: dict, p: str, cur: dict, k: str, v) -> bool:
    """Revert per SNMP (desired = before einer Aenderung): ist Feld k von Port p (cur = port_state) nicht schon v? Die PVID kennt cfg
    nicht, sie steht in raw (R21). Was der SNMP-Weg nicht lesen kann (alles ausser snmpwrite.FIELD_CAPS, etwa 802.1X / MAC-Anmeldung:
    cfg zeigt dafuer nur Vorgabewerte), zaehlt immer als Aenderung: so lehnt snmp_block_reason den Port ab, statt dass ein Revert still
    nur seinen VLAN-Teil zuruecknimmt."""
    if k not in snmpwrite.FIELD_CAPS:
        return True
    if k == "pvid":
        return raw["pvid"].get(p) != v
    return (sorted(cur[k], key=int) if k == "t" else cur[k]) != v


def _snmp_before(driver, cfg: dict, raw: dict, p: str, d: dict) -> dict:
    """before eines per SNMP geplanten Ports: die Felder aus d, wie dieser Read sie zeigt, und dazu die PVID aus raw (R21), wenn u oder
    pvid sich aendern, damit der Revert sie wiederherstellt (sonst bliebe nach u -> None die PVID des VLANs, das der Port gerade
    verlassen hat). Nur bei Q-BRIDGE fuer einen Port ohne vmVlan-Zeile und nur eine VLAN-ID 1..4094: cisco_vmps schreibt keine PVID
    (render_ops lehnte jeden Revert ab, der eine traegt), und eine fehlende oder kaputte (etwa "0") liesse sich nicht zurueckschreiben."""
    st = cfgparse.port_state(cfg, p)
    b = {k: st[k] for k in d if k != "pvid"}
    pvid = raw["pvid"].get(p)
    if ("u" in d or "pvid" in d) and driver.vlan_strategy == "qbridge" and p not in raw["vmvlan"] and snmpwrite.is_vlan_id(pvid):
        b["pvid"] = pvid
    return b


def _commands(cfg: dict, desired: dict) -> list[str]:
    atoms: dict[tuple, list[str]] = defaultdict(list)
    for p, d in desired.items():
        cur = cfgparse.port_state(cfg, p)
        x_new, m_new = d.get("x", cur["x"]), d.get("m", cur["m"])
        if d.get("x") is False:
            atoms[("dot1x_off",)].append(p)
        if d.get("m") is False:
            atoms[("mac_off",)].append(p)
        if "u" in d:
            atoms[("vlan_untagged", d["u"])].append(p)
        if "t" in d:
            for v in set(d["t"]) - set(cur["t"]):
                atoms[("vlan_tagged", v)].append(p)
            for v in set(cur["t"]) - set(d["t"]):
                atoms[("no_vlan_tagged", v)].append(p)
        if "name" in d:
            atoms[("name", d["name"]) if d["name"] else ("no_name",)].append(p)
        if "en" in d:
            atoms[("enable",) if d["en"] else ("disable",)].append(p)
        if d.get("x"):
            atoms[("dot1x_on",)].append(p)
        if x_new and d.get("cl"):
            atoms[("dot1x_cl", d["cl"])].append(p)
        if x_new and "xuv" in d:
            atoms[("dot1x_uv", d["xuv"]) if d["xuv"] else ("dot1x_no_uv",)].append(p)
        if d.get("m"):
            atoms[("mac_on",)].append(p)
        if m_new and d.get("al"):
            atoms[("mac_al", d["al"])].append(p)
        if m_new and "muv" in d:
            atoms[("mac_uv", d["muv"]) if d["muv"] else ("mac_no_uv",)].append(p)

    def render(atom, pl):
        k, v = atom[0], (atom[1] if len(atom) > 1 else None)
        return {
            "dot1x_off": f"no aaa port-access authenticator {pl}", "mac_off": f"no aaa port-access mac-based {pl}",
            "vlan_untagged": f"vlan {v} untagged {pl}", "vlan_tagged": f"vlan {v} tagged {pl}",
            "no_vlan_tagged": f"no vlan {v} tagged {pl}", "name": f"interface {pl} name {v}", "no_name": f"no interface {pl} name",
            "enable": f"interface {pl} enable", "disable": f"interface {pl} disable",
            "dot1x_on": f"aaa port-access authenticator {pl}", "dot1x_cl": f"aaa port-access authenticator {pl} client-limit {v}",
            "dot1x_uv": f"aaa port-access authenticator {pl} unauth-vid {v}", "dot1x_no_uv": f"no aaa port-access authenticator {pl} unauth-vid",
            "mac_on": f"aaa port-access mac-based {pl}", "mac_al": f"aaa port-access mac-based {pl} addr-limit {v}",
            "mac_uv": f"aaa port-access mac-based {pl} unauth-vid {v}", "mac_no_uv": f"no aaa port-access mac-based {pl} unauth-vid",
        }[k]

    out = []
    for atom in sorted(atoms, key=lambda a: (ORDER.index(a[0]), str(a[1:]))):
        ports = sorted(set(atoms[atom]), key=cfgparse.port_sort_key)
        chunk: list[str] = []
        for p in ports:  # Zeilen kurz halten (J.15: terminal width <= 150)
            if chunk and len(render(atom, cfgparse.compress_ports(chunk + [p]))) > 110:
                out.append(render(atom, cfgparse.compress_ports(chunk)))
                chunk = []
            chunk.append(p)
        if chunk:
            out.append(render(atom, cfgparse.compress_ports(chunk)))
    return out


def verify_ports(cfg_after: dict, desired: dict) -> list[str]:
    bad = []
    for p, d in desired.items():
        st = cfgparse.port_state(cfg_after, p)
        for k, v in d.items():
            # Limits/Gast-VLAN bleiben nach 'no aaa port-access ...' in der Konfiguration stehen, wirken dann aber nicht
            if (k in ("cl", "xuv") and not st["x"]) or (k in ("al", "muv") and not st["m"]):
                continue
            have = sorted(st[k], key=int) if k == "t" else st[k]
            want = sorted(v, key=int) if k == "t" else v
            if have != want:
                bad.append(f"Port {p}: {k} ist {have!r}, erwartet {want!r}")
    return bad


# ── RADIUS-Grundeinrichtung des Switches ──────────────────────────────────────
PARK_VLAN = "3999"  # Park-VLAN: ohne IP, ohne Routing, auf keinem Uplink


async def radius_settings() -> dict:
    return {"server": await get_setting("radius_server", "") or "", "key": decrypt(await get_setting("radius_key")) or ""}


def readiness(cfg: dict, server: str | None) -> dict:
    hosts = cfg.get("radius") or {}
    h = hosts.get(server) if server else next(iter(hosts.values()), None)
    return {"host": bool(h), "coa": bool(h and h.get("dyn")), "eap": bool(cfg.get("eap_radius")),
            "active": bool(cfg.get("auth_active")), "park": PARK_VLAN in (cfg.get("vlans") or {}),
            # CoA ohne Event-Timestamp (PacketFence schickt keins) nimmt der Switch nur mit time-window 0 an
            "tw": bool(h and h.get("time_window") == 0),
            "login_radius": bool(cfg.get("login_radius")), "others": [ip for ip in hosts if server and ip != server]}


def readiness_missing(cfg: dict, server: str | None) -> list[str]:
    r = readiness(cfg, server)
    names = {"host": "RADIUS-Server", "eap": "802.1X-Methode eap-radius", "active": "802.1X global aktiv"}
    return [names[k] for k in names if not r[k]]


def plan_prepare(cfg: dict, rs: dict) -> dict:
    server, key = rs["server"], rs["key"]
    blocked, warnings, cmds, shown = [], [], [], []
    try:
        ipaddress.ip_address(server)
    except ValueError:
        blocked.append({"port": "*", "reason": "RADIUS-Server (PacketFence-IP) fehlt in den Einstellungen"})
        return {"commands": [], "shown": [], "blocked": blocked, "warnings": [], "expected": {}}
    r = readiness(cfg, server)
    if not r["host"]:
        if not key or not RADIUS_KEY_RE.fullmatch(key):
            blocked.append({"port": "*", "reason": "Shared Secret fehlt oder enthält unzulässige Zeichen (8–64 Zeichen, ohne Leerzeichen, Anführungszeichen, Backslash, ? und ~)"})
        else:
            cmds.append(f"radius-server host {server} key {key}")
            shown.append(f"radius-server host {server} key ***")
    if not r["coa"]:
        cmds.append(f"radius-server host {server} dyn-authorization")
        shown.append(cmds[-1])
    if not r["tw"]:
        cmds.append(f"radius-server host {server} time-window 0")
        shown.append(cmds[-1])
    if not r["eap"]:
        cmds.append("aaa authentication port-access eap-radius")
        shown.append(cmds[-1])
    if not r["active"]:
        cmds.append("aaa port-access authenticator active")
        shown.append(cmds[-1])
    if not r["park"]:
        cmds.append(f'vlan {PARK_VLAN} name "Park"')
        shown.append(cmds[-1])
    if r["login_radius"]:
        warnings.append("Die Anmeldung am Switch selbst nutzt RADIUS. Ein weiterer Server kann sich darauf auswirken.")
    if r["others"]:
        warnings.append("Weitere RADIUS-Server sind eingetragen: " + ", ".join(r["others"]))
    warnings.append("Wirkt switchweit, ändert aber noch keinen Port. Ports bleiben „Protected“, bis du sie umstellst.")
    return {"commands": cmds, "shown": shown, "blocked": blocked, "warnings": warnings,
            "expected": {"host": True, "coa": True, "tw": True, "eap": True, "active": True, "park": True}}


# ── Konfiguration lesen (Cache) ───────────────────────────────────────────────
async def store_cfg(sid: int, content: str) -> dict:
    parsed = cfgparse.parse_config(content)
    async with db() as conn:
        await conn.execute("INSERT INTO switch_cfg(switch_id, taken_at, parsed) VALUES (?,?,?) ON CONFLICT(switch_id) DO UPDATE "
                           "SET taken_at = excluded.taken_at, parsed = excluded.parsed", (sid, _now(), json.dumps(parsed)))
        await conn.commit()
    return parsed


async def cached_cfg(sid: int) -> tuple[dict | None, str | None]:
    async with db() as conn:
        async with conn.execute("SELECT taken_at, parsed FROM switch_cfg WHERE switch_id = ?", (sid,)) as cur:
            row = await cur.fetchone()
    return (json.loads(row["parsed"]), row["taken_at"]) if row else (None, None)


async def fresh_cfg(sid: int, max_age_s: int = 600) -> dict:
    cfg, at = await cached_cfg(sid)
    if cfg and at and (datetime.now(timezone.utc) - datetime.strptime(at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)).total_seconds() < max_age_s:
        return cfg
    res = await sshcli.backup_config(sid, "lesen")
    if not res.get("ok"):
        raise RuntimeError(res.get("error") or "Konfiguration konnte nicht gelesen werden")
    cfg, _ = await cached_cfg(sid)
    return cfg


# ── Ausfuehren ────────────────────────────────────────────────────────────────
def cmd_token(cmds: list[str]) -> str:
    return hashlib.sha256("\n".join(cmds).encode()).hexdigest()[:16]


async def _upd(cid: int, **f):
    sets = ", ".join(f"{k} = ?" for k in f)
    async with db() as conn:
        await conn.execute(f"UPDATE changes SET {sets} WHERE id = ?", (*f.values(), cid))
        await conn.commit()


async def _step(cid: int, steps: list, text: str, level: str = "info"):
    steps.append([_now(), text, level])
    await _upd(cid, steps=json.dumps(steps))


async def create_change(sid: int, user: str, kind: str, summary: str, req: dict, plan: dict, revert_of: int | None = None) -> int:
    async with db() as conn:
        cur = await conn.execute(
            "INSERT INTO changes(switch_id, username, kind, summary, request, ports, desired, before, commands, status, steps, expert, revert_of) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, user, kind, summary, json.dumps(req), json.dumps(sorted(plan.get("desired", {}), key=cfgparse.port_sort_key)),
             json.dumps(plan.get("desired", {})), json.dumps(plan.get("before", {})), json.dumps(plan["shown"]), "queued", "[]",
             int(bool(plan.get("expert"))), revert_of))
        await conn.commit()
        return cur.lastrowid


async def run_change(cid: int):
    """Hintergrund-Task. Status: queued -> running -> ok | unclear | failed | aborted."""
    async with db() as conn:
        async with conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)) as cur:
            ch = await cur.fetchone()
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (ch["switch_id"],)) as cur:
            row = await cur.fetchone()
    sid, kind = ch["switch_id"], ch["kind"]
    req, previewed = json.loads(ch["request"] or "{}"), json.loads(ch["commands"] or "[]")
    steps: list = []
    rs = await radius_settings()
    secrets = [rs["key"]] if rs["key"] else []
    pre = post = None
    status, error, saved, output = "failed", None, 0, ""
    try:
        inv = await inventory(sid) if kind == "ports" else None
        lock = sshcli.lock(sid)
        if lock.locked():
            await _step(cid, steps, "Warte auf laufende Aktion an diesem Switch")
        async with lock:
            await _upd(cid, status="running")
            await _step(cid, steps, f"Verbinde mit {row['host']}")
            conn = await asyncio.to_thread(sshcli.connect, row)
            try:
                pre = sshcli.clean(await asyncio.to_thread(conn.send_command, "show running-config", read_timeout=90))
                cfg = cfgparse.parse_config(pre)
                await _step(cid, steps, "Konfiguration vorher gelesen")
                if kind == "save":
                    plan = {"commands": [], "shown": [], "blocked": []}
                elif kind == "prepare":
                    plan = plan_prepare(cfg, rs)
                else:
                    plan = plan_ports(row["firmware"] or "", inv, cfg, req)
                if plan["blocked"]:
                    status, error = "aborted", "; ".join(f"{b['port']}: {b['reason']}" for b in plan["blocked"])
                    await _step(cid, steps, "Abgebrochen: " + error, "error")
                    return
                if plan["shown"] != previewed:
                    status, error = "aborted", "Der Switch hat sich seit der Vorschau geändert. Bitte Vorschau neu laden."
                    await _step(cid, steps, error, "error")
                    return
                if kind == "ports":
                    await _upd(cid, before=json.dumps(plan["before"]))
                if plan["commands"]:
                    await _step(cid, steps, f"Sende {len(plan['commands'])} Befehle")
                    try:
                        output = await asyncio.to_thread(conn.send_config_set, plan["commands"], read_timeout=30,
                                                         error_pattern=ERROR_PATTERN, cmd_verify=True)
                    except ConfigInvalidException as e:
                        output = str(e)
                        post = sshcli.clean(await asyncio.to_thread(conn.send_command, "show running-config", read_timeout=90))
                        status, error = "failed", "Der Switch hat einen Befehl abgelehnt. Nichts gespeichert, Teile können schon wirken."
                        await _step(cid, steps, error, "error")
                        return
                    post = sshcli.clean(await asyncio.to_thread(conn.send_command, "show running-config", read_timeout=90))
                    after = cfgparse.parse_config(post)
                    await _step(cid, steps, "Konfiguration nachher gelesen")
                    if kind == "prepare":
                        r = readiness(after, rs["server"])
                        bad = [k for k in ("host", "coa", "tw", "eap", "active", "park") if not r[k]]
                    else:
                        bad = verify_ports(after, plan["desired"])
                    if bad:
                        status, error = "unclear", "Prüfung nach der Änderung passt nicht: " + "; ".join(bad[:8])
                        await _step(cid, steps, error + ". Nicht gespeichert.", "error")
                        return
                    await _step(cid, steps, "Prüfung ok")
                await _step(cid, steps, "Speichere (write memory)")
                await asyncio.to_thread(conn.save_config)
                saved, status = 1, "ok"
                await _step(cid, steps, "Gespeichert", "ok")
            finally:
                await asyncio.to_thread(sshcli.disconnect, conn)
    except Exception as e:  # noqa: BLE001
        log.exception("Änderung %s", cid)
        status, error = ("unclear" if post or output else "failed"), f"{type(e).__name__}: {str(e)[:300]}"
        await _step(cid, steps, error, "error")
    finally:
        await _upd(cid, status=status, error=error, saved=saved, finished_at=_now(),
                   output=cfgparse.mask_secrets(output or "", secrets))
        if pre:
            await sshcli.store_backup(sid, pre, f"vor #{cid}")
        if post:
            await sshcli.store_backup(sid, post, f"nach #{cid}")
            await store_cfg(sid, post)
        elif pre:
            await store_cfg(sid, pre)
        if kind == "save" and status == "ok" and req.get("of"):
            await _upd(int(req["of"]), saved=1)
        await audit(ch["username"], "change_" + status, str(sid), f"#{cid} {ch['summary']}")
        if status in ("ok", "unclear", "failed") and kind != "save":
            asyncio.create_task(_repoll(sid))


async def _repoll(sid: int):
    await asyncio.sleep(3)
    try:
        await poller.poll_switch(sid)
    except Exception:  # noqa: BLE001
        log.exception("Nach-Abfrage %s", sid)
