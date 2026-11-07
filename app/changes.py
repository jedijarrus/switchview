"""Phase 2: Ports aendern. Planen (Vorschau) und Ausfuehren mit Read-back.

Regeln aus docs/procurve-cli-referenz.md (3.3-3.13):
- untagged wechseln nur per 'vlan <neu> untagged <p>', nie entfernen+hinzufuegen
- VLANs nur auf TrkX, nie auf Trunk-Mitglieder; 802.1X/MAC nie auf Trunks
- Ablauf: running-config lesen, erneut planen (muss der Vorschau entsprechen), senden,
  zuruecklesen und pruefen, erst dann 'write memory'
- switchweite Befehle nur beim ausdruecklichen 'Vorbereiten' und nur hinzufuegend
Per SNMP (changes.mechanism "snmp", Spec §6) derselbe Ablauf: live lesen (snmpwrite.read_cfg), erneut planen, ein SET
(snmpwrite.apply_ops), zuruecklesen und pruefen (verify_snmp); dauerhaft speichert dort nur ein Treiber mit snmp_autosave (R26).
"""
import asyncio
import hashlib
import json
import logging
import re
import traceback
from collections import defaultdict
from datetime import datetime, timezone

from netmiko.exceptions import ConfigInvalidException

import cfgparse
import drivers
import poller
import snmp
import snmpwrite
import sshcli
from changeverify import _poe_entry_moved, verify_ports, verify_snmp
from db import audit, db
from radiusprep import PARK_VLAN, RADIUS_KEY_RE, _SWITCH_SECRETS, _secrets_of, plan_prepare, radius_settings, readiness, readiness_missing

# The names that moved out of changes into radiusprep and changeverify (Phase 3, Task 11): changes re-exports them, so every changes.X
# stays valid, and calls them by these names (ruff takes a name listed here as used, F401)
__all__ = ["PARK_VLAN", "RADIUS_KEY_RE", "_SWITCH_SECRETS", "_secrets_of", "plan_prepare", "radius_settings", "readiness",
           "readiness_missing", "_poe_entry_moved", "verify_ports", "verify_snmp"]

log = logging.getLogger("switchview.changes")

# Port-Zustaende wie bei macmon: aus / protected (festes VLAN) / known (nur bekannte Geraete) / radius. Dazu "on" (R43): nur einschalten,
# 802.1X / MAC-Anmeldung bleiben, wie sie sind (per SNMP geht nur das, per SSH ist es die enable-Zeile wie bei jedem anderen Zustand).
STATUS = {
    "protected": {"x": False, "m": False},
    "known": {"x": False, "m": True},
    "radius": {"x": True, "m": True},
}
STATUS_ON = "on"
PORTNAME_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,64}$")
ERROR_PATTERN = r"(Invalid input|Incomplete input|Ambiguous input|Module not present|invalid port|cannot|Error|Unable|denied)"
# no_vlan_untagged (u -> None, a revert) after every tagged line: the port must stay in some VLAN (docs/procurve-cli-referenz.md 3.3)
ORDER = ["dot1x_off", "mac_off", "vlan_untagged", "vlan_tagged", "no_vlan_tagged", "no_vlan_untagged", "name", "no_name", "enable",
         "disable", "dot1x_on", "dot1x_cl", "dot1x_uv", "dot1x_no_uv", "mac_on", "mac_al", "mac_uv", "mac_no_uv"]
# The fields a trunk member takes on its own, over SSH and SNMP (snmpwrite.snmp_block_reason): its name and on / off. Its VLANs are the
# trunk's, NAC never goes on a trunk, PoE on members stays refused (R36).
MEMBER_FIELDS = snmpwrite.MEMBER_FIELDS
TERMINAL = {"ok", "unclear", "failed", "aborted"}
# R26: ohne snmp_autosave steht ein SNMP-Set nur in der laufenden Konfiguration des Switches
SNMP_UNSAVED = "Änderung ist aktiv, aber NICHT dauerhaft gespeichert – am Switch speichern (z. B. write memory / copy running-config startup-config)"
# Hinter jedem Schritt, mit dem ein SNMP-Lauf nach dem SET unklar endet, je nach snmp_autosave des Treibers
SNMP_KEPT = {True: "Was der Switch davon übernommen hat, wirkt schon und ist gespeichert (er speichert SNMP-Änderungen selbst).",
             False: "Was der Switch davon übernommen hat, wirkt schon, ist aber nicht dauerhaft gespeichert."}
# Behind each step with which an SSH run ends unclear, by what was going out: lines (send_config_set, and a read-back that does not
# match) or write memory. The progress dialog shows that step, as over SNMP (sv-switch.js resultHead).
SSH_KEPT = {"lines": SNMP_KEPT[False], "save": "Ob der Switch gespeichert hat (write memory), ist offen."}
# The error of a run whose task was cancelled (the app shut down): unclear once something went out; before that the run ends aborted
# with CANCELLED_UNSENT, the label a restart gives such a change too (mark_interrupted)
CANCELLED = "Abgebrochen (Prozess beendet)"
CANCELLED_UNSENT = f"{CANCELLED}, nichts gesendet"
# The error of a change whose switch was disabled while it waited for the lock (run_change, _run_snmp)
DISABLED_RUN = "Switch ist deaktiviert: nichts gesendet"


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
    """The switch's ports plus its uplinks: the ports of its links (LLDP or MAC link, main._links), each with its trunk (the trunk of
    every port of a link side, not only the one trunk the side names: a side whose ports sit in two trunks keeps both). For every
    driver (Phase 1 had this backstop only where poller.by_iftype, not for ProCurve, R48) also, even without a link found, every port
    whose LLDP neighbour is another managed switch (the mapping of _links, main.switch_keys; R40: a neighbour can name a port _links
    does not find, and without uplink protection anyone could switch off the only uplink) and every port on which the base MAC of
    another managed switch is learned (build_map's "bm"; T6-RR1c: _links makes one link per switch pair, from one sighting, so a
    device sending that base MAC on an access port could move the link off the real uplink), each with its trunk. Then the members of
    every uplink trunk. Rather too many uplinks than one too few. All by the switch's id (a name is not unique): its links carry it in
    "a" / "b", and an LLDP name it shares with another switch names that one too."""
    from topology import build_map, switch_keys  # spaete Bindung, vermeidet Zyklus
    m = await build_map()
    sw = next((s for s in m["switches"] if s["id"] == sid), None)
    if not sw:
        raise LookupError("Switch nicht gefunden oder nicht aktiv")
    trunk_of = {p["n"]: p["tr"] for p in sw["ports"]}
    uplinks: set[str] = set()
    for link in m["links"]:
        for end, side in ((link["a"], link["A"]), (link["b"], link["B"])):
            if end == sid:
                uplinks |= set(side["ports"]) | {trunk_of[n] for n in side["ports"] if trunk_of.get(n)}
                if side["trunk"]:
                    uplinks.add(side["trunk"])
    keys = switch_keys(m["switches"])
    for p in sw["ports"]:
        if p["bm"] or any(keys.get(entry[0], set()) - {sid} for entry in p["l"]):
            uplinks.add(p["n"])
            if p["tr"]:
                uplinks.add(p["tr"])
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
        if s.get("poe") is not None:  # PoE an / aus; nur per SNMP (R30), der SSH-Weg lehnt den Port ab (plan_ports)
            d["poe"] = s["poe"]
        status = s.get("status")
        if status == "off":
            d["en"] = False
        elif status == STATUS_ON:
            d["en"] = True
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
        # (J.15 meldet sonst: "Only Web or MAC-authenticator can have unauthenticated VLAN enabled ...").
        # Only for a request that touches NAC (R48): the switch has taken the state as it is, and "on", a VLAN or a name change must
        # not take an authentication line off the port.
        touches_nac = status in STATUS or s.get("limit") or s.get("guest") is not None
        if touches_nac and x_new and m_new and cur["xuv"]:
            d["xuv"] = None
        # cur.get: eine running-config kennt kein PoE (port_state hat dann kein "poe"), ein PoE-Feld bleibt dort also stehen
        out[p] = {k: v for k, v in d.items() if (sorted(cur[k], key=int) if k == "t" else cur.get(k)) != v}
    return out


def plan_ports(fw: str, inv: dict, cfg: dict, req: dict, *, mechanism: str = "ssh", driver=None, raw: dict | None = None,
               radius_server: str | None = None) -> dict:
    """req: {ports:[..], set:{..}, expert:bool} oder {desired:{port:{feld:wert}}, expert:bool}

    mechanism ist der Schreibweg. "ssh" (Vorgabe): cfg aus der running-config, commands = shown = ProCurve-CLI-Zeilen (_commands).
    "snmp": cfg und raw aus demselben Live-Read (snmpwrite.read_cfg), driver der Treiber des Switches; ops (die Varbinds) und shown
    (je Port und Feld vorher -> nachher) kommen aus snmpwrite.render_ops, commands ist leer. _commands und cfgparse.compress_ports laufen
    dort nie: sie kennen nur ProCurve-Portnamen.

    Gesperrt wird auf beiden Wegen gleich (Uplink / Trunk nur im Expertenmodus, kein NAC auf Uplinks und Trunks, ein Trunk-Mitglied nur
    ueber seinen Trunk, VLANs muss es geben, ...). Trunk ist TrkN oder jeder Trunk / LAG in cfg["trunks"] (Po1, ae0, ...); Mitglied ist
    ein Port laut Inventar (Poll) oder laut cfg["trunks"], dem frischen Read. A member takes MEMBER_FIELDS (name, on / off) on its own,
    under the uplink / expert rule of every port (a member of an uplink trunk is an uplink, whether the poll or the fresh read puts it
    there; inventory lists only the poll's); with any other field it is blocked ("gehört zu <trunk>"). Its VLANs are the trunk's, so
    "Port wäre in keinem VLAN mehr" is not checked for it (over SSH port_state shows a member in no VLAN line at all). Per SSH dazu
    jeder Port mit PoE (R30: PoE nur per SNMP; _commands kennt das Feld nicht und liesse es still weg). Over SSH also a port whose name
    in desired (a revert) does not fit PORTNAME_RE: it would land in a CLI line (E28). Per SNMP kommt fuer jeden Port, der diese Regeln
    besteht, snmpwrite.snmp_block_reason dazu (nicht verwaltbar, ohne Bridge-Port, ein Feld, das SNMP nicht schreiben kann, ...).
    Ein gesperrter Port steht mit Grund in blocked und faellt aus desired / before / commands / ops heraus, die anderen werden weiter
    geplant; ausgefuehrt wird nichts, solange blocked nicht leer ist (api_changes.apply_change, run_change).

    before haelt die Werte der geplanten Felder vor der Aenderung (die Quelle eines Reverts: plan_ports mit desired = before), per SNMP
    dazu die PVID (R21, siehe _snmp_before). Ergebnis: commands, shown, desired, before, blocked, warnings, expert, mechanism; per SNMP
    dazu ops. ValueError fuer eine ungueltige Anfrage oder einen unbekannten mechanism (per SNMP auch aus render_ops, wenn raw in sich
    nicht stimmt: zwei Ports auf einem ifIndex, was read_cfg nie liefert), TypeError fuer "snmp" ohne driver oder raw.

    radius_server: the RADIUS server of the settings (radius_settings()["server"]). A NAC change then needs exactly that server on the
    switch; without one ("" or None) any radius-server host line will do, as before."""
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
            else:  # PoE kennt eine running-config nicht: es bleibt stehen, unten wird der Port abgelehnt
                desired[p] = {k: v for k, v in d.items() if k == "poe" or (sorted(cur[k], key=int) if k == "t" else cur[k]) != v}
    else:
        ports = [str(p) for p in req.get("ports") or []]
        s = req.get("set") or {}
        if s.get("name") and not PORTNAME_RE.fullmatch(s["name"]):
            raise ValueError("Beschreibung: 1–64 Zeichen, nur Buchstaben, Ziffern und . _ : @ - (keine Leerzeichen)")
        if s.get("status") not in (None, "off", STATUS_ON, *STATUS):
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
        member = bool(trk) and not is_trk
        if member and not set(d) <= MEMBER_FIELDS:    # a member without fields is not blocked: nothing is planned for it
            blocked.append({"port": p, "reason": f"gehört zu {trk}, bitte {trk} wählen"})
            continue
        if not d:
            continue
        if not over_snmp and "poe" in d:
            blocked.append({"port": p, "reason": "PoE geht nur per SNMP, nicht über die SSH-CLI"})
            continue
        # §6 Revert-Portname (E28): a name from desired (a revert writes back what a running-config said) lands in a CLI line; per SSH
        # only one that PORTNAME_RE allows, like a name set by hand (the set branch above refuses the others outright)
        if not over_snmp and d.get("name") and not (isinstance(d["name"], str) and PORTNAME_RE.fullmatch(d["name"])):
            blocked.append({"port": p, "reason": f"Name „{d['name']}“ lässt sich per SSH nicht sicher zurückschreiben "
                                                 "(erlaubt: Buchstaben, Ziffern und . _ : @ -)"})
            continue
        x_new, m_new = d.get("x", cur["x"]), d.get("m", cur["m"])
        # A member of an uplink trunk is an uplink, by the poll's trunk or the fresh read's (R40): inventory lists it only when the poll
        # knows it as a member of that trunk. A trunk formed since the poll: inventory may list only a sibling (the uplink port itself),
        # not the trunk, so a sibling in the fresh read's trunk counts as well
        fresh_trk = member_of.get(p)
        uplink = p in inv["uplinks"] or (member and bool({ip["tr"], fresh_trk, *trunks.get(fresh_trk, ())} & inv["uplinks"]))
        if (d.get("x") or d.get("m")) and (is_trk or uplink):
            blocked.append({"port": p, "reason": "RADIUS/bekannte Geräte gehen nicht auf Uplinks und Trunks"})
            continue
        if (uplink or is_trk) and not expert:
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
        # Per SNMP nur, wenn sich VLANs aendern (L17): An / Aus, Name und PoE lassen sie, wie sie sind, und bei einem nicht verwaltbaren
        # Port (snmp_block_reason laesst ihn dafuer zu) ist das leere u nur ein Platzhalter. Per SSH wie bisher immer, except for a trunk
        # member (only MEMBER_FIELDS get here): its VLANs are the trunk's, and over SSH it stands in no VLAN line (u None, t []).
        if not u_new and not t_new and not member and (not over_snmp or snmpwrite.VLAN_FIELDS & set(d)):
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
        if d.get("poe") is False and over_snmp and raw["poe"].get(p, {}).get("status") == snmpwrite.POE_DELIVERING:
            warnings.append(f"Port {p}: versorgt gerade ein Gerät mit Strom (PoE), es verliert die Stromversorgung")
        if d.get("u") == "1":
            warnings.append(f"Port {p}: VLAN 1 ist das Standard-VLAN")

    if needs_radius:
        miss = readiness_missing(cfg, radius_server or None)
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


def touches_poe(req: dict) -> bool:
    """Beruehrt die Port-Aenderung `req` (die Anfrage, die create_change speichert) PoE (R34)? Ja, wenn ihr set ein poe hat
    (vorwaerts) oder ihr desired (ein Revert: before einer Aenderung) bei einem Port das Feld poe. Nur dann liest snmpwrite.read_cfg
    die PoE-Tabellen. Die eine Stelle dafuer: die Vorschau (main) und beide Reads von run_change rechnen es aus derselben Anfrage."""
    if (req.get("set") or {}).get("poe") is not None:
        return True
    return any(isinstance(d, dict) and "poe" in d for d in (req.get("desired") or {}).values())


def _snmp_differs(raw: dict, p: str, cur: dict, k: str, v) -> bool:
    """Revert per SNMP (desired = before einer Aenderung): ist Feld k von Port p (cur = port_state) nicht schon v? Die PVID kennt cfg
    nicht, sie steht in raw (R21). Was der SNMP-Weg nicht lesen kann (alles ausser snmpwrite.FIELD_CAPS, etwa 802.1X / MAC-Anmeldung:
    cfg zeigt dafuer nur Vorgabewerte), zaehlt immer als Aenderung: so lehnt snmp_block_reason den Port ab, statt dass ein Revert still
    nur seinen VLAN-Teil zuruecknimmt."""
    if k not in snmpwrite.FIELD_CAPS:
        return True
    if k == "pvid":
        return raw["pvid"].get(p) != v
    return (sorted(cur[k], key=int) if k == "t" else cur.get(k)) != v    # cur.get: poe fehlt bei einem Port, den der Read nicht kennt


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
        # One VID switching between untagged and tagged takes one line: 'vlan <v> untagged|tagged <p>' changes the membership type, the
        # no-form after it would set the port to "No" in that VLAN (docs/procurve-cli-referenz.md 3.4)
        if "u" in d and d["u"] is not None:
            atoms[("vlan_untagged", d["u"])].append(p)
        elif "u" in d and cur["u"] is not None and cur["u"] not in d.get("t", ()):
            atoms[("no_vlan_untagged", cur["u"])].append(p)    # u -> None (a revert): leave the old untagged VLAN, after the tagged lines
        if "t" in d:
            for v in set(d["t"]) - set(cur["t"]):
                atoms[("vlan_tagged", v)].append(p)
            for v in set(cur["t"]) - set(d["t"]):
                if v != d.get("u"):
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
            "no_vlan_tagged": f"no vlan {v} tagged {pl}", "no_vlan_untagged": f"no vlan {v} untagged {pl}",
            "name": f"interface {pl} name {v}", "no_name": f"no interface {pl} name",
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


# ── Konfiguration lesen (Cache) ───────────────────────────────────────────────
# R27: Switches, deren zwischengespeicherter SSH-Read (switch_cfg) nicht mehr zaehlt: per SSH war die Konfiguration zuletzt nicht zu
# lesen (run_change kam nicht bis zur running-config, fresh_cfg las vergeblich), oder ein SNMP-SET hat den Switch seither geaendert, or
# run_change sent lines (it reads back and stores the result; without a read-back, after an exception mid-send, the mark stays).
# fresh_cfg liest fuer sie wirklich, statt bis zu max_age_s lang aus dem Cache: so merkt die Vorschau, dass SSH weg ist, und kann auf
# SNMP ausweichen, statt eine SSH-Aenderung zu planen, die beim Ausfuehren scheitert. Die Zeile in switch_cfg bleibt (die Karte zeigt
# daraus NAC-Zustand und RADIUS-Bereitschaft); ein erfolgreicher Read (store_cfg) hebt die Marke auf. Im Prozess gehalten wie die Locks
# (Single-Worker); nach einem Neustart kostet das hoechstens einen vergeblichen SSH-Versuch. What changed the switch must outlast a
# restart (else an SSH preview would show the state from before it): the column switch_cfg.stale (mark_cfg_stale), set before an SNMP
# SET and before SSH lines go out, cleared by the next read (store_cfg). fresh_cfg treats a stale entry as expired; taken_at stays the
# time of the read, which the RADIUS card shows, marked "veraltet", and the map takes a port's on / off from the poll meanwhile.
_cfg_stale: set[int] = set()
CFG_MAX_AGE_S = 600    # so lange nimmt fresh_cfg einen SSH-Read aus switch_cfg


def invalidate_cfg(sid: int):
    """Den zwischengespeicherten SSH-Read von Switch sid verwerfen (R27): der naechste fresh_cfg liest wirklich."""
    _cfg_stale.add(sid)


async def mark_cfg_stale(sid: int):
    """Mark the SSH read of switch sid stale in the database (switch_cfg.stale = 1): the switch may have changed since (an SNMP SET, or
    SSH lines going out). Like invalidate_cfg, but it outlasts a restart; parsed and taken_at stay (M3). store_cfg clears it."""
    async with db() as conn:
        await conn.execute("UPDATE switch_cfg SET stale = 1 WHERE switch_id = ?", (sid,))
        await conn.commit()


async def store_cfg(sid: int, content: str) -> dict:
    parsed = cfgparse.parse_config(content)
    async with db() as conn:
        await conn.execute("INSERT INTO switch_cfg(switch_id, taken_at, parsed, stale) VALUES (?,?,?,0) ON CONFLICT(switch_id) DO UPDATE "
                           "SET taken_at = excluded.taken_at, parsed = excluded.parsed, stale = 0", (sid, _now(), json.dumps(parsed)))
        await conn.commit()
    _cfg_stale.discard(sid)
    return parsed


async def cached_cfg(sid: int) -> tuple[dict | None, str | None, bool]:
    """The stored SSH read of switch sid: (parsed, taken_at, stale); (None, None, False) without one."""
    async with db() as conn:
        async with conn.execute("SELECT taken_at, parsed, stale FROM switch_cfg WHERE switch_id = ?", (sid,)) as cur:
            row = await cur.fetchone()
    return (json.loads(row["parsed"]), row["taken_at"], bool(row["stale"])) if row else (None, None, False)


class HostKeyRefused(RuntimeError):
    """fresh_cfg's SSH read was refused because the switch offered another host key than the pinned one (sshcli.HostKeyMismatch,
    backup_config's "host_key"): whoever answers at the address may be an attacker. api_changes._choose_mechanism lets SNMP take over then
    only with an SNMPv3 authPriv write identity. The message is backup_config's error."""


async def fresh_cfg(sid: int, max_age_s: int = CFG_MAX_AGE_S) -> dict:
    """Die geparste running-config: aus switch_cfg, wenn sie juenger als max_age_s ist und weder verworfen (R27, invalidate_cfg) noch
    veraltet (stale, mark_cfg_stale), sonst per SSH neu gelesen. RuntimeError, wenn das Lesen scheitert; dann ist der Cache verworfen.
    If the read was refused for the switch's host key, the error is HostKeyRefused (a RuntimeError) with the same message.
    RuntimeError ohne Read und ohne Cache fuer einen Switch, dessen Treiber keine SSH-CLI hat (R39): ein Eintrag in switch_cfg waere
    dort eine Fehldeutung oder von vor einem Treiberwechsel. Die Aufrufer fragen das schon vorher; diese Sperre gilt unabhaengig davon."""
    row = await _switch_row(sid)
    reason = sshcli.cli_refusal(row) if row is not None else "Switch nicht gefunden"
    if reason:
        raise RuntimeError(reason)
    cfg, at, stale = (None, None, False) if sid in _cfg_stale else await cached_cfg(sid)
    taken = datetime.strptime(at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) if at else None
    if cfg and taken and not stale and (datetime.now(timezone.utc) - taken).total_seconds() < max_age_s:
        return cfg
    res = await sshcli.backup_config(sid, "lesen")
    if not res.get("ok"):
        invalidate_cfg(sid)
        raise (HostKeyRefused if res.get("host_key") else RuntimeError)(res.get("error") or "Konfiguration konnte nicht gelesen werden")
    cfg, _, _ = await cached_cfg(sid)
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


BUSY = "An diesem Switch läuft gerade eine Änderung"


class Busy(RuntimeError):
    """create_change: the switch already has a change that is queued or running (BUSY)."""


async def create_change(sid: int, user: str, kind: str, summary: str, req: dict, plan: dict, revert_of: int | None = None, *,
                        role: str | None = None, approved_by: str | None = None, claim=None) -> int:
    """Die Aenderung als queued anlegen. mechanism ist plan["mechanism"], der Schreibweg der Vorschau, den run_change genau so faehrt;
    ohne ihn bleibt die Spalte NULL und heisst ssh, wie bei Zeilen von vor der Spalte. sent is 0: nothing has gone out yet (run_change
    and _run_snmp set it to 1 right before anything does). role is the role of whoever starts it (Phase 4a): its change_* audit entry
    names it, whenever the change ends (run_change, _close). approved_by is whoever approved it under the four-eyes principle (Phase
    4a, Task 7; None for a change without an approval).

    One change at a time per switch (Phase 1, review §2): the check for a queued or running change of the switch and the INSERT are one
    write transaction (BEGIN IMMEDIATE), so of two concurrent requests that both passed api_changes.apply_change's early check the second
    waits for the first's commit and then raises Busy(BUSY), nothing inserted. claim, if given, is `async (conn, cid) -> None` and runs
    after the INSERT on the same connection, in the same transaction, before the commit (approvals.claim marks the request approved
    there): an exception from it goes through and nothing is stored, the change row included, so of two approvals of one request at
    once exactly one starts a change."""
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute("SELECT 1 FROM changes WHERE switch_id = ? AND status IN ('queued', 'running') LIMIT 1", (sid,)) as cur:
            if await cur.fetchone():
                raise Busy(BUSY)    # closing the connection rolls the transaction back
        cur = await conn.execute(
            "INSERT INTO changes(switch_id, username, kind, summary, request, ports, desired, before, commands, status, steps, expert, revert_of, "
            "mechanism, sent, role, approved_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)",
            (sid, user, kind, summary, json.dumps(req), json.dumps(sorted(plan.get("desired", {}), key=cfgparse.port_sort_key)),
             json.dumps(plan.get("desired", {})), json.dumps(plan.get("before", {})), json.dumps(plan["shown"]), "queued", "[]",
             int(bool(plan.get("expert"))), revert_of, plan.get("mechanism"), role, approved_by))
        if claim is not None:
            await claim(conn, cur.lastrowid)    # its exception: closing the connection rolls the INSERT back, as for Busy
        await conn.commit()
        return cur.lastrowid


async def run_change(cid: int):
    """Hintergrund-Task. Status: queued -> running -> ok | unclear | failed | aborted.

    Auf dem Schreibweg der Vorschau (changes.mechanism; NULL heisst ssh, eine Zeile von vor der Spalte): "snmp" faehrt _run_snmp, ein
    unbekannter bricht ab, ohne den Switch anzufassen (nie still per SSH). Der Rest hier ist der SSH-Weg; ab dem Lock gilt die Switch-Zeile
    von dann, und ohne SSH-CLI in ihrem Treiber endet er failed, ohne Sitzung (R39).

    sent = 1 goes into the row right before send_config_set and right before write memory: from there on the switch may have taken
    something. An exception after that point ends "unclear", not "failed" (the SNMP way's rule): netmiko's ReadTimeout from
    send_config_set, say, comes after the lines went out; its last step says what that leaves open (SSH_KEPT). A line the switch
    refused (ConfigInvalidException) stays "failed", with sent = 1 (the lines before it can be in effect). A cancelled task (the app
    shut down) ends the same way with CANCELLED, as on the SNMP way; one cancelled before anything went out ends "aborted" with
    CANCELLED_UNSENT, as after a restart (mark_interrupted). A change that ends "failed" without having sent anything (a switch
    disabled meanwhile, a read that failed) gets no re-poll (_repolls_after). Before lines go out the cached read is marked stale and
    dropped (R27, mark_cfg_stale): the end stores the read-back as the fresh read, or the read from before when no line went out;
    after lines without a read-back it stores neither. A revert that ends ok marks the change it took back (_mark_reverted).

    Inside the lock, before anything else, the switch row of then: a switch disabled while the change waited ends it failed with
    DISABLED_RUN, no session. Only then the inventory of a port change (the poll's ports and uplinks): a change before it may have
    renewed the poll while this one waited."""
    async with db() as conn:
        async with conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)) as cur:
            ch = await cur.fetchone()
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (ch["switch_id"],)) as cur:
            row = await cur.fetchone()
    mech = ch["mechanism"] or "ssh"
    if mech == "snmp":
        return await _run_snmp(cid, ch, row)
    if mech != "ssh":
        return await _refuse(cid, ch, f"Unbekannter Schreibweg {mech!r}: nichts ausgeführt")
    sid, kind = ch["switch_id"], ch["kind"]
    req, previewed = json.loads(ch["request"] or "{}"), json.loads(ch["commands"] or "[]")
    steps: list = []
    rs = await radius_settings()
    secrets = _secrets_of(row, rs)    # plus those of the row of after the lock (below): no text of this change shows one (E25)

    def mask(text: str) -> str:
        return cfgparse.mask_secrets(text, secrets)

    async def step(text: str, level: str = "info"):
        await _step(cid, steps, mask(text), level)

    pre = post = None
    status, error, saved, output = None, None, 0, ""    # status None to the end: the task was cancelled
    sent, kept, lines = False, "", False    # sent: changes.sent; kept: what is open then (SSH_KEPT); lines: lines went out

    async def going_out(what: str):
        """Right before `what` ("lines" or "save", SSH_KEPT) goes out to the switch. Lines change the running-config: the cached read
        is marked stale first (it then stays so after a hard kill or a restart, as on the SNMP way) and dropped once sent is in the
        row."""
        nonlocal sent, kept, lines
        if what == "lines":
            await mark_cfg_stale(sid)
        if not sent:
            await _upd(cid, sent=1)    # before it goes out: if writing the row fails, nothing is sent
            sent = True
        kept = SSH_KEPT[what]
        if what == "lines":
            lines = True
            invalidate_cfg(sid)

    try:
        lock = sshcli.lock(sid)
        if lock.locked():
            await step("Warte auf laufende Aktion an diesem Switch")
        async with lock:
            await _upd(cid, status="running")
            # R39, das Gegenstueck zu R33 auf dem SNMP-Weg: die Switch-Zeile von jetzt, nach dem Warten auf den Lock. Ist der Switch
            # (inzwischen) deaktiviert oder hat ihr Treiber keine SSH-CLI, geht keine Sitzung auf und nichts hinaus.
            row = await _switch_row(sid)
            secrets.extend(_secrets_of(row, rs))
            if row is not None and not row["enabled"]:
                status, error = "failed", DISABLED_RUN
                await step(error, "error")
                return
            reason = sshcli.cli_refusal(row) if row is not None else "Switch nicht gefunden"
            if reason:
                status, error = "failed", f"{reason}: nichts gesendet"
                await step(error, "error")
                return
            inv = await inventory(sid) if kind == "ports" else None    # inside the lock: the poll as it is now
            await step(f"Verbinde mit {row['host']}")
            conn = await asyncio.to_thread(sshcli.connect, row)
            try:
                pre = sshcli.clean(await asyncio.to_thread(conn.send_command, "show running-config", read_timeout=90))
                cfg = cfgparse.parse_config(pre)
                await step("Konfiguration vorher gelesen")
                if kind == "save":
                    plan = {"commands": [], "shown": [], "blocked": []}
                elif kind == "prepare":
                    plan = plan_prepare(cfg, rs)
                else:
                    plan = plan_ports(row["firmware"] or "", inv, cfg, req, radius_server=rs["server"])
                if plan["blocked"]:
                    status, error = "aborted", "; ".join(f"{b['port']}: {b['reason']}" for b in plan["blocked"])
                    await step("Abgebrochen: " + error, "error")
                    return
                if plan["shown"] != previewed:
                    status, error = "aborted", "Der Switch hat sich seit der Vorschau geändert. Bitte Vorschau neu laden."
                    await step(error, "error")
                    return
                if kind == "ports":
                    await _upd(cid, before=json.dumps(plan["before"]))
                if plan["commands"]:
                    await step(f"Sende {len(plan['commands'])} Befehle")
                    await going_out("lines")
                    try:
                        output = await asyncio.to_thread(conn.send_config_set, plan["commands"], read_timeout=30,
                                                         error_pattern=ERROR_PATTERN, cmd_verify=True)
                    except ConfigInvalidException as e:
                        output = str(e)
                        post = sshcli.clean(await asyncio.to_thread(conn.send_command, "show running-config", read_timeout=90))
                        status, error = "failed", "Der Switch hat einen Befehl abgelehnt. Nichts gespeichert, Teile können schon wirken."
                        await step(error, "error")
                        return
                    post = sshcli.clean(await asyncio.to_thread(conn.send_command, "show running-config", read_timeout=90))
                    after = cfgparse.parse_config(post)
                    await step("Konfiguration nachher gelesen")
                    if kind == "prepare":
                        r = readiness(after, rs["server"])
                        bad = [k for k in ("host", "coa", "tw", "eap", "active", "park") if not r[k]]
                    else:
                        bad = verify_ports(after, plan["desired"])
                    if bad:
                        status, error = "unclear", "Prüfung nach der Änderung passt nicht: " + "; ".join(bad[:8])
                        await step(f"{error}. {kept}", "error")
                        return
                    await step("Prüfung ok")
                await step("Speichere (write memory)")
                await going_out("save")
                await asyncio.to_thread(conn.save_config)
                saved, status = 1, "ok"
                await step("Gespeichert", "ok")
            finally:
                await asyncio.to_thread(sshcli.disconnect, conn)
    except Exception as e:  # noqa: BLE001
        if pre is None:  # R27: per SSH nicht bis zur running-config gekommen (Verbinden oder erstes Lesen scheiterte)
            invalidate_cfg(sid)
        status, error = ("unclear" if sent or post or output else "failed"), _error_text(e, mask)
        _log_masked(cid, e, mask)
        await step(f"{error}. {kept}" if sent else error, "error")
    finally:
        if status is None:    # did not run to its end: the task was cancelled (the app shut down)
            status, error = ("unclear", CANCELLED) if sent else ("aborted", CANCELLED_UNSENT)
            await _logged(cid, "Abbruch vermerken", step(f"{error}. {kept}" if sent else error, "error"))
        await _upd(cid, status=status, error=error and mask(error), saved=saved, finished_at=_now(), output=mask(output or ""))
        # Each step on its own: what fails is logged and costs the rest nothing, the audit and the re-poll (by _repolls_after) still
        # run. A read that does not parse (beyond the limits of cfgparse) is still kept as the backup, and the cached read is dropped
        # (R27). After lines without a read-back the read from before them is no fresh read: the entry stays dropped and marked stale
        # (going_out, mark_cfg_stale).
        if pre:
            await _logged(cid, "Sicherung vorher", sshcli.store_backup(sid, pre, f"vor #{cid}"))
        if post:
            await _logged(cid, "Sicherung nachher", sshcli.store_backup(sid, post, f"nach #{cid}"))
        fresh = post or (None if lines else pre)
        if fresh and not await _logged(cid, "Konfiguration auswerten", store_cfg(sid, fresh)):
            invalidate_cfg(sid)
        if kind == "save" and status == "ok" and req.get("of"):
            await _upd(int(req["of"]), saved=1)
        await _logged(cid, "Rücknahme vermerken", _mark_reverted(ch, cid, status))
        # "Speichern" (also "Trotzdem speichern") writes the whole running configuration, not only what change "of" sent: the audit
        # names the state it read before, the start of the sha of its backup "vor #cid" (or of the equal one before it)
        stand = f", Stand {sshcli.backup_sha(pre)[:12]}" if kind == "save" and pre else ""
        await audit(ch["username"], "change_" + status, str(sid), f"#{cid} {ch['summary']}{stand}", role=ch["role"])
        if _repolls_after(status, kind, sent):
            asyncio.create_task(_repoll(sid))


def _error_text(e: BaseException, mask) -> str:
    """The error of a change that ends with the exception e (run_change, _run_snmp): its type and its text through mask, the text cut
    to 300 characters after masking (a secret that straddles the cut leaves nothing of itself), except for an sshcli.HostKeyMismatch:
    SwitchView's own text, bounded by the 64-character host, whose end says what to do."""
    text = mask(str(e))
    return f"{type(e).__name__}: {text if isinstance(e, sshcli.HostKeyMismatch) else text[:300]}"


def _log_masked(cid: int, e: BaseException, mask) -> None:
    """Logs the exception e that ends change cid with its whole traceback, through mask like every stored text of the change: an
    exception text can carry a secret (netmiko's ReadTimeout names the command, the RADIUS key in it), and a container log often goes
    to a collector with more readers than the host."""
    log.error("Änderung %s: %s", cid, mask("".join(traceback.format_exception(e))))


async def _logged(cid: int, what: str, aw) -> bool:
    """await aw at the end of run_change; False when it raised, logged with the change and what: the end of the change goes on."""
    try:
        await aw
        return True
    except Exception:  # noqa: BLE001
        log.exception("Änderung %s: %s fehlgeschlagen", cid, what)
        return False


async def _run_snmp(cid: int, ch, row):
    """run_change per SNMP (Spec §6, Q2): der Ablauf des SSH-Wegs, im selben Lock des Switches (sshcli.lock), damit Aenderungen an
    einem Switch nacheinander laufen, gleich ueber welchen Weg.
      1. Ohne Schreib-Identitaet (poller.creds_of(row, write=True)): failed, nichts gelesen, nichts gesendet. Nach dem Warten auf den
         Lock noch einmal, mit der Switch-Zeile von dann (R33): SNMP-Schreiben kann inzwischen aus sein, die Zugangsdaten weg. Ab da
         gilt diese Zeile (Zugangsdaten, Treiber). Before that, and before anything else in the lock: a switch disabled meanwhile ends
         the change failed with DISABLED_RUN. Only then the inventory (the poll's ports and uplinks), inside the lock as on the SSH way.
      2. Live lesen: snmpwrite.read_cfg selbst, nie api_changes._read_snmp (das naehme den Lock ein zweites Mal, asyncio.Lock ist nicht
         reentrant), die PoE-Tabellen nur, wenn die Aenderung PoE beruehrt (touches_poe, R34; das Zuruecklesen genauso). Scheitert es:
         failed.
      3. Gegen diesen Read neu planen (die Anfrage der Aenderung): gesperrt oder shown anders als in der Vorschau -> aborted, ebenso ein
         Plan ohne Varbinds ("Nichts zu ändern": nie ok ohne Zuruecklesen und Pruefen); nichts geschrieben. before kommt aus diesem
         Read (mit der PVID, R21) und steht in der Zeile, bevor das SET hinausgeht.
      4. EIN SET (snmpwrite.apply_ops). Scheitert es (Timeout, Fehlerpaket), ist offen, ob der Switch es uebernommen hat: kein failed,
         das Zuruecklesen entscheidet. Hat der Switch das SET verarbeitet, hat ein Treiber mit snmp_autosave seine gesamte laufende
         Konfiguration gespeichert, also auch jede absichtlich nicht gespeicherte SSH-Aenderung (unsaved_ssh_changes, vor dem SET
         festgestellt): sie bekommen saved=1 mit einem Schritt, und diese Aenderung einen, der sie nennt (R42). Verarbeitet heisst: das SET
         kam ohne Fehler zurueck, oder seine Antwort fehlte, aber das Pruefen in 5. bestaetigt jeden Wert (R42b, dann nach dem Pruefen).
         Ein SET mit Fehler, das das Zuruecklesen nicht bestaetigt, markiert nichts.
      5. Zuruecklesen und pruefen (verify_snmp, die ganze VLAN-Zugehoerigkeit, R32): scheitert der Read oder weicht etwas ab, unclear.
         Sonst ok, saved=1 nur bei einem Treiber, der jeden SET selbst speichert (snmp_autosave, R26), sonst saved=0 mit Hinweis.
    Was ab dem Uebergeben des SET schiefgeht, ist unclear (der Schritt sagt, ob es schon gespeichert waere), davor failed (without a
    re-poll: nothing went out, _close, _repolls_after). A cancelled task (the app shut down, say) ends unclear with CANCELLED once the
    SET was handed over, before that "aborted" with CANCELLED_UNSENT, as after a restart (mark_interrupted). The row gets sent = 1 right
    before the SET is handed over (changes.sent), so a restart (mark_interrupted) and the follow-up actions (actions_of) know it too; a
    revert that ends ok marks the change it took back (_close, _mark_reverted). Nie SSH, keine Sicherung, kein
    switch_cfg: es gibt keine running-config. Den zwischengespeicherten SSH-Read verwirft das SET (invalidate_cfg, und mark_cfg_stale
    fuer die Zeit nach einem Neustart)."""
    sid = ch["switch_id"]
    if ch["kind"] != "ports":  # Speichern und RADIUS-Vorbereitung gibt es nur per SSH (main lehnt sie vorher ab)
        return await _refuse(cid, ch, "Per SNMP gibt es nur Port-Änderungen: nichts ausgeführt")
    req, previewed = json.loads(ch["request"] or "{}"), json.loads(ch["commands"] or "[]")
    steps: list = []
    secrets: list[str] = []    # as in run_change (E25): _secrets_of, read in the try (a cancel there still ends the change below)

    def mask(text: str) -> str:
        return cfgparse.mask_secrets(text, secrets)

    async def step(text: str, level: str = "info"):
        await _step(cid, steps, mask(text), level)

    status, error, saved, output = None, None, 0, ""
    sent, kept = False, ""  # sent: ab hier kann der Switch etwas uebernommen haben; kept: was das dann heisst (SNMP_KEPT)
    try:
        rs = await radius_settings()
        secrets.extend(_secrets_of(row, rs))
        reason = _no_write_identity(row)
        if reason:
            status, error = "failed", reason
            await step(error, "error")
            return
        lock = sshcli.lock(sid)
        if lock.locked():
            await step("Warte auf laufende Aktion an diesem Switch")
        async with lock:
            await _upd(cid, status="running")
            row = await _switch_row(sid)
            secrets.extend(_secrets_of(row, rs))
            if row is not None and not row["enabled"]:
                reason = DISABLED_RUN
            else:
                reason = _no_write_identity(row) if row is not None else "Switch nicht gefunden"
            if reason:
                status, error = "failed", reason
                await step(error, "error")
                return
            inv = await inventory(sid)    # inside the lock: the poll as it is now
            driver = drivers.driver_for(row)
            autosave = drivers.can(driver, "snmp_autosave")
            kept = SNMP_KEPT[autosave]
            await step(f"Lese {row['host']} per SNMP")
            with_poe = touches_poe(req)    # R34: fuer beide Reads dieser Aenderung derselbe Wert
            try:
                cfg, raw = await snmpwrite.read_cfg(row, driver, with_poe=with_poe)
            except (snmp.SnmpError, OSError) as e:
                status, error = "failed", f"Zustand per SNMP nicht lesbar: {e}"
                await step(error, "error")
                return
            await step("Zustand vorher gelesen")
            plan = plan_ports(row["firmware"] or "", inv, cfg, req, mechanism="snmp", driver=driver, raw=raw)
            if plan["blocked"]:
                status, error = "aborted", "; ".join(f"{b['port']}: {b['reason']}" for b in plan["blocked"])
                await step("Abgebrochen: " + error, "error")
                return
            if plan["shown"] != previewed:
                status, error = "aborted", "Der Switch hat sich seit der Vorschau geändert. Bitte Vorschau neu laden."
                await step(error, "error")
                return
            if not plan["ops"]:
                status, error = "aborted", "Nichts zu ändern"
                await step(error, "error")
                return
            await _upd(cid, before=json.dumps(plan["before"]))
            n = len(plan["ops"])
            await step(f"Setze {n} {'Wert' if n == 1 else 'Werte'} per SNMP (ein SET)")
            await mark_cfg_stale(sid)    # vor sent: scheitert das Schreiben in die DB, ist nichts gesendet
            unsaved = await unsaved_ssh_changes(sid) if autosave else []    # R42: was dieses SET mitspeichert, im Lock festgestellt
            await _upd(cid, sent=1)    # changes.sent, before the SET goes out: if writing the row fails, nothing is sent
            sent = True
            invalidate_cfg(sid)
            set_failed = False
            try:
                output = await snmpwrite.apply_ops(row, driver, plan["ops"])
            except (snmp.SnmpError, OSError) as e:
                output, set_failed = str(e), True
                await step(f"SET nicht bestätigt ({e}): ob der Switch die Werte übernommen hat, zeigt das Zurücklesen", "error")
            else:
                if unsaved:    # ein SET ohne Fehler: der Switch hat seine gesamte laufende Konfiguration gespeichert
                    await _also_saved(cid, steps, unsaved)
            try:
                cfg_after, raw_after = await snmpwrite.read_cfg(row, driver, with_poe=with_poe)
            except (snmp.SnmpError, OSError) as e:
                status, error = "unclear", f"Zurücklesen per SNMP fehlgeschlagen: {e}"
                await step(f"{error}. {kept}", "error")
                return
            await step("Zustand nachher gelesen")
            bad = verify_snmp(driver, cfg, cfg_after, raw_after, plan["desired"], raw=raw)
            if bad:
                status, error = "unclear", "Prüfung nach der Änderung passt nicht: " + "; ".join(bad[:8])
                await step(f"{error}. {kept}", "error")
                return
            await step("Prüfung ok")
            if set_failed and unsaved:
                # R42b: die Antwort auf das SET fehlte, das Zuruecklesen bestaetigt aber jeden Wert: der Switch hat das SET verarbeitet
                # und dabei (wie bei jedem SET) seine gesamte laufende Konfiguration gespeichert (unsaved gibt es nur mit snmp_autosave)
                await _also_saved(cid, steps, unsaved)
            status = "ok"
            if autosave:
                saved = 1
                await step("Gespeichert (der Switch speichert SNMP-Änderungen selbst)", "ok")
            else:
                await step(SNMP_UNSAVED, "warn")
    except Exception as e:  # noqa: BLE001
        status, error = ("unclear" if sent else "failed"), _error_text(e, mask)
        _log_masked(cid, e, mask)
        await step(f"{error}. {kept}" if sent else error, "error")
    finally:
        if status is None:  # nicht zu Ende gelaufen: der Task wurde abgebrochen
            status, error = ("unclear", CANCELLED) if sent else ("aborted", CANCELLED_UNSENT)
            steps.append([_now(), f"{error}. {kept}" if sent else error, "error"])
        await _close(cid, ch, status, error and mask(error), saved, mask(output or ""), steps, sent)


ALSO_SAVED = "der Switch speichert bei jedem SNMP-SET die gesamte laufende Konfiguration"


def change_refs(ids: list[int]) -> str:
    """[12] -> "#12", [12, 15, 16] -> "#12, #15 und #16"."""
    refs = [f"#{i}" for i in ids]
    return refs[0] if len(refs) == 1 else ", ".join(refs[:-1]) + " und " + refs[-1]


async def unsaved_ssh_changes(sid: int) -> list[int]:
    """Die Aenderungen von Switch sid, die ein SNMP-SET auf einem Treiber mit snmp_autosave mitspeichern wuerde (R42): per SSH gelaufen
    (mechanism ssh, oder NULL von vor der Spalte), mit Folgen in der laufenden Konfiguration (Status ok / unclear / failed, nicht
    zurueckgenommen, and sent: 1, or NULL from before the column; one that sent nothing has nothing to be saved, R48) und absichtlich
    nicht gespeichert (saved 0). Ohne Speichern-Aenderungen: ein gescheitertes write memory hat keinen eigenen Stand, den traegt die
    Aenderung, die es speichern sollte. Ids aufsteigend."""
    async with db() as conn:
        async with conn.execute("SELECT id FROM changes WHERE switch_id = ? AND (mechanism IS NULL OR mechanism = 'ssh') AND saved = 0 "
                                "AND reverted_by IS NULL AND status IN ('ok', 'unclear', 'failed') AND kind != 'save' "
                                "AND (sent IS NULL OR sent = 1) ORDER BY id", (sid,)) as cur:
            return [r["id"] for r in await cur.fetchall()]


async def _also_saved(cid: int, steps: list, ids: list[int]):
    """R42: die SNMP-Aenderung cid hat mit ihrem SET die gesamte laufende Konfiguration gespeichert: die Aenderungen ids bekommen saved=1
    und einen Schritt (_mark_saved_by_snmp), cid einen, der sie nennt."""
    await _mark_saved_by_snmp(cid, ids)
    await _step(cid, steps, f"Mitgespeichert: Änderung {change_refs(ids)} ({ALSO_SAVED})", "warn")


async def _mark_saved_by_snmp(cid: int, ids: list[int]):
    """R42: die SNMP-Aenderung cid hat mit ihrem SET die gesamte laufende Konfiguration gespeichert: die Aenderungen ids sind damit
    gespeichert (saved 1), jede bekommt einen Schritt, der das sagt. In einem Schreiben in die DB."""
    text = f"Mitgespeichert durch SNMP-Änderung #{cid}: {ALSO_SAVED}."
    async with db() as conn:
        for i in ids:
            async with conn.execute("SELECT steps FROM changes WHERE id = ?", (i,)) as cur:
                r = await cur.fetchone()
            if r is None:    # inzwischen geloescht
                continue
            steps = json.loads(r["steps"] or "[]") + [[_now(), text, "warn"]]
            await conn.execute("UPDATE changes SET saved = 1, steps = ? WHERE id = ?", (json.dumps(steps), i))
        await conn.commit()


def _no_write_identity(row) -> str | None:
    """Warum keine SNMP-SETs an den Switch row gehen duerfen (der Grund aus poller.creds_of(row, write=True)), sonst None."""
    try:
        poller.creds_of(row, write=True)
    except snmp.SnmpError as e:
        return str(e)
    return None


async def _switch_row(sid: int):
    async with db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)) as cur:
            return await cur.fetchone()


async def _refuse(cid: int, ch, error: str):
    """Eine Aenderung abbrechen, ohne den Switch anzufassen (aborted, mit Grund)."""
    await _close(cid, ch, "aborted", error, 0, "", [[_now(), error, "error"]])


async def _close(cid: int, ch, status: str, error: str | None, saved: int, output: str, steps: list, sent: bool = True):
    """Abschluss einer Aenderung, die nicht ueber SSH lief: Ergebnis und Schritte in EINEM Schreiben in die Zeile, Audit wie auf dem
    SSH-Weg, dazu der Schreibweg, und die Nach-Abfrage wie dort (_repolls_after; sent: whether the switch may have taken something,
    _run_snmp's sent). Keine Sicherung und kein switch_cfg: es gibt keine running-config. A revert that ended ok marks the change it
    took back (_mark_reverted), as on the SSH way."""
    sid = ch["switch_id"]
    await _upd(cid, status=status, error=error, saved=saved, finished_at=_now(), output=output, steps=json.dumps(steps))
    await _logged(cid, "Rücknahme vermerken", _mark_reverted(ch, cid, status))    # as in run_change: audit and re-poll still run
    await audit(ch["username"], "change_" + status, str(sid), f"#{cid} {ch['summary']}, mechanism: {ch['mechanism']}", role=ch["role"])
    if _repolls_after(status, ch["kind"], sent):
        asyncio.create_task(_repoll(sid))


def _repolls_after(status: str, kind: str, sent: bool) -> bool:
    """Whether a change that ended with status re-polls its switch (run_change, _close): after ok or unclear, and after failed only
    when something went out (sent; a change that failed before that left the switch as it was, which may just have been disabled,
    DISABLED_RUN); never after aborted (nothing went out) or a save (write memory changes no port)."""
    return status in ("ok", "unclear", "failed") and kind != "save" and (status != "failed" or sent)


async def _mark_reverted(ch, cid: int, status: str):
    """Change cid (its row ch) took back change ch["revert_of"]: only a revert that ended ok marks that one reverted_by = cid (review
    §2). An unclear or failed revert leaves it revertable: another revert plans against a fresh read and does only what is missing."""
    if ch["revert_of"] and status == "ok":
        await _upd(int(ch["revert_of"]), reverted_by=cid)


def may_have_sent(ch) -> bool:
    """Whether change ch may have reached its switch: sent is 1, or NULL (a row from before the column, unknown, counted as sent)."""
    return ch["sent"] != 0


def actions_of(ch) -> dict[str, bool]:
    """The follow-up actions of change ch, as the UI offers them (main._change_out serves both): "Rückgängig" (can_revert) for a port
    change that ended ok / unclear / failed, is not reverted yet and may have sent something; "Trotzdem speichern" (can_save, write
    memory) for an SSH change (NULL = ssh) that ended unclear / failed, is not saved and may have sent something. The same rules as
    api_changes._plan_revert and api_changes._plan_save, which refuse the rest."""
    sent = may_have_sent(ch)
    return {"can_revert": ch["kind"] == "ports" and not ch["reverted_by"] and ch["status"] in ("ok", "unclear", "failed") and sent,
            "can_save": (ch["mechanism"] or "ssh") == "ssh" and ch["status"] in ("unclear", "failed") and not ch["saved"] and sent}


INTERRUPTED = "Abgebrochen durch Neustart von SwitchView"


async def mark_interrupted() -> int:
    """At start: every change the last process left queued or running ends now. One that never sent anything (sent 0) is "aborted"
    (INTERRUPTED + ", nichts gesendet"), every other one "unclear" as before (sent 1, or NULL from before the column). Returns how many."""
    async with db() as conn:
        aborted = await conn.execute("UPDATE changes SET status = 'aborted', error = ?, finished_at = datetime('now') "
                                     "WHERE status IN ('queued', 'running') AND sent = 0", (f"{INTERRUPTED}, nichts gesendet",))
        unclear = await conn.execute("UPDATE changes SET status = 'unclear', error = ?, finished_at = datetime('now') "
                                     "WHERE status IN ('queued', 'running')", (INTERRUPTED,))
        await conn.commit()
    return aborted.rowcount + unclear.rowcount


async def _repoll(sid: int):
    await asyncio.sleep(3)
    try:
        await poller.poll_switch(sid)
    except Exception:  # noqa: BLE001
        log.exception("Nach-Abfrage %s", sid)
