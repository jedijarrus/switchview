"""The RADIUS basics of a switch: the RADIUS server and shared secret of the settings, the secrets no text of a change may show, how far
a running-config is prepared for RADIUS (readiness) and the plan that prepares it (plan_prepare). Split from changes.py (Phase 3,
Task 11), the code as it was; changes re-exports every name."""
import ipaddress
import re

from crypto import decrypt, unreadable
from db import load_settings

# Druckbares ASCII ohne Leerzeichen. Ausgeschlossen: ? (startet die CLI-Hilfe), ~ (J.15 kennt es nicht), Quotes, Backslash
RADIUS_KEY_RE = re.compile(r"""^(?!.*[?~"'\\])[!-~]{8,64}$""")


# ── RADIUS-Grundeinrichtung des Switches ──────────────────────────────────────
PARK_VLAN = "3999"  # Park-VLAN: ohne IP, ohne Routing, auf keinem Uplink


async def radius_settings() -> dict:
    """The RADIUS server and shared secret of the settings: server and key ("" when not set or not decryptable), and key_unreadable
    when a stored key does not decrypt (plan_prepare names it instead of "fehlt")."""
    # target and secret in one SELECT (db.load_settings): a concurrent settings PUT never pairs one with the other's old value (F2)
    s = await load_settings(["radius_server", "radius_key"])
    return {"server": s["radius_server"] or "", "key": decrypt(s["radius_key"]) or "", "key_unreadable": unreadable(s["radius_key"])}


# Every secret column of a switches row (main.SECRET_FIELDS), in the order _secrets_of lists them
_SWITCH_SECRETS = ("ssh_pass", "snmp_community", "snmp_rw_community", "snmp_auth_pass", "snmp_priv_pass", "snmp_rw_auth_pass",
                   "snmp_rw_priv_pass")


def _secrets_of(row, rs: dict) -> list[str]:
    """What no text of a change may show (cfgparse.mask_secrets(text, _secrets_of(...))): the RADIUS key of rs (radius_settings) and,
    decrypted, every secret of the switch row (None: no switch), its SSH password, its communities and its SNMPv3 passphrases, read and
    write. Only the non-empty ones, and no community "public" (any case, outer whitespace ignored, like snmp._secrets): it is no secret,
    and masking it would garble messages that name it."""
    out = [rs.get("key") or ""]
    for col in _SWITCH_SECRETS if row is not None else ():
        value = decrypt(row[col]) or ""
        if col.endswith("community") and value.strip().lower() == "public":
            continue
        out.append(value)
    return [s for s in out if s]


def readiness(cfg: dict, server: str | None) -> dict:
    hosts = cfg.get("radius") or {}
    h = hosts.get(server) if server else next(iter(hosts.values()), None)
    return {"host": bool(h), "coa": bool(h and h.get("dyn")), "eap": bool(cfg.get("eap_radius")),
            "active": bool(cfg.get("auth_active")), "park": PARK_VLAN in (cfg.get("vlans") or {}),
            # CoA ohne Event-Timestamp (PacketFence schickt keins) nimmt der Switch nur mit time-window 0 an
            "tw": bool(h and h.get("time_window") == 0),
            "login_radius": bool(cfg.get("login_radius")), "others": [ip for ip in hosts if server and ip != server]}


def readiness_missing(cfg: dict, server: str | None) -> list[str]:
    """What a NAC change needs on the switch and cfg does not show: the RADIUS server (exactly `server` when given, any host line
    without), eap-radius and 802.1X globally on."""
    r = readiness(cfg, server)
    names = {"host": f"RADIUS-Server {server}" if server else "RADIUS-Server", "eap": "802.1X-Methode eap-radius",
             "active": "802.1X global aktiv"}
    return [names[k] for k in names if not r[k]]


def plan_prepare(cfg: dict, rs: dict) -> dict:
    server, key = rs["server"], rs["key"]
    blocked, warnings, cmds, shown = [], [], [], []
    try:
        ip = ipaddress.ip_address(server)
    except ValueError:
        ip = None
    # A zone id ("fe80::1%eth0") is refused like a missing server: it lands in a CLI line, and ipaddress takes any text after the "%",
    # a line break included (§6 (a)). main.put_settings refuses it on saving; this covers a value stored before that.
    if ip is None or getattr(ip, "scope_id", None) is not None:
        blocked.append({"port": "*", "reason": "RADIUS-Server (PacketFence-IP) fehlt in den Einstellungen"})
        return {"commands": [], "shown": [], "blocked": blocked, "warnings": [], "expected": {}}
    r = readiness(cfg, server)
    if not r["host"]:    # only here the key is needed: a switch with the host line already is prepared without it
        if rs.get("key_unreadable"):
            blocked.append({"port": "*", "reason": "Shared Secret lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – in den Einstellungen "
                                                   "neu eingeben"})
        elif not key or not RADIUS_KEY_RE.fullmatch(key):
            blocked.append({"port": "*", "reason": "Shared Secret fehlt oder enthält unzulässige Zeichen (8–64 Zeichen, ohne Leerzeichen, "
                                                   "Anführungszeichen, Backslash, ? und ~)"})
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
