"""The RADIUS basics of a switch: the RADIUS server and shared secret of the settings, the SNMPv3 user PacketFence switches a port
with, the secrets no text of a change may show, how far a running-config is prepared for RADIUS (readiness) and the plan that prepares
it (plan_prepare). Split from changes.py (Phase 3, Task 11); changes re-exports every name."""
import ipaddress
import re

from crypto import decrypt, unreadable
from db import load_settings

# Druckbares ASCII ohne Leerzeichen. Ausgeschlossen: ? (startet die CLI-Hilfe), ~ (J.15 kennt es nicht), Quotes, Backslash
RADIUS_KEY_RE = re.compile(r"""^(?!.*[?~"'\\])[!-~]{8,64}$""")
# The SNMPv3 user PacketFence re-evaluates a port with (deauthMethod SNMP, no cable pulled): its name as the CLI takes it unquoted,
# its two passphrases with the characters of the RADIUS key, 8 to 32 of them (the ProCurve CLI takes no longer one)
SNMP_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
SNMP_PASS_RE = re.compile(r"""^(?!.*[?~"'\\])[!-~]{8,32}$""")
SNMP_GROUP = "managerpriv"    # read and write, authPriv: what a SET of PacketFence needs


# ── RADIUS-Grundeinrichtung des Switches ──────────────────────────────────────
PARK_VLAN = "3999"  # Park-VLAN: ohne IP, ohne Routing, auf keinem Uplink


async def radius_settings() -> dict:
    """The RADIUS server and shared secret of the settings: server and key ("" when not set or not decryptable), and key_unreadable
    when a stored key does not decrypt (plan_prepare names it instead of "fehlt"). And snmp, the SNMPv3 user of PacketFence: user ("":
    none, "Vorbereiten" leaves SNMPv3 alone), auth and priv (its passphrases, "" like key) and unreadable (one of them does not
    decrypt)."""
    # target and secrets in one SELECT (db.load_settings): a concurrent settings PUT never pairs one with the other's old value (F2)
    s = await load_settings(["radius_server", "radius_key", "pf_snmp_user", "pf_snmp_auth", "pf_snmp_priv"])
    return {"server": s["radius_server"] or "", "key": decrypt(s["radius_key"]) or "", "key_unreadable": unreadable(s["radius_key"]),
            "snmp": {"user": s["pf_snmp_user"] or "", "auth": decrypt(s["pf_snmp_auth"]) or "", "priv": decrypt(s["pf_snmp_priv"]) or "",
                     "unreadable": unreadable(s["pf_snmp_auth"]) or unreadable(s["pf_snmp_priv"])}}


# Every secret column of a switches row (main.SECRET_FIELDS), in the order _secrets_of lists them
_SWITCH_SECRETS = ("ssh_pass", "snmp_community", "snmp_rw_community", "snmp_auth_pass", "snmp_priv_pass", "snmp_rw_auth_pass",
                   "snmp_rw_priv_pass")


def _secrets_of(row, rs: dict) -> list[str]:
    """What no text of a change may show (cfgparse.mask_secrets(text, _secrets_of(...))): the RADIUS key of rs (radius_settings), the
    two passphrases of its SNMPv3 user and, decrypted, every secret of the switch row (None: no switch), its SSH password, its
    communities and its SNMPv3 passphrases, read and write. Only the non-empty ones, and no community "public" (any case, outer
    whitespace ignored, like snmp._secrets): it is no secret, and masking it would garble messages that name it."""
    snmp = rs.get("snmp") or {}
    out = [rs.get("key") or "", snmp.get("auth") or "", snmp.get("priv") or ""]
    for col in _SWITCH_SECRETS if row is not None else ():
        value = decrypt(row[col]) or ""
        if col.endswith("community") and value.strip().lower() == "public":
            continue
        out.append(value)
    return [s for s in out if s]


def readiness(cfg: dict, server: str | None, snmp_user: str = "") -> dict:
    """How far cfg is prepared. snmp says whether the SNMPv3 user snmp_user is there and in SNMP_GROUP: None when none is asked for
    ("") or cfg does not tell (read over SNMP, or stored before SNMPv3 was parsed). snmp_off: a user is asked for, but SNMPv3 is
    switched off on the switch."""
    hosts = cfg.get("radius") or {}
    h = hosts.get(server) if server else next(iter(hosts.values()), None)
    v3 = cfg.get("snmpv3") if snmp_user else None
    there = v3 is not None and snmp_user in (v3.get("users") or []) and SNMP_GROUP in ((v3.get("groups") or {}).get(snmp_user) or [])
    return {"host": bool(h), "coa": bool(h and h.get("dyn")), "eap": bool(cfg.get("eap_radius")),
            "active": bool(cfg.get("auth_active")), "park": PARK_VLAN in (cfg.get("vlans") or {}),
            # CoA ohne Event-Timestamp (PacketFence schickt keins) nimmt der Switch nur mit time-window 0 an
            "tw": bool(h and h.get("time_window") == 0),
            "login_radius": bool(cfg.get("login_radius")), "others": [ip for ip in hosts if server and ip != server],
            "snmp": None if v3 is None else there, "snmp_off": v3 is not None and not v3.get("enabled")}


def readiness_missing(cfg: dict, server: str | None) -> list[str]:
    """What a NAC change needs on the switch and cfg does not show: the RADIUS server (exactly `server` when given, any host line
    without), eap-radius and 802.1X globally on."""
    r = readiness(cfg, server)
    names = {"host": f"RADIUS-Server {server}" if server else "RADIUS-Server", "eap": "802.1X-Methode eap-radius",
             "active": "802.1X global aktiv"}
    return [names[k] for k in names if not r[k]]


def _plan_snmp(cfg: dict, snmp: dict, r: dict, cmds: list, shown: list, blocked: list, warnings: list) -> bool:
    """Adds what the SNMPv3 user of snmp (radius_settings) lacks on the switch: the user with its passphrases, shown masked, and its
    place in SNMP_GROUP. A user that is there is never created anew: the switch would take the passphrases of the settings, and whoever
    set others on purpose would lose them. True when the user is expected afterwards."""
    user = snmp.get("user") or ""
    if r["snmp"] is not False:    # none asked for, cfg does not tell, or already there
        return False
    if not SNMP_USER_RE.fullmatch(user):    # lands in a CLI line; api_settings refuses it on saving
        blocked.append({"port": "*", "reason": "SNMP-Benutzer für PacketFence enthält unzulässige Zeichen – in den Einstellungen neu eingeben"})
        return False
    if r["snmp_off"]:    # "snmpv3 enable" asks back at the CLI (docs/procurve-cli-referenz.md): never automated
        warnings.append(f"SNMPv3 ist am Switch ausgeschaltet. Der SNMP-Benutzer „{user}“ wird nicht angelegt: „snmpv3 enable“ fragt an "
                        "der CLI nach und muss einmal von Hand laufen.")
        return False
    if user not in ((cfg.get("snmpv3") or {}).get("users") or []):
        auth, priv = snmp.get("auth") or "", snmp.get("priv") or ""
        if snmp.get("unreadable"):
            blocked.append({"port": "*", "reason": "SNMP-Passwörter für PacketFence lassen sich nicht entschlüsseln (SECRET_KEY geändert?) – "
                                                   "in den Einstellungen neu eingeben"})
            return False
        if not SNMP_PASS_RE.fullmatch(auth) or not SNMP_PASS_RE.fullmatch(priv):
            blocked.append({"port": "*", "reason": "SNMP-Passwörter für PacketFence fehlen oder enthalten unzulässige Zeichen (je 8–32 "
                                                   "Zeichen, ohne Leerzeichen, Anführungszeichen, Backslash, ? und ~)"})
            return False
        cmds.append(f"snmpv3 user {user} auth sha {auth} priv aes {priv}")
        shown.append(f"snmpv3 user {user} auth sha *** priv aes ***")
    cmds.append(f"snmpv3 group {SNMP_GROUP} user {user} sec-model ver3")
    shown.append(cmds[-1])
    return True


def plan_prepare(cfg: dict, rs: dict) -> dict:
    server, key = rs["server"], rs["key"]
    snmp = rs.get("snmp") or {}
    blocked, warnings, cmds, shown = [], [], [], []
    try:
        ip = ipaddress.ip_address(server)
    except ValueError:
        ip = None
    # A zone id ("fe80::1%eth0") is refused like a missing server: it lands in a CLI line, and ipaddress takes any text after the "%",
    # a line break included (§6 (a)). api_settings.put_settings refuses it on saving; this covers a value stored before that.
    if ip is None or getattr(ip, "scope_id", None) is not None:
        blocked.append({"port": "*", "reason": "RADIUS-Server (PacketFence-IP) fehlt in den Einstellungen"})
        return {"commands": [], "shown": [], "blocked": blocked, "warnings": [], "expected": {}}
    r = readiness(cfg, server, snmp.get("user") or "")
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
    expected = {"host": True, "coa": True, "tw": True, "eap": True, "active": True, "park": True}
    if _plan_snmp(cfg, snmp, r, cmds, shown, blocked, warnings):
        expected["snmp"] = True
    if r["login_radius"]:
        warnings.append("Die Anmeldung am Switch selbst nutzt RADIUS. Ein weiterer Server kann sich darauf auswirken.")
    if r["others"]:
        warnings.append("Weitere RADIUS-Server sind eingetragen: " + ", ".join(r["others"]))
    warnings.append("Wirkt switchweit, ändert aber noch keinen Port. Ports bleiben „Protected“, bis du sie umstellst.")
    return {"commands": cmds, "shown": shown, "blocked": blocked, "warnings": warnings, "expected": expected}
