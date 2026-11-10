"""running-config von ProCurve/ArubaOS-Switch lesen, Portlisten wandeln, Geheimnisse maskieren.

Grundlage: docs/procurve-cli-referenz.md (3.2). Der Parser versteht beide Schreibweisen fuer
Port-Access: globale Zeilen mit Portliste (15.x) und Zeilen im interface-Block (16.x).
"""
import re
from collections import defaultdict

# A port token, bounded and ASCII only (\d takes every Unicode digit, and int() fails beyond 4300 digits): [<stack>/][<module>]<port>,
# at most 4 digits of stack member and 6 of port; a trunk TrkN with at most 4 digits
_TOKEN = re.compile(r"^(?:([0-9]{1,4})/)?([A-Za-z]?)([0-9]{1,6})$")
_TRK = re.compile(r"(?i)^trk([0-9]{1,4})$")

# Limits for text from a switch (F5, NV cfgparse-unbounded-range-expansion): a compromised or MITM'd switch controls its
# running-config, and parse_config runs on the single worker's event loop. The largest real case (a chassis, 288 ports x 500 VLANs)
# stays far below MAX_REFS (E23).
MAX_RANGE = 1024        # ports in one range a-b of a port list
MAX_EXPAND = 4096       # ports in one port list
MAX_REFS = 1_000_000    # port and port x VLAN entries of one configuration (parse_config)
_VID = re.compile(r"[1-9][0-9]{0,3}")    # a VLAN ID as a switch writes it: ASCII digits, no leading zero (1..4094 checks int)


def expand_ports(spec: str) -> list[str]:
    """'1-3,7,A1-A2,Trk1' -> ['1','2','3','7','A1','A2','Trk1']. ValueError for a part it cannot read, for a range of more than
    MAX_RANGE ports and for a result of more than MAX_EXPAND ports, each checked before the ports are made."""
    out: list[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        t = _TRK.match(part)
        if t:
            out.append(f"Trk{int(t.group(1))}")
        elif "-" in part:
            a, b = part.split("-", 1)
            ta, tb = _TRK.match(a), _TRK.match(b)
            if ta and tb:
                pre, lo, hi = "Trk", int(ta.group(1)), int(tb.group(1))
            else:
                ma, mb = _TOKEN.match(a), _TOKEN.match(b)
                if not (ma and mb) or ma.group(1) != mb.group(1) or ma.group(2).upper() != mb.group(2).upper():
                    raise ValueError(f"Portbereich nicht lesbar: {part}")
                pre, lo, hi = (ma.group(1) + "/" if ma.group(1) else "") + ma.group(2).upper(), int(ma.group(3)), int(mb.group(3))
            if hi - lo + 1 > MAX_RANGE:
                raise ValueError(f"Portbereich zu groß: {part} (höchstens {MAX_RANGE} Ports)")
            if len(out) + max(hi - lo + 1, 0) > MAX_EXPAND:
                raise ValueError(f"Portliste zu lang: mehr als {MAX_EXPAND} Ports")
            out += [f"{pre}{i}" for i in range(lo, hi + 1)]
            continue
        else:
            m = _TOKEN.match(part)
            if not m:
                raise ValueError(f"Port nicht lesbar: {part}")
            out.append((m.group(1) + "/" if m.group(1) else "") + m.group(2).upper() + m.group(3))
        if len(out) > MAX_EXPAND:
            raise ValueError(f"Portliste zu lang: mehr als {MAX_EXPAND} Ports")
    return out


def port_sort_key(p: str):
    t = _TRK.match(p)
    if t:
        return (1, "", 0, int(t.group(1)))
    m = _TOKEN.match(p)
    if not m:
        return (2, p, 0, 0)
    return (0, (m.group(1) or "") + "/" + m.group(2), 0, int(m.group(3)))


def compress_ports(ports) -> str:
    """['1','2','3','7','Trk1'] -> '1-3,7,Trk1'. Bereiche nie ueber Modul-/Stackgrenzen."""
    groups: dict[str, list[int]] = defaultdict(list)
    trks: list[int] = []
    for p in ports:
        t = _TRK.match(p)
        if t:
            trks.append(int(t.group(1)))
            continue
        m = _TOKEN.match(p)
        if not m:
            raise ValueError(f"Port nicht lesbar: {p}")
        groups[(m.group(1) + "/" if m.group(1) else "") + m.group(2).upper()].append(int(m.group(3)))
    parts = []
    for pre in sorted(groups):
        nums = sorted(set(groups[pre]))
        start = prev = nums[0]
        for n in nums[1:] + [None]:
            if n is not None and n == prev + 1:
                prev = n
                continue
            parts.append(f"{pre}{start}" if start == prev else f"{pre}{start}-{pre}{prev}")
            if n is not None:
                start = prev = n
    parts += [f"Trk{i}" for i in sorted(set(trks))]
    return ",".join(parts)


# ── Geheimnisse maskieren (Sicherungen, Befehls-Ausgaben) ─────────────────────
_SECRETS = [
    re.compile(r'(\b(?:encrypted-)?key(?:-string)?\s+)("[^"]*"|\S+)'),
    re.compile(r'(\bcommunity\s+)("[^"]*"|\S+)'),
    # SNMPv3 passphrases behind every protocol spelling: sha, sha1, sha256, sha-256, des, des56, 3des, aes, aes128, aes-256, ... (§6 (d))
    re.compile(r'(\b(?:auth|priv)\s+(?:md5|sha(?:-?\d+)?|des\d*|3des|aes(?:-?\d+)?)\s+)("[^"]*"|\S+)', re.I),
    re.compile(r'(\bpassword\s+(?:manager|operator|port-access)\b.*?\b(?:sha1|sha256|plaintext)\s+)("[^"]*"|\S+)'),
    # "key" in a command as netmiko writes it into a ReadTimeout, repr(re.escape(cmd)): key\\ <key>, up to the closing quote; so a
    # stored text keeps no RADIUS key that SwitchView no longer knows (a change row from before Phase 2, the key changed since)
    re.compile(r"(\bkey\\+\s+)([^\s']+)"),
    # Tabelle aus 'show radius': IP, Auth-Port, Acct-Port, DM/CoA, Time Window, Key im Klartext
    re.compile(r'(?m)^(\s*\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\d+\s+(?:Yes|No)\s+\d+\s+)(\S+)[ \t]*$'),
]


def mask_secrets(text: str, extra: list[str] | None = None) -> str:
    """text with every secret the patterns of _SECRETS find as "***", and every non-empty value of extra (the secrets SwitchView knows)
    as ***, each also in the forms a command takes in an exception text: re.escape(s), and that again as repr() shows it (netmiko's
    ReadTimeout says "Pattern not detected: {repr(re.escape(cmd))}"). The longest form goes first, so no rest of a secret stays that
    contains a shorter one."""
    for rx in _SECRETS:
        text = rx.sub(lambda m: m.group(1) + '"***"', text)
    forms = {f for s in extra or () if s for f in (s, re.escape(s), re.escape(s).replace("\\", "\\\\"))}
    for f in sorted(forms, key=len, reverse=True):
        text = text.replace(f, "***")
    return text


# ── running-config lesen ─────────────────────────────────────────────────────
def _empty_port() -> dict:
    return {"u": None, "t": [], "name": "", "en": True, "x": False, "m": False,
            "cl": None, "al": None, "xuv": None, "muv": None}


def _empty_vlan() -> dict:
    return {"name": "", "untagged": set(), "tagged": set(), "voice": False}


def _is_vid(tok: str) -> bool:
    """Is tok a VLAN ID 1..4094 as a switch writes it (ASCII digits, no leading zero)?"""
    return bool(_VID.fullmatch(tok)) and int(tok) <= 4094


def _num(tok: str) -> int | None:
    """tok as a number when it is 1 to 9 ASCII digits (a limit, a time window), otherwise None: int() would take other digits
    ("²".isdigit() is True, int("²") raises) and raises for very long ones."""
    return int(tok) if tok.isascii() and tok.isdigit() and len(tok) <= 9 else None


def _vlan_ranges(spec: str) -> list[tuple[int, int]]:
    """The VLAN list of an interface's 'untagged|tagged vlan <spec>': '10,20-22,x,0' -> [(10, 10), (20, 22)]. Each token is a VLAN ID
    (_is_vid) or a range a-b of two with a <= b; every other token is skipped (F5)."""
    out = []
    for tok in spec.split(","):
        a, dash, b = tok.partition("-")
        b = b if dash else a
        if _is_vid(a) and _is_vid(b) and int(a) <= int(b):
            out.append((int(a), int(b)))
    return out


def _aaa(st: dict, rest: str):
    """rest = 'authenticator', 'authenticator client-limit 2', 'mac-based addr-limit 2', ..."""
    w = rest.split()
    if not w:
        return
    kind, args = w[0], w[1:]
    if kind == "authenticator":
        if not args:
            st["x"] = True
        elif args[0] == "client-limit" and len(args) > 1 and _num(args[1]) is not None:
            st["cl"] = _num(args[1])
        elif args[0] == "unauth-vid" and len(args) > 1:
            st["xuv"] = args[1] if args[1] != "0" else None
    elif kind == "mac-based":
        if not args:
            st["m"] = True
        elif args[0] == "addr-limit" and len(args) > 1 and _num(args[1]) is not None:
            st["al"] = _num(args[1])
        elif args[0] == "unauth-vid" and len(args) > 1:
            st["muv"] = args[1] if args[1] != "0" else None


_PA_KEYWORDS = {"active", "addr-format", "client-limit", "unauth-vid", "auth-vid", "logoff-period", "quiet-period",
                "tx-period", "supplicant-timeout", "server-timeout", "max-requests", "reauth-period", "reauthenticate",
                "control", "addr-limit", "addr-moves", "unauth-period", "auth-order", "auth-priority", "gvrp-vlans"}


def parse_config(text: str) -> dict:
    """The running-config text as a dict (hostname, vlans, ports, trunks, radius, ...). A token it cannot use (a port list, a VLAN ID, a
    number) is skipped with its line or block, never raised. Every expansion counts against MAX_REFS: each port list from expand_ports,
    and in an interface block each line once per port, a VLAN line once per port and VLAN. Beyond it ValueError("Konfiguration zu groß:
    …") for the whole configuration (E23)."""
    vlans: dict[str, dict] = {}
    ports: dict[str, dict] = defaultdict(_empty_port)
    radius: dict[str, dict] = {}
    # SNMPv3 as the running-config names it: on or off, the users (never their passphrases) and the ver3 groups of each user
    snmpv3: dict = {"enabled": False, "users": [], "groups": {}}
    res = {"hostname": "", "primary_vlan": "1", "mgmt_vlan": None, "auth_active": False, "eap_radius": False,
           "login_radius": False, "addr_format": None, "trunks": {}}
    refs = 0

    def spend(n: int):
        nonlocal refs
        refs += n
        if refs > MAX_REFS:
            raise ValueError(f"Konfiguration zu groß: mehr als {MAX_REFS} Port-/VLAN-Einträge")

    def ports_of(spec: str) -> list[str] | None:
        """expand_ports(spec), None when it cannot be read; counted outside the try, so a per-line except never swallows the limit."""
        try:
            plist = expand_ports(spec)
        except ValueError:
            return None
        spend(len(plist))
        return plist

    ctx = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        indented = raw[:1] in (" ", "\t")
        if line == "exit":
            ctx = None
            continue
        if not indented:
            ctx = None
            m = re.fullmatch(r"vlan (\d+)", line)
            if m:
                if not _is_vid(m.group(1)):
                    ctx = ("skip", None)
                    continue
                ctx = ("vlan", m.group(1))
                vlans.setdefault(m.group(1), _empty_vlan())
                continue
            m = re.fullmatch(r"interface (\S+)", line)
            if m:
                plist = ports_of(m.group(1))
                ctx = ("skip", None) if plist is None else ("if", plist)
                continue
        if ctx and indented:
            if ctx[0] == "vlan":
                v = vlans[ctx[1]]
                if line.startswith("name "):
                    v["name"] = line[5:].strip().strip('"')
                elif line == "voice":
                    v["voice"] = True
                else:
                    m = re.fullmatch(r"(untagged|tagged) (\S+)", line)
                    if m:
                        v[m.group(1)].update(ports_of(m.group(2)) or ())
            elif ctx[0] == "if":
                plist = ctx[1]
                vm = re.fullmatch(r"(untagged|tagged) vlan (\S+)", line)
                ranges = _vlan_ranges(vm.group(2)) if vm else []
                spend(len(plist) * max(sum(b - a + 1 for a, b in ranges), 1))
                for p in plist:
                    st = ports[p]
                    if line.startswith("name "):
                        st["name"] = line[5:].strip().strip('"')
                    elif line == "disable":
                        st["en"] = False
                    elif line.startswith("aaa port-access "):
                        _aaa(st, line[len("aaa port-access "):])
                if plist:
                    for a, b in ranges:
                        for vid in range(a, b + 1):
                            vlans.setdefault(str(vid), _empty_vlan())[vm.group(1)].update(plist)
            continue
        # Top-Level-Zeilen
        if line.startswith("hostname "):
            res["hostname"] = line[9:].strip().strip('"')
        elif m := re.fullmatch(r"primary-vlan (\d+)", line):
            res["primary_vlan"] = m.group(1)
        elif m := re.fullmatch(r"management-vlan (\d+)", line):
            res["mgmt_vlan"] = m.group(1)
        elif m := re.fullmatch(r"trunk (\S+) (Trk\d+)(?: \S+)?", line, re.I):
            plist, n = ports_of(m.group(1)), _num(m.group(2)[3:])
            if plist is not None and n is not None:
                res["trunks"][f"Trk{n}"] = plist
        elif line == "aaa port-access authenticator active":
            res["auth_active"] = True
        elif line.startswith("aaa authentication port-access") and "eap-radius" in line:
            res["eap_radius"] = True
        elif re.match(r"aaa authentication (login|ssh|telnet|web|console)\b.*\bradius\b", line):
            res["login_radius"] = True
        elif m := re.fullmatch(r"aaa port-access mac-based addr-format (\S+)", line):
            res["addr_format"] = m.group(1)
        elif m := re.fullmatch(r"aaa port-access (authenticator|mac-based) (\S+)(?: (.*))?", line):
            kind, first, rest = m.group(1), m.group(2), m.group(3) or ""
            if first in _PA_KEYWORDS:
                continue
            for p in ports_of(first) or ():
                _aaa(ports[p], (kind + " " + rest).strip())
        elif m := re.match(r"radius-server host (\S+)(.*)$", line):
            h = radius.setdefault(m.group(1), {"key": False, "dyn": False, "time_window": None})
            rest = m.group(2)
            if re.search(r"\b(?:encrypted-)?key\b", rest):
                h["key"] = True
            if "dyn-authorization" in rest:
                h["dyn"] = True
            tw = re.search(r"time-window (\d+)", rest)
            if tw and _num(tw.group(1)) is not None:
                h["time_window"] = _num(tw.group(1))
        elif line == "snmpv3 enable":
            snmpv3["enabled"] = True
        elif m := re.fullmatch(r'snmpv3 user "?([^"\s]+)"?', line):
            if m.group(1) not in snmpv3["users"]:
                snmpv3["users"].append(m.group(1))
        elif m := re.fullmatch(r'snmpv3 group (\S+) user "?([^"\s]+)"? sec-model ver3', line):
            groups = snmpv3["groups"].setdefault(m.group(2), [])
            if m.group(1).lower() not in groups:
                groups.append(m.group(1).lower())

    # Every VLAN key is a VLAN ID (_is_vid), so int() below cannot fail. The tagged VLANs of a port are collected in a set (a list
    # with "vid not in" made this quadratic: 9 s of CPU for 100 ports x 4000 VLANs), then sorted by number.
    tagged: dict[str, set[str]] = defaultdict(set)
    for vid, v in vlans.items():
        for p in v["untagged"]:
            ports[p]["u"] = vid
        for p in v["tagged"]:
            tagged[p].add(vid)
            ports[p]["t"] = tagged[p]
    for st in ports.values():
        st["t"] = sorted(st["t"], key=int)
        if st["m"] and st["al"] is None:  # addr-limit 1 ist Standard und steht nicht in der Konfiguration
            st["al"] = 1
    res["vlans"] = {vid: v["name"] for vid, v in sorted(vlans.items(), key=lambda kv: int(kv[0]))}
    res["voice_vlans"] = [vid for vid, v in vlans.items() if v["voice"]]
    res["radius"] = radius
    res["snmpv3"] = snmpv3
    res["ports"] = dict(ports)
    return res


def port_state(cfg: dict, port: str) -> dict:
    st = _empty_port()
    st.update(cfg.get("ports", {}).get(port) or {})
    st["t"] = list(st["t"])
    return st
