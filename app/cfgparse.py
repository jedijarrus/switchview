"""running-config von ProCurve/ArubaOS-Switch lesen, Portlisten wandeln, Geheimnisse maskieren.

Grundlage: docs/procurve-cli-referenz.md (3.2). Der Parser versteht beide Schreibweisen fuer
Port-Access: globale Zeilen mit Portliste (15.x) und Zeilen im interface-Block (16.x).
"""
import re
from collections import defaultdict

_TOKEN = re.compile(r"^(?:(\d+)/)?([A-Za-z]?)(\d+)$")
_TRK = re.compile(r"(?i)^trk(\d+)$")


def expand_ports(spec: str) -> list[str]:
    """'1-3,7,A1-A2,Trk1' -> ['1','2','3','7','A1','A2','Trk1']"""
    out: list[str] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        t = _TRK.match(part)
        if t:
            out.append(f"Trk{int(t.group(1))}")
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ta, tb = _TRK.match(a), _TRK.match(b)
            if ta and tb:
                out += [f"Trk{i}" for i in range(int(ta.group(1)), int(tb.group(1)) + 1)]
                continue
            ma, mb = _TOKEN.match(a), _TOKEN.match(b)
            if not (ma and mb) or ma.group(1) != mb.group(1) or ma.group(2).upper() != mb.group(2).upper():
                raise ValueError(f"Portbereich nicht lesbar: {part}")
            pre = (ma.group(1) + "/" if ma.group(1) else "") + ma.group(2).upper()
            out += [f"{pre}{i}" for i in range(int(ma.group(3)), int(mb.group(3)) + 1)]
            continue
        m = _TOKEN.match(part)
        if not m:
            raise ValueError(f"Port nicht lesbar: {part}")
        out.append((m.group(1) + "/" if m.group(1) else "") + m.group(2).upper() + m.group(3))
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
    re.compile(r'(\b(?:encrypted-)?key\s+)("[^"]*"|\S+)'),
    re.compile(r'(\bcommunity\s+)("[^"]*"|\S+)'),
    re.compile(r'(\b(?:auth|priv)\s+(?:md5|sha\d*|des|aes\d*)\s+)("[^"]*"|\S+)', re.I),
    re.compile(r'(\bpassword\s+(?:manager|operator|port-access)\b.*?\b(?:sha1|sha256|plaintext)\s+)("[^"]*"|\S+)'),
    # Tabelle aus 'show radius': IP, Auth-Port, Acct-Port, DM/CoA, Time Window, Key im Klartext
    re.compile(r'(?m)^(\s*\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+\d+\s+(?:Yes|No)\s+\d+\s+)(\S+)[ \t]*$'),
]


def mask_secrets(text: str, extra: list[str] | None = None) -> str:
    for rx in _SECRETS:
        text = rx.sub(lambda m: m.group(1) + '"***"', text)
    for s in extra or []:
        if s:
            text = text.replace(s, "***")
    return text


# ── running-config lesen ─────────────────────────────────────────────────────
def _empty_port() -> dict:
    return {"u": None, "t": [], "name": "", "en": True, "x": False, "m": False,
            "cl": None, "al": None, "xuv": None, "muv": None}


def _aaa(st: dict, rest: str):
    """rest = 'authenticator', 'authenticator client-limit 2', 'mac-based addr-limit 2', ..."""
    w = rest.split()
    if not w:
        return
    kind, args = w[0], w[1:]
    if kind == "authenticator":
        if not args:
            st["x"] = True
        elif args[0] == "client-limit" and len(args) > 1 and args[1].isdigit():
            st["cl"] = int(args[1])
        elif args[0] == "unauth-vid" and len(args) > 1:
            st["xuv"] = args[1] if args[1] != "0" else None
    elif kind == "mac-based":
        if not args:
            st["m"] = True
        elif args[0] == "addr-limit" and len(args) > 1 and args[1].isdigit():
            st["al"] = int(args[1])
        elif args[0] == "unauth-vid" and len(args) > 1:
            st["muv"] = args[1] if args[1] != "0" else None


_PA_KEYWORDS = {"active", "addr-format", "client-limit", "unauth-vid", "auth-vid", "logoff-period", "quiet-period",
                "tx-period", "supplicant-timeout", "server-timeout", "max-requests", "reauth-period", "reauthenticate",
                "control", "addr-limit", "addr-moves", "unauth-period", "auth-order", "auth-priority", "gvrp-vlans"}


def parse_config(text: str) -> dict:
    vlans: dict[str, dict] = {}
    ports: dict[str, dict] = defaultdict(_empty_port)
    radius: dict[str, dict] = {}
    res = {"hostname": "", "primary_vlan": "1", "mgmt_vlan": None, "auth_active": False, "eap_radius": False,
           "login_radius": False, "addr_format": None, "trunks": {}}
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
                ctx = ("vlan", m.group(1))
                vlans.setdefault(m.group(1), {"name": "", "untagged": set(), "tagged": set(), "voice": False})
                continue
            m = re.fullmatch(r"interface (\S+)", line)
            if m:
                try:
                    ctx = ("if", expand_ports(m.group(1)))
                except ValueError:
                    ctx = ("skip", None)
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
                        try:
                            v[m.group(1)] |= set(expand_ports(m.group(2)))
                        except ValueError:
                            pass
            elif ctx[0] == "if":
                for p in ctx[1]:
                    st = ports[p]
                    if line.startswith("name "):
                        st["name"] = line[5:].strip().strip('"')
                    elif line == "disable":
                        st["en"] = False
                    elif line.startswith("aaa port-access "):
                        _aaa(st, line[len("aaa port-access "):])
                    else:
                        m = re.fullmatch(r"(untagged|tagged) vlan (\S+)", line)
                        if m:
                            for vid in re.split(r"[,]", m.group(2)):
                                if "-" in vid:
                                    a, b = vid.split("-", 1)
                                    ids = [str(i) for i in range(int(a), int(b) + 1)]
                                else:
                                    ids = [vid]
                                for i in ids:
                                    vlans.setdefault(i, {"name": "", "untagged": set(), "tagged": set(), "voice": False})[m.group(1)].add(p)
            continue
        # Top-Level-Zeilen
        if line.startswith("hostname "):
            res["hostname"] = line[9:].strip().strip('"')
        elif m := re.fullmatch(r"primary-vlan (\d+)", line):
            res["primary_vlan"] = m.group(1)
        elif m := re.fullmatch(r"management-vlan (\d+)", line):
            res["mgmt_vlan"] = m.group(1)
        elif m := re.fullmatch(r"trunk (\S+) (Trk\d+)(?: \S+)?", line, re.I):
            try:
                res["trunks"][f"Trk{int(m.group(2)[3:])}"] = expand_ports(m.group(1))
            except ValueError:
                pass
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
            try:
                plist = expand_ports(first)
            except ValueError:
                continue
            for p in plist:
                _aaa(ports[p], (kind + " " + rest).strip())
        elif m := re.match(r"radius-server host (\S+)(.*)$", line):
            h = radius.setdefault(m.group(1), {"key": False, "dyn": False, "time_window": None})
            rest = m.group(2)
            if re.search(r"\b(?:encrypted-)?key\b", rest):
                h["key"] = True
            if "dyn-authorization" in rest:
                h["dyn"] = True
            tw = re.search(r"time-window (\d+)", rest)
            if tw:
                h["time_window"] = int(tw.group(1))

    for vid, v in vlans.items():
        for p in v["untagged"]:
            ports[p]["u"] = vid
        for p in v["tagged"]:
            if vid not in ports[p]["t"]:
                ports[p]["t"].append(vid)
    for st in ports.values():
        st["t"] = sorted(st["t"], key=int)
        if st["m"] and st["al"] is None:  # addr-limit 1 ist Standard und steht nicht in der Konfiguration
            st["al"] = 1
    res["vlans"] = {vid: v["name"] for vid, v in sorted(vlans.items(), key=lambda kv: int(kv[0]))}
    res["voice_vlans"] = [vid for vid, v in vlans.items() if v["voice"]]
    res["radius"] = radius
    res["ports"] = dict(ports)
    return res


def port_state(cfg: dict, port: str) -> dict:
    st = _empty_port()
    st.update(cfg.get("ports", {}).get(port) or {})
    st["t"] = list(st["t"])
    return st
