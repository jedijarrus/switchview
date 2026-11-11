"""The triage of unknown devices (Phase 4c, Task 10): what a device probably is. Without a database; it imports api_changes only
for STATUS_LABEL (Ruling 5).

suggest gives an entry of the list of unknown devices (api_devices.unknown_devices) a suggestion: the device type of the device
database, the PacketFence role released devices of that type have most (the caller counts them: api_devices.roles_by_kind) and the
port mode "Bekannte Geräte" as a hint. It reads only what SwitchView has already: the vendor (the ARP table, else the prefix of
the MAC in OUI, else names.vendor_of), the name, the LLDP text of the port (only at a port with exactly one learned device: at a
port with a phone and a PC behind it the LLDP is the phone's) and the PoE of the port. Each of vendor, name and LLDP gives its type
2 points; a port that delivers power gives a phone, a camera or an access point 1 more, only if that type has a vote already. A
type needs 2 points, a tie goes by KIND_ORDER. LLDP capabilities are not read (the poll does not have them). A suggestion is a
hint: nothing here writes, and nothing applies a suggestion by itself.

parse_csv reads the list of an import (POST /api/devices/import): MAC, role, name and type per line, as people send it.
"""
import csv
import re

import names
from api_changes import STATUS_LABEL
from csvout import FORMULA

# The prefixes (MA-L) of vendors whose devices are mostly of one type, by vendor; checked against the IEEE registry
# (/usr/share/ieee-data/oui.csv) on 2026-11-08. Small on purpose: a hint, not a device database.
_PREFIXES = {
    "Yealink": "80:5e:c0 80:5e:0c 24:9a:d8 00:15:65", "Polycom": "64:16:7f 00:04:f2", "snom": "00:04:13",
    "Grandstream": "c0:74:ad 00:0b:82 ec:74:d7", "Gigaset": "7c:2f:80 58:9e:c6 00:21:04", "Mitel": "08:00:0f 14:00:e9 00:08:5d",
    "Avaya": "c8:1f:ea bc:ad:ab fc:a8:41 3c:b1:5b 34:75:c7",
    "Brother": "00:80:77 00:1b:a9 3c:2a:f4 30:05:5c b4:22:00", "Ricoh": "58:38:79 00:26:73 00:00:74",
    "Lexmark": "00:21:b7 00:20:00 78:8c:77 00:04:00 00:84:ed", "Kyocera": "d4:f0:c9", "Xerox": "00:00:aa 9c:93:4e",
    "Konica Minolta": "00:50:aa 08:00:86 00:20:6b", "Canon": "84:ba:3b 60:12:8b 74:38:b7 00:bb:c1 f4:81:39",
    "Epson": "50:57:9c 00:26:ab a4:d7:3c 64:eb:8c 38:1a:52",
    "Axis": "b8:a4:4f 00:40:8c ac:cc:8e", "Mobotix": "00:03:c5", "Hikvision": "44:47:cc 58:03:fb 94:e1:ac 64:db:8b bc:ad:28 c0:56:e3",
    "Dahua": "08:ed:ed 6c:1c:71 74:c9:29 24:52:6a e0:50:8b",
    "Ubiquiti": "74:83:c2 e0:63:da 80:2a:a8 f0:9f:c2 78:8a:20", "Aruba": "88:3a:30 00:0b:86 d8:c7:c8 70:3a:0e 20:4c:03",
    "Cisco Meraki": "88:15:44 a8:46:9d 6c:de:a9 0c:8d:db cc:03:d9", "Ruckus": "60:d0:2c 34:fa:9f e8:1d:a8 94:f6:65 ac:67:06",
    "LANCOM": "00:a0:57",
}
OUI: dict[str, str] = {prefix: vendor for vendor, prefixes in _PREFIXES.items() for prefix in prefixes.split()}

# A part of a vendor's name (lower case) -> the type its devices mostly are
VENDOR_KIND: dict[str, str] = (
    dict.fromkeys(("yealink", "polycom", "snom", "grandstream", "gigaset", "mitel", "avaya"), "telefon")
    | dict.fromkeys(("brother", "ricoh", "lexmark", "kyocera", "xerox", "konica", "canon", "epson"), "drucker")
    | dict.fromkeys(("axis", "mobotix", "hikvision", "dahua"), "kamera")
    | dict.fromkeys(("ubiquiti", "aruba", "meraki", "ruckus", "lancom"), "netzwerk"))
# What a name or an LLDP text of a type looks like
NAME_HINTS: dict[str, re.Pattern] = {
    "telefon": re.compile(r"\b(sep[0-9a-f]{12}|sip-?t\d+\w*|yealink|polycom|vvx\s?\d+|snom|gigaset|grandstream|gxp\d+|avaya|mitel|ip ?phone|telefon)\b", re.I),
    "drucker": re.compile(r"\b(npi[0-9a-f]{6}|brn[0-9a-f]{12}|brw[0-9a-f]{12}|laserjet|officejet|ecosys|taskalfa|bizhub|printer|drucker|mfp)\b", re.I),
    "kamera": re.compile(r"\b(axis-[0-9a-f]{12}|ipcam|camera|kamera|hikvision|dahua|mobotix)\b", re.I),
    "netzwerk": re.compile(r"\b(uap\S*|unifi|access ?point|aruba-?ap\S*|meraki|ruckus|lancom)\b", re.I),
}
KIND_ORDER = ("telefon", "drucker", "kamera", "netzwerk")    # the types a suggestion can name; a tie goes to the earlier one
KIND_LABEL = {"telefon": "Telefon", "drucker": "Drucker", "kamera": "Kamera", "netzwerk": "Netzwerkgerät"}    # as the devices view names them
POE_KINDS = {"telefon", "kamera", "netzwerk"}                # the types a port mostly powers
KNOWN_MODE = {"telefon", "drucker", "kamera", "netzwerk"}    # devices that mostly cannot do 802.1X: the port mode "Bekannte Geräte"
IMPORT_MAX = 200                                             # rows of one import

POE_REASON = "PoE: liefert Strom"
POE_HINT = "Gerät mit PoE – Telefon, Kamera oder Access Point?"
PORT_HINT = "Port steht auf „{state}“: eine Freigabe wirkt erst an einem Port „Bekannte Geräte“ oder „RADIUS“"
DELIVERING = 3    # pethPsePortDetectionStatus deliveringPower (RFC 3621), the "status" of a port's "poe" in topology.build_map


def vendor_label(mac: str, vendor: str) -> tuple[str, bool]:
    """The vendor of a device and whether it comes from the prefix of its MAC: vendor (the one of the ARP table) with False; else
    the one of OUI, else names.vendor_of, each with True; ("", False) without any."""
    if vendor:
        return vendor, False
    label = OUI.get(mac[:8].lower()) or names.vendor_of(mac)
    return label, bool(label)


def suggest(entry: dict, port: dict | None, roles_by_kind: dict[str, tuple[str, int]], nac: bool) -> dict:
    """The suggestion for entry (its mac, name, vendor of the ARP table, lldp, mc and st, as the list of unknown devices has them)
    at port (the port of topology.build_map, None without one): kind (one of KIND_ORDER or None), label (KIND_LABEL), role and
    role_count (roles_by_kind of the kind: the role released devices of it have most, and how many; None and 0 without one),
    port_mode ("known" for a kind of KNOWN_MODE), why (the German reasons that speak for the kind, in the order vendor, name, LLDP,
    PoE; without a kind only the PoE, if the port delivers) and hint (None, or: a port that delivers power without a kind; a port
    of a switch with nac that asks nobody, where a release has no effect)."""
    votes: dict[str, list[str]] = {}    # type -> the reasons of its 2-point signals
    label, from_prefix = vendor_label(entry["mac"], entry.get("vendor") or "")
    by_vendor = next((kind for word, kind in VENDOR_KIND.items() if word in label.lower()), None)
    if by_vendor:
        votes.setdefault(by_vendor, []).append(f"Hersteller {label}" + (" (MAC-Präfix)" if from_prefix else ""))
    texts = [("Name", entry.get("name") or ""), ("LLDP", (entry.get("lldp") or "") if entry.get("mc") == 1 else "")]
    for what, text in texts:
        for kind, pattern in NAME_HINTS.items():
            if text and pattern.search(text):
                votes.setdefault(kind, []).append(f"{what} „{text}“")
    powered = ((port or {}).get("poe") or {}).get("status") == DELIVERING
    points = {kind: 2 * len(reasons) + (1 if powered and kind in POE_KINDS else 0) for kind, reasons in votes.items()}
    kind = max((k for k in KIND_ORDER if k in points), key=lambda k: points[k], default=None)    # max keeps the first of a tie
    why = list(votes[kind]) if kind else []
    if powered and (kind is None or kind in POE_KINDS):
        why.append(POE_REASON)
    role, count = roles_by_kind.get(kind, (None, 0))
    mode = "known" if kind in KNOWN_MODE else None
    hint = None
    if kind is None and powered:
        hint = POE_HINT
    elif mode and nac and entry.get("st") not in ("known", "radius", "", None):
        hint = PORT_HINT.format(state=STATUS_LABEL.get(entry["st"], entry["st"]))
    return {"kind": kind, "label": KIND_LABEL.get(kind), "role": role, "role_count": count, "port_mode": mode, "why": why, "hint": hint}


def mac_of(text: str) -> str | None:
    """text as a MAC ("aa:bb:cc:dd:ee:ff") in any usual spelling, None when it is none."""
    h = re.sub(r"[^0-9a-fA-F]", "", text or "").lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


def unformula(text: str) -> str:
    """text without the "'" csvout.cell put before a cell that starts like a formula (so an export of SwitchView reads back as it
    was); any other text as it is."""
    return text[1:] if text.startswith("'") and text[1:].startswith(FORMULA) else text


def parse_csv(text: str) -> list[dict]:
    """The rows of an import list, each {"line", "mac", "role", "name", "kind"} with the cells as sent, trimmed (nothing checked): a
    BOM is dropped, an empty line skipped (it counts in line), the separator is ";" when the first line with content has one, else
    ",", a first line whose first cell is "mac" or "mac-adresse" is a header, and only the first four cells of a line count."""
    lines = [(n, line) for n, line in enumerate(text.removeprefix("\ufeff").splitlines(), 1) if line.strip()]
    if not lines:
        return []
    delimiter = ";" if ";" in lines[0][1] else ","
    rows = []
    for n, line in lines:
        cells = [c.strip() for c in next(csv.reader([line], delimiter=delimiter), [])]
        cells = (cells + [""] * 4)[:4]
        if n == lines[0][0] and cells[0].lower() in ("mac", "mac-adresse"):
            continue
        rows.append(dict(zip(("line", "mac", "role", "name", "kind"), [n, *cells])))
    return rows
