"""The devices API: the device database (with its PacketFence sync), the unknown devices the switches have learned, and the
PacketFence roles and test. Split from main.py (Phase 3, Task 11), the code as it was."""
import json
import re
import time
from collections import defaultdict
from datetime import date

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import auth
import names as names_mod
import pf
import roles
from db import audit, db
from topology import build_map, device_port, switch_keys

router = APIRouter()


# ── Geraete-Datenbank ─────────────────────────────────────────────────────────
KINDS = ("drucker", "telefon", "kamera", "iot", "zugang", "server", "netzwerk", "sonstiges")


def norm_mac(v: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", v or "").lower()
    if len(h) != 12:
        raise HTTPException(422, "MAC-Adresse ungültig")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


class DeviceIn(BaseModel):
    mac: str = Field(max_length=20)
    name: str = Field(min_length=1, max_length=64)
    kind: str = Field(default="sonstiges", pattern=r"^(drucker|telefon|kamera|iot|zugang|server|netzwerk|sonstiges)$")
    location: str = Field(default="", max_length=64)
    owner: str = Field(default="", max_length=64)
    notes: str = Field(default="", max_length=500)
    role: str = Field(default="", max_length=64)
    allowed: bool = False
    valid_until: str | None = Field(default=None, pattern=r"^(\d{4}-\d{2}-\d{2})?$")    # null or "": no expiry date


def _valid_until(body: DeviceIn) -> str | None:
    """body.valid_until as stored: None for no expiry date (null or ""), else the date; 422 for one that has the format of a date but
    is none (2026-13-45, 0000-00-00, 2026-02-30): pf compares it as text with today's date and hands it to PacketFence as the
    node's unregdate, so an impossible one would end the release at a point nobody chose."""
    if not body.valid_until:
        return None
    try:
        date.fromisoformat(body.valid_until)
    except ValueError:
        raise HTTPException(422, "Gültig bis: kein gültiges Datum (JJJJ-MM-TT)") from None
    return body.valid_until


@router.get("/api/devices")
async def list_devices(user=Depends(auth.require(roles.LESEN))):
    async with db() as conn:
        async with conn.execute("SELECT * FROM devices ORDER BY name COLLATE NOCASE") as cur:
            devs = [dict(r) for r in await cur.fetchall()]
        async with conn.execute("SELECT m.mac, m.port, m.vlan, m.last_seen, s.name AS sw, p.mac_count, p.trunk, n.ip, n.name AS hn FROM macs m "
                                "JOIN devices d ON d.mac = m.mac JOIN switches s ON s.id = m.switch_id "
                                "LEFT JOIN ports p ON p.switch_id = m.switch_id AND p.name = m.port LEFT JOIN names n ON n.mac = m.mac") as cur:
            seen = await cur.fetchall()
    best: dict[str, dict] = {}
    # Zugangsport = kein Trunk (Trk, LAG oder ein Mitglied: dort lernt ein Uplink die MACs eines ganzen Switches), dann der Port mit
    # den wenigsten MACs
    rank = lambda r: (bool(str(r["port"]).startswith("Trk") or r["trunk"]), r["mac_count"] or 999)    # noqa: E731
    for r in seen:
        b = best.get(r["mac"])
        if not b or rank(r) < rank(b):
            best[r["mac"]] = dict(r)
    for d in devs:
        d["seen"] = best.get(d["mac"])
        d["vendor"] = names_mod.vendor_of(d["mac"])
    return devs


UNKNOWN_PER_PORT = 12  # unknown devices listed per port: a flood shows its port (flag "many" with its count), not thousands of rows


@router.get("/api/devices/unknown")
async def unknown_devices(user=Depends(auth.require(roles.LESEN))):
    m = await build_map()
    async with db() as conn:
        # Every unregistered device each port has learned, not build_map's display list "d": that one holds twelve devices per port,
        # registered ones first, so twelve registered devices or a flood ahead of a device in poll order kept it off this list.
        async with conn.execute("SELECT m.switch_id, m.port, m.mac, m.vlan, n.ip, n.name, n.vendor FROM macs m LEFT JOIN names n "
                                "ON n.mac = m.mac WHERE m.mac NOT IN (SELECT mac FROM devices) ORDER BY m.rowid") as cur:
            rows = await cur.fetchall()
    base = {s["baseMac"] for s in m["switches"]}
    learned: dict[tuple, list] = defaultdict(list)
    for r in rows:
        if r["mac"] not in base:
            learned[(r["switch_id"], r["port"])].append(r)
    keys = switch_keys(m["switches"])
    out = []
    for s in m["switches"]:
        for p in s["ports"]:
            # F3: only trunks and confirmed uplinks are skipped (topology.device_port, which history.record takes as well). An LLDP
            # frame or a MAC flood on an access port no longer hides the devices behind it; such entries are flagged and listed after
            # the unflagged ones, so they push no one past the cap.
            if not device_port(p):
                continue
            # One of the two uplink flags wherever the port table shows "Uplink (unbestätigt)" (sv-core.js isUnconfirmedUplink;
            # changes.inventory's backstop protects such ports). "uplink_lldp" keeps its name for the API, though it covers more than
            # LLDP: an uplink nobody confirms (up, so not uc here; an LLDP or a MAC link), or no link while an LLDP neighbour is a
            # managed switch (isPeer). "uplink_bm": no link and no such neighbour, an uplink only by the base MAC of another managed
            # switch learned on the port ("bm"; Phase 3 Task 9).
            peer = any(e[0] in keys for e in p["l"])
            flags = [f for f, on in (("uplink_lldp", p.get("up") or peer), ("uplink_bm", p["bm"] and not (p.get("up") or peer)),
                                     ("lldp", p["l"]), ("many", p["mc"] > 4)) if on]
            # Of a port's devices, those the router knows (an IP or a name) come first, then poll order: a heuristic. A flood of made-up
            # MACs mostly has no ARP entry, but a flooder can send ARP for each of them, so this only makes it harder to push a known
            # device past the cap.
            ds = sorted(learned.get((s["id"], p["n"]), []), key=lambda r: not (r["ip"] or r["name"]))
            for r in ds[:UNKNOWN_PER_PORT]:
                out.append({"mac": r["mac"], "vlan": r["vlan"], "ip": r["ip"] or "", "name": r["name"] or "",
                            "vendor": r["vendor"] or names_mod.vendor_of(r["mac"]), "sw": s["k"], "sid": s["id"], "port": p["n"],
                            "st": p["st"], "flags": flags, "lldp": p["l"][0][0] if p["l"] else "", "mc": p["mc"]})
    out.sort(key=lambda e: bool(e["flags"]))  # stable: poll order within each group
    return out[:500]


async def _save_device(body: DeviceIn, user: dict, mac: str, create: bool):
    """Creates (create) or updates the device mac from body for the signed-in user, syncs it to PacketFence and audits it."""
    vu = _valid_until(body)
    async with db() as conn:
        if create:
            try:
                await conn.execute("INSERT INTO devices(mac, name, kind, location, owner, notes, role, allowed, valid_until, created_by, updated_at) "
                                   "VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))",
                                   (mac, body.name.strip(), body.kind, body.location.strip(), body.owner.strip(), body.notes.strip(),
                                    body.role.strip(), int(body.allowed), vu, user["username"]))
            except Exception as e:  # noqa: BLE001
                if "UNIQUE" in str(e):
                    raise HTTPException(409, "Dieses Gerät ist schon in der Datenbank")
                raise
        else:
            cur = await conn.execute("UPDATE devices SET name=?, kind=?, location=?, owner=?, notes=?, role=?, allowed=?, valid_until=?, "
                                     "updated_at=datetime('now') WHERE mac=?",
                                     (body.name.strip(), body.kind, body.location.strip(), body.owner.strip(), body.notes.strip(),
                                      body.role.strip(), int(body.allowed), vu, mac))
            if cur.rowcount == 0:
                raise HTTPException(404, "Gerät nicht gefunden")
        await conn.commit()
    res = await pf.sync([mac])
    _sessions["items"] = None    # PacketFence bounces the port: the next GET /api/pf/sessions asks it anew
    await audit(user["username"], "device_create" if create else "device_update", mac, f"{body.name} freigegeben={int(body.allowed)}",
                role=user["role"])
    return {"ok": True, "pf": res}


@router.post("/api/devices")
async def create_device(body: DeviceIn, user=Depends(auth.require(roles.AENDERN))):
    return await _save_device(body, user, norm_mac(body.mac), True)


@router.put("/api/devices/{mac}")
async def update_device(mac: str, body: DeviceIn, user=Depends(auth.require(roles.AENDERN))):
    mac = norm_mac(mac)
    if norm_mac(body.mac) != mac:    # the form never sends another one; saving it under the path's MAC would hide the mismatch
        raise HTTPException(422, "MAC-Adresse im Formular passt nicht zum Gerät")
    return await _save_device(body, user, mac, False)


@router.delete("/api/devices/{mac}")
async def delete_device(mac: str, user=Depends(auth.require(roles.AENDERN))):
    mac = norm_mac(mac)
    try:    # PacketFence has to confirm reading and unregistering the node, else the device stays; a failed CoA is only a warning
        warning = await pf.unregister(mac)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"In PacketFence nicht zurückgenommen ({e}). Gerät bleibt erhalten.")
    async with db() as conn:
        cur = await conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))
        await conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "Gerät nicht gefunden")
    await audit(user["username"], "device_delete", mac, warning or "", role=user["role"])
    _sessions["items"] = None    # as in _save_device
    return {"ok": True, "warning": warning}


@router.post("/api/devices/sync")
async def sync_devices(user=Depends(auth.require(roles.AENDERN))):
    res = await pf.sync()
    await audit(user["username"], "device_sync", "", json.dumps(res), role=user["role"])
    return res


@router.get("/api/pf/roles")
async def pf_roles(user=Depends(auth.require(roles.LESEN))):
    if not await pf.configured():
        return {"configured": False, "roles": []}
    try:
        return {"configured": True, "roles": await pf.roles()}
    except Exception as e:  # noqa: BLE001
        return {"configured": True, "roles": [], "error": str(e)[:200]}


@router.post("/api/pf/test")
async def pf_test(user=Depends(auth.require(roles.LESEN))):
    return await pf.test()


# ── Anmeldungen: who is logged in on the LAN now, as PacketFence holds it (docs/anmeldungen.md) ──────────────────────────────────
SESSIONS_TTL = 60.0     # seconds an answer of PacketFence is reused (the switch view and the devices view ask at each render)
_sessions: dict = {"at": 0.0, "items": None}


def _mac_or_none(v) -> str | None:
    h = re.sub(r"[^0-9a-fA-F]", "", str(v or "")).lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


async def _open_sessions() -> list[dict]:
    """pf.open_sessions, its answer reused for SESSIONS_TTL seconds (a failure is not kept)."""
    if _sessions["items"] is None or time.monotonic() - _sessions["at"] > SESSIONS_TTL:
        _sessions["items"] = await pf.open_sessions()
        _sessions["at"] = time.monotonic()
    return _sessions["items"]


def session_view(items: list[dict], switches: list[dict], ports: list[dict], devices: dict[str, str]) -> list[dict]:
    """The sessions of PacketFence (pf.open_sessions) as the views show them: per session the MAC, how (dot1x: 802.1X, mac: a MAC
    login), park (in the park role), the user of an 802.1X login, role, VLAN, since (PacketFence's clock), the switch SwitchView knows
    under the base MAC PacketFence names, else under its address (switch_id and switch_name; None and the address without one), the
    port by name (ifDesc when the switch has such a port, else the port of that ifIndex, else as PacketFence names it) and the name of
    the device of that MAC in the database (device, "" without one); sorted by switch, port and MAC."""
    by_mac = {_mac_or_none(s["base_mac"]): s for s in switches if _mac_or_none(s["base_mac"])}
    by_host = {str(s["host"]).strip().lower(): s for s in switches}
    names = {(p["switch_id"], p["name"]) for p in ports}
    by_index = {(p["switch_id"], str(p["ifindex"])): p["name"] for p in ports}
    out = []
    for x in items:
        mac = _mac_or_none(x.get("mac"))
        if not mac:
            continue
        sw = by_mac.get(_mac_or_none(x.get("switch_mac"))) or by_host.get(str(x.get("switch_ip") or x.get("switch") or "").strip().lower())
        sid = sw["id"] if sw else None
        desc, idx = str(x.get("ifDesc") or ""), str(x.get("port") or "")
        port = desc if (sid, desc) in names else by_index.get((sid, idx)) or desc or idx
        eap = x.get("connection_type") == "Ethernet-EAP"
        out.append({"mac": mac, "how": "dot1x" if eap else "mac", "park": x.get("role") == pf.PARK_ROLE,
                    "user": str(x.get("dot1x_username") or "") if eap else "", "role": str(x.get("role") or ""), "vlan": str(x.get("vlan") or ""),
                    "since": str(x.get("start_time") or ""), "switch_id": sid,
                    "switch_name": sw["name"] if sw else str(x.get("switch_ip") or x.get("switch") or ""), "port": port,
                    "device": devices.get(mac, "")})
    nat = lambda p: [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", p)]    # noqa: E731 - port 2 before port 10
    return sorted(out, key=lambda s: (s["switch_name"].lower(), nat(s["port"]), s["mac"]))


@router.get("/api/pf/sessions")
async def pf_sessions(user=Depends(auth.require(roles.LESEN))):
    """Who is logged in on the LAN now, as PacketFence holds it (session_view of pf.open_sessions, at most SESSIONS_TTL seconds
    old). Without PacketFence set up {"configured": False, "sessions": []}; when it does not answer, ok False with its reason."""
    if not await pf.configured():
        return {"configured": False, "ok": True, "sessions": []}
    try:
        items = await _open_sessions()
    except Exception as e:  # noqa: BLE001
        return {"configured": True, "ok": False, "error": str(e)[:200] if isinstance(e, RuntimeError) else f"{type(e).__name__}: {str(e)[:160]}",
                "sessions": []}
    async with db() as conn:
        async with conn.execute("SELECT id, name, host, base_mac FROM switches") as cur:
            switches = [dict(r) for r in await cur.fetchall()]
        async with conn.execute("SELECT switch_id, ifindex, name FROM ports") as cur:
            ports = [dict(r) for r in await cur.fetchall()]
        async with conn.execute("SELECT mac, name FROM devices") as cur:
            devices = {r["mac"]: r["name"] for r in await cur.fetchall()}
    return {"configured": True, "ok": True, "sessions": session_view(items, switches, ports, devices)}
