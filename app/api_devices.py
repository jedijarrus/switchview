"""The devices API: the device database (with its PacketFence sync), the unknown devices the switches have learned, and the
PacketFence roles and test. Split from main.py (Phase 3, Task 11), the code as it was. Since Phase 4c (Task 10) the triage: each
unknown device with a suggestion (triage.suggest), its first sighting and whether it is new; several devices or a CSV list released
through one route with a preview (import_devices); and the re-evaluation of one MAC by PacketFence (reevaluate_device)."""
import json
import re
import time
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import auth
import csvout
import history
import names as names_mod
import pf
import roles
import triage
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


def _valid_until(body) -> str | None:
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
NEW_HOURS = 24         # an unknown device is "new" this long after its first sighting


async def roles_by_kind() -> dict[str, tuple[str, int]]:
    """Per device type the PacketFence role its released devices with a role have most, with their number; of a tie the
    alphabetically first. What a suggestion names as the role (triage.suggest): the roles are called differently in every
    PacketFence, the own device database knows them."""
    async with db() as conn:
        async with conn.execute("SELECT kind, role, count(*) AS n FROM devices WHERE allowed = 1 AND role <> '' GROUP BY kind, role "
                                "ORDER BY n, role DESC") as cur:
            return {r["kind"]: (r["role"], r["n"]) for r in await cur.fetchall()}    # the last row of a kind stays: most, then first


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
    kinds = await roles_by_kind()
    out = []
    for s in m["switches"]:
        nac = "nac" in s["caps"] and s["ssh"]    # SwitchView sets the port mode of this switch (as the port table offers it)
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
                e = {"mac": r["mac"], "vlan": r["vlan"], "ip": r["ip"] or "", "name": r["name"] or "",
                     "vendor": r["vendor"] or names_mod.vendor_of(r["mac"]), "sw": s["k"], "sid": s["id"], "port": p["n"],
                     "st": p["st"], "flags": flags, "lldp": p["l"][0][0] if p["l"] else "", "mc": p["mc"], "poe": p.get("poe")}
                # The triage (Phase 4c): asked with the vendor of the ARP table alone, so a vendor triage finds by the prefix says so
                e["suggest"] = triage.suggest(e | {"vendor": r["vendor"] or ""}, p, kinds, nac=nac)
                out.append(e)
    # The first sighting from the history (the rows history.record writes) and "new": first seen in the last NEW_HOURS hours and
    # after the first recording of its switch (the stock a switch brings at its first poll is not new)
    first, base = await history.first_seen({e["mac"] for e in out}), await history.baselines()
    recent = (datetime.now(timezone.utc) - timedelta(hours=NEW_HOURS)).strftime(history.TIME)
    for e in out:
        seen = e["first_seen"] = first.get(e["mac"])
        e["new"] = bool(seen and seen > recent and seen > base.get(e["sid"], seen))
    # Two stable sorts: the latest first sighting first (none last), then unflagged before flagged and in each the new ones first;
    # equal entries stay in poll order, and the cap keeps the newest
    out.sort(key=lambda e: e["first_seen"] or "", reverse=True)
    out.sort(key=lambda e: (bool(e["flags"]), not e["new"]))
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


# ── Triage: several devices or a CSV list in one go, and the re-evaluation of one MAC (Phase 4c, Task 10) ─────────────────────────
KIND_PATTERN = "^(" + "|".join(KINDS) + ")$"
IMPORT_ONE_OF = "Entweder eine CSV-Liste oder ausgewählte Geräte schicken"
IMPORT_TOO_MANY = f"Höchstens {triage.IMPORT_MAX} Zeilen je Import"
IMPORT_ERRORS = "Die Liste hat {n} – nichts übernommen"
BAD_MAC = "MAC-Adresse ungültig"
TWICE = "doppelt (wie Zeile {line})"
EXISTS = "schon in der Datenbank – bleibt, wie es ist"
NO_ROLE = "Rolle „{role}“ gibt es in PacketFence nicht"
FORMULA_NAME = "Name beginnt wie eine Formel (= + - @)"
LONG_NAME = "Name zu lang (höchstens 64 Zeichen)"
BAD_KIND = "Typ „{kind}“ unbekannt"
ROLES_UNCHECKED = "Rollen nicht geprüft: {why}"
PF_OFF = "PacketFence-API ist nicht eingerichtet"
REEVAL_FAILED = "Neubewertung (CoA) fehlgeschlagen: {why}"
NAME_MAX = 64          # as DeviceIn.name


class ImportRow(BaseModel):
    mac: str = Field(max_length=40)
    name: str = Field(default="", max_length=200)
    role: str = Field(default="", max_length=64)
    kind: str = Field(default="", max_length=20)


class DeviceImportIn(BaseModel):
    """Several devices to release: rows (the devices picked in the lists) or csv (a list "MAC;Rolle;Name;Typ"), never both; kind
    and role for a row without its own, valid_until for all; dry_run (the default) only checks."""
    rows: list[ImportRow] = Field(default_factory=list, max_length=triage.IMPORT_MAX)
    csv: str | None = Field(default=None, max_length=50000)
    kind: str = Field(default="sonstiges", pattern=KIND_PATTERN)
    role: str = Field(default="", max_length=64)
    valid_until: str | None = Field(default=None, pattern=r"^(\d{4}-\d{2}-\d{2})?$")
    dry_run: bool = True


async def _known_roles() -> tuple[set[str] | None, str | None]:
    """The names of PacketFence's roles and None; without PacketFence set up, or when it does not answer, None and the note that
    says why the roles of an import are not checked."""
    if not await pf.configured():
        return None, ROLES_UNCHECKED.format(why=PF_OFF)
    try:
        return {r["name"] for r in await pf.roles()}, None
    except Exception as e:  # noqa: BLE001
        return None, ROLES_UNCHECKED.format(why=str(e)[:200] or type(e).__name__)


def _checked_rows(raw: list[dict], body: DeviceImportIn, existing: set[str], arp: dict[str, tuple[str, str]], known_roles: set[str] | None) -> list[dict]:
    """The rows of an import as its answer lists them: each of raw (line, mac, role, name, kind as sent) with what would be stored
    (the MAC normalized; role and kind of the request for a row without its own; without a name the one of the ARP table up to its
    first dot, else "<vendor or Gerät> <the last three bytes of the MAC>") and its status: "error" with the reason (no MAC, a MAC
    of an earlier row, an unknown type, a name that starts like a formula or is too long, a role PacketFence does not have),
    "exists" for a device of the database (it stays as it is), else "ok". arp: MAC -> (name, vendor) of the ARP table."""
    out, lines = [], {}    # lines: MAC -> the line that named it first
    for r in raw:
        mac = triage.mac_of(r["mac"])
        row = {"line": r["line"], "mac": mac or r["mac"], "name": triage.unformula(r["name"].strip()), "role": r["role"].strip() or body.role.strip(),
               "kind": r["kind"].strip().lower() or body.kind, "status": "ok", "reason": ""}
        out.append(row)
        if mac is None:
            reason = BAD_MAC
        elif mac in lines:
            reason = TWICE.format(line=lines[mac])
        else:
            lines[mac] = r["line"]
            if mac in existing:
                row |= {"status": "exists", "reason": EXISTS}
                continue
            if not row["name"]:
                arp_name, arp_vendor = arp.get(mac, ("", ""))
                row["name"] = (arp_name.split(".")[0] or f"{triage.vendor_label(mac, arp_vendor)[0] or 'Gerät'} {mac[9:]}")[:NAME_MAX]
            if row["kind"] not in KINDS:
                reason = BAD_KIND.format(kind=row["kind"])
            elif row["name"].startswith(csvout.FORMULA):
                reason = FORMULA_NAME
            elif len(row["name"]) > NAME_MAX:
                reason = LONG_NAME
            elif known_roles is not None and row["role"] and row["role"] not in known_roles:
                reason = NO_ROLE.format(role=row["role"])
            else:
                continue
        row |= {"status": "error", "reason": reason}
    return out


async def sync_job(macs: list[str]) -> None:
    """The PacketFence sync of an import, after its answer (200 devices are 600 requests): pf.sync writes the state of each device
    (pf_state, as the list shows it; the nightly sync catches up on what failed), then the kept sessions go, as in _save_device."""
    await pf.sync(macs)
    _sessions["items"] = None


def schedule_sync(macs: list[str]) -> None:
    """sync_job(macs) as a date job of the one scheduler (jobs.scheduler, imported here: jobs imports half the app), now;
    misfire_grace_time None: a sync that starts late still runs."""
    from jobs import scheduler
    scheduler.add_job(sync_job, "date", args=[macs], misfire_grace_time=None)


@router.post("/api/devices/import")
async def import_devices(body: DeviceImportIn, user=Depends(auth.require(roles.AENDERN))):
    """Releases several devices in one go: the ones picked in the lists (rows) or a CSV list (csv), at most triage.IMPORT_MAX.
    With dry_run (the default) it only answers what would happen, per row. Else it stores, all or nothing: with a faulty row 422
    and nothing is stored; a device of the database stays as it is; every other row goes the way of one device (a devices row,
    released, the audit device_create, the PacketFence sync - in the background, sync_job - and the kept sessions dropped)."""
    if bool(body.rows) == (body.csv is not None):
        raise HTTPException(422, IMPORT_ONE_OF)
    from_csv = body.csv is not None
    raw = triage.parse_csv(body.csv) if from_csv else [{"line": i, **r.model_dump()} for i, r in enumerate(body.rows, 1)]
    if len(raw) > triage.IMPORT_MAX:
        raise HTTPException(422, IMPORT_TOO_MANY)
    vu = _valid_until(body)
    known_roles, note = await _known_roles()
    async with db() as conn:
        async with conn.execute("SELECT mac FROM devices") as cur:
            existing = {r["mac"] for r in await cur.fetchall()}
        async with conn.execute("SELECT mac, name, vendor FROM names") as cur:
            arp = {r["mac"]: (r["name"] or "", r["vendor"] or "") for r in await cur.fetchall()}
    rows = _checked_rows(raw, body, existing, arp, known_roles)
    count = lambda status: sum(1 for r in rows if r["status"] == status)    # noqa: E731
    answer = {"rows": rows, "ok": count("ok"), "exists": count("exists"), "errors": count("error"), "roles_checked": known_roles is not None,
              "note": note}
    if body.dry_run:
        return answer
    if answer["errors"]:
        n = answer["errors"]
        raise HTTPException(422, IMPORT_ERRORS.format(n="1 fehlerhafte Zeile" if n == 1 else f"{n} fehlerhafte Zeilen"))
    source = "CSV-Import" if from_csv else "Sammel-Freigabe"
    created = []
    async with db() as conn:    # one transaction: all rows or none
        for r in rows:
            if r["status"] != "ok":
                continue
            cur = await conn.execute("INSERT INTO devices(mac, name, kind, notes, role, allowed, valid_until, created_by, updated_at) "
                                     "VALUES (?,?,?,?,?,1,?,?,datetime('now')) ON CONFLICT (mac) DO NOTHING",
                                     (r["mac"], r["name"], r["kind"], source, r["role"], vu, user["username"]))
            if cur.rowcount:
                created.append(r)
            else:    # someone stored it since the check: it stays theirs
                r |= {"status": "exists", "reason": EXISTS}
        await conn.commit()
    for r in created:
        await audit(user["username"], "device_create", r["mac"], f"{r['name']} freigegeben=1 ({source})", role=user["role"])
    if created:
        _sessions["items"] = None    # as in _save_device; sync_job drops them again once PacketFence has the releases
        schedule_sync([r["mac"] for r in created])
    return answer | {"ok": count("ok"), "exists": count("exists"), "created": len(created)}


@router.post("/api/devices/{mac}/reevaluate")
async def reevaluate_device(mac: str, user=Depends(auth.require(roles.AENDERN))):
    """„Neu bewerten“: PacketFence re-evaluates the access of the MAC now (CoA), for a released device it parks anyway or one that
    does not switch over. 409 without PacketFence, 502 with its reason when it does not take it (a MAC it does not know); audited
    either way. Without a zone: a MAC belongs to no switch, like the device database."""
    mac = norm_mac(mac)
    if not await pf.configured():
        raise HTTPException(409, PF_OFF)
    why = await pf.reevaluate(mac)
    await audit(user["username"], "device_reevaluate", mac, why or "ok", role=user["role"])
    if why:
        raise HTTPException(502, REEVAL_FAILED.format(why=why))
    _sessions["items"] = None    # the port switches: the next GET /api/pf/sessions asks PacketFence anew
    return {"ok": True}


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


async def _open_sessions(fresh: bool = False) -> list[dict]:
    """pf.open_sessions, its answer reused for SESSIONS_TTL seconds unless fresh (a failure is not kept)."""
    if fresh or _sessions["items"] is None or time.monotonic() - _sessions["at"] > SESSIONS_TTL:
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
async def pf_sessions(fresh: bool = False, user=Depends(auth.require(roles.LESEN))):
    """Who is logged in on the LAN now, as PacketFence holds it (session_view of pf.open_sessions, at most SESSIONS_TTL seconds
    old; fresh: asked now, as the devices view does after a release until the device's session switched). Without PacketFence set up
    {"configured": False, "sessions": []}; when it does not answer, ok False with its reason."""
    if not await pf.configured():
        return {"configured": False, "ok": True, "sessions": []}
    try:
        items = await _open_sessions(fresh)
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
