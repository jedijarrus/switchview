"""The history routes (Phase 4b): where a device was seen (Task 3: GET /api/history, the search; GET /api/history.csv, the same search
as a CSV download), the events (Task 4: GET /api/events), the security rules (Task 5: GET /api/switches/{sid}/findings, GET
/api/compliance, GET and PUT /api/compliance/rules) and the MAC watch list (Task 7: GET and POST /api/watch, DELETE
/api/watch/{mac}). The search and the watch list themselves are app/history.py, the CSV app/csvout.py, the events app/monitor.py,
the rules and their findings app/compliance.py.

Every read needs Lesen and is not limited by zone, like every read route of Phase 4a: zones limit changes only (roles.SCOPED), and a
place of a device belongs to no single switch. Changing the rules is Admin; the watch list is kept by Ändern, like the device
database, without a zone either: a MAC belongs to no switch.
"""
import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import api_devices
import auth
import compliance
import csvout
import history
import monitor
import roles
from db import audit, db, set_setting

log = logging.getLogger("switchview.history")
router = APIRouter()

CSV_HEADER = ["MAC", "Hersteller", "IP", "Name", "Switch", "Port", "VLAN", "Zuerst gesehen (UTC)", "Zuletzt gesehen (UTC)", "Möglicher Uplink"]


@router.get("/api/history")
async def search_history(q: str | None = Query(default=None, max_length=100), switch_id: int | None = None,
                         port: str | None = Query(default=None, max_length=100), cursor: str | None = Query(default=None, max_length=64),
                         limit: int = Query(default=50, ge=1, le=200), user=Depends(auth.require(roles.LESEN))):
    """One page of the sightings by a MAC, an IP or a name (q), or of a switch's port (switch_id and port), newest first:
    {"rows": [...], "next": the cursor of the next page or null}. 422 with the German text of history for a bad question or cursor."""
    try:
        return await history.search(q=q, switch_id=switch_id, port=port, cursor=cursor, limit=limit)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


@router.get("/api/history.csv")
async def export_history(q: str | None = Query(default=None, max_length=100), switch_id: int | None = None,
                         port: str | None = Query(default=None, max_length=100), user=Depends(auth.require(roles.LESEN))):
    """The same search as a CSV download (switchview-verlauf-<date>.csv), at most history.EXPORT_MAX rows; times in UTC, the last
    column "ja" for a row at a possible uplink."""
    try:
        rows = await history.export(q=q, switch_id=switch_id, port=port)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    return csvout.response(csvout.render(CSV_HEADER, ([r["mac"], r["vendor"], r["ip"], r["name"], r["switch"], r["port"], r["vlan"],
                                                       r["first_seen"], r["last_seen"], "ja" if r["suspect"] else ""] for r in rows)),
                           "switchview-verlauf")


ROW_ID_MAX = 2 ** 63 - 1    # the largest id SQLite stores: a larger number would fail in the query (OverflowError), not as a 422


@router.get("/api/events")
async def list_events(switch_id: int | None = Query(default=None, ge=1, le=ROW_ID_MAX), kind: str | None = Query(default=None, max_length=20),
                      since: str | None = Query(default=None, max_length=40), cursor: int | None = Query(default=None, ge=1, le=ROW_ID_MAX),
                      limit: int = Query(default=50, ge=1, le=200), user=Depends(auth.require(roles.LESEN))):
    """One page of the events, newest first: of one switch, of one kind or group (reach, lldp, drift), from since on (an ISO time,
    history.to_utc), before the id cursor: {"rows": [...], "next": the cursor of the next page or null}. 422 with the German text
    for an unknown kind or a time that is none."""
    try:
        return await monitor.list_events(switch_id=switch_id, kind=kind, since=None if since is None else history.to_utc(since),
                                         cursor=cursor, limit=limit)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


@router.get("/api/switches/{sid}/findings")
async def list_findings(sid: int, user=Depends(auth.require(roles.LESEN))):
    """The open findings of the switch's rules in force (compliance.open_findings), critical first; 404 for a switch that is not there."""
    async with db() as conn:
        async with conn.execute("SELECT 1 FROM switches WHERE id = ?", (sid,)) as cur:
            if await cur.fetchone() is None:
                raise HTTPException(404, "Switch nicht gefunden")
    return {"findings": await compliance.open_findings(sid)}


@router.get("/api/compliance")
async def compliance_summary(user=Depends(auth.require(roles.LESEN))):
    """The open findings over all switches for the overview (compliance.summary): {"total", "crit", "switches"}."""
    return await compliance.summary()


@router.get("/api/compliance/rules")
async def get_compliance_rules(user=Depends(auth.require(roles.LESEN))):
    """Every rule with its state (compliance.rules_view): the built-in ones, then the custom ones."""
    return await compliance.rules_view()


CUSTOM_MAX_NO = 999_999_999      # the largest number the id of a custom rule takes: the 9 digits of CustomRuleIn.id


class CustomRuleIn(BaseModel):
    """One custom rule of PUT /api/compliance/rules: its id as GET serves it (c<n>; none for a new one), a name, the mode ("must": a
    line has to contain the text, "must_not": none may) and the text (A1: plain text, no pattern)."""
    id: str | None = Field(default=None, pattern=r"^c[0-9]{1,9}$")
    name: str = Field(min_length=1, max_length=80)
    mode: str = Field(pattern=r"^(must|must_not)$")
    text: str = Field(min_length=1, max_length=200)


class RulesIn(BaseModel):
    off: list[Annotated[str, Field(max_length=40)]] = Field(max_length=20)
    custom: list[CustomRuleIn] = Field(max_length=50)


UNKNOWN_RULE = "Unbekannte Regel: {}"
NO_TEXT = "Eigene Regel ohne Text"
NO_NAME = "Eigene Regel ohne Namen"


@router.put("/api/compliance/rules")
async def put_compliance_rules(body: RulesIn, user=Depends(auth.require(roles.ADMIN))):
    """Replaces the built-in rules switched off and the custom rules, then checks the custom ones on the latest backup of every switch
    (compliance.reevaluate_custom). off takes only ids of compliance.RULES: a custom rule is removed, not switched off (422
    „Unbekannte Regel: <id>“); a name or text blank once trimmed is a 422 too, nothing stored. Names and texts are stored trimmed; a
    custom rule without an id, or with one an earlier rule of the same PUT has, gets c<n>, n one more than the largest number stored
    or sent - past CUSTOM_MAX_NO the smallest number neither stored nor sent, so every id GET serves comes back through this route.
    The audit names the rules switched off and the number of custom ones, never a name or a text; the answer is GET's."""
    for rid in body.off:
        if rid not in compliance.RULES:
            raise HTTPException(422, UNKNOWN_RULE.format(rid))
    for c in body.custom:
        if not c.text.strip():
            raise HTTPException(422, NO_TEXT)
        if not c.name.strip():
            raise HTTPException(422, NO_NAME)
    stored = (await compliance.load_rules())["custom"]
    taken = {int(rid[1:]) for rid in [c["id"] for c in stored] + [c.id for c in body.custom if c.id]}
    custom, used = [], set()
    for c in body.custom:
        rid = c.id
        if rid is None or rid in used:
            n = max(taken, default=0) + 1
            if n > CUSTOM_MAX_NO:
                n = min(set(range(1, len(taken) + 2)) - taken)
            taken.add(n)
            rid = f"c{n}"
        used.add(rid)
        custom.append({"id": rid, "name": c.name.strip(), "mode": c.mode, "text": c.text.strip()})
    off = [rid for rid in compliance.RULES if rid in body.off]
    await set_setting(compliance.SETTINGS_KEY, json.dumps({"off": off, "custom": custom}))
    try:
        await compliance.reevaluate_custom()
    except Exception:  # noqa: BLE001 - the rules are stored; their audit must not be lost to a failing check
        log.exception("Eigene Sicherheitsregeln an den Sicherungen")
    await audit(user["username"], "compliance_rules", "", f"aus: {', '.join(off) or '–'} · eigene: {len(custom)}", role=user["role"])
    return await compliance.rules_view()


WATCHED = "Diese MAC-Adresse wird schon beobachtet"
NOT_WATCHED = "Nicht in der Beobachtungsliste"
WATCH_FULL = "Höchstens 1000 beobachtete MAC-Adressen"      # history.WATCH_MAX


class WatchIn(BaseModel):
    """A MAC for the watch list, in any usual spelling (api_devices.norm_mac), with a note (stored trimmed; none is fine)."""
    mac: str = Field(max_length=20)
    note: str = Field(default="", max_length=200)


@router.get("/api/watch")
async def get_watch_list(user=Depends(auth.require(roles.LESEN))):
    """Every watched MAC by MAC, each with its note, who added it and when, and its latest sighting (last, null without one)."""
    return await history.watch_list()


@router.post("/api/watch")
async def add_to_watch_list(body: WatchIn, user=Depends(auth.require(roles.AENDERN))):
    """Watches a MAC (422 „MAC-Adresse ungültig“, 422 WATCH_FULL when the list holds history.WATCH_MAX already, 409 WATCHED when it
    is watched already) and audits it (watch_add, the MAC, the note); the answer is the entry as GET lists it."""
    mac = api_devices.norm_mac(body.mac)
    try:
        entry = await history.watch_add(mac, body.note.strip(), user)
    except history.WatchFull:
        raise HTTPException(422, WATCH_FULL) from None
    except KeyError:
        raise HTTPException(409, WATCHED) from None
    await audit(user["username"], "watch_add", mac, entry["note"], role=user["role"])
    return entry


@router.delete("/api/watch/{mac}")
async def remove_from_watch_list(mac: str, user=Depends(auth.require(roles.AENDERN))):
    """Watches the MAC no longer (422 „MAC-Adresse ungültig“, 404 NOT_WATCHED when it is not watched) and audits it (watch_remove)."""
    mac = api_devices.norm_mac(mac)
    if not await history.watch_remove(mac):
        raise HTTPException(404, NOT_WATCHED)
    await audit(user["username"], "watch_remove", mac, "", role=user["role"])
    return {"ok": True}
