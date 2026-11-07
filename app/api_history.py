"""The history routes (Phase 4b): where a device was seen (Task 3: GET /api/history, the search; GET /api/history.csv, the same search
as a CSV download) and the events (Task 4: GET /api/events). The search itself is app/history.py, the CSV app/csvout.py, the events
app/monitor.py.

All need Lesen and are not limited by zone, like every read route of Phase 4a: zones limit changes only (roles.SCOPED), and a place
of a device belongs to no single switch.
"""
from fastapi import APIRouter, Depends, HTTPException, Query

import auth
import csvout
import history
import monitor
import roles

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
