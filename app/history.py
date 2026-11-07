"""Where each device was seen (Phase 4b): the sightings and their retention. Without FastAPI.

What: for every MAC a good poll read at a device port, where it was seen - the switch, the port and the VLAN, with the IP and the
name known for it (names, devices) - in the table sightings, from the first poll that saw it there to the last one that did. When:
once per round of poller.poll_all for all its good polls (one build_map: the uplink rule needs the links of every switch), and right
away for a single poll (poller.poll_switch with record: "Jetzt abfragen", the poll after a change). The time of a sighting is the
poll that read it (switches.last_poll), and only the MAC rows of that poll count: rows a failed MAC walk kept from the poll before
are no new sighting.

The rule of the place: a place is (MAC, switch, port, VLAN). A new row comes only when the latest row of that place is missing, has
been overtaken by a row of the same MAC begun later at another place (first_seen there after last_seen here), or carried another IP
(both not empty); otherwise its last_seen moves on and an empty IP or name is filled in. So a device at two places at once (two
VLANs, an unconfirmed uplink) grows nothing, a move there and back gives three rows, and a quiet device keeps its row. The ports are
those of the list of unknown devices (topology.device_port: no Trk port, no trunk or LAG member, no confirmed uplink); a row at a
possible uplink (topology.suspect_port) is marked suspect, and the base MACs of the managed switches are never recorded.

purge deletes what is older than HISTORY_DAYS from every table of RETAINED, nightly at 04:00 (jobs._schedule).
"""
import logging
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

import topology
from config import settings
from db import db, get_setting

log = logging.getLogger("switchview.history")

TIME = "%Y-%m-%d %H:%M:%S"    # the times of the tables, in UTC (macs.last_seen, switches.last_poll, poller.utc_now)
# The tables purge keeps for HISTORY_DAYS: (table, time column, extra condition of a row that may go, "" for none); Tasks 4-6 append
RETAINED: list[tuple[str, str, str]] = [("sightings", "last_seen", "")]
PURGE_BATCH = 5000    # rows per DELETE of purge, each batch committed on its own: a record or a poll waits for one batch, not for all
IN_CHUNK = 500        # MACs per IN list of record


def back_after(poll_minutes: int) -> int:
    """Minutes without a sighting after which a return to the same place counts as "wieder da": two poll intervals, at least an
    hour (a missed poll or a device asleep for a quarter of an hour is no absence)."""
    return max(60, 2 * poll_minutes)


async def record(switch_ids: Iterable[int]) -> list[dict]:
    """Records the sightings of the last poll of each switch in switch_ids (enabled ones: build_map knows only those) by the rule of the
    place (module docstring), in one transaction. Returns one dict per row it added or revived: id, mac, switch_id, switch (its
    name), port, vlan, ip, name, known (the MAC is in devices), suspect (a possible uplink), first (the MAC had no row before),
    moved (a new row while the MAC had one: another place, or another IP at the same place), back (a row whose last sighting was
    more than back_after minutes ago, continued) and baseline (the switch had no sighting before this call)."""
    wanted = set(switch_ids)
    if not wanted:
        return []
    m = await topology.build_map()
    keys = topology.switch_keys(m["switches"])
    base = sorted({s["baseMac"] for s in m["switches"] if s["baseMac"]})
    ports = [(s["id"], p["n"], int(topology.suspect_port(p, keys)))
             for s in m["switches"] if s["id"] in wanted for p in s["ports"] if topology.device_port(p)]
    if not ports:
        return []
    window = back_after(int(await get_setting("poll_minutes", "15") or 15))
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        news = await _record(conn, sorted(wanted), ports, base, window)
        await conn.commit()
    return news


async def _record(conn, wanted: list[int], ports: list[tuple[int, str, int]], base: list[str], window: int) -> list[dict]:
    """record inside its transaction on conn: ports are the device ports (switch id, name, suspect) of the switches in wanted."""
    # The device ports as a TEMP table (it ends with the connection), so only their MAC rows come out of the MAC table: at 50
    # switches with uplinks full of MACs all rows would be some 150 000 a round instead of a few thousand
    await conn.execute("CREATE TEMP TABLE _dp (switch_id INTEGER NOT NULL, port TEXT NOT NULL, suspect INTEGER NOT NULL, "
                       "PRIMARY KEY (switch_id, port))")
    # a port name twice on a switch is one row, suspect if either is
    await conn.executemany("INSERT INTO _dp VALUES (?, ?, ?) ON CONFLICT (switch_id, port) DO UPDATE SET "
                           "suspect = max(suspect, excluded.suspect)", ports)
    not_base = f" AND m.mac NOT IN ({', '.join('?' * len(base))})" if base else ""
    # Driven by _dp (CROSS JOIN keeps it the outer loop): one lookup in idx_macs_port per device port, never a scan of the MAC table
    async with conn.execute(
            "SELECT m.mac, m.switch_id, s.name AS switch, m.port, m.vlan, coalesce(n.ip, '') AS ip, coalesce(dv.name, n.name, '') AS name, "
            "dv.mac IS NOT NULL AS known, d.suspect, s.last_poll AS t FROM _dp d CROSS JOIN macs m ON m.switch_id = d.switch_id "
            "AND m.port = d.port JOIN switches s ON s.id = m.switch_id LEFT JOIN names n ON n.mac = m.mac "
            f"LEFT JOIN devices dv ON dv.mac = m.mac WHERE m.last_seen = s.last_poll{not_base} ORDER BY m.switch_id, m.rowid",
            base) as cur:
        seen = await cur.fetchall()
    if not seen:
        return []
    # The latest row of each place of the MACs seen (max(id): SQLite takes the other columns from that row), and per MAC the two
    # latest starts (first_seen, id) among those rows: whether another place began after a row's last sighting is then one look
    latest: dict[tuple, tuple] = {}    # place -> (id, ip, name, last_seen)
    starts: dict[str, list[tuple[str, int]]] = defaultdict(list)
    macs = sorted({o["mac"] for o in seen})
    for i in range(0, len(macs), IN_CHUNK):
        part = macs[i:i + IN_CHUNK]
        async with conn.execute("SELECT max(id), mac, switch_id, port, vlan, ip, name, first_seen, last_seen FROM sightings "
                                f"WHERE mac IN ({', '.join('?' * len(part))}) GROUP BY mac, switch_id, port, vlan", part) as cur:
            for rid, mac, sid, port, vlan, ip, name, first_seen, last_seen in await cur.fetchall():
                latest[(mac, sid, port, vlan)] = (rid, ip, name, last_seen)
                starts[mac].append((first_seen, rid))
    for both in starts.values():
        both.sort(reverse=True)
        del both[2:]
    async with conn.execute(f"SELECT s.id FROM switches s WHERE s.id IN ({', '.join('?' * len(wanted))}) "
                            "AND EXISTS (SELECT 1 FROM sightings g WHERE g.switch_id = s.id)", wanted) as cur:
        recorded = {r[0] for r in await cur.fetchall()}    # the switches with a sighting before this call
    absent_before: dict[str, str] = {}    # poll time -> a last_seen before this is an absence (back)

    def absence(t: str) -> str:
        if t not in absent_before:
            absent_before[t] = (datetime.strptime(t, TIME) - timedelta(minutes=window)).strftime(TIME)
        return absent_before[t]

    updates, inserts, news, added = [], [], [], []
    for mac, sid, switch, port, vlan, ip, name, known, suspect, t in seen:
        place = (mac, sid, port, vlan)
        r = latest.get(place)
        if r is not None:
            rid, rip, rname, rlast = r
            other = next((first for first, oid in starts[mac] if oid != rid), None)    # the latest start at another place
            if not (other is not None and other > rlast) and not (rip and ip and rip != ip):
                updates.append((t, ip or rip, name or rname, suspect, switch, rid))
                if rlast < absence(t):
                    news.append(_news(rid, place, switch, ip or rip, name or rname, known, suspect, "back", sid not in recorded))
                continue
        inserts.append((mac, sid, switch, port, vlan, ip, name, suspect, t, t))
        item = _news(None, place, switch, ip, name, known, suspect, "moved" if mac in starts else "first", sid not in recorded)
        news.append(item)
        added.append((place, item))
    await conn.executemany("UPDATE sightings SET last_seen = ?, ip = ?, name = ?, suspect = ?, switch_name = ? WHERE id = ?", updates)
    if inserts:
        # Under the write lock of this transaction, every id above the largest one now is a row of this INSERT (AUTOINCREMENT)
        async with conn.execute("SELECT coalesce(max(id), 0) FROM sightings") as cur:
            top = (await cur.fetchone())[0]
        await conn.executemany("INSERT INTO sightings(mac, switch_id, switch_name, port, vlan, ip, name, suspect, first_seen, last_seen) "
                               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", inserts)
        async with conn.execute("SELECT id, mac, switch_id, port, vlan FROM sightings WHERE id > ?", (top,)) as cur:
            ids = {(mac, sid, port, vlan): rid for rid, mac, sid, port, vlan in await cur.fetchall()}
        for place, item in added:
            item["id"] = ids[place]
    return news


def _news(rid: int | None, place: tuple, switch: str, ip: str, name: str, known: int, suspect: int, why: str, baseline: bool) -> dict:
    """One dict of record's result: the row rid at place (MAC, switch id, port, VLAN), why one of "first", "moved" or "back"."""
    mac, sid, port, vlan = place
    return {"id": rid, "mac": mac, "switch_id": sid, "switch": switch, "port": port, "vlan": vlan, "ip": ip, "name": name,
            "known": bool(known), "suspect": bool(suspect), "first": why == "first", "moved": why == "moved", "back": why == "back",
            "baseline": baseline}


async def purge(days: int | None = None) -> dict[str, int]:
    """Deletes from every table of RETAINED the rows whose time is older than days (None: HISTORY_DAYS; 0 or less: nothing, {}), in
    batches of PURGE_BATCH rows, each committed. Returns table -> rows deleted, for the tables with any."""
    days = settings.history_days if days is None else days
    if days <= 0:
        return {}
    before = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(TIME)
    out: dict[str, int] = {}
    async with db() as conn:
        for table, column, extra in RETAINED:
            where = f"{column} < ?" + (f" AND ({extra})" if extra else "")
            total = 0
            while True:
                cur = await conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {where} LIMIT ?)",
                                         (before, PURGE_BATCH))
                await conn.commit()
                total += cur.rowcount
                if cur.rowcount < PURGE_BATCH:
                    break
            if total:
                out[table] = total
    if out:
        log.info("Verlauf älter als %d Tage gelöscht: %s", days, ", ".join(f"{t} {n}" for t, n in out.items()))
    return out
