"""Where each device was seen (Phase 4b): the sightings and their retention. Without FastAPI.

What: for every MAC a good poll read at a device port, where it was seen - the switch, the port and the VLAN, with the IP and the
name known for it (names, devices) - in the table sightings, from the first poll that saw it there to the last one that did. When:
once per round of poller.poll_all for all its good polls (one build_map: the uplink rule needs the links of every switch), and right
away for a single poll (poller.poll_switch with record: "Jetzt abfragen", the poll after a change). The time of a sighting is the
poll that read it (switches.last_poll), and only the MAC rows of that poll count: rows a failed MAC walk kept from the poll before
are no new sighting.

The rule of the place: a place is (MAC, switch, port, VLAN). A new row comes only when the latest row of that place is missing, has
been overtaken, or carried another IP (both not empty); otherwise its last_seen moves on and an empty IP or name is filled in. A row
is overtaken when the device left it - its switch has a recorded poll after the row's last sighting (a later last_seen of another
row there) - and a place of the same MAC that is not seen now began after that last sighting (first_seen there after last_seen
here). The times are each switch's own poll times, which differ within a round: a place seen now never overtakes, and a row seen at
its switch's last recorded poll is never overtaken - the device is at both places. So a device at two places at once (two VLANs, an
unconfirmed uplink on another switch) grows nothing, whatever the order of the polls - except after a move followed by one round in
which the device is seen nowhere: then the row at such an uplink can, by the order of the polls, split in two with a "moved"
(Bekannte Grenzen, T2-n; the rows at the access ports stay exact). A move there and back gives three rows, and a quiet device keeps
its row. The ports are those of the list of unknown devices (topology.device_port: no Trk port, no trunk or LAG member, no confirmed
uplink); a row at a possible uplink (topology.suspect_port) is marked suspect, and the base MACs of the managed switches are never
recorded.

purge deletes what is older than HISTORY_DAYS from every table of RETAINED, nightly at 04:00 (jobs._schedule).

search answers "where was device X" (Task 3, GET /api/history): by a MAC in any usual spelling, an IP address (exact) or a part of a
name or MAC, or by a switch and a port; newest first by last_seen (the place of now on top, even when an old row lives again), paged
by the cursor "<last_seen>|<id>" of the last row shown. export gives the same rows for the CSV (at most EXPORT_MAX).

The watch list (Task 7, table watch_macs, GET/POST /api/watch, DELETE /api/watch/{mac}): MACs a helpdesk wants to hear of, each
with a note, at most WATCH_MAX (Phase 4c). After its commit, record hands what it added or revived to alerts.announce_sightings,
which tells a new unknown device and every watched MAC seen for the first time, at another place or back (watched gives their notes).
"""
import ipaddress
import logging
import re
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

import alerts
import names
import topology
from config import settings
from db import db, get_setting

log = logging.getLogger("switchview.history")

TIME = "%Y-%m-%d %H:%M:%S"    # the times of the tables, in UTC (macs.last_seen, switches.last_poll, poller.utc_now)
# The tables purge keeps for HISTORY_DAYS: (table, time column, extra condition of a row that may go, "" for none). A finding goes
# only once resolved (an open one is the state of now, however old its first sighting), an alert only once it is no longer queued
RETAINED: list[tuple[str, str, str]] = [("sightings", "last_seen", ""), ("events", "ts", ""), ("findings", "resolved_at", "resolved_at IS NOT NULL"),
                                        ("alert_outbox", "created_at", "status <> 'queued'")]
PURGE_BATCH = 5000    # rows per DELETE of purge, each batch committed on its own: a record or a poll waits for one batch, not for all
IN_CHUNK = 500        # MACs per IN list of record


BAD_TIME = "Zeitpunkt ungültig"


def to_utc(value: str) -> str:
    """A point in time as ISO 8601 writes it - with "Z", with an offset, or without either (then it is UTC), a date alone being its
    midnight, fractions of a second dropped - as the tables store times: YYYY-MM-DD HH:MM:SS in UTC. ValueError(BAD_TIME) for
    anything else, also for a time whose UTC falls outside the years 1-9999. The `since` of GET /api/events (Task 4) and of the
    audit (Task 8)."""
    try:
        t = datetime.fromisoformat(value.strip())
        t = t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError(BAD_TIME) from None
    return t.replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")


def back_after(poll_minutes: int) -> int:
    """Minutes without a sighting after which a return to the same place counts as "wieder da": two poll intervals, at least an
    hour (a missed poll or a device asleep for a quarter of an hour is no absence)."""
    return max(60, 2 * poll_minutes)


async def record(switch_ids: Iterable[int]) -> list[dict]:
    """Records the sightings of the last poll of each switch in switch_ids (enabled ones: build_map knows only those) by the rule of the
    place (module docstring), in one transaction. Returns one dict per row it added or revived: id, mac, switch_id, switch (its
    name), port, vlan, ip, name, known (the MAC is in devices), suspect (a possible uplink), first (the MAC had no row before),
    moved (a new row while the MAC had one: another place, or another IP at the same place), back (a row whose last sighting was
    more than back_after minutes ago, continued) and baseline (the switch had no sighting before this call). After the commit, the
    same list goes to alerts.announce_sightings, wrapped: a failure there is logged ("Meldungen des Verlaufs") and changes nothing
    of the recording or of what it returns (announce writes on a connection of its own, which would wait out this one's lock)."""
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
    try:
        await alerts.announce_sightings(news)
    except Exception:  # noqa: BLE001 - an alert never changes the recording
        log.exception("Meldungen des Verlaufs")
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
    # The latest row of each place of the MACs seen (max(id): SQLite takes the other columns from that row), and per MAC the latest
    # start (first_seen) among the rows of its places not seen now: whether the device was elsewhere after a row's last sighting is
    # then one look. A place seen now overtakes nothing: the device is at both now (an unconfirmed uplink on another switch, whose
    # poll time differs from this one's within a round)
    latest: dict[tuple, tuple] = {}    # place -> (id, ip, name, last_seen)
    left: dict[str, str] = {}    # MAC -> the latest first_seen of its places not seen now
    observed = {(o["mac"], o["switch_id"], o["port"], o["vlan"]) for o in seen}
    macs = sorted({o["mac"] for o in seen})
    for i in range(0, len(macs), IN_CHUNK):
        part = macs[i:i + IN_CHUNK]
        async with conn.execute("SELECT max(id), mac, switch_id, port, vlan, ip, name, first_seen, last_seen FROM sightings "
                                f"WHERE mac IN ({', '.join('?' * len(part))}) GROUP BY mac, switch_id, port, vlan", part) as cur:
            for rid, mac, sid, port, vlan, ip, name, first_seen, last_seen in await cur.fetchall():
                latest[(mac, sid, port, vlan)] = (rid, ip, name, last_seen)
                if (mac, sid, port, vlan) not in observed and first_seen > left.get(mac, ""):
                    left[mac] = first_seen
    had = {place[0] for place in latest}    # the MACs with a row before this call
    # Per switch the time of its last recorded poll (the latest last_seen of its rows: a poll records each place it sees with its own
    # time). A row last seen then was there at its switch's last poll, so the device never left it, whatever began elsewhere since
    async with conn.execute(f"SELECT switch_id, max(last_seen) FROM sightings WHERE switch_id IN ({', '.join('?' * len(wanted))}) "
                            "GROUP BY switch_id", wanted) as cur:
        recorded = dict(await cur.fetchall())    # switch id -> that time; its keys: the switches with a sighting before this call
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
            # overtaken: the device left this place (its switch was recorded since without it) and another place began after
            overtaken = rlast < recorded[sid] and left.get(mac, "") > rlast
            if not overtaken and not (rip and ip and rip != ip):
                updates.append((t, ip or rip, name or rname, suspect, switch, rid))
                if rlast < absence(t):
                    news.append(_news(rid, place, switch, ip or rip, name or rname, known, suspect, "back", sid not in recorded))
                continue
        inserts.append((mac, sid, switch, port, vlan, ip, name, suspect, t, t))
        item = _news(None, place, switch, ip, name, known, suspect, "moved" if mac in had else "first", sid not in recorded)
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
        log.info("Verlauf älter als %d %s gelöscht: %s", days, "Tag" if days == 1 else "Tage", ", ".join(f"{t} {n}" for t, n in out.items()))
    return out


# ── Search (Task 3) ──────────────────────────────────────────────────────────
QUERY_HELP = "Bitte nach MAC, IP oder Name suchen (mindestens 2 Zeichen) oder Switch und Port angeben"
BAD_CURSOR = "Blättermarke ungültig"
EXPORT_MAX = 10_000    # rows of one CSV export; more need a narrower search
# A cursor: the last_seen and the id of the last row shown; at most 18 digits, so the id always fits an SQLite INTEGER
CURSOR = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\|([0-9]{1,18})")
COLUMNS = "id, mac, ip, name, switch_id, switch_name, port, vlan, first_seen, last_seen, suspect"


def parse_query(q: str) -> tuple[str, str]:
    """The kind of search q asks for and its value: ("ip", the address as ipaddress writes it) for an IP address, ("mac",
    "aa:bb:cc:dd:ee:ff") for 12 hex digits once ":", "-", "." and spaces are gone, else ("text", q); q trimmed first. The IP comes
    before the MAC: an IPv4 address with three digits in each part (192.168.178.100) is 12 digits without its dots. A text stays as
    typed: LIKE ignores the case of A-Z by itself, and SQLite folds no other letter, so a text in lower case would never find a
    capital umlaut ("ähren" misses "Ähren", "Ähren" finds it). ValueError(QUERY_HELP) for fewer than 2 characters."""
    q = q.strip()
    if len(q) < 2:
        raise ValueError(QUERY_HELP)
    try:
        return "ip", str(ipaddress.ip_address(q))
    except ValueError:
        pass
    digits = re.sub(r"[:.\- ]", "", q)
    if re.fullmatch(r"[0-9a-fA-F]{12}", digits):
        digits = digits.lower()
        return "mac", ":".join(digits[i:i + 2] for i in range(0, 12, 2))
    return "text", q


def _question(q: str | None, switch_id: int | None, port: str | None) -> tuple[str, list]:
    """The WHERE condition and its arguments for exactly one question: q, or switch_id and port together; ValueError(QUERY_HELP)
    otherwise. Each kind runs on its index: idx_sightings_mac, idx_sightings_ip (a partial index: SQLite takes it only with its own
    condition ip <> '' in the query), idx_sightings_port; a part of a name or MAC has none and walks idx_sightings_seen from the
    newest row."""
    if q is not None:
        if switch_id is not None or port is not None:
            raise ValueError(QUERY_HELP)
        kind, value = parse_query(q)
        if kind == "mac":
            return "mac = ?", [value]
        if kind == "ip":
            return "ip = ? AND ip <> ''", [value]
        like = "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"    # the text as text, not as a pattern
        return "(name LIKE ? ESCAPE '\\' OR mac LIKE ? ESCAPE '\\')", [like, like]
    if switch_id is None or not port:
        raise ValueError(QUERY_HELP)
    return "switch_id = ? AND port = ?", [switch_id, port]


def _served(r) -> dict:
    """A row of sightings as search answers it."""
    return {"id": r["id"], "mac": r["mac"], "vendor": names.vendor_of(r["mac"]), "ip": r["ip"], "name": r["name"],
            "switch_id": r["switch_id"], "switch": r["switch_name"], "port": r["port"], "vlan": r["vlan"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"], "suspect": bool(r["suspect"])}


async def _select(conn, where: str, args: list, limit: int) -> list[dict]:
    async with conn.execute(f"SELECT {COLUMNS} FROM sightings WHERE {where} ORDER BY last_seen DESC, id DESC LIMIT ?",
                            [*args, limit]) as cur:
        return [_served(r) for r in await cur.fetchall()]


async def _rows(where: str, args: list, limit: int) -> list[dict]:
    """The first limit rows of sightings under where, newest first (last_seen, then id), as search answers them."""
    async with db() as conn:
        return await _select(conn, where, args, limit)


async def search(*, q: str | None = None, switch_id: int | None = None, port: str | None = None, cursor: str | None = None,
                 limit: int = 50) -> dict:
    """One page of the sightings that answer q, or switch_id and port (_question), newest first: {"rows": [...], "next": the cursor
    of the last row when more follow, else None}. cursor is the "next" of the page before; ValueError(BAD_CURSOR) for one that does
    not look like it, ValueError(QUERY_HELP) for no question or two."""
    where, args = _question(q, switch_id, port)
    if cursor is not None:
        m = CURSOR.fullmatch(cursor)
        if not m:
            raise ValueError(BAD_CURSOR)
        where += " AND (last_seen < ? OR (last_seen = ? AND id < ?))"
        args += [m[1], m[1], int(m[2])]
    rows = await _rows(where, args, limit + 1)
    more = len(rows) > limit
    rows = rows[:limit]
    return {"rows": rows, "next": f"{rows[-1]['last_seen']}|{rows[-1]['id']}" if more else None}


async def export(*, q: str | None = None, switch_id: int | None = None, port: str | None = None) -> list[dict]:
    """The rows search gives for the same question, in the same order, all on one page: at most EXPORT_MAX."""
    where, args = _question(q, switch_id, port)
    return await _rows(where, args, EXPORT_MAX)


# ── The watch list (Task 7) ──────────────────────────────────────────────────
WATCH_MAX = 1000    # watched MACs at most (Phase 4c: a script can fill the list through the REST API); GET /api/watch reads all at once


class WatchFull(Exception):
    """watch_add: the watch list holds WATCH_MAX entries already."""


async def _last(conn, mac: str) -> dict | None:
    """The latest sighting of mac as search reads it (the first row of a search by that MAC, on idx_sightings_mac), None without one."""
    rows = await _select(conn, "mac = ?", [mac], 1)
    return rows[0] if rows else None


# Every watched MAC with its latest sighting in one SELECT (Phase 4c; a query per entry before): the correlated subquery takes the
# first row of a search by that MAC on idx_sightings_mac, as _last does, and the LEFT JOIN leaves s.* NULL for a MAC never seen
_WATCH_LIST = (f"SELECT w.mac AS watch_mac, w.note, w.created_by, w.created_at, {', '.join('s.' + c for c in COLUMNS.split(', '))} "
               "FROM watch_macs w LEFT JOIN sightings s ON s.id = "
               "(SELECT id FROM sightings WHERE mac = w.mac ORDER BY last_seen DESC, id DESC LIMIT 1) ORDER BY w.mac")


async def watch_list() -> list[dict]:
    """Every watched MAC by MAC: mac, note, created_by, created_at and last, its latest sighting as search reads it (None without
    one), all in one query."""
    async with db() as conn:
        async with conn.execute(_WATCH_LIST) as cur:
            return [{"mac": r["watch_mac"], "note": r["note"], "created_by": r["created_by"], "created_at": r["created_at"],
                     "last": None if r["id"] is None else _served(r)} for r in await cur.fetchall()]


async def watch_add(mac: str, note: str, user: dict) -> dict:
    """Watches mac (as api_devices.norm_mac writes it) with note, added by user (auth.current_user) now; the entry as watch_list
    reads it. Counts and writes in one write transaction (BEGIN IMMEDIATE), so two at once cannot pass WATCH_MAX: WatchFull when
    the list holds WATCH_MAX entries, KeyError when mac is watched already (nothing changes then)."""
    now = datetime.now(timezone.utc).strftime(TIME)
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute("SELECT count(*) FROM watch_macs") as cur:
            (count,) = await cur.fetchone()
        if count >= WATCH_MAX:
            await conn.rollback()
            raise WatchFull()
        cur = await conn.execute("INSERT INTO watch_macs(mac, note, created_by, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (mac) DO NOTHING",
                                 (mac, note, user["username"], now))
        await conn.commit()
        if cur.rowcount != 1:
            raise KeyError(mac)
        return {"mac": mac, "note": note, "created_by": user["username"], "created_at": now, "last": await _last(conn, mac)}


async def watch_remove(mac: str) -> bool:
    """Watches mac no longer; whether it was watched."""
    async with db() as conn:
        cur = await conn.execute("DELETE FROM watch_macs WHERE mac = ?", (mac,))
        await conn.commit()
    return cur.rowcount == 1


async def watched(macs: set[str]) -> dict[str, str]:
    """Of macs those that are watched, each with its note (MAC -> note); no query for none."""
    out: dict[str, str] = {}
    wanted = sorted(macs)
    if not wanted:
        return out
    async with db() as conn:
        for i in range(0, len(wanted), IN_CHUNK):
            part = wanted[i:i + IN_CHUNK]
            async with conn.execute(f"SELECT mac, note FROM watch_macs WHERE mac IN ({', '.join('?' * len(part))})", part) as cur:
                out |= {r["mac"]: r["note"] for r in await cur.fetchall()}
    return out


async def first_seen(macs: set[str]) -> dict[str, str]:
    """Of macs those with a sighting, each with its earliest first_seen at any place (MAC -> time); no query for none. The list
    of unknown devices shows it as "seit" and takes "new" from it (Phase 4c, Task 10)."""
    out: dict[str, str] = {}
    wanted = sorted(macs)
    if not wanted:
        return out
    async with db() as conn:
        for i in range(0, len(wanted), IN_CHUNK):
            part = wanted[i:i + IN_CHUNK]
            async with conn.execute(f"SELECT mac, min(first_seen) FROM sightings WHERE mac IN ({', '.join('?' * len(part))}) GROUP BY mac",
                                    part) as cur:
                out |= dict(await cur.fetchall())
    return out


async def baselines() -> dict[int, str]:
    """Per switch with a sighting its earliest first_seen (switch id -> time): the first recording of the switch, its stock. A
    device first seen then is not new."""
    async with db() as conn:
        async with conn.execute("SELECT switch_id, min(first_seen) FROM sightings GROUP BY switch_id") as cur:
            return dict(await cur.fetchall())
