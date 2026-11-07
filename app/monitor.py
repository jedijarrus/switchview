"""Discrete events (Phase 4b, Task 4): reachability, LLDP neighbours and changes made outside SwitchView. Without FastAPI.

What, in the table events (one row each, with its time, never a counter):
  switch_down / switch_up   a switch that did not answer UNREACHABLE_AFTER polls in a row (switches.poll_failures, down_since), and
                            the first good poll after that; poller.poll_switch counts, poll_failed and poll_succeeded tell.
  lldp_new / _changed / _gone  an LLDP neighbour that appears at a port, another one there (another sysName or PortId: the PortDesc
                            changes with a description, the neighbour does not), none any more (lldp_changes). Not at the first poll of
                            a switch, nor when an LLDP walk of its driver failed (the old entries stay then, poller.merge_lldp).
                            detail.uplink says whether the port is a trunk or LAG member or a neighbour is named like a managed switch.
  drift_port                drift (b): a port changed outside SwitchView - untagged, tagged, PVID, status or name (DRIFT_FIELDS) -
                            at a switch SwitchView does not back up (drift_applies), compared with the last good poll (port_drift).
  drift_config              drift (a): a backup that differs from the one before it (sshcli.store_backup stores no other) while no
                            SwitchView change ran between the two (backup_outside, config_backups.outside).
A drift is explained by a change at the switch that may have sent something (changes.sent != 0) and ran in the window
(explained_ports): for a port, one that named the port, its trunk, or the whole switch (prepare, save). Nothing counts that was not
read completely: a field of a walk that failed or broke off (FIELD_WALKS, unread_fields), the VLANs of an empty VLAN table, and a
field the poll before could not read (switches.unread_fields: its stored value is no base). list_events serves GET /api/events.

Every caller wraps its call: a failure here is logged and never changes a poll or a backup.
"""
import json
import re
from collections.abc import Container, Iterable
from datetime import datetime, timezone

import drivers
import poller
from db import db

UNREACHABLE_AFTER = 3    # failed polls in a row after which a switch counts as unreachable
KINDS = {"switch_down": "Antwortet nicht", "switch_up": "Antwortet wieder", "lldp_new": "LLDP-Nachbar neu",
         "lldp_changed": "LLDP-Nachbar geändert", "lldp_gone": "LLDP-Nachbar weg", "drift_port": "Port außerhalb von SwitchView geändert",
         "drift_config": "Konfiguration außerhalb von SwitchView geändert"}
KIND_GROUPS = {"reach": ("switch_down", "switch_up"), "lldp": ("lldp_new", "lldp_changed", "lldp_gone"), "drift": ("drift_port", "drift_config")}
UNKNOWN_KIND = "Unbekannte Art von Ereignis"
# The fields of drift (b): the port configuration SwitchView changes, with their German labels, in the order the text names them
DRIFT_FIELDS = {"untagged": "ungetaggt", "tagged": "getaggt", "pvid": "PVID", "admin": "Status", "alias": "Name"}
# The walks each field is read from (poller.O keys): a field counts only when each of them was read completely. ifStack: without it a
# trunk member reads its own bridge port instead of the trunk's (poller.select_ports)
FIELD_WALKS = {"untagged": ("vlanEgress", "vlanUntagged", "vlanName", "bp2if", "ifStack"),
               "tagged": ("vlanEgress", "vlanUntagged", "vlanName", "bp2if", "ifStack"),
               "pvid": ("pvid", "bp2if", "ifStack"), "admin": ("ifAdmin",), "alias": ("ifAlias",)}
TEXT_MAX = 500    # characters of the text of a port's event
TIME = "%Y-%m-%d %H:%M:%S"
_TRIGGER = re.compile(r"(vor|nach) #([0-9]{1,18})")    # the backups around a change (changes.run_change)


def _now() -> str:
    """Now in UTC as the tables store it; the clock of explained_ports' window end after a poll (a seam like poller.utc_now)."""
    return datetime.now(timezone.utc).strftime(TIME)


def _cut(text: str) -> str:
    return text if len(text) <= TEXT_MAX else text[:TEXT_MAX - 1] + "…"


# ── The pure parts ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _identity(entry: list) -> tuple[str, str]:
    """An LLDP neighbour as (sysName, PortId); an entry from before R40 has only [sysName, PortDesc or PortId]."""
    return entry[0], entry[2] if len(entry) > 2 else entry[1]


def lldp_changes(old: dict[str, list], new: dict[str, list]) -> list[tuple[str, str, list, list]]:
    """The LLDP events between two polls, (port, kind, old entries, new entries) per port name both know, in the port order of new:
    lldp_new (none before, some now), lldp_gone (some before, none now), lldp_changed (another set of neighbours, by _identity)."""
    out = []
    for port, after in new.items():
        if port not in old:
            continue
        before = old[port]
        if not before and after:
            out.append((port, "lldp_new", before, after))
        elif before and not after:
            out.append((port, "lldp_gone", before, after))
        elif before and {_identity(e) for e in before} != {_identity(e) for e in after}:
            out.append((port, "lldp_changed", before, after))
    return out


def _stored(row, field: str):
    """The value of field in a row of the table ports as port_drift compares it: the VLAN lists decoded, an empty text as ""."""
    if field in ("untagged", "tagged"):
        return json.loads(row[field] or "[]")
    return row[field] if field == "admin" else row[field] or ""


def port_drift(old: dict[str, dict], new: list[dict], unreadable: set[str]) -> dict[str, dict[str, tuple]]:
    """Port name -> {field: (before, now)} for each port both know whose fields of DRIFT_FIELDS (without unreadable) changed: old are
    the rows of the table ports by name (the VLAN lists as JSON text), new the ports of poller._build."""
    out: dict[str, dict[str, tuple]] = {}
    for p in new:
        row = old.get(p["name"])
        if row is None:
            continue
        changed = {f: (_stored(row, f), p[f]) for f in DRIFT_FIELDS if f not in unreadable and _stored(row, f) != p[f]}
        if changed:
            out[p["name"]] = changed
    return out


def unread_fields(failed: Container[str], data: dict) -> set[str]:
    """The fields of DRIFT_FIELDS a poll did not read completely: each with a walk of FIELD_WALKS in failed (the walks that failed or
    broke off), and the VLAN lists when the VLAN table came out empty (more likely a narrowed SNMP view than a switch without VLANs)."""
    out = {f for f, walks in FIELD_WALKS.items() if any(w in failed for w in walks)}
    return out | ({"untagged", "tagged"} if not data["vlans"] else set())


def _shown(field: str, value) -> str:
    if field in ("untagged", "tagged"):
        return ", ".join(value) or "–"
    if field == "admin":
        return "an" if value else "aus"
    if field == "alias":
        return f"„{value}“"
    return str(value) if value not in ("", None) else "–"


def drift_text(port: str, fields: dict[str, tuple]) -> str:
    """The sentence of a drift_port event: each changed field in the order of DRIFT_FIELDS, at most TEXT_MAX characters."""
    parts = [f"{label} {_shown(f, fields[f][0])} → {_shown(f, fields[f][1])}" for f, label in DRIFT_FIELDS.items() if f in fields]
    return _cut(f"Port {port} außerhalb von SwitchView geändert: " + "; ".join(parts))


def _who(entries: list) -> str:
    return ", ".join(f"{e[0]} (Port {(e[2] if len(e) > 2 else '') or e[1]})" for e in entries)


def _lldp_text(port: str, kind: str, before: list, after: list) -> str:
    if kind == "lldp_new":
        return _cut(f"Port {port}: neuer LLDP-Nachbar {_who(after)}")
    if kind == "lldp_gone":
        return _cut(f"Port {port}: LLDP-Nachbar {_who(before)} nicht mehr da")
    return _cut(f"Port {port}: LLDP-Nachbar {_who(before)} → {_who(after)}")


def drift_applies(row) -> bool:
    """Whether port drift (b) is watched at the switch row: only where SwitchView takes no backup (a driver without "backup", or no
    SSH access); where it does, drift (a) of the backups says more."""
    return not drivers.can(drivers.driver_for(row), "backup") or not (row["ssh_user"] and row["ssh_pass"])


def _minutes(since: str, until: str) -> int:
    return max(0, int((datetime.strptime(until, TIME) - datetime.strptime(since, TIME)).total_seconds() // 60))


# ── The database ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def _explaining(conn, switch_id: int, since: str, until: str, exclude: int | None) -> list:
    """The changes at the switch that may have sent something (sent IS NULL, from before the column, counts as sent) and ran in the
    window [since, until]: created by its end, not finished before its start; without the change exclude."""
    sql = ("SELECT kind, ports FROM changes WHERE switch_id = ? AND (sent IS NULL OR sent = 1) AND created_at <= ? "
           "AND (finished_at IS NULL OR finished_at >= ?)")
    args: list = [switch_id, until, since]
    if exclude is not None:
        sql += " AND id <> ?"
        args.append(exclude)
    async with conn.execute(sql, args) as cur:
        return await cur.fetchall()


def _ports_of(rows: Iterable) -> set[str]:
    out: set[str] = set()
    for kind, ports in rows:
        out |= set(json.loads(ports or "[]"))
        if kind in ("prepare", "save"):
            out.add("*")
    return out


async def explained_ports(switch_id: int, since: str, until: str, exclude: int | None = None) -> set[str]:
    """The port names (changes.ports) of each change at the switch that may have sent something and ran in [since, until], without
    the change exclude; "*" as well when one of them concerns the whole switch (prepare, save)."""
    async with db() as conn:
        return _ports_of(await _explaining(conn, switch_id, since, until, exclude))


async def _insert(conn, row, at: str, items: list[tuple[str, str, str, dict]]) -> list[dict]:
    """The events items (kind, port, text, detail) of the switch row at the time at, on conn without a commit; each as list_events
    reads it."""
    out = []
    for kind, port, text, detail in items:
        cur = await conn.execute("INSERT INTO events(ts, switch_id, kind, port, text, detail) VALUES (?, ?, ?, ?, ?, ?)",
                                 (at, row["id"], kind, port, text, json.dumps(detail)))
        out.append({"id": cur.lastrowid, "ts": at, "switch_id": row["id"], "switch": row["name"], "kind": kind, "label": KINDS[kind],
                    "port": port, "text": text, "detail": detail})
    return out


async def poll_failed(row, error: str, at: str) -> dict | None:
    """After the UPDATE of a failed poll of the switch row (read before it): at the UNREACHABLE_AFTER-th failed poll in a row the
    switch counts as unreachable from at (down_since) and the switch_down event is stored and returned; otherwise None."""
    n = (row["poll_failures"] or 0) + 1
    if n < UNREACHABLE_AFTER or row["down_since"]:
        return None
    async with db() as conn:
        cur = await conn.execute("UPDATE switches SET down_since = ? WHERE id = ? AND down_since IS NULL", (at, row["id"]))
        if cur.rowcount != 1:
            return None
        [event] = await _insert(conn, row, at, [("switch_down", "", f"{row['name']} antwortet seit {n} Abfragen nicht: {error[:200]}",
                                                 {"failures": n})])
        await conn.commit()
    return event


async def poll_succeeded(row, old: dict[str, dict], data: dict, failed: Container[str], at: str) -> list[dict]:
    """After the commit of a good poll of the switch row (read before it) at the time at: old are the rows of the table ports the
    poll replaced, by name, data what it read (poller._build), failed the walks that failed or broke off. Stores and returns the
    events of this poll, in one transaction: switch_up when the switch counted as unreachable (the minutes since it last answered),
    the LLDP events (not at the first poll, nor after a failed LLDP walk), and the port drift (only at a switch without backups,
    against the last good poll, without what is explained or was not read completely, now or by the poll before)."""
    items: list[tuple[str, str, str, dict]] = []
    if row["down_since"]:
        m = _minutes(row["last_ok_at"] or row["down_since"], at)
        items.append(("switch_up", "", f"{row['name']} antwortet wieder (nach {m} {'Minute' if m == 1 else 'Minuten'})",
                      {"down_since": row["down_since"], "minutes": m}))
    current = {p["name"]: p for p in data["ports"]}    # the ports this poll read, by name
    if old and not any(w in failed for w in poller.lldp_walks(row["driver"] or "procurve")):
        found = lldp_changes({name: json.loads(r["lldp"] or "[]") for name, r in old.items()}, {n: p["lldp"] for n, p in current.items()})
        if found:
            async with db() as conn:
                async with conn.execute("SELECT name, sys_name FROM switches") as cur:
                    managed = {name for r in await cur.fetchall() for name in r if name}    # topology.switch_keys reads the same two
            for port, kind, before, after in found:
                uplink = bool(current[port]["trunk"] or old[port]["trunk"]) or any(e[0] in managed for e in before + after)
                items.append((kind, port, _lldp_text(port, kind, before, after), {"uplink": uplink, "before": before, "after": after}))
    base = row["last_ok_at"] or (row["last_poll"] if row["last_poll_ok"] else None)
    if old and base and drift_applies(row):
        unreadable = unread_fields(failed, data) | set(json.loads(row["unread_fields"] or "[]"))
        drift = port_drift(old, data["ports"], unreadable)
        if drift:
            # The window ends now, not at the poll's start: a change that began while the walks ran may be what they read
            explained = await explained_ports(row["id"], base, max(at, _now()))
            for port, fields in drift.items():
                if {port, current[port]["trunk"], "*"} & explained:
                    continue
                items.append(("drift_port", port, drift_text(port, fields), {"changes": {f: list(v) for f, v in fields.items()}}))
    if not items:
        return []
    async with db() as conn:
        out = await _insert(conn, row, at, items)
        await conn.commit()
    return out


async def backup_outside(conn, switch_id: int, backup_id: int, trigger: str, taken_at: str) -> dict | None:
    """On the connection of sshcli.store_backup, after its INSERT of the backup backup_id and before its commit: whether that backup
    is "outside of SwitchView". Without a backup before it outside stays NULL and None comes back. Otherwise it is explained when the
    trigger is "nach #N" and change N may have sent something, or when a change that may have sent something ran between the backup
    before it and this one (for "vor #N" without N itself: that backup is the read before N sent anything); outside becomes 0 or 1,
    and with 1 the drift_config event is stored (on conn) and returned."""
    async with conn.execute("SELECT id, taken_at FROM config_backups WHERE switch_id = ? AND id < ? ORDER BY id DESC LIMIT 1",
                            (switch_id, backup_id)) as cur:
        previous = await cur.fetchone()
    if previous is None:
        return None
    m = _TRIGGER.fullmatch(trigger)
    explained = False
    if m and m[1] == "nach":
        async with conn.execute("SELECT 1 FROM changes WHERE id = ? AND switch_id = ? AND (sent IS NULL OR sent = 1)",
                                (int(m[2]), switch_id)) as cur:
            explained = await cur.fetchone() is not None
    if not explained:
        explained = bool(await _explaining(conn, switch_id, previous[1], taken_at, int(m[2]) if m and m[1] == "vor" else None))
    await conn.execute("UPDATE config_backups SET outside = ? WHERE id = ?", (0 if explained else 1, backup_id))
    if explained:
        return None
    async with conn.execute("SELECT id, name FROM switches WHERE id = ?", (switch_id,)) as cur:
        row = await cur.fetchone()
    [event] = await _insert(conn, row, taken_at, [("drift_config", "", f"Konfiguration außerhalb von SwitchView geändert (Sicherung vom "
                                                   f"{taken_at} UTC)", {"backup": backup_id, "previous": previous[0]})])
    return event


async def list_events(*, switch_id: int | None = None, kind: str | None = None, since: str | None = None, cursor: int | None = None,
                      limit: int = 50) -> dict:
    """One page of the events, newest first (by id): of one switch, of one kind of KINDS or a group of KIND_GROUPS
    (ValueError(UNKNOWN_KIND) for anything else), from the time since on (as the tables store it, history.to_utc), before the id
    cursor. {"rows": [{"id", "ts", "switch_id", "switch", "kind", "label", "port", "text", "detail"}], "next": the id of the last
    row when more follow, else None}."""
    where, args = [], []
    if kind is not None:
        kinds = KIND_GROUPS.get(kind) or ((kind,) if kind in KINDS else ())
        if not kinds:
            raise ValueError(UNKNOWN_KIND)
        where.append(f"e.kind IN ({', '.join('?' * len(kinds))})")
        args += kinds
    for clause, value in (("e.switch_id = ?", switch_id), ("e.ts >= ?", since), ("e.id < ?", cursor)):
        if value is not None:
            where.append(clause)
            args.append(value)
    async with db() as conn:
        async with conn.execute("SELECT e.id, e.ts, e.switch_id, coalesce(s.name, '') AS switch, e.kind, e.port, e.text, e.detail "
                                "FROM events e LEFT JOIN switches s ON s.id = e.switch_id"
                                f"{' WHERE ' + ' AND '.join(where) if where else ''} ORDER BY e.id DESC LIMIT ?", [*args, limit + 1]) as cur:
            got = await cur.fetchall()
    rows = [{"id": r["id"], "ts": r["ts"], "switch_id": r["switch_id"], "switch": r["switch"], "kind": r["kind"],
             "label": KINDS.get(r["kind"], r["kind"]), "port": r["port"], "text": r["text"], "detail": json.loads(r["detail"])}
            for r in got[:limit]]
    return {"rows": rows, "next": rows[-1]["id"] if len(got) > limit else None}
