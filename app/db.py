"""SQLite-Zugriff. Immer ueber db() verbinden (PRAGMAs pro Connection)."""
import hashlib
import os
import re
import sqlite3
from collections.abc import Iterable
from contextlib import asynccontextmanager, closing

import aiosqlite

from config import settings

# Urstand der Tabellen. Spaeter dazugekommene Spalten gehoeren NICHT hierher, sondern in ADDED_COLUMNS (siehe migrate()).
SCHEMA = """
CREATE TABLE IF NOT EXISTS switches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL UNIQUE,
    zone TEXT NOT NULL DEFAULT '',
    sort INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    snmp_version TEXT NOT NULL DEFAULT '2c',
    snmp_community TEXT,
    snmp_user TEXT,
    snmp_auth_proto TEXT,
    snmp_auth_pass TEXT,
    snmp_priv_proto TEXT,
    snmp_priv_pass TEXT,
    ssh_user TEXT,
    ssh_pass TEXT,
    sys_name TEXT,
    sys_descr TEXT,
    model TEXT,
    firmware TEXT,
    base_mac TEXT,
    uptime INTEGER,
    last_poll TEXT,
    last_poll_ok INTEGER,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ports (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    ifindex INTEGER NOT NULL,
    name TEXT NOT NULL,
    alias TEXT,
    oper INTEGER,
    admin INTEGER,
    speed INTEGER,
    pvid TEXT,
    untagged TEXT,
    tagged TEXT,
    trunk TEXT,
    members TEXT,
    lldp TEXT,
    mac_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (switch_id, ifindex)
);
CREATE TABLE IF NOT EXISTS vlans (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    vid TEXT NOT NULL,
    name TEXT,
    PRIMARY KEY (switch_id, vid)
);
CREATE TABLE IF NOT EXISTS macs (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    port TEXT NOT NULL,
    mac TEXT NOT NULL,
    vlan TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (switch_id, mac, vlan)
);
CREATE INDEX IF NOT EXISTS idx_macs_port ON macs(switch_id, port);
CREATE TABLE IF NOT EXISTS names (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    name TEXT,
    vendor TEXT,
    source TEXT,
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS config_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    taken_at TEXT NOT NULL,
    sha TEXT NOT NULL,
    content TEXT NOT NULL,
    trigger TEXT NOT NULL DEFAULT 'nightly'
);
CREATE INDEX IF NOT EXISTS idx_backups_sw ON config_backups(switch_id, taken_at);
CREATE TABLE IF NOT EXISTS switch_cfg (
    switch_id INTEGER PRIMARY KEY REFERENCES switches(id) ON DELETE CASCADE,
    taken_at TEXT NOT NULL,
    parsed TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    username TEXT,
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    request TEXT,
    ports TEXT,
    desired TEXT,
    before TEXT,
    commands TEXT,
    status TEXT NOT NULL,
    saved INTEGER NOT NULL DEFAULT 0,
    expert INTEGER NOT NULL DEFAULT 0,
    steps TEXT,
    output TEXT,
    error TEXT,
    revert_of INTEGER,
    reverted_by INTEGER
);
CREATE INDEX IF NOT EXISTS idx_changes_sw ON changes(switch_id, id);
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'sonstiges',
    location TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    allowed INTEGER NOT NULL DEFAULT 0,
    valid_until TEXT,
    pf_state TEXT,
    pf_error TEXT,
    pf_synced_at TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT,
    method TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    username TEXT,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);
-- Phase 4a, Task 5: the zone scopes, kept by an Admin (PUT /api/zone-scopes). A user with Ändern or Freigeben whose Entra app roles
-- (sessions.claims) contain a principal here changes only switches whose zone is one of that principal's zones (roles.zones_of);
-- zone '' is the switches without a zone. Read on every request of such a user (auth.current_user). Empty: no one is limited.
CREATE TABLE IF NOT EXISTS zone_scopes (principal TEXT NOT NULL, zone TEXT NOT NULL, PRIMARY KEY (principal, zone));
-- Phase 4a, Task 6: the four-eyes requests (app/approvals.py). One row per request: its kind (approvals.KINDS), its switch (NULL for
-- a kind without one; deleting the switch deletes its requests), the exact desired state its requester sent (payload, JSON) and the
-- preview they saw (preview, JSON), its status (open, then approved, rejected, withdrawn, expired or stale), who asked (user name,
-- display name, subject, role) and when, when it expires (ISO-UTC), who decided and when, the rejection's comment, the reason of a
-- stale one and the change an approval started (Task 7).
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, switch_id INTEGER REFERENCES switches(id) ON DELETE CASCADE,
    summary TEXT NOT NULL, payload TEXT NOT NULL, preview TEXT NOT NULL, status TEXT NOT NULL,
    requested_by TEXT NOT NULL, requester_name TEXT, requester_subject TEXT NOT NULL, requester_role TEXT,
    requested_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    decided_by TEXT, decided_subject TEXT, decided_at TEXT, comment TEXT, reason TEXT, change_id INTEGER);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, id);
-- Phase 4b, Task 2: where each device was seen (app/history.py). Written only by history.record after a good poll (one round of
-- poll_all at once, a single poll for its switch). One row per place - a MAC at a switch, a port and a VLAN, with the IP and name
-- known for it - from the poll that first saw it there to the last one that did; a new row only when the place changes or another
-- IP turns up there, otherwise last_seen moves on. Trunks and confirmed uplinks are no place; suspect marks a possible uplink.
-- Purged after HISTORY_DAYS (history.purge). A deleted switch keeps its rows (ON DELETE SET NULL, its name in switch_name): where a
-- device was stays a question after a switch is replaced.
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL,
    switch_id INTEGER REFERENCES switches(id) ON DELETE SET NULL, switch_name TEXT NOT NULL DEFAULT '',
    port TEXT NOT NULL, vlan TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',
    suspect INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sightings_mac ON sightings(mac, last_seen);
CREATE INDEX IF NOT EXISTS idx_sightings_ip ON sightings(ip, last_seen) WHERE ip <> '';
CREATE INDEX IF NOT EXISTS idx_sightings_port ON sightings(switch_id, port, last_seen);
CREATE INDEX IF NOT EXISTS idx_sightings_seen ON sightings(last_seen);
-- Phase 4b, Task 4: discrete events (app/monitor.py), one row each: a switch that stops answering (switch_down, after
-- monitor.UNREACHABLE_AFTER failed polls in a row) or answers again (switch_up), an LLDP neighbour that appears, changes or vanishes
-- at a port (lldp_new, lldp_changed, lldp_gone), a port changed outside SwitchView at a switch it does not back up (drift_port) and a
-- backup that differs from the one before without a SwitchView change between them (drift_config). ts is when it was seen (the
-- poll's time, the backup's), port '' for an event of the whole switch, text the German sentence, detail JSON (monitor.KINDS says
-- what each kind carries). Written by poller.poll_switch (through monitor.poll_succeeded / poll_failed) and sshcli.store_backup
-- (monitor.backup_outside); read by GET /api/events. Deleting the switch deletes its events; purged after HISTORY_DAYS by ts.
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, switch_id INTEGER REFERENCES switches(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, port TEXT NOT NULL DEFAULT '', text TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_events_sw ON events(switch_id, id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
-- Phase 4b, Task 5: the findings of the security rules (app/compliance.py), one row per switch, rule and line: rule an id of
-- compliance.RULES or of a custom rule, source config | custom | snmp (where it was checked), line_no 1-based (NULL for a finding
-- without a line), line the masked line ('' without one), detail the German detail (never a secret value), first_seen and last_seen
-- the first and the last check that found it, resolved_at the check that no longer did (NULL: open). Written by
-- compliance.evaluate_config (sshcli.store_backup), evaluate_snmp (poller.poll_switch) and reevaluate_custom (PUT
-- /api/compliance/rules); read by GET /api/switches/{sid}/findings and GET /api/compliance. Deleting the switch deletes its findings;
-- resolved ones are purged after HISTORY_DAYS by resolved_at.
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE, rule TEXT NOT NULL,
    source TEXT NOT NULL, line_no INTEGER, line TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, resolved_at TEXT);
CREATE INDEX IF NOT EXISTS idx_findings_sw ON findings(switch_id, resolved_at);
-- Phase 4b, Task 6: the alert queue (app/alerts.py), one row per message and channel (mail | webhook): created_at when alerts.emit
-- wrote it, event a key of alerts.EVENTS (or cap, the summary past the hourly limit), dedup_key "<event>:<key>" (the same key within
-- alerts.DEDUP_MINUTES adds to repeats instead of a new row), the switch it is about (no foreign key: a message outlives its switch,
-- switch_name keeps the name), title (one line), text and facts (JSON) as they go out, status queued | sent | failed | suppressed
-- (past the hourly limit, never sent), attempts the failed attempts so far, next_at when a queued row is due, sent_at, error (the
-- masked text of the last failure). Written by alerts.emit, delivered by the scheduler job alerts.deliver_due; read by GET
-- /api/alerts/deliveries. Every row but a queued one is purged after HISTORY_DAYS by created_at.
CREATE TABLE IF NOT EXISTS alert_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, channel TEXT NOT NULL, event TEXT NOT NULL, dedup_key TEXT NOT NULL,
    switch_id INTEGER, switch_name TEXT NOT NULL DEFAULT '', title TEXT NOT NULL, text TEXT NOT NULL, facts TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_at TEXT, sent_at TEXT, error TEXT, repeats INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_outbox_due ON alert_outbox(status, next_at);
CREATE INDEX IF NOT EXISTS idx_outbox_key ON alert_outbox(channel, dedup_key, created_at);
CREATE INDEX IF NOT EXISTS idx_outbox_created ON alert_outbox(created_at);
"""

# Spalten, die nach dem Urstand dazugekommen sind: (Tabelle, Spalte, Definition). migrate() ist die EINZIGE Stelle, die sie anlegt,
# damit eine frische und eine bestehende DB denselben Weg gehen und es keine zweite Quelle der Wahrheit gibt. Neue Spalten nur hier
# anhaengen. Alle Eintraege sind feste Literale und werden so ins SQL eingesetzt: nie Nutzereingaben hier hineinreichen.
ADDED_COLUMNS = (
    # Treiber und SNMP-Schreibfreigabe (Spec 2). Bestandszeilen bleiben ProCurve ohne SNMP-Write, das Verhalten aendert sich nicht.
    ("switches", "driver", "TEXT NOT NULL DEFAULT 'procurve'"),
    ("switches", "snmp_write", "INTEGER NOT NULL DEFAULT 0"),
    # Eigene Write-Identitaet fuer SNMP-SET, getrennt von den Read-Spalten snmp_*. Bestandszeilen haben NULL. Community und Passwoerter
    # liegen wie die Read-Spalten verschluesselt und stehen in main.SECRET_FIELDS (verschluesseln, nur *_set ausliefern, im Audit beim
    # Namen nennen). Ausgeliefert wird ohnehin nur, was in der Allowlist api_switches.PUBLIC_FIELDS steht; welche Identitaet schreibt,
    # entscheidet allein poller.write_identity.
    ("switches", "snmp_rw_community", "TEXT"),
    ("switches", "snmp_rw_user", "TEXT"),
    ("switches", "snmp_rw_auth_proto", "TEXT"),
    ("switches", "snmp_rw_auth_pass", "TEXT"),
    ("switches", "snmp_rw_priv_proto", "TEXT"),
    ("switches", "snmp_rw_priv_pass", "TEXT"),
    # PoE je Port. Bestandszeilen haben NULL.
    ("ports", "poe_admin", "INTEGER"),
    ("ports", "poe_status", "INTEGER"),
    ("ports", "poe_power", "INTEGER"),
    # Audit-Spur: ssh | snmp. Bestandszeilen haben NULL.
    ("changes", "mechanism", "TEXT"),
    # The switch's SSH host key, pinned at the first successful SSH contact ("<type> <base64>", sshcli.host_key_of), and when (UTC).
    # Existing rows have NULL: their next SSH contact pins the key (trust on first use, E30). No secret, but never served as is: GET
    # /api/switches serves its fingerprints only.
    ("switches", "ssh_host_key", "TEXT"),
    ("switches", "ssh_host_key_at", "TEXT"),
    # The mark of the unmasked running-config a backup was taken from: crypto.keyed_digest("backup", text), never a plain hash (that
    # would be an oracle for the masked secrets in a copy of the database). sshcli.store_backup compares it to tell a change of
    # secrets alone, which the masked sha cannot see. Existing rows have NULL: the next backup of the same masked text fills it in.
    ("config_backups", "raw_mac", "TEXT"),
    # Whether a change may have reached its switch: 0 while nothing has gone out (changes.create_change writes 0), 1 from the moment
    # the switch may have taken something (right before send_config_set / write memory over SSH, right before the SET over SNMP).
    # Existing rows have NULL: unknown, and counted as sent (changes.may_have_sent), so they keep revert and save as before.
    ("changes", "sent", "INTEGER"),
    # Whether the switch may have changed since its read of the running-config (switch_cfg): 1 once an SNMP SET or SSH lines may have
    # gone out (changes.mark_cfg_stale), 0 again with the next read (changes.store_cfg). taken_at stays the time of the read. fresh_cfg
    # reads anew for a stale entry, and the map takes a port's on / off from the poll then. Existing rows have 0.
    ("switch_cfg", "stale", "INTEGER NOT NULL DEFAULT 0"),
    # Phase 4a, written by auth.create_session at the login: the roles claim of the id_token as JSON ({"roles": [...]}, from which
    # auth.current_user works out the role on every request), the stable identity of the person (entra:<oid>, without an oid
    # entra:<sub>; local:<user name>) and the time of the last request (ISO-UTC like created_at, written at most once a minute, for
    # the idle logout). Sessions of before have NULL: no stored roles, the subject <method>:<user name>, and their first request
    # counts as activity.
    ("sessions", "claims", "TEXT"),
    ("sessions", "subject", "TEXT"),
    ("sessions", "last_seen", "TEXT"),
    # Phase 4a: the role of whoever made an audit entry (audit() requires it; NULL for a failed login, which has no session), the role
    # of whoever started a change (changes.create_change; its change_* entry names it, whenever the change ends) and who approved it
    # (Task 7; NULL until then and for every change without a four-eyes request). Rows of before have NULL.
    ("audit", "role", "TEXT"),
    ("changes", "role", "TEXT"),
    ("changes", "approved_by", "TEXT"),
    # Phase 4b, Task 4, written by poller.poll_switch: the failed polls in a row (+1 with each failed poll, 0 with a good one); since
    # when the switch counts as unreachable (set by monitor.poll_failed at the UNREACHABLE_AFTER-th failed poll in a row, NULL again
    # with the next good poll; NULL: reachable); the time of the last good poll (NULL: none since the update, monitor then takes
    # last_poll if that one was good); and the fields of the port configuration (monitor.DRIFT_FIELDS keys, a JSON list) the last
    # good poll could not read completely, which the next one does not compare (NULL: none known, a poll from before the update;
    # monitor then compares none of them when that poll left a note in last_error). Existing rows have 0 and NULL.
    ("switches", "poll_failures", "INTEGER NOT NULL DEFAULT 0"),
    ("switches", "down_since", "TEXT"),
    ("switches", "last_ok_at", "TEXT"),
    ("switches", "unread_fields", "TEXT"),
    # Phase 4b, Task 4, written by sshcli.store_backup (monitor.backup_outside): 1 when the backup differs from the one before it and
    # no SwitchView change that may have sent something ran between the two, 0 when one did. NULL: not compared - the first backup
    # of a switch, a backup from before the update, or one whose check failed.
    ("config_backups", "outside", "INTEGER"),
    # Phase 4b, Task 5, written by compliance (evaluate_config, evaluate_snmp): the time of the last check of the security rules per
    # source, the running-config and the SNMP access. NULL: never checked, so the next check is the baseline and tells nothing.
    # Existing rows have NULL.
    ("switches", "compliance_cfg_at", "TEXT"),
    ("switches", "compliance_snmp_at", "TEXT"),
)


@asynccontextmanager
async def db():
    os.makedirs(settings.data_dir, exist_ok=True)
    conn = await aiosqlite.connect(settings.db_path)
    conn.row_factory = aiosqlite.Row
    try:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    finally:
        await conn.close()


def execute_sync(sql: str, args: tuple = ()) -> int:
    """sql with args on a connection of its own (the stdlib sqlite3, for code in a worker thread, where db() cannot run), committed;
    the number of rows it changed."""
    with closing(sqlite3.connect(settings.db_path, timeout=5)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cur = conn.execute(sql, args)
        conn.commit()
        return cur.rowcount


def query_sync(sql: str, args: tuple = ()) -> list[tuple]:
    """The rows of sql with args, read like execute_sync writes (a connection of its own, for a worker thread), as tuples."""
    with closing(sqlite3.connect(settings.db_path, timeout=5)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        return conn.execute(sql, args).fetchall()


async def migrate(conn) -> None:
    """Legt fehlende Spalten aus ADDED_COLUMNS per ALTER TABLE ... ADD COLUMN an, je Spalte per PRAGMA table_info abgesichert.

    Idempotent: eine vorhandene Spalte bleibt unangetastet (kein Fehler, keine Werte zuruecksetzen), ein zweiter Lauf aendert nichts,
    und ein frueher abgebrochener Lauf wird beim naechsten Aufruf zu Ende gefuehrt. Laeuft nach executescript(SCHEMA) auf derselben
    Connection und committet nicht selbst (das macht init_db). Die Zeilen von table_info werden per Index gelesen, damit es mit und
    ohne row_factory geht. Gegen zwei gleichzeitig startende Prozesse ist die Pruefung nicht gesichert, dafuer gilt die
    Single-Worker-Invariante (siehe main.py)."""
    have: dict[str, set[str]] = {}
    for table, column, definition in ADDED_COLUMNS:
        if table not in have:
            async with conn.execute(f"PRAGMA table_info({table})") as cur:
                have[table] = {row[1] for row in await cur.fetchall()}    # Zeile: (cid, name, type, notnull, dflt_value, pk)
        if column not in have[table]:
            await conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            have[table].add(column)


# A session token as the sessions table keeps it since F4: token_hash, 64 lower-case hex digits. A raw token of before
# (secrets.token_urlsafe(32), 43 characters) never looks like this.
_HASHED_TOKEN = re.compile(r"[0-9a-f]{64}")


def token_hash(token: str) -> str:
    """What the sessions table stores in place of a session token: its SHA-256 as 64 hex digits (F4). A copy of the database then
    holds no value a browser could send as the cookie. The one definition: auth imports it, hash_legacy_session_tokens uses it for
    the rows of before."""
    return hashlib.sha256(token.encode()).hexdigest()


async def hash_legacy_session_tokens(conn) -> int:
    """Replaces every raw session token of a release before F4 by its token_hash, so its browser stays signed in; returns how many it
    replaced. Idempotent: a stored hash is never hashed again, also after a rollback to an older image and a new update (the
    sessions of the older image are raw again). Does not commit (init_db does), works with and without row_factory."""
    async with conn.execute("SELECT token FROM sessions") as cur:
        raw = [row[0] for row in await cur.fetchall() if not _HASHED_TOKEN.fullmatch(row[0])]
    await conn.executemany("UPDATE sessions SET token = ? WHERE token = ?", [(token_hash(t), t) for t in raw])
    return len(raw)


async def init_db():
    async with db() as conn:
        await conn.executescript(SCHEMA)
        await migrate(conn)
        await hash_legacy_session_tokens(conn)
        await conn.commit()


async def get_setting(key: str, default: str | None = None) -> str | None:
    async with db() as conn:
        async with conn.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
    return row["value"] if row else default


async def set_setting(key: str, value: str | None):
    async with db() as conn:
        await conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        await conn.commit()


async def read_settings(conn, keys: Iterable[str]) -> dict[str, str | None]:
    """The value of each settings key in keys (None without a row), read on conn: inside the caller's transaction, if one is open."""
    keys = list(keys)
    if not keys:
        return {}
    async with conn.execute(f"SELECT key, value FROM settings WHERE key IN ({', '.join('?' * len(keys))})", keys) as cur:
        found = {row[0]: row[1] for row in await cur.fetchall()}
    return {k: found.get(k) for k in keys}


async def load_settings(keys: Iterable[str]) -> dict[str, str | None]:
    """The value of each settings key in keys (None without a row), on a connection of its own and in one SELECT (read_settings): one
    state of the table, so a reader that takes a destination and its secret from it never pairs one with the other's old value while a
    settings PUT commits (F2)."""
    async with db() as conn:
        return await read_settings(conn, keys)


async def write_settings(conn, items: dict[str, str | None]) -> None:
    """Stores each key → value of items on conn, without a commit: the caller commits (or not) its transaction as a whole."""
    await conn.executemany("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                           list(items.items()))


async def audit(username: str | None, action: str, target: str = "", detail: str = "", *, role: str | None):
    """One audit entry. role is required as a keyword, so no call can forget it (tests/test_permissions.py checks every call): the
    role of the request (user["role"]), of the new session for a login, of whoever started a change for its change_* entry, None
    for a failed login."""
    async with db() as conn:
        await conn.execute(
            "INSERT INTO audit(username, action, target, detail, role) VALUES(?, ?, ?, ?, ?)",
            (username, action, target, detail, role),
        )
        await conn.commit()
