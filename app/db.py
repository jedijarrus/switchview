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
    # Namen nennen). Ausgeliefert wird ohnehin nur, was in der Allowlist main.PUBLIC_FIELDS steht; welche Identitaet schreibt,
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


async def write_settings(conn, items: dict[str, str | None]) -> None:
    """Stores each key → value of items on conn, without a commit: the caller commits (or not) its transaction as a whole."""
    await conn.executemany("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                           list(items.items()))


async def audit(username: str | None, action: str, target: str = "", detail: str = ""):
    async with db() as conn:
        await conn.execute(
            "INSERT INTO audit(username, action, target, detail) VALUES(?, ?, ?, ?)",
            (username, action, target, detail),
        )
        await conn.commit()
