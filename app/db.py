"""SQLite-Zugriff. Immer ueber db() verbinden (PRAGMAs pro Connection)."""
import os
from contextlib import asynccontextmanager

import aiosqlite

from config import settings

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


async def init_db():
    async with db() as conn:
        await conn.executescript(SCHEMA)
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


async def audit(username: str | None, action: str, target: str = "", detail: str = ""):
    async with db() as conn:
        await conn.execute(
            "INSERT INTO audit(username, action, target, detail) VALUES(?, ?, ?, ?)",
            (username, action, target, detail),
        )
        await conn.commit()
