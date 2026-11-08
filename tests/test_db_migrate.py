"""Tests for the schema migration in app/db.py: migrate(conn) and its call from init_db().

SwitchView keeps one SQLite file on a volume, so every upgrade runs against a database that an older release created. migrate() adds
the columns of the SNMP multivendor work to such a database with ALTER TABLE ... ADD COLUMN, once per missing column, and has to be a
no-op on every later start. The tests pin what an operator relies on: the new columns exist with exactly the planned definitions,
existing rows keep their data and read as "ProCurve, SNMP write off" (an upgrade changes no behaviour), and running it again, or on a
half-migrated file, neither fails nor touches anything that is already there.

SCHEMA in app/db.py stays the pre-migration schema on purpose: migrate() is the one place that adds the new columns, so a fresh
database and an existing one take the same path. That is why the "legacy" database below is simply db.SCHEMA plus a few rows.

Nothing here opens the real data directory. The migrate() tests use their own sqlite file under tmp_path; the init_db() tests point
db() at tmp_path by replacing db.settings (Settings is a frozen dataclass, so the object is swapped, not mutated).
"""
from contextlib import asynccontextmanager

import aiosqlite
import pytest
import pytest_asyncio

import config
import db
from drivers import DRIVERS, driver_for

# What migrate() has to add, written out by hand from the plan and independent of app/db.py:
# table -> column -> (declared type, NOT NULL flag, default expression), exactly as PRAGMA table_info reports a column.
NEW_COLUMNS = {
    "switches": {
        "driver": ("TEXT", 1, "'procurve'"),
        "snmp_write": ("INTEGER", 1, "0"),
        "snmp_rw_community": ("TEXT", 0, None),
        "snmp_rw_user": ("TEXT", 0, None),
        "snmp_rw_auth_proto": ("TEXT", 0, None),
        "snmp_rw_auth_pass": ("TEXT", 0, None),
        "snmp_rw_priv_proto": ("TEXT", 0, None),
        "snmp_rw_priv_pass": ("TEXT", 0, None),
        "ssh_host_key": ("TEXT", 0, None),
        "ssh_host_key_at": ("TEXT", 0, None),
        "poll_failures": ("INTEGER", 1, "0"),    # Phase 4b appends the poll state (Task 4)
        "down_since": ("TEXT", 0, None),
        "last_ok_at": ("TEXT", 0, None),
        "unread_fields": ("TEXT", 0, None),
        "compliance_cfg_at": ("TEXT", 0, None),    # and the last check of the security rules per source (Task 5)
        "compliance_snmp_at": ("TEXT", 0, None),
    },
    "ports": {
        "poe_admin": ("INTEGER", 0, None),
        "poe_status": ("INTEGER", 0, None),
        "poe_power": ("INTEGER", 0, None),
    },
    "changes": {
        "mechanism": ("TEXT", 0, None),
        "sent": ("INTEGER", 0, None),    # Phase 3 appends sent
        "role": ("TEXT", 0, None),       # Phase 4a appends role and approved_by
        "approved_by": ("TEXT", 0, None),
        "confirm_minutes": ("INTEGER", 0, None),    # Phase 4c appends the confirmation (Task 4)
        "confirm_until": ("TEXT", 0, None),
        "confirmed_by": ("TEXT", 0, None),
        "bulk_id": ("INTEGER", 0, None),    # and the bulk change a change belongs to (Task 7)
    },
}
# config_backups and switch_cfg are not in NEW_COLUMNS: their Phase 3 columns are checked by test_migration_adds_the_phase3_columns.
# The columns Phase 3 adds, (table, column) -> (declared type, NOT NULL flag, default expression), and what an existing row reads then.
PHASE3_COLUMNS = {
    ("changes", "sent"): (("INTEGER", 0, None), None),
    ("switch_cfg", "stale"): (("INTEGER", 1, "0"), 0),
    ("config_backups", "raw_mac"): (("TEXT", 0, None), None),
}
# The columns Phase 4a adds, in the same form. Sessions of before keep NULL in all three: no stored roles, the subject of their
# method and user name, and their first request counts as activity (auth.current_user). Audit entries and changes of before have no
# role (NULL), and no change of before was approved by anyone (approved_by NULL).
PHASE4A_COLUMNS = {
    ("sessions", "claims"): (("TEXT", 0, None), None),
    ("sessions", "subject"): (("TEXT", 0, None), None),
    ("sessions", "last_seen"): (("TEXT", 0, None), None),
    ("audit", "role"): (("TEXT", 0, None), None),
    ("changes", "role"): (("TEXT", 0, None), None),
    ("changes", "approved_by"): (("TEXT", 0, None), None),
}
# The tables Phase 4a adds (db.SCHEMA, CREATE TABLE IF NOT EXISTS), table -> (name, declared type, NOT NULL flag, default, position in
# the primary key) of every column, as PRAGMA table_info reports them. A database of before has none of them; init_db creates each
# one empty. Task 5: zone_scopes, the Admin-kept list "app role -> zone". Task 6: approvals, the four-eyes requests.
PHASE4A_TABLES = {
    "zone_scopes": [("principal", "TEXT", 1, None, 1), ("zone", "TEXT", 1, None, 2)],
    "approvals": [("id", "INTEGER", 0, None, 1), ("kind", "TEXT", 1, None, 0), ("switch_id", "INTEGER", 0, None, 0),
                  ("summary", "TEXT", 1, None, 0), ("payload", "TEXT", 1, None, 0), ("preview", "TEXT", 1, None, 0),
                  ("status", "TEXT", 1, None, 0), ("requested_by", "TEXT", 1, None, 0), ("requester_name", "TEXT", 0, None, 0),
                  ("requester_subject", "TEXT", 1, None, 0), ("requester_role", "TEXT", 0, None, 0), ("requested_at", "TEXT", 1, None, 0),
                  ("expires_at", "TEXT", 1, None, 0), ("decided_by", "TEXT", 0, None, 0), ("decided_subject", "TEXT", 0, None, 0),
                  ("decided_at", "TEXT", 0, None, 0), ("comment", "TEXT", 0, None, 0), ("reason", "TEXT", 0, None, 0),
                  ("change_id", "INTEGER", 0, None, 0)],
}


async def _table_info(conn, table: str) -> list[tuple]:
    """(name, declared type, NOT NULL flag, default) of every column, in table order.

    PRAGMA table_info rows are (cid, name, type, notnull, dflt_value, pk); they are read by index, so this works with and without a
    row_factory on the connection."""
    async with conn.execute(f"PRAGMA table_info({table})") as cur:
        return [(r[1], r[2], r[3], r[4]) for r in await cur.fetchall()]


async def _assert_has_new_columns(conn):
    """Every new column exists in its table with the planned definition (a missing column shows up as None in the diff)."""
    for table, columns in NEW_COLUMNS.items():
        have = {r[0]: r[1:] for r in await _table_info(conn, table)}
        assert {name: have.get(name) for name in columns} == columns, table


async def _schema_version(conn) -> int:
    """SQLite raises this counter on every schema change, so an unchanged value proves that no ALTER TABLE ran in between."""
    async with conn.execute("PRAGMA schema_version") as cur:
        return (await cur.fetchone())[0]


async def _first_row(conn, table: str) -> dict:
    """The (only) row of `table` as a dict; needs aiosqlite.Row as row_factory."""
    async with conn.execute(f"SELECT * FROM {table}") as cur:
        return dict(await cur.fetchone())


@asynccontextmanager
async def _legacy_db(path):
    """A database the way the release before this migration left it: the old schema and one row in each table that gains columns."""
    conn = await aiosqlite.connect(path)
    try:
        conn.row_factory = aiosqlite.Row    # as db() sets it
        await conn.executescript(db.SCHEMA)
        await conn.execute("INSERT INTO switches (name, host, zone, snmp_version, snmp_community, ssh_user) VALUES (?, ?, ?, ?, ?, ?)",
                           ("SW-EK-01", "203.0.113.21", "EK", "2c", "enc:ro-community", "manager"))
        await conn.execute("INSERT INTO ports (switch_id, ifindex, name, alias, oper, admin) VALUES (1, 1, 'A1', 'Platz-107', 1, 1)")
        await conn.execute("INSERT INTO changes (switch_id, kind, summary, status) VALUES (1, 'port', 'A1: VLAN 20', 'ok')")
        await conn.commit()
        # The premise of every test below. Should db.SCHEMA ever define one of the new columns itself, migrate() would skip it and
        # these tests would silently stop exercising ALTER TABLE, so fail loudly instead.
        for table, columns in NEW_COLUMNS.items():
            known = {r[0] for r in await _table_info(conn, table)}
            assert not known & set(columns), f"db.SCHEMA already defines new columns of {table}: this is no longer a legacy database"
        yield conn
    finally:
        await conn.close()


@pytest_asyncio.fixture
async def legacy(tmp_path):
    async with _legacy_db(tmp_path / "legacy.db") as conn:
        yield conn


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """Point db() (and so init_db()) at a scratch directory instead of /data."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    return tmp_path


@pytest.mark.parametrize("table", list(NEW_COLUMNS))
async def test_migrate_adds_exactly_the_new_columns(legacy, table):
    before = await _table_info(legacy, table)

    await db.migrate(legacy)

    after = await _table_info(legacy, table)
    assert after[:len(before)] == before    # every old column is still there, unchanged and in its place
    appended = {name: (type_, notnull, default) for name, type_, notnull, default in after[len(before):]}
    assert appended == NEW_COLUMNS[table]   # and exactly the planned ones were added: no more, none missing, as defined


async def test_migrate_keeps_legacy_rows_and_reads_them_as_procurve_without_snmp_write(legacy):
    before = {table: await _first_row(legacy, table) for table in NEW_COLUMNS}

    await db.migrate(legacy)

    after = {table: await _first_row(legacy, table) for table in NEW_COLUMNS}
    for table in NEW_COLUMNS:
        assert {k: after[table][k] for k in before[table]} == before[table]    # nothing that was stored has changed
    switch = after["switches"]
    assert switch["driver"] == "procurve"
    assert switch["snmp_write"] == 0
    assert switch["poll_failures"] == 0    # Phase 4b: no failed poll in a row yet
    # Rows from before the feature have no RW identity, no PoE data and no mechanism (they were all SSH changes).
    assert [c for c in NEW_COLUMNS["switches"] if c not in ("driver", "snmp_write", "poll_failures") and switch[c] is not None] == []
    assert [c for c in NEW_COLUMNS["ports"] if after["ports"][c] is not None] == []
    assert after["changes"]["mechanism"] is None


async def test_migrated_legacy_switch_resolves_to_the_procurve_driver(legacy):
    # Later code fetches `SELECT * FROM switches` and hands the row to drivers.driver_for, which raises on a row without `driver`.
    await db.migrate(legacy)

    async with legacy.execute("SELECT * FROM switches") as cur:
        row = await cur.fetchone()
    assert driver_for(row) is DRIVERS["procurve"]


async def test_migrate_twice_is_a_no_op(legacy):
    await db.migrate(legacy)
    tables = {table: await _table_info(legacy, table) for table in NEW_COLUMNS}
    version = await _schema_version(legacy)
    # An operator has configured things since the first run; a repeated start must not reset or rewrite any of it.
    await legacy.execute("UPDATE switches SET driver = 'cisco', snmp_write = 1, snmp_rw_community = 'enc:rw-community'")

    await db.migrate(legacy)    # SQLite would raise "duplicate column name" for a column that is added a second time

    assert {table: await _table_info(legacy, table) for table in NEW_COLUMNS} == tables
    for table_columns in tables.values():
        names = [name for name, *_ in table_columns]
        assert len(names) == len(set(names))
    assert await _schema_version(legacy) == version    # no schema change at all, not even a harmless one
    switch = await _first_row(legacy, "switches")
    assert (switch["driver"], switch["snmp_write"], switch["snmp_rw_community"]) == ("cisco", 1, "enc:rw-community")


async def test_migrate_completes_a_partially_migrated_database(legacy):
    # A start that died between two ALTER TABLEs, or a file edited by hand: some of the new columns are already there.
    await legacy.execute("ALTER TABLE switches ADD COLUMN driver TEXT NOT NULL DEFAULT 'procurve'")
    await legacy.execute("ALTER TABLE switches ADD COLUMN snmp_rw_priv_pass TEXT")
    await legacy.execute("ALTER TABLE ports ADD COLUMN poe_admin INTEGER")

    await db.migrate(legacy)

    await _assert_has_new_columns(legacy)
    for table in NEW_COLUMNS:
        names = [name for name, *_ in await _table_info(legacy, table)]
        assert len(names) == len(set(names))
    assert (await _first_row(legacy, "switches"))["driver"] == "procurve"


async def test_migrate_does_not_need_a_row_factory(tmp_path):
    # db() always sets aiosqlite.Row, but migrate() takes any connection; a plain one returns tuples, where row["name"] would fail.
    async with aiosqlite.connect(tmp_path / "plain.db") as conn:
        await conn.executescript(db.SCHEMA)

        await db.migrate(conn)
        await db.migrate(conn)

        await _assert_has_new_columns(conn)


async def test_init_db_creates_a_fresh_database_with_the_new_columns(data_dir):
    await db.init_db()

    async with aiosqlite.connect(data_dir / "switchview.db") as conn:
        await _assert_has_new_columns(conn)


async def test_init_db_upgrades_an_existing_database_and_survives_a_restart(data_dir):
    path = data_dir / "switchview.db"
    async with _legacy_db(path):
        pass    # the file exactly as the previous release left it; the connection is closed again before the app starts

    await db.init_db()
    await db.init_db()    # every restart of the app runs it once more

    async with aiosqlite.connect(path) as conn:
        conn.row_factory = aiosqlite.Row
        await _assert_has_new_columns(conn)
        switch = await _first_row(conn, "switches")
    assert (switch["name"], switch["host"]) == ("SW-EK-01", "203.0.113.21")
    assert switch["driver"] == "procurve"
    assert switch["snmp_write"] == 0


async def _first_row_plain(conn, table: str) -> dict:
    """The (only) row of table as a dict, on a connection without a row_factory."""
    async with conn.execute(f"SELECT * FROM {table}") as cur:
        names = [d[0] for d in cur.description]
        return dict(zip(names, await cur.fetchone()))


async def _table_names(conn) -> set[str]:
    """The names of every table of the database on conn."""
    async with conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'") as cur:
        return {r[0] for r in await cur.fetchall()}


async def _added_state(conn, columns: dict) -> dict:
    """(definition, value in the one row) of each (table, column) of columns; a missing column is (None, None)."""
    out = {}
    for table, column in columns:
        have = {r[0]: r[1:] for r in await _table_info(conn, table)}
        if column not in have:
            out[(table, column)] = (None, None)
            continue
        async with conn.execute(f"SELECT {column} FROM {table}") as cur:
            [(value,)] = [tuple(r) for r in await cur.fetchall()]
        out[(table, column)] = (have[column], value)
    return out


async def test_migration_adds_the_phase3_columns(data_dir):
    """Review Focus 1: a database as the release before Phase 3 left it (db.SCHEMA, every column added before Phase 3, one row in
    changes, switch_cfg and config_backups) gets changes.sent (the row: NULL, unknown), switch_cfg.stale (the row: 0, INTEGER NOT NULL
    DEFAULT 0) and config_backups.raw_mac (the row: NULL) from init_db, the rows keep what they held; a second init_db changes
    nothing."""
    path = data_dir / "switchview.db"
    async with aiosqlite.connect(path) as conn:
        await conn.executescript(db.SCHEMA)
        for table, column, definition in db.ADDED_COLUMNS:
            if (table, column) not in PHASE3_COLUMNS:
                await conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        await conn.execute("INSERT INTO switches (name, host) VALUES ('SW-EK-01', '203.0.113.21')")
        await conn.execute("INSERT INTO changes (switch_id, kind, summary, status, mechanism) VALUES (1, 'ports', 'A1: VLAN 20', 'failed', 'ssh')")
        await conn.execute("INSERT INTO switch_cfg (switch_id, taken_at, parsed) VALUES (1, '2026-11-01 10:00:00', '{}')")
        await conn.execute("INSERT INTO config_backups (switch_id, taken_at, sha, content) VALUES (1, '2026-11-01 10:00:00', 'abc', 'x')")
        await conn.commit()
        assert set((await _added_state(conn, PHASE3_COLUMNS)).values()) == {(None, None)}    # the premise: none of the three columns is there yet
        before = {t: await _first_row_plain(conn, t) for t in ("changes", "switch_cfg", "config_backups")}

    await db.init_db()

    async with aiosqlite.connect(path) as conn:
        assert await _added_state(conn, PHASE3_COLUMNS) == PHASE3_COLUMNS
        for table, row in before.items():
            assert {k: v for k, v in (await _first_row_plain(conn, table)).items() if k in row} == row
        version, rows = await _schema_version(conn), {t: await _first_row_plain(conn, t) for t in before}

    await db.init_db()    # every restart of the app runs it once more

    async with aiosqlite.connect(path) as conn:
        assert await _schema_version(conn) == version
        assert {t: await _first_row_plain(conn, t) for t in before} == rows


async def test_migration_adds_the_phase4a_columns(data_dir):
    """Review Focus 3: a database as the release before Phase 4a left it (db.SCHEMA without the Phase 4a tables, every column added
    before Phase 4a, one session, one audit entry and one change of before) gets sessions.claims, sessions.subject, sessions.last_seen,
    audit.role, changes.role and changes.approved_by from init_db (the rows: NULL in each) and the tables of PHASE4A_TABLES (empty),
    the rows keep what they held; a second init_db changes nothing."""
    path = data_dir / "switchview.db"
    async with aiosqlite.connect(path) as conn:
        await conn.executescript(db.SCHEMA)
        for table in PHASE4A_TABLES:
            await conn.execute(f"DROP TABLE {table}")
        for table, column, definition in db.ADDED_COLUMNS:
            if (table, column) not in PHASE4A_COLUMNS:
                await conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        await conn.execute("INSERT INTO sessions (token, username, display_name, method, created_at, expires_at) VALUES "
                           "(?, 'anna@example.org', 'Anna', 'entra', '2026-11-07T08:00:00+00:00', '2026-11-07T20:00:00+00:00')",
                           (db.token_hash("vorher"),))    # a hashed token: init_db's rehashing leaves the row as it is
        await conn.execute("INSERT INTO audit (username, action, target, detail) VALUES ('anna@example.org', 'login', 'entra', '')")
        await conn.execute("INSERT INTO switches (name, host) VALUES ('SW-EK-01', '203.0.113.21')")
        await conn.execute("INSERT INTO changes (switch_id, username, kind, summary, status, mechanism, sent) VALUES "
                           "(1, 'anna@example.org', 'ports', 'Port 2: VLAN 20', 'ok', 'ssh', 1)")
        await conn.commit()
        assert set((await _added_state(conn, PHASE4A_COLUMNS)).values()) == {(None, None)}    # the premise: none of them is there yet
        assert not await _table_names(conn) & set(PHASE4A_TABLES)
        before = {t: await _first_row_plain(conn, t) for t in sorted({table for table, _ in PHASE4A_COLUMNS})}

    await db.init_db()

    async with aiosqlite.connect(path) as conn:
        assert await _added_state(conn, PHASE4A_COLUMNS) == PHASE4A_COLUMNS
        for table, columns in PHASE4A_TABLES.items():
            async with conn.execute(f"PRAGMA table_info({table})") as cur:
                assert [(r[1], r[2], r[3], r[4], r[5]) for r in await cur.fetchall()] == columns, table
            async with conn.execute(f"SELECT count(*) FROM {table}") as cur:
                assert (await cur.fetchone())[0] == 0, table
        for table, row in before.items():
            assert {k: v for k, v in (await _first_row_plain(conn, table)).items() if k in row} == row
        version, rows = await _schema_version(conn), {t: await _first_row_plain(conn, t) for t in before}

    await db.init_db()    # every restart of the app runs it once more

    async with aiosqlite.connect(path) as conn:
        assert await _schema_version(conn) == version
        assert {t: await _first_row_plain(conn, t) for t in before} == rows


# The tables and the columns Phase 4b adds (Tasks 2-8 extend both): Task 2 the sightings, Task 4 the events and the switches' poll
# state (failures in a row, unreachable since, last good poll, the fields it could not read) and whether a backup differs from the
# one before without a SwitchView change, Task 5 the findings of the security rules and their last check per source, Task 6 the
# alert queue, Task 7 the MAC watch list. A database as Phase 4a left it has none of them; init_db creates each table empty, with
# the indexes db.SCHEMA gives it, and adds each column, which a row of before reads as the column's default.
PHASE4B_TABLES = {"sightings", "events", "findings", "alert_outbox", "watch_macs"}
PHASE4B_COLUMNS: set[tuple[str, str]] = {("switches", "poll_failures"), ("switches", "down_since"), ("switches", "last_ok_at"),
                                         ("switches", "unread_fields"), ("config_backups", "outside"), ("switches", "compliance_cfg_at"),
                                         ("switches", "compliance_snmp_at")}
# The tables and the columns Phase 4c adds (Tasks 4, 7 and 8 extend both): Task 2 the API tokens (with idx_api_tokens_subject) and
# the API token an audit entry was made with, Task 4 the confirmation of a change (its minutes, its deadline, who confirmed it), Task
# 7 the bulk changes with their switches (with idx_bulks_status) and the bulk change a change belongs to. A database as Phase 4b left
# it has none of them, and its audit entries and changes read NULL there.
PHASE4C_TABLES = {"api_tokens", "bulks", "bulk_items"}
PHASE4C_COLUMNS: set[tuple[str, str]] = {("audit", "token"), ("changes", "confirm_minutes"), ("changes", "confirm_until"),
                                         ("changes", "confirmed_by"), ("changes", "bulk_id")}


async def _index_names(conn, tables: set[str]) -> set[str]:
    """The names of every index on the tables in tables."""
    async with conn.execute("SELECT name, tbl_name FROM sqlite_master WHERE type = 'index'") as cur:
        return {r[0] for r in await cur.fetchall() if r[1] in tables}


async def _default_of(conn, table: str, column: str):
    """What a row of before reads in table.column once migrate() added it: the value of its default expression, NULL without one."""
    [default] = [r[3] for r in await _table_info(conn, table) if r[0] == column]
    if default is None:
        return None
    async with conn.execute(f"SELECT {default}") as cur:
        return (await cur.fetchone())[0]


@pytest.mark.parametrize("tables, columns", [(PHASE4B_TABLES, PHASE4B_COLUMNS), (PHASE4C_TABLES, PHASE4C_COLUMNS)], ids=["4b", "4c"])
async def test_migration_adds_the_tables_and_columns_of_a_phase(data_dir, tables, columns):
    """A database as the phase before left it (db.SCHEMA without the tables of tables, every column of db.ADDED_COLUMNS but those of
    columns, one switch, one backup, one audit entry and one change) gets the tables (empty, with their indexes) and the columns (the
    rows: the column's default) from init_db, the rows keep what they held; a second init_db changes nothing."""
    path = data_dir / "switchview.db"
    async with aiosqlite.connect(path) as conn:
        await conn.executescript(db.SCHEMA)
        indexes = await _index_names(conn, tables)
        for table in tables:
            await conn.execute(f"DROP TABLE {table}")
        for table, column, definition in db.ADDED_COLUMNS:
            if (table, column) not in columns:
                await conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        await conn.execute("INSERT INTO switches (name, host) VALUES ('SW-EK-01', '203.0.113.21')")
        await conn.execute("INSERT INTO config_backups (switch_id, taken_at, sha, content) VALUES (1, '2026-11-01 02:30:00', 'abc', 'x')")
        await conn.execute("INSERT INTO audit (username, action, target, detail, role) VALUES ('anna', 'login', 'entra', '', 'aendern')")
        await conn.execute("INSERT INTO changes (switch_id, username, kind, summary, status, mechanism, sent) VALUES "
                           "(1, 'anna', 'ports', 'Port 2: VLAN 20', 'ok', 'ssh', 1)")
        await conn.commit()
        # the premise: none of the tables, their indexes or the columns is there yet
        assert not await _table_names(conn) & tables and not await _index_names(conn, tables)
        assert set((await _added_state(conn, columns)).values()) <= {(None, None)}
        before = {t: await _first_row_plain(conn, t) for t in ("switches", "config_backups", "audit", "changes")}

    await db.init_db()

    async with aiosqlite.connect(path) as conn:
        assert tables <= await _table_names(conn) and await _index_names(conn, tables) == indexes
        for table in tables:
            async with conn.execute(f"SELECT count(*) FROM {table}") as cur:
                assert (await cur.fetchone())[0] == 0, table
        for (table, column), (definition, value) in (await _added_state(conn, columns)).items():
            assert definition is not None and value == await _default_of(conn, table, column), (table, column)
        for table, row in before.items():
            assert {k: v for k, v in (await _first_row_plain(conn, table)).items() if k in row} == row
        version, rows = await _schema_version(conn), {t: await _first_row_plain(conn, t) for t in before}

    await db.init_db()    # every restart of the app runs it once more

    async with aiosqlite.connect(path) as conn:
        assert await _schema_version(conn) == version
        assert {t: await _first_row_plain(conn, t) for t in before} == rows
