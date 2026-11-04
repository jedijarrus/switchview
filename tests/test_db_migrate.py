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
    },
    "ports": {
        "poe_admin": ("INTEGER", 0, None),
        "poe_status": ("INTEGER", 0, None),
        "poe_power": ("INTEGER", 0, None),
    },
    "changes": {
        "mechanism": ("TEXT", 0, None),
    },
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
    # Rows from before the feature have no RW identity, no PoE data and no mechanism (they were all SSH changes).
    assert [c for c in NEW_COLUMNS["switches"] if c not in ("driver", "snmp_write") and switch[c] is not None] == []
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
