"""Shared database helpers of the suite: a connection to the database the app uses now (db.settings.db_path, which each test's fixture
points at a fresh one under tmp_path), a query that commits, a switches row with exactly the given columns, and stand-ins for an
async function that raise.

Unlike tests/switchfix.py this module imports app code, so tests/conftest.py imports it only inside a fixture (like netfix); a test
module imports it at the top, after conftest.py has set the environment.
"""
import sqlite3

import db


def connect() -> sqlite3.Connection:
    """A connection to the database the app uses now, its rows as sqlite3.Row. The caller closes it."""
    conn = sqlite3.connect(db.settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def query(sql: str, args: tuple = ()) -> list[tuple]:
    """The rows of sql as tuples; commits, so an INSERT or UPDATE takes effect as well."""
    conn = connect()
    try:
        rows = [tuple(r) for r in conn.execute(sql, args).fetchall()]
        conn.commit()
        return rows
    finally:
        conn.close()


def insert_switch(**cols) -> int:
    """A switches row with exactly cols (no defaults of its own); its id."""
    conn = connect()
    try:
        cur = conn.execute(f"INSERT INTO switches ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(cols.values()))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


async def raising_async(exc: BaseException):
    """A coroutine that raises exc."""
    raise exc


def raising_async_fn(exc: BaseException):
    """A function that returns such a coroutine, whatever it is called with (a stand-in for an async function)."""
    return lambda *args, **kwargs: raising_async(exc)
