"""Constants and helpers shared by the login and session tests (tests/test_login_security.py and the session tests after it), next to
the login_api fixture in conftest.py, which sets up the emergency account GOOD names.

A plain module like switchfix.py: the tests import it by name (`from loginfix import ...`). It imports the app's db module (for the
path of the database the app writes to), so conftest.py imports it only inside its fixture, after the test environment is set.
"""
import sqlite3
from contextlib import closing

import db

CSRF = {"X-Requested-With": "SwitchView"}                              # the header the app wants on every non-GET request
GOOD = {"username": "admin", "password": "Notfall-Kennwort-ß1"}        # the emergency account of login_api; "ß" on purpose
BAD = {"username": "admin", "password": "falsch"}


def audit_rows() -> list[tuple]:
    """(username, action, target) of every audit row in the database the app uses now (login_api's), oldest first."""
    with closing(sqlite3.connect(db.settings.db_path)) as conn:
        return conn.execute("SELECT username, action, target FROM audit ORDER BY id").fetchall()
