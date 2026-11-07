"""Constants and helpers shared by the login and session tests (tests/test_login_security.py, tests/test_nonce.py and the session tests),
next to the login_api fixture in conftest.py, which sets up the emergency account GOOD names, and its entra fixture (sso_login).

A plain module like switchfix.py: the tests import it by name (`from loginfix import ...`). It imports the app's db module (for the
path of the database the app writes to), so conftest.py imports it only inside its fixture, after the test environment is set.
"""
import sqlite3
from contextlib import closing

import db

CSRF = {"X-Requested-With": "SwitchView"}                              # the header the app wants on every non-GET request
GOOD = {"username": "admin", "password": "Notfall-Kennwort-ß1"}        # the emergency account of login_api; "ß" on purpose
BAD = {"username": "admin", "password": "falsch"}


def sso_login(client, sign, **claims):
    """An SSO login as the browser makes it (sv-core.js, #btn-sso): POST /api/auth/nonce for this login attempt (its binding cookie
    goes into client's cookie jar), then POST /api/auth/azure with sign(nonce=<that nonce>, **claims), an id_token of the entra
    fixture of conftest.py. Returns the answer of /api/auth/azure."""
    nonce = client.post("/api/auth/nonce").json()["nonce"]
    return client.post("/api/auth/azure", json={"id_token": sign(nonce=nonce, **claims)})


def audit_rows() -> list[tuple]:
    """(username, action, target) of every audit row in the database the app uses now (login_api's), oldest first."""
    with closing(sqlite3.connect(db.settings.db_path)) as conn:
        return conn.execute("SELECT username, action, target FROM audit ORDER BY id").fetchall()
