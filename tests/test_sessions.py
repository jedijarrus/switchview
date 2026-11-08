"""Sessions and cookies (Phase 2, Task 3): the database keeps only the SHA-256 of a session token, so a token read from a copy of the
database is no cookie (F4); sessions of the release before are rehashed at start, nobody is logged out, and a second start changes
nothing; "log out everywhere" ends every session of the signed-in user and no other; the Secure flag of both login cookies follows
COOKIE_SECURE (auto: the request's own scheme or X-Forwarded-Proto, either of which can only add the flag; always), and the start
refuses a COOKIE_SECURE other than auto/always and warns about a weak SECRET_KEY.

The app runs in-process through FastAPI's TestClient (the login_api fixture in conftest.py: a fresh database under tmp_path, the
emergency account of loginfix.GOOD, no dependency_overrides, the scheduler booby-trapped). A legacy database is written with sqlite3
from db.SCHEMA, as the migration tests in tests/test_db_migrate.py do.
"""
import asyncio
import dataclasses
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

import aiosqlite
import pytest
from fastapi.testclient import TestClient

import auth
import config
import db
import main
from loginfix import CSRF, GOOD, audit_rows

RAW = "Rohtoken-von-vorher-0123456789abcdefghijklm"          # 43 characters like secrets.token_urlsafe(32)


def query(sql: str) -> list[tuple]:
    """The rows of sql, as tuples, in the database the app uses now (db.settings)."""
    with closing(sqlite3.connect(db.settings.db_path)) as conn:
        return conn.execute(sql).fetchall()


def add_session(path, token: str, expires: datetime, username: str = "admin") -> None:
    """One sessions row as create_session writes it (method "local", ISO-UTC times), with the token column exactly as given."""
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("INSERT INTO sessions(token, username, display_name, method, created_at, expires_at) VALUES (?,?,?,?,?,?)",
                     (token, username, username, "local", datetime.now(timezone.utc).isoformat(), expires.isoformat()))
        conn.commit()


def legacy_db(path, token: str, expires: datetime) -> None:
    """A database as the release before the hashing left it: db.SCHEMA and one session of "admin" whose raw token is stored."""
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(db.SCHEMA)
    add_session(path, token, expires)


def test_a_token_from_a_db_copy_is_no_cookie(login_api):                     # F4, the audit's input
    raw = login_api.post("/api/auth/local", json=GOOD).cookies[auth.COOKIE]
    (stored,), = query("SELECT token FROM sessions")
    assert stored == auth.token_hash(raw) != raw
    assert TestClient(main.app, cookies={auth.COOKIE: stored}).get("/api/auth/me").status_code == 401
    assert login_api.get("/api/auth/me").status_code == 200


def test_existing_sessions_survive_the_upgrade(tmp_path, monkeypatch):        # Review Focus 2
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    legacy_db(tmp_path / "switchview.db", RAW, expires=datetime.now(timezone.utc) + timedelta(days=1))
    asyncio.run(db.init_db())
    asyncio.run(db.init_db())                                                  # the second run changes nothing
    assert query("SELECT token FROM sessions") == [(auth.token_hash(RAW),)]
    assert TestClient(main.app, cookies={auth.COOKIE: RAW}).get("/api/auth/me").status_code == 200


def test_logout_all_ends_every_session_of_the_user_only(login_api):
    login_api.post("/api/auth/local", json=GOOD)
    second = TestClient(main.app, headers=CSRF)
    second.post("/api/auth/local", json=GOOD)
    other = TestClient(main.app, cookies={auth.COOKIE: asyncio.run(auth.create_session("other", "Other", "entra"))})
    assert login_api.post("/api/auth/logout-all").json() == {"ok": True, "ended": 2}
    assert second.get("/api/auth/me").status_code == 401 and other.get("/api/auth/me").status_code == 200


def test_logout_all_needs_the_csrf_header(login_api):
    login_api.post("/api/auth/local", json=GOOD)
    bare = TestClient(main.app, cookies={auth.COOKIE: login_api.cookies[auth.COOKIE]})
    assert bare.post("/api/auth/logout-all").status_code == 403


@pytest.mark.parametrize("base, xfp, mode, secure", [
    ("http://testserver", None, "auto", False), ("https://testserver", None, "auto", True),
    ("http://testserver", "https", "auto", True),
    ("https://testserver", "http", "auto", True),                              # NV, the input: a forged "http" does not take Secure away
    ("http://testserver", None, "always", True)])
def test_cookie_secure(login_api, monkeypatch, base, xfp, mode, secure):
    s = dataclasses.replace(auth.settings, cookie_secure=mode)
    monkeypatch.setattr(auth, "settings", s)
    monkeypatch.setattr(main, "settings", s)
    c = TestClient(main.app, base_url=base, headers=CSRF | ({"X-Forwarded-Proto": xfp} if xfp else {}))
    cookies = c.post("/api/auth/local", json=GOOD).headers.get_list("set-cookie")             # session and device cookie
    assert len(cookies) == 2 and all(("; secure" in h.lower()) == secure for h in cookies)


def test_startup_config():
    with pytest.raises(RuntimeError, match="COOKIE_SECURE"):
        main.check_startup_config(config.Settings(secret_key=secrets.token_hex(32), cookie_secure="ja"))
    assert main.check_startup_config(config.Settings(secret_key="a" * 16)) and not main.check_startup_config(config.Settings(secret_key=secrets.token_hex(32)))


# Beyond the plan's list: the rest of what Task 3 states, each pinned where no test above would notice a break.

def test_logout_ends_this_session_on_the_server(login_api):                    # logout deletes by the hash
    raw = login_api.post("/api/auth/local", json=GOOD).cookies[auth.COOKIE]
    second = TestClient(main.app, headers=CSRF)
    second.post("/api/auth/local", json=GOOD)
    assert login_api.post("/api/auth/logout").json() == {"ok": True}
    assert TestClient(main.app, cookies={auth.COOKIE: raw}).get("/api/auth/me").status_code == 401   # the old cookie, replayed
    assert second.get("/api/auth/me").status_code == 200


def test_logout_all_clears_the_session_cookie_and_is_audited(login_api):
    login_api.post("/api/auth/local", json=GOOD)
    r = login_api.post("/api/auth/logout-all")
    (cleared,) = [h for h in r.headers.get_list("set-cookie") if h.startswith(f"{auth.COOKIE}=")]
    assert "max-age=0" in cleared.lower()
    assert audit_rows()[-1] == ("admin", "logout_all", "")


def test_logout_all_counts_only_sessions_still_valid(login_api):
    login_api.post("/api/auth/local", json=GOOD)
    add_session(db.settings.db_path, auth.token_hash("abgelaufen"), expires=datetime.now(timezone.utc) - timedelta(hours=1))
    assert login_api.post("/api/auth/logout-all").json()["ended"] == 1
    assert query("SELECT count(*) FROM sessions") == [(0,)]


def test_idle_sessions_go_with_the_hourly_prune_and_are_not_counted(login_api, monkeypatch):    # 4a, Später 4c
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, idle_minutes=30))
    login_api.post("/api/auth/local", json=GOOD)
    add_session(db.settings.db_path, auth.token_hash("ruht"), expires=datetime.now(timezone.utc) + timedelta(hours=1))
    with closing(sqlite3.connect(db.settings.db_path)) as conn:
        conn.execute("UPDATE sessions SET last_seen = ? WHERE token = ?",
                     ((datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat(), auth.token_hash("ruht")))
        conn.commit()
    assert login_api.post("/api/auth/logout-all").json()["ended"] == 1          # this session; the idle one is gone, not counted


async def test_without_an_idle_limit_the_prune_keeps_a_quiet_session(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    await db.init_db()
    add_session(db.settings.db_path, auth.token_hash("ruht"), expires=datetime.now(timezone.utc) + timedelta(hours=1))
    with closing(sqlite3.connect(db.settings.db_path)) as conn:                 # quiet for decades: only the idle rule could end it
        conn.execute("UPDATE sessions SET last_seen = '2000-01-01T00:00:00+00:00'")
        conn.commit()
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, idle_minutes=0))
    assert await auth.prune_sessions() == 0                                    # IDLE_MINUTES=0: no idle logout, the session stays
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, idle_minutes=30))
    assert await auth.prune_sessions() == 1


async def test_rehashing_counts_the_legacy_tokens_and_keeps_hashed_ones(tmp_path):
    path = tmp_path / "switchview.db"
    hashed = "0123456789abcdef" * 4                                            # a session stored by the new code
    legacy_db(path, RAW, expires=datetime.now(timezone.utc) + timedelta(days=1))
    add_session(path, hashed, expires=datetime.now(timezone.utc) + timedelta(days=1))
    async with aiosqlite.connect(path) as conn:
        assert await db.hash_legacy_session_tokens(conn) == 1
        assert await db.hash_legacy_session_tokens(conn) == 0
        await conn.commit()
    with closing(sqlite3.connect(path)) as conn:
        assert sorted(conn.execute("SELECT token FROM sessions").fetchall()) == [
            (hashed,), ("514398352d4e97da62b414cffbabd04bc16254bede189147cb3126a7fca9d848",)]   # sha256sum of RAW
    assert auth.token_hash(RAW) == "514398352d4e97da62b414cffbabd04bc16254bede189147cb3126a7fca9d848"           # the cookie side agrees


@pytest.mark.parametrize("xfp, secure", [(" HTTPS ", True), ("https, http", True), ("http, https", False)])
def test_the_first_forwarded_proto_counts(login_api, xfp, secure):           # a proxy chain lists the client's protocol first
    c = TestClient(main.app, headers=CSRF | {"X-Forwarded-Proto": xfp})
    cookies = c.post("/api/auth/local", json=GOOD).headers.get_list("set-cookie")
    assert len(cookies) == 2 and all(("; secure" in h.lower()) == secure for h in cookies)


@pytest.mark.parametrize("raw, value", [(" Always ", "always"), ("AUTO", "auto"), ("", "auto"), (None, "auto")])
def test_cookie_secure_is_read_trimmed_and_in_lower_case(monkeypatch, raw, value):
    if raw is None:
        monkeypatch.delenv("COOKIE_SECURE", raising=False)
    else:
        monkeypatch.setenv("COOKIE_SECURE", raw)
    assert config.Settings().cookie_secure == value


def test_a_secret_key_under_16_characters_stops_the_start():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        main.check_startup_config(config.Settings(secret_key="0123456789abcde"))


@pytest.mark.parametrize("key, warns", [
    ("0123456789abcdef" * 2, False),                                           # 32 characters, 16 different ones
    ("0123456789abcdef0123456789abcde", True),                                 # 31 characters
    ("abcdefgh" * 4, False),                                                   # 8 different characters
    ("abcdefg" * 5, True)])                                                    # 35 characters, 7 different ones
def test_a_weak_secret_key_only_warns_and_the_warning_never_shows_it(key, warns):    # E16
    messages = main.check_startup_config(config.Settings(secret_key=key))
    assert bool(messages) == warns and not any(key in m for m in messages)


class Stop(Exception):
    """Raised by the stand-in for the start's first step after the startup check."""


def fail_with_stop(*args, **kwargs):
    raise Stop


def test_the_start_runs_the_startup_check_first_and_logs_its_warnings(monkeypatch, caplog):
    monkeypatch.setattr(main, "init_db", fail_with_stop)
    monkeypatch.setattr(main, "settings", config.Settings(secret_key=secrets.token_hex(32), cookie_secure="ja"))
    with pytest.raises(RuntimeError, match="COOKIE_SECURE"), TestClient(main.app):
        pass
    monkeypatch.setattr(main, "settings", config.Settings(secret_key="a" * 16))
    with pytest.raises(Stop), TestClient(main.app):
        pass
    assert [r.levelname for r in caplog.records if "SECRET_KEY" in r.getMessage()] == ["WARNING"]
