"""Shared helpers of the API tests: the test user (USER, and user() for one of any role), the scheduler trap, a fresh database, a
TestClient signed in through the user override (become() and by_header() sign it in as someone else), and a fake httpx for the code
that talks to PacketFence and OPNsense (pf, names).

The fixtures stay in their test files, each with its name and parameters (they hang on different things: a world, a database, a
fake switch, tmp_path); only their common body lives here: the scheduler trap, the override, the CSRF header and the cleanup.

Like tests/dbfix.py this module imports app code, so tests/conftest.py imports it only inside a fixture; a test module imports it at
the top, after conftest.py has set the environment.
"""
import asyncio
import contextlib
import types
from typing import NoReturn

from fastapi import Request
from fastapi.testclient import TestClient

import auth
import config
import db
import loginfix
import main


def user(role: str, name: str = "tester", *, method: str = "entra", subject: str | None = None, zones: list[str] | None = None) -> dict:
    """A signed-in user as auth.current_user returns it: role one of roles.ORDER, subject <method>:<name> unless given, zones None
    (no zone scope) unless given."""
    return {"username": name, "name": name.title(), "method": method, "role": role, "subject": subject or f"{method}:{name}", "zones": zones}


USER: dict = user("admin", method="local")      # the test user of every API fixture: the emergency login, Admin


def never(*args, **kwargs) -> NoReturn:
    """main.scheduler.start in a test: the scheduler must not start (it would poll the switches and reach the network)."""
    raise AssertionError("the scheduler must not start in a test (no background polling, no network)")


def fresh_db(tmp_path, monkeypatch) -> None:
    """A fresh database under tmp_path for the app's db module, set up by the app's own init_db (schema plus migration)."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    asyncio.run(db.init_db())


@contextlib.contextmanager
def signed_in(monkeypatch, user: dict | None = None):
    """A TestClient on main.app, signed in as user (USER unless given) through the override of auth.current_user and sending the
    CSRF header. It is created without `with`, so the app's lifespan never runs, and the scheduler is booby-trapped on top. The
    override goes again when the block ends."""
    monkeypatch.setattr(main.scheduler, "start", never)
    main.app.dependency_overrides[auth.current_user] = lambda: user or USER
    try:
        yield TestClient(main.app, headers=loginfix.CSRF)
    finally:
        main.app.dependency_overrides.pop(auth.current_user, None)


def become(user: dict) -> None:
    """Inside a signed_in block: every request from now on is signed in as user (the end of the block removes the override)."""
    main.app.dependency_overrides[auth.current_user] = lambda: user


def by_header(users: dict[str, dict]) -> None:
    """Inside a signed_in block: every request from now on is signed in as users[<its X-Test-User header>]. users is looked up on
    each request, so an entry added later counts at once. The parameter is annotated: FastAPI would take an unannotated `request`
    for a query parameter."""
    def current(request: Request) -> dict:
        return users[request.headers["X-Test-User"]]

    main.app.dependency_overrides[auth.current_user] = current


class Remote:
    """A fake system behind fake_httpx: the status per (method, URL as the code passes it), 200 unless set; and what it saw: calls
    (method, URL), urls (the client's base_url + URL) and made (the keyword arguments of every client the code created). It answers
    every request with reply, {} here; a subclass answers as its system does."""

    def __init__(self):
        self.status: dict[tuple[str, str], int] = {}
        self.calls: list[tuple[str, str]] = []
        self.urls: list[str] = []
        self.made: list[dict] = []

    def reply(self, method: str, url: str):
        return {}


class _Response:
    """What pf and names read of an httpx response; json() asks the remote for its answer."""

    def __init__(self, remote: Remote, method: str, url: str):
        self._remote, self._method, self._url = remote, method, url
        self.status_code = remote.status.get((method, url), 200)
        self.text = f"answer {self.status_code}"

    def json(self):
        return self._remote.reply(self._method, self._url)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _Client:
    """httpx.AsyncClient as pf and names use it: `async with`, headers, get / post / patch / delete, each recorded on the remote."""

    def __init__(self, remote: Remote, base_url: str = "", **kwargs):
        self._remote, self._base_url, self.headers = remote, base_url, {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kwargs):
        return self._send("GET", url)

    async def post(self, url, **kwargs):
        return self._send("POST", url)

    async def patch(self, url, **kwargs):
        return self._send("PATCH", url)

    async def delete(self, url, **kwargs):
        return self._send("DELETE", url)

    def _send(self, method: str, url: str) -> _Response:
        self._remote.calls.append((method, url))
        self._remote.urls.append(self._base_url + url)
        return _Response(self._remote, method, url)


def fake_httpx(remote: Remote) -> types.SimpleNamespace:
    """A stand-in for the httpx module of pf or names (monkeypatch.setattr(pf, "httpx", fake_httpx(remote))): every AsyncClient the
    code creates records its keyword arguments in remote.made and sends to remote; nothing leaves the process."""

    def client(**kwargs) -> _Client:
        remote.made.append(kwargs)
        return _Client(remote, **kwargs)

    return types.SimpleNamespace(AsyncClient=client)
