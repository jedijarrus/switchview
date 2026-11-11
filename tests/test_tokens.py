"""Phase 4c, Task 2: API tokens per user. A person signed in over SSO creates their own (POST /api/tokens: a name, 1-365 days, by
default 90, and on request a lower maximum role), lists and revokes them; an Admin lists every token (GET /api/settings/tokens) and
revokes any. A token ("svt_" + 256 random bits) is shown once and stored as db.token_hash. A request with "Authorization: Bearer
svt_..." is the same user as a session (auth.current_user): its role is worked out per request from the app roles of the session it
was created in, against the mapping of now, capped by its maximum role; its zones likewise. It never reads the cookie and needs no
CSRF header; any other scheme and a bearer value without "svt_" (a proxy in front) take the cookie path as it is. Invalid tokens are
throttled after the lookup (a valid one never), every audit entry made through a token names it (audit.token), the emergency login
gets none, and neither managing tokens nor approving works with one.

The app runs in-process through FastAPI's TestClient without any override (login_api, entra and mapping of tests/conftest.py, the
helpers of tests/tokenfix.py): every request goes through the real session and token code. No network.
"""
import asyncio
import contextlib
import dataclasses
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from tokenfix import bare, bearer, mint, signed

import api_changes
import api_tokens
import apifix
import auth
import changes
import db
import dbfix
import main
import roles
from loginfix import CSRF, GOOD

TIME = "%Y-%m-%d %H:%M:%S"


def test_a_token_is_shown_once_and_stored_hashed(mapping, entra):
    t = mint(signed(mapping, entra))
    assert t["token"].startswith(auth.TOKEN_PREFIX) and len(t["token"]) == len(auth.TOKEN_PREFIX) + 43 and t["max_role"] is None
    assert dbfix.query("SELECT token_hash, name, username, subject, method FROM api_tokens") == [
        (db.token_hash(t["token"]), "ci", "anna@example.org", "entra:oid-anna", "entra")]
    listed = mapping.get("/api/tokens").json()
    assert [x["name"] for x in listed] == ["ci"] and t["token"] not in json.dumps(listed) and "token_hash" not in listed[0]
    assert not [r for r in dbfix.query("SELECT * FROM audit") if t["token"] in str(r)]
    assert dbfix.query("SELECT username, target, role FROM audit WHERE action = 'token_create'") == [
        ("anna@example.org", f"#{t['id']}", "aendern")]
    expires = datetime.strptime(t["expires_at"], TIME).replace(tzinfo=timezone.utc)
    assert abs(expires - datetime.now(timezone.utc) - timedelta(days=90)) < timedelta(minutes=1)


def test_a_token_signs_a_script_in_as_its_user(mapping, entra):
    t = mint(signed(mapping, entra))
    me = bare().get("/api/auth/me", headers=bearer(t["token"])).json()
    assert (me["username"], me["role"], me["method"], me["zones"], me["api_token"]) == ("anna@example.org", "aendern", "entra", None, "ci")


def test_a_bearer_write_needs_no_csrf_header_and_its_audit_names_the_token(mapping, entra):
    t = mint(signed(mapping, entra))
    assert bare().post("/api/watch", json={"mac": "aa:bb:cc:dd:ee:ff", "note": ""}, headers=bearer(t["token"])).status_code == 200
    assert mapping.post("/api/watch", json={"mac": "aa:bb:cc:dd:ee:01", "note": ""}).status_code == 200    # the cookie: no token named
    assert dbfix.query("SELECT username, role, token FROM audit WHERE action = 'watch_add' ORDER BY id") == [
        ("anna@example.org", "aendern", f"ci (#{t['id']})"), ("anna@example.org", "aendern", None)]


def test_a_bearer_request_never_falls_back_to_the_cookie(mapping, entra):              # Review Focus 3
    signed(mapping, entra)
    for value in ("Bearer svt_falsch", "bearer svt_falsch", "Bearer   svt_"):
        r = mapping.get("/api/auth/me", headers={"Authorization": value})
        assert (r.status_code, r.json()["detail"]) == (401, auth.TOKEN_BAD), value
    assert mapping.get("/api/auth/me").status_code == 200


@pytest.mark.parametrize("value", ["Basic eDp5", "Bearer eyJhbGciOiJSUzI1NiJ9.e30.c2ln", "Bearer ", "Bearer"])
def test_another_scheme_leaves_the_cookie_path_as_it_is(mapping, entra, value):        # Review Focus 3: a proxy's own bearer too
    signed(mapping, entra)
    assert mapping.get("/api/auth/me", headers={"Authorization": value}).json()["username"] == "anna@example.org"
    r = TestClient(main.app, cookies=mapping.cookies).post("/api/auth/logout-all", headers={"Authorization": value})
    assert (r.status_code, r.json()["detail"]) == (403, "Ungültige Anfrage") and len(auth._TOKENS) == 0


@pytest.mark.parametrize("how", ["expired", "revoked"])
def test_an_expired_or_revoked_token_is_refused(mapping, entra, how):
    t = mint(signed(mapping, entra))
    if how == "expired":
        dbfix.query("UPDATE api_tokens SET expires_at = '2000-01-01 00:00:00'")
        assert mapping.get("/api/tokens").json()[0]["expired"] is True
    else:
        assert mapping.delete(f"/api/tokens/{t['id']}").status_code == 200
    r = bare().get("/api/switches", headers=bearer(t["token"]))
    assert (r.status_code, r.json()["detail"]) == (401, auth.TOKEN_BAD)


def test_a_token_that_runs_out_later_today_still_works_and_stays(mapping, entra):     # the format of expires_at, never isoformat()
    t = mint(signed(mapping, entra))
    later = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime(TIME)
    dbfix.query("UPDATE api_tokens SET expires_at = ?", (later,))
    assert bare().get("/api/switches", headers=bearer(t["token"])).status_code == 200 and mapping.get("/api/tokens").json()[0]["expired"] is False
    asyncio.run(auth.prune_sessions())
    assert dbfix.query("SELECT count(*) FROM api_tokens") == [(1,)]


def test_a_capped_token_cannot_write(mapping, entra):                                    # Review Focus 3
    t = mint(signed(mapping, entra), max_role="lesen")
    assert bare().get("/api/switches", headers=bearer(t["token"])).status_code == 200
    r = bare().post("/api/watch", json={"mac": "aa:bb:cc:dd:ee:ff", "note": ""}, headers=bearer(t["token"]))
    assert (r.status_code, r.json()["detail"]) == (403, roles.denial(roles.AENDERN, roles.LESEN))


def test_a_token_follows_the_mapping_of_now(mapping, entra, monkeypatch):               # Review Focus 3
    t = mint(signed(mapping, entra))
    values = {**auth.settings.entra_role_values, "aendern": ["SwitchView.Anders"]}
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, entra_role_values=values))
    assert bare().get("/api/auth/me", headers=bearer(t["token"])).json()["role"] == "lesen"


def test_a_token_carries_the_zones_of_its_user(mapping, entra):
    dbfix.query("INSERT INTO zone_scopes(principal, zone) VALUES ('SwitchView.Zone.EK', 'EK')")
    t = mint(signed(mapping, entra, app_roles=("SwitchView.Aendern", "SwitchView.Zone.EK")))
    assert bare().get("/api/auth/me", headers=bearer(t["token"])).json()["zones"] == ["EK"]


def test_the_emergency_login_gets_no_token(login_api):
    login_api.post("/api/auth/local", json=GOOD)
    r = login_api.post("/api/tokens", json={"name": "ci"})
    assert (r.status_code, r.json()["detail"]) == (403, api_tokens.EMERGENCY) and dbfix.query("SELECT count(*) FROM api_tokens") == [(0,)]


@pytest.mark.parametrize("method, path", [("POST", "/api/tokens"), ("GET", "/api/tokens"), ("DELETE", "/api/tokens/1"),
                                          ("GET", "/api/settings/tokens")])
def test_tokens_are_managed_signed_in_only(mapping, entra, method, path):
    t = mint(signed(mapping, entra, app_roles=("SwitchView.Admin",)))
    r = bare().request(method, path, json={"name": "x"} if method == "POST" else None, headers=bearer(t["token"]))
    assert (r.status_code, r.json()["detail"]) == (403, api_tokens.VIA_TOKEN) and dbfix.query("SELECT count(*) FROM api_tokens") == [(1,)]


def test_the_limits_of_a_token(mapping, entra):
    c = signed(mapping, entra)
    assert c.post("/api/tokens", json={"name": "a", "max_role": "admin"}).json()["detail"] == api_tokens.ABOVE_ROLE.format(role="Ändern")
    assert [c.post("/api/tokens", json={"name": "a", "days": d}).status_code for d in (0, 366)] == [422, 422]
    assert c.post("/api/tokens", json={"name": "  "}).json()["detail"] == api_tokens.NO_NAME
    mint(c, name="a")
    assert c.post("/api/tokens", json={"name": "a"}).json()["detail"] == api_tokens.NAME_TAKEN
    for i in range(19):
        mint(c, name=f"t{i}")
    r = c.post("/api/tokens", json={"name": "zu viel"})
    assert (r.status_code, r.json()["detail"]) == (409, api_tokens.TOO_MANY) and dbfix.query("SELECT count(*) FROM api_tokens") == [(20,)]


def test_only_the_owner_or_an_admin_revokes(mapping, entra):
    t = mint(signed(mapping, entra))
    ben = signed(TestClient(main.app, headers=CSRF), entra, "ben")
    r = ben.delete(f"/api/tokens/{t['id']}")
    assert (r.status_code, r.json()["detail"]) == (404, api_tokens.NOT_FOUND) and ben.get("/api/tokens").json() == []
    cleo = signed(TestClient(main.app, headers=CSRF), entra, "cleo", ("SwitchView.Admin",))
    assert [x["username"] for x in cleo.get("/api/settings/tokens").json()] == ["anna@example.org"]
    assert cleo.delete(f"/api/tokens/{t['id']}").status_code == 200 and dbfix.query("SELECT count(*) FROM api_tokens") == [(0,)]
    assert dbfix.query("SELECT username, target, detail FROM audit WHERE action = 'token_revoke'") == [
        ("cleo@example.org", f"#{t['id']}", "„ci“ von anna@example.org")]


def test_invalid_tokens_are_throttled_but_a_valid_one_never(mapping, entra):
    t = mint(signed(mapping, entra))
    assert [bare().get("/api/switches", headers=bearer("svt_raten")).status_code for _ in range(10)] == [401] * 10
    r = bare().get("/api/switches", headers=bearer("svt_raten"))
    assert (r.status_code, r.json()["detail"]) == (429, auth.TOKEN_THROTTLED)
    assert bare().get("/api/switches", headers=bearer(t["token"])).status_code == 200


def test_a_token_counts_as_used_at_most_once_a_minute(mapping, entra):
    t = mint(signed(mapping, entra))
    assert dbfix.query("SELECT last_used_at FROM api_tokens") == [(None,)]
    bare().get("/api/switches", headers=bearer(t["token"]))
    [(first,)] = dbfix.query("SELECT last_used_at FROM api_tokens")
    bare().get("/api/switches", headers=bearer(t["token"]))
    assert first and dbfix.query("SELECT last_used_at FROM api_tokens") == [(first,)]


def test_the_hourly_prune_deletes_expired_tokens(mapping, entra):
    mint(signed(mapping, entra))
    dbfix.query("UPDATE api_tokens SET expires_at = '2000-01-01 00:00:00'")
    asyncio.run(auth.prune_sessions())
    assert dbfix.query("SELECT count(*) FROM api_tokens") == [(0,)]


# ── Beyond the plan's tests: what the interface names and no test above holds ─────────────────────────────────────────────────────
@pytest.mark.parametrize("value, want", [("Bearer svt_a", "svt_a"), ("  BEARER\tsvt_a  ", "svt_a"), ("Bearer   svt_", "svt_"),
                                         ("Bearer svt", None), ("Bearersvt_a", None), ("Basic svt_a", None), ("Bearer", None), ("", None)])
def test_bearer_of_takes_only_a_bearer_value_with_the_prefix(value, want):
    assert auth.bearer_of(Request({"type": "http", "headers": [(b"authorization", value.encode())]})) == want
    assert auth.bearer_of(Request({"type": "http", "headers": []})) is None


@pytest.mark.parametrize("role, maximum, want", [("admin", None, "admin"), ("admin", "lesen", "lesen"), ("freigeben", "aendern", "aendern"),
                                                 ("aendern", "aendern", "aendern"), ("lesen", "admin", "lesen")])
def test_cap_lowers_a_role_to_its_maximum_and_never_raises_it(role, maximum, want):
    assert roles.cap(role, maximum) == want


def test_a_valid_token_next_to_another_persons_cookie_is_its_own_user(mapping, entra):  # Review Focus 3: never the cookie's user
    t = mint(signed(mapping, entra))
    cleo = signed(TestClient(main.app, headers=CSRF), entra, "cleo", ("SwitchView.Admin",))
    me = cleo.get("/api/auth/me", headers=bearer(t["token"])).json()
    assert (me["username"], me["role"], me["api_token"]) == ("anna@example.org", "aendern", "ci")


def test_the_audit_names_the_token_only_in_entries_of_its_user(login_api):
    async def entries():                            # in a task of its own: the context set here ends with it
        db.AUDIT_TOKEN.set(("Anna@Example.org", "ci (#7)"))
        await db.audit("anna@example.org", "watch_add", role="aendern")
        await db.audit("ben@example.org", "watch_add", role="aendern")
        await db.audit(None, "approval_expired", role=None)

    asyncio.run(entries())
    assert dbfix.query("SELECT username, token FROM audit ORDER BY id") == [("anna@example.org", "ci (#7)"), ("ben@example.org", None),
                                                                           (None, None)]
    assert db.AUDIT_TOKEN.get() is None


def test_creating_a_token_audits_its_name_expiry_and_maximum_role(mapping, entra):
    c = signed(mapping, entra)
    a, b = mint(c, name="a"), mint(c, name="b", days=30, max_role="lesen")
    assert (a["max_role"], b["max_role"]) == (None, "lesen")
    assert dbfix.query("SELECT detail FROM audit WHERE action = 'token_create' ORDER BY id") == [
        (f"„a“ bis {a['expires_at']} UTC, Höchstrolle wie der Benutzer",), (f"„b“ bis {b['expires_at']} UTC, Höchstrolle Lesen",)]


def test_the_list_names_each_token_newest_first(mapping, entra):
    c = signed(mapping, entra)
    mint(c, name="alt")
    neu = mint(c, name="neu", max_role="lesen")
    listed = c.get("/api/tokens").json()
    assert [x["name"] for x in listed] == ["neu", "alt"]
    assert set(listed[0]) == {"id", "name", "username", "display_name", "max_role", "created_at", "expires_at", "last_used_at", "expired"}
    assert (listed[0]["id"], listed[0]["max_role"], listed[0]["expires_at"], listed[0]["last_used_at"], listed[0]["expired"]) == (
        neu["id"], "lesen", neu["expires_at"], None, False)


def test_an_invalid_token_is_logged_without_itself_and_not_while_throttled(mapping, entra, caplog):
    t = mint(signed(mapping, entra))
    dbfix.query("UPDATE api_tokens SET expires_at = '2000-01-01 00:00:00'")
    with caplog.at_level(logging.WARNING, logger="switchview.auth"):
        assert bare().get("/api/switches", headers=bearer(t["token"])).status_code == 401
        assert [bare().get("/api/switches", headers=bearer("svt_raten")).status_code for _ in range(10)] == [401] * 9 + [429]
    assert [r.getMessage() for r in caplog.records if r.name == "switchview.auth"] == (
        ["API-Token abgelehnt (abgelaufen) von testclient"] + ["API-Token abgelehnt (unbekannt) von testclient"] * 9)
    assert t["token"] not in caplog.text and "svt_raten" not in caplog.text


async def test_two_tokens_at_once_cannot_pass_the_limit(login_api, monkeypatch):
    """Pin of BEGIN IMMEDIATE in auth.create_token: each INSERT waits 0.2 s after its count, so without the write transaction both
    would count 19 tokens and both insert. With it the second count waits for the first commit and sees 20."""
    for i in range(19):
        dbfix.query("INSERT INTO api_tokens(token_hash, name, username, method, subject, created_at, expires_at) "
                    "VALUES (?, ?, 'tester', 'entra', 'entra:tester', '2026-11-08 10:00:00', '2099-01-01 00:00:00')", (f"h{i}", f"t{i}"))
    real = auth.db

    @contextlib.asynccontextmanager
    async def slow_insert():
        async with real() as conn:
            execute = conn.execute

            async def later(sql, args):
                await asyncio.sleep(0.2)
                return await execute(sql, args)

            conn.execute = lambda sql, args=(): later(sql, args) if sql.startswith("INSERT INTO api_tokens") else execute(sql, args)
            yield conn

    monkeypatch.setattr(auth, "db", slow_insert)
    both = await asyncio.gather(*(auth.create_token(apifix.user("aendern"), [], name, 90, None) for name in ("x", "y")), return_exceptions=True)
    assert sorted(type(r).__name__ for r in both) == ["TokenLimit", "dict"] and dbfix.query("SELECT count(*) FROM api_tokens") == [(20,)]


async def test_the_audit_of_a_change_started_with_a_token_names_it(mapping, entra, monkeypatch):
    """Final review of Phase 4c, finding 10 (T2-g): the change_* entries of a change are written by its run, a task of its own
    (api_changes.spawn), not by the request of /apply; they name the token because that task starts with a copy of the request's
    context. A run moved to a context of its own (the scheduler's, say) would drop the token from the audit. The request goes through
    httpx on the app's own loop, so the task runs to its end (a TestClient ends its loop with the request)."""
    t = mint(signed(mapping, entra))
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1", zone="")

    async def plan(row, body):
        shown = ["vlan 30 untagged 5"]
        return ({"shown": shown, "commands": shown, "blocked": [], "mechanism": "ssh", "warnings": [], "desired": {"5": {"u": "30"}},
                 "before": {"5": {"u": "20"}}, "expert": False}, {"ports": body.ports, "set": body.change.model_dump(), "expert": False},
                "ports", api_changes._summary(body))

    async def run(cid):                             # what run_change writes at its end, as the change's user
        await asyncio.sleep(0)
        await db.audit("anna@example.org", "change_ok", "SW", f"#{cid}", role="aendern")

    monkeypatch.setattr(api_changes, "_make_plan", plan)
    monkeypatch.setattr(changes, "run_change", run)
    want, before = {"ports": ["5"], "change": {"untagged": "30"}}, set(api_changes._tasks)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test", headers=bearer(t["token"])) as c:
        p = (await c.post(f"/api/switches/{sid}/plan", json=want)).json()
        r = await c.post(f"/api/switches/{sid}/apply", json={**want, "token": p["token"], "mechanism": p["mechanism"]})
        assert r.status_code == 200, r.json()
        for _ in range(500):                        # the run's task to its end, at most 5 s
            if not api_changes._tasks - before:
                break
            await asyncio.sleep(0.01)
    assert dbfix.query("SELECT username, detail, token FROM audit WHERE action = 'change_ok'") == [
        ("anna@example.org", f"#{r.json()['id']}", f"ci (#{t['id']})")]
