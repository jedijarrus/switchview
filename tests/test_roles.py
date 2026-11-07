"""Roles (Phase 4a, Task 3): four roles (Lesen ⊂ Ändern ⊂ Freigeben ⊂ Admin) from the Entra app roles in the roles claim of the
id_token, mapped by ENTRA_ROLE_MAPPING and ENTRA_ROLE_LESEN/_AENDERN/_FREIGEBEN/_ADMIN. The session stores the roles claim and a
stable subject (entra:<oid>, without an oid entra:<sub>, or local:<user name>) at the login; current_user works out the role on every
request from the stored claim against the mapping of now. Without the mapping every SSO user is Admin as before, the emergency login
is Admin always, and the start warns. A session ends after IDLE_MINUTES without a request (0 = never); its last_seen is written at
most once a minute. Sessions from before the update (no claims, no subject, no last_seen) stay signed in.

The app runs in-process through FastAPI's TestClient (the login_api fixture in conftest.py: a fresh database under tmp_path, the
emergency account of loginfix.GOOD, SSO for tenant "t", no dependency_overrides, the scheduler booby-trapped); SSO logins go through
the entra fixture and loginfix.sso_login, as in tests/test_nonce.py.
"""
import asyncio
import dataclasses
import json
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

import auth
import config
import db
import loginfix
import main
import roles
from loginfix import GOOD

ON = dict(entra_role_mapping="on")


def query(sql: str) -> list[tuple]:
    """The rows of sql, as tuples, in the database the app uses now (db.settings); a write is committed."""
    with closing(sqlite3.connect(db.settings.db_path)) as conn:
        rows = conn.execute(sql).fetchall()
        conn.commit()
        return rows


def session(client, roles_=(), method="entra", username="anna@example.org") -> None:
    """Signs client in with a session as an SSO login starts it: roles_ as the stored roles claim, the subject "entra:oid-anna"."""
    token = asyncio.run(auth.create_session(username, "Anna", method, roles=list(roles_), subject="entra:oid-anna"))
    client.cookies.set(auth.COOKIE, token)


def ago(**delta) -> str:
    return (datetime.now(timezone.utc) - timedelta(**delta)).isoformat()


@pytest.mark.parametrize("method, claim, mapping, want", [
    ("local", [], "on", "admin"), ("local", [], "off", "admin"), ("entra", [], "off", "admin"), ("entra", ["SwitchView.Lesen"], "off", "admin"),
    ("entra", [], "on", "lesen"), ("entra", None, "on", "lesen"), ("entra", ["Fremd"], "on", "lesen"), ("entra", ["SwitchView.Aendern"], "on", "aendern"),
    ("entra", ["SwitchView.Freigeben"], "on", "freigeben"), ("entra", ["SwitchView.Admin"], "on", "admin"),
    ("entra", ["SwitchView.Lesen", "SwitchView.Admin"], "on", "admin"), ("token", [], "off", "lesen")])
def test_role_of(method, claim, mapping, want):                                              # Review Focus 2
    assert roles.role_of(method, claim, config.Settings(entra_role_mapping=mapping)) == want


def test_a_value_in_two_lists_gives_the_higher_role():                                       # Review Focus 2
    s = config.Settings(entra_role_mapping="on")
    s = dataclasses.replace(s, entra_role_values={**s.entra_role_values, "aendern": ["Ops"], "admin": ["Ops"]})
    assert roles.role_of("entra", ["Ops"], s) == "admin"


def test_each_role_includes_the_one_before():
    assert [roles.at_least(r, m) for r in roles.ORDER for m in roles.ORDER] == [i >= j for i in range(4) for j in range(4)]
    assert not roles.at_least(None, "lesen") and not roles.at_least("chef", "lesen")


def test_the_denial_names_both_roles():
    assert roles.denial("admin", "lesen") == "Keine Berechtigung: Das braucht die Rolle „Admin“ (deine Rolle: „Lesen“)"


def test_the_role_follows_the_mapping_of_now(login_api, monkeypatch):                         # A3
    session(login_api, ["SwitchView.Aendern"])
    assert login_api.get("/api/auth/me").json()["role"] == "admin"
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, **ON))
    assert login_api.get("/api/auth/me").json()["role"] == "aendern"
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, entra_role_values={**auth.settings.entra_role_values, "aendern": ["NetOps"]}))
    assert login_api.get("/api/auth/me").json()["role"] == "lesen"


def test_the_entra_login_stores_the_roles_and_the_object_id(login_api, entra):
    assert loginfix.sso_login(login_api, entra, preferred_username="anna@example.org", roles=["SwitchView.Freigeben"], oid="oid-anna").status_code == 200
    [(claims, subject)] = query("SELECT claims, subject FROM sessions")
    assert json.loads(claims) == {"roles": ["SwitchView.Freigeben"]} and subject == "entra:oid-anna"


def test_without_an_object_id_the_subject_is_the_sub(login_api, entra):
    loginfix.sso_login(login_api, entra, preferred_username="bob@example.org")
    assert query("SELECT subject FROM sessions") == [("entra:s",)]


def test_the_entra_login_keeps_only_text_roles(login_api, entra):                             # Review Focus 2
    assert loginfix.sso_login(login_api, entra, roles=["SwitchView.Aendern", 7, None, "x" * 300]).status_code == 200
    assert json.loads(query("SELECT claims FROM sessions")[0][0]) == {"roles": ["SwitchView.Aendern"]}


@pytest.mark.parametrize("claim, want", [(["SwitchView.Aendern", 7, None, "x" * 300], ["SwitchView.Aendern"]), ("SwitchView.Admin", []),
                                         ({"SwitchView.Admin": 1}, []), (None, []), ([f"r{i}" for i in range(250)], [f"r{i}" for i in range(200)])],
                         ids=["mixed", "text", "dict", "none", "too-many"])
def test_claim_roles(claim, want):                                                            # Review Focus 2
    assert auth.claim_roles({"roles": claim}) == want and auth.claim_roles({}) == []


def test_the_emergency_login_is_admin_also_with_a_mapping(login_api, monkeypatch):
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, **ON))
    login_api.post("/api/auth/local", json=GOOD)
    me = login_api.get("/api/auth/me").json()
    assert (me["role"], me["zones"], "subject" in me) == ("admin", None, False) and query("SELECT subject FROM sessions") == [("local:admin",)]
    assert set(me) == {"username", "name", "method", "role", "zones", "idle_minutes", "four_eyes"} and me["idle_minutes"] == 120


def test_an_idle_session_ends(login_api):
    login_api.post("/api/auth/local", json=GOOD)
    query(f"UPDATE sessions SET last_seen = '{(datetime.now(timezone.utc) - timedelta(minutes=121)).isoformat()}'")
    r = login_api.get("/api/auth/me")
    assert (r.status_code, r.json()["detail"]) == (401, "Abgemeldet nach 120 Minuten ohne Aktivität – bitte neu anmelden") and query(
        "SELECT count(*) FROM sessions") == [(0,)]


@pytest.mark.parametrize("minutes, said", [(1, "1 Minute"), (2, "2 Minuten"), (120, "120 Minuten")])
def test_the_idle_reason_counts_one_minute_in_the_singular(minutes, said):
    assert auth.idle_reason(minutes) == f"Abgemeldet nach {said} ohne Aktivität – bitte neu anmelden"


def test_activity_keeps_a_session_and_is_written_at_most_once_a_minute(login_api):
    login_api.post("/api/auth/local", json=GOOD)
    for delta, written in ((dict(seconds=30), False), (dict(seconds=61), True), (dict(minutes=119), True)):
        before = ago(**delta)
        query(f"UPDATE sessions SET last_seen = '{before}'")
        assert login_api.get("/api/auth/me").status_code == 200 and (query("SELECT last_seen FROM sessions")[0][0] != before) == written


def test_a_write_refused_for_its_missing_header_is_no_activity(login_api):                 # beyond the plan: touch after the CSRF check
    login_api.post("/api/auth/local", json=GOOD)
    before = ago(minutes=5)
    query(f"UPDATE sessions SET last_seen = '{before}'")
    bare = TestClient(main.app, cookies={auth.COOKIE: login_api.cookies[auth.COOKIE]})       # a cross-site form post: no X-Requested-With
    assert bare.post("/api/auth/logout-all").status_code == 403 and query("SELECT last_seen FROM sessions") == [(before,)]


def test_idle_logout_can_be_off(login_api, monkeypatch):
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, idle_minutes=0))
    login_api.post("/api/auth/local", json=GOOD)
    query(f"UPDATE sessions SET last_seen = '{(datetime.now(timezone.utc) - timedelta(days=3)).isoformat()}'")
    assert login_api.get("/api/auth/me").status_code == 200


def test_a_session_from_before_the_update_stays_signed_in(login_api, monkeypatch):           # Review Focus 3
    token = "vorher-" + secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc)
    query("INSERT INTO sessions(token, username, display_name, method, created_at, expires_at) VALUES "
          f"('{db.token_hash(token)}', 'anna@example.org', 'Anna', 'entra', '{(now - timedelta(hours=5)).isoformat()}', "
          f"'{(now + timedelta(hours=1)).isoformat()}')")
    login_api.cookies.set(auth.COOKIE, token)
    assert login_api.get("/api/auth/me").json()["role"] == "admin" and query("SELECT last_seen IS NOT NULL FROM sessions") == [(1,)]
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, **ON))
    assert login_api.get("/api/auth/me").json()["role"] == "lesen"


def test_a_session_from_before_the_update_has_method_and_user_name_as_its_subject(login_api):
    """A session that stored no subject (from before the update) gets <method>:<username>: the identity the self-approval lock
    compares (approvals.same_person), so the same person signed in twice is the same subject."""
    token = "vorher-" + secrets.token_urlsafe(16)
    now = datetime.now(timezone.utc)
    query("INSERT INTO sessions(token, username, display_name, method, created_at, expires_at) VALUES "
          f"('{db.token_hash(token)}', 'anna@example.org', 'Anna', 'entra', '{now.isoformat()}', '{(now + timedelta(hours=1)).isoformat()}')")
    request = Request({"type": "http", "method": "GET", "path": "/api/auth/me", "query_string": b"",
                       "headers": [(b"cookie", f"{auth.COOKIE}={token}".encode())]})
    assert asyncio.run(auth.current_user(request))["subject"] == "entra:anna@example.org"


def test_the_login_cookie_is_httponly_lax_site_wide_and_good_for_ten_minutes(login_api):     # main._set_cookie, auth.NONCE_TTL_S
    headers = login_api.post("/api/auth/nonce").headers.get_list("set-cookie")
    attrs = {h.split("=", 1)[0]: {a.strip().lower() for a in h.split(";")[1:]} for h in headers}
    assert attrs.keys() == {"sv_login"} and {"httponly", "samesite=lax", "path=/", "max-age=600"} <= attrs["sv_login"]


def test_the_start_names_full_rights_without_a_mapping():
    s = config.Settings(secret_key=secrets.token_hex(32), entra_tenant_id="t", entra_client_id="c", entra_allowed_roles=["SwitchView.Admin"])
    assert main.check_startup_config(s) == [main.NO_ROLE_MAPPING] and main.check_startup_config(dataclasses.replace(s, **ON)) == []
    assert main.check_startup_config(dataclasses.replace(s, entra_tenant_id="")) == []


@pytest.mark.parametrize("field, value, text", [("entra_role_mapping", "ja", "ENTRA_ROLE_MAPPING muss on oder off sein"),
                                                ("idle_minutes", -1, "IDLE_MINUTES muss 0 oder größer sein"),
                                                ("history_days", -1, "HISTORY_DAYS muss 0 oder größer sein"),
                                                ("public_url", "ftp://sv", "PUBLIC_URL muss mit http:// oder https:// beginnen")])
def test_the_start_refuses(field, value, text):
    with pytest.raises(RuntimeError, match=text):
        main.check_startup_config(config.Settings(secret_key=secrets.token_hex(32), **{field: value}))
