"""Rights per route (Phase 4a, Task 4): every route declares its minimum role through exactly one dependency auth.require(<role>),
recognisable by its min_role, or is one of the public routes of auth.PUBLIC_ROUTES. A walk over main.app.routes holds both against
MATRIX, the permission matrix of the plan (docs/superpowers/plans/2026-11-07-phase4a-rollen.md, Task 4; the rows of Tasks 5-7 come
with them; since Phase 4b Task 1 the union of MATRIX_4A and MATRIX_4B, the routes of docs/superpowers/plans/2026-11-07-phase4b-verlauf.md),
so a new route without a right fails here, not in operation. A role below the minimum gets 403 with the German text of
roles.denial; without a session every non-public route is 401. Inside /plan and /apply the mode has rules of its own: preparing RADIUS
is Admin (Sicherheit Phase 2 T2-R1, it sends the RADIUS secret), the expert mode and taking back an expert change are Freigeben. Every
audit entry records the role: the role of the request, of the new session for a login, none for a failed login, and the role of
whoever started a change for its change_* entry (changes.role).

The app runs in-process through FastAPI's TestClient: `api` signed in through the override of auth.current_user (apifix.signed_in,
then apifix.become for another role), `login_api` of conftest.py without any override (the real session code).
"""
import ast
import asyncio
import dataclasses
from pathlib import Path

import pytest
from fastapi.routing import APIRoute

import apifix
import auth
import changes
import dbfix
import loginfix
import main
import roles
from loginfix import BAD, GOOD

ROOT = Path(__file__).resolve().parent.parent

# The permission matrix of the plans, (method, path) -> minimum role, None for a public route (no sign-in). Written out by hand from
# the plans' tables in two halves: MATRIX_4A the routes up to Phase 4a (the table of docs/rollen-phase4a.md), MATRIX_4B the routes of
# Phase 4b (the table of docs/verlauf-phase4b.md); tests/test_readme.py holds each note to its half. MATRIX, their union, is what the
# walk over the routes compares. A new route needs a row in one half and one in tests/data/routes.json.
MATRIX_4A = {
    ("GET", "/"): None,
    ("GET", "/static/{name}"): None,
    ("GET", "/static/fonts/{name}"): None,
    ("GET", "/api/auth/config"): None,
    ("POST", "/api/auth/nonce"): None,
    ("POST", "/api/auth/local"): None,
    ("POST", "/api/auth/azure"): None,
    ("POST", "/api/auth/logout"): None,
    ("GET", "/api/auth/me"): "lesen",
    ("POST", "/api/auth/logout-all"): "lesen",
    ("GET", "/api/netmap"): "lesen",
    ("GET", "/api/drivers"): "lesen",
    ("GET", "/api/switches"): "lesen",
    ("POST", "/api/switches"): "admin",
    ("PUT", "/api/switches/{sid}"): "admin",
    ("DELETE", "/api/switches/{sid}"): "admin",
    ("DELETE", "/api/switches/{sid}/ssh-host-key"): "admin",
    ("POST", "/api/switches/{sid}/test"): "lesen",
    ("POST", "/api/switches/{sid}/poll"): "lesen",
    ("POST", "/api/poll"): "lesen",
    ("POST", "/api/switches/{sid}/config/refresh"): "lesen",
    ("POST", "/api/switches/{sid}/port-access"): "lesen",
    ("POST", "/api/switches/{sid}/backup"): "lesen",
    ("GET", "/api/switches/{sid}/backups"): "lesen",
    ("GET", "/api/backups/{bid}"): "lesen",
    ("GET", "/api/backups/{bid}/diff"): "lesen",
    ("POST", "/api/switches/{sid}/plan"): "aendern",
    ("POST", "/api/switches/{sid}/apply"): "aendern",
    ("GET", "/api/changes"): "lesen",
    ("GET", "/api/changes/{cid}"): "lesen",
    ("GET", "/api/devices"): "lesen",
    ("GET", "/api/devices/unknown"): "lesen",
    ("POST", "/api/devices"): "aendern",
    ("PUT", "/api/devices/{mac}"): "aendern",
    ("DELETE", "/api/devices/{mac}"): "aendern",
    ("POST", "/api/devices/sync"): "aendern",
    ("GET", "/api/pf/roles"): "lesen",
    ("POST", "/api/pf/test"): "lesen",
    ("GET", "/api/settings"): "lesen",
    ("PUT", "/api/settings"): "admin",
    ("POST", "/api/names/refresh"): "lesen",
    ("GET", "/api/audit"): "lesen",
    ("GET", "/api/zone-scopes"): "lesen",
    ("PUT", "/api/zone-scopes"): "admin",
    ("PUT", "/api/settings/approvals"): "admin",
    ("POST", "/api/approvals"): "aendern",
    ("GET", "/api/approvals"): "lesen",
    ("GET", "/api/approvals/{aid}"): "lesen",
    ("POST", "/api/approvals/{aid}/withdraw"): "aendern",
    ("POST", "/api/approvals/{aid}/reject"): "freigeben",
    ("POST", "/api/approvals/{aid}/preview"): "freigeben",
    ("POST", "/api/approvals/{aid}/approve"): "freigeben",
}
MATRIX_4B: dict = {
    ("GET", "/api/history"): "lesen",
    ("GET", "/api/history.csv"): "lesen",
    ("GET", "/api/events"): "lesen",
}
MATRIX = MATRIX_4A | MATRIX_4B


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app against a fresh database under tmp_path (the app's own init_db), signed in as apifix.USER (Admin);
    apifix.become signs it in as another user."""
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def declared() -> dict:
    """(method, path) -> the min_role of the route's one auth.require dependency, None for a route without one."""
    assert all(isinstance(r, APIRoute) for r in main.app.routes)            # no plain Route or Mount slips past the walk
    out = {}
    for r in main.app.routes:
        found = [d.call.min_role for d in r.dependant.dependencies if hasattr(d.call, "min_role")]
        assert len(found) <= 1, r.path
        out |= {(m, r.path): (found[0] if found else None) for m in r.methods}
    return out


def test_every_route_declares_a_minimum_role_or_is_public():
    assert {k for k, v in declared().items() if v is None} == auth.PUBLIC_ROUTES


def test_the_rights_are_the_matrix_of_the_plan():
    assert declared() == MATRIX


def test_the_two_halves_of_the_matrix_do_not_overlap():
    assert not set(MATRIX_4A) & set(MATRIX_4B) and MATRIX == MATRIX_4A | MATRIX_4B


def test_there_is_one_dependency_per_role():
    """auth.require hands out the same dependency for the same role (cached), each carrying its role; a role that is none of the four
    fails at import, not at the first request."""
    assert [auth.require(r).min_role for r in roles.ORDER] == list(roles.ORDER)
    assert all(auth.require(r) is auth.require(r) for r in roles.ORDER) and len({auth.require(r) for r in roles.ORDER}) == 4
    with pytest.raises(ValueError):
        auth.require("admn")


PATH = dict(sid=1, bid=1, cid=1, aid=1, mac="aa:bb:cc:dd:ee:ff", name="x")


@pytest.mark.parametrize("method, path", [k for k, v in MATRIX.items() if v not in (None, roles.LESEN)])
def test_a_route_refuses_the_role_below_its_minimum(api, method, path):
    need = MATRIX[(method, path)]
    below = roles.ORDER[roles.ORDER.index(need) - 1]
    apifix.become(apifix.user(below))
    r = api.request(method, path.format(**PATH), json={})
    assert (r.status_code, r.json()["detail"]) == (403, roles.denial(need, below))


@pytest.mark.parametrize("method, path", [k for k, v in MATRIX.items() if v is not None])
def test_every_other_route_needs_a_session(login_api, method, path):
    assert login_api.request(method, path.format(**PATH), json={}).status_code == 401


MODES = [({"mode": "prepare"}, "freigeben", "admin", "„RADIUS vorbereiten“"),
         ({"ports": ["1"], "change": {"status": "off"}, "expert": True}, "aendern", "freigeben", "Der Expertenmodus")]


@pytest.mark.parametrize("route", ["plan", "apply"])
@pytest.mark.parametrize("payload, role, need, what", MODES)
def test_a_mode_needs_its_role(api, route, payload, role, need, what):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    apifix.become(apifix.user(role))
    r = api.post(f"/api/switches/{sid}/{route}", json=payload)
    assert (r.status_code, r.json()["detail"]) == (403, roles.denial(need, role, what))


@pytest.mark.parametrize("expert, refused", [(1, True), (0, False)])
def test_taking_back_an_expert_change_needs_freigeben(api, expert, refused):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    [(cid,)] = dbfix.query("INSERT INTO changes(switch_id, kind, summary, status, expert, sent) VALUES (?, 'ports', 'x', 'ok', ?, 1) "
                           "RETURNING id", (sid, expert))
    apifix.become(apifix.user("aendern"))
    r = api.post(f"/api/switches/{sid}/plan", json={"mode": "revert", "of": cid})
    assert (r.status_code == 403) == refused
    if refused:
        assert r.json()["detail"] == roles.denial("freigeben", "aendern", "Eine Änderung im Expertenmodus zurückzunehmen")


def test_every_audit_call_names_a_role():
    for path in sorted((ROOT / "app").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and "audit" in (getattr(node.func, "id", None), getattr(node.func, "attr", None)):
                assert "role" in {k.arg for k in node.keywords}, f"{path.name}:{node.lineno}"


def test_logins_are_audited_with_their_role(login_api):
    login_api.post("/api/auth/local", json=BAD)
    login_api.post("/api/auth/local", json=GOOD)
    assert dbfix.query("SELECT action, role FROM audit ORDER BY id") == [("login_failed", None), ("login", "admin")]
    assert [r["role"] for r in login_api.get("/api/audit").json()] == ["admin", None]


def test_an_sso_login_is_audited_with_the_role_of_its_session(login_api, entra, monkeypatch):
    s = dataclasses.replace(main.settings, entra_role_mapping="on")
    for module in (main, auth):
        monkeypatch.setattr(module, "settings", s)
    assert loginfix.sso_login(login_api, entra, preferred_username="anna@example.org", roles=["SwitchView.Aendern"]).status_code == 200
    assert dbfix.query("SELECT username, action, role FROM audit") == [("anna@example.org", "login", "aendern")]
    assert login_api.get("/api/auth/me").json()["role"] == "aendern"


def test_a_route_audits_the_role_of_its_request(api):
    """Through api_devices._save_device, which takes the user dict: the device is created by anna, the entry names her role."""
    apifix.become(apifix.user("aendern", "anna"))
    assert api.post("/api/devices", json={"mac": "aa:bb:cc:dd:ee:ff", "name": "Drucker"}).status_code == 200    # PacketFence not set up
    assert dbfix.query("SELECT username, action, role FROM audit") == [("anna", "device_create", "aendern")]
    assert dbfix.query("SELECT created_by FROM devices") == [("anna",)]


def test_a_change_is_audited_with_the_role_of_who_started_it(ssh_env):
    cid = asyncio.run(changes.create_change(ssh_env.sid, "anna", "save", "Speichern", {}, {"shown": [], "desired": {}, "before": {},
                                                                                           "mechanism": "ssh"}, role="aendern"))
    asyncio.run(changes.run_change(cid))
    assert dbfix.query("SELECT username, action, role FROM audit") == [("anna", "change_ok", "aendern")]
    assert ssh_env.change(cid)["role"] == "aendern"


def test_a_change_closed_off_the_ssh_way_is_audited_with_its_role(ssh_env):
    """_close (the end of every change that does not run over SSH; here the refusal of an unknown mechanism) audits with the role of
    the change as well."""
    cid = asyncio.run(changes.create_change(ssh_env.sid, "anna", "ports", "Port 1: Aus", {}, {"shown": [], "mechanism": "telnet"},
                                            role="freigeben"))
    asyncio.run(changes.run_change(cid))
    assert dbfix.query("SELECT username, action, role FROM audit") == [("anna", "change_aborted", "freigeben")]


def test_by_header_signs_each_request_in_as_the_user_its_header_names(api):
    users = {"anna": apifix.user("aendern", "anna")}
    apifix.by_header(users)
    assert api.get("/api/auth/me", headers={"X-Test-User": "anna"}).json()["role"] == "aendern"
    users["ben"] = apifix.user("freigeben", "ben")                          # added after the override: looked up per request
    assert api.get("/api/auth/me", headers={"X-Test-User": "ben"}).json()["username"] == "ben"
