"""Phase 4c, Task 3: the REST API side. The schema FastAPI generates from the routes is served as JSON at GET /api/openapi.json to
every signed-in role (no Swagger or ReDoc page: /docs, /redoc and /openapi.json stay 404); the {"rows", "next"} answers of the audit
and the history are a contract now (4b, "Später" 4c: the keys of the answer and of a row); and a script changes a port only through
/plan then /apply with the preview token of the plan, signed in by its API token - the flow of the README's "REST API".

The app runs in-process through FastAPI's TestClient: `api` signed in through the override of auth.current_user (apifix), the
script flow without any override (mapping and entra of tests/conftest.py, the helpers of tests/tokenfix.py). No network: the plan
and the run of the change are replaced at their seams (api_changes._make_plan, changes.run_change).
"""
import asyncio

import pytest
import tokenfix
from test_permissions import MATRIX

import api_changes
import apifix
import changes
import dbfix


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app against a fresh database under tmp_path, signed in as apifix.USER (Admin); apifix.become signs it in
    as another user."""
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def test_the_schema_is_served_to_every_role_and_names_every_api_route(api):
    apifix.become(apifix.user("lesen"))
    r = api.get("/api/openapi.json")
    assert r.status_code == 200 and r.json()["info"]["title"] == "SwitchView"
    paths = set(r.json()["paths"])
    assert {p for _, p in MATRIX if p.startswith("/api/")} - {"/api/openapi.json"} <= paths and "/api/openapi.json" not in paths and "/" not in paths


def test_a_read_only_api_token_reads_the_schema(mapping, entra):                         # beyond the brief: T3-a, any token
    t = tokenfix.mint(tokenfix.signed(mapping, entra), max_role="lesen")
    r = tokenfix.bare().get("/api/openapi.json", headers=tokenfix.bearer(t["token"]))
    assert r.status_code == 200 and "/api/switches/{sid}/plan" in r.json()["paths"]


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_no_page_of_swagger_or_redoc_is_served(api, path):
    assert api.get(path).status_code == 404


def test_the_schema_needs_a_session(login_api):
    assert login_api.get("/api/openapi.json").status_code == 401


AUDIT_ROW = {"id", "ts", "username", "action", "target", "detail", "role", "token"}
HISTORY_ROW = {"id", "mac", "vendor", "ip", "name", "switch_id", "switch", "port", "vlan", "first_seen", "last_seen", "suspect"}


def test_the_audit_and_the_history_answer_rows_and_next(api):                           # 4b, Später 4c: now a contract
    for i in (1, 2):
        dbfix.query("INSERT INTO audit(ts, username, action, role) VALUES (?, 'anna', 'login', 'admin')", (f"2026-11-08 10:0{i}:00",))
        dbfix.query("INSERT INTO sightings(mac, switch_name, port, vlan, first_seen, last_seen) VALUES ('aa:bb:cc:00:00:01', 'SW', ?, '1', "
                    "'2026-11-08 08:00:00', ?)", (str(i), f"2026-11-08 09:0{i}:00"))
    for url, params, row in (("/api/audit", {}, AUDIT_ROW), ("/api/history", {"q": "aa:bb:cc:00:00:01"}, HISTORY_ROW)):
        first = api.get(url, params={**params, "limit": 1}).json()
        assert set(first) == {"rows", "next"} and set(first["rows"][0]) == row and first["next"] is not None
        second = api.get(url, params={**params, "limit": 1, "cursor": first["next"]}).json()
        assert len(second["rows"]) == 1 and second["next"] is None


def test_a_script_changes_a_port_only_through_plan_and_apply(mapping, entra, monkeypatch):     # the flow of the README
    sid, ran = dbfix.insert_switch(name="SW", host="10.0.0.1", zone=""), []

    async def plan(row, body):
        shown = ["vlan 30 untagged 5"]
        return ({"shown": shown, "commands": shown, "blocked": [], "mechanism": "ssh", "warnings": [], "desired": {"5": {"u": "30"}},
                 "before": {"5": {"u": "20"}}, "expert": False}, {"ports": body.ports, "set": body.change.model_dump(), "expert": False},
                "ports", api_changes._summary(body))

    def run(cid):
        ran.append(cid)
        return asyncio.sleep(0)

    monkeypatch.setattr(api_changes, "_make_plan", plan)
    monkeypatch.setattr(changes, "run_change", run)
    h, s, want = tokenfix.bearer(tokenfix.mint(tokenfix.signed(mapping, entra))["token"]), tokenfix.bare(), {"ports": ["5"], "change": {"untagged": "30"}}
    p = s.post(f"/api/switches/{sid}/plan", json=want, headers=h).json()
    assert {"token", "mechanism", "commands", "blocked", "warnings", "approval"} <= set(p) and p["commands"] == ["vlan 30 untagged 5"]
    r = s.post(f"/api/switches/{sid}/apply", json=want, headers=h)                     # without the preview token: nothing starts
    assert (r.status_code, r.json()["detail"], ran) == (409, api_changes.STALE, [])
    r = s.post(f"/api/switches/{sid}/apply", json={**want, "token": p["token"], "mechanism": p["mechanism"]}, headers=h)
    assert r.status_code == 200 and set(r.json()) == {"id"} and ran == [r.json()["id"]]
    assert s.get(f"/api/changes/{r.json()['id']}", headers=h).json()["status"] == "queued"
