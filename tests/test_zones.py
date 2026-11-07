"""Zone scopes (Phase 4a, Task 5, market theme E "scoping operators to specific switches"): an Admin-kept list "Entra app role → zones"
(table zone_scopes, GET/PUT /api/zone-scopes) limits Ändern and Freigeben to the switches of those zones. A user whose app roles meet
no entry is not limited, an empty list limits no one, Admin and Lesen are never limited. auth.current_user works the zones out on
every request from the roles the session stored and the list of now (roles.zones_of), so a new entry counts at once; /plan and /apply
check the switch's zone before anything else (api_changes._mode_rights, roles.zone_allows) and refuse with roles.zone_denial.

The app runs in-process through FastAPI's TestClient: `api` signed in through the override of auth.current_user (apifix.signed_in,
then apifix.become for another user), `login_api` of conftest.py without any override (the real session code).
"""
import asyncio
import dataclasses

import pytest

import apifix
import auth
import dbfix
import roles


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app against a fresh database under tmp_path (the app's own init_db), signed in as apifix.USER (Admin);
    apifix.become signs it in as another user."""
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


@pytest.mark.parametrize("role, claim, scopes, want", [
    ("admin", ["Z.EK"], [("Z.EK", "EK")], None), ("lesen", ["Z.EK"], [("Z.EK", "EK")], None), ("aendern", [], [("Z.EK", "EK")], None),
    ("aendern", ["Z.EK"], [("Z.EK", "EK")], ["EK"]), ("freigeben", ["Z.EK", "Z.VK"], [("Z.EK", "EK"), ("Z.VK", "VK"), ("Z.VK", "")], ["", "EK", "VK"]),
    ("aendern", ["Z.EK"], [], None)])
def test_zones_of(role, claim, scopes, want):
    assert roles.zones_of(role, claim, scopes) == want


def test_the_denial_names_the_zones():
    assert roles.zone_denial("", ["EK", "VK"]) == ("Keine Berechtigung: Der Switch liegt in der Zone „Ohne Zone“ – "
                                                   "du darfst nur an Switches der Zonen „EK“, „VK“ ändern")


def test_the_scopes_take_effect_at_once(login_api, monkeypatch):
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, entra_role_mapping="on"))
    login_api.cookies.set(auth.COOKIE, asyncio.run(auth.create_session("anna", "Anna", "entra", roles=["SwitchView.Aendern", "Z.EK"])))
    assert login_api.get("/api/auth/me").json()["zones"] is None
    dbfix.query("INSERT INTO zone_scopes(principal, zone) VALUES ('Z.EK', 'EK')")
    assert login_api.get("/api/auth/me").json()["zones"] == ["EK"]


def test_put_replaces_every_entry_and_audits(api):
    api.put("/api/zone-scopes", json={"entries": [{"principal": "Z.EK", "zones": ["EK"]}]})
    r = api.put("/api/zone-scopes", json={"entries": [{"principal": " Z.VK ", "zones": ["VK", ""]}, {"principal": "Z.VK", "zones": ["Lager"]}]})
    assert r.json() == api.get("/api/zone-scopes").json() == {"entries": [{"principal": "Z.VK", "zones": ["", "Lager", "VK"]}]}
    assert dbfix.query("SELECT action, role FROM audit") == [("zone_scopes_update", "admin")] * 2
    assert dbfix.query("SELECT detail FROM audit ORDER BY id") == [("1 Einträge: Z.EK → EK",), ("1 Einträge: Z.VK → Ohne Zone, Lager, VK",)]


@pytest.mark.parametrize("entries", [[{"principal": " ", "zones": ["EK"]}], [{"principal": "Z", "zones": []}], [{"principal": "Z", "zones": ["x" * 41]}]])
def test_put_refuses_bad_entries(api, entries):
    assert api.put("/api/zone-scopes", json={"entries": entries}).status_code == 422


@pytest.mark.parametrize("zone, refused", [("VK", True), ("EK", False)])
@pytest.mark.parametrize("route", ["plan", "apply"])
def test_a_scoped_user_changes_only_in_their_zones(api, route, zone, refused):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1", zone=zone)
    apifix.become(apifix.user("aendern", zones=["EK"]))
    r = api.post(f"/api/switches/{sid}/{route}", json={"ports": ["1"], "change": {"status": "off"}})
    assert (r.status_code == 403 and r.json()["detail"] == roles.zone_denial(zone, ["EK"])) == refused


# ── Beyond the plan ──────────────────────────────────────────────────────────


def test_a_blank_app_role_is_named_and_stores_nothing(api):
    """The 422 for a principal that is blank once trimmed says what is missing, and the refused PUT leaves the list as it was."""
    api.put("/api/zone-scopes", json={"entries": [{"principal": "Z.EK", "zones": ["EK"]}]})
    r = api.put("/api/zone-scopes", json={"entries": [{"principal": "Z.VK", "zones": ["VK"]}, {"principal": "  ", "zones": ["EK"]}]})
    assert (r.status_code, r.json()["detail"]) == (422, "App-Rolle fehlt")
    assert dbfix.query("SELECT principal, zone FROM zone_scopes") == [("Z.EK", "EK")]
    assert dbfix.query("SELECT count(*) FROM audit") == [(1,)]


def test_an_empty_list_clears_every_entry_and_a_long_audit_is_cut(api):
    many = [{"principal": f"SwitchView.Zone.{i:03}", "zones": ["Gebäude A", "Gebäude B"]} for i in range(30)]
    assert len(api.put("/api/zone-scopes", json={"entries": many}).json()["entries"]) == 30
    assert api.put("/api/zone-scopes", json={"entries": []}).json() == {"entries": []}
    assert api.put("/api/zone-scopes", json={}).json() == {"entries": []}
    assert dbfix.query("SELECT count(*) FROM zone_scopes") == [(0,)]
    [(long,), (empty,), (default,)] = dbfix.query("SELECT detail FROM audit ORDER BY id")
    assert len(long) == 500 and long.startswith("30 Einträge: SwitchView.Zone.000 → Gebäude A, Gebäude B; SwitchView.Zone.001 → ")
    assert empty == default == "0 Einträge"


def test_the_zone_is_checked_before_the_mode(api):
    """A scoped user's request for a switch outside their zones is refused for the zone, whatever its mode would need."""
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1", zone="VK")
    apifix.become(apifix.user("aendern", zones=["EK"]))
    r = api.post(f"/api/switches/{sid}/plan", json={"mode": "prepare"})
    assert (r.status_code, r.json()["detail"]) == (403, roles.zone_denial("VK", ["EK"]))


@pytest.mark.parametrize("method, app_roles", [("local", []), ("entra", ["SwitchView.Lesen", "Z.EK"]), ("entra", ["SwitchView.Admin", "Z.EK"])])
def test_admin_and_lesen_are_never_scoped_and_read_no_scopes(login_api, monkeypatch, method, app_roles):
    """Admin (the emergency login, an SSO Admin) and Lesen get zones None without reading the list: with the table gone, so that any
    read of it would fail, their request still passes."""
    monkeypatch.setattr(auth, "settings", dataclasses.replace(auth.settings, entra_role_mapping="on"))
    dbfix.query("DROP TABLE zone_scopes")
    login_api.cookies.set(auth.COOKIE, asyncio.run(auth.create_session("anna", "Anna", method, roles=app_roles)))
    assert login_api.get("/api/auth/me").json()["zones"] is None
