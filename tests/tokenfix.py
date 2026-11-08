"""Helpers of the API-token tests (tests/test_tokens.py; Tasks 3, 7 and 12 of Phase 4c take them too): a person signed in over SSO
through the entra fixture of conftest.py, an API token created through POST /api/tokens, a client as a script is (no cookie, no CSRF
header) and the Authorization header of a token.

A module like tests/loginfix.py: helpers, no fixture (a fixture is never imported). It imports app code (main), so test modules
import it at the top, after conftest.py has set the environment, and conftest.py never does at its top.
"""
from fastapi.testclient import TestClient

import loginfix
import main


def signed(client, entra, who="anna", app_roles=("SwitchView.Aendern",)):
    """client signed in over SSO as <who>@example.org (object id oid-<who>, so subject entra:oid-<who>) with app_roles; client."""
    assert loginfix.sso_login(client, entra, preferred_username=f"{who}@example.org", oid=f"oid-{who}",
                              roles=list(app_roles)).status_code == 200
    return client


def mint(client, **body) -> dict:
    """A new API token of client's user, named "ci" unless body names it: the answer of POST /api/tokens (with the token itself)."""
    r = client.post("/api/tokens", json={"name": "ci", **body})
    assert r.status_code == 200, r.json()
    return r.json()


def bare() -> TestClient:
    return TestClient(main.app)                     # no cookie, no CSRF header: what a script sends


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
