"""Phase 4a, Task 2 (Sicherheit Phase 2 A2): the Entra id_token is bound to its login attempt. POST /api/auth/nonce hands out a
short-lived nonce, bound to the cookie sv_login of the browser that asked; the frontend passes it to MSAL's loginPopup, Entra puts
it into the id_token, and POST /api/auth/azure accepts the token only with the nonce of this browser's attempt, once, for ten
minutes. The emergency login needs no nonce.

The app runs in-process through FastAPI's TestClient (login_api in conftest.py); the id_tokens are signed by the entra fixture of
conftest.py with a key of its own, so the real token check runs and nothing reaches Microsoft.
"""
import dataclasses

import pytest
from fastapi.testclient import TestClient

import auth
import loginfix
import main
from loginfix import CSRF, GOOD


def test_a_token_carrying_the_nonce_of_this_login_signs_in(login_api, entra):
    r = loginfix.sso_login(login_api, entra, preferred_username="anna@example.org", name="Anna")
    assert r.status_code == 200 and login_api.get("/api/auth/me").json()["username"] == "anna@example.org"
    assert auth.LOGIN_COOKIE not in login_api.cookies


def test_a_nonce_signs_in_once(login_api, entra):
    nonce = login_api.post("/api/auth/nonce").json()["nonce"]
    binding = login_api.cookies[auth.LOGIN_COOKIE]
    token = entra(nonce=nonce)
    assert login_api.post("/api/auth/azure", json={"id_token": token}).status_code == 200
    login_api.cookies.set(auth.LOGIN_COOKIE, binding)
    r = login_api.post("/api/auth/azure", json={"id_token": token})
    assert (r.status_code, r.json()["detail"]) == (401, main.NONCE_FAILED)


def test_a_token_without_the_nonce_is_refused(login_api, entra):
    login_api.post("/api/auth/nonce")
    assert login_api.post("/api/auth/azure", json={"id_token": entra()}).json()["detail"] == main.NONCE_FAILED


def test_the_nonce_of_another_browser_is_refused(login_api, entra):
    nonce = login_api.post("/api/auth/nonce").json()["nonce"]
    other = TestClient(main.app, headers=CSRF)
    other.post("/api/auth/nonce")
    assert other.post("/api/auth/azure", json={"id_token": entra(nonce=nonce)}).status_code == 401


def test_a_second_login_attempt_replaces_the_first(login_api, entra):                      # Review Focus 5
    first = login_api.post("/api/auth/nonce").json()["nonce"]
    second = login_api.post("/api/auth/nonce").json()["nonce"]
    assert login_api.post("/api/auth/azure", json={"id_token": entra(nonce=first)}).json()["detail"] == main.NONCE_FAILED
    assert login_api.post("/api/auth/azure", json={"id_token": entra(nonce=second)}).status_code == 200


def test_a_nonce_is_good_for_ten_minutes():                                                # Review Focus 5
    nonce, binding = auth.issue_nonce(now=1000.0)
    with pytest.raises(ValueError, match=auth.NONCE_BAD):
        auth.check_nonce(nonce, binding, now=1000.0 + auth.NONCE_TTL_S + 1)
    auth.check_nonce(nonce, binding, now=1000.0 + auth.NONCE_TTL_S - 1)


@pytest.mark.parametrize("mangle", [lambda n, b: (n[:-1] + ("0" if n[-1] != "0" else "1"), b), lambda n, b: (n, b + "x"), lambda n, b: (None, b),
                                    lambda n, b: (n, None), lambda n, b: ("kaputt", b), lambda n, b: ("9" * 400 + "." + n.split(".")[1], b)],
                         ids=["mac", "binding", "no-nonce", "no-cookie", "shape", "huge-ts"])
def test_a_forged_nonce_is_refused(mangle):
    with pytest.raises(ValueError, match=auth.NONCE_BAD):
        auth.check_nonce(*mangle(*auth.issue_nonce(now=1000.0)), now=1000.0)


@pytest.mark.parametrize("spell", [lambda n: "0" + n, lambda n: n.upper(), lambda n: n + "\n", lambda n: [n], lambda n: int(n.split(".")[0])],
                         ids=["leading-zero", "upper-hex", "newline", "list", "number"])
def test_a_used_nonce_in_another_spelling_or_type_is_refused(spell, monkeypatch):
    """The MAC is taken over ts as written: "01000.<mac>" is not a second, unused spelling of "1000.<mac>". A claim that is no text
    (Entra sends a text; a token could carry anything) is the same refusal, not a TypeError."""
    monkeypatch.setattr(auth, "_used_nonces", {})
    nonce, binding = auth.issue_nonce(now=1000.0)
    auth.check_nonce(nonce, binding, now=1000.0)
    with pytest.raises(ValueError, match=auth.NONCE_BAD):
        auth.check_nonce(spell(nonce), binding, now=1000.0)


def test_a_nonce_from_another_clock_counts_up_to_a_minute_ahead(monkeypatch):
    monkeypatch.setattr(auth, "_used_nonces", {})
    with pytest.raises(ValueError, match=auth.NONCE_BAD):
        auth.check_nonce(*auth.issue_nonce(now=1000.0 + 61), now=1000.0)
    auth.check_nonce(*auth.issue_nonce(now=1000.0 + 59), now=1000.0)


def test_used_nonces_are_forgotten_after_their_time(monkeypatch):
    monkeypatch.setattr(auth, "_used_nonces", {})
    auth.check_nonce(*auth.issue_nonce(now=1000.0), now=1000.0)
    auth.check_nonce(*auth.issue_nonce(now=2000.0), now=2000.0)
    assert len(auth._used_nonces) == 1


def test_the_nonce_route_needs_sso(login_api, monkeypatch):
    monkeypatch.setattr(main, "settings", dataclasses.replace(main.settings, entra_tenant_id=""))
    assert login_api.post("/api/auth/nonce").status_code == 400


def test_the_emergency_login_needs_no_nonce(login_api):                                    # Pin
    assert login_api.post("/api/auth/local", json=GOOD).status_code == 200
