"""Login hardening (Phase 2, Task 1): the emergency login's throttle counts failures per identity, never per client address (F1); the
image trusts no proxy headers by default; a request body over 64 KiB is refused before any endpoint reads it; a non-ASCII login is a
clean, audited 401 (F6), compared without a length or user-name oracle; the Entra check reloads the JWKS for an unknown kid at most
once per 5 minutes and refuses an access token in place of an id_token. SSO is never throttled.

The app runs in-process through FastAPI's TestClient (the login_api fixture in conftest.py: a fresh database under tmp_path, the
emergency account and SSO switched on, no dependency_overrides, the scheduler booby-trapped). Nothing reaches Microsoft: the JWKS
client and the token check are faked where a test needs them.
"""
import asyncio
import json
import pathlib
import time
import types

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import auth
import bodylimit
import main
import throttle
from loginfix import BAD, CSRF, GOOD, audit_rows

DOCKERFILE = (pathlib.Path(__file__).parent.parent / "Dockerfile").read_text(encoding="utf-8")


def raising(exc):
    """A stand-in that raises exc, whatever it is called with."""
    def fail(*args, **kwargs):
        raise exc
    return fail


class FakeJwks:
    """A tenant's JWKS client (jwt.PyJWKClient) that knows no key; counts the forced reloads (refresh=True)."""

    def __init__(self):
        self.refreshes = 0

    def get_signing_keys(self, refresh=False):
        if refresh:
            self.refreshes += 1
        return []

    match_kid = staticmethod(lambda keys, kid: None)


@pytest.fixture
def entra(monkeypatch):
    """The tenant "t" of login_api with one RS256 signing key, kid "k1", served by a JWKS client that never leaves the process.
    Returns sign(**claims): an id_token for client "c", signed with that key, with the given claims added or replaced."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.PyJWK({**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key())), "kid": "k1", "use": "sig"})
    client = types.SimpleNamespace(get_signing_keys=lambda refresh=False: [jwk], match_kid=jwt.PyJWKClient.match_kid)
    monkeypatch.setattr(auth, "_jwks_client", lambda tenant: client)
    now = int(time.time())
    base = {"iss": "https://login.microsoftonline.com/t/v2.0", "tid": "t", "aud": "c", "sub": "s", "iat": now, "exp": now + 600}
    return lambda **claims: jwt.encode({**base, **claims}, private, algorithm="RS256", headers={"kid": "k1"})


def test_spoofed_forwarded_for_never_opens_a_new_bucket(login_api):           # F1, the audit's input
    proxied = TestClient(ProxyHeadersMiddleware(main.app, trusted_hosts="*"), headers=CSRF)   # as --forwarded-allow-ips * did: XFF becomes the client
    codes = [proxied.post("/api/auth/local", json=BAD, headers={"X-Forwarded-For": f"10.{i}.0.1"}).status_code for i in range(12)]
    assert codes == [401] * 10 + [429, 429] and len(main._LOGIN) == 1


def test_throttle_memory_is_bounded():
    t = throttle.LoginThrottle(max_keys=100)
    for i in range(1000):
        t.fail([f"dev:{i}"])
    assert len(t) <= 100


def test_failures_expire_after_the_window():
    now = [0.0]
    t = throttle.LoginThrottle(clock=lambda: now[0])
    for _ in range(10):
        t.fail(["local"])
    assert t.blocked(["local"])
    now[0] = 60.1
    assert not t.blocked(["local"]) and len(t) == 0


def test_the_keys_stay_in_the_order_of_their_last_failure():
    """_expire drops keys from the front only, so a key that fails again moves to the end. Otherwise B (last failure at 10) would sit
    behind A (last failure at 50) after its window, blocked() would empty its times at 75, and at 111 _expire would read the last time
    of an empty deque: an IndexError, a 500 on every emergency login."""
    now = [0.0]
    t = throttle.LoginThrottle(clock=lambda: now[0])
    for at, key in ((0, "A"), (10, "B"), (50, "A")):
        now[0] = at
        t.fail([key])
    now[0] = 75
    assert not t.blocked(["B"]) and len(t) == 1
    now[0] = 111
    assert not t.blocked(["A"]) and len(t) == 0


def test_beyond_max_keys_the_key_with_the_oldest_last_failure_goes():
    """One failure blocks here (limit 1), so blocked() shows which keys are kept: A failed again after B, so B goes when C comes."""
    now = [0.0]
    t = throttle.LoginThrottle(limit=1, max_keys=2, clock=lambda: now[0])
    for at, key in ((0, "A"), (1, "B"), (2, "A"), (3, "C")):
        now[0] = at
        t.fail([key])
    assert [t.blocked([k]) for k in "ABC"] == [True, False, True]
    one = throttle.LoginThrottle(limit=1, max_keys=1, clock=lambda: now[0])
    for at, key in ((4, "A"), (5, "B")):
        now[0] = at
        one.fail([key])
    assert [one.blocked([k]) for k in "AB"] == [False, True]


def test_a_known_browser_gets_in_while_an_attacker_hammers(login_api):        # Review Focus 1
    assert login_api.post("/api/auth/local", json=GOOD).cookies.get(auth.DEVICE_COOKIE)
    attacker = TestClient(main.app, headers=CSRF)                               # the same sender address, no device cookie
    assert [attacker.post("/api/auth/local", json=BAD).status_code for _ in range(11)][-1] == 429
    assert login_api.post("/api/auth/local", json=GOOD).status_code == 200


def test_device_cookie_is_bound_to_its_user_and_unforgeable():
    tok = auth.device_token("admin")
    assert auth.device_id(tok, "ADMIN") == tok.split(".")[0] and auth.device_id(tok, "root") is None
    assert auth.device_id(tok[:-1] + ("0" if tok[-1] != "0" else "1"), "admin") is None
    assert auth.device_id("kaputt", "admin") is None and auth.device_id(None, "admin") is None


def test_non_ascii_login_is_a_clean_401_and_audited(login_api):              # F6, the audit's input
    r = login_api.post("/api/auth/local", json={"username": "ädmin", "password": "x"})
    assert r.status_code == 401 and audit_rows() == [("ädmin", "login_failed", "local")]


def test_a_non_ascii_password_logs_in(login_api):
    assert login_api.post("/api/auth/local", json=GOOD).status_code == 200    # GOOD contains "ß"


def test_check_local_always_compares_both_fields(login_api, monkeypatch):    # §6 timing
    calls = []
    monkeypatch.setattr(auth.hmac, "compare_digest", lambda a, b: calls.append(1) or a == b)
    assert auth.check_local("niemand", "x") is False and len(calls) == 2


def test_sso_is_never_throttled(login_api, monkeypatch):
    monkeypatch.setattr(auth, "verify_id_token", raising(ValueError("kaputt")))
    assert {login_api.post("/api/auth/azure", json={"id_token": "x"}).status_code for _ in range(30)} == {401}
    monkeypatch.setattr(auth, "verify_id_token", lambda t: {"sub": "s", "preferred_username": "u@example.org"})
    assert login_api.post("/api/auth/azure", json={"id_token": "x"}).status_code == 200


def test_unknown_kid_reloads_the_jwks_at_most_once(login_api, monkeypatch):   # JWKS flood
    fake = FakeJwks()
    monkeypatch.setattr(auth, "_jwks_client", lambda tenant: fake)
    for i in range(50):
        with pytest.raises(ValueError, match="Signaturschlüssel unbekannt"):
            auth.verify_id_token(jwt.encode({}, "x" * 32, algorithm="HS256", headers={"kid": f"k{i}"}))
    assert fake.refreshes == 1


def test_an_access_token_is_not_an_id_token(login_api, monkeypatch):         # §6 token class
    monkeypatch.setattr(auth, "_signing_key", lambda tenant, token: types.SimpleNamespace(key="k"))
    monkeypatch.setattr(auth.jwt, "decode", lambda *a, **k: {"iss": "https://login.microsoftonline.com/t/v2.0", "tid": "t",
                                                              "sub": "s", "scp": "User.Read"})
    with pytest.raises(ValueError, match="Kein ID-Token"):
        auth.verify_id_token("x.y.z")


def test_oversized_body_is_refused_before_the_endpoint(login_api):          # NV body, the audit's input
    big = b'{"username":"' + b"a" * 70_000 + b'","password":"x"}'
    for content in (big, iter([big[:40_000], big[40_000:]])):                 # with a Content-Length, and streamed
        r = login_api.post("/api/auth/local", content=content, headers={"Content-Type": "application/json"})
        assert r.status_code == 413 and r.json() == {"detail": "Anfrage zu groß"}
    assert audit_rows() == [] and login_api.post("/api/auth/local", json=BAD).status_code == 401


def test_dockerfile_trusts_no_proxy_by_default():
    cmd = next(line for line in DOCKERFILE.splitlines() if line.startswith("CMD"))
    assert "--proxy-headers" in cmd and "--forwarded-allow-ips" not in cmd


# Beyond the plan's list: the rest of what Task 1 states, each pinned where no test above would notice a break.

def test_a_successful_login_does_not_count(login_api):
    for _ in range(10):
        assert TestClient(main.app, headers=CSRF).post("/api/auth/local", json=GOOD).status_code == 200   # each a new browser
    assert TestClient(main.app, headers=CSRF).post("/api/auth/local", json=BAD).status_code == 401


def test_both_login_cookies_are_httponly_lax_and_site_wide(login_api):      # main._set_cookie, the one place for the flags
    headers = login_api.post("/api/auth/local", json=GOOD).headers.get_list("set-cookie")
    attrs = {h.split("=", 1)[0]: {a.strip().lower() for a in h.split(";")[1:]} for h in headers}
    assert attrs.keys() == {"sv_session", "sv_device"}
    assert {"httponly", "samesite=lax", "path=/", "max-age=43200"} <= attrs["sv_session"]          # SESSION_HOURS 12
    assert {"httponly", "samesite=lax", "path=/", "max-age=15552000"} <= attrs["sv_device"]        # 180 days


def test_an_id_token_signed_by_the_tenant_passes(login_api, entra):
    assert auth.verify_id_token(entra(name="Ada"))["name"] == "Ada"


def test_an_app_only_token_is_not_an_id_token(login_api, entra):            # E5, the other mark of an access token
    with pytest.raises(ValueError, match="Kein ID-Token"):
        auth.verify_id_token(entra(idtyp="app"))


def test_the_token_check_runs_off_the_event_loop(login_api, monkeypatch):    # E4: a JWKS fetch must not stall every request
    def check(token):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return {"sub": "s", "preferred_username": "u@example.org"}
        raise AssertionError("verify_id_token ran on the event loop")
    monkeypatch.setattr(auth, "verify_id_token", check)
    assert login_api.post("/api/auth/azure", json={"id_token": "x"}).status_code == 200


def test_the_413_carries_the_security_headers(login_api):
    r = login_api.post("/api/auth/local", content=b"x" * 70_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"


@pytest.mark.parametrize("chunks, status", [((b"01234", b"56789"), 204), ((b"01234", b"56789", b"!"), 413)])
async def test_streamed_chunks_reach_the_app_as_one_body_up_to_the_cap(chunks, status):
    seen, sent = [], []
    messages = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]

    async def app(scope, receive, send):
        seen.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    await bodylimit.BodyLimit(app, max_bytes=10)({"type": "http", "headers": []}, receive, send)
    assert sent[0]["status"] == status
    assert seen == ([{"type": "http.request", "body": b"0123456789", "more_body": False}] if status == 204 else [])


async def test_a_declared_length_over_the_cap_is_refused_unread():      # Phase 2 gap: the Content-Length short cut (E3)
    sent, app_called = [], []

    async def app(scope, receive, send):
        app_called.append(True)

    async def receive():
        raise AssertionError("the body must not be read")

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/", "headers": [(b"content-length", b"11")]}
    await bodylimit.BodyLimit(app, max_bytes=10)(scope, receive, send)
    assert sent[0]["status"] == 413 and app_called == []
