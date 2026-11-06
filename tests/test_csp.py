"""Phase 5 Task 2: one strict Content-Security-Policy on every answer; with SSO it allows exactly the Entra login host for MSAL's
fetches. The page and the scripts need nothing it forbids: no inline script, no handler attribute, no eval, no external origin."""
import dataclasses
import re
from pathlib import Path

import pytest

import auth
import main
from loginfix import GOOD

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
SCRIPTS = re.findall(r'<script src="/static/([\w.\-]+)"></script>', INDEX)
BASE = ("default-src 'none'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self'; font-src 'self'; "
        "connect-src 'self'{sso}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
WITH_SSO, WITHOUT_SSO = BASE.format(sso=" https://login.microsoftonline.com"), BASE.format(sso="")


def test_the_policy_is_pinned():
    assert (main.content_security_policy(True), main.content_security_policy(False)) == (WITH_SSO, WITHOUT_SSO)


@pytest.mark.parametrize("method, path", [("GET", "/"), ("GET", "/static/app.css"), ("GET", "/static/fonts/Geist-Regular.woff2"),
                                          ("GET", "/api/auth/config"), ("GET", "/api/netmap"), ("GET", "/nope"), ("POST", "/api/auth/logout")])
def test_every_answer_carries_the_policy(login_api, method, path):
    assert login_api.request(method, path).headers["Content-Security-Policy"] == WITH_SSO


def test_a_304_and_a_413_carry_it_too(login_api):
    etag = login_api.get("/static/app.css").headers["etag"]
    assert login_api.get("/static/app.css", headers={"If-None-Match": etag}).headers["Content-Security-Policy"] == WITH_SSO
    r = login_api.post("/api/auth/local", content=b"x" * 70_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.headers["Content-Security-Policy"] == WITH_SSO


def test_without_sso_no_external_origin_is_allowed(login_api, monkeypatch):
    monkeypatch.setattr(main, "settings", dataclasses.replace(main.settings, entra_tenant_id=""))
    assert login_api.get("/").headers["Content-Security-Policy"] == WITHOUT_SSO and "https:" not in WITHOUT_SSO


def test_the_emergency_login_works_under_the_policy(login_api):
    r = login_api.post("/api/auth/local", json=GOOD)
    assert r.status_code == 200 and r.headers["Content-Security-Policy"] == WITH_SSO
    assert login_api.get("/api/auth/me").json()["username"] == GOOD["username"]


def test_the_entra_login_works_under_the_policy(login_api, monkeypatch):
    monkeypatch.setattr(auth, "verify_id_token", lambda token: {"sub": "s1", "preferred_username": "anna@example.org", "name": "Anna"})
    r = login_api.post("/api/auth/azure", json={"id_token": "x.y.z"})
    assert r.status_code == 200 and r.headers["Content-Security-Policy"] == WITH_SSO
    assert login_api.get("/api/auth/me").json()["username"] == "anna@example.org"


def test_the_page_needs_no_inline_script_style_or_handler():
    assert re.findall(r"<script\b[^>]*>", INDEX) == [f'<script src="/static/{n}">' for n in SCRIPTS]
    assert not re.search(r"<style\b|\son[a-z]+=|javascript:", INDEX)
    for n in SCRIPTS[1:]:
        text = (STATIC / n).read_text(encoding="utf-8")
        assert not re.search(r"\beval\(|new Function|\bset(?:Timeout|Interval)\(\s*['\"`]|<style\b|\son[a-z]+=\"|javascript:", text), n


def test_msal_needs_no_eval():
    text = (STATIC / "msal-browser.min.js").read_text(encoding="utf-8")
    assert text.startswith("/*! @azure/msal-browser v3.30.0") and "eval(" not in text and "new Function" not in text


def test_the_only_origin_a_script_reaches_is_the_sso_host():
    """The two others are placeholder texts of the settings form, never fetched by the browser."""
    admin = (STATIC / "sv-admin.js").read_text(encoding="utf-8")
    placeholders = set(re.findall(r'placeholder="(https?://[^"]+)"', admin))
    origins = {o for n in SCRIPTS[1:] for o in re.findall(r"https?://[\w.:-]+", (STATIC / n).read_text(encoding="utf-8"))}
    assert placeholders == {"https://opnsense.example.com", "https://packetfence:9999"} and origins - placeholders == {main.SSO_ORIGIN}
