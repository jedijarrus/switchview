"""Anmeldung: Entra-SSO (MSAL-Popup, id_token per JWKS geprueft) und optionaler Notfall-Login."""
import hashlib
import hmac
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Request

from config import settings
from db import db

COOKIE = "sv_session"
# The device cookie of the emergency login: a browser in which it succeeded once carries a MAC-signed nonce bound to the user, and the
# login throttle counts that browser's failures apart from all others (main.login_local), so an attacker cannot lock it out.
DEVICE_COOKIE = "sv_device"
DEVICE_DAYS = 180
# A kid the cached JWKS lacks reloads the set from Microsoft at most this often per tenant (seconds).
JWKS_REFRESH_S = 300
_jwks: dict[str, tuple[object, float]] = {}
_jwks_refreshed: dict[str, float] = {}      # tenant -> time.monotonic() of its last forced reload
_jwks_lock = threading.Lock()               # the token checks run in worker threads (main.login_azure)


def _jwks_client(tenant: str):
    entry = _jwks.get(tenant)
    if entry and time.time() - entry[1] < 3600:
        return entry[0]
    client = jwt.PyJWKClient(f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys")
    _jwks[tenant] = (client, time.time())
    return client


def _signing_key(tenant: str, token: str):
    """The key for the token's kid from the tenant's cached JWKS. A kid the cached set lacks (Microsoft rolled its keys) reloads the
    set, but at most once per JWKS_REFRESH_S and tenant: otherwise every token with a made-up kid would cost a fetch from Microsoft."""
    kid = jwt.get_unverified_header(token).get("kid")
    client = _jwks_client(tenant)
    key = client.match_kid(client.get_signing_keys(), kid)
    if key is None and _may_reload(tenant):
        key = client.match_kid(client.get_signing_keys(refresh=True), kid)
    if key is None:
        raise ValueError("Signaturschlüssel unbekannt")
    return key


def _may_reload(tenant: str) -> bool:
    """True at most once per JWKS_REFRESH_S and tenant, and records it."""
    with _jwks_lock:
        now = time.monotonic()
        last = _jwks_refreshed.get(tenant)
        if last is not None and now - last < JWKS_REFRESH_S:
            return False
        _jwks_refreshed[tenant] = now
        return True


def verify_id_token(token: str) -> dict:
    tenant, client_id = settings.entra_tenant_id, settings.entra_client_id
    key = _signing_key(tenant, token)
    payload = jwt.decode(token, key.key, algorithms=["RS256"], audience=client_id,
                         options={"require": ["exp", "iat", "iss", "sub", "aud"]}, leeway=60)
    if payload.get("iss") not in (f"https://login.microsoftonline.com/{tenant}/v2.0", f"https://sts.windows.net/{tenant}/"):
        raise ValueError("Aussteller ungültig")
    if payload.get("tid") != tenant:
        raise ValueError("Falscher Tenant")
    # An access token for an API of this app registration passes the checks above as well. An id_token never carries scp (delegated
    # scopes) and never idtyp "app" (an app-only token); an access token carries one of them.
    if "scp" in payload or payload.get("idtyp") == "app":
        raise ValueError("Kein ID-Token")
    roles, groups = payload.get("roles") or [], payload.get("groups") or []
    if settings.entra_allowed_roles or settings.entra_allowed_groups:
        ok = any(r in roles for r in settings.entra_allowed_roles) or any(g in groups for g in settings.entra_allowed_groups)
        if not ok:
            raise PermissionError("Keine Berechtigung für SwitchView")
    return payload


def _utf8(text: str) -> bytes:
    """text as UTF-8 bytes. Never raises, not even on a lone surrogate."""
    return text.encode("utf-8", "surrogatepass")


def _digest(text: str) -> bytes:
    return hashlib.sha256(_utf8(text)).digest()


def check_local(username: str, password: str) -> bool:
    """The emergency login. Never raises (F6: hmac.compare_digest refuses a str with non-ASCII characters): it compares the SHA-256
    digests of both fields, always both, so neither the length of a value nor a wrong user name shows in the time the answer takes."""
    if not settings.local_login_active:
        return False
    user_ok = hmac.compare_digest(_digest(username), _digest(settings.admin_user))
    password_ok = hmac.compare_digest(_digest(password), _digest(settings.admin_password))
    return user_ok & password_ok


def _device_mac(nonce: str, username: str) -> str:
    key = hashlib.sha256(b"switchview-device-cookie:" + _utf8(settings.secret_key)).digest()
    return hmac.new(key, _utf8(f"{nonce}:{username.casefold()}"), hashlib.sha256).hexdigest()


def device_token(username: str) -> str:
    """The value of the device cookie for username: a random nonce and its MAC, "<nonce>.<mac>"."""
    nonce = secrets.token_urlsafe(16)
    return f"{nonce}.{_device_mac(nonce, username)}"


def device_id(cookie: str | None, username: str) -> str | None:
    """The nonce of a device cookie that device_token made for this user (the case of the name aside), otherwise None. Never raises."""
    nonce, _, mac = (cookie or "").partition(".")
    if not nonce or not mac:
        return None
    return nonce if hmac.compare_digest(_device_mac(nonce, username).encode(), _utf8(mac)) else None


async def create_session(username: str, display: str, method: str) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    async with db() as conn:
        await conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now.isoformat(),))
        await conn.execute("INSERT INTO sessions(token, username, display_name, method, created_at, expires_at) VALUES (?,?,?,?,?,?)",
                           (token, username, display, method, now.isoformat(), (now + timedelta(hours=settings.session_hours)).isoformat()))
        await conn.commit()
    return token


async def drop_session(token: str):
    async with db() as conn:
        await conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        await conn.commit()


async def current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Nicht angemeldet")
    async with db() as conn:
        async with conn.execute("SELECT username, display_name, method, expires_at FROM sessions WHERE token = ?", (token,)) as cur:
            row = await cur.fetchone()
    if not row or row["expires_at"] < datetime.now(timezone.utc).isoformat():
        raise HTTPException(401, "Sitzung abgelaufen")
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-Requested-With") != "SwitchView":
        raise HTTPException(403, "Ungültige Anfrage")
    return {"username": row["username"], "name": row["display_name"] or row["username"], "method": row["method"]}


def is_https(request: Request) -> bool:
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
