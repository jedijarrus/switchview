"""Anmeldung: Entra-SSO (MSAL-Popup, id_token per JWKS geprueft) und optionaler Notfall-Login."""
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Request

from config import settings
from db import db

COOKIE = "sv_session"
_jwks: dict[str, tuple[object, float]] = {}


def _jwks_client(tenant: str):
    entry = _jwks.get(tenant)
    if entry and time.time() - entry[1] < 3600:
        return entry[0]
    client = jwt.PyJWKClient(f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys")
    _jwks[tenant] = (client, time.time())
    return client


def verify_id_token(token: str) -> dict:
    tenant, client_id = settings.entra_tenant_id, settings.entra_client_id
    key = _jwks_client(tenant).get_signing_key_from_jwt(token)
    payload = jwt.decode(token, key.key, algorithms=["RS256"], audience=client_id,
                         options={"require": ["exp", "iat", "iss", "sub", "aud"]}, leeway=60)
    if payload.get("iss") not in (f"https://login.microsoftonline.com/{tenant}/v2.0", f"https://sts.windows.net/{tenant}/"):
        raise ValueError("Aussteller ungültig")
    if payload.get("tid") != tenant:
        raise ValueError("Falscher Tenant")
    roles, groups = payload.get("roles") or [], payload.get("groups") or []
    if settings.entra_allowed_roles or settings.entra_allowed_groups:
        ok = any(r in roles for r in settings.entra_allowed_roles) or any(g in groups for g in settings.entra_allowed_groups)
        if not ok:
            raise PermissionError("Keine Berechtigung für SwitchView")
    return payload


def check_local(username: str, password: str) -> bool:
    if not settings.local_login_active:
        return False
    return hmac.compare_digest(username, settings.admin_user) and hmac.compare_digest(password, settings.admin_password)


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
