"""Anmeldung: Entra-SSO (MSAL-Popup, id_token per JWKS geprueft) und optionaler Notfall-Login."""
import functools
import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request

import roles
import throttle
from config import settings
from crypto import keyed_digest
from db import AUDIT_TOKEN, db, token_hash

log = logging.getLogger("switchview.auth")
COOKIE = "sv_session"
# The device cookie of the emergency login: a browser in which it succeeded once carries a MAC-signed nonce bound to the user, and the
# login throttle counts that browser's failures apart from all others (main.login_local), so an attacker cannot lock it out.
DEVICE_COOKIE = "sv_device"
DEVICE_DAYS = 180
# A kid the cached JWKS lacks reloads the set from Microsoft at most this often per tenant (seconds).
JWKS_REFRESH_S = 300
# A JWKS fetch waits at most JWKS_TIMEOUT_S for Microsoft (PyJWKClient's own default is 30 s, a worker thread each). After a fetch that
# could not reach Microsoft, no check of that tenant fetches for JWKS_FAIL_COOLDOWN_S: each fails at once with JWKS_DOWN (PyJWT drops
# its cached set after a failed fetch, so every SSO attempt during an outage would fetch and wait again).
JWKS_TIMEOUT_S = 5
JWKS_FAIL_COOLDOWN_S = 30
JWKS_DOWN = "Microsoft-Schlüssel gerade nicht abrufbar, bitte in einer halben Minute erneut anmelden"
# What a token check raises for a token it refuses, or while the JWKS cannot be fetched: expected, main.login_azure logs it in one line
TOKEN_ERRORS = (jwt.PyJWTError, ValueError)
_jwks: dict[str, tuple[object, float]] = {}
_jwks_refreshed: dict[str, float] = {}      # tenant -> time.monotonic() of its last forced reload
_jwks_failed: dict[str, float] = {}         # tenant -> time.monotonic() of its last fetch that could not reach Microsoft
_jwks_lock = threading.Lock()               # the token checks run in worker threads (main.login_azure)
# The nonce of an SSO login attempt (Phase 4a, Sicherheit Phase 2 A2): POST /api/auth/nonce hands out "<ts>.<mac>", the MAC over a
# random binding value and ts; the binding value goes into the httponly cookie LOGIN_COOKIE of the browser that asked, the nonce through
# MSAL into the id_token. main.login_azure takes the token only with the nonce of this browser's attempt, within NONCE_TTL_S, once.
# Stateless until used: only a nonce that came back in a valid id_token is remembered (_used_nonces), until it would have expired
# anyway, so the public route fills no memory.
LOGIN_COOKIE = "sv_login"
NONCE_TTL_S = 600
NONCE_SKEW_S = 60                           # a nonce of up to this many seconds in the future (another clock) still counts
NONCE_BAD = "Anmeldeversuch unbekannt, abgelaufen oder schon benutzt"
_NONCE = re.compile(r"([0-9]{1,12})\.([0-9a-f]{32})")
_used_nonces: dict[str, float] = {}         # nonce -> the time from which it may be forgotten (its ts + NONCE_TTL_S)
# The idle logout (Phase 4a, Sicherheit Phase 2 A3): a session without a request for settings.idle_minutes ends (current_user). Every
# signed-in request counts as activity; its time (sessions.last_seen) is written at most once per TOUCH_S, not on every request.
TOUCH_S = 60
# The routes anyone may call without a session (Phase 4a): the page, its static files and the login steps. Every other route declares
# its minimum role through require() (tests/test_permissions.py walks the routes against both and against the matrix of the plan).
PUBLIC_ROUTES = frozenset({("GET", "/"), ("GET", "/static/{name}"), ("GET", "/static/fonts/{name}"), ("GET", "/api/auth/config"),
                           ("POST", "/api/auth/nonce"), ("POST", "/api/auth/local"), ("POST", "/api/auth/azure"),
                           ("POST", "/api/auth/logout")})
# The API tokens of Phase 4c (Task 2; the routes are app/api_tokens.py): "svt_" + secrets.token_urlsafe(32), 256 random bits, the
# prefix so that secret scanners and people recognise a leaked one. A request with "Authorization: Bearer svt_..." is signed in by
# its token alone (current_user, _token_user); its times are UTC in the format of the column (TOKEN_TIME), never isoformat(): as
# text "2026-11-08 10:00:00" < "2026-11-08T09:00:00", a token would end hours early on the day of its expiry.
TOKEN_PREFIX = "svt_"
TOKEN_DEFAULT_DAYS = 90
TOKEN_MAX_DAYS = 365
TOKENS_PER_USER = 20
TOKEN_TIME = "%Y-%m-%d %H:%M:%S"
TOKEN_BAD = "API-Token ungültig, abgelaufen oder widerrufen"
TOKEN_THROTTLED = "Zu viele ungültige API-Tokens, bitte eine Minute warten"
# Invalid API tokens count under the one key "bearer" (never the client address, which a client forges, as for the emergency login),
# and only after the lookup: a valid token is never throttled, so no attacker can lock out the scripts. A token cannot be guessed
# (256 bits): the throttle keeps the log and the answers small, it does not stop anyone guessing.
_TOKENS = throttle.LoginThrottle()


class TokenLimit(Exception):
    """create_token: the subject has TOKENS_PER_USER API tokens already."""


class TokenNameTaken(Exception):
    """create_token: the subject has an API token of this name already."""


def _jwks_client(tenant: str):
    entry = _jwks.get(tenant)
    if entry and time.time() - entry[1] < 3600:
        return entry[0]
    client = jwt.PyJWKClient(f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys", timeout=JWKS_TIMEOUT_S)
    _jwks[tenant] = (client, time.time())
    return client


def _signing_key(tenant: str, token: str):
    """The key for the token's kid from the tenant's cached JWKS. A kid the cached set lacks (Microsoft rolled its keys) reloads the
    set, but at most once per JWKS_REFRESH_S and tenant: otherwise every token with a made-up kid would cost a fetch from Microsoft.
    Within JWKS_FAIL_COOLDOWN_S of a fetch that could not reach Microsoft (jwt.PyJWKClientConnectionError, recorded here) it raises
    ValueError(JWKS_DOWN) without fetching."""
    kid = jwt.get_unverified_header(token).get("kid")
    if _jwks_down(tenant):
        raise ValueError(JWKS_DOWN)
    client = _jwks_client(tenant)
    try:
        key = client.match_kid(client.get_signing_keys(), kid)
        if key is None and _may_reload(tenant):
            key = client.match_kid(client.get_signing_keys(refresh=True), kid)
    except jwt.PyJWKClientConnectionError:
        with _jwks_lock:
            _jwks_failed[tenant] = time.monotonic()
        raise
    if key is None:
        raise ValueError("Signaturschlüssel unbekannt")
    return key


def _jwks_down(tenant: str) -> bool:
    """Whether a fetch of the tenant's JWKS failed to reach Microsoft less than JWKS_FAIL_COOLDOWN_S ago."""
    with _jwks_lock:
        failed = _jwks_failed.get(tenant)
    return failed is not None and time.monotonic() - failed < JWKS_FAIL_COOLDOWN_S


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


def _nonce_mac(binding: str, ts: str) -> str:
    return keyed_digest("sso-nonce", f"{binding}:{ts}")[:32]


def issue_nonce(now: float | None = None) -> tuple[str, str]:
    """A new login attempt: (nonce, binding). The binding value goes into LOGIN_COOKIE, the nonce into MSAL's login request."""
    binding = secrets.token_urlsafe(16)
    ts = int(now or time.time())
    return f"{ts}.{_nonce_mac(binding, str(ts))}", binding


def check_nonce(nonce: str | None, binding: str | None, now: float | None = None) -> None:
    """Accepts the nonce of an id_token once: issued by issue_nonce for this binding value (the browser's LOGIN_COOKIE), not older
    than NONCE_TTL_S, not more than NONCE_SKEW_S ahead, not used before. Then remembers it until it would have expired, and forgets
    every used nonce whose time is over. Anything else raises ValueError(NONCE_BAD), never another exception: a claim that is no
    text fails the shape, and the MAC is taken over ts as written, before ts is read as a number (a leading zero is another nonce
    with another MAC, not a second spelling of a used one; no ts of a forged nonce ever meets a float)."""
    now = time.time() if now is None else now
    m = _NONCE.fullmatch(nonce) if isinstance(nonce, str) else None
    if not m or not isinstance(binding, str) or not binding:
        raise ValueError(NONCE_BAD)
    ts_text, mac = m.groups()
    if not hmac.compare_digest(_nonce_mac(binding, ts_text), mac):
        raise ValueError(NONCE_BAD)
    ts = int(ts_text)
    if now - ts > NONCE_TTL_S or ts - now > NONCE_SKEW_S or nonce in _used_nonces:
        raise ValueError(NONCE_BAD)
    for used in [n for n, until in _used_nonces.items() if until < now]:
        del _used_nonces[used]
    _used_nonces[nonce] = ts + NONCE_TTL_S


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


async def _delete_expired(conn) -> int:
    """Deletes the sessions of anyone on conn that current_user would refuse, without a commit; how many. A session is gone after its
    expires_at, and (Phase 4c) with settings.idle_minutes > 0 also when its last_seen lies further back than idle_minutes - the rule
    of current_user: a session without last_seen, from before the update, is not idle and stays."""
    now = datetime.now(timezone.utc)
    cur = await conn.execute("DELETE FROM sessions WHERE expires_at < ? OR (? > 0 AND last_seen IS NOT NULL AND last_seen < ?)",
                             (now.isoformat(), settings.idle_minutes, (now - timedelta(minutes=settings.idle_minutes)).isoformat()))
    return cur.rowcount


async def prune_sessions() -> int:
    """Deletes every expired or idle session (_delete_expired) and returns how many, and (Phase 4c) every expired API token, which
    the count leaves out: hourly by the scheduler (main._schedule) and once at the start (main.lifespan), so neither table grows
    between logins. Until then an expired token is refused like an unknown one (_token_user)."""
    async with db() as conn:
        pruned = await _delete_expired(conn)
        await conn.execute("DELETE FROM api_tokens WHERE expires_at < ?", (_token_now(),))
        await conn.commit()
    return pruned


def claim_roles(claims: dict) -> list[str]:
    """The app roles of an id_token as the session stores them: the text entries of its roles claim of at most 256 characters, in
    their order, the first 200. A roles claim that is no list (missing, None, a text, an object, ...) is no roles: [] (iterating a
    text or an object would take its characters or keys for roles)."""
    value = claims.get("roles")
    if not isinstance(value, list):
        return []
    return [r for r in value if isinstance(r, str) and len(r) <= 256][:200]


# "roles" (the plan's name) hides the module roles inside this function: use no roles.X here
async def create_session(username: str, display: str, method: str, *, roles: list[str] | None = None, subject: str | None = None) -> str:
    """Starts a session and returns its token for the cookie; the database keeps only token_hash(token). It stores the app roles of
    the login (claims, from which current_user works out the role on every request), the person's stable identity (subject, by
    default <method>:<username>) and the login as its first activity (last_seen)."""
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    async with db() as conn:
        await _delete_expired(conn)
        await conn.execute("INSERT INTO sessions(token, username, display_name, method, created_at, expires_at, claims, subject, last_seen) "
                           "VALUES (?,?,?,?,?,?,?,?,?)",
                           (token_hash(token), username, display, method, now.isoformat(),
                            (now + timedelta(hours=settings.session_hours)).isoformat(), json.dumps({"roles": roles or []}),
                            subject or f"{method}:{username}", now.isoformat()))
        await conn.commit()
    return token


async def drop_session(token: str):
    async with db() as conn:
        await conn.execute("DELETE FROM sessions WHERE token = ?", (token_hash(token),))
        await conn.commit()


async def drop_user_sessions(username: str) -> int:
    """Ends every session of username, on every device ("log out everywhere"), and returns how many of them were still valid.
    Expired and idle sessions of anyone are deleted first (_delete_expired), as create_session does, so they are not counted."""
    async with db() as conn:
        await _delete_expired(conn)
        cur = await conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        ended = cur.rowcount
        await conn.commit()
    return ended


def _token_now() -> str:
    """Now in UTC as the times of api_tokens are written (TOKEN_TIME), for comparing with them."""
    return datetime.now(timezone.utc).strftime(TOKEN_TIME)


def _stored_roles(claims: str | None) -> list[str]:
    """The app roles a session or an API token stored (claims, JSON {"roles": [...]}); [] without any (a session of before)."""
    return (json.loads(claims) if claims else {}).get("roles") or []


async def _zone_scopes(conn) -> list[tuple[str, str]]:
    """The (principal, zone) entries of the zone list of now, read on conn."""
    async with conn.execute("SELECT principal, zone FROM zone_scopes") as cur:
        return [(r["principal"], r["zone"]) for r in await cur.fetchall()]


def idle_reason(minutes: int) -> str:
    """The detail of the 401 for a session idle longer than minutes (settings.idle_minutes), one minute in the singular."""
    said = "1 Minute" if minutes == 1 else f"{minutes} Minuten"
    return f"Abgemeldet nach {said} ohne Aktivität – bitte neu anmelden"


async def current_user(request: Request) -> dict:
    """The signed-in user of request: username, name, method, role (roles.role_of from the roles the session stored at its login,
    against the mapping of now: a changed mapping counts from the restart that reads it, without a new login), subject (the stable
    identity; a session of before the update has none and gets <method>:<username>), zones (roles.zones_of: for Ändern and
    Freigeben from the stored roles against the zone_scopes of now, read on the same connection, so a new entry counts at once;
    None, no zone scope and no read, for every other role) and api_token (Phase 4c: None for a session). 401 without a session, for
    an expired one, and for one idle longer than settings.idle_minutes (then deleted, idle_reason; a session that never recorded a
    request, from before the update, is not idle); 403 for a write without the CSRF header. Every request that passes counts as
    activity: last_seen is written when it is unset or at least TOUCH_S old.

    A request with an API token (bearer_of: "Authorization: Bearer svt_...") is decided by the token alone (_token_user): the same
    dict, api_token its id and name; it never reads the cookie, so an invalid token is a 401 also next to a valid cookie, and it needs
    no CSRF header (that header protects the cookie, which such a request never reads, and a foreign page cannot set Authorization
    without a CORS grant). Any other Authorization header takes the cookie path as before."""
    api_token = bearer_of(request)
    if api_token is not None:
        return await _token_user(request, api_token)
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Nicht angemeldet")
    hashed, now = token_hash(token), datetime.now(timezone.utc)
    async with db() as conn:
        async with conn.execute("SELECT username, display_name, method, expires_at, claims, subject, last_seen FROM sessions WHERE token = ?",
                                (hashed,)) as cur:
            row = await cur.fetchone()
        if not row or row["expires_at"] < now.isoformat():
            raise HTTPException(401, "Sitzung abgelaufen")
        last_seen = row["last_seen"]
        if settings.idle_minutes and last_seen and last_seen < (now - timedelta(minutes=settings.idle_minutes)).isoformat():
            await conn.execute("DELETE FROM sessions WHERE token = ?", (hashed,))
            await conn.commit()
            raise HTTPException(401, idle_reason(settings.idle_minutes))
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-Requested-With") != "SwitchView":
            raise HTTPException(403, "Ungültige Anfrage")
        if not last_seen or last_seen <= (now - timedelta(seconds=TOUCH_S)).isoformat():
            await conn.execute("UPDATE sessions SET last_seen = ? WHERE token = ?", (now.isoformat(), hashed))
            await conn.commit()
        username, method = row["username"], row["method"]
        claim = _stored_roles(row["claims"])
        role = roles.role_of(method, claim, settings)
        scopes = await _zone_scopes(conn) if role in roles.SCOPED else []
    return {"username": username, "name": row["display_name"] or username, "method": method, "role": role,
            "subject": row["subject"] or f"{method}:{username}", "zones": roles.zones_of(role, claim, scopes), "api_token": None}


# ── API tokens (Phase 4c, Task 2) ─────────────────────────────────────────────
def bearer_of(request: Request) -> str | None:
    """The API token of request's Authorization header: the header, without the whitespace at its ends, splits at its first
    whitespace into scheme and rest; with the scheme bearer (any case) and a rest that starts, without the whitespace at its ends,
    with TOKEN_PREFIX, that rest. Otherwise None, and current_user takes the cookie path as before: without the header, with another
    scheme (Basic ...), with "Bearer" without a value, and with a bearer value without svt_ - a reverse proxy in front may set one of
    its own (oauth2-proxy with --pass-authorization-header passes its id_token so); refusing those would lock out every session
    behind such a proxy and fill the throttle with every request."""
    parts = request.headers.get("authorization", "").split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip().startswith(TOKEN_PREFIX):
        return parts[1].strip()
    return None


def token_label(row) -> str:
    """How the audit names an API token (audit.token): "<name> (#<id>)"."""
    return f"{row['name']} (#{row['id']})"


async def _token_user(request: Request, api_token: str) -> dict:
    """The user of an API token (current_user's bearer path), as a session's dict: the user name, name, method and subject of whoever
    created it; the role per request from the app roles of the session it was created in, against the mapping of now (roles.role_of),
    capped at its max_role (roles.cap); the zones likewise (for Ändern and Freigeben against the zone_scopes of now, on the same
    connection); api_token its id and name. No new check at Microsoft, as for a session: an app role taken away in Entra counts for
    a token only with its expiry or revocation. An unknown or expired token (expires_at before now, compared as TOKEN_TIME) is 401
    TOKEN_BAD, logged with the client's address and counted under "bearer" (_TOKENS); while "bearer" is blocked, every further invalid
    one is 429 TOKEN_THROTTLED instead, not logged. The lookup comes first, so a valid token is never throttled. last_used_at is
    written when it is unset or at least TOUCH_S old. Sets AUDIT_TOKEN for the request: every audit entry of its user names the token."""
    now = datetime.now(timezone.utc)
    async with db() as conn:
        async with conn.execute("SELECT id, name, username, display_name, method, subject, claims, max_role, expires_at, last_used_at "
                                "FROM api_tokens WHERE token_hash = ?", (token_hash(api_token),)) as cur:
            row = await cur.fetchone()
        if not row or row["expires_at"] < now.strftime(TOKEN_TIME):
            if _TOKENS.blocked(["bearer"]):
                raise HTTPException(429, TOKEN_THROTTLED)
            _TOKENS.fail(["bearer"])
            log.warning("API-Token abgelehnt (%s) von %s", "abgelaufen" if row else "unbekannt", request.client.host if request.client else "?")
            raise HTTPException(401, TOKEN_BAD)
        last_used = row["last_used_at"]
        if not last_used or last_used <= (now - timedelta(seconds=TOUCH_S)).strftime(TOKEN_TIME):
            await conn.execute("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now.strftime(TOKEN_TIME), row["id"]))
            await conn.commit()
        claim = _stored_roles(row["claims"])
        role = roles.cap(roles.role_of(row["method"], claim, settings), row["max_role"])
        scopes = await _zone_scopes(conn) if role in roles.SCOPED else []
    AUDIT_TOKEN.set((row["username"], token_label(row)))
    return {"username": row["username"], "name": row["display_name"] or row["username"], "method": row["method"], "role": role,
            "subject": row["subject"], "zones": roles.zones_of(role, claim, scopes), "api_token": {"id": row["id"], "name": row["name"]}}


async def session_claims(request: Request) -> list[str]:
    """The app roles the session of request's cookie stored at its login (what an API token created in it copies); [] without one."""
    token = request.cookies.get(COOKIE)
    if not token:
        return []
    async with db() as conn:
        async with conn.execute("SELECT claims FROM sessions WHERE token = ?", (token_hash(token),)) as cur:
            row = await cur.fetchone()
    return _stored_roles(row["claims"]) if row else []


async def create_token(user: dict, claims: list[str], name: str, days: int, max_role: str | None) -> dict:
    """A new API token of user (as current_user returns it) named name, good for days days, capped at max_role (None: the role of
    its user), with claims, the app roles of the session it is created in: {"id", "name", "token", "expires_at", "max_role"}, the
    one answer that ever holds the token (the table keeps its token_hash). Every token expires; there is none without expires_at.
    Counts, checks the name and inserts in one write transaction (BEGIN IMMEDIATE), so two at once cannot pass the limits:
    TokenLimit when user's subject has TOKENS_PER_USER tokens, TokenNameTaken when it has one named name; nothing is stored then."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    created, expires = now.strftime(TOKEN_TIME), (now + timedelta(days=days)).strftime(TOKEN_TIME)
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute("SELECT name FROM api_tokens WHERE subject = ?", (user["subject"],)) as cur:
            names = [r["name"] for r in await cur.fetchall()]
        if len(names) >= TOKENS_PER_USER or name in names:
            await conn.rollback()
            raise TokenLimit() if len(names) >= TOKENS_PER_USER else TokenNameTaken()
        cur = await conn.execute("INSERT INTO api_tokens(token_hash, name, username, display_name, method, subject, claims, max_role, "
                                 "created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                 (token_hash(token), name, user["username"], user["name"], user["method"], user["subject"],
                                  json.dumps({"roles": claims}), max_role, created, expires))
        await conn.commit()
    return {"id": cur.lastrowid, "name": name, "token": token, "expires_at": expires, "max_role": max_role}


async def list_tokens(subject: str | None) -> list[dict]:
    """The API tokens of subject (None: every one), newest first: id, name, username, display_name, max_role, created_at,
    expires_at, last_used_at and expired (expires_at before now: refused, until the hourly prune deletes it); never the hash."""
    where, args = ("WHERE subject = ?", (subject,)) if subject is not None else ("", ())
    async with db() as conn:
        async with conn.execute("SELECT id, name, username, display_name, max_role, created_at, expires_at, last_used_at FROM api_tokens "
                                f"{where} ORDER BY id DESC", args) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    now = _token_now()
    return [r | {"expired": r["expires_at"] < now} for r in rows]


async def revoke_token(tid: int, user: dict) -> dict | None:
    """Deletes API token tid if it is one of user's subject, or any as Admin: the deleted row (id, name, username, subject), None
    without such a token - someone else's is as unknown as a missing one. A script with it is refused from its next request on."""
    mine, args = ("", (tid,)) if user["role"] == roles.ADMIN else (" AND subject = ?", (tid, user["subject"]))
    async with db() as conn:
        async with conn.execute(f"DELETE FROM api_tokens WHERE id = ?{mine} RETURNING id, name, username, subject", args) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        await conn.commit()
    return rows[0] if rows else None


@functools.cache
def require(minimum: str) -> Callable:
    """The dependency of a route that needs at least the role minimum (one of roles.ORDER), one per role: the signed-in user
    (current_user, so 401 without a session and 403 for a write without the CSRF header, as before), 403 with roles.denial when
    their role is below minimum. It carries min_role, by which the route walk of the tests finds it. A role that is none of the four
    raises ValueError when the route is defined, not at its first request."""
    if minimum not in roles.ORDER:
        raise ValueError(f"unknown role {minimum!r}")

    async def dependency(user: dict = Depends(current_user)) -> dict:
        if not roles.at_least(user["role"], minimum):
            raise HTTPException(403, roles.denial(minimum, user["role"]))
        return user

    dependency.min_role = minimum
    return dependency


def cookie_secure(request: Request) -> bool:
    """Whether SwitchView's cookies get the Secure flag. COOKIE_SECURE=always: every time. auto: when the request came over https,
    by its own scheme or by the first value of X-Forwarded-Proto. Either signal can only add the flag: a forged
    "X-Forwarded-Proto: http" on an https request never takes it away. A forged "https" on a plain-http request only makes that
    client's browser drop its own cookies."""
    if settings.cookie_secure == "always":
        return True
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or forwarded == "https"
