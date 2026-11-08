"""SwitchView: Switches, Ports und VLANs ansehen und Ports aendern (Phase 2)."""
import asyncio
import logging
import math
import os
import re
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

import api_alerts
import api_approvals
import api_changes
import api_devices
import api_history
import api_settings
import api_switches
import api_tokens
import approvals
import auth
import bodylimit
import changes
import confirm
import roles
import throttle
import topology
from api_changes import DISABLED, PlanIn, PortChange, _change_out, _inventory, _make_plan, _plan_revert, _snmp_unwritable, _summary, needed_ops
from api_devices import UNKNOWN_PER_PORT, unknown_devices
from api_settings import SettingsIn
from api_switches import SECRET_FIELDS, SECRET_INPUTS, SECRET_ONLY_DIFF, SwitchIn, _public, _row, _validate, same_destination
from config import Settings, settings
from db import audit, init_db
from jobs import _schedule, scheduler
from topology import _links, _port_num, _vid_num, build_map, confirmed_endpoints, netmap, switch_keys

# The names that moved out of main into the routers, the netmap and the scheduler module (Phase 3, Task 11) and that the tests reach
# as main.X: main re-exports them (ruff takes a name listed here as used, F401)
__all__ = ["DISABLED", "PlanIn", "PortChange", "_change_out", "_inventory", "_make_plan", "_plan_revert", "_snmp_unwritable", "_summary",
           "needed_ops", "UNKNOWN_PER_PORT", "unknown_devices", "SettingsIn", "SECRET_FIELDS", "SECRET_INPUTS", "SECRET_ONLY_DIFF",
           "SwitchIn", "_public", "_row", "_validate", "same_destination", "_schedule", "scheduler", "_links", "_port_num", "_vid_num",
           "build_map", "confirmed_endpoints", "netmap", "switch_keys"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("switchview")
STATIC = os.path.join(os.path.dirname(__file__), "static")

# ── Single-Worker-Invariante ──────────────────────────────────────────────────
# SwitchView laeuft mit genau EINEM uvicorn-Worker (kein --workers, kein WEB_CONCURRENCY). Der Zustand liegt im Prozess:
# Scheduler (jobs.scheduler), Login-Ratelimit (_LOGIN), laufende Aenderungs-Tasks (api_changes._tasks) und die Locks je Switch
# fuer SSH (sshcli._locks) und Abfrage (poller._locks). Mehrere Worker haetten je ihren eigenen Satz: Jobs liefen mehrfach, das
# Ratelimit gaelte je Prozess, zwei Worker koennten gleichzeitig per SSH am selben Switch arbeiten (max. 5 Sessions),
# und der Start (lifespan) markiert die laufende Aenderung eines anderen Workers als abgebrochen.
# The SSO key cache is in-process as well (auth._jwks, its reload marks auth._jwks_refreshed and the marks of a failed fetch
# auth._jwks_failed): each worker would fetch from Microsoft and wait out the 30 s after a failed fetch on its own.
# The used SSO nonces are in-process as well (auth._used_nonces): another worker would accept a nonce this one has seen.
# The alert queue (alert_outbox) is delivered by a scheduler job: a second worker would send every message twice.
# The throttle of invalid API tokens is in-process as well (auth._TOKENS): each worker would count its own failures.


# The start warnings about SSO (check_startup_config): an open login gate, without and with the role mapping, and SSO without it
OPEN_TENANT = ("ENTRA_ALLOWED_ROLES und ENTRA_ALLOWED_GROUPS sind leer: jeder Benutzer des Tenants kann sich per SSO anmelden und "
               "alles ändern.")
OPEN_TENANT_READ = ("ENTRA_ALLOWED_ROLES und ENTRA_ALLOWED_GROUPS sind leer: jeder Benutzer des Tenants kann sich per SSO anmelden, "
                    "ohne zugeordnete App-Rolle mit der Rolle „Lesen“.")
NO_ROLE_MAPPING = ("ENTRA_ROLE_MAPPING ist aus: jeder SSO-Benutzer hat volle Rechte (Rolle „Admin“), wie vor den Rollen. Rollen aus "
                   "Entra: die App-Rollen aus ENTRA_ROLE_LESEN, ENTRA_ROLE_AENDERN, ENTRA_ROLE_FREIGEBEN und ENTRA_ROLE_ADMIN anlegen und "
                   "zuweisen, dann ENTRA_ROLE_MAPPING=on.")


def check_startup_config(s: Settings) -> list[str]:
    """Stops a start that cannot run safely (RuntimeError): a SECRET_KEY under 16 characters, a COOKIE_SECURE other than auto or
    always, an ENTRA_ROLE_MAPPING other than on or off, a negative IDLE_MINUTES or HISTORY_DAYS, a PUBLIC_URL that is set but not
    http(s)://<host>[/<path>]. Returns the warnings for the log: a SECRET_KEY under 32 characters or with fewer than 8 different
    characters is weak but only warned about (E16: changing it means entering every stored credential anew, a stop would shut out
    running installations). Likewise SSO with neither
    ENTRA_ALLOWED_ROLES nor ENTRA_ALLOWED_GROUPS: documented behaviour (every user of the tenant may sign in, auth.verify_id_token),
    so a warning, not a stop (OPEN_TENANT, with the role mapping OPEN_TENANT_READ); and SSO without the role mapping, where every SSO
    user is Admin as before the roles (NO_ROLE_MAPPING). No message contains the key."""
    if len(s.secret_key) < 16:
        raise RuntimeError("SECRET_KEY fehlt oder ist zu kurz")
    if s.cookie_secure not in ("auto", "always"):
        raise RuntimeError("COOKIE_SECURE muss auto oder always sein")
    if s.entra_role_mapping not in ("on", "off"):
        raise RuntimeError("ENTRA_ROLE_MAPPING muss on oder off sein")
    if s.idle_minutes < 0:
        raise RuntimeError("IDLE_MINUTES muss 0 oder größer sein")
    if s.history_days < 0:
        raise RuntimeError("HISTORY_DAYS muss 0 oder größer sein")
    if s.public_url and not re.fullmatch(r"https?://[^\s/]+(/\S*)?", s.public_url):
        raise RuntimeError("PUBLIC_URL muss mit http:// oder https:// beginnen")
    messages = []
    if len(s.secret_key) < 32 or len(set(s.secret_key)) < 8:
        messages.append("SECRET_KEY ist schwach (kürzer als 32 Zeichen oder weniger als 8 verschiedene Zeichen). Ein neuer Schlüssel "
                        "(z. B. openssl rand -hex 32) macht die gespeicherten Zugangsdaten unlesbar: danach alle Zugangsdaten der Switches, "
                        "von PacketFence, OPNsense und RADIUS neu eingeben.")
    if s.sso_active and not s.entra_allowed_roles and not s.entra_allowed_groups:
        messages.append(OPEN_TENANT_READ if s.role_mapping_on else OPEN_TENANT)
    if s.sso_active and not s.role_mapping_on:
        messages.append(NO_ROLE_MAPPING)
    return messages


@asynccontextmanager
async def lifespan(app: FastAPI):
    for warning in check_startup_config(settings):
        log.warning(warning)
    await init_db()
    await auth.prune_sessions()    # expired sessions of before the start; the scheduler prunes hourly from here on
    await changes.mark_interrupted()    # changes the last process left queued or running: aborted if nothing went out, else unclear
    await _schedule()
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


SSO_ORIGIN = "https://login.microsoftonline.com"    # the Entra authority host of MSAL's loginPopup (sv-core.js)


def content_security_policy(sso: bool) -> str:
    """The Content-Security-Policy of every answer: nothing but SwitchView itself, with SSO also SSO_ORIGIN for MSAL's fetches."""
    # style-src-attr 'unsafe-inline': computed style attributes (VLAN colour, widths) run no script; SSO only connect-src: MSAL fetches, its popup navigates
    return "; ".join(["default-src 'none'", "script-src 'self'", "style-src 'self'", "style-src-attr 'unsafe-inline'", "img-src 'self'",
                      "font-src 'self'", "connect-src 'self'" + (" " + SSO_ORIGIN if sso else ""), "form-action 'self'",
                      "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"])


app = FastAPI(title="SwitchView", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
# Both added before the security_headers decorator below, so that one wraps them and the 413 and every compressed answer carry the
# same headers as every answer.
app.add_middleware(bodylimit.BodyLimit)
# gzip for answers from 4 KiB (smaller ones do not pay), at level 1 instead of Starlette's default 9: /api/netmap is 10 MB at 300
# switches (34 MB at 1000) and shrinks to about a ninth in about 50 ms (150 ms); level 9 is a fifth smaller still but holds the single
# worker 0.4 s (1.3 s) per answer. Inside security_headers, not around it: that one (a BaseHTTPMiddleware) passes every body on as
# a stream of chunks, and GZipMiddleware compresses a stream whatever its size (minimum_size holds only for a body in one piece).
app.add_middleware(GZipMiddleware, minimum_size=4096, compresslevel=1)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = content_security_policy(settings.sso_active)
    return resp


# ── Statische Dateien ─────────────────────────────────────────────────────────
# index.html is no-store. Scripts, CSS, the icon and the fonts are no-cache with an ETag: the browser asks on every page load, an
# unchanged file costs a 304 instead of a full download, and an update reaches every browser without a hard reload. Starlette's
# FileResponse sets the ETag (from mtime and size) but never answers 304 itself, so _static_file compares If-None-Match.
STATIC_TYPES = {"js": "text/javascript", "css": "text/css", "svg": "image/svg+xml", "woff2": "font/woff2"}


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-store"})


def _static_file(path: str, request: Request) -> Response:
    """The file at path (404 if there is none) as no-cache with its ETag, typed by its extension (STATIC_TYPES); a 304 without a body
    when If-None-Match names that ETag. If-None-Match is a comma list; each entry counts without surrounding space and without a W/
    prefix (the weak comparison RFC 9110 asks for here)."""
    if not os.path.isfile(path):
        raise HTTPException(404)
    resp = FileResponse(path, stat_result=os.stat(path), media_type=STATIC_TYPES[path.rsplit(".", 1)[1]],
                        headers={"Cache-Control": "no-cache"})
    etag = resp.headers["etag"]
    if etag in (tag.strip().removeprefix("W/") for tag in request.headers.get("if-none-match", "").split(",")):
        return Response(status_code=304, headers={"ETag": etag, "Cache-Control": "no-cache"})
    return resp


@app.get("/static/{name}", include_in_schema=False)
async def static(name: str, request: Request):
    if not re.fullmatch(r"[\w.\-]+\.(js|css|svg)", name):
        raise HTTPException(404)
    return _static_file(os.path.join(STATIC, name), request)


@app.get("/static/fonts/{name}", include_in_schema=False)
async def static_font(name: str, request: Request):
    """Only the .woff2 files of app/static/fonts; OFL.txt lies next to them for the image but is not served."""
    if not re.fullmatch(r"[\w.\-]+\.woff2", name):
        raise HTTPException(404)
    return _static_file(os.path.join(STATIC, "fonts", name), request)


# ── Anmeldung ─────────────────────────────────────────────────────────────────
# Failed emergency logins count per identity (F1), never per client address: an address is forged with X-Forwarded-For or shared
# behind a proxy. Every attempt without a valid device cookie shares the key "local"; a browser in which the emergency login succeeded
# once carries a device cookie (auth.device_token) and counts under its own key, so an attacker hammering "local" cannot lock it out.
# SSO is not throttled: an id_token cannot be guessed, and auth bounds what a bad one costs (JWKS reloads).
_LOGIN = throttle.LoginThrottle()


def _set_cookie(resp: Response, request: Request, name: str, value: str, max_age: int):
    """The one place that sets a cookie of SwitchView: httponly, SameSite=Lax, path /, Secure as COOKIE_SECURE says (auth.cookie_secure)."""
    resp.set_cookie(name, value, httponly=True, samesite="lax", secure=auth.cookie_secure(request), max_age=max_age, path="/")


@app.get("/api/auth/config")
async def auth_config():
    return {"sso": settings.sso_active, "tenant": settings.entra_tenant_id, "client_id": settings.entra_client_id,
            "local": settings.local_login_active}


class LocalLogin(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=200)


@app.post("/api/auth/local")
async def login_local(body: LocalLogin, request: Request, response: Response):
    dev = auth.device_id(request.cookies.get(auth.DEVICE_COOKIE), body.username)
    keys = [f"dev:{dev}"] if dev else ["local"]
    if _LOGIN.blocked(keys):
        raise HTTPException(429, "Zu viele Anmeldeversuche, bitte eine Minute warten")
    if not auth.check_local(body.username, body.password):
        _LOGIN.fail(keys)
        await audit(body.username, "login_failed", "local", role=None)    # no session, no role
        raise HTTPException(401, "Benutzername oder Kennwort falsch")
    token = await auth.create_session(body.username, body.username, "local", subject=f"local:{body.username}")
    _set_cookie(response, request, auth.COOKIE, token, settings.session_hours * 3600)
    _set_cookie(response, request, auth.DEVICE_COOKIE, auth.device_token(body.username), auth.DEVICE_DAYS * 86400)
    await audit(body.username, "login", "local", role=roles.role_of("local", [], settings))
    return {"ok": True}


# The 401 of an id_token without the nonce of this browser's login attempt (auth.check_nonce): too old, used, another browser's, or a
# login page from before the nonce, whose script asks for none
NONCE_FAILED = ("Anmeldung über Microsoft fehlgeschlagen: der Anmeldeversuch ist abgelaufen oder wurde schon benutzt – bitte erneut "
                "anmelden")


@app.post("/api/auth/nonce")
async def login_nonce(request: Request, response: Response):
    """A new SSO login attempt (sv-core.js, before MSAL's loginPopup): the nonce for the id_token, its binding value in the cookie
    auth.LOGIN_COOKIE. Public, like the logins; a new attempt in the same browser replaces the one before (one cookie per browser)."""
    if not settings.sso_active:
        raise HTTPException(400, "SSO ist nicht eingerichtet")
    nonce, binding = auth.issue_nonce()
    _set_cookie(response, request, auth.LOGIN_COOKIE, binding, auth.NONCE_TTL_S)
    return {"nonce": nonce}


class AzureLogin(BaseModel):
    id_token: str = Field(max_length=20000)


@app.post("/api/auth/azure")
async def login_azure(body: AzureLogin, request: Request, response: Response):
    if not settings.sso_active:
        raise HTTPException(400, "SSO ist nicht eingerichtet")
    try:  # in a thread: a JWKS fetch from Microsoft blocks
        claims = await asyncio.to_thread(auth.verify_id_token, body.id_token)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except auth.TOKEN_ERRORS as e:    # an expected refusal (bad token, JWKS unreachable): one line, no traceback (a flood fills no log)
        log.warning("Anmeldung über Microsoft abgelehnt: %s", e)
        # Microsoft unreachable (this fetch, or the cooldown after one): the login page says to wait; any other reason stays unnamed
        jwks_down = str(e) == auth.JWKS_DOWN or isinstance(e, auth.jwt.PyJWKClientConnectionError)
        raise HTTPException(401, auth.JWKS_DOWN if jwks_down else "Anmeldung über Microsoft fehlgeschlagen")
    except Exception:  # noqa: BLE001
        log.exception("id_token ungültig")
        raise HTTPException(401, "Anmeldung über Microsoft fehlgeschlagen")
    try:  # only a token that passed the checks above: a forged one never takes a nonce out of use
        auth.check_nonce(claims.get("nonce"), request.cookies.get(auth.LOGIN_COOKIE))
    except ValueError as e:
        log.warning("Anmeldung über Microsoft abgelehnt: %s", e)
        raise HTTPException(401, NONCE_FAILED)
    user = claims.get("preferred_username") or claims.get("upn") or claims.get("email") or claims["sub"]
    # The roles claim for the role of every request of this session; the object id (stable across apps of the tenant; without it the
    # sub, stable per app) for the person, whatever the user name
    app_roles = auth.claim_roles(claims)
    token = await auth.create_session(user, claims.get("name") or user, "entra", roles=app_roles,
                                      subject="entra:" + str(claims.get("oid") or claims["sub"]))
    _set_cookie(response, request, auth.COOKIE, token, settings.session_hours * 3600)
    response.delete_cookie(auth.LOGIN_COOKIE, path="/")
    await audit(user, "login", "entra", role=roles.role_of("entra", app_roles, settings))    # the role of the new session
    return {"ok": True}


@app.get("/api/auth/me")
async def me(user=Depends(auth.require(roles.LESEN))):
    """The signed-in user for the page: name, role, zones, the idle limit, whether the four-eyes principle is on (approvals.policy)
    and the name of the API token a request was made with (Phase 4c; null for a session); not the subject (it is for the server's
    comparisons)."""
    return {"username": user["username"], "name": user["name"], "method": user["method"], "role": user["role"], "zones": user["zones"],
            "idle_minutes": settings.idle_minutes, "four_eyes": (await approvals.policy())["four_eyes"],
            "api_token": user["api_token"]["name"] if user["api_token"] else None}


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get(auth.COOKIE)
    if token:
        await auth.drop_session(token)
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@app.post("/api/auth/logout-all")
async def logout_all(response: Response, user=Depends(auth.require(roles.LESEN))):
    """Ends every session of the signed-in user on every device, this one too: the lever when a session must end now (A3). Through
    current_user, so it needs the CSRF header like every other write; any role, and only the user's own sessions."""
    ended = await auth.drop_user_sessions(user["username"])
    response.delete_cookie(auth.COOKIE, path="/")
    await audit(user["username"], "logout_all", "", f"Sitzungen beendet: {ended}", role=user["role"])
    return {"ok": True, "ended": ended}


def _without_secrets(value):
    """value ohne die Schluessel aus SECRET_INPUTS, auch in verschachtelten dicts und Listen."""
    if isinstance(value, dict):
        return {k: _without_secrets(v) for k, v in value.items() if k not in SECRET_INPUTS}
    if isinstance(value, list):
        return [_without_secrets(v) for v in value]
    return value


# A lone surrogate: a JSON string can escape one ("\ud800"), UTF-8 cannot encode it.
_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _renderable(value):
    """value as a JSON answer can carry it, in dicts (keys too) and lists as well: a float that is not finite as its text (Python's json
    reads NaN and Infinity, JSON has neither), a lone surrogate as U+FFFD. Without this a 422 that echoes such an input failed to
    render: a 500 with a traceback in the log, for any client."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, str):
        return _SURROGATE.sub("\ufffd", value)
    if isinstance(value, dict):
        return {_renderable(k): _renderable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_renderable(v) for v in value]
    return value


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    """FastAPI's default 422 ({"detail": [errors]}) without an echoed secret, for the whole app: an error AT a field in SECRET_INPUTS
    loses "input" and "ctx" (type, loc and msg stay). An error at the whole body (loc just "body") whose input is no object loses that
    input: a list or a scalar can hold anything. Any other "input" loses the keys in SECRET_INPUTS, nested ones too, since a "missing"
    error carries the whole body. Everything else stays as FastAPI has it, made renderable (_renderable)."""
    errors = []
    for err in exc.errors():
        err = dict(err)
        loc = err.get("loc") or ()
        if any(isinstance(part, str) and part in SECRET_INPUTS for part in loc):
            err.pop("input", None)
            err.pop("ctx", None)
        elif "input" in err:
            if len(loc) <= 1 and not isinstance(err["input"], dict):
                del err["input"]
            elif isinstance(err["input"], (dict, list)):
                err["input"] = _without_secrets(err["input"])
        errors.append(err)
    return JSONResponse(status_code=422, content={"detail": _renderable(jsonable_encoder(errors))})


# The API routers split out of main (Phase 3, Task 11), in the order their sections had there
app.include_router(api_switches.router)
app.include_router(api_settings.router)
app.include_router(api_changes.router)
app.include_router(api_devices.router)
app.include_router(topology.router)
app.include_router(api_approvals.router)    # Phase 4a, Task 6
app.include_router(api_history.router)    # Phase 4b
app.include_router(api_alerts.router)    # Phase 4b, Task 6
app.include_router(api_tokens.router)    # Phase 4c, Task 2
app.include_router(confirm.router)    # Phase 4c, Task 4
