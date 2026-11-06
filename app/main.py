"""SwitchView: Switches, Ports und VLANs ansehen und Ports aendern (Phase 2)."""
import asyncio
import difflib
import ipaddress
import json
import logging
import math
import os
import re
import sqlite3
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

import auth
import bodylimit
import cfgparse
import changes
import drivers
import names as names_mod
import pf
import poller
import snmp
import snmpwrite
import sshcli
import throttle
from config import Settings, settings
from crypto import encrypt, unreadable
from db import audit, db, get_setting, init_db, load_settings, read_settings, write_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("switchview")
STATIC = os.path.join(os.path.dirname(__file__), "static")
scheduler = AsyncIOScheduler(timezone="Europe/Berlin")

# ── Single-Worker-Invariante ──────────────────────────────────────────────────
# SwitchView laeuft mit genau EINEM uvicorn-Worker (kein --workers, kein WEB_CONCURRENCY). Der Zustand liegt im Prozess:
# Scheduler, Login-Ratelimit (_LOGIN), laufende Aenderungs-Tasks (_tasks) und die Locks je Switch fuer SSH
# (sshcli._locks) und Abfrage (poller._locks). Mehrere Worker haetten je ihren eigenen Satz: Jobs liefen mehrfach, das
# Ratelimit gaelte je Prozess, zwei Worker koennten gleichzeitig per SSH am selben Switch arbeiten (max. 5 Sessions),
# und der Start (lifespan) markiert die laufende Aenderung eines anderen Workers als abgebrochen.
# The SSO key cache is in-process as well (auth._jwks, its reload marks auth._jwks_refreshed and the marks of a failed fetch
# auth._jwks_failed): each worker would fetch from Microsoft and wait out the 30 s after a failed fetch on its own.


async def _schedule():
    minutes = int(await get_setting("poll_minutes", "15") or 15)
    scheduler.add_job(poller.poll_all, "interval", minutes=max(5, minutes), id="poll", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(names_mod.refresh_names, "interval", minutes=15, id="names", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(sshcli.backup_all, "cron", hour=2, minute=30, id="backup", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(pf.expire_and_sync, "cron", hour=3, minute=15, id="pf_sync", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(auth.prune_sessions, "interval", minutes=60, id="sessions", replace_existing=True, max_instances=1, coalesce=True)


def check_startup_config(s: Settings) -> list[str]:
    """Stops a start that cannot run safely (RuntimeError): a SECRET_KEY under 16 characters, a COOKIE_SECURE other than auto or
    always. Returns the warnings for the log: a SECRET_KEY under 32 characters or with fewer than 8 different characters is weak but
    only warned about (E16: changing it means entering every stored credential anew, a stop would shut out running installations).
    Likewise SSO with neither ENTRA_ALLOWED_ROLES nor ENTRA_ALLOWED_GROUPS: documented behaviour (every user of the tenant may sign
    in, auth.verify_id_token), so a warning, not a stop. No message contains the key."""
    if len(s.secret_key) < 16:
        raise RuntimeError("SECRET_KEY fehlt oder ist zu kurz")
    if s.cookie_secure not in ("auto", "always"):
        raise RuntimeError("COOKIE_SECURE muss auto oder always sein")
    messages = []
    if len(s.secret_key) < 32 or len(set(s.secret_key)) < 8:
        messages.append("SECRET_KEY ist schwach (kürzer als 32 Zeichen oder weniger als 8 verschiedene Zeichen). Ein neuer Schlüssel "
                        "(z. B. openssl rand -hex 32) macht die gespeicherten Zugangsdaten unlesbar: danach alle Zugangsdaten der Switches, "
                        "von PacketFence, OPNsense und RADIUS neu eingeben.")
    if s.sso_active and not s.entra_allowed_roles and not s.entra_allowed_groups:
        messages.append("ENTRA_ALLOWED_ROLES und ENTRA_ALLOWED_GROUPS sind leer: jeder Benutzer des Tenants kann sich per SSO anmelden und "
                        "alles ändern.")
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


app = FastAPI(title="SwitchView", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
# Added before the security_headers decorator below, so that one wraps it and the 413 carries the same headers as every answer.
app.add_middleware(bodylimit.BodyLimit)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


# ── Statische Dateien ─────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-store"})


@app.get("/static/{name}", include_in_schema=False)
async def static(name: str):
    if not re.fullmatch(r"[\w.\-]+\.(js|css|svg)", name):
        raise HTTPException(404)
    path = os.path.join(STATIC, name)
    if not os.path.isfile(path):
        raise HTTPException(404)
    return FileResponse(path, headers={"Cache-Control": "no-cache"})


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
        await audit(body.username, "login_failed", "local")
        raise HTTPException(401, "Benutzername oder Kennwort falsch")
    token = await auth.create_session(body.username, body.username, "local")
    _set_cookie(response, request, auth.COOKIE, token, settings.session_hours * 3600)
    _set_cookie(response, request, auth.DEVICE_COOKIE, auth.device_token(body.username), auth.DEVICE_DAYS * 86400)
    await audit(body.username, "login", "local")
    return {"ok": True}


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
        raise HTTPException(401, "Anmeldung über Microsoft fehlgeschlagen")
    except Exception:  # noqa: BLE001
        log.exception("id_token ungültig")
        raise HTTPException(401, "Anmeldung über Microsoft fehlgeschlagen")
    user = claims.get("preferred_username") or claims.get("upn") or claims.get("email") or claims["sub"]
    token = await auth.create_session(user, claims.get("name") or user, "entra")
    _set_cookie(response, request, auth.COOKIE, token, settings.session_hours * 3600)
    await audit(user, "login", "entra")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(user=Depends(auth.current_user)):
    return user


@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get(auth.COOKIE)
    if token:
        await auth.drop_session(token)
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@app.post("/api/auth/logout-all")
async def logout_all(response: Response, user=Depends(auth.current_user)):
    """Ends every session of the signed-in user on every device, this one too: the lever when a session must end now (A3). Through
    current_user, so it needs the CSRF header like every other write."""
    ended = await auth.drop_user_sessions(user["username"])
    response.delete_cookie(auth.COOKIE, path="/")
    await audit(user["username"], "logout_all", "", f"Sitzungen beendet: {ended}")
    return {"ok": True, "ended": ended}


# ── Switches verwalten ───────────────────────────────────────────────────────
NAME_RE = r"^[\w .\-+()/]{1,64}$"


class SwitchIn(BaseModel):
    """Body von POST und PUT /api/switches. Geheimnisse (SECRET_FIELDS): None = unveraendert, "" = loeschen. Die Felder in
    UPDATE_IF_SENT aendert ein PUT nur, wenn er sie mitschickt."""
    name: str = Field(pattern=NAME_RE)
    host: str = Field(max_length=64)
    zone: str = Field(default="", max_length=40)
    sort: int = 0
    enabled: bool = True
    snmp_version: str = Field(default="2c", pattern=r"^(2c|3)$")
    snmp_community: str | None = Field(default=None, max_length=64)
    snmp_user: str | None = Field(default=None, max_length=64)
    snmp_auth_proto: str | None = None
    snmp_auth_pass: str | None = Field(default=None, max_length=128)
    snmp_priv_proto: str | None = None
    snmp_priv_pass: str | None = Field(default=None, max_length=128)
    ssh_user: str | None = Field(default=None, max_length=64)
    ssh_pass: str | None = Field(default=None, max_length=128)
    # Treiber und SNMP-Schreibweg. Die eigene Schreib-Identitaet snmp_rw_* gilt nur mit snmp_write; welche Identitaet schreibt,
    # entscheidet allein poller.write_identity.
    driver: str = Field(default="procurve", max_length=32)
    snmp_write: bool = False
    snmp_rw_community: str | None = Field(default=None, max_length=64)
    snmp_rw_user: str | None = Field(default=None, max_length=64)
    snmp_rw_auth_proto: str | None = None
    snmp_rw_auth_pass: str | None = Field(default=None, max_length=128)
    snmp_rw_priv_proto: str | None = None
    snmp_rw_priv_pass: str | None = Field(default=None, max_length=128)


# Alle Geheimnis-Spalten von switches: verschluesselt abgelegt, nie ausgeliefert (nur als *_set), im Audit beim Namen genannt.
SECRET_FIELDS = ("snmp_community", "snmp_auth_pass", "snmp_priv_pass", "ssh_pass", "snmp_rw_community", "snmp_rw_auth_pass",
                 "snmp_rw_priv_pass")
# Felder, die erst mit dem SNMP-Schreibweg kamen: ein PUT ohne sie laesst sie stehen. Das Switch-Formular von vorher kennt sie nicht und
# setzte sonst bei jedem Speichern den Treiber auf procurve zurueck, schaltete SNMP-Schreiben ab und loeschte den RW-Benutzer (der
# Schreibweg fiele damit still auf die Lese-Identitaet zurueck). Mitgeschickt gilt wie bei den alten Feldern: null bzw. "" = leer.
UPDATE_IF_SENT = ("driver", "snmp_write", "snmp_rw_user", "snmp_rw_auth_proto", "snmp_rw_priv_proto")
# Was GET /api/switches von einer Zeile ausliefert, als ALLOWLIST: eine neue Spalte erscheint erst, wenn sie hier steht. Geheimnisse
# (SECRET_FIELDS) stehen nie hier, von ihnen liefert _public nur das *_set-Flag.
PUBLIC_FIELDS = ("id", "name", "host", "zone", "sort", "enabled", "snmp_version", "snmp_user", "snmp_auth_proto", "snmp_priv_proto",
                 "ssh_user", "sys_name", "sys_descr", "model", "firmware", "base_mac", "uptime", "last_poll", "last_poll_ok", "last_error",
                 "created_at", "driver", "snmp_rw_user", "snmp_rw_auth_proto", "snmp_rw_priv_proto")
# Hostname: das erste Zeichen kein "-" (und kein "."). net-snmp bekommt den Host als eigenes Argument und laese "-..." als Option.
HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]{0,63}")
# The zone id of an IPv6 address (fe80::1%eth0) as an interface name: 15 characters at most (IFNAMSIZ - 1 on Linux), no whitespace and
# no line break. The host lands in the known_hosts line of sshcli._open, which such a character would end.
ZONE_RE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
ZONE_INVALID = "Zonen-Angabe der Adresse ungültig (erlaubt: Buchstaben, Ziffern, . _ -, höchstens 15 Zeichen)"
# Felder einer Anfrage, deren Wert eine 422-Antwort nie zuruecksendet (pydantic legt ihn in "input" ab): die Geheimnisse der Switches
# und die der anderen Formulare (Anmeldung, Einstellungen).
SECRET_INPUTS = frozenset(SECRET_FIELDS) | {"password", "id_token", "opnsense_key", "opnsense_secret", "radius_key", "pf_pass"}


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


# The SNMP credential fields, read and RW identity. Their secrets travel in a line of a snmp.conf (snmp._conf_lines, R45), which a
# NUL, CR or LF would end: such a value is refused here, before it is stored (snmp refuses one stored before, too).
SNMP_CREDENTIAL_FIELDS = ("snmp_community", "snmp_user", "snmp_auth_pass", "snmp_priv_pass", "snmp_rw_community", "snmp_rw_user",
                          "snmp_rw_auth_pass", "snmp_rw_priv_pass")


def _validate(body: SwitchIn):
    try:
        ip = ipaddress.ip_address(body.host)
    except ValueError:
        if not HOST_RE.fullmatch(body.host):
            raise HTTPException(422, "Adresse ist weder IP noch gültiger Hostname")
    else:
        zone = getattr(ip, "scope_id", None)    # ip_address takes any text after "%", whitespace and line breaks included
        if zone is not None and not ZONE_RE.fullmatch(zone):
            raise HTTPException(422, ZONE_INVALID)
    if body.driver not in drivers.DRIVERS:
        raise HTTPException(422, "Unbekannter Treiber")
    for proto in (body.snmp_auth_proto, body.snmp_rw_auth_proto):
        if proto and proto not in snmp.AUTH_PROTOS:
            raise HTTPException(422, "Unbekanntes SNMP-Auth-Verfahren")
    for proto in (body.snmp_priv_proto, body.snmp_rw_priv_proto):
        if proto and proto not in snmp.PRIV_PROTOS:
            raise HTTPException(422, "Unbekanntes SNMP-Verschlüsselungsverfahren")
    if any(c in (getattr(body, k) or "") for k in SNMP_CREDENTIAL_FIELDS for c in snmp.CONF_FORBIDDEN):
        raise HTTPException(422, "SNMP-Zugangsdaten dürfen keine Zeilenumbrüche oder Nullzeichen enthalten")


def _columns(body: SwitchIn, update: bool) -> dict:
    """Die Spalten ohne Geheimnisse, wie POST (alle) und PUT (UPDATE_IF_SENT nur, wenn mitgeschickt) sie schreiben."""
    cols = {"name": body.name, "host": body.host, "zone": body.zone, "sort": body.sort, "enabled": int(body.enabled),
            "snmp_version": body.snmp_version, "snmp_user": body.snmp_user or None, "snmp_auth_proto": body.snmp_auth_proto or None,
            "snmp_priv_proto": body.snmp_priv_proto or None, "ssh_user": body.ssh_user or None, "driver": body.driver,
            "snmp_write": int(body.snmp_write), "snmp_rw_user": body.snmp_rw_user or None,
            "snmp_rw_auth_proto": body.snmp_rw_auth_proto or None, "snmp_rw_priv_proto": body.snmp_rw_priv_proto or None}
    if update:
        for k in UPDATE_IF_SENT:
            if k not in body.model_fields_set:
                del cols[k]
    return cols


def _on_off(value) -> str:
    return "an" if value else "aus"


# Fields without a secret that decide which identity SNMP SETs go out with (poller.write_identity): the RW user and its protocols,
# without an RW user the read identity (snmp_version, snmp_user, and its protocols, R48: audited always, not only while the read
# identity writes, so switching the writing identity leaves no gap). The audit records each change with its values.
IDENTITY_FIELDS = ("snmp_rw_user", "snmp_rw_auth_proto", "snmp_rw_priv_proto", "snmp_version", "snmp_user", "snmp_auth_proto",
                   "snmp_priv_proto")


def _update_detail(fields: dict, old) -> str:
    """The audit detail of a PUT: a new host first ("host: old → new"), then the changed secrets by name, never with a value (one that
    the new host deleted counts as changed), then driver, SNMP writing and the identity fields (IDENTITY_FIELDS) as "old → new"
    (empty: "–") when they were sent and change. Switching SNMP writing on is a privilege change, and whoever writes without an RW
    user depends on the read identity."""
    parts = [f"host: {old['host']} → {fields['host']}"] if fields["host"] != old["host"] else []
    parts += [k for k in fields if k in SECRET_FIELDS]
    if "driver" in fields and fields["driver"] != old["driver"]:
        parts.append(f"driver: {old['driver']} → {fields['driver']}")
    if "snmp_write" in fields and bool(fields["snmp_write"]) != bool(old["snmp_write"]):
        parts.append(f"snmp_write: {_on_off(old['snmp_write'])} → {_on_off(fields['snmp_write'])}")
    for k in IDENTITY_FIELDS:
        if k in fields and (fields[k] or None) != (old[k] or None):
            parts.append(f"{k}: {old[k] or '–'} → {fields[k] or '–'}")
    return ", ".join(parts)


def _write_info(row) -> dict:
    """Mit welcher Identitaet SNMP-SETs an diesen Switch gingen, ohne ein Geheimnis, aus poller.write_identity: snmp_write_via "rw"
    (die eigene RW-Identitaet) oder "read" (die Lese-Identitaet, sie muss am Geraet schreiben duerfen), sonst None und der Grund in
    snmp_write_error; snmp_rw_insecure, wenn der SET faelschbar hinausginge (v2c-Community im Klartext, v3 ohne Authentifizierung)."""
    try:
        via, cred = poller.write_identity(row)
    except snmp.SnmpError as e:
        return {"snmp_write_via": None, "snmp_write_error": str(e), "snmp_rw_insecure": False}
    insecure = cred["snmp_version"] != "3" or not (cred["snmp_auth_proto"] and cred["snmp_auth_pass"])
    return {"snmp_write_via": via, "snmp_write_error": None, "snmp_rw_insecure": insecure}


def _public(row) -> dict:
    d = {k: row[k] for k in PUBLIC_FIELDS}
    d["snmp_write"] = bool(row["snmp_write"])
    d["caps"] = sorted(drivers.driver_for(row).caps)
    for k in SECRET_FIELDS:
        d[k + "_set"] = bool(row[k])
    d.update(_write_info(row))
    # The pinned SSH host key by its fingerprints only (compared with the switch's own display), each None without a key
    fp = sshcli.fingerprints(row["ssh_host_key"])
    d["ssh_host_key_fp"], d["ssh_host_key_md5"] = (fp["sha256"], fp["md5"]) if fp else (None, None)
    d["ssh_host_key_at"] = row["ssh_host_key_at"] if fp else None
    d["cred_warnings"] = poller.credential_warnings(row)    # what the read path falls back to in silence, without a secret
    return d


@app.get("/api/drivers")
async def list_drivers(user=Depends(auth.current_user)):
    """Die Treiber fuer die Auswahl im Switch-Formular, in der Reihenfolge von drivers.DRIVERS: Name, Faehigkeiten (sortiert), Hinweise."""
    return [{"name": d.name, "caps": sorted(d.caps), "notes": d.notes} for d in drivers.DRIVERS.values()]


@app.get("/api/switches")
async def list_switches(user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT * FROM switches ORDER BY zone, sort, name") as cur:
            rows = await cur.fetchall()
    return [_public(r) for r in rows]


@app.post("/api/switches")
async def create_switch(body: SwitchIn, user=Depends(auth.current_user)):
    _validate(body)
    fields = _columns(body, update=False) | {k: encrypt(getattr(body, k)) for k in SECRET_FIELDS}
    async with db() as conn:
        try:
            cur = await conn.execute(f"INSERT INTO switches({', '.join(fields)}) VALUES ({', '.join('?' * len(fields))})",
                                     tuple(fields.values()))
        except Exception as e:  # noqa: BLE001
            if "UNIQUE" in str(e):
                raise HTTPException(409, "Ein Switch mit dieser Adresse existiert bereits")
            raise
        await conn.commit()
        sid = cur.lastrowid
    await audit(user["username"], "switch_create", body.host, f"{body.name}, driver: {body.driver}, snmp_write: {_on_off(body.snmp_write)}")
    return {"id": sid}


def same_destination(old: str | None, new: str | None) -> bool:
    """Whether old and new name the same destination of a secret (a switch's host, a URL or the RADIUS server of the settings): the
    same IP address when both parse as one, otherwise the same text ignoring case, surrounding whitespace and a trailing "/". Another
    spelling is no new destination (E9)."""
    try:
        return ipaddress.ip_address(old or "") == ipaddress.ip_address(new or "")
    except ValueError:
        return (old or "").strip().rstrip("/").casefold() == (new or "").strip().rstrip("/").casefold()


@app.put("/api/switches/{sid}")
async def update_switch(sid: int, body: SwitchIn, user=Depends(auth.current_user)):
    """A secret (SECRET_FIELDS) changes only when the PUT carries a value for it ("" deletes it), except that it is bound to the host
    it was entered for (F2): a new host (same_destination) deletes every stored secret the PUT does not carry anew, so none of them
    ever reaches the new host; "cleared" names them, in SECRET_FIELDS order. Reading the old row and writing the new one is one write
    transaction (BEGIN IMMEDIATE): a concurrent PUT waits, so the host rule and the audit's "old → new" see the row as it is (E11)."""
    _validate(body)
    fields = _columns(body, update=True)
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute(f"SELECT host, driver, snmp_write, {', '.join(IDENTITY_FIELDS + SECRET_FIELDS)} FROM switches WHERE id = ?",
                                (sid,)) as cur:
            old = await cur.fetchone()
        if not old:
            raise HTTPException(404, "Switch nicht gefunden")    # closing the connection rolls the transaction back
        moved, cleared = not same_destination(old["host"], body.host), []
        for k in SECRET_FIELDS:
            v = getattr(body, k)
            if v is not None:
                fields[k] = encrypt(v) if v != "" else None
            elif moved and old[k]:
                fields[k] = None
                cleared.append(k)
        sets = ", ".join(f"{k} = ?" for k in fields)
        try:
            await conn.execute(f"UPDATE switches SET {sets} WHERE id = ?", (*fields.values(), sid))
        except sqlite3.IntegrityError as e:    # the host of another switch (host is UNIQUE), as in create_switch
            if "UNIQUE" in str(e):
                raise HTTPException(409, "Ein Switch mit dieser Adresse existiert bereits")    # rolled back like the 404 above
            raise
        await conn.commit()
    await audit(user["username"], "switch_update", body.host, _update_detail(fields, old))
    return {"ok": True, "cleared": cleared}


@app.delete("/api/switches/{sid}")
async def delete_switch(sid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        cur = await conn.execute("DELETE FROM switches WHERE id = ?", (sid,))
        await conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "Switch nicht gefunden")
    await audit(user["username"], "switch_delete", str(sid))
    return {"ok": True}


@app.delete("/api/switches/{sid}/ssh-host-key")
async def forget_ssh_host_key(sid: int, user=Depends(auth.current_user)):
    """Forgets the pinned SSH host key of the switch: its next SSH contact pins the key it is then offered (E30). Only for a key that
    changed as expected (replacement, new firmware); the audit keeps the old SHA256."""
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute("SELECT host, ssh_host_key FROM switches WHERE id = ?", (sid,)) as cur:
            old = await cur.fetchone()
        if not old:
            raise HTTPException(404, "Switch nicht gefunden")    # closing the connection rolls the transaction back
        await conn.execute("UPDATE switches SET ssh_host_key = NULL, ssh_host_key_at = NULL WHERE id = ?", (sid,))
        await conn.commit()
    fp = sshcli.fingerprints(old["ssh_host_key"])
    await audit(user["username"], "switch_hostkey_reset", old["host"], fp["sha256"] if fp else "–")
    return {"ok": True}


async def _row(sid: int):
    async with db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Switch nicht gefunden")
    return row


def _cli_way(row, cap: str, what: str):
    """409, wenn der Treiber des Switches row die Faehigkeit cap (cli, backup) nicht hat: what gibt es nur ueber die SSH-CLI (R39).
    Darunter sperrt sshcli ohnehin jede Sitzung; hier bekommt die Anfrage ihren Grund, bevor etwas versucht wird."""
    driver = drivers.driver_for(row)
    if not drivers.can(driver, cap):
        raise HTTPException(409, f"{what} geht nur über die SSH-CLI (ProCurve), Treiber {driver.name} kann das nicht")


@app.post("/api/switches/{sid}/test")
async def test_switch(sid: int, user=Depends(auth.current_user)):
    row = await _row(sid)
    res = {}
    try:
        got = await snmp.get(row["host"], poller.creds_of(row), ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"])
        res["snmp"] = {"ok": bool(got), "detail": got.get("1.3.6.1.2.1.1.5.0", "")}
    except Exception as e:  # noqa: BLE001
        res["snmp"] = {"ok": False, "error": str(e)}
    res["ssh"] = await sshcli.test_ssh(row)
    res["warnings"] = poller.credential_warnings(row)
    return res


@app.post("/api/switches/{sid}/poll")
async def poll_now(sid: int, user=Depends(auth.current_user)):
    await _row(sid)
    return await poller.poll_switch(sid)


@app.post("/api/poll")
async def poll_everything(user=Depends(auth.current_user)):
    await poller.poll_all()
    return {"ok": True}


# ── Sicherungen ───────────────────────────────────────────────────────────────
@app.post("/api/switches/{sid}/backup")
async def backup_now(sid: int, user=Depends(auth.current_user)):
    _cli_way(await _row(sid), "backup", "Konfiguration sichern")
    res = await sshcli.backup_config(sid, "manual")
    await audit(user["username"], "backup", str(sid), json.dumps(res))
    return res


@app.get("/api/switches/{sid}/backups")
async def list_backups(sid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT id, taken_at, sha, trigger, length(content) AS size FROM config_backups WHERE switch_id = ? "
                                "ORDER BY id DESC LIMIT 200", (sid,)) as cur:
            return [dict(r) for r in await cur.fetchall()]


# A backup is served masked with today's patterns, also one stored before them; the stored rows stay as they are (E26)
@app.get("/api/backups/{bid}", response_class=PlainTextResponse)
async def get_backup(bid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT content FROM config_backups WHERE id = ?", (bid,)) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Sicherung nicht gefunden")
    return cfgparse.mask_secrets(row["content"])


# What the diff of a backup says when its masked text equals the one before: only what masking hides changed, a secret (sshcli.store_backup
# keeps such a backup, its raw_mac tells it apart)
SECRET_ONLY_DIFF = "Nur maskierte Geheimnisse haben sich geändert – der Vergleich zeigt sie nicht.\n"


@app.get("/api/backups/{bid}/diff", response_class=PlainTextResponse)
async def diff_backup(bid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT id, switch_id, taken_at, content FROM config_backups WHERE id = ?", (bid,)) as cur:
            cur_row = await cur.fetchone()
        if not cur_row:
            raise HTTPException(404, "Sicherung nicht gefunden")
        async with conn.execute("SELECT taken_at, content FROM config_backups WHERE switch_id = ? AND id < ? ORDER BY id DESC LIMIT 1",
                                (cur_row["switch_id"], bid)) as cur:
            prev = await cur.fetchone()
    if not prev:
        return "Erste Sicherung dieses Switches, kein Vergleich möglich.\n"
    before, after = cfgparse.mask_secrets(prev["content"]), cfgparse.mask_secrets(cur_row["content"])
    if before == after:
        return SECRET_ONLY_DIFF
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                        fromfile=f"vorher {prev['taken_at']} UTC", tofile=f"nachher {cur_row['taken_at']} UTC"))


# ── Einstellungen ─────────────────────────────────────────────────────────────
class SettingsIn(BaseModel):
    poll_minutes: int = Field(default=15, ge=5, le=1440)
    opnsense_url: str = Field(default="", max_length=200)
    opnsense_key: str | None = Field(default=None, max_length=200)
    opnsense_secret: str | None = Field(default=None, max_length=200)
    opnsense_verify_tls: bool = True    # E32: on for a new installation; a stored value stays what it is
    radius_server: str = Field(default="", max_length=45)
    radius_key: str | None = Field(default=None, max_length=64)
    pf_url: str = Field(default="", max_length=200)
    pf_user: str = Field(default="", max_length=100)
    pf_pass: str | None = Field(default=None, max_length=200)
    pf_verify_tls: bool = True


# The secrets of the settings by the destination each one is sent to (F2): a PUT that changes a destination deletes each of its stored
# secrets that it does not carry anew. The order is that of "cleared" in the answer.
DESTINATION_SECRETS: dict[str, tuple[str, ...]] = {"opnsense_url": ("opnsense_key", "opnsense_secret"), "radius_server": ("radius_key",),
                                                   "pf_url": ("pf_pass",)}


# The secrets of the settings in the order "unreadable" lists them (sorted)
SETTINGS_SECRETS = ("opnsense_key", "opnsense_secret", "pf_pass", "radius_key")


@app.get("/api/settings")
async def get_settings(user=Depends(auth.current_user)):
    """The settings without a secret: of each secret only *_set, and in "unreadable" those stored that do not decrypt (SECRET_KEY
    changed?), so the view asks for them anew. One SELECT (db.load_settings)."""
    s = await load_settings(["poll_minutes", "opnsense_url", "opnsense_verify_tls", "radius_server", "pf_url", "pf_user", "pf_verify_tls",
                             *SETTINGS_SECRETS])
    return {"poll_minutes": int(s["poll_minutes"] or 15),
            "opnsense_url": s["opnsense_url"] or "",
            "opnsense_key_set": bool(s["opnsense_key"]),
            "opnsense_secret_set": bool(s["opnsense_secret"]),
            "opnsense_verify_tls": (s["opnsense_verify_tls"] or "1") == "1",
            "radius_server": s["radius_server"] or "",
            "radius_key_set": bool(s["radius_key"]),
            "pf_url": s["pf_url"] or "",
            "pf_user": s["pf_user"] or "",
            "pf_pass_set": bool(s["pf_pass"]),
            "pf_verify_tls": (s["pf_verify_tls"] or "1") == "1",
            "unreadable": sorted(k for k in SETTINGS_SECRETS if unreadable(s[k]))}


@app.put("/api/settings")
async def put_settings(body: SettingsIn, user=Depends(auth.current_user)):
    """A secret changes only when the PUT carries a value for it ("" deletes it), except that it is bound to its destination (F2,
    DESTINATION_SECRETS): a new destination (same_destination) deletes each of its stored secrets the PUT does not carry anew;
    "cleared" names them. One write transaction as in update_switch. The RADIUS server is stored canonical and without a zone id
    (§6 (a)): it lands in a CLI line on every switch prepared for RADIUS. The audit names each destination whose stored text changes
    ("old → new") and what the change deleted."""
    if body.opnsense_url and not re.fullmatch(r"https?://[A-Za-z0-9.\-:]+(/[\w\-./]*)?", body.opnsense_url):
        raise HTTPException(422, "OPNsense-Adresse ungültig")
    if body.pf_url and not re.fullmatch(r"https?://[A-Za-z0-9.\-:]+(/[\w\-./]*)?", body.pf_url):
        raise HTTPException(422, "PacketFence-Adresse ungültig")
    radius_server = body.radius_server
    if radius_server:
        try:
            ip = ipaddress.ip_address(radius_server)
        except ValueError:
            raise HTTPException(422, "RADIUS-Server muss eine IP-Adresse sein")
        if getattr(ip, "scope_id", None) is not None:
            raise HTTPException(422, "RADIUS-Server muss eine IP-Adresse ohne Zonen-Angabe sein")
        radius_server = str(ip)
    if body.radius_key and not changes.RADIUS_KEY_RE.fullmatch(body.radius_key):
        raise HTTPException(422, "Shared Secret: 8–64 Zeichen, ohne Leerzeichen, Anführungszeichen, Backslash, ? und ~ (die versteht die Switch-CLI nicht)")
    new = {"poll_minutes": str(body.poll_minutes), "opnsense_url": body.opnsense_url.rstrip("/"),
           "opnsense_verify_tls": "1" if body.opnsense_verify_tls else "0", "radius_server": radius_server,
           "pf_url": body.pf_url.rstrip("/"), "pf_user": body.pf_user, "pf_verify_tls": "1" if body.pf_verify_tls else "0"}
    secrets = [k for keys in DESTINATION_SECRETS.values() for k in keys]
    for k in secrets:
        v = getattr(body, k)
        if v is not None:
            new[k] = encrypt(v) if v else None
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        old = await read_settings(conn, [*DESTINATION_SECRETS, *secrets])
        changed, cleared = [], []
        for dest, keys in DESTINATION_SECRETS.items():
            if (old[dest] or "") != new[dest]:
                changed.append(f"{dest}: {old[dest] or '–'} → {new[dest] or '–'}")
            if not same_destination(old[dest], new[dest]):
                for k in keys:
                    if old[k] and getattr(body, k) is None:
                        new[k] = None
                        cleared.append(k)
        await write_settings(conn, new)
        await conn.commit()
    await _schedule()
    await audit(user["username"], "settings_update", "", ", ".join(changed + ([f"gelöscht: {', '.join(cleared)}"] if cleared else [])))
    return {"ok": True, "cleared": cleared}


@app.post("/api/names/refresh")
async def names_refresh(user=Depends(auth.current_user)):
    return await names_mod.refresh_names()


@app.get("/api/audit")
async def audit_log(user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT ts, username, action, target, detail FROM audit ORDER BY id DESC LIMIT 200") as cur:
            return [dict(r) for r in await cur.fetchall()]


# ── Aenderungen an Ports (Phase 2) ────────────────────────────────────────────
STATUS_LABEL = {"off": "Aus", "on": "An", "protected": "Protected", "known": "Bekannte Geräte", "radius": "RADIUS"}
# Portnamen auf dem SSH-Weg: ProCurve, streng, denn sie stehen in den CLI-Zeilen.
PORT_RE = re.compile(r"^[A-Za-z0-9/]{1,12}$")
# Portnamen auf dem SNMP-Weg: die jedes Herstellers (Gi1/0/1, ge-0/0/1, 1/1/1, Port-channel1, ...), ohne fuehrendes "-". SNMP setzt sie
# nie in einen Befehl ein (es schreibt auf ifIndex / Bridge-Port); der Port muss ausserdem im Live-Read stehen.
SNMP_PORT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$")
# Die Felder eines Ports, die der SSH-Weg plant (cfgparse.port_state). Ein before mit anderen (etwa pvid, R21, aus einer SNMP-Aenderung)
# nimmt er nicht zurueck.
SSH_FIELDS = frozenset(cfgparse.port_state({}, ""))
STALE = "Die Vorschau ist veraltet, bitte neu laden"
# A disabled switch gets no change in any mode (/plan and /apply): "Aktiv" means polled and backed up, the views do not show it
DISABLED = "Switch ist deaktiviert – Änderungen erst nach dem Aktivieren (Zugang bearbeiten)"
SSH_NEEDED = "Für Änderungen braucht der Switch einen SSH-Zugang (Zugang bearbeiten)"
NO_SSH = "für diesen Switch ist kein SSH-Zugang hinterlegt (Zugang bearbeiten)"
_tasks: set = set()


class PortChange(BaseModel):
    # "on" (R43): nur einschalten, 802.1X / MAC-Anmeldung unveraendert (changes.STATUS_ON); geht auf jedem Treiber, auch per SNMP
    status: str | None = Field(default=None, pattern=r"^(off|on|protected|known|radius)$")
    untagged: str | None = Field(default=None, pattern=r"^\d{1,4}$")
    tagged_add: list[str] = Field(default_factory=list, max_length=64)
    tagged_remove: list[str] = Field(default_factory=list, max_length=64)
    name: str | None = Field(default=None, max_length=64)
    limit: int | None = Field(default=None, ge=1, le=32)
    guest: str | None = Field(default=None, pattern=r"^\d{0,4}$")
    # PoE an (true) / aus (false), nur per SNMP (R30). strict: nur JSON true / false, kein "yes", 1 oder "off", das jemand anders meinen kann
    poe: bool | None = Field(default=None, strict=True)


class PlanIn(BaseModel):
    mode: str = Field(default="ports", pattern=r"^(ports|prepare|revert|save)$")
    ports: list[str] = Field(default_factory=list, max_length=200)
    change: PortChange = Field(default_factory=PortChange)
    expert: bool = False
    of: int | None = None
    token: str | None = Field(default=None, max_length=32)
    # Der Schreibweg der Vorschau (die Antwort von /plan nennt ihn), von /apply mitgeschickt: dann plant _make_plan genau so oder lehnt
    # ab, nie still ueber den anderen Weg. Ohne ihn waehlt _make_plan selbst; /plan beachtet ihn nie, die Vorschau waehlt immer (R28).
    mechanism: str | None = Field(default=None, pattern=r"^(ssh|snmp)$")


def _port_list(ports: list[str]) -> str:
    """Die Ports fuer eine Zusammenfassung: ProCurve-Namen zusammengefasst (1-3,7,Trk1); Namen anderer Hersteller (Gi1/0/1, ge-0/0/1,
    ...), an denen cfgparse.compress_ports scheitert, natuerlich sortiert und mit Komma."""
    try:
        return cfgparse.compress_ports(ports)
    except ValueError:
        return ", ".join(sorted(set(ports), key=snmpwrite.port_order))


def _listing(items: list[str]) -> str:
    """["a"] -> "a", ["a", "b", "c"] -> "a, b und c"."""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " und " + items[-1]


def _summary(body: PlanIn) -> str:
    c, parts = body.change, []
    if c.status:
        parts.append(STATUS_LABEL[c.status])
    if c.untagged:
        parts.append(f"VLAN {c.untagged}")
    if c.tagged_add:
        parts.append("getaggt +" + ",".join(c.tagged_add))
    if c.tagged_remove:
        parts.append("getaggt −" + ",".join(c.tagged_remove))
    if c.name is not None:
        parts.append(f"Name {c.name}" if c.name else "Name entfernt")
    if c.limit:
        parts.append(f"{c.limit} Geräte/Port")
    if c.guest is not None:
        parts.append(f"Gast-VLAN {c.guest}" if c.guest else "ohne Gast-VLAN")
    if c.poe is not None:
        parts.append("PoE an" if c.poe else "PoE aus")
    return f"Port {_port_list(body.ports)}: " + (", ".join(parts) or "–")


# ── Schreibweg waehlen: SSH-CLI oder SNMP ─────────────────────────────────────────────────────────────────────────────────────────────
# Fixiert beim Planen, vor dem ersten Schreibzugriff, nie mitten im Ausfuehren (Spec §5, Q5); plan["mechanism"] nennt ihn.
def needed_ops(body: PlanIn) -> set[str]:
    """Die SNMP-Faehigkeiten des Treibers (drivers.can), die die Anfrage per SNMP braucht: VLANs snmp_vlan, jeder Zustand snmp_admin
    ("Aus" schaltet den Port ab, jeder andere ein), ein Name snmp_name, PoE snmp_poe. Was per SNMP gar nicht geht (802.1X /
    MAC-Anmeldung, Limit, Gast-VLAN), prueft _cli_only."""
    c, ops = body.change, set()
    if c.untagged is not None or c.tagged_add or c.tagged_remove:
        ops.add("snmp_vlan")
    if c.status is not None:
        ops.add("snmp_admin")
    if c.name is not None:
        ops.add("snmp_name")
    if c.poe is not None:
        ops.add("snmp_poe")
    return ops


def _cli_only(body: PlanIn, driver: drivers.Driver) -> str | None:
    """Warum die Anfrage nur ueber die SSH-CLI geht (sonst None). 802.1X / MAC-Anmeldung kennt der SNMP-Weg nicht: read_cfg zeigt sie
    immer aus, render_ops schreibt sie nie; plan_ports plante davon per SNMP still nichts. Darum auch "Protected" nicht auf einem
    Treiber mit NAC: es heisst Anmeldung aus, per SNMP schaltete es nur den Port ein. Eine RADIUS-Vorbereitung ist reine CLI."""
    c, parts = body.change, []
    if body.mode == "prepare":
        parts.append("RADIUS vorbereiten")
    if c.status in ("known", "radius"):
        parts.append(f"Zustand „{STATUS_LABEL[c.status]}“")
    elif c.status == "protected" and drivers.can(driver, "nac"):
        parts.append("Zustand „Protected“ (802.1X/MAC-Anmeldung ist per SNMP weder lesbar noch abschaltbar)")
    if c.limit is not None:
        parts.append("Geräte pro Port")
    if c.guest is not None:
        parts.append("Gast-VLAN")
    if not parts:
        return None
    return f"{_listing(parts)} {'geht' if len(parts) == 1 else 'gehen'} nur mit SSH/ProCurve, nicht per SNMP"


def _snmp_unwritable(row, driver: drivers.Driver, ops: set[str]) -> str | None:
    """Warum der SNMP-Weg hier nicht schreiben kann (sonst None): dem Treiber fehlt eine der Faehigkeiten ops, oder es gibt keine
    Schreib-Identitaet; deren Grund (SNMP-Schreiben aus, keine Zugangsdaten, Community public, ...) kommt allein aus
    poller.creds_of(row, write=True)."""
    missing = sorted(op for op in ops if not drivers.can(driver, op))
    if missing:
        labels = [snmpwrite._CAP_LABEL.get(op, op) for op in missing]    # dieselben Namen wie in snmpwrite.snmp_block_reason
        return f"Treiber {driver.name} kann {_listing(labels)} nicht per SNMP schreiben"
    try:
        poller.creds_of(row, write=True)
    except snmp.SnmpError as e:
        return str(e)
    return None


def _snmp_refusal(row, driver: drivers.Driver, body: PlanIn) -> tuple[int, str] | None:
    """Warum die Anfrage nicht per SNMP gehen kann: (409, Grund), wenn sie etwas will, das nur die CLI kann; (422, Grund), wenn der
    SNMP-Weg nicht schreiben kann; sonst None."""
    reason = _cli_only(body, driver)
    if reason:
        return 409, reason
    reason = _snmp_unwritable(row, driver, needed_ops(body))
    return (422, reason) if reason else None


def _ssh_refusal(row, driver: drivers.Driver) -> str | None:
    """Warum der SSH-CLI-Weg fuer diesen Switch nicht geht (sonst None)."""
    if not drivers.can(driver, "cli"):
        return f"Treiber {driver.name} hat keine SSH-CLI"
    if not row["ssh_user"] or not row["ssh_pass"]:
        return NO_SSH
    return None


async def _choose_mechanism(row, driver: drivers.Driver, body: PlanIn) -> tuple[str, dict | None, str | None]:
    """Der Schreibweg einer neuen Aenderung (mode ports oder prepare): ("ssh", cfg aus der running-config, None) oder ("snmp", None,
    ssh_error), ssh_error der Fehler des SSH-Reads, fuer den SNMP einspringt (sonst None); sonst HTTPException.
      1. Ein mitgeschickter mechanism (nur von /apply, nach seiner Vorschau; /plan reicht keinen weiter, R28) gilt genau so, wenn er
         noch geht, sonst 409 STALE: nie still der andere Weg. Was nur die CLI kann, lehnt auch ein mitgeschicktes "snmp" mit seinem
         eigenen Grund ab.
      2. Treiber mit CLI und SSH-Zugang: SSH, das Lesen der Konfiguration (changes.fresh_cfg) ist der Pre-Flight. Scheitert es, geht die
         Aenderung per SNMP, wenn sie dort geht (mit Hinweis), sonst 502 wie bisher, mit dem Grund, warum SNMP nicht geht. If the read
         was refused for the switch's host key (changes.HostKeyRefused, Phase 2 F-b), SNMP takes over only with an SNMPv3 authPriv
         write identity (poller.write_authpriv), otherwise 502: whoever answers at the address may be an attacker, and a v2c community
         or v3 without privacy would go to it in the clear. A request SNMP cannot take anyway keeps the 502 of before.
      3. Sonst SNMP, wenn die Anfrage dort geht, sonst 409 / 422 mit dem Grund (_snmp_refusal), bei einem Treiber mit CLI (dann fehlt
         der SSH-Zugang) hinter der Meldung von bisher (SSH_NEEDED).
    PoE (R30) geht bei jedem Treiber nur per SNMP, auch bei ProCurve mit SSH: eine Port-Aenderung mit PoE geht als Ganzes per SNMP (u, t,
    an / aus und Name kann SNMP auch), ohne SSH-Read, wenn sie dort geht; sonst 422 "PoE erfordert SNMP-Schreibzugriff (Grund)", oder 409,
    wenn sie dazu etwas will, das nur die CLI kann. Ein mitgeschicktes "ssh" mit PoE: 409 STALE (diese Vorschau gab es nie)."""
    ssh_refusal = _ssh_refusal(row, driver)
    poe = body.mode == "ports" and body.change.poe is not None
    if body.mechanism == "ssh":
        if poe:
            raise HTTPException(409, f"{STALE} (PoE geht nur per SNMP)")
        if ssh_refusal:
            raise HTTPException(409, f"{STALE} ({ssh_refusal})")
        try:
            return "ssh", await changes.fresh_cfg(row["id"]), None
        except Exception as e:  # noqa: BLE001
            raise HTTPException(409, f"{STALE} (Konfiguration per SSH nicht lesbar: {e})")
    if body.mechanism == "snmp":
        reason = _cli_only(body, driver)
        if reason:
            raise HTTPException(409, reason)
        reason = _snmp_unwritable(row, driver, needed_ops(body))
        if reason:
            raise HTTPException(409, f"{STALE} ({reason})")
        return "snmp", None, None
    if poe:
        refusal = _snmp_refusal(row, driver, body)
        if refusal and refusal[0] == 409:
            raise HTTPException(409, f"{refusal[1]}. PoE geht nur per SNMP: bitte getrennt ändern")
        if refusal:
            raise HTTPException(422, f"PoE erfordert SNMP-Schreibzugriff ({refusal[1]})")
        return "snmp", None, None
    if not ssh_refusal:
        try:
            return "ssh", await changes.fresh_cfg(row["id"]), None
        except Exception as e:  # noqa: BLE001
            error = str(e) or type(e).__name__    # nie leer: ein leerer ssh_error hiesse sonst "kein SSH-Fehler", SNMP spraenge still ein
            refusal = _snmp_refusal(row, driver, body)
            if refusal:
                raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {error} (per SNMP geht es auch nicht: {refusal[1]})")
            if isinstance(e, changes.HostKeyRefused) and not poller.write_authpriv(row):
                # one period between the host key message (it ends with one) and the reason
                raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {error.removesuffix('.')}. Kein Ausweichen auf SNMP: "
                                         "der Schlüssel kann von einem Angreifer stammen, und SNMP schriebe hier nicht mit SNMPv3 authPriv.")
            return "snmp", None, error
    refusal = _snmp_refusal(row, driver, body)
    if refusal:
        status, reason = refusal
        if drivers.can(driver, "cli"):
            reason = f"{SSH_NEEDED}. Per SNMP geht es auch nicht: {reason}"
        raise HTTPException(status, reason)
    return "snmp", None, None


async def _read_snmp(row, driver: drivers.Driver, ssh_error: str | None = None, *, with_poe: bool = False) -> tuple[dict, dict]:
    """Der Live-Read per SNMP (snmpwrite.read_cfg) im Change-Lock des Switches, wie der SSH-Weg seine Konfiguration im selben Lock liest:
    nie mitten in eine laufende Aenderung hinein. with_poe (R34): auch die PoE-Tabellen, fuer eine Aenderung, die PoE beruehrt
    (changes.touches_poe der Anfrage, wie run_change es rechnet). read_cfg faellt geschlossen aus, das wird 502 mit dem Grund; springt
    SNMP fuer einen gescheiterten SSH-Read ein (ssh_error), nennt die Meldung beide Fehler."""
    try:
        async with sshcli.lock(row["id"]):
            return await snmpwrite.read_cfg(row, driver, with_poe=with_poe)
    except (snmp.SnmpError, OSError) as e:
        if ssh_error is not None:
            raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {ssh_error} (per SNMP auch nicht: {e})")
        raise HTTPException(502, f"Konfiguration des Switches per SNMP nicht lesbar: {e}")


def _check_request(body: PlanIn, port_re: re.Pattern):
    for p in body.ports:
        if not port_re.fullmatch(p):
            raise HTTPException(422, f"Port ungültig: {p}")
    for v in body.change.tagged_add + body.change.tagged_remove:
        if not re.fullmatch(r"\d{1,4}", v):
            raise HTTPException(422, f"VLAN ungültig: {v}")
    # Baseline L7: one VLAN in both lists was planned as "remove" without a word; the UI never sends both for one VLAN
    both = sorted(set(body.change.tagged_add) & set(body.change.tagged_remove), key=int)
    if both:
        raise HTTPException(422, f"VLAN {both[0]} steht in „getaggt hinzufügen“ und „getaggt entfernen“")


async def _inventory(sid: int) -> dict:
    """changes.inventory(sid); its LookupError (the switch is not in the map: disabled since the request began, or gone) is 409
    DISABLED, never a 500."""
    try:
        return await changes.inventory(sid)
    except LookupError:
        raise HTTPException(409, DISABLED)


async def _make_plan(row, body: PlanIn) -> tuple[dict, dict, str, str]:
    """-> (plan, request fuer run_change, kind, summary). plan["mechanism"] ist der Schreibweg, "ssh" oder "snmp"."""
    driver = drivers.driver_for(row)
    if body.mode in ("revert", "save"):
        return await _plan_of_change(row, driver, body)
    mech, cfg, ssh_error = await _choose_mechanism(row, driver, body)
    if mech == "snmp":
        return await _plan_snmp(row, driver, body, ssh_error)
    if body.mode == "prepare":
        plan = changes.plan_prepare(cfg, await changes.radius_settings())
        return plan | {"mechanism": "ssh"}, {}, "prepare", "RADIUS vorbereiten"
    _check_request(body, PORT_RE)
    req = {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}
    try:
        plan = changes.plan_ports(row["firmware"] or "", await _inventory(row["id"]), cfg, req,
                                  radius_server=(await changes.radius_settings())["server"])
    except ValueError as e:
        raise HTTPException(422, str(e))
    return plan, req, "ports", _summary(body)


async def _warn_unsaved(row, driver: drivers.Driver, plan: dict):
    """R42: ein SNMP-SET auf einem Treiber mit snmp_autosave laesst den Switch seine gesamte laufende Konfiguration speichern, auch jede
    per SSH absichtlich nicht gespeicherte Aenderung, die etwas gesendet hat (changes.unsaved_ssh_changes; R48: one that sent nothing
    is not named). Das sagt die Vorschau laut, vor den Hinweisen zu den Ports. Keine Sperre: per SNMP geht es gerade dann, wenn SSH weg
    ist und sich die SSH-Aenderung weder zuruecknehmen noch speichern laesst."""
    if not drivers.can(driver, "snmp_autosave"):
        return
    ids = await changes.unsaved_ssh_changes(row["id"])
    if not ids:
        return
    refs, one = changes.change_refs(ids), len(ids) == 1
    plan["warnings"] = [f"Achtung: {'Änderung' if one else 'Änderungen'} {refs} {'ist' if one else 'sind'} absichtlich nicht gespeichert. Ein "
                        f"SNMP-SET lässt den Switch die gesamte laufende Konfiguration speichern – {refs} {'wäre' if one else 'wären'} danach "
                        f"dauerhaft. Vorher {refs} zurücknehmen oder bewusst speichern.", *plan["warnings"]]


async def _plan_snmp(row, driver: drivers.Driver, body: PlanIn, ssh_error: str | None) -> tuple[dict, dict, str, str]:
    """Eine neue Port-Aenderung per SNMP (_choose_mechanism hat schon abgelehnt, was dort nicht geht): gegen einen Live-Read geplant,
    jeder Port muss in ihm stehen. ssh_error: SNMP springt fuer diesen gescheiterten SSH-Read ein, das sagt eine Warnung vorne."""
    _check_request(body, SNMP_PORT_RE)
    req = {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}
    cfg, raw = await _read_snmp(row, driver, ssh_error, with_poe=changes.touches_poe(req))
    missing = [p for p in body.ports if p not in cfg["ports"]]
    if missing:
        raise HTTPException(422, f"Port gibt es auf diesem Switch nicht: {', '.join(missing)}")
    try:
        plan = changes.plan_ports(row["firmware"] or "", await _inventory(row["id"]), cfg, req, mechanism="snmp", driver=driver,
                                  raw=raw)
    except ValueError as e:
        raise HTTPException(422, str(e))
    await _warn_unsaved(row, driver, plan)
    if ssh_error is not None:    # nie still per SNMP (L19)
        plan["warnings"] = [f"SSH nicht verfügbar ({ssh_error}), die Änderung geht per SNMP", *plan["warnings"]]
    return plan, req, "ports", _summary(body)


async def _plan_of_change(row, driver: drivers.Driver, body: PlanIn) -> tuple[dict, dict, str, str]:
    """Rueckgaengig (revert) und Speichern (save) einer Aenderung, auf dem Weg der Aenderung selbst (changes.mechanism; NULL heisst ssh,
    eine Zeile von vor der Spalte) und nie auf einem anderen: before einer SNMP-Aenderung haelt etwa die PVID (R21), die der SSH-Weg
    nicht kennt. Ein unbekannter Weg, und ein mitgeschickter mechanism (/apply), der nicht dieser ist: 409."""
    async with db() as conn:
        async with conn.execute("SELECT * FROM changes WHERE id = ? AND switch_id = ?", (body.of, row["id"])) as cur:
            ch = await cur.fetchone()
    if not ch:
        raise HTTPException(404, "Änderung nicht gefunden")
    mech = ch["mechanism"] or "ssh"
    if mech not in ("ssh", "snmp"):  # im Zweifel gesperrt, nie still per SSH
        raise HTTPException(409, f"Änderung #{ch['id']} hat einen unbekannten Schreibweg ({mech})")
    if body.mechanism and body.mechanism != mech:
        raise HTTPException(409, STALE)
    if body.mode == "save":
        return await _plan_save(row, driver, ch, mech)
    return await _plan_revert(row, driver, ch, mech)


def _refuse_ssh_way(row, driver: drivers.Driver, ch, verb: str):
    """409, wenn sich die per SSH gemachte Aenderung ch jetzt nicht per SSH `verb` laesst: ohne SSH-Zugang mit der Meldung von bisher
    vorne (SSH_NEEDED), sonst mit dem Grund (der Treiber hat keine CLI)."""
    reason = _ssh_refusal(row, driver)
    done = f"Änderung #{ch['id']} lief per SSH und lässt sich nur per SSH {verb}"
    if reason == NO_SSH:
        raise HTTPException(409, f"{SSH_NEEDED}. {done}")
    if reason:
        raise HTTPException(409, f"{done}: {reason}")


async def _plan_save(row, driver: drivers.Driver, ch, mech: str) -> tuple[dict, dict, str, str]:
    """Speichern (write memory) nach einer Aenderung, die unklar oder fehlgeschlagen endete; nur per SSH, und es plant nie etwas. Eine
    SNMP-Aenderung speichert ein Treiber mit snmp_autosave selbst; bei jedem anderen geht Speichern per SNMP nicht, das bleibt dem
    Switch (R26). Beides vor der Pruefung des Status: eine SNMP-Aenderung, die ok endete, ist dort nicht unbedingt gespeichert. A
    change that sent nothing (changes.may_have_sent) has nothing to save either: the same 409. The rules of changes.actions_of."""
    if mech == "snmp":
        if drivers.can(driver, "snmp_autosave"):
            raise HTTPException(409, "SNMP-Änderungen werden automatisch gespeichert")
        raise HTTPException(409, "Per SNMP nicht speicherbar – bitte am Switch speichern (z. B. write memory / copy running-config startup-config)")
    if ch["status"] not in ("unclear", "failed") or ch["saved"] or not changes.may_have_sent(ch):    # sent nothing: nothing to save
        raise HTTPException(409, "Diese Änderung muss nicht gespeichert werden")
    _refuse_ssh_way(row, driver, ch, "speichern")
    try:
        await changes.fresh_cfg(row["id"])  # der Pre-Flight wie bisher
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {e}")
    plan = {"commands": [], "shown": [], "blocked": [], "mechanism": "ssh",
            "warnings": ["Speichert den aktuellen Stand des Switches dauerhaft (write memory)."]}
    return plan, {"of": ch["id"]}, "save", f"Speichern nach #{ch['id']}"


async def _plan_revert(row, driver: drivers.Driver, ch, mech: str) -> tuple[dict, dict, str, str]:
    """Rueckgaengig: plan_ports mit desired = before der Aenderung gegen einen frischen Read auf ihrem Weg mech. Geht der gerade nicht,
    409 mit dem Grund; per SSH auch, wenn before Felder hat, die der SSH-Weg nicht kennt (SSH_FIELDS; der Planer liefe sonst in einen
    KeyError). Was ein Treiber per SNMP nicht schreiben kann, sperrt plan_ports je Port (snmpwrite.snmp_block_reason). A change that
    sent nothing (changes.may_have_sent, e.g. failed before connecting) has nothing to take back: 409, before any read. The rules of
    changes.actions_of."""
    if ch["kind"] != "ports" or ch["reverted_by"] or ch["status"] in ("queued", "running", "aborted"):
        raise HTTPException(409, "Diese Änderung lässt sich nicht zurücknehmen")
    if not changes.may_have_sent(ch):    # e.g. failed before connecting: the switch is as it was
        raise HTTPException(409, f"Änderung #{ch['id']} hat nichts an den Switch gesendet – es gibt nichts zurückzunehmen")
    req = {"desired": json.loads(ch["before"] or "{}"), "expert": bool(ch["expert"])}
    if mech == "snmp":
        reason = _snmp_unwritable(row, driver, set())
        if reason:
            raise HTTPException(409, f"Änderung #{ch['id']} lief per SNMP und lässt sich nur per SNMP zurücknehmen: {reason}")
        cfg, raw = await _read_snmp(row, driver, with_poe=changes.touches_poe(req))    # R34: before mit poe liest PoE mit
        way = {"mechanism": "snmp", "driver": driver, "raw": raw}    # die Schluesselwoerter von plan_ports fuer diesen Weg
    else:
        _refuse_ssh_way(row, driver, ch, "zurücknehmen")
        odd = sorted({str(k) for d in req["desired"].values() for k in d} - SSH_FIELDS)
        if odd:
            raise HTTPException(409, f"Änderung #{ch['id']} lässt sich per SSH nicht zurücknehmen: ihr Vorher-Stand enthält Felder, die der "
                                     f"SSH-Weg nicht kennt ({', '.join(odd)})")
        try:
            cfg = await changes.fresh_cfg(row["id"])
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {e}")
        way = {"radius_server": (await changes.radius_settings())["server"]}    # a NAC revert needs the configured server, like run_change
    try:
        plan = changes.plan_ports(row["firmware"] or "", await _inventory(row["id"]), cfg, req, **way)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if mech == "snmp":
        await _warn_unsaved(row, driver, plan)
    return plan, req, "ports", f"Rückgängig #{ch['id']}: {ch['summary']}"


async def _enabled_row(sid: int):
    """The switches row of sid for a change (_row), 409 DISABLED for a disabled switch: in every mode, before anything is read."""
    row = await _row(sid)
    if not row["enabled"]:
        raise HTTPException(409, DISABLED)
    return row


@app.post("/api/switches/{sid}/plan")
async def plan_change(sid: int, body: PlanIn, user=Depends(auth.current_user)):
    row = await _enabled_row(sid)
    # Die Vorschau waehlt den Schreibweg immer selbst (R28): einen mitgeschickten mechanism beachtet nur /apply.
    plan, _, kind, summary = await _make_plan(row, body.model_copy(update={"mechanism": None}))
    return {"kind": kind, "summary": summary, "mechanism": plan["mechanism"], "commands": plan["shown"], "warnings": plan.get("warnings", []),
            "blocked": plan["blocked"], "before": plan.get("before", {}), "desired": plan.get("desired", {}),
            "token": changes.cmd_token(plan["shown"])}


@app.post("/api/switches/{sid}/apply")
async def apply_change(sid: int, body: PlanIn, user=Depends(auth.current_user)):
    """The early check for a queued or running change spares the read and the plan; the binding one is changes.create_change's, in one
    transaction with the INSERT (two requests can both pass this one while they plan): either way 409 changes.BUSY."""
    row = await _enabled_row(sid)
    async with db() as conn:
        async with conn.execute("SELECT id FROM changes WHERE switch_id = ? AND status IN ('queued', 'running')", (sid,)) as cur:
            if await cur.fetchone():
                raise HTTPException(409, changes.BUSY)
    plan, req, kind, summary = await _make_plan(row, body)
    if plan["blocked"]:
        raise HTTPException(409, "Nicht ausführbar: " + "; ".join(f"{b['port']}: {b['reason']}" for b in plan["blocked"]))
    if body.token != changes.cmd_token(plan["shown"]):
        raise HTTPException(409, "Die Vorschau ist veraltet, bitte neu laden")
    if not plan["shown"] and kind != "save":
        raise HTTPException(422, "Es gibt nichts zu ändern")
    # A revert marks the change it takes back (reverted_by) only when it ends ok (changes._mark_reverted), not here
    try:
        cid = await changes.create_change(sid, user["username"], kind, summary, req, plan,
                                          revert_of=body.of if body.mode == "revert" else None)
    except changes.Busy:
        raise HTTPException(409, changes.BUSY)
    t = asyncio.create_task(changes.run_change(cid))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return {"id": cid}


def _change_out(r, secrets: list[str]) -> dict:
    """A changes row as the API serves it: error, output and the text of every step masked again (cfgparse.mask_secrets with
    secrets, changes._secrets_of of its switch). A row from before Phase 2 was stored unmasked; on one that run_change stored masked
    the masking changes nothing. The row in the database stays as it is (E26, as for backups). Plus can_revert and can_save
    (changes.actions_of): the UI offers "Rückgängig" and "Trotzdem speichern" by these flags alone."""
    d = dict(r) | changes.actions_of(r)
    for k in ("ports", "desired", "before", "commands", "steps"):
        d[k] = json.loads(d[k] or ("[]" if k in ("ports", "commands", "steps") else "{}"))
    d.pop("request", None)
    for k in ("error", "output"):
        if d[k]:
            d[k] = cfgparse.mask_secrets(d[k], secrets)
    d["steps"] = [[s[0], cfgparse.mask_secrets(s[1], secrets), *s[2:]] if isinstance(s, list) and len(s) > 1 and isinstance(s[1], str)
                  else s for s in d["steps"]]
    return d


async def _changes_out(conn, rows) -> list[dict]:
    """_change_out of each row, with the RADIUS key read once and the secrets of each switch once."""
    rs = await changes.radius_settings()
    secrets: dict[int, list[str]] = {}
    for r in rows:
        if r["switch_id"] not in secrets:
            async with conn.execute("SELECT * FROM switches WHERE id = ?", (r["switch_id"],)) as cur:
                secrets[r["switch_id"]] = changes._secrets_of(await cur.fetchone(), rs)
    return [_change_out(r, secrets[r["switch_id"]]) for r in rows]


@app.get("/api/changes")
async def list_changes(switch_id: int | None = None, limit: int = 100, user=Depends(auth.current_user)):
    q, args = "SELECT c.*, s.name AS switch_name FROM changes c JOIN switches s ON s.id = c.switch_id", []
    if switch_id:
        q += " WHERE c.switch_id = ?"
        args.append(switch_id)
    q += " ORDER BY c.id DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    async with db() as conn:
        async with conn.execute(q, args) as cur:
            rows = await cur.fetchall()
        return await _changes_out(conn, rows)


@app.get("/api/changes/{cid}")
async def get_change(cid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT c.*, s.name AS switch_name FROM changes c JOIN switches s ON s.id = c.switch_id WHERE c.id = ?", (cid,)) as cur:
            r = await cur.fetchone()
        if not r:
            raise HTTPException(404, "Änderung nicht gefunden")
        return (await _changes_out(conn, [r]))[0]


@app.post("/api/switches/{sid}/config/refresh")
async def refresh_config(sid: int, user=Depends(auth.current_user)):
    _cli_way(await _row(sid), "cli", "Konfiguration lesen")
    res = await sshcli.backup_config(sid, "lesen")
    if not res.get("ok"):
        raise HTTPException(502, res.get("error") or "Lesen fehlgeschlagen")
    return res


@app.post("/api/switches/{sid}/port-access")
async def port_access(sid: int, user=Depends(auth.current_user)):
    row = await _row(sid)
    _cli_way(row, "cli", "Anmeldungen anzeigen")
    if not row["ssh_user"] or not row["ssh_pass"]:
        raise HTTPException(422, "Kein SSH-Zugang hinterlegt")
    cmds = ["show port-access authenticator", "show port-access authenticator clients", "show port-access mac-based clients"]
    try:
        out = await sshcli.run_shows(row, cmds)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, sshcli.error_text(e))
    return {c: cfgparse.mask_secrets(out.get(c, "")) for c in cmds}


# ── Geraete-Datenbank ─────────────────────────────────────────────────────────
KINDS = ("drucker", "telefon", "kamera", "iot", "zugang", "server", "netzwerk", "sonstiges")


def norm_mac(v: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", v or "").lower()
    if len(h) != 12:
        raise HTTPException(422, "MAC-Adresse ungültig")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


class DeviceIn(BaseModel):
    mac: str = Field(max_length=20)
    name: str = Field(min_length=1, max_length=64)
    kind: str = Field(default="sonstiges", pattern=r"^(drucker|telefon|kamera|iot|zugang|server|netzwerk|sonstiges)$")
    location: str = Field(default="", max_length=64)
    owner: str = Field(default="", max_length=64)
    notes: str = Field(default="", max_length=500)
    role: str = Field(default="", max_length=64)
    allowed: bool = False
    valid_until: str | None = Field(default=None, pattern=r"^(\d{4}-\d{2}-\d{2})?$")    # null or "": no expiry date


def _valid_until(body: DeviceIn) -> str | None:
    """body.valid_until as stored: None for no expiry date (null or ""), else the date; 422 for one that has the format of a date but
    is none (2026-13-45, 0000-00-00, 2026-02-30): pf compares it as text with today's date and hands it to PacketFence as the
    node's unregdate, so an impossible one would end the release at a point nobody chose."""
    if not body.valid_until:
        return None
    try:
        date.fromisoformat(body.valid_until)
    except ValueError:
        raise HTTPException(422, "Gültig bis: kein gültiges Datum (JJJJ-MM-TT)") from None
    return body.valid_until


@app.get("/api/devices")
async def list_devices(user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT * FROM devices ORDER BY name COLLATE NOCASE") as cur:
            devs = [dict(r) for r in await cur.fetchall()]
        async with conn.execute("SELECT m.mac, m.port, m.vlan, m.last_seen, s.name AS sw, p.mac_count, n.ip, n.name AS hn FROM macs m "
                                "JOIN devices d ON d.mac = m.mac JOIN switches s ON s.id = m.switch_id "
                                "LEFT JOIN ports p ON p.switch_id = m.switch_id AND p.name = m.port LEFT JOIN names n ON n.mac = m.mac") as cur:
            seen = await cur.fetchall()
    best: dict[str, dict] = {}
    for r in seen:  # Zugangsport = der Port mit den wenigsten MACs
        b = best.get(r["mac"])
        if not b or (r["mac_count"] or 999) < (b["mac_count"] or 999):
            best[r["mac"]] = dict(r)
    for d in devs:
        d["seen"] = best.get(d["mac"])
        d["vendor"] = names_mod.vendor_of(d["mac"])
    return devs


UNKNOWN_PER_PORT = 12  # unknown devices listed per port: a flood shows its port (flag "many" with its count), not thousands of rows


@app.get("/api/devices/unknown")
async def unknown_devices(user=Depends(auth.current_user)):
    m = await build_map()
    async with db() as conn:
        # Every unregistered device each port has learned, not build_map's display list "d": that one holds twelve devices per port,
        # registered ones first, so twelve registered devices or a flood ahead of a device in poll order kept it off this list.
        async with conn.execute("SELECT m.switch_id, m.port, m.mac, m.vlan, n.ip, n.name, n.vendor FROM macs m LEFT JOIN names n "
                                "ON n.mac = m.mac WHERE m.mac NOT IN (SELECT mac FROM devices) ORDER BY m.rowid") as cur:
            rows = await cur.fetchall()
    base = {s["baseMac"] for s in m["switches"]}
    learned: dict[tuple, list] = defaultdict(list)
    for r in rows:
        if r["mac"] not in base:
            learned[(r["switch_id"], r["port"])].append(r)
    keys = switch_keys(m["switches"])
    out = []
    for s in m["switches"]:
        for p in s["ports"]:
            # F3: only trunks and confirmed uplinks are skipped. An LLDP frame or a MAC flood on an access port no longer hides the
            # devices behind it; such entries are flagged and listed after the unflagged ones, so they push no one past the cap.
            if p["n"].startswith("Trk") or p["tr"] or (p.get("up") and p["uc"]):
                continue
            # "uplink_lldp" wherever the port table shows "Uplink (unbestätigt)" (app.js): an uplink nobody confirms (up, so not uc
            # here), or no link while an LLDP neighbour is a managed switch (isPeer; changes.inventory's backstop protects such ports).
            # Not on a port that is an uplink only by a base MAC learned on it ("bm" without a link): the flag says "per LLDP" (Phase 3
            # Task 9 left this list as it was, docs/logik-phase3.md "Bekannte Grenzen").
            peer = any(e[0] in keys for e in p["l"])
            flags = [f for f, on in (("uplink_lldp", p.get("up") or peer), ("lldp", p["l"]), ("many", p["mc"] > 4)) if on]
            # Of a port's devices, those the router knows (an IP or a name) come first, then poll order: a heuristic. A flood of made-up
            # MACs mostly has no ARP entry, but a flooder can send ARP for each of them, so this only makes it harder to push a known
            # device past the cap.
            ds = sorted(learned.get((s["id"], p["n"]), []), key=lambda r: not (r["ip"] or r["name"]))
            for r in ds[:UNKNOWN_PER_PORT]:
                out.append({"mac": r["mac"], "vlan": r["vlan"], "ip": r["ip"] or "", "name": r["name"] or "",
                            "vendor": r["vendor"] or names_mod.vendor_of(r["mac"]), "sw": s["k"], "sid": s["id"], "port": p["n"],
                            "st": p["st"], "flags": flags, "lldp": p["l"][0][0] if p["l"] else "", "mc": p["mc"]})
    out.sort(key=lambda e: bool(e["flags"]))  # stable: poll order within each group
    return out[:500]


async def _save_device(body: DeviceIn, user: str, mac: str, create: bool):
    vu = _valid_until(body)
    async with db() as conn:
        if create:
            try:
                await conn.execute("INSERT INTO devices(mac, name, kind, location, owner, notes, role, allowed, valid_until, created_by, updated_at) "
                                   "VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))",
                                   (mac, body.name.strip(), body.kind, body.location.strip(), body.owner.strip(), body.notes.strip(),
                                    body.role.strip(), int(body.allowed), vu, user))
            except Exception as e:  # noqa: BLE001
                if "UNIQUE" in str(e):
                    raise HTTPException(409, "Dieses Gerät ist schon in der Datenbank")
                raise
        else:
            cur = await conn.execute("UPDATE devices SET name=?, kind=?, location=?, owner=?, notes=?, role=?, allowed=?, valid_until=?, "
                                     "updated_at=datetime('now') WHERE mac=?",
                                     (body.name.strip(), body.kind, body.location.strip(), body.owner.strip(), body.notes.strip(),
                                      body.role.strip(), int(body.allowed), vu, mac))
            if cur.rowcount == 0:
                raise HTTPException(404, "Gerät nicht gefunden")
        await conn.commit()
    res = await pf.sync([mac])
    await audit(user, "device_create" if create else "device_update", mac, f"{body.name} freigegeben={int(body.allowed)}")
    return {"ok": True, "pf": res}


@app.post("/api/devices")
async def create_device(body: DeviceIn, user=Depends(auth.current_user)):
    return await _save_device(body, user["username"], norm_mac(body.mac), True)


@app.put("/api/devices/{mac}")
async def update_device(mac: str, body: DeviceIn, user=Depends(auth.current_user)):
    mac = norm_mac(mac)
    if norm_mac(body.mac) != mac:    # the form never sends another one; saving it under the path's MAC would hide the mismatch
        raise HTTPException(422, "MAC-Adresse im Formular passt nicht zum Gerät")
    return await _save_device(body, user["username"], mac, False)


@app.delete("/api/devices/{mac}")
async def delete_device(mac: str, user=Depends(auth.current_user)):
    mac = norm_mac(mac)
    try:    # PacketFence has to confirm reading and unregistering the node, else the device stays; a failed CoA is only a warning
        warning = await pf.unregister(mac)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"In PacketFence nicht zurückgenommen ({e}). Gerät bleibt erhalten.")
    async with db() as conn:
        cur = await conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))
        await conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "Gerät nicht gefunden")
    await audit(user["username"], "device_delete", mac, warning or "")
    return {"ok": True, "warning": warning}


@app.post("/api/devices/sync")
async def sync_devices(user=Depends(auth.current_user)):
    res = await pf.sync()
    await audit(user["username"], "device_sync", "", json.dumps(res))
    return res


@app.get("/api/pf/roles")
async def pf_roles(user=Depends(auth.current_user)):
    if not await pf.configured():
        return {"configured": False, "roles": []}
    try:
        return {"configured": True, "roles": await pf.roles()}
    except Exception as e:  # noqa: BLE001
        return {"configured": True, "roles": [], "error": str(e)[:200]}


@app.post("/api/pf/test")
async def pf_test(user=Depends(auth.current_user)):
    return await pf.test()


# ── Netzplan ──────────────────────────────────────────────────────────────────
@app.get("/api/netmap")
async def netmap(user=Depends(auth.current_user)):
    return await build_map()


async def build_map() -> dict:
    server = await get_setting("radius_server", "") or ""
    async with db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE enabled = 1 ORDER BY zone, sort, name") as cur:
            sws = await cur.fetchall()
        async with conn.execute("SELECT * FROM ports ORDER BY switch_id, ifindex") as cur:
            prows = await cur.fetchall()
        async with conn.execute("SELECT switch_id, vid, name FROM vlans") as cur:
            vrows = await cur.fetchall()
        async with conn.execute("SELECT m.switch_id, m.port, m.mac, m.vlan, n.ip, n.name, n.vendor, dv.name AS dname, dv.allowed "
                                "FROM macs m LEFT JOIN names n ON n.mac = m.mac LEFT JOIN devices dv ON dv.mac = m.mac") as cur:
            mrows = await cur.fetchall()
        async with conn.execute("SELECT switch_id, taken_at, parsed, stale FROM switch_cfg") as cur:
            cfgs = {r["switch_id"]: (r["taken_at"], json.loads(r["parsed"]), bool(r["stale"])) for r in await cur.fetchall()}
    # R39: ein Read der running-config zaehlt nur fuer einen Treiber mit SSH-CLI. Bei jedem anderen waere er eine Fehldeutung durch den
    # ProCurve-Parser (jeder Port "Protected") oder von vor einem Treiberwechsel: der Switch gilt als nicht gelesen.
    with_cli = {s["id"] for s in sws if drivers.can(drivers.driver_for(s), "cli")}
    cfgs = {sid: v for sid, v in cfgs.items() if sid in with_cli}

    vlans: dict[str, str] = {}
    vl_by: dict[int, list[str]] = defaultdict(list)
    for v in sorted(vrows, key=lambda r: _vid_num(r["vid"])):
        vlans.setdefault(v["vid"], v["name"])
        vl_by[v["switch_id"]].append(v["vid"])
    devs: dict[tuple, list] = defaultdict(list)
    for m in mrows:
        known = 0 if m["dname"] is None else (2 if m["allowed"] else 1)
        devs[(m["switch_id"], m["port"])].append([m["mac"], m["vlan"], m["ip"] or "", m["dname"] or m["name"] or "",
                                                  m["vendor"] or names_mod.vendor_of(m["mac"]), known])
    ports_by: dict[int, list] = defaultdict(list)
    # PoE nur, wo der Treiber des Switches es jetzt kann: PoE-Spalten eines Polls von vor einem Treiberwechsel zeigen nichts mehr
    poe_ok = {s["id"]: drivers.can(drivers.driver_for(s), "snmp_poe") for s in sws}
    for p in prows:
        key = (p["switch_id"], p["trunk"] or p["name"])
        d = sorted(devs.get(key, []), key=lambda x: -x[5])
        _, cfg, stale = cfgs.get(p["switch_id"], (None, None, False))
        st = cfgparse.port_state(cfg, p["name"]) if cfg else None
        if st and stale:    # the read is older than the switch's last change (switch_cfg.stale): on / off from the poll
            st = st | {"en": bool(p["admin"])}
        port = {
            "st": changes.status_of(st) if st else ("off" if not p["admin"] else ""),
            "lim": ((st["cl"] if st["x"] else None) or (st["al"] if st["m"] else None)) if st else None,
            "n": p["name"], "a": p["alias"] or "", "o": bool(p["oper"]), "ad": bool(p["admin"]), "s": p["speed"] or 0,
            "pv": p["pvid"] or "", "u": json.loads(p["untagged"] or "[]"), "t": json.loads(p["tagged"] or "[]"),
            "tr": p["trunk"] or "", "mb": json.loads(p["members"] or "[]"), "l": json.loads(p["lldp"] or "[]"),
            "mc": p["mac_count"], "d": d[:12]}
        if poe_ok.get(p["switch_id"]) and (p["poe_admin"] is not None or p["poe_status"] is not None):
            # nur ein Port mit sicher zugeordnetem PoE-Eintrag (poller.poe_ports): an / aus, Erkennungsstatus (RFC 3621), Leistung in mW
            port["poe"] = {"on": None if p["poe_admin"] is None else p["poe_admin"] == 1, "status": p["poe_status"], "mw": p["poe_power"]}
        ports_by[p["switch_id"]].append(port)

    # Switches by id (Review §4): a name is not unique, and two switches of one name looked up by it shadowed one another
    enabled = {s["id"] for s in sws}
    all_macs: dict[tuple[int, str], set[str]] = defaultdict(set)  # (switch id, port) -> every MAC, for the link detection
    for m in mrows:
        if m["switch_id"] in enabled:
            all_macs[(m["switch_id"], m["port"])].add(m["mac"])
    switches = []
    for s in sws:
        switches.append({"k": s["name"], "id": s["id"], "sys": s["sys_name"] or "", "model": s["model"] or "", "fw": s["firmware"] or "",
                         "zone": s["zone"] or "", "host": s["host"], "lastPoll": s["last_poll"], "ok": bool(s["last_poll_ok"]),
                         "error": s["last_error"] or "", "baseMac": s["base_mac"] or "", "ports": ports_by.get(s["id"], []),
                         "ssh": bool(s["ssh_user"] and s["ssh_pass"]), "driver": s["driver"], "caps": sorted(drivers.driver_for(s).caps),
                         "snmp_write": bool(s["snmp_write"]), "cfgAt": cfgs.get(s["id"], (None,))[0],
                         "cfgStale": cfgs.get(s["id"], (None, None, False))[2],
                         "ready": changes.readiness(cfgs[s["id"]][1], server or None) if s["id"] in cfgs else None,
                         "limitMax": changes.limit_max(s["firmware"] or ""), "vl": vl_by.get(s["id"], []),
                         "credWarnings": poller.credential_warnings(s)})
    links = _links(switches, all_macs)
    by_id = {s["id"]: s for s in switches}
    for link in links:  # Uplink-Ports markieren (inkl. Trunk-Mitglieder)
        for sid, side in ((link["a"], link["A"]), (link["b"], link["B"])):
            ups = set(side["ports"]) | ({side["trunk"]} if side["trunk"] else set())
            for p in by_id[sid]["ports"]:
                if p["n"] in ups or (p["tr"] and p["tr"] in ups):
                    p["up"] = True
    # F3: "uc" = the port, its trunk or (for a trunk) one of its members is an endpoint both switches confirm; a link is confirmed
    # when every port of both sides is. Display and the unknown-device list only: the uplink protection (changes.inventory) is unchanged.
    confirmed = confirmed_endpoints(switches, all_macs)
    for s in switches:
        for p in s["ports"]:
            p["uc"] = any((s["id"], n) in confirmed for n in (p["n"], p["tr"], *p["mb"]) if n)
    uc = {(s["id"], p["n"]) for s in switches for p in s["ports"] if p["uc"]}
    for link in links:
        link["confirmed"] = all((sid, n) in uc for sid, side in ((link["a"], link["A"]), (link["b"], link["B"])) for n in side["ports"])
    # "bm" = the base MAC of another managed switch is learned on the port (on a member: on its trunk, where the poller files a member's
    # MACs). changes.inventory counts every such port as an uplink (T6-RR1c), whichever port _links takes for the link.
    base_of = {s["baseMac"]: s["id"] for s in switches if s["baseMac"]}
    for s in switches:
        for p in s["ports"]:
            p["bm"] = any(base_of.get(mac) not in (None, s["id"]) for mac in all_macs.get((s["id"], p["tr"] or p["n"]), ()))
    return {"generated": datetime.now(timezone.utc).isoformat(), "vlans": vlans, "switches": switches, "links": links}


def _port_num(v: str) -> int:
    """Sort key of a port name: its number for ASCII digits up to nine places, else 999. int() alone raised on a name of more than 4300
    digits and on a digit isdigit() takes but int() does not ("²"), and with it build_map, the netmap, the inventory and every change."""
    return int(v) if v.isascii() and v.isdigit() and len(v) <= 9 else 999


def _vid_num(v: str) -> int:
    """Sort key of a VLAN id as text (vlans.vid, a port's u / t): as _port_num, else 10**9 (after every number)."""
    return int(v) if v.isascii() and v.isdigit() and len(v) <= 9 else 10**9


def switch_keys(switches: list[dict]) -> dict[str, set[int]]:
    """Non-empty sysName and name (k) of every switch -> the ids of the switches so named: how _links and confirmed_endpoints tell an
    LLDP neighbour that is a managed switch. A name two switches carry names both (LLDP gives only the name; R40, rather one uplink too
    many). changes.inventory takes the same mapping for its uplink backstop (R40)."""
    keys: dict[str, set[int]] = defaultdict(set)
    for s in switches:
        for name in (s["sys"], s["k"]):
            if name:
                keys[name].add(s["id"])
    return dict(keys)


def _lldp_claims(switches: list[dict], keys: dict[str, set[int]]) -> set[tuple[tuple[int, str], tuple[int, str]]]:
    """((A, P), (B, Q)) for every LLDP entry on port P of switch A whose sysName maps (keys, switch_keys) to another switch B and whose
    element 1 or 2 (stripped) is B's port Q; a name several switches carry maps to each of them. A pair is reported by both sides
    when ((B, Q), (A, P)) is a claim as well (confirmed_endpoints, _links)."""
    names = {s["id"]: {p["n"] for p in s["ports"]} for s in switches}
    claims = set()
    for s in switches:
        for p in s["ports"]:
            for entry in p["l"]:
                for nid in sorted(keys.get(entry[0], ())):
                    if nid != s["id"]:
                        claims |= {((s["id"], p["n"]), (nid, q)) for q in (e.strip() for e in entry[1:3]) if q in names[nid]}
    return claims


def confirmed_endpoints(switches: list[dict], all_macs: dict[tuple[int, str], set[str]]) -> set[tuple[int, str]]:
    """(switch id, port name) of every link endpoint both switches report themselves (F3); inputs as for _links.
    LLDP: port P of A names B's port Q (_lldp_claims), and Q names A and P back in the same way: P and Q. MAC (rule (b)): B's base MAC is
    learned on P (all_macs[(A, P)], a trunk under its own name), A learns B's base MAC on exactly one port (P; a trunk and its members
    count as one port) and B learns A's on exactly one port: P, unless P carries an LLDP claim like the above that the other switch
    does not make back. A claim only one side makes confirms nothing, not even the foreign port an LLDP entry names: otherwise a device
    on an access port would decide which port of another switch counts as confirmed. A base MAC learned on a second port confirms
    neither port (T6-RR1c): one of them is a device sending it."""
    claims = _lldp_claims(switches, switch_keys(switches))
    out = {end for here, there in claims if (there, here) in claims for end in (here, there)}
    # A device on an access port can send another switch's base MAC as its source in its own VLAN: the FDB is per VLAN, so that is a
    # second row and the switch's management is untouched. So base MACs confirm no port whose switch-LLDP claim is one-sided.
    one_sided = {here for here, _ in claims} - out
    base = {s["baseMac"]: s["id"] for s in switches if s["baseMac"]}
    trunk_of = {(s["id"], p["n"]): p["tr"] or p["n"] for s in switches for p in s["ports"]}
    seen: dict[tuple[int, int], set[str]] = defaultdict(set)    # (A, B) -> the ports (a trunk as one) on which A learns B's base MAC
    for (sid, pname), macs in all_macs.items():
        for mac in macs:
            if base.get(mac) not in (None, sid):
                seen[(sid, base[mac])].add(trunk_of.get((sid, pname), pname))

    def one_port_each(a: int, b: int) -> bool:
        return len(seen.get((a, b), ())) == 1 and len(seen.get((b, a), ())) == 1
    out |= {(sid, pname) for (sid, pname), macs in all_macs.items()
            if (sid, pname) not in one_sided and any(one_port_each(sid, base[mac]) for mac in macs if base.get(mac) not in (None, sid))}
    return out


def _links(switches: list[dict], all_macs: dict[tuple[int, str], set[str]]) -> list[dict]:
    """The links between the switches, by switch id (a name is not unique): per link the ids in "a" < "b", their names in "an" / "bn"
    for display; all_macs by (id, port). An LLDP entry of a port is [sysName, PortDesc (else PortId), PortId] (R40; a row from before
    the upgrade has only the first two). A sysName several switches carry (switch_keys; the factory sysName of one model, or two
    switches of one name) is tried at each of them that has the port it names, in id order. The neighbour's port is looked up by the
    PortDesc first, then by the PortId: with other vendors the PortDesc is often the long name or the description of the port, the
    PortId its ifName. A pair only the PortId finds, and every pair from a name more than one switch carries (the own one counted), is
    added after the base-MAC pairs and displaces none of them: it only adds links. Otherwise a shared name's pair to a switch that has
    the named port only by chance hid that switch's real link, one only base MACs see, and its real uplink lost its protection (R40).
    Of the other LLDP pairs only a confirmed one, which both sides report (A:P names B:Q and B:Q names A:P, as in _lldp_claims), and
    its ports (with their trunks) displace a base-MAC pair: the MAC pair of the same switch pair, or one on those ports. A pair only
    one side reports stays a link next to the MAC pair: otherwise one forged LLDP frame on an access port, naming a real port of the
    neighbour, hid a link only base MACs see, and the real uplink lost its protection (T6-F1c)."""
    by_id = {s["id"]: s for s in switches}
    sys2 = switch_keys(switches)
    base2 = {s["baseMac"]: s["id"] for s in switches if s["baseMac"]}
    claims = _lldp_claims(switches, sys2)

    def port(sid, n):
        return next((p for p in by_id[sid]["ports"] if p["n"] == n), None)

    pairs: dict[tuple, str] = {}
    late: dict[tuple, str] = {}    # pairs that only add links: found by the PortId, or from a name several switches carry
    confirmed: set[tuple] = set()  # the LLDP pairs in pairs that both sides report
    lldp_ports = set()             # their ports and trunks
    for s in switches:
        for p in s["ports"]:
            if p["n"].startswith("Trk"):
                continue
            for entry in p["l"]:
                nsys, nport = entry[0], entry[1]
                nids = sys2.get(nsys, set())
                for nid in sorted(nids - {s["id"]}):
                    np_ = port(nid, nport.strip())
                    if np_ and len(nids) == 1:
                        here, there = (s["id"], p["n"]), (nid, np_["n"])
                        key = tuple(sorted([here, there]))
                        pairs[key] = "lldp"
                        if (there, here) in claims:
                            confirmed.add(key)
                            for kk, pp in ((s["id"], p), (nid, np_)):
                                lldp_ports.add((kk, pp["n"]))
                                if pp["tr"]:
                                    lldp_ports.add((kk, pp["tr"]))
                    elif np_:
                        late[tuple(sorted([(s["id"], p["n"]), (nid, nport.strip())]))] = "lldp"
                    elif len(entry) > 2 and entry[2].strip() and port(nid, entry[2].strip()):
                        late[tuple(sorted([(s["id"], p["n"]), (nid, entry[2].strip())]))] = "lldp"
    # Ohne LLDP: Port, an dem die Basis-MAC eines anderen Switches gelernt wird, und umgekehrt
    seen_at: dict[tuple, str] = {}
    for (sid, pname), macset in all_macs.items():
        for mac in macset:
            other = base2.get(mac)
            if other is not None and other != sid:
                seen_at[(sid, other)] = pname
    for (a, b), pa in seen_at.items():
        pb = seen_at.get((b, a))
        if not pb or a > b:
            continue
        if (a, pa) in lldp_ports or (b, pb) in lldp_ports:
            continue
        if any({a, b} == {x[0][0], x[1][0]} for x in confirmed):
            continue
        pairs.setdefault(tuple(sorted([(a, pa), (b, pb)])), "mac")    # an unconfirmed LLDP pair on the very same ports keeps its label
    for key, src in late.items():
        pairs.setdefault(key, src)

    groups: dict[tuple, dict] = {}
    for (x, y), src in pairs.items():
        key = tuple(sorted([x[0], y[0]]))
        g = groups.setdefault(key, {"a": key[0], "b": key[1], "ap": [], "bp": [], "src": src})
        px, py = (x, y) if x[0] == key[0] else (y, x)
        g["ap"].append(px[1])
        g["bp"].append(py[1])
    out = []
    for g in groups.values():
        def side(sid, plist):
            ps = [port(sid, n) for n in plist if port(sid, n)]
            trk = sorted({p["tr"] for p in ps if p["tr"]})
            rep = port(sid, trk[0]) if trk else (ps[0] if ps else None)
            return {"ports": sorted(plist, key=_port_num), "trunk": trk[0] if trk else "",
                    "u": rep["u"] if rep else [], "t": rep["t"] if rep else [], "speed": rep["s"] if rep else 0}
        A, B = side(g["a"], g["ap"]), side(g["b"], g["bp"])
        va, vb = set(A["u"]) | set(A["t"]), set(B["u"]) | set(B["t"])
        out.append({"a": g["a"], "b": g["b"], "an": by_id[g["a"]]["k"], "bn": by_id[g["b"]]["k"], "A": A, "B": B, "src": g["src"],
                    "onlyA": sorted(va - vb, key=_vid_num), "onlyB": sorted(vb - va, key=_vid_num),
                    "native": sorted(set(A["u"]) ^ set(B["u"]), key=_vid_num)})
    return out
