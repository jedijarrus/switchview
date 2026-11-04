"""SwitchView: Switches, Ports und VLANs ansehen und Ports aendern (Phase 2)."""
import asyncio
import difflib
import ipaddress
import json
import logging
import os
import re
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

import auth
import cfgparse
import changes
import drivers
import names as names_mod
import pf
import poller
import snmp
import snmpwrite
import sshcli
from config import settings
from crypto import encrypt
from db import audit, db, get_setting, init_db, set_setting

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("switchview")
STATIC = os.path.join(os.path.dirname(__file__), "static")
scheduler = AsyncIOScheduler(timezone="Europe/Berlin")

# ── Single-Worker-Invariante ──────────────────────────────────────────────────
# SwitchView laeuft mit genau EINEM uvicorn-Worker (kein --workers, kein WEB_CONCURRENCY). Der Zustand liegt im Prozess:
# Scheduler, Login-Ratelimit (_login_hits), laufende Aenderungs-Tasks (_tasks) und die Locks je Switch fuer SSH
# (sshcli._locks) und Abfrage (poller._locks). Mehrere Worker haetten je ihren eigenen Satz: Jobs liefen mehrfach, das
# Ratelimit gaelte je Prozess, zwei Worker koennten gleichzeitig per SSH am selben Switch arbeiten (max. 5 Sessions),
# und der Start (lifespan) markiert die laufende Aenderung eines anderen Workers als abgebrochen.


async def _schedule():
    minutes = int(await get_setting("poll_minutes", "15") or 15)
    scheduler.add_job(poller.poll_all, "interval", minutes=max(5, minutes), id="poll", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(names_mod.refresh_names, "interval", minutes=15, id="names", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(sshcli.backup_all, "cron", hour=2, minute=30, id="backup", replace_existing=True, max_instances=1, coalesce=True)
    scheduler.add_job(pf.expire_and_sync, "cron", hour=3, minute=15, id="pf_sync", replace_existing=True, max_instances=1, coalesce=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if len(settings.secret_key) < 16:
        raise RuntimeError("SECRET_KEY fehlt oder ist zu kurz")
    await init_db()
    async with db() as conn:  # nach Neustart haengen gebliebene Aenderungen markieren
        await conn.execute("UPDATE changes SET status = 'unclear', error = 'Abgebrochen durch Neustart von SwitchView', "
                           "finished_at = datetime('now') WHERE status IN ('queued', 'running')")
        await conn.commit()
    await _schedule()
    scheduler.start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="SwitchView", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


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
_login_hits: dict[str, list[float]] = defaultdict(list)


def _rate_limit(request: Request):
    ip = request.client.host if request.client else "?"
    now = time.time()
    hits = [t for t in _login_hits[ip] if now - t < 60]
    if len(hits) >= 10:
        raise HTTPException(429, "Zu viele Anmeldeversuche, bitte eine Minute warten")
    hits.append(now)
    _login_hits[ip] = hits


def _set_cookie(resp: Response, request: Request, token: str):
    resp.set_cookie(auth.COOKIE, token, httponly=True, samesite="lax", secure=auth.is_https(request),
                    max_age=settings.session_hours * 3600, path="/")


@app.get("/api/auth/config")
async def auth_config():
    return {"sso": settings.sso_active, "tenant": settings.entra_tenant_id, "client_id": settings.entra_client_id,
            "local": settings.local_login_active}


class LocalLogin(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=200)


@app.post("/api/auth/local")
async def login_local(body: LocalLogin, request: Request, response: Response):
    _rate_limit(request)
    if not auth.check_local(body.username, body.password):
        await audit(body.username, "login_failed", "local")
        raise HTTPException(401, "Benutzername oder Kennwort falsch")
    token = await auth.create_session(body.username, body.username, "local")
    _set_cookie(response, request, token)
    await audit(body.username, "login", "local")
    return {"ok": True}


class AzureLogin(BaseModel):
    id_token: str = Field(max_length=20000)


@app.post("/api/auth/azure")
async def login_azure(body: AzureLogin, request: Request, response: Response):
    _rate_limit(request)
    if not settings.sso_active:
        raise HTTPException(400, "SSO ist nicht eingerichtet")
    try:
        claims = auth.verify_id_token(body.id_token)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except Exception:  # noqa: BLE001
        log.exception("id_token ungültig")
        raise HTTPException(401, "Anmeldung über Microsoft fehlgeschlagen")
    user = claims.get("preferred_username") or claims.get("upn") or claims.get("email") or claims["sub"]
    token = await auth.create_session(user, claims.get("name") or user, "entra")
    _set_cookie(response, request, token)
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


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    """FastAPIs Standard-422 ({"detail": [Fehler]}), nur ohne zurueckgesendete Geheimnisse (fuer die ganze App): ein Fehler AN einem
    Feld aus SECRET_INPUTS verliert "input" und "ctx" (type, loc, msg bleiben). Jedes andere "input" verliert die Schluessel aus
    SECRET_INPUTS, denn ein "missing"-Fehler traegt den ganzen Body. Ist der ganze Body kein Objekt (loc nur "body"), faellt sein
    "input" weg, er kann alles enthalten. Alle anderen Fehler bleiben, wie FastAPI sie liefert."""
    errors = []
    for err in exc.errors():
        err = dict(err)
        loc = err.get("loc") or ()
        if any(isinstance(part, str) and part in SECRET_INPUTS for part in loc):
            err.pop("input", None)
            err.pop("ctx", None)
        elif "input" in err:
            if isinstance(err["input"], (dict, list)):
                err["input"] = _without_secrets(err["input"])
            elif len(loc) <= 1:
                del err["input"]
        errors.append(err)
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})


def _validate(body: SwitchIn):
    try:
        ipaddress.ip_address(body.host)
    except ValueError:
        if not HOST_RE.fullmatch(body.host):
            raise HTTPException(422, "Adresse ist weder IP noch gültiger Hostname")
    if body.driver not in drivers.DRIVERS:
        raise HTTPException(422, "Unbekannter Treiber")
    for proto in (body.snmp_auth_proto, body.snmp_rw_auth_proto):
        if proto and proto not in snmp.AUTH_PROTOS:
            raise HTTPException(422, "Unbekanntes SNMP-Auth-Verfahren")
    for proto in (body.snmp_priv_proto, body.snmp_rw_priv_proto):
        if proto and proto not in snmp.PRIV_PROTOS:
            raise HTTPException(422, "Unbekanntes SNMP-Verschlüsselungsverfahren")


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


def _update_detail(fields: dict, old) -> str:
    """Audit-Detail eines PUT: die geaenderten Geheimnisse beim Namen (nie mit Wert), dann Treiber und SNMP-Schreiben als "alt → neu",
    wenn sie mitkamen und sich aendern. SNMP-Schreiben einzuschalten ist eine Rechte-Aenderung."""
    parts = [k for k in fields if k in SECRET_FIELDS]
    if "driver" in fields and fields["driver"] != old["driver"]:
        parts.append(f"driver: {old['driver']} → {fields['driver']}")
    if "snmp_write" in fields and bool(fields["snmp_write"]) != bool(old["snmp_write"]):
        parts.append(f"snmp_write: {_on_off(old['snmp_write'])} → {_on_off(fields['snmp_write'])}")
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


@app.put("/api/switches/{sid}")
async def update_switch(sid: int, body: SwitchIn, user=Depends(auth.current_user)):
    _validate(body)
    fields = _columns(body, update=True)
    # Geheimnisse nur ueberschreiben, wenn ein neuer Wert mitkommt ("" = loeschen)
    for k in SECRET_FIELDS:
        v = getattr(body, k)
        if v is not None:
            fields[k] = encrypt(v) if v != "" else None
    sets = ", ".join(f"{k} = ?" for k in fields)
    async with db() as conn:
        async with conn.execute("SELECT driver, snmp_write FROM switches WHERE id = ?", (sid,)) as cur:
            old = await cur.fetchone()    # fuer das Audit: Treiber und SNMP-Schreiben vorher
        if not old:
            raise HTTPException(404, "Switch nicht gefunden")
        cur = await conn.execute(f"UPDATE switches SET {sets} WHERE id = ?", (*fields.values(), sid))
        await conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(404, "Switch nicht gefunden")
    await audit(user["username"], "switch_update", body.host, _update_detail(fields, old))
    return {"ok": True}


@app.delete("/api/switches/{sid}")
async def delete_switch(sid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        cur = await conn.execute("DELETE FROM switches WHERE id = ?", (sid,))
        await conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "Switch nicht gefunden")
    await audit(user["username"], "switch_delete", str(sid))
    return {"ok": True}


async def _row(sid: int):
    async with db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Switch nicht gefunden")
    return row


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
    await _row(sid)
    res = await sshcli.backup_config(sid, "manual")
    await audit(user["username"], "backup", str(sid), json.dumps(res))
    return res


@app.get("/api/switches/{sid}/backups")
async def list_backups(sid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT id, taken_at, sha, trigger, length(content) AS size FROM config_backups WHERE switch_id = ? ORDER BY id DESC LIMIT 200", (sid,)) as cur:
            return [dict(r) for r in await cur.fetchall()]


@app.get("/api/backups/{bid}", response_class=PlainTextResponse)
async def get_backup(bid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT content FROM config_backups WHERE id = ?", (bid,)) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Sicherung nicht gefunden")
    return row["content"]


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
    return "".join(difflib.unified_diff(prev["content"].splitlines(True), cur_row["content"].splitlines(True),
                                        fromfile=f"vorher {prev['taken_at']} UTC", tofile=f"nachher {cur_row['taken_at']} UTC"))


# ── Einstellungen ─────────────────────────────────────────────────────────────
class SettingsIn(BaseModel):
    poll_minutes: int = Field(default=15, ge=5, le=1440)
    opnsense_url: str = Field(default="", max_length=200)
    opnsense_key: str | None = Field(default=None, max_length=200)
    opnsense_secret: str | None = Field(default=None, max_length=200)
    opnsense_verify_tls: bool = False
    radius_server: str = Field(default="", max_length=45)
    radius_key: str | None = Field(default=None, max_length=64)
    pf_url: str = Field(default="", max_length=200)
    pf_user: str = Field(default="", max_length=100)
    pf_pass: str | None = Field(default=None, max_length=200)
    pf_verify_tls: bool = False


@app.get("/api/settings")
async def get_settings(user=Depends(auth.current_user)):
    return {"poll_minutes": int(await get_setting("poll_minutes", "15") or 15),
            "opnsense_url": await get_setting("opnsense_url", "") or "",
            "opnsense_key_set": bool(await get_setting("opnsense_key")),
            "opnsense_secret_set": bool(await get_setting("opnsense_secret")),
            "opnsense_verify_tls": (await get_setting("opnsense_verify_tls", "0")) == "1",
            "radius_server": await get_setting("radius_server", "") or "",
            "radius_key_set": bool(await get_setting("radius_key")),
            "pf_url": await get_setting("pf_url", "") or "",
            "pf_user": await get_setting("pf_user", "") or "",
            "pf_pass_set": bool(await get_setting("pf_pass")),
            "pf_verify_tls": (await get_setting("pf_verify_tls", "0")) == "1"}


@app.put("/api/settings")
async def put_settings(body: SettingsIn, user=Depends(auth.current_user)):
    if body.opnsense_url and not re.fullmatch(r"https?://[A-Za-z0-9.\-:]+(/[\w\-./]*)?", body.opnsense_url):
        raise HTTPException(422, "OPNsense-Adresse ungültig")
    if body.pf_url and not re.fullmatch(r"https?://[A-Za-z0-9.\-:]+(/[\w\-./]*)?", body.pf_url):
        raise HTTPException(422, "PacketFence-Adresse ungültig")
    if body.radius_server:
        try:
            ipaddress.ip_address(body.radius_server)
        except ValueError:
            raise HTTPException(422, "RADIUS-Server muss eine IP-Adresse sein")
    if body.radius_key and not changes.RADIUS_KEY_RE.fullmatch(body.radius_key):
        raise HTTPException(422, "Shared Secret: 8–64 Zeichen, ohne Leerzeichen, Anführungszeichen, Backslash, ? und ~ (die versteht die Switch-CLI nicht)")
    await set_setting("poll_minutes", str(body.poll_minutes))
    await set_setting("radius_server", body.radius_server)
    await set_setting("pf_url", body.pf_url.rstrip("/"))
    await set_setting("pf_user", body.pf_user)
    await set_setting("pf_verify_tls", "1" if body.pf_verify_tls else "0")
    for k in ("radius_key", "pf_pass"):
        v = getattr(body, k)
        if v is not None:
            await set_setting(k, encrypt(v) if v else None)
    await set_setting("opnsense_url", body.opnsense_url.rstrip("/"))
    await set_setting("opnsense_verify_tls", "1" if body.opnsense_verify_tls else "0")
    for k in ("opnsense_key", "opnsense_secret"):
        v = getattr(body, k)
        if v is not None:
            await set_setting(k, encrypt(v) if v else None)
    await _schedule()
    await audit(user["username"], "settings_update")
    return {"ok": True}


@app.post("/api/names/refresh")
async def names_refresh(user=Depends(auth.current_user)):
    return await names_mod.refresh_names()


@app.get("/api/audit")
async def audit_log(user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT ts, username, action, target, detail FROM audit ORDER BY id DESC LIMIT 200") as cur:
            return [dict(r) for r in await cur.fetchall()]


# ── Aenderungen an Ports (Phase 2) ────────────────────────────────────────────
STATUS_LABEL = {"off": "Aus", "protected": "Protected", "known": "Bekannte Geräte", "radius": "RADIUS"}
# Portnamen auf dem SSH-Weg: ProCurve, streng, denn sie stehen in den CLI-Zeilen.
PORT_RE = re.compile(r"^[A-Za-z0-9/]{1,12}$")
# Portnamen auf dem SNMP-Weg: die jedes Herstellers (Gi1/0/1, ge-0/0/1, 1/1/1, Port-channel1, ...), ohne fuehrendes "-". SNMP setzt sie
# nie in einen Befehl ein (es schreibt auf ifIndex / Bridge-Port); der Port muss ausserdem im Live-Read stehen.
SNMP_PORT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$")
_CAP_LABEL = {"snmp_vlan": "VLANs", "snmp_admin": "An/Aus", "snmp_name": "Portnamen", "snmp_poe": "PoE"}
STALE = "Die Vorschau ist veraltet, bitte neu laden"
NO_SSH = "für diesen Switch ist kein SSH-Zugang hinterlegt (Zugang bearbeiten)"
_tasks: set = set()


class PortChange(BaseModel):
    status: str | None = Field(default=None, pattern=r"^(off|protected|known|radius)$")
    untagged: str | None = Field(default=None, pattern=r"^\d{1,4}$")
    tagged_add: list[str] = Field(default_factory=list, max_length=64)
    tagged_remove: list[str] = Field(default_factory=list, max_length=64)
    name: str | None = Field(default=None, max_length=64)
    limit: int | None = Field(default=None, ge=1, le=32)
    guest: str | None = Field(default=None, pattern=r"^\d{0,4}$")


class PlanIn(BaseModel):
    mode: str = Field(default="ports", pattern=r"^(ports|prepare|revert|save)$")
    ports: list[str] = Field(default_factory=list, max_length=200)
    change: PortChange = Field(default_factory=PortChange)
    expert: bool = False
    of: int | None = None
    token: str | None = Field(default=None, max_length=32)
    # Der Schreibweg der Vorschau (die Antwort von /plan nennt ihn), beim Ausfuehren mitgeschickt: dann plant _make_plan genau so oder
    # lehnt ab, nie still ueber den anderen Weg. Ohne ihn waehlt _make_plan selbst.
    mechanism: str | None = Field(default=None, pattern=r"^(ssh|snmp)$")


def _port_list(ports: list[str]) -> str:
    """Die Ports fuer eine Zusammenfassung: ProCurve-Namen zusammengefasst (1-3,7,Trk1); Namen anderer Hersteller (Gi1/0/1, ge-0/0/1,
    ...), an denen cfgparse.compress_ports scheitert, natuerlich sortiert und mit Komma."""
    try:
        return cfgparse.compress_ports(ports)
    except ValueError:
        return ", ".join(sorted(set(ports), key=snmpwrite._port_order))


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
    return f"Port {_port_list(body.ports)}: " + (", ".join(parts) or "–")


# ── Schreibweg waehlen: SSH-CLI oder SNMP ─────────────────────────────────────────────────────────────────────────────────────────────
# Fixiert beim Planen, vor dem ersten Schreibzugriff, nie mitten im Ausfuehren (Spec §5, Q5); plan["mechanism"] nennt ihn.
def needed_ops(body: PlanIn) -> set[str]:
    """Die SNMP-Faehigkeiten des Treibers (drivers.can), die die Anfrage per SNMP braucht: VLANs snmp_vlan, jeder Zustand snmp_admin
    ("Aus" schaltet den Port ab, jeder andere ein), ein Name snmp_name. Das PoE-Feld (Task 12) kommt hier als snmp_poe dazu. Was per
    SNMP gar nicht geht (802.1X / MAC-Anmeldung, Limit, Gast-VLAN), prueft _cli_only."""
    c, ops = body.change, set()
    if c.untagged is not None or c.tagged_add or c.tagged_remove:
        ops.add("snmp_vlan")
    if c.status is not None:
        ops.add("snmp_admin")
    if c.name is not None:
        ops.add("snmp_name")
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
        return f"Treiber {driver.name} kann {_listing([_CAP_LABEL.get(op, op) for op in missing])} nicht per SNMP schreiben"
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


async def _choose_mechanism(row, driver: drivers.Driver, body: PlanIn) -> tuple[str, dict | None, list[str]]:
    """Der Schreibweg einer neuen Aenderung (mode ports oder prepare): ("ssh", cfg aus der running-config, Hinweise) oder ("snmp", None,
    Hinweise); sonst HTTPException.
      1. Schickt der Client einen mechanism mit (das Ausfuehren nach seiner Vorschau), gilt genau der, wenn er noch geht, sonst 409
         STALE: nie still der andere Weg. Was nur die CLI kann, lehnt auch ein mitgeschicktes "snmp" mit seinem eigenen Grund ab.
      2. Treiber mit CLI und SSH-Zugang: SSH, das Lesen der Konfiguration (changes.fresh_cfg) ist der Pre-Flight. Scheitert es, geht die
         Aenderung per SNMP, wenn sie dort geht (mit Hinweis), sonst 502 wie bisher, mit dem Grund, warum SNMP nicht geht.
      3. Sonst SNMP, wenn die Anfrage dort geht, sonst 409 / 422 mit dem Grund (_snmp_refusal), bei einem Treiber mit CLI (dann fehlt
         der SSH-Zugang) nach dem Hinweis auf den SSH-Zugang."""
    ssh_refusal = _ssh_refusal(row, driver)
    if body.mechanism == "ssh":
        if ssh_refusal:
            raise HTTPException(409, f"{STALE} ({ssh_refusal})")
        try:
            return "ssh", await changes.fresh_cfg(row["id"]), []
        except Exception as e:  # noqa: BLE001
            raise HTTPException(409, f"{STALE} (Konfiguration per SSH nicht lesbar: {e})")
    if body.mechanism == "snmp":
        reason = _cli_only(body, driver)
        if reason:
            raise HTTPException(409, reason)
        reason = _snmp_unwritable(row, driver, needed_ops(body))
        if reason:
            raise HTTPException(409, f"{STALE} ({reason})")
        return "snmp", None, []
    if not ssh_refusal:
        try:
            return "ssh", await changes.fresh_cfg(row["id"]), []
        except Exception as e:  # noqa: BLE001
            refusal = _snmp_refusal(row, driver, body)
            if refusal:
                raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {e} (per SNMP geht es auch nicht: {refusal[1]})")
            return "snmp", None, [f"SSH nicht verfügbar ({e}), die Änderung geht per SNMP"]
    refusal = _snmp_refusal(row, driver, body)
    if refusal:
        status, reason = refusal
        if drivers.can(driver, "cli"):
            reason = f"Für Änderungen braucht der Switch einen SSH-Zugang (Zugang bearbeiten). Per SNMP geht es auch nicht: {reason}"
        raise HTTPException(status, reason)
    return "snmp", None, []


async def _read_snmp(row, driver: drivers.Driver) -> tuple[dict, dict]:
    """Der Live-Read per SNMP (snmpwrite.read_cfg) im Change-Lock des Switches, wie der SSH-Weg seine Konfiguration im selben Lock liest:
    nie mitten in eine laufende Aenderung hinein. read_cfg faellt geschlossen aus, das wird 502 mit dem Grund."""
    try:
        async with sshcli.lock(row["id"]):
            return await snmpwrite.read_cfg(row, driver)
    except (snmp.SnmpError, OSError) as e:
        raise HTTPException(502, f"Konfiguration des Switches per SNMP nicht lesbar: {e}")


def _check_request(body: PlanIn, port_re: re.Pattern):
    for p in body.ports:
        if not port_re.fullmatch(p):
            raise HTTPException(422, f"Port ungültig: {p}")
    for v in body.change.tagged_add + body.change.tagged_remove:
        if not re.fullmatch(r"\d{1,4}", v):
            raise HTTPException(422, f"VLAN ungültig: {v}")


async def _make_plan(row, body: PlanIn) -> tuple[dict, dict, str, str]:
    """-> (plan, request fuer run_change, kind, summary). plan["mechanism"] ist der Schreibweg, "ssh" oder "snmp"."""
    driver = drivers.driver_for(row)
    if body.mode in ("revert", "save"):
        return await _plan_of_change(row, driver, body)
    mech, cfg, notes = await _choose_mechanism(row, driver, body)
    if mech == "snmp":
        return await _plan_snmp(row, driver, body, notes)
    if body.mode == "prepare":
        plan = changes.plan_prepare(cfg, await changes.radius_settings())
        return plan | {"mechanism": "ssh"}, {}, "prepare", "RADIUS vorbereiten"
    _check_request(body, PORT_RE)
    req = {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}
    try:
        plan = changes.plan_ports(row["firmware"] or "", await changes.inventory(row["id"]), cfg, req)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return plan, req, "ports", _summary(body)


async def _plan_snmp(row, driver: drivers.Driver, body: PlanIn, notes: list[str]) -> tuple[dict, dict, str, str]:
    """Eine neue Port-Aenderung per SNMP (_choose_mechanism hat schon abgelehnt, was dort nicht geht): gegen einen Live-Read geplant,
    jeder Port muss in ihm stehen. notes kommen vor die Warnungen des Plans."""
    _check_request(body, SNMP_PORT_RE)
    cfg, raw = await _read_snmp(row, driver)
    missing = [p for p in body.ports if p not in cfg["ports"]]
    if missing:
        raise HTTPException(422, f"Port gibt es auf diesem Switch nicht: {', '.join(missing)}")
    req = {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}
    try:
        plan = changes.plan_ports(row["firmware"] or "", await changes.inventory(row["id"]), cfg, req, mechanism="snmp", driver=driver,
                                  raw=raw)
    except ValueError as e:
        raise HTTPException(422, str(e))
    plan["warnings"] = notes + plan["warnings"]
    return plan, req, "ports", _summary(body)


async def _plan_of_change(row, driver: drivers.Driver, body: PlanIn) -> tuple[dict, dict, str, str]:
    """Rueckgaengig (revert) und Speichern (save) einer Aenderung, auf dem Weg der Aenderung selbst (changes.mechanism; NULL heisst ssh,
    eine Zeile von vor der Spalte) und nie auf einem anderen: before einer SNMP-Aenderung haelt etwa die PVID (R21), die der SSH-Weg
    nicht kennt. Geht dieser Weg gerade nicht, 409 mit dem Grund. Gespeichert wird nur per SSH (write memory): SNMP-Sets speichert der
    Switch selbst."""
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
        if mech == "snmp":
            raise HTTPException(409, "SNMP-Änderungen werden sofort gespeichert, Speichern ist nicht nötig")
        if ch["status"] not in ("unclear", "failed") or ch["saved"]:
            raise HTTPException(409, "Diese Änderung muss nicht gespeichert werden")
    elif ch["kind"] != "ports" or ch["reverted_by"] or ch["status"] in ("queued", "running", "aborted"):
        raise HTTPException(409, "Diese Änderung lässt sich nicht zurücknehmen")
    reason = _snmp_unwritable(row, driver, set()) if mech == "snmp" else _ssh_refusal(row, driver)
    if reason:
        label = mech.upper()
        raise HTTPException(409, f"Änderung #{ch['id']} lief per {label} und lässt sich nur per {label} "
                                 f"{'speichern' if body.mode == 'save' else 'zurücknehmen'}: {reason}")
    if mech == "snmp":
        cfg, raw = await _read_snmp(row, driver)
        way = {"mechanism": "snmp", "driver": driver, "raw": raw}    # die Schluesselwoerter von plan_ports fuer diesen Weg
    else:
        try:
            cfg = await changes.fresh_cfg(row["id"])
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {e}")
        if body.mode == "save":
            plan = {"commands": [], "shown": [], "blocked": [], "mechanism": "ssh",
                    "warnings": ["Speichert den aktuellen Stand des Switches dauerhaft (write memory)."]}
            return plan, {"of": ch["id"]}, "save", f"Speichern nach #{ch['id']}"
        way = {}
    req = {"desired": json.loads(ch["before"] or "{}"), "expert": bool(ch["expert"])}
    try:
        plan = changes.plan_ports(row["firmware"] or "", await changes.inventory(row["id"]), cfg, req, **way)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return plan, req, "ports", f"Rückgängig #{ch['id']}: {ch['summary']}"


@app.post("/api/switches/{sid}/plan")
async def plan_change(sid: int, body: PlanIn, user=Depends(auth.current_user)):
    row = await _row(sid)
    plan, _, kind, summary = await _make_plan(row, body)
    return {"kind": kind, "summary": summary, "mechanism": plan["mechanism"], "commands": plan["shown"], "warnings": plan.get("warnings", []),
            "blocked": plan["blocked"], "before": plan.get("before", {}), "desired": plan.get("desired", {}),
            "token": changes.cmd_token(plan["shown"])}


@app.post("/api/switches/{sid}/apply")
async def apply_change(sid: int, body: PlanIn, user=Depends(auth.current_user)):
    row = await _row(sid)
    async with db() as conn:
        async with conn.execute("SELECT id FROM changes WHERE switch_id = ? AND status IN ('queued', 'running')", (sid,)) as cur:
            if await cur.fetchone():
                raise HTTPException(409, "An diesem Switch läuft gerade eine Änderung")
    plan, req, kind, summary = await _make_plan(row, body)
    if plan["blocked"]:
        raise HTTPException(409, "Nicht ausführbar: " + "; ".join(f"{b['port']}: {b['reason']}" for b in plan["blocked"]))
    if body.token != changes.cmd_token(plan["shown"]):
        raise HTTPException(409, "Die Vorschau ist veraltet, bitte neu laden")
    if not plan["shown"] and kind != "save":
        raise HTTPException(422, "Es gibt nichts zu ändern")
    cid = await changes.create_change(sid, user["username"], kind, summary, req, plan,
                                      revert_of=body.of if body.mode == "revert" else None)
    if body.mode == "revert":
        async with db() as conn:
            await conn.execute("UPDATE changes SET reverted_by = ? WHERE id = ?", (cid, body.of))
            await conn.commit()
    t = asyncio.create_task(changes.run_change(cid))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return {"id": cid}


def _change_out(r) -> dict:
    d = dict(r)
    for k in ("ports", "desired", "before", "commands", "steps"):
        d[k] = json.loads(d[k] or ("[]" if k in ("ports", "commands", "steps") else "{}"))
    d.pop("request", None)
    return d


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
            return [_change_out(r) for r in await cur.fetchall()]


@app.get("/api/changes/{cid}")
async def get_change(cid: int, user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT c.*, s.name AS switch_name FROM changes c JOIN switches s ON s.id = c.switch_id WHERE c.id = ?", (cid,)) as cur:
            r = await cur.fetchone()
    if not r:
        raise HTTPException(404, "Änderung nicht gefunden")
    return _change_out(r)


@app.post("/api/switches/{sid}/config/refresh")
async def refresh_config(sid: int, user=Depends(auth.current_user)):
    await _row(sid)
    res = await sshcli.backup_config(sid, "lesen")
    if not res.get("ok"):
        raise HTTPException(502, res.get("error") or "Lesen fehlgeschlagen")
    return res


@app.post("/api/switches/{sid}/port-access")
async def port_access(sid: int, user=Depends(auth.current_user)):
    row = await _row(sid)
    if not row["ssh_user"] or not row["ssh_pass"]:
        raise HTTPException(422, "Kein SSH-Zugang hinterlegt")
    cmds = ["show port-access authenticator", "show port-access authenticator clients", "show port-access mac-based clients"]
    try:
        out = await sshcli.run_shows(row, cmds)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"{type(e).__name__}: {str(e)[:200]}")
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
    valid_until: str | None = Field(default=None, pattern=r"^(\d{4}-\d{2}-\d{2})?$")


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


@app.get("/api/devices/unknown")
async def unknown_devices(user=Depends(auth.current_user)):
    m = await build_map()
    known = set()
    async with db() as conn:
        async with conn.execute("SELECT mac FROM devices") as cur:
            known = {r["mac"] for r in await cur.fetchall()}
    base = {s["baseMac"] for s in m["switches"]}
    out = []
    for s in m["switches"]:
        for p in s["ports"]:
            # Uplinks, Trunks und Ports mit LLDP-Nachbar (APs, Telefone mit PC) auslassen: dort lernt der Switch fremde MACs
            if p["n"].startswith("Trk") or p["tr"] or p.get("up") or p["l"] or p["mc"] > 4:
                continue
            for d in p["d"]:
                if d[0] in known or d[0] in base:
                    continue
                out.append({"mac": d[0], "vlan": d[1], "ip": d[2], "name": d[3], "vendor": d[4], "sw": s["k"], "port": p["n"], "st": p["st"]})
    return out[:500]


async def _save_device(body: DeviceIn, user: str, mac: str, create: bool):
    vu = body.valid_until or None
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
    return await _save_device(body, user["username"], norm_mac(mac), False)


@app.delete("/api/devices/{mac}")
async def delete_device(mac: str, user=Depends(auth.current_user)):
    mac = norm_mac(mac)
    try:
        await pf.unregister(mac)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"In PacketFence nicht zurückgenommen ({e}). Gerät bleibt erhalten.")
    async with db() as conn:
        cur = await conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))
        await conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "Gerät nicht gefunden")
    await audit(user["username"], "device_delete", mac)
    return {"ok": True}


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
        async with conn.execute("SELECT switch_id, taken_at, parsed FROM switch_cfg") as cur:
            cfgs = {r["switch_id"]: (r["taken_at"], json.loads(r["parsed"])) for r in await cur.fetchall()}

    vlans: dict[str, str] = {}
    vl_by: dict[int, list[str]] = defaultdict(list)
    for v in sorted(vrows, key=lambda r: int(r["vid"])):
        vlans.setdefault(v["vid"], v["name"])
        vl_by[v["switch_id"]].append(v["vid"])
    devs: dict[tuple, list] = defaultdict(list)
    for m in mrows:
        known = 0 if m["dname"] is None else (2 if m["allowed"] else 1)
        devs[(m["switch_id"], m["port"])].append([m["mac"], m["vlan"], m["ip"] or "", m["dname"] or m["name"] or "",
                                                  m["vendor"] or names_mod.vendor_of(m["mac"]), known])
    ports_by: dict[int, list] = defaultdict(list)
    for p in prows:
        key = (p["switch_id"], p["trunk"] or p["name"])
        d = sorted(devs.get(key, []), key=lambda x: -x[5])
        cfg = cfgs.get(p["switch_id"], (None, None))[1]
        st = cfgparse.port_state(cfg, p["name"]) if cfg else None
        ports_by[p["switch_id"]].append({
            "st": changes.status_of(st) if st else ("off" if not p["admin"] else ""),
            "lim": ((st["cl"] if st["x"] else None) or (st["al"] if st["m"] else None)) if st else None,
            "n": p["name"], "a": p["alias"] or "", "o": bool(p["oper"]), "ad": bool(p["admin"]), "s": p["speed"] or 0,
            "pv": p["pvid"] or "", "u": json.loads(p["untagged"] or "[]"), "t": json.loads(p["tagged"] or "[]"),
            "tr": p["trunk"] or "", "mb": json.loads(p["members"] or "[]"), "l": json.loads(p["lldp"] or "[]"),
            "mc": p["mac_count"], "d": d[:12]})

    sw_name = {s["id"]: s["name"] for s in sws}
    all_macs = defaultdict(set)  # (switch_name, port) -> alle MACs, fuer die Link-Erkennung
    for m in mrows:
        if m["switch_id"] in sw_name:
            all_macs[(sw_name[m["switch_id"]], m["port"])].add(m["mac"])
    switches = []
    for s in sws:
        switches.append({"k": s["name"], "id": s["id"], "sys": s["sys_name"] or "", "model": s["model"] or "", "fw": s["firmware"] or "",
                         "zone": s["zone"] or "", "host": s["host"], "lastPoll": s["last_poll"], "ok": bool(s["last_poll_ok"]),
                         "error": s["last_error"] or "", "baseMac": s["base_mac"] or "", "ports": ports_by.get(s["id"], []),
                         "ssh": bool(s["ssh_user"] and s["ssh_pass"]), "driver": s["driver"], "caps": sorted(drivers.driver_for(s).caps),
                         "snmp_write": bool(s["snmp_write"]), "cfgAt": cfgs.get(s["id"], (None, None))[0],
                         "ready": changes.readiness(cfgs[s["id"]][1], server or None) if s["id"] in cfgs else None,
                         "limitMax": changes.limit_max(s["firmware"] or ""), "vl": vl_by.get(s["id"], [])})
    links = _links(switches, all_macs)
    for l in links:  # Uplink-Ports markieren (inkl. Trunk-Mitglieder)
        for k, side in ((l["a"], l["A"]), (l["b"], l["B"])):
            ups = set(side["ports"]) | ({side["trunk"]} if side["trunk"] else set())
            for p in next(x for x in switches if x["k"] == k)["ports"]:
                if p["n"] in ups or (p["tr"] and p["tr"] in ups):
                    p["up"] = True
    return {"generated": datetime.now(timezone.utc).isoformat(), "vlans": vlans, "switches": switches, "links": links}


def _links(switches: list[dict], all_macs: dict) -> list[dict]:
    by_name = {s["k"]: s for s in switches}
    sys2 = {}
    for s in switches:
        sys2[s["sys"]] = s["k"]; sys2[s["k"]] = s["k"]
    base2 = {s["baseMac"]: s["k"] for s in switches if s["baseMac"]}

    def port(k, n):
        return next((p for p in by_name[k]["ports"] if p["n"] == n), None)

    pairs: dict[tuple, str] = {}
    lldp_ports = set()
    for s in switches:
        for p in s["ports"]:
            if p["n"].startswith("Trk"):
                continue
            for nsys, nport in p["l"]:
                nk = sys2.get(nsys)
                np_ = port(nk, nport.strip()) if nk else None
                if nk and nk != s["k"] and np_:
                    pairs[tuple(sorted([(s["k"], p["n"]), (nk, nport.strip())]))] = "lldp"
                    for kk, pp in ((s["k"], p), (nk, np_)):
                        lldp_ports.add((kk, pp["n"]))
                        if pp["tr"]:
                            lldp_ports.add((kk, pp["tr"]))
    # Ohne LLDP: Port, an dem die Basis-MAC eines anderen Switches gelernt wird, und umgekehrt
    seen_at: dict[tuple, str] = {}
    for (k, pname), macset in all_macs.items():
        for mac in macset:
            other = base2.get(mac)
            if other and other != k:
                seen_at[(k, other)] = pname
    for (a, b), pa in seen_at.items():
        pb = seen_at.get((b, a))
        if not pb or a > b:
            continue
        if (a, pa) in lldp_ports or (b, pb) in lldp_ports:
            continue
        if any({a, b} == {x[0][0], x[1][0]} for x in pairs):
            continue
        pairs[tuple(sorted([(a, pa), (b, pb)]))] = "mac"

    groups: dict[tuple, dict] = {}
    for (x, y), src in pairs.items():
        key = tuple(sorted([x[0], y[0]]))
        g = groups.setdefault(key, {"a": key[0], "b": key[1], "ap": [], "bp": [], "src": src})
        px, py = (x, y) if x[0] == key[0] else (y, x)
        g["ap"].append(px[1]); g["bp"].append(py[1])
    out = []
    for g in groups.values():
        def side(k, plist):
            ps = [port(k, n) for n in plist if port(k, n)]
            trk = sorted({p["tr"] for p in ps if p["tr"]})
            rep = port(k, trk[0]) if trk else (ps[0] if ps else None)
            return {"ports": sorted(plist, key=lambda v: int(v) if v.isdigit() else 999), "trunk": trk[0] if trk else "",
                    "u": rep["u"] if rep else [], "t": rep["t"] if rep else [], "speed": rep["s"] if rep else 0}
        A, B = side(g["a"], g["ap"]), side(g["b"], g["bp"])
        va, vb = set(A["u"]) | set(A["t"]), set(B["u"]) | set(B["t"])
        out.append({"a": g["a"], "b": g["b"], "A": A, "B": B, "src": g["src"], "onlyA": sorted(va - vb, key=int),
                    "onlyB": sorted(vb - va, key=int), "native": sorted(set(A["u"]) ^ set(B["u"]), key=int)})
    return out
