"""The switches API: the drivers, the switches (create, update, delete, SSH host key, connection test, poll), reading the
running-config and the port-access shows over the SSH CLI, and the backups. Split from main.py (Phase 3, Task 11), the code as it
was; main includes the router and re-exports the names the tests reach as main.X."""
import difflib
import ipaddress
import json
import re
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

import auth
import cfgparse
import drivers
import poller
import roles
import snmp
import sshcli
from crypto import encrypt
from db import audit, db

router = APIRouter()


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
# The fields of a request whose value a 422 answer never sends back (pydantic puts it into "input"): the secrets of the switches and
# those of the other forms (login, settings, and since Phase 4b the alerts: the SMTP password and the webhook URL with its token).
SECRET_INPUTS = frozenset(SECRET_FIELDS) | {"password", "id_token", "opnsense_key", "opnsense_secret", "radius_key", "pf_pass", "smtp_pass",
                                            "webhook_url"}


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


def _insecurity(cred: dict) -> str | None:
    """How a SET with the write identity cred would go out spoofable: "v2c" (the community in plain text), "v3" (SNMPv3 without
    authentication: auth protocol or auth password missing), None when it is authenticated."""
    if cred["snmp_version"] != "3":
        return "v2c"
    if not (cred["snmp_auth_proto"] and cred["snmp_auth_pass"]):
        return "v3"
    return None


def write_insecurity(row) -> str | None:
    """_insecurity of the identity SNMP SETs to this switch go out with (poller.write_identity), None when SNMP cannot write here.
    The /plan answer names it for a change over SNMP (insecure_write)."""
    try:
        return _insecurity(poller.write_identity(row)[1])
    except snmp.SnmpError:
        return None


def _write_info(row) -> dict:
    """Mit welcher Identitaet SNMP-SETs an diesen Switch gingen, ohne ein Geheimnis, aus poller.write_identity: snmp_write_via "rw"
    (die eigene RW-Identitaet) oder "read" (die Lese-Identitaet, sie muss am Geraet schreiben duerfen), sonst None und der Grund in
    snmp_write_error; snmp_rw_insecure, wenn der SET faelschbar hinausginge (v2c-Community im Klartext, v3 ohne Authentifizierung)."""
    try:
        via, cred = poller.write_identity(row)
    except snmp.SnmpError as e:
        return {"snmp_write_via": None, "snmp_write_error": str(e), "snmp_rw_insecure": False}
    return {"snmp_write_via": via, "snmp_write_error": None, "snmp_rw_insecure": _insecurity(cred) is not None}


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


@router.get("/api/drivers")
async def list_drivers(user=Depends(auth.require(roles.LESEN))):
    """Die Treiber fuer die Auswahl im Switch-Formular, in der Reihenfolge von drivers.DRIVERS: Name, Faehigkeiten (sortiert), Hinweise."""
    return [{"name": d.name, "caps": sorted(d.caps), "notes": d.notes} for d in drivers.DRIVERS.values()]


@router.get("/api/switches")
async def list_switches(user=Depends(auth.require(roles.LESEN))):
    async with db() as conn:
        async with conn.execute("SELECT * FROM switches ORDER BY zone, sort, name") as cur:
            rows = await cur.fetchall()
    return [_public(r) for r in rows]


@router.post("/api/switches")
async def create_switch(body: SwitchIn, user=Depends(auth.require(roles.ADMIN))):
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
    await audit(user["username"], "switch_create", body.host, f"{body.name}, driver: {body.driver}, snmp_write: {_on_off(body.snmp_write)}",
                role=user["role"])
    return {"id": sid}


def same_destination(old: str | None, new: str | None) -> bool:
    """Whether old and new name the same destination of a secret (a switch's host, a URL or the RADIUS server of the settings): the
    same IP address when both parse as one, otherwise the same text ignoring case, surrounding whitespace and a trailing "/". Another
    spelling is no new destination (E9)."""
    try:
        return ipaddress.ip_address(old or "") == ipaddress.ip_address(new or "")
    except ValueError:
        return (old or "").strip().rstrip("/").casefold() == (new or "").strip().rstrip("/").casefold()


@router.put("/api/switches/{sid}")
async def update_switch(sid: int, body: SwitchIn, user=Depends(auth.require(roles.ADMIN))):
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
    await audit(user["username"], "switch_update", body.host, _update_detail(fields, old), role=user["role"])
    return {"ok": True, "cleared": cleared}


@router.delete("/api/switches/{sid}")
async def delete_switch(sid: int, user=Depends(auth.require(roles.ADMIN))):
    async with db() as conn:
        cur = await conn.execute("DELETE FROM switches WHERE id = ?", (sid,))
        await conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "Switch nicht gefunden")
    await audit(user["username"], "switch_delete", str(sid), role=user["role"])
    return {"ok": True}


@router.delete("/api/switches/{sid}/ssh-host-key")
async def forget_ssh_host_key(sid: int, user=Depends(auth.require(roles.ADMIN))):
    """Forgets the pinned SSH host key of the switch: its next SSH contact pins the key it is then offered (E30). Only for a key that
    changed as expected (replacement, new firmware); the audit keeps the old SHA256. Admin only (Sicherheit Phase 2 T2-R1): whoever
    forgets the key decides which key the next contact trusts."""
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute("SELECT host, ssh_host_key FROM switches WHERE id = ?", (sid,)) as cur:
            old = await cur.fetchone()
        if not old:
            raise HTTPException(404, "Switch nicht gefunden")    # closing the connection rolls the transaction back
        await conn.execute("UPDATE switches SET ssh_host_key = NULL, ssh_host_key_at = NULL WHERE id = ?", (sid,))
        await conn.commit()
    fp = sshcli.fingerprints(old["ssh_host_key"])
    await audit(user["username"], "switch_hostkey_reset", old["host"], fp["sha256"] if fp else "–", role=user["role"])
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


@router.post("/api/switches/{sid}/test")
async def test_switch(sid: int, user=Depends(auth.require(roles.LESEN))):
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


@router.post("/api/switches/{sid}/poll")
async def poll_now(sid: int, user=Depends(auth.require(roles.LESEN))):
    await _row(sid)
    return await poller.poll_switch(sid)


@router.post("/api/poll")
async def poll_everything(user=Depends(auth.require(roles.LESEN))):
    await poller.poll_all()
    return {"ok": True}


@router.post("/api/switches/{sid}/config/refresh")
async def refresh_config(sid: int, user=Depends(auth.require(roles.LESEN))):
    _cli_way(await _row(sid), "cli", "Konfiguration lesen")
    res = await sshcli.backup_config(sid, "lesen")
    if not res.get("ok"):
        raise HTTPException(502, res.get("error") or "Lesen fehlgeschlagen")
    return res


@router.post("/api/switches/{sid}/port-access")
async def port_access(sid: int, user=Depends(auth.require(roles.LESEN))):
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


# ── Sicherungen ───────────────────────────────────────────────────────────────
@router.post("/api/switches/{sid}/backup")
async def backup_now(sid: int, user=Depends(auth.require(roles.LESEN))):
    _cli_way(await _row(sid), "backup", "Konfiguration sichern")
    res = await sshcli.backup_config(sid, "manual")
    await audit(user["username"], "backup", str(sid), json.dumps(res), role=user["role"])
    return res


@router.get("/api/switches/{sid}/backups")
async def list_backups(sid: int, user=Depends(auth.require(roles.LESEN))):
    """The switch's last 200 backups, newest first; outside (Phase 4b) 1 for one that differs from the one before without a SwitchView
    change between them, 0 with one, null where it was not compared (monitor.backup_outside)."""
    async with db() as conn:
        async with conn.execute("SELECT id, taken_at, sha, trigger, length(content) AS size, outside FROM config_backups WHERE switch_id = ? "
                                "ORDER BY id DESC LIMIT 200", (sid,)) as cur:
            return [dict(r) for r in await cur.fetchall()]


# A backup is served masked with today's patterns, also one stored before them; the stored rows stay as they are (E26)
@router.get("/api/backups/{bid}", response_class=PlainTextResponse)
async def get_backup(bid: int, user=Depends(auth.require(roles.LESEN))):
    async with db() as conn:
        async with conn.execute("SELECT content FROM config_backups WHERE id = ?", (bid,)) as cur:
            row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Sicherung nicht gefunden")
    return cfgparse.mask_secrets(row["content"])


# What the diff of a backup says when its masked text equals the one before: only what masking hides changed, a secret (sshcli.store_backup
# keeps such a backup, its raw_mac tells it apart)
SECRET_ONLY_DIFF = "Nur maskierte Geheimnisse haben sich geändert – der Vergleich zeigt sie nicht.\n"


@router.get("/api/backups/{bid}/diff", response_class=PlainTextResponse)
async def diff_backup(bid: int, user=Depends(auth.require(roles.LESEN))):
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
