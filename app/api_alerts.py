"""The alert routes (Phase 4b, Task 6): the settings of the two channels (GET and PUT /api/settings/alerts), the test button (POST
/api/alerts/test) and the list of deliveries (GET /api/alerts/deliveries). Queue, delivery and texts are app/alerts.py.

Admin only, reading too: the recipients are addresses of people, and only an Admin can act on what the list shows. The SMTP password
and the webhook URL are secrets bound to their destination like those of PUT /api/settings (api_settings.put_settings): stored
encrypted, a value of None leaves them, "" deletes them, a new mail server deletes a stored password the PUT does not bring anew
(Phase 2 E8); neither is ever served, logged or audited, and a 422 never echoes them (api_switches.SECRET_INPUTS).
"""
import ipaddress
import json
import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import alerts
import auth
import roles
from api_switches import same_destination
from crypto import encrypt
from db import audit, db, load_settings, read_settings, write_settings

router = APIRouter()

ROW_ID_MAX = 2 ** 63 - 1    # the largest id SQLite stores: a larger cursor would fail in the query, not as a 422

# A mail server: an IP address, or a host name of labels of letters, digits and "-" between dots
HOST_LABELS = re.compile(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*")
# A mail address as SwitchView takes it: one "@", a dot after it, no space, no <>",; (a display name or a list is no address)
ADDRESS = re.compile(r'^[^@\s<>",;]+@[^@\s<>",;]+\.[^@\s<>",;]+$')
WEBHOOK_URL = re.compile(r"^https?://[^\s/?#]+[^\s]*$")

BAD_HOST = "Mailserver: Name oder IP-Adresse ungültig"
BAD_ADDRESS = "Mail-Adresse ungültig: {}"
NO_LOGIN_IN_CLEAR = "Ohne TLS meldet sich SwitchView nicht am Mailserver an: das Kennwort ginge im Klartext übers Netz"
MAIL_NEEDS = "Mail einschalten braucht {}"
BAD_WEBHOOK = "Webhook-Adresse muss mit http:// oder https:// beginnen"
WEBHOOK_NEEDS = "Webhook einschalten braucht eine Webhook-Adresse"
UNKNOWN_EVENT = "Unbekanntes Ereignis: {}"


class AlertSettingsIn(BaseModel):
    """The whole alert settings (a field not sent takes its default, as in PUT /api/settings). smtp_pass and webhook_url: None leaves
    the stored one, "" deletes it."""
    mail_on: bool = False
    smtp_host: str = Field(default="", max_length=253)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_security: str = Field(default="starttls", pattern=r"^(starttls|tls|none)$")
    smtp_verify_tls: bool = True
    smtp_user: str = Field(default="", max_length=200)
    smtp_pass: str | None = Field(default=None, max_length=200)
    mail_from: str = Field(default="", max_length=254)
    mail_to: list[Annotated[str, Field(max_length=254)]] = Field(default_factory=list, max_length=20)
    mail_events: list[Annotated[str, Field(max_length=40)]] = Field(default_factory=lambda: list(alerts.DEFAULT_EVENTS), max_length=20)
    hook_on: bool = False
    webhook_url: str | None = Field(default=None, max_length=2000)
    hook_format: str = Field(default="teams", pattern=r"^(teams|json)$")
    hook_verify_tls: bool = True
    hook_events: list[Annotated[str, Field(max_length=40)]] = Field(default_factory=lambda: list(alerts.DEFAULT_EVENTS), max_length=20)


def _host_ok(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOST_LABELS.fullmatch(host))


def _checked(body: AlertSettingsIn, old: dict) -> dict:
    """The values PUT stores, trimmed, after the checks (422 with the German text, nothing stored): a mail server set that is no IP
    address and no host name; a sender or recipient that is no address (blank recipients are dropped); a login without TLS; mail on
    without a server, a sender or a recipient; a new webhook URL that is not http(s)://; the webhook on without a URL stored or new;
    an event that is not one of alerts.EVENTS. The events are stored in the order of EVENTS, each once."""
    host, user, sender = body.smtp_host.strip(), body.smtp_user.strip(), body.mail_from.strip()
    recipients = [a.strip() for a in body.mail_to if a.strip()]
    url = None if body.webhook_url is None else body.webhook_url.strip()
    if host and not _host_ok(host):
        raise HTTPException(422, BAD_HOST)
    for address in ([sender] if sender else []) + recipients:
        if not ADDRESS.fullmatch(address):
            raise HTTPException(422, BAD_ADDRESS.format(address))
    if body.smtp_security == "none" and user:
        raise HTTPException(422, NO_LOGIN_IN_CLEAR)
    missing = [what for what, have in (("den Mailserver", host), ("einen Absender", sender), ("mindestens einen Empfänger", recipients))
               if not have]
    if body.mail_on and missing:
        raise HTTPException(422, MAIL_NEEDS.format(", ".join(missing)))
    if url and not WEBHOOK_URL.fullmatch(url):
        raise HTTPException(422, BAD_WEBHOOK)
    if body.hook_on and not (url if url is not None else old["webhook_url"]):
        raise HTTPException(422, WEBHOOK_NEEDS)
    for event in body.mail_events + body.hook_events:
        if event not in alerts.EVENTS:
            raise HTTPException(422, UNKNOWN_EVENT.format(event))
    flag = {True: "1", False: "0"}
    return {"mail_on": flag[body.mail_on], "smtp_host": host, "smtp_port": str(body.smtp_port), "smtp_security": body.smtp_security,
            "smtp_verify_tls": flag[body.smtp_verify_tls], "smtp_user": user, "mail_from": sender, "mail_to": json.dumps(recipients),
            "mail_events": json.dumps([e for e in alerts.EVENTS if e in body.mail_events]), "hook_on": flag[body.hook_on],
            "hook_format": body.hook_format, "hook_verify_tls": flag[body.hook_verify_tls],
            "hook_events": json.dumps([e for e in alerts.EVENTS if e in body.hook_events]),
            **{k: (encrypt(v) if v else None) for k, v in (("smtp_pass", body.smtp_pass), ("webhook_url", url)) if v is not None}}


@router.get("/api/settings/alerts")
async def get_alert_settings(user=Depends(auth.require(roles.ADMIN))):
    """The alert settings without a secret (alerts.public_view), in one SELECT (db.load_settings)."""
    return alerts.public_view(await load_settings(alerts.SETTINGS_KEYS))


@router.put("/api/settings/alerts")
async def put_alert_settings(body: AlertSettingsIn, user=Depends(auth.require(roles.ADMIN))):
    """Stores the alert settings in one write transaction (BEGIN IMMEDIATE, as put_settings): the checks of _checked, a new mail
    server (same_destination false) deletes a stored password the PUT does not carry ("cleared"), a channel that is off fails its
    queued messages (alerts.drop_queued, "dropped"). The audit names on/off, server, port, security, the number of recipients and the
    format, a new webhook address, the secrets deleted and the messages dropped - never a secret, never the URL."""
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        old = await read_settings(conn, alerts.SETTINGS_KEYS)
        new = _checked(body, old)
        cleared = []
        for dest, keys in alerts.DESTINATION_SECRETS.items():
            if not same_destination(old[dest], new[dest]):
                for k in keys:
                    if old[k] and getattr(body, k) is None:
                        new[k] = None
                        cleared.append(k)
        deleted = [k for k in alerts.SECRETS if old[k] and k in new and new[k] is None]
        await write_settings(conn, new)
        dropped = 0
        for channel, on in (("mail", body.mail_on), ("webhook", body.hook_on)):
            if not on:
                dropped += await alerts.drop_queued(conn, channel)
        await conn.commit()
    detail = (f"Mail: {'an' if body.mail_on else 'aus'}, {new['smtp_host'] or '–'}:{body.smtp_port} ({body.smtp_security}), "
              f"{len(json.loads(new['mail_to']))} Empfänger; Webhook: {'an' if body.hook_on else 'aus'}, {body.hook_format}")
    if new.get("webhook_url"):
        detail += ", Webhook-Adresse neu"
    if deleted:
        detail += f"; gelöscht: {', '.join(deleted)}"
    if dropped:
        detail += f"; {dropped} wartende {'Meldung' if dropped == 1 else 'Meldungen'} verworfen"
    await audit(user["username"], "alert_settings", "", detail, role=user["role"])
    return {"ok": True, "cleared": cleared, "dropped": dropped}


class AlertTestIn(BaseModel):
    channel: str = Field(pattern=r"^(mail|webhook)$")


@router.post("/api/alerts/test")
async def send_test_alert(body: AlertTestIn, user=Depends(auth.require(roles.ADMIN))):
    """A test message now over the stored channel, without the queue (alerts.send_test): {"ok", "error"}; audited with the channel
    and "ok" or the error text."""
    result = await alerts.send_test(body.channel)
    await audit(user["username"], "alert_test", body.channel, "ok" if result["ok"] else result["error"], role=user["role"])
    return result


@router.get("/api/alerts/deliveries")
async def list_deliveries(status: str | None = Query(default=None, pattern=r"^(queued|sent|failed|suppressed)$"),
                          cursor: int | None = Query(default=None, ge=1, le=ROW_ID_MAX), limit: int = Query(default=20, ge=1, le=100),
                          user=Depends(auth.require(roles.ADMIN))):
    """One page of the messages, newest first, of one status if given, before the id cursor (alerts.deliveries): {"rows", "next"}."""
    return await alerts.deliveries(status=status, cursor=cursor, limit=limit)
