"""Alerts by mail (SMTP) and webhook (Microsoft Teams or plain JSON), through a queue in the database (Phase 4b, Task 6). Without
FastAPI; the routes are app/api_alerts.py.

The way of a message: a source (a poll, a backup, a change, a four-eyes request, the watch list; Task 7, the section "Sources"
below) calls emit, which only writes rows of alert_outbox - one per channel that is on and wants the event - and never waits for a
delivery. Within DEDUP_MINUTES the same event
with the same key on the same channel is counted on its row (repeats), not queued again; a channel takes at most CAP_PER_HOUR rows
an hour, the rest are stored as suppressed, with one summary ("Zu viele Meldungen") queued in their place. The scheduler job
deliver_due (every 30 seconds, jobs._schedule) takes up to BATCH queued rows that are due and makes one attempt each through _send:
a mail through smtplib in a thread, a webhook through httpx. A success is sent; a failure counts in attempts and waits BACKOFF_S
before the next attempt, and after MAX_ATTEMPTS it is failed and audited (alert_failed). A channel that is off or incomplete by
then fails its rows at once. Rows survive a restart; delivered, failed and suppressed ones are purged after HISTORY_DAYS
(history.RETAINED).

What never goes out: the SMTP password and the webhook URL (the URL of a Teams workflow is its key). Both are stored encrypted
(crypto), served only as *_set and, of the URL, its scheme and host (public_view), never written to the audit or a log: httpx logs
every answered request with its whole URL at INFO, so its logger "httpx" is set to WARNING when this module loads (main sets the
root logger to INFO, and the container log shows it). An error text is made from a status or a type (error_text), never from str()
of an httpx error (it names the URL), and goes through the mask with both secrets. A title is one line (no header injection into
the mail's Subject); a Teams card escapes Markdown, so text from the network (a port description "[x](https://...)") never becomes
a link.
"""
import asyncio
import email.message
import email.utils
import json
import logging
import re
import smtplib
import ssl
import urllib.parse
from datetime import datetime, timedelta, timezone

import httpx
from httpx import HTTPError, TimeoutException

import approvals
import cfgparse
import compliance
import crypto
from config import settings
from db import audit, db, load_settings

log = logging.getLogger("switchview.alerts")
# httpx logs each answered request at INFO as 'HTTP Request: POST <the whole URL> "HTTP/1.1 202 Accepted"', and the URL of a Teams
# workflow is its key: the request log stays off for every httpx client of the process (pf and names lose their request lines too)
logging.getLogger("httpx").setLevel(logging.WARNING)

CHANNELS = ("mail", "webhook")
# The events a channel can want, with the German label of the settings, the deliveries and the mail's last line
EVENTS = {"reachability": "Switch nicht erreichbar oder wieder erreichbar", "unknown_device": "Neues unbekanntes Gerät an einem Zugangsport",
          "drift": "Änderung außerhalb von SwitchView", "compliance": "Neuer Sicherheitsbefund",
          "change_problem": "Änderung fehlgeschlagen, unklar, abgebrochen oder zurückgenommen",
          "confirm_revert": "Änderung ohne Bestätigung zurückgenommen", "bulk_problem": "Sammeländerung mit Fehlern beendet",
          "lldp_uplink": "LLDP-Nachbar an einem Uplink geändert", "approval": "Freigabe angefordert oder entschieden",
          "watch": "Beobachtete MAC-Adresse gesehen"}
# Every event but the new unknown device: in a network with guests it would be most of the messages; an Admin switches it on
DEFAULT_EVENTS = [e for e in EVENTS if e != "unknown_device"]
CAP_EVENT = "cap"          # the summary of a channel past CAP_PER_HOUR; every channel that is on takes it
TEST_EVENT = "test"        # the message of the test button (send_test), never queued
# The labels of the two events no channel chooses
OTHER_LABELS = {CAP_EVENT: "Zu viele Meldungen", TEST_EVENT: "Testnachricht"}

DEDUP_MINUTES = 60
CAP_PER_HOUR = 30
MAX_ATTEMPTS = 5
BACKOFF_S = (60, 120, 240, 480)    # the wait after failed attempt 1-4
TIMEOUT_S = 10                     # a webhook attempt as a whole; a mail attempt per read of its socket (connecting, each recv)
BATCH = 20                         # rows per run of deliver_due
TITLE_MAX = 200
TEXT_MAX = 2000

# The stored settings (table settings): lists as JSON, switches "1"/"0"; the secrets encrypted (crypto.encrypt)
SETTINGS_KEYS = ("mail_on", "smtp_host", "smtp_port", "smtp_security", "smtp_verify_tls", "smtp_user", "smtp_pass", "mail_from", "mail_to",
                 "mail_events", "hook_on", "webhook_url", "hook_format", "hook_verify_tls", "hook_events")
SECRETS = ("smtp_pass", "webhook_url")
# A secret by the destination it goes to (Phase 2 E8, as api_settings.DESTINATION_SECRETS): a new mail server drops the password
DESTINATION_SECRETS = {"smtp_host": ("smtp_pass",)}

TIME = "%Y-%m-%d %H:%M:%S"    # the times of the table, in UTC

CAP_TITLE = "Zu viele Meldungen"
CAP_TEXT = ("In der letzten Stunde gingen {cap} Meldungen über diesen Weg hinaus. Bis {until} UTC sendet SwitchView hier keine weiteren; "
            "sie stehen in SwitchView unter Einstellungen → Benachrichtigungen.")
NOT_SET_UP = "Kanal ausgeschaltet oder nicht eingerichtet"
SWITCHED_OFF = "Kanal ausgeschaltet"
TEST_TITLE = "SwitchView: Testnachricht"
TEST_TEXT = "Diese Nachricht hat ein Admin in SwitchView ausgelöst (Einstellungen → Benachrichtigungen)."
TEST_NOT_SET_UP = "Nicht eingerichtet: erst speichern"


class HookStatus(Exception):
    """A webhook answered with a status from 300 on (httpx follows no redirect): status is that status."""

    def __init__(self, status: int):
        super().__init__(f"HTTP {status}")
        self.status = status


def _now() -> datetime:
    """Now in UTC: the clock of this module (a seam like poller.utc_now)."""
    return datetime.now(timezone.utc)


def label_of(event: str) -> str:
    return EVENTS.get(event) or OTHER_LABELS.get(event, event)


def one_line(text: str) -> str:
    """text with every CR and LF as a space: a title goes into the Subject header of a mail."""
    return text.replace("\r", " ").replace("\n", " ")


# ── Settings ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def _flag(value: str | None, default: bool) -> bool:
    return default if value is None else value == "1"


def _list(value: str | None, default: list[str]) -> list[str]:
    """A stored JSON list (a value that is none: default, a copy)."""
    try:
        got = json.loads(value) if value else None
    except ValueError:
        got = None
    return [str(x) for x in got] if isinstance(got, list) else list(default)


def config_of(s: dict) -> dict:
    """The two channels from the stored values of SETTINGS_KEYS (s; a key without a value takes its default: off, port 587,
    STARTTLS, the certificate checked, Teams, DEFAULT_EVENTS), with the secrets decrypted - for the server only, never served. A
    secret that does not decrypt (crypto.decrypt gives None: another SECRET_KEY) counts as not set: a webhook without a readable URL
    and a mail with a user but without a readable password are incomplete (complete), never an attempt with an empty password."""
    try:
        port = int(s.get("smtp_port") or 587)
    except ValueError:
        port = 587
    return {"mail": {"on": _flag(s.get("mail_on"), False), "host": s.get("smtp_host") or "", "port": port,
                     "security": s.get("smtp_security") or "starttls", "verify_tls": _flag(s.get("smtp_verify_tls"), True),
                     "user": s.get("smtp_user") or "", "password": crypto.decrypt(s.get("smtp_pass")), "sender": s.get("mail_from") or "",
                     "recipients": _list(s.get("mail_to"), []), "events": _list(s.get("mail_events"), DEFAULT_EVENTS)},
            "webhook": {"on": _flag(s.get("hook_on"), False), "url": crypto.decrypt(s.get("webhook_url")),
                        "format": s.get("hook_format") or "teams", "verify_tls": _flag(s.get("hook_verify_tls"), True),
                        "events": _list(s.get("hook_events"), DEFAULT_EVENTS)}}


def complete(cfg: dict, channel: str) -> bool:
    """Whether the channel has a destination it can send to: a mail server, a sender, a recipient and, with a user, a readable
    password; a readable webhook URL."""
    if channel == "mail":
        m = cfg["mail"]
        return bool(m["host"] and m["sender"] and m["recipients"] and (not m["user"] or m["password"]))
    return channel == "webhook" and bool(cfg["webhook"]["url"])


def _secrets_of(cfg: dict) -> list[str]:
    return [v for v in (cfg["mail"]["password"], cfg["webhook"]["url"]) if v]


def webhook_target(url: str | None) -> str:
    """Of a webhook URL its scheme and host (and port, if one is given): never urlsplit's netloc, which carries a user:password@."""
    try:
        u = urllib.parse.urlsplit(url or "")
        host, port = u.hostname, u.port
    except ValueError:
        return ""
    if not (u.scheme and host):
        return ""
    host = f"[{host}]" if ":" in host else host
    return f"{u.scheme}://{host}" + (f":{port}" if port is not None else "")


def public_view(s: dict) -> dict:
    """GET /api/settings/alerts: every setting but the two secrets, of those only *_set, of the URL its target (webhook_target), the
    secrets stored that do not decrypt (unreadable), the events to choose, PUBLIC_URL (None without one) and the limits."""
    cfg = config_of(s)
    m, w = cfg["mail"], cfg["webhook"]
    return {"mail_on": m["on"], "smtp_host": m["host"], "smtp_port": m["port"], "smtp_security": m["security"],
            "smtp_verify_tls": m["verify_tls"], "smtp_user": m["user"], "mail_from": m["sender"], "mail_to": m["recipients"],
            "mail_events": m["events"], "hook_on": w["on"], "hook_format": w["format"], "hook_verify_tls": w["verify_tls"],
            "hook_events": w["events"], "smtp_pass_set": bool(s.get("smtp_pass")), "webhook_url_set": bool(s.get("webhook_url")),
            "webhook_target": webhook_target(w["url"]), "unreadable": [k for k in SECRETS if crypto.unreadable(s.get(k))],
            "events": EVENTS, "public_url": settings.public_url or None,
            "limits": {"dedup_minutes": DEDUP_MINUTES, "cap_per_hour": CAP_PER_HOUR, "attempts": MAX_ATTEMPTS}}


async def drop_queued(conn, channel: str) -> int:
    """The queued rows of channel as failed („Kanal ausgeschaltet“), on conn without a commit (PUT /api/settings/alerts, when a
    channel goes off); how many."""
    cur = await conn.execute("UPDATE alert_outbox SET status = 'failed', error = ?, next_at = NULL WHERE channel = ? AND status = 'queued'",
                             (SWITCHED_OFF, channel))
    return cur.rowcount


# ── The queue ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────

async def _insert(conn, row: dict) -> None:
    await conn.execute("INSERT INTO alert_outbox(created_at, channel, event, dedup_key, switch_id, switch_name, title, text, facts, status, "
                       "next_at) VALUES (:created_at, :channel, :event, :dedup_key, :switch_id, :switch_name, :title, :text, :facts, "
                       ":status, :next_at)", row)


async def emit(event: str, title: str, text: str, *, switch_id: int | None = None, switch_name: str = "", key: str = "",
               facts: dict[str, str] | None = None) -> int:
    """Queues the message for each channel that is on and wants event (CAP_EVENT: every channel that is on) and returns how many rows
    it queued; never sends, never raises (a failure is logged, „Benachrichtigung <event>“, and counts 0). Per channel: a row of the
    last DEDUP_MINUTES with the dedup_key f"{event}:{key}" and a status other than suppressed takes the repeat (repeats + 1), nothing
    new; else, under CAP_PER_HOUR rows of the channel in the last hour (neither suppressed ones nor the summary counted: a sliding
    hour sends at most CAP_PER_HOUR and the summary), a queued row due now; else a suppressed row and, without a CAP_EVENT row of the
    channel in that hour, the summary queued (until when: the oldest row counted plus an hour, when the hour has room again). title
    is one line of at most TITLE_MAX characters, text at most TEXT_MAX; facts are shown as "key: value" (a key starting with "_"
    steers instead: "_view" picks the link). The checks and the writes are one write transaction (BEGIN IMMEDIATE, as
    changes.create_change): the polls of poll_all that report at once never count past the same cap."""
    try:
        cfg = config_of(await load_settings(SETTINGS_KEYS))
        channels = [c for c in CHANNELS if cfg[c]["on"] and (event == CAP_EVENT or event in cfg[c]["events"])]
        if not channels:
            return 0
        now = _now()
        at = now.strftime(TIME)
        hour_ago = (now - timedelta(hours=1)).strftime(TIME)
        window = (now - timedelta(minutes=DEDUP_MINUTES)).strftime(TIME)
        row = {"created_at": at, "event": event, "dedup_key": f"{event}:{key}", "switch_id": switch_id, "switch_name": switch_name or "",
               "title": one_line(title)[:TITLE_MAX], "text": text[:TEXT_MAX], "facts": json.dumps(facts or {}, ensure_ascii=False)}
        queued = 0
        async with db() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            for channel in channels:
                cur = await conn.execute("UPDATE alert_outbox SET repeats = repeats + 1 WHERE id = (SELECT id FROM alert_outbox WHERE "
                                         "channel = ? AND dedup_key = ? AND created_at >= ? AND status <> 'suppressed' ORDER BY id DESC "
                                         "LIMIT 1)", (channel, row["dedup_key"], window))
                if cur.rowcount:
                    continue
                # The summary is no message of the count: counted, it would hold the hour full past the time it names
                async with conn.execute("SELECT count(*), min(created_at) FROM alert_outbox WHERE channel = ? AND created_at >= ? AND "
                                        "status <> 'suppressed' AND event <> ?", (channel, hour_ago, CAP_EVENT)) as cur:
                    count, oldest = await cur.fetchone()
                if count < CAP_PER_HOUR:
                    await _insert(conn, {**row, "channel": channel, "status": "queued", "next_at": at})
                    queued += 1
                    continue
                await _insert(conn, {**row, "channel": channel, "status": "suppressed", "next_at": None})
                async with conn.execute("SELECT 1 FROM alert_outbox WHERE channel = ? AND dedup_key = ? AND created_at >= ? LIMIT 1",
                                        (channel, f"{CAP_EVENT}:", hour_ago)) as cur:
                    if await cur.fetchone():
                        continue
                until = (datetime.strptime(oldest, TIME) + timedelta(hours=1)).strftime("%H:%M")
                await _insert(conn, {"created_at": at, "channel": channel, "event": CAP_EVENT, "dedup_key": f"{CAP_EVENT}:",
                                     "switch_id": None, "switch_name": "", "title": CAP_TITLE,
                                     "text": CAP_TEXT.format(cap=CAP_PER_HOUR, until=until), "facts": "{}", "status": "queued",
                                     "next_at": at})
                queued += 1
            await conn.commit()
        return queued
    except Exception:  # noqa: BLE001 - a source's poll, backup or change never fails over an alert
        log.exception("Benachrichtigung %s", event)
        return 0


# ── Texts ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def _facts(item: dict) -> dict[str, str]:
    """The facts of a row that are shown: those whose key does not start with "_" (such a key steers, "_view" the link)."""
    return {str(k): str(v) for k, v in json.loads(item["facts"] or "{}").items() if not str(k).startswith("_")}


def link_for(switch_id: int | None, view: str | None = None) -> str | None:
    """The link of a message into SwitchView: None without PUBLIC_URL; the view (e.g. approvals), else the switch, else the start."""
    url = settings.public_url
    if not url:
        return None
    if view:
        return f"{url}/#{view}"
    if switch_id is not None:
        return f"{url}/#sw={switch_id}"
    return f"{url}/"


def mail_message(cfg: dict, item: dict, link: str | None) -> email.message.EmailMessage:
    """The mail of a row for the mail channel cfg: Subject "[SwitchView] <title>" on one line, From the sender, To the recipients,
    Date now and a Message-ID of the sender's domain (RFC 5322 requires Date; neither EmailMessage nor send_message adds them, a relay
    only for its local clients, and spam filters score a mail without them; the domain given, make_msgid asks no DNS); the text, the
    facts as "key: value", the link (if any) and the event, each block after an empty line."""
    msg = email.message.EmailMessage()
    msg["Subject"] = f"[SwitchView] {one_line(item['title'])}"
    msg["From"] = cfg["sender"]
    msg["To"] = ", ".join(cfg["recipients"])
    msg["Date"] = email.utils.format_datetime(_now())
    msg["Message-ID"] = email.utils.make_msgid(domain=cfg["sender"].rpartition("@")[2] or "switchview.invalid")
    blocks = [item["text"], "\n".join(f"{k}: {v}" for k, v in _facts(item).items())]
    if link:
        blocks.append(f"In SwitchView öffnen: {link}")
    blocks.append(f"Ereignis: {label_of(item['event'])} · SwitchView")
    msg.set_content("\n\n".join(b for b in blocks if b))
    return msg


_MARKDOWN = re.compile(r"([\\*_`\[\]()#<>~])")


def md_escape(text: str) -> str:
    """text with a backslash before each character Markdown reads (Teams renders Markdown in a TextBlock and a fact)."""
    return _MARKDOWN.sub(r"\\\1", text)


def webhook_payload(fmt: str, item: dict, link: str | None) -> dict:
    """The body of a webhook: "teams" a message with an Adaptive Card 1.4, as a Teams workflow „Post to a channel when a webhook
    request is received“ takes it (title, text and facts with Markdown escaped, a button with the link if any); "json" the event as
    it is."""
    facts = _facts(item)
    if fmt == "teams":
        content = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                   "body": [{"type": "TextBlock", "text": md_escape(item["title"]), "weight": "Bolder", "size": "Medium", "wrap": True},
                            {"type": "TextBlock", "text": md_escape(item["text"]), "wrap": True},
                            {"type": "FactSet", "facts": [{"title": md_escape(k), "value": md_escape(v)} for k, v in facts.items()]}]}
        if link:
            content["actions"] = [{"type": "Action.OpenUrl", "title": "In SwitchView öffnen", "url": link}]
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
                                                    "content": content}]}
    switch = {"id": item["switch_id"], "name": item["switch_name"]} if item["switch_id"] is not None or item["switch_name"] else None
    return {"source": "switchview", "event": item["event"], "title": item["title"], "text": item["text"], "switch": switch,
            "facts": facts, "at": item["created_at"].replace(" ", "T") + "Z", "url": link}


def error_text(e: BaseException, secrets: list[str]) -> str:
    """The text of a failed attempt, from a status or a type - never str() of an httpx error, which names the URL - and then masked
    with the secrets (the password, the webhook URL): a timeout (httpx's, TimeoutError, which socket.timeout and the end of
    asyncio.wait_for are), a webhook status, any other httpx error by its type, an SMTP answer with its code and at most 200
    characters of its text, an OSError with its text (SMTPException is one), anything else by its type."""
    if isinstance(e, (TimeoutException, TimeoutError)):
        text = f"Zeitüberschreitung nach {TIMEOUT_S} s"
    elif isinstance(e, HookStatus):
        text = f"HTTP {e.status}"
    elif isinstance(e, HTTPError):
        text = f"Verbindung fehlgeschlagen ({type(e).__name__})"
    elif isinstance(e, smtplib.SMTPResponseException):
        msg = e.smtp_error.decode(errors="replace") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        text = f"SMTP {e.smtp_code}: {msg[:200]}"
    elif isinstance(e, OSError):
        text = f"{type(e).__name__}: {e.strerror or e}"
    else:
        text = type(e).__name__
    return cfgparse.mask_secrets(text, secrets)


# ── Delivery ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def _send_mail(cfg: dict, msg: email.message.EmailMessage) -> None:
    """One mail over SMTP (in a thread: smtplib blocks): SMTP_SSL for "tls", else SMTP and, for "starttls", STARTTLS; the login only
    with a user. timeout=TIMEOUT_S is the socket's: it bounds connecting and each single read, not an answer or the attempt, and a
    thread cannot be cancelled. A server that answers each step just within it holds an attempt about two minutes (connecting and at
    least eleven answers; one more for each further recipient); one that trickles a byte at a time within it holds it, and the run of
    deliver_due with it, for as long as it trickles (Bekannte Grenzen).
    Without the certificate check the context verifies nothing (an internal relay)."""
    context = ssl.create_default_context()
    if not cfg["verify_tls"]:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if cfg["security"] == "tls":
        smtp = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=TIMEOUT_S, context=context)
    else:
        smtp = smtplib.SMTP(cfg["host"], cfg["port"], timeout=TIMEOUT_S)
    try:
        if cfg["security"] == "starttls":
            smtp.starttls(context=context)
        if cfg["user"]:
            smtp.login(cfg["user"], cfg["password"])
        smtp.send_message(msg)
        smtp.quit()
    finally:
        smtp.close()


async def _send(cfg: dict, channel: str, item: dict) -> None:
    """The one place that sends anything out (deliver_due, send_test): the row item over channel of cfg (config_of), with the link
    link_for(switch_id, facts["_view"]). A webhook attempt is bounded as a whole by asyncio.wait_for (httpx's timeout counts per
    phase, a server that answers drop by drop would pass it); a status from 300 on raises HookStatus. Raises on every failure."""
    view = json.loads(item["facts"] or "{}").get("_view")
    link = link_for(item["switch_id"], view)
    if channel == "mail":
        await asyncio.to_thread(_send_mail, cfg["mail"], mail_message(cfg["mail"], item, link))
        return
    hook = cfg["webhook"]
    async with httpx.AsyncClient(timeout=TIMEOUT_S, verify=hook["verify_tls"]) as client:
        r = await asyncio.wait_for(client.post(hook["url"], json=webhook_payload(hook["format"], item, link)), TIMEOUT_S)
    if r.status_code >= 300:
        raise HookStatus(r.status_code)


async def _update(sql: str, args: tuple) -> None:
    async with db() as conn:
        await conn.execute(sql, args)
        await conn.commit()


async def _still_queued(row_id: int) -> bool:
    async with db() as conn:
        async with conn.execute("SELECT 1 FROM alert_outbox WHERE id = ? AND status = 'queued'", (row_id,)) as cur:
            return await cur.fetchone() is not None


async def deliver_due() -> int:
    """The job (every 30 seconds): at most BATCH queued rows due now, by id, one attempt each. A success is sent with sent_at; a
    failure adds one to attempts (the failed attempts) with its error_text, and waits BACKOFF_S[attempts - 1] under MAX_ATTEMPTS,
    else it is failed and audited (alert_failed, „#<id> <title>: <error>“). A row of a channel that is off or incomplete by now is
    failed at once (NOT_SET_UP), audited the same way, without an attempt. Each row is checked anew right before its attempt, with
    the settings of that moment: a run takes up to BATCH attempts of a minute or more each, and a row dropped meanwhile (the channel
    switched off) or a destination changed meanwhile counts from the next row on. Returns the number of attempts."""
    async with db() as conn:
        async with conn.execute("SELECT * FROM alert_outbox WHERE status = 'queued' AND next_at <= ? ORDER BY id LIMIT ?",
                                (_now().strftime(TIME), BATCH)) as cur:
            items = [dict(r) for r in await cur.fetchall()]
    tried = 0
    for item in items:
        if not await _still_queued(item["id"]):
            continue
        cfg = config_of(await load_settings(SETTINGS_KEYS))
        channel = item["channel"]
        if channel not in CHANNELS or not cfg[channel]["on"] or not complete(cfg, channel):
            await _fail(item, item["attempts"], NOT_SET_UP)
            continue
        tried += 1
        try:
            await _send(cfg, channel, item)
        except Exception as e:  # noqa: BLE001 - every failure of an attempt is the row's error, never the job's
            error = error_text(e, _secrets_of(cfg))
            attempts = item["attempts"] + 1
            if attempts < MAX_ATTEMPTS:
                await _update("UPDATE alert_outbox SET attempts = ?, error = ?, next_at = ? WHERE id = ? AND status = 'queued'",
                              (attempts, error, (_now() + timedelta(seconds=BACKOFF_S[attempts - 1])).strftime(TIME), item["id"]))
            else:
                await _fail(item, attempts, error)
        else:
            # sent, whatever happened to the row meanwhile: it went out (attempts keeps the failed attempts before)
            await _update("UPDATE alert_outbox SET status = 'sent', sent_at = ?, next_at = NULL, error = NULL WHERE id = ?",
                          (_now().strftime(TIME), item["id"]))
    return tried


async def _fail(item: dict, attempts: int, error: str) -> None:
    """The row failed for good, with its error, and the audit entry; a row dropped meanwhile (no longer queued) stays as it is."""
    async with db() as conn:
        cur = await conn.execute("UPDATE alert_outbox SET status = 'failed', attempts = ?, error = ?, next_at = NULL WHERE id = ? AND "
                                 "status = 'queued'", (attempts, error, item["id"]))
        await conn.commit()
    if cur.rowcount:
        await audit(None, "alert_failed", item["channel"], f"#{item['id']} {item['title']}: {error}", role=None)


async def send_test(channel: str) -> dict:
    """A test message straight over the stored channel (the test button), without the queue, with the same timeouts: {"ok": True,
    "error": None} or {"ok": False, "error": <error_text>}; a channel without a destination (complete) {"ok": False, "error":
    TEST_NOT_SET_UP}. A channel that is off can be tested."""
    cfg = config_of(await load_settings(SETTINGS_KEYS))
    if not complete(cfg, channel):
        return {"ok": False, "error": TEST_NOT_SET_UP}
    item = {"id": 0, "created_at": _now().strftime(TIME), "channel": channel, "event": TEST_EVENT, "switch_id": None, "switch_name": "",
            "title": TEST_TITLE, "text": TEST_TEXT, "facts": "{}"}
    try:
        await _send(cfg, channel, item)
    except Exception as e:  # noqa: BLE001 - the button says why
        return {"ok": False, "error": error_text(e, _secrets_of(cfg))}
    return {"ok": True, "error": None}


async def deliveries(status: str | None = None, cursor: int | None = None, limit: int = 20) -> dict:
    """One page of the rows of alert_outbox, newest first (by id), of one status if given, before the id cursor: {"rows": [{"id",
    "created_at", "channel", "event", "label", "switch_name", "title", "status", "attempts", "next_at", "sent_at", "error",
    "repeats"}], "next": the id of the last row when more follow, else None}. Neither the text nor the facts."""
    where, args = [], []
    for clause, value in (("status = ?", status), ("id < ?", cursor)):
        if value is not None:
            where.append(clause)
            args.append(value)
    async with db() as conn:
        async with conn.execute("SELECT id, created_at, channel, event, switch_name, title, status, attempts, next_at, sent_at, error, repeats "
                                f"FROM alert_outbox{' WHERE ' + ' AND '.join(where) if where else ''} ORDER BY id DESC LIMIT ?",
                                [*args, limit + 1]) as cur:
            got = await cur.fetchall()
    rows = [{"id": r["id"], "created_at": r["created_at"], "channel": r["channel"], "event": r["event"], "label": label_of(r["event"]),
             "switch_name": r["switch_name"], "title": r["title"], "status": r["status"], "attempts": r["attempts"], "next_at": r["next_at"],
             "sent_at": r["sent_at"], "error": r["error"], "repeats": r["repeats"]} for r in got[:limit]]
    return {"rows": rows, "next": rows[-1]["id"] if len(got) > limit else None}


# ── Sources (Task 7) ────────────────────────────────────────────────────────────────────────────────────────────────────────────
# Each one is called where its data comes from - poller.poll_switch, sshcli.store_backup, history.record, the end of a change
# (changes.run_change, changes._close), approvals.emit - and each is wrapped: it never raises, a failure is logged („Benachrichtigung
# …“) and never changes the poll, the backup, the recording or the change. The key of a message (emit's dedup) is its subject: a
# change of reachability is each one a message (its key carries the event's id; the three polls of monitor.UNREACHABLE_AFTER are the
# debounce), everything else counts once per port, MAC, finding, change or step of a request within DEDUP_MINUTES.

def _switch_facts(name: str, host: str) -> dict[str, str]:
    return {"Switch": name, "Adresse": host}


async def announce_events(events: list[dict], switch) -> None:
    """The events of monitor (poll_failed, poll_succeeded, backup_outside: dicts as list_events reads them) of the switch (a row
    with id, name and host): switch_down and switch_up as reachability, drift_port and drift_config as drift, an LLDP event at an
    uplink (detail.uplink) as lldp_uplink; an LLDP event elsewhere tells nothing."""
    try:
        sid, name = switch["id"], switch["name"]
        facts = _switch_facts(name, switch["host"])
        for e in events:
            kind, port, text = e["kind"], e["port"], e["text"]
            if kind in ("switch_down", "switch_up"):
                title = f"Switch {name} antwortet {'nicht' if kind == 'switch_down' else 'wieder'}"
                await emit("reachability", title, text, switch_id=sid, switch_name=name, key=f"{sid}:{e['id']}", facts=facts)
            elif kind == "drift_port":
                await emit("drift", f"Änderung außerhalb von SwitchView: {name} Port {port}", text, switch_id=sid, switch_name=name,
                           key=f"drift_port:{sid}:{port}", facts=facts)
            elif kind == "drift_config":
                await emit("drift", f"Konfiguration außerhalb von SwitchView geändert: {name}",
                           f"{text.rstrip('.')}. Den Vergleich zeigt SwitchView unter Sicherungen.", switch_id=sid, switch_name=name,
                           key=f"drift_config:{sid}:{e['detail']['backup']}", facts=facts)
            elif kind.startswith("lldp_") and e["detail"].get("uplink"):
                await emit("lldp_uplink", f"LLDP-Nachbar an Uplink geändert: {name} Port {port}", text, switch_id=sid,
                           switch_name=name, key=f"lldp:{sid}:{port}", facts=facts)
    except Exception:  # noqa: BLE001 - a poll or a backup never fails over an alert
        log.exception("Benachrichtigung der Ereignisse")


SEEN_AS = {"first": "zum ersten Mal gesehen", "moved": "an einem anderen Port", "back": "wieder da"}


async def announce_sightings(news: list[dict]) -> None:
    """What history.record added or revived (its return): a first sighting ever of a MAC that is neither in the device database
    (known) nor at a possible uplink (suspect), outside the first recording of its switch (baseline), as unknown_device (once per
    MAC and call: a MAC first seen in two VLANs at once is one device); and every watched MAC (history.watched) seen for the first
    time, at another place or back, as watch (its note first)."""
    try:
        import history  # late: history → alerts
        hits = [n for n in news if n["first"] or n["moved"] or n["back"]]
        if not hits:
            return
        notes = await history.watched({n["mac"] for n in hits})
        told: set[str] = set()    # the keys told in this call: one message per subject, not one and a repeat

        async def tell(event: str, n: dict, title: str, text: str, key: str) -> None:
            if key not in told:
                told.add(key)
                await emit(event, title, text, switch_id=n["switch_id"], switch_name=n["switch"], key=key,
                           facts={"Switch": n["switch"], "Port": n["port"]})

        for n in hits:
            mac, switch, port, vlan, ip, name = n["mac"], n["switch"], n["port"], n["vlan"], n["ip"], n["name"]
            if n["first"] and not (n["known"] or n["suspect"] or n["baseline"]):
                await tell("unknown_device", n, f"Neues unbekanntes Gerät an {switch} Port {port}",
                           f"MAC {mac}{', IP ' + ip if ip else ''}{', Name ' + name if name else ''} im VLAN {vlan}, zum ersten Mal gesehen.",
                           f"unknown:{mac}")
            if mac in notes:
                note, why = notes[mac], next(w for w in SEEN_AS if n[w])
                await tell("watch", n, f"Beobachtete MAC {mac} gesehen: {switch} Port {port}",
                           f"{note + ': ' if note else ''}{SEEN_AS[why]} (VLAN {vlan}{', IP ' + ip if ip else ''}).",
                           f"watch:{mac}:{n['switch_id']}:{port}")
    except Exception:  # noqa: BLE001 - a recording never fails over an alert
        log.exception("Benachrichtigung der Sichtungen")


async def announce_findings(switch, findings: list[dict]) -> None:
    """The new findings of the switch (a row with id, name and host) as compliance.evaluate_config and evaluate_snmp return them,
    each as compliance: its detail and, with a line, „Zeile <n>: <the masked line>“; with neither, the rule's hint."""
    try:
        sid, name = switch["id"], switch["name"]
        facts = _switch_facts(name, switch["host"])
        for f in findings:
            text = (f["detail"] + (f" Zeile {f['line_no']}: {f['line']}" if f["line_no"] else "")).strip()
            rule = compliance.RULES.get(f["rule"])
            await emit("compliance", f"Neuer Sicherheitsbefund an {name}: {f['label']}", text or (rule.hint if rule else ""),
                       switch_id=sid, switch_name=name, key=f"compliance:{sid}:{f['id']}", facts=facts)
    except Exception:  # noqa: BLE001 - a poll or a backup never fails over an alert
        log.exception("Benachrichtigung der Sicherheitsbefunde")


CHANGE_LABELS = {"failed": "fehlgeschlagen", "unclear": "unklar", "aborted": "abgebrochen"}


async def change_ended(ch, cid: int, status: str, error: str | None) -> None:
    """The end of change cid (ch: its changes row, as run_change and _close read it; error masked): failed, unclear or aborted as
    change_problem („Änderung #<cid> an <switch> <fehlgeschlagen|unklar|abgebrochen>“, the summary, who and the error), a revert that
    ended ok as „Änderung #<revert_of> an <switch> zurückgenommen“; any other end tells nothing. The switch's name from the table
    switches (gone meanwhile: „Switch <id>“)."""
    try:
        sid, revert_of = ch["switch_id"], ch["revert_of"]
        if status not in CHANGE_LABELS and not (status == "ok" and revert_of):
            return
        async with db() as conn:
            async with conn.execute("SELECT name FROM switches WHERE id = ?", (sid,)) as cur:
                row = await cur.fetchone()
        name = row["name"] if row else f"Switch {sid}"
        if status in CHANGE_LABELS:
            title = f"Änderung #{cid} an {name} {CHANGE_LABELS[status]}"
            text = f"{ch['summary']} (von {ch['username']})" + (f": {error}" if error else "")
        else:
            title, text = f"Änderung #{revert_of} an {name} zurückgenommen", f"Zurückgenommen mit #{cid} von {ch['username']}."
        await emit("change_problem", title, text, switch_id=sid, switch_name=name, key=f"change:{cid}", facts={"Switch": name})
    except Exception:  # noqa: BLE001 - a change never ends otherwise over an alert
        log.exception("Benachrichtigung zum Ende von Änderung %s", cid)


APPROVAL_LABELS = {"requested": "angefordert", "approved": "freigegeben", "rejected": "abgelehnt", "withdrawn": "zurückgezogen",
                   "expired": "abgelaufen", "stale": "veraltet"}


async def on_approval(event: str, approval: dict) -> None:
    """The listener of approvals (subscribed below, at import): every step of a request (APPROVAL_LABELS) as approval, linked to
    #approvals (the fact "_view", which steers and is never shown): its summary, switch and requester, who decided (if anyone), the
    comment and the reason (if any). A step not in APPROVAL_LABELS tells nothing."""
    try:
        if event not in APPROVAL_LABELS:
            return
        a, name = approval, approval.get("switch_name") or ""
        text = (f"{a['summary']}{' an ' + name if name else ''}, angefordert von {a.get('requester_name') or a['requested_by']}"
                + (f", entschieden von {a['decided_by']}" if a.get("decided_by") else "") + (f": {a['comment']}" if a.get("comment") else "")
                + (f" – {a['reason']}" if a.get("reason") else ""))
        await emit("approval", f"Freigabe #{a['id']} {APPROVAL_LABELS[event]}", text, switch_id=a.get("switch_id"), switch_name=name,
                   key=f"approval:{a['id']}:{event}", facts=({"Switch": name} if name else {}) | {"_view": "approvals"})
    except Exception:  # noqa: BLE001 - approvals.emit wraps it as well; a step of a request never fails over an alert
        log.exception("Benachrichtigung zur Freigabe (%s)", event)


approvals.subscribe(on_approval)
