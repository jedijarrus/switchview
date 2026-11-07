"""Phase 4b, Task 6: alerts by mail (SMTP) and webhook (Teams or JSON) through a queue in the database (app/alerts.py, table
alert_outbox, routes in app/api_alerts.py). emit only writes rows - per channel that is on and wants the event, at most one per key
within DEDUP_MINUTES (a repeat is counted), at most CAP_PER_HOUR per channel and hour with one summary - and a scheduler job
(deliver_due) sends them: a mail through smtplib in a thread, a webhook through httpx, each attempt bounded by TIMEOUT_S, MAX_ATTEMPTS
attempts with BACKOFF_S between them, then failed and audited. The SMTP password and the webhook URL are stored encrypted and never
served; an error text comes from a status or a type, never from str() of an httpx error, and goes through the mask. Admin only.

No network: smtplib.SMTP and smtplib.SMTP_SSL are replaced by FakeSMTP, alerts.httpx by apifix.fake_httpx; a fresh database per test
(apifix.fresh_db).
"""
import asyncio
import json
import secrets
import smtplib
import socket
import ssl
import types
from datetime import datetime, timezone

import httpx
import pytest

import alerts
import apifix
import config
import crypto
import db
import dbfix
import history
import main

MAIL = {"mail_on": True, "smtp_host": "mail.example.org", "smtp_port": 587, "smtp_security": "starttls", "smtp_user": "sv",
        "smtp_pass": "mail-s3cret", "mail_from": "switchview@example.org", "mail_to": ["netz@example.org"], "mail_events": ["reachability"],
        "hook_on": False, "webhook_url": None, "hook_format": "teams", "hook_events": []}
HOOK_URL = "https://prod.example.org/workflows/abc/triggers/manual/paths/invoke?sig=hook-s3cret-token"
# The mail channel as config_of gives it from MAIL
CFG_MAIL = {"on": True, "host": "mail.example.org", "port": 587, "security": "starttls", "verify_tls": True, "user": "sv",
            "password": "mail-s3cret", "sender": "switchview@example.org", "recipients": ["netz@example.org"], "events": ["reachability"]}
FROZEN = datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def database(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)


@pytest.fixture
def api(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


async def configure(mail: bool = False, hook: bool = False, events: list[str] | None = None) -> None:
    """The alert settings as PUT /api/settings/alerts stores them (db.write_settings): mail with the values of MAIL, the webhook with
    HOOK_URL in the Teams format, each on as given; the events for both channels, without: mail reachability and drift, webhook drift."""
    async with db.db() as conn:
        await db.write_settings(conn, {
            "mail_on": "1" if mail else "0", "smtp_host": MAIL["smtp_host"], "smtp_port": str(MAIL["smtp_port"]),
            "smtp_security": MAIL["smtp_security"], "smtp_verify_tls": "1", "smtp_user": MAIL["smtp_user"],
            "smtp_pass": crypto.encrypt(MAIL["smtp_pass"]), "mail_from": MAIL["mail_from"], "mail_to": json.dumps(MAIL["mail_to"]),
            "mail_events": json.dumps(events if events is not None else ["reachability", "drift"]), "hook_on": "1" if hook else "0",
            "webhook_url": crypto.encrypt(HOOK_URL), "hook_format": "teams", "hook_verify_tls": "1",
            "hook_events": json.dumps(events if events is not None else ["drift"])})
        await conn.commit()


def setting(key: str, value: str) -> None:
    """One stored alert setting replaced, as a PUT would leave it."""
    dbfix.query("UPDATE settings SET value = ? WHERE key = ?", (value, key))


class FakeSMTP:
    """smtplib.SMTP and smtplib.SMTP_SSL as alerts uses them: every step of every connection in calls - ("connect", host, port,
    timeout), ("starttls",), ("login", user, password), ("send", Subject, From, To), ("quit",) - the class of each connection in
    classes, the TLS context of the connection or its STARTTLS in contexts, the messages in sent; raises[step] is raised at that step
    (after it is recorded)."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.classes: list[str] = []
        self.contexts: list[ssl.SSLContext | None] = []
        self.sent: list = []
        self.raises: dict[str, BaseException] = {}

    def step(self, name: str, *args) -> None:
        self.calls.append((name, *args))
        if name in self.raises:
            raise self.raises[name]

    def factory(self, cls: str):
        fake = self

        class Connection:
            def __init__(self, host, port, timeout=None, context=None):
                fake.classes.append(cls)
                if cls == "SMTP_SSL":
                    fake.contexts.append(context)
                fake.step("connect", host, port, timeout)

            def starttls(self, context=None):
                fake.contexts.append(context)
                fake.step("starttls")

            def login(self, user, password):
                fake.step("login", user, password)

            def send_message(self, msg):
                fake.sent.append(msg)
                fake.step("send", msg["Subject"], msg["From"], msg["To"])

            def quit(self):
                fake.step("quit")

            def close(self):
                pass

        return Connection


def fake_smtp(monkeypatch) -> FakeSMTP:
    smtp = FakeSMTP()
    monkeypatch.setattr(smtplib, "SMTP", smtp.factory("SMTP"))
    monkeypatch.setattr(smtplib, "SMTP_SSL", smtp.factory("SMTP_SSL"))
    return smtp


class Hook(apifix.Remote):
    """The webhook's server: 200 with an empty object unless status says otherwise."""


def item(**kw) -> dict:
    """A row of alert_outbox as deliver_due reads it."""
    return {"id": 1, "created_at": "2026-11-07 10:00:00", "channel": "mail", "event": "drift", "dedup_key": "drift:", "switch_id": None,
            "switch_name": "", "title": "T", "text": "x", "facts": "{}", "status": "queued", "attempts": 0,
            "next_at": "2026-11-07 10:00:00", "sent_at": None, "error": None, "repeats": 0, **kw}


async def never(*args, **kwargs):
    raise AssertionError("emit must not send: a poll or a change never waits for a delivery")


def outbox(cols: str = "channel, event, status") -> list[tuple]:
    return dbfix.query(f"SELECT {cols} FROM alert_outbox ORDER BY id")


def due_now() -> None:
    dbfix.query("UPDATE alert_outbox SET next_at = '2000-01-01 00:00:00' WHERE status = 'queued'")


# ── Settings ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_the_secrets_are_encrypted_and_never_served(api):
    assert api.put("/api/settings/alerts", json={**MAIL, "hook_on": True, "webhook_url": HOOK_URL}).status_code == 200
    got = api.get("/api/settings/alerts").json()
    raw = dict(dbfix.query("SELECT key, value FROM settings"))
    assert got["smtp_pass_set"] and got["webhook_url_set"] and got["webhook_target"] == "https://prod.example.org"
    assert "smtp_pass" not in got and "webhook_url" not in got and "s3cret" not in json.dumps(got)
    assert crypto.decrypt(raw["smtp_pass"]) == "mail-s3cret" and crypto.decrypt(raw["webhook_url"]) == HOOK_URL and "s3cret" not in raw[
        "smtp_pass"] + raw["webhook_url"]
    assert "s3cret" not in json.dumps(dbfix.query("SELECT detail FROM audit"))


def test_get_serves_every_setting_with_its_defaults_events_and_limits(api):
    got = api.get("/api/settings/alerts").json()
    assert got == {"mail_on": False, "smtp_host": "", "smtp_port": 587, "smtp_security": "starttls", "smtp_verify_tls": True, "smtp_user": "",
                   "mail_from": "", "mail_to": [], "mail_events": alerts.DEFAULT_EVENTS, "hook_on": False, "hook_format": "teams",
                   "hook_verify_tls": True, "hook_events": alerts.DEFAULT_EVENTS, "smtp_pass_set": False, "webhook_url_set": False,
                   "webhook_target": "", "unreadable": [], "events": alerts.EVENTS, "public_url": None,
                   "limits": {"dedup_minutes": 60, "cap_per_hour": 30, "attempts": 5}}
    assert alerts.DEFAULT_EVENTS == [e for e in alerts.EVENTS if e != "unknown_device"]


def test_put_stores_what_get_serves_trimmed_and_audits_without_a_secret(api):
    body = {**MAIL, "smtp_host": " mail.example.org ", "smtp_user": " sv ", "mail_from": " switchview@example.org ",
            "mail_to": [" netz@example.org ", "", "noc@example.org"], "mail_events": ["drift", "reachability", "drift"], "hook_on": True,
            "webhook_url": HOOK_URL, "hook_format": "json", "hook_verify_tls": False, "hook_events": ["approval"]}
    assert api.put("/api/settings/alerts", json=body).json() == {"ok": True, "cleared": [], "dropped": 0}
    got = api.get("/api/settings/alerts").json()
    assert {k: got[k] for k in ("smtp_host", "smtp_user", "mail_from", "mail_to", "mail_events", "hook_on", "hook_format",
                                "hook_verify_tls", "hook_events")} == {
        "smtp_host": "mail.example.org", "smtp_user": "sv", "mail_from": "switchview@example.org",
        "mail_to": ["netz@example.org", "noc@example.org"], "mail_events": ["reachability", "drift"], "hook_on": True, "hook_format": "json",
        "hook_verify_tls": False, "hook_events": ["approval"]}
    assert dbfix.query("SELECT username, action, detail, role FROM audit") == [
        ("tester", "alert_settings", "Mail: an, mail.example.org:587 (starttls), 2 Empfänger; Webhook: an, json, Webhook-Adresse neu", "admin")]


def test_a_secret_put_as_none_stays_and_as_empty_is_deleted(api):
    api.put("/api/settings/alerts", json={**MAIL, "webhook_url": HOOK_URL})
    api.put("/api/settings/alerts", json=MAIL | {"smtp_pass": None})
    assert api.get("/api/settings/alerts").json()["smtp_pass_set"] and api.get("/api/settings/alerts").json()["webhook_url_set"]
    assert api.put("/api/settings/alerts", json=MAIL | {"smtp_pass": "", "webhook_url": ""}).json()["cleared"] == []
    got = api.get("/api/settings/alerts").json()
    assert not got["smtp_pass_set"] and not got["webhook_url_set"] and got["webhook_target"] == ""
    assert dbfix.query("SELECT detail FROM audit ORDER BY id DESC LIMIT 1") == [
        ("Mail: an, mail.example.org:587 (starttls), 1 Empfänger; Webhook: aus, teams; gelöscht: smtp_pass, webhook_url",)]


@pytest.mark.parametrize("host, cleared", [("relay.example.org", ["smtp_pass"]), (" MAIL.example.org ", [])])
def test_a_new_mail_server_drops_the_stored_password(api, host, cleared):
    api.put("/api/settings/alerts", json=MAIL)
    assert api.put("/api/settings/alerts", json={**MAIL, "smtp_host": host, "smtp_pass": None}).json()["cleared"] == cleared
    assert api.get("/api/settings/alerts").json()["smtp_pass_set"] == (not cleared)


def test_a_new_mail_server_keeps_a_password_the_put_brings(api):
    api.put("/api/settings/alerts", json=MAIL)
    assert api.put("/api/settings/alerts", json={**MAIL, "smtp_host": "relay.example.org", "smtp_pass": "neu-s3cret"}).json()["cleared"] == []
    assert crypto.decrypt(dict(dbfix.query("SELECT key, value FROM settings"))["smtp_pass"]) == "neu-s3cret"


@pytest.mark.parametrize("change, detail", [
    ({"smtp_host": "a b"}, "Mailserver: Name oder IP-Adresse ungültig"), ({"mail_to": ["kein-at"]}, "Mail-Adresse ungültig: kein-at"),
    ({"smtp_security": "none"}, "Ohne TLS meldet sich SwitchView nicht am Mailserver an: das Kennwort ginge im Klartext übers Netz"),
    ({"smtp_host": "", "mail_to": []}, "Mail einschalten braucht den Mailserver, mindestens einen Empfänger"),
    ({"hook_on": True, "webhook_url": "ftp://x"}, "Webhook-Adresse muss mit http:// oder https:// beginnen"),
    ({"hook_on": True}, "Webhook einschalten braucht eine Webhook-Adresse"), ({"mail_events": ["x"]}, "Unbekanntes Ereignis: x")])
def test_bad_settings_are_named_in_german(api, change, detail):
    r = api.put("/api/settings/alerts", json={**MAIL, **change})
    assert (r.status_code, r.json()["detail"]) == (422, detail)


@pytest.mark.parametrize("change, detail", [
    ({"mail_from": "a@b"}, "Mail-Adresse ungültig: a@b"), ({"mail_to": ["Netz <netz@example.org>"]}, "Mail-Adresse ungültig: Netz <netz@example.org>"),
    ({"smtp_host": "mail.example.org:25"}, "Mailserver: Name oder IP-Adresse ungültig"),
    ({"mail_from": "", "smtp_host": ""}, "Mail einschalten braucht den Mailserver, einen Absender"),
    ({"hook_on": True, "webhook_url": ""}, "Webhook einschalten braucht eine Webhook-Adresse"),
    ({"hook_events": ["drift", "cap"]}, "Unbekanntes Ereignis: cap")])
def test_more_bad_settings_are_named_and_nothing_is_stored(api, change, detail):
    r = api.put("/api/settings/alerts", json={**MAIL, **change})
    assert (r.status_code, r.json()["detail"]) == (422, detail)
    assert dbfix.query("SELECT key FROM settings") == [] and dbfix.query("SELECT 1 FROM audit") == []


@pytest.mark.parametrize("host", ["10.0.0.25", "2001:db8::25", "smtp-relay", "Mail.Example.org"])
def test_an_ip_address_or_a_hostname_is_a_mail_server(api, host):
    assert api.put("/api/settings/alerts", json={**MAIL, "smtp_host": host}).status_code == 200


def test_without_tls_a_relay_without_login_is_fine(api):
    assert api.put("/api/settings/alerts", json={**MAIL, "smtp_security": "none", "smtp_port": 25, "smtp_user": " ", "smtp_pass": None}).status_code == 200


def test_the_webhook_can_go_on_with_its_stored_address(api):
    api.put("/api/settings/alerts", json={**MAIL, "webhook_url": HOOK_URL})
    assert api.put("/api/settings/alerts", json={**MAIL, "hook_on": True, "webhook_url": None}).status_code == 200


def test_a_422_never_echoes_a_secret(api):
    r = api.put("/api/settings/alerts", json={**MAIL, "webhook_url": "https://x/" + "s3cret" * 400})
    assert r.status_code == 422 and "s3cret" not in r.text


def test_a_422_at_the_password_never_echoes_it(api):
    r = api.put("/api/settings/alerts", json={**MAIL, "smtp_pass": "s3cret" * 40, "smtp_port": 0})
    assert r.status_code == 422 and "s3cret" not in r.text


def test_the_webhook_target_shows_no_user_password_or_path(api):
    api.put("/api/settings/alerts", json={**MAIL, "hook_on": True, "webhook_url": "https://bot:pw-s3cret@hook.example.org:8443/x?sig=s3cret"})
    assert api.get("/api/settings/alerts").json()["webhook_target"] == "https://hook.example.org:8443"


# ── The queue ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

async def test_nothing_is_queued_while_no_channel_is_on(database):
    assert await alerts.emit("reachability", "SW-A antwortet nicht", "…", switch_id=1, key="1:1") == 0 and dbfix.query("SELECT 1 FROM alert_outbox") == []


async def test_an_event_goes_to_each_channel_that_wants_it(database):
    await configure(mail=True, hook=True)
    assert await alerts.emit("reachability", "SW-A antwortet nicht", "x", switch_id=1, key="1") == 1
    assert outbox() == [("mail", "reachability", "queued")]
    assert await alerts.emit("drift", "Port 5 geändert", "x", switch_id=1, key="1:5") == 2
    assert outbox() == [("mail", "reachability", "queued"), ("mail", "drift", "queued"), ("webhook", "drift", "queued")]
    assert await alerts.emit("approval", "Freigabe angefordert", "x") == 0 and len(outbox()) == 3


async def test_a_queued_row_has_its_one_line_title_its_text_and_facts(database, monkeypatch):
    await configure(mail=True)
    monkeypatch.setattr(alerts, "_now", lambda: FROZEN)
    await alerts.emit("drift", "Port 5\r\ngeändert " + "x" * 300, "y" * 3000, switch_id=3, switch_name="SW-C", key="3:5", facts={"Port": "5"})
    [row] = outbox("created_at, channel, event, dedup_key, switch_id, switch_name, title, text, facts, status, attempts, next_at, sent_at, "
                   "error, repeats")
    assert row == ("2026-11-07 10:00:00", "mail", "drift", "drift:3:5", 3, "SW-C", ("Port 5  geändert " + "x" * 300)[:200], "y" * 2000,
                   '{"Port": "5"}', "queued", 0, "2026-11-07 10:00:00", None, None, 0)


async def test_the_same_event_within_the_window_is_counted_not_queued(database):
    await configure(mail=True)
    await alerts.emit("drift", "T", "x", key="drift_port:1:5")
    await alerts.emit("drift", "T", "x", key="drift_port:1:5")
    assert dbfix.query("SELECT status, repeats FROM alert_outbox") == [("queued", 1)]


async def test_a_sent_or_failed_row_counts_a_repeat_too(database):
    await configure(mail=True)
    await alerts.emit("drift", "T", "x", key="k")
    dbfix.query("UPDATE alert_outbox SET status = 'sent'")
    assert await alerts.emit("drift", "T", "x", key="k") == 0
    assert dbfix.query("SELECT status, repeats FROM alert_outbox") == [("sent", 1)]


async def test_after_the_window_it_is_queued_again(database):
    await configure(mail=True)
    await alerts.emit("drift", "T", "x", key="drift_port:1:5")
    dbfix.query("UPDATE alert_outbox SET created_at = datetime(created_at, '-61 minutes')")
    assert await alerts.emit("drift", "T", "x", key="drift_port:1:5") == 1
    assert dbfix.query("SELECT status, repeats FROM alert_outbox ORDER BY id") == [("queued", 0), ("queued", 0)]


async def test_the_cap_queues_one_summary_and_suppresses_the_rest(database):  # Review Focus 4
    await configure(mail=True)
    for i in range(alerts.CAP_PER_HOUR + 5):
        await alerts.emit("reachability", f"SW-{i}", "x", key=str(i))
    assert dbfix.query("SELECT status, count(*) FROM alert_outbox WHERE event <> 'cap' GROUP BY status ORDER BY status") == [("queued", 30), ("suppressed", 5)]
    assert dbfix.query("SELECT title, status FROM alert_outbox WHERE event = 'cap'") == [("Zu viele Meldungen", "queued")]


async def test_a_suppressed_message_takes_no_repeat_and_goes_out_once_the_hour_has_room(database):
    await configure(mail=True)
    for i in range(alerts.CAP_PER_HOUR):
        await alerts.emit("reachability", "T", "x", key=str(i))
    dbfix.query("UPDATE alert_outbox SET created_at = datetime(created_at, '-50 minutes')")
    assert await alerts.emit("reachability", "T", "x", key="late") == 1    # the summary
    dbfix.query("UPDATE alert_outbox SET created_at = datetime(created_at, '-20 minutes')")    # the 30 leave the hour, the summary stays
    assert await alerts.emit("reachability", "T", "x", key="late") == 1
    assert dbfix.query("SELECT status, repeats FROM alert_outbox WHERE dedup_key = 'reachability:late' ORDER BY id") == [("suppressed", 0),
                                                                                                                     ("queued", 0)]


async def test_the_summary_says_until_when_and_each_channel_counts_on_its_own(database, monkeypatch):
    await configure(mail=True, hook=True, events=["drift", "reachability"])
    times = iter([datetime(2026, 11, 7, 9, 15, tzinfo=timezone.utc)] + [FROZEN] * 200)
    monkeypatch.setattr(alerts, "_now", lambda: next(times))
    await alerts.emit("drift", "T", "x", key="first")
    for i in range(alerts.CAP_PER_HOUR):
        await alerts.emit("reachability", "T", "x", key=str(i))
    assert dbfix.query("SELECT channel, text FROM alert_outbox WHERE event = 'cap' ORDER BY id") == [
        (channel, "In der letzten Stunde gingen 30 Meldungen über diesen Weg hinaus. Bis 10:15 UTC sendet SwitchView hier keine weiteren; "
                  "sie stehen in SwitchView unter Einstellungen → Benachrichtigungen.") for channel in ("mail", "webhook")]
    assert dbfix.query("SELECT channel, count(*) FROM alert_outbox WHERE status = 'suppressed' GROUP BY channel ORDER BY channel") == [
        ("mail", 1), ("webhook", 1)]


async def test_concurrent_emits_never_pass_the_cap(database):
    await configure(mail=True)
    await asyncio.gather(*(alerts.emit("reachability", "T", "x", key=str(i)) for i in range(alerts.CAP_PER_HOUR + 10)))
    assert dbfix.query("SELECT event, status, count(*) FROM alert_outbox GROUP BY event, status ORDER BY event, status") == [
        ("cap", "queued", 1), ("reachability", "queued", 30), ("reachability", "suppressed", 10)]


async def test_emit_only_queues(database, monkeypatch):                     # Review Focus 4: a poll or a change never waits for a delivery
    await configure(mail=True, hook=True)
    monkeypatch.setattr(alerts, "_send", never)
    assert await alerts.emit("drift", "T", "x", key="k") == 2


async def test_emit_never_raises(database, monkeypatch, caplog):
    monkeypatch.setattr(alerts, "load_settings", dbfix.raising_async_fn(RuntimeError("weg")))
    assert await alerts.emit("drift", "T", "x") == 0 and "Benachrichtigung" in caplog.text


# ── Delivery ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

async def test_a_mail_goes_out_with_starttls_login_and_a_timeout(database, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    await configure(mail=True)
    await alerts.emit("reachability", "SW-A antwortet nicht", "Seit 3 Abfragen.", switch_id=1, key="a")
    assert await alerts.deliver_due() == 1
    assert smtp.calls[:4] == [("connect", "mail.example.org", 587, 10), ("starttls",), ("login", "sv", "mail-s3cret"),
                              ("send", "[SwitchView] SW-A antwortet nicht", "switchview@example.org", "netz@example.org")]
    assert dbfix.query("SELECT status, attempts FROM alert_outbox") == [("sent", 0)]
    assert smtp.calls[4:] == [("quit",)] and dbfix.query("SELECT sent_at IS NOT NULL FROM alert_outbox") == [(1,)]


async def test_a_mail_reads_text_facts_and_the_event(database, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    await configure(mail=True)
    await alerts.emit("drift", "Port 5 geändert", "ungetaggt 1 → 20", switch_id=3, facts={"Switch": "SW-C", "Port": "5"})
    await alerts.deliver_due()
    [msg] = smtp.sent
    assert msg.get_content() == "ungetaggt 1 → 20\n\nSwitch: SW-C\nPort: 5\n\nEreignis: Änderung außerhalb von SwitchView · SwitchView\n"


@pytest.mark.parametrize("security, cls, starttls", [("tls", "SMTP_SSL", False), ("none", "SMTP", False), ("starttls", "SMTP", True)])
async def test_each_security_mode_uses_its_smtp_way(database, monkeypatch, security, cls, starttls):
    smtp = fake_smtp(monkeypatch)
    await configure(mail=True)
    setting("smtp_security", security)
    setting("smtp_port", {"tls": "465", "none": "25", "starttls": "2587"}[security])
    if security == "none":
        setting("smtp_user", "")
    await alerts.emit("drift", "T", "x")
    assert await alerts.deliver_due() == 1
    assert smtp.classes == [cls] and (("starttls",) in smtp.calls) == starttls
    assert smtp.calls[0] == ("connect", "mail.example.org", {"tls": 465, "none": 25, "starttls": 2587}[security], 10)
    assert any(c[0] == "login" for c in smtp.calls) == (security != "none")
    assert [type(c) for c in smtp.contexts] == ([] if security == "none" else [ssl.SSLContext])


@pytest.mark.parametrize("verify, mode, hostname", [("1", ssl.CERT_REQUIRED, True), ("0", ssl.CERT_NONE, False)])
async def test_without_the_certificate_check_the_context_does_not_verify(database, monkeypatch, verify, mode, hostname):
    smtp = fake_smtp(monkeypatch)
    await configure(mail=True)
    setting("smtp_verify_tls", verify)
    await alerts.emit("drift", "T", "x")
    await alerts.deliver_due()
    [context] = smtp.contexts
    assert (context.verify_mode, context.check_hostname) == (mode, hostname)


async def test_a_teams_webhook_posts_an_adaptive_card_with_timeout_and_verify(database, monkeypatch):
    hook = Hook()
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(hook=True)
    await alerts.emit("drift", "Port 5 geändert", "ungetaggt 1 → 20", switch_id=3, switch_name="SW-C", facts={"Switch": "SW-C"})
    await alerts.deliver_due()
    [card] = [s["json"] for s in hook.sent]
    body = card["attachments"][0]["content"]["body"]
    assert hook.made == [{"timeout": 10, "verify": True}] and hook.urls == [HOOK_URL] and card["type"] == "message"
    assert body[0]["text"] == "Port 5 geändert" and body[2]["facts"] == [{"title": "Switch", "value": "SW-C"}]
    assert card == {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": [
            {"type": "TextBlock", "text": "Port 5 geändert", "weight": "Bolder", "size": "Medium", "wrap": True},
            {"type": "TextBlock", "text": "ungetaggt 1 → 20", "wrap": True},
            {"type": "FactSet", "facts": [{"title": "Switch", "value": "SW-C"}]}]}}]}
    assert dbfix.query("SELECT status FROM alert_outbox") == [("sent",)]


async def test_without_the_certificate_check_the_webhook_does_not_verify(database, monkeypatch):
    hook = Hook()
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(hook=True)
    setting("hook_verify_tls", "0")
    await alerts.emit("drift", "T", "x")
    await alerts.deliver_due()
    assert hook.made == [{"timeout": 10, "verify": False}]


async def test_a_json_webhook_posts_the_plain_event(database, monkeypatch):
    hook = Hook()
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    monkeypatch.setattr(alerts, "_now", lambda: FROZEN)
    await configure(hook=True)
    setting("hook_format", "json")
    await alerts.emit("drift", "Port 5 geändert", "ungetaggt 1 → 20", switch_id=3, switch_name="SW-C", facts={"Switch": "SW-C", "_view": "x"})
    await alerts.deliver_due()
    assert [s["json"] for s in hook.sent] == [{"source": "switchview", "event": "drift", "title": "Port 5 geändert", "text": "ungetaggt 1 → 20",
                                               "switch": {"id": 3, "name": "SW-C"}, "facts": {"Switch": "SW-C"}, "at": "2026-11-07T10:00:00Z",
                                               "url": None}]


def test_a_json_payload_without_a_switch_names_none():
    assert alerts.webhook_payload("json", item(), "https://sv.example.org/")["switch"] is None
    assert alerts.webhook_payload("json", item(), "https://sv.example.org/")["url"] == "https://sv.example.org/"


async def test_a_failed_send_is_retried_with_backoff_then_failed_and_audited(database, monkeypatch):   # Review Focus 4
    hook = Hook()
    hook.status[("POST", HOOK_URL)] = 500
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(hook=True)
    monkeypatch.setattr(alerts, "_now", lambda: datetime(2026, 11, 7, 10, 0, tzinfo=timezone.utc))
    await alerts.emit("drift", "T", "x")
    waits = []
    for _ in range(alerts.MAX_ATTEMPTS):
        dbfix.query("UPDATE alert_outbox SET next_at = '2000-01-01 00:00:00' WHERE status = 'queued'")
        await alerts.deliver_due()
        waits += dbfix.query("SELECT next_at FROM alert_outbox WHERE status = 'queued'")
    assert dbfix.query("SELECT status, attempts, error FROM alert_outbox") == [("failed", 5, "HTTP 500")] and len(waits) == 4
    assert dbfix.query("SELECT username, action, target, detail, role FROM audit") == [(None, "alert_failed", "webhook", "#1 T: HTTP 500", None)]
    assert [w for (w,) in waits] == ["2026-11-07 10:01:00", "2026-11-07 10:02:00", "2026-11-07 10:04:00", "2026-11-07 10:08:00"]   # alerts._now frozen at 10:00


async def test_a_row_not_due_yet_waits_and_a_redirect_is_a_failure(database, monkeypatch):
    hook = Hook()
    hook.status[("POST", HOOK_URL)] = 302
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(hook=True)
    await alerts.emit("drift", "T", "x")
    assert await alerts.deliver_due() == 1 and await alerts.deliver_due() == 0
    assert dbfix.query("SELECT status, attempts, error FROM alert_outbox") == [("queued", 1, "HTTP 302")] and len(hook.sent) == 1


async def test_a_run_sends_at_most_a_batch_oldest_first(database, monkeypatch):
    hook = Hook()
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(hook=True)
    for i in range(alerts.BATCH + 3):
        await alerts.emit("drift", f"T{i}", "x", key=str(i))
    assert await alerts.deliver_due() == alerts.BATCH
    assert [s["json"]["attachments"][0]["content"]["body"][0]["text"] for s in hook.sent] == [f"T{i}" for i in range(alerts.BATCH)]
    assert await alerts.deliver_due() == 3 and dbfix.query("SELECT DISTINCT status FROM alert_outbox") == [("sent",)]


async def test_a_hanging_server_costs_at_most_the_timeout(database, monkeypatch):   # Review Focus 4
    smtp = fake_smtp(monkeypatch)
    smtp.raises["connect"] = socket.timeout("timed out")
    hook = Hook()
    hook.raises[("POST", HOOK_URL)] = httpx.ReadTimeout("read timed out")
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(mail=True, hook=True)
    await alerts.emit("drift", "T", "x")
    assert await alerts.deliver_due() == 2
    assert outbox("channel, status, attempts, error") == [("mail", "queued", 1, "Zeitüberschreitung nach 10 s"),
                                                         ("webhook", "queued", 1, "Zeitüberschreitung nach 10 s")]
    assert smtp.calls == [("connect", "mail.example.org", 587, 10)] and hook.made == [{"timeout": 10, "verify": True}]


async def test_a_webhook_that_never_answers_ends_after_the_timeout(database, monkeypatch):   # Review Focus 4

    class Hanging:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, **kwargs):
            await asyncio.sleep(3600)

    monkeypatch.setattr(alerts, "httpx", types.SimpleNamespace(AsyncClient=Hanging))
    monkeypatch.setattr(alerts, "TIMEOUT_S", 0.05)
    await configure(hook=True)
    await alerts.emit("drift", "T", "x")
    assert await asyncio.wait_for(alerts.deliver_due(), 5) == 1
    assert outbox("status, error") == [("queued", "Zeitüberschreitung nach 0.05 s")]


async def test_no_secret_reaches_an_error_text(api, monkeypatch):                     # Review Focus 4
    smtp = fake_smtp(monkeypatch)
    smtp.raises["login"] = smtplib.SMTPAuthenticationError(535, b"auth failed for sv mail-s3cret")
    hook = Hook()
    hook.raises[("POST", HOOK_URL)] = httpx.ConnectError(HOOK_URL)
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(mail=True, hook=True)
    await alerts.emit("drift", "T", "x")
    for _ in range(alerts.MAX_ATTEMPTS):
        due_now()
        await alerts.deliver_due()
    assert outbox("channel, status, error") == [("mail", "failed", "SMTP 535: auth failed for sv ***"),
                                               ("webhook", "failed", "Verbindung fehlgeschlagen (ConnectError)")]
    shown = json.dumps([outbox("error"), dbfix.query("SELECT detail FROM audit"), api.get("/api/alerts/deliveries").json()])
    assert "mail-s3cret" not in shown and "hook-s3cret-token" not in shown and "prod.example.org" not in shown


@pytest.mark.parametrize("exc, text", [
    (TimeoutError(), "Zeitüberschreitung nach 10 s"), (httpx.ConnectTimeout("x"), "Zeitüberschreitung nach 10 s"),
    (alerts.HookStatus(404), "HTTP 404"), (httpx.RemoteProtocolError(HOOK_URL), "Verbindung fehlgeschlagen (RemoteProtocolError)"),
    (smtplib.SMTPRecipientsRefused({"netz@example.org": (550, b"no")}), "SMTPRecipientsRefused: {'netz@example.org': (550, b'no')}"),
    (smtplib.SMTPDataError(554, "Nachricht abgelehnt: " + "y" * 300), "SMTP 554: Nachricht abgelehnt: " + "y" * 179),
    (ConnectionRefusedError(111, "Connection refused"), "ConnectionRefusedError: Connection refused"),
    (OSError("ohne Nummer mail-s3cret"), "OSError: ohne Nummer ***"), (ValueError(HOOK_URL), "ValueError")])
def test_an_error_text_comes_from_a_status_or_a_type(exc, text):
    assert alerts.error_text(exc, ["mail-s3cret", HOOK_URL]) == text


async def test_an_unreadable_secret_counts_as_missing(database, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    await configure(mail=True)
    setting("smtp_pass", "gAAAAA-kaputt")
    assert await alerts.emit("drift", "T", "x") == 1
    assert await alerts.deliver_due() == 0
    assert outbox("status, attempts, error") == [("failed", 0, "Kanal ausgeschaltet oder nicht eingerichtet")] and smtp.calls == []
    assert dbfix.query("SELECT action, target, detail FROM audit") == [("alert_failed", "mail", "#1 T: Kanal ausgeschaltet oder nicht eingerichtet")]
    assert alerts.public_view(await db.load_settings(alerts.SETTINGS_KEYS))["unreadable"] == ["smtp_pass"]


async def test_an_unreadable_webhook_address_counts_as_missing(database, monkeypatch):
    hook = Hook()
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(hook=True)
    setting("webhook_url", "gAAAAA-kaputt")
    await alerts.emit("drift", "T", "x")
    assert await alerts.deliver_due() == 0 and hook.made == []
    view = alerts.public_view(await db.load_settings(alerts.SETTINGS_KEYS))
    assert (view["unreadable"], view["webhook_url_set"], view["webhook_target"]) == (["webhook_url"], True, "")


@pytest.mark.parametrize("after", ["0", "1"])     # switched off, or off and on again
async def test_a_channel_switched_off_during_a_run_sends_nothing_more(database, monkeypatch, after):
    hook = Hook()
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    await configure(hook=True)
    for key in ("a", "b", "c"):
        await alerts.emit("drift", "T", "x", key=key)
    send = alerts._send

    async def send_then_switch_off(cfg, channel, item):    # what PUT /api/settings/alerts with hook_on false does meanwhile
        await send(cfg, channel, item)
        async with db.db() as conn:
            await db.write_settings(conn, {"hook_on": "0"})
            await alerts.drop_queued(conn, "webhook")
            await db.write_settings(conn, {"hook_on": after})
            await conn.commit()

    monkeypatch.setattr(alerts, "_send", send_then_switch_off)
    assert await alerts.deliver_due() == 1 and len(hook.sent) == 1
    assert outbox("status, error") == [("sent", None), ("failed", "Kanal ausgeschaltet"), ("failed", "Kanal ausgeschaltet")]


async def test_a_channel_switched_off_since_fails_its_queued_rows(database, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    await configure(mail=True)
    await alerts.emit("drift", "T", "x")
    setting("mail_on", "0")
    assert await alerts.deliver_due() == 0 and smtp.calls == []
    assert outbox("status, error") == [("failed", "Kanal ausgeschaltet oder nicht eingerichtet")]


# ── Texts ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_a_subject_with_a_line_break_is_one_line():                                        # Review Focus 5
    msg = alerts.mail_message(CFG_MAIL, item(title="Port 5\r\nBcc: x@evil.example"), None)
    assert msg["Subject"] == "[SwitchView] Port 5  Bcc: x@evil.example" and msg["Bcc"] is None


def test_a_mail_goes_to_every_recipient_and_names_its_link():
    msg = alerts.mail_message(CFG_MAIL | {"recipients": ["a@example.org", "b@example.org"]}, item(event="cap", text="Zu viel."),
                              "https://sv.example.org/")
    assert (msg["From"], msg["To"]) == ("switchview@example.org", "a@example.org, b@example.org")
    assert msg.get_content() == "Zu viel.\n\nIn SwitchView öffnen: https://sv.example.org/\n\nEreignis: Zu viele Meldungen · SwitchView\n"


def test_a_fact_whose_key_starts_with_an_underscore_is_no_fact():
    item_ = item(facts=json.dumps({"Switch": "SW", "_view": "approvals"}))
    body = alerts.mail_message(CFG_MAIL, item_, None).get_content()
    assert "Switch: SW" in body and "_view" not in body and alerts.webhook_payload("json", item_, None)["facts"] == {"Switch": "SW"}
    assert alerts.webhook_payload("teams", item_, None)["attachments"][0]["content"]["body"][2]["facts"] == [{"title": "Switch", "value": "SW"}]


def test_teams_text_escapes_markdown():                                                    # Review Focus 5
    card = alerts.webhook_payload("teams", item(text="Beschreibung [klick](https://evil.example) *fett*"), None)
    assert card["attachments"][0]["content"]["body"][1]["text"] == r"Beschreibung \[klick\]\(https://evil.example\) \*fett\*"


def test_md_escape_puts_a_backslash_before_each_markdown_character():
    assert alerts.md_escape(r"a\b*c_d`e[f]g(h)i#j<k>l~m.n:o/p") == r"a\\b\*c\_d\`e\[f\]g\(h\)i\#j\<k\>l\~m.n:o/p"
    card = alerts.webhook_payload("teams", item(title="**T**", facts=json.dumps({"_a_": "<b>"})), None)
    assert card["attachments"][0]["content"]["body"][0]["text"] == r"\*\*T\*\*" and card["attachments"][0]["content"]["body"][2]["facts"] == []


def test_a_teams_card_with_a_link_has_its_button():
    card = alerts.webhook_payload("teams", item(), "https://sv.example.org/#sw=3")
    assert card["attachments"][0]["content"]["actions"] == [{"type": "Action.OpenUrl", "title": "In SwitchView öffnen",
                                                             "url": "https://sv.example.org/#sw=3"}]
    assert "actions" not in alerts.webhook_payload("teams", item(), None)["attachments"][0]["content"]


@pytest.mark.parametrize("url, sid, view, link", [("", 3, None, None), ("https://sv.example.org", 3, None, "https://sv.example.org/#sw=3"),
                                                  ("https://sv.example.org", None, "approvals", "https://sv.example.org/#approvals"),
                                                  ("https://sv.example.org", None, None, "https://sv.example.org/")])
def test_the_link_points_at_the_switch_when_a_public_url_is_set(monkeypatch, url, sid, view, link):
    monkeypatch.setattr(alerts, "settings", config.Settings(public_url=url))
    assert alerts.link_for(sid, view) == link


async def test_a_delivered_message_links_its_switch_or_its_view(database, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    monkeypatch.setattr(alerts, "settings", config.Settings(public_url="https://sv.example.org"))
    await configure(mail=True, events=["drift", "approval"])
    await alerts.emit("drift", "T", "x", switch_id=3)
    await alerts.emit("approval", "Freigabe angefordert", "x", switch_id=3, facts={"_view": "approvals"})
    await alerts.deliver_due()
    assert ["In SwitchView öffnen: https://sv.example.org/#sw=3" in smtp.sent[0].get_content(),
            "In SwitchView öffnen: https://sv.example.org/#approvals" in smtp.sent[1].get_content()] == [True, True]


@pytest.mark.parametrize("url", ["", "https://sv.example.org", "http://10.0.0.5:8080", "https://sv.example.org/switchview"])
def test_the_start_takes_a_public_url_with_http_or_https(url):
    assert main.check_startup_config(config.Settings(secret_key=secrets.token_hex(32), public_url=url)) == []


@pytest.mark.parametrize("url", ["sv.example.org", "https://", "https:// sv", "https://sv.example.org/a b"])
def test_the_start_refuses_a_public_url_that_is_none(url):
    with pytest.raises(RuntimeError, match="PUBLIC_URL muss mit http:// oder https:// beginnen"):
        main.check_startup_config(config.Settings(secret_key=secrets.token_hex(32), public_url=url))


@pytest.mark.parametrize("value, url", [(" https://sv.example.org/ ", "https://sv.example.org"), ("", ""),
                                        ("https://sv.example.org/switchview//", "https://sv.example.org/switchview")])
def test_public_url_is_read_trimmed_without_a_trailing_slash(monkeypatch, value, url):
    monkeypatch.setenv("PUBLIC_URL", value)
    assert config.Settings().public_url == url


# ── Routes ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_the_test_button_sends_now_and_says_why_it_failed(api, monkeypatch):
    smtp = fake_smtp(monkeypatch)
    assert api.post("/api/alerts/test", json={"channel": "mail"}).json() == {"ok": False, "error": "Nicht eingerichtet: erst speichern"}
    api.put("/api/settings/alerts", json={**MAIL, "mail_on": False})
    assert api.post("/api/alerts/test", json={"channel": "mail"}).json() == {"ok": True, "error": None}
    assert smtp.calls[3] == ("send", "[SwitchView] SwitchView: Testnachricht", "switchview@example.org", "netz@example.org")
    assert smtp.sent[0].get_content().startswith("Diese Nachricht hat ein Admin in SwitchView ausgelöst (Einstellungen → Benachrichtigungen).")
    smtp.raises["login"] = smtplib.SMTPAuthenticationError(535, b"5.7.8 Authentication failed mail-s3cret")
    assert api.post("/api/alerts/test", json={"channel": "mail"}).json() == {"ok": False, "error": "SMTP 535: 5.7.8 Authentication failed ***"}
    assert dbfix.query("SELECT 1 FROM alert_outbox") == []
    assert dbfix.query("SELECT action, target, detail FROM audit WHERE action = 'alert_test' ORDER BY id") == [
        ("alert_test", "mail", "Nicht eingerichtet: erst speichern"), ("alert_test", "mail", "ok"),
        ("alert_test", "mail", "SMTP 535: 5.7.8 Authentication failed ***")]


def test_the_test_button_of_the_webhook_posts_now(api, monkeypatch):
    hook = Hook()
    monkeypatch.setattr(alerts, "httpx", apifix.fake_httpx(hook))
    api.put("/api/settings/alerts", json={**MAIL, "webhook_url": HOOK_URL})
    assert api.post("/api/alerts/test", json={"channel": "webhook"}).json() == {"ok": True, "error": None}
    assert [s["json"]["attachments"][0]["content"]["body"][0]["text"] for s in hook.sent] == ["SwitchView: Testnachricht"]
    hook.status[("POST", HOOK_URL)] = 403
    assert api.post("/api/alerts/test", json={"channel": "webhook"}).json() == {"ok": False, "error": "HTTP 403"}
    assert api.post("/api/alerts/test", json={"channel": "sms"}).status_code == 422


def test_turning_a_channel_off_drops_its_queued_messages(api):
    api.put("/api/settings/alerts", json={**MAIL, "mail_events": ["drift"], "hook_on": True, "webhook_url": HOOK_URL, "hook_events": ["drift"]})
    asyncio.run(alerts.emit("drift", "T", "x", key="1"))
    asyncio.run(alerts.emit("drift", "T", "x", key="2"))
    assert api.put("/api/settings/alerts", json={**MAIL, "mail_on": False, "hook_on": True, "hook_events": ["drift"]}).json() == {
        "ok": True, "cleared": [], "dropped": 2}
    assert outbox("channel, status, error") == [("mail", "failed", "Kanal ausgeschaltet"), ("webhook", "queued", None),
                                               ("mail", "failed", "Kanal ausgeschaltet"), ("webhook", "queued", None)]
    assert dbfix.query("SELECT detail FROM audit ORDER BY id DESC LIMIT 1") == [
        ("Mail: aus, mail.example.org:587 (starttls), 1 Empfänger; Webhook: an, teams; 2 wartende Meldungen verworfen",)]


def test_one_dropped_message_is_named_in_the_singular(api):
    api.put("/api/settings/alerts", json={**MAIL, "mail_events": ["drift"]})
    asyncio.run(alerts.emit("drift", "T", "x"))
    assert api.put("/api/settings/alerts", json={**MAIL, "mail_on": False}).json()["dropped"] == 1
    assert dbfix.query("SELECT detail FROM audit ORDER BY id DESC LIMIT 1")[0][0].endswith("; 1 wartende Meldung verworfen")


def test_failed_deliveries_are_listed_for_the_admin(api):
    api.put("/api/settings/alerts", json={**MAIL, "mail_events": ["drift", "reachability"]})
    asyncio.run(alerts.emit("drift", "Port 5 geändert", "x", switch_id=3, switch_name="SW-C", key="a"))
    asyncio.run(alerts.emit("reachability", "SW-A antwortet nicht", "x", key="b"))
    dbfix.query("UPDATE alert_outbox SET status = 'failed', attempts = 5, error = 'HTTP 500', next_at = NULL WHERE id = 1")
    got = api.get("/api/alerts/deliveries?status=failed").json()
    [(created_at,)] = dbfix.query("SELECT created_at FROM alert_outbox WHERE id = 1")
    assert got == {"rows": [{"id": 1, "created_at": created_at, "channel": "mail", "event": "drift", "label": "Änderung außerhalb von SwitchView",
                             "switch_name": "SW-C", "title": "Port 5 geändert", "status": "failed", "attempts": 5, "next_at": None,
                             "sent_at": None, "error": "HTTP 500", "repeats": 0}], "next": None}
    assert [r["id"] for r in api.get("/api/alerts/deliveries").json()["rows"]] == [2, 1]


def test_the_deliveries_page_newest_first_by_a_cursor(api):
    api.put("/api/settings/alerts", json={**MAIL, "mail_events": ["drift"]})
    for i in range(5):
        asyncio.run(alerts.emit("drift", "T", "x", key=str(i)))
    first = api.get("/api/alerts/deliveries?limit=2").json()
    second = api.get(f"/api/alerts/deliveries?limit=2&cursor={first['next']}").json()
    third = api.get(f"/api/alerts/deliveries?limit=2&cursor={second['next']}").json()
    assert [[r["id"] for r in p["rows"]] for p in (first, second, third)] == [[5, 4], [3, 2], [1]] and third["next"] is None


@pytest.mark.parametrize("query", ["status=offen", "limit=0", "limit=101", "cursor=0"])
def test_a_bad_deliveries_question_is_a_422(api, query):
    assert api.get(f"/api/alerts/deliveries?{query}").status_code == 422


def test_the_alert_routes_are_admin_only(api):
    apifix.become(apifix.user("freigeben"))
    for method, path in (("GET", "/api/settings/alerts"), ("PUT", "/api/settings/alerts"), ("POST", "/api/alerts/test"),
                         ("GET", "/api/alerts/deliveries")):
        assert api.request(method, path, json={**MAIL}).status_code == 403, path


async def test_the_purge_keeps_queued_rows_whatever_their_age(database):
    await configure(mail=True)
    for key in ("a", "b", "c"):
        await alerts.emit("drift", "T", "x", key=key)
    dbfix.query("UPDATE alert_outbox SET created_at = '2000-01-01 00:00:00'")
    dbfix.query("UPDATE alert_outbox SET status = 'sent' WHERE dedup_key = 'drift:a'")
    dbfix.query("UPDATE alert_outbox SET status = 'failed' WHERE dedup_key = 'drift:b'")
    assert (await history.purge(180)).get("alert_outbox") == 2 and outbox("dedup_key, status") == [("drift:c", "queued")]
