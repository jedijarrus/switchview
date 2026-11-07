"""Phase 4b Task 10: the cards of Tasks 5-7 in the UI, against the recording DOM stub of tests/test_frontend_dom.py - under
"Einstellungen" the card "Benachrichtigungen" (Admin: the two channels, the events of each, the test buttons, the latest messages;
below Admin one sentence and no request) and the card "Sicherheitsregeln" (everyone reads, an Admin switches built-in rules off and
keeps custom ones), under "Geräte" the "Beobachtungsliste" (Ändern keeps it), and for an Admin the messages not delivered among the
overview's "Auffälligkeiten". Skipped without node."""
import json
import re
import shutil
from datetime import datetime, timedelta, timezone

import pytest
from test_frontend_dom import SETTINGS_ANSWER, STATIC, in_dom, role_me

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

EVENTS = {"reachability": "Switch nicht erreichbar oder wieder erreichbar", "drift": "Änderung außerhalb von SwitchView",
          "watch": "Beobachtete MAC-Adresse gesehen"}
ALERTS = {"mail_on": True, "smtp_host": "mail.example.org", "smtp_port": 587, "smtp_security": "starttls", "smtp_verify_tls": True, "smtp_user": "sv",
          "mail_from": "switchview@example.org", "mail_to": ["netz@example.org", "noc@example.org"], "mail_events": ["reachability", "drift"],
          "hook_on": False, "hook_format": "json", "hook_verify_tls": False, "hook_events": ["drift"], "smtp_pass_set": True, "webhook_url_set": True,
          "webhook_target": "https://workflow.example.com", "unreadable": [], "events": EVENTS, "public_url": None,
          "limits": {"dedup_minutes": 60, "cap_per_hour": 30, "attempts": 5}}
RULES = {"rules": [
    {"id": "telnet", "label": "Telnet-Server an", "severity": "crit", "source": "config", "hint": "Ab Werk an. Abschalten: no telnet-server (SSH bleibt).",
     "on": True, "custom": False},
    {"id": "web_plaintext", "label": "Web-Oberfläche per HTTP", "severity": "warn", "source": "config", "hint": "Nur <HTTPS>.", "on": True, "custom": False},
    {"id": "c1", "label": "Kein VLAN 666", "severity": "warn", "source": "custom", "hint": "", "on": True, "custom": True, "mode": "must_not",
     "text": 'vlan 666 "x"'}]}
DELIVERIES = [
    {"id": 4, "created_at": "2026-11-07 10:00:00", "channel": "mail", "event": "drift", "label": "Änderung außerhalb von SwitchView", "switch_name": "SW",
     "title": "SW: Port 5 <geändert>", "status": "sent", "attempts": 1, "next_at": None, "sent_at": "2026-11-07 10:00:05", "error": None, "repeats": 2},
    {"id": 3, "created_at": "2026-11-07 09:00:00", "channel": "webhook", "event": "watch", "label": "", "switch_name": "SW", "title": "MAC gesehen",
     "status": "queued", "attempts": 2, "next_at": "2026-11-07 09:10:00", "sent_at": None, "error": "HTTP 503", "repeats": 0},
    {"id": 2, "created_at": "2026-11-07 08:00:00", "channel": "webhook", "event": "drift", "label": "", "switch_name": "SW", "title": "Neu",
     "status": "queued", "attempts": 0, "next_at": "2026-11-07 08:00:00", "sent_at": None, "error": None, "repeats": 0},
    {"id": 1, "created_at": "2026-11-07 07:00:00", "channel": "webhook", "event": "drift", "label": "", "switch_name": "SW", "title": "Alt",
     "status": "failed", "attempts": 5, "next_at": None, "sent_at": None, "error": "HTTP 500 <x>", "repeats": 0},
    {"id": 0, "created_at": "2026-11-07 06:00:00", "channel": "mail", "event": "drift", "label": "", "switch_name": "SW", "title": "Zu viel",
     "status": "suppressed", "attempts": 0, "next_at": None, "sent_at": None, "error": None, "repeats": 0}]

# renderSettings as role, with the answers of the four GETs of the settings (alerts and rules as JSON or a JS expression); every call
# as [method, url, body]; then: the statements after the render, their value the test's
SETTINGS = ('(async () => { %s const calls = []; let alerts = %s, rules = %s, deliveries = %s, put = %s; '
            'api = async (m, u, b) => { calls.push([m, u, b === undefined ? null : b]); '
            'if (m === "PUT" || m === "POST") return typeof put === "function" ? put(u, b) : put; '
            'return u === "/api/settings" ? ' + SETTINGS_ANSWER + ' : u === "/api/zone-scopes" ? {entries: []} : u === "/api/compliance/rules" ? rules '
            ': u === "/api/settings/alerts" ? alerts : u === "/api/alerts/deliveries" ? deliveries : {}; }; await renderSettings(); %s })()')
CLICK = 'await $("#%s").handlers.click[0]({target: $("#%s")}); '
TOASTS = '$("#toasts").children.map(t => t.textContent)'
KEPT = 'gesetzt – leer lassen = unverändert"'


def settings(then, role="admin", alerts=ALERTS, rules=RULES, deliveries=None, put='{ok: true, cleared: [], dropped: 0}'):
    js = lambda v: v if isinstance(v, str) else json.dumps(v)     # noqa: E731 - a JS expression stays as it is
    return in_dom(SETTINGS % (role_me(role), js(alerts), js(rules), js(deliveries or {"rows": [], "next": None}), put, then))


def click(button):
    return CLICK % (button, button)


# The fields of the alert card as the browser holds them after the render (the stub keeps no markup), and the event boxes checked
FILL = ('Object.entries({"a-host": "mail.example.org", "a-port": "587", "a-sec": "starttls", "a-user": "sv", "a-pass": "", '
        '"a-from": "switchview@example.org", "a-to": %s, "a-url": "", "a-fmt": "json"}).forEach(([k, v]) => { $("#" + k).value = v; }); '
        '$("#a-mail-on").checked = true; $("#a-mtls").checked = true; document.lists["[data-mev]"] = [{dataset: {mev: "reachability"}, checked: true}, '
        '{dataset: {mev: "drift"}, checked: false}, {dataset: {mev: "watch"}, checked: true}]; '
        'document.lists["[data-hev]"] = [{dataset: {hev: "drift"}, checked: true}]; ')


def test_an_admin_gets_the_alert_card_and_saves_without_resending_secrets():
    then = ('const card = $("#view").innerHTML; ' + FILL % json.dumps(" netz@example.org\n\nnoc@example.org, ") + click("a-save")
            + 'return [card, calls, ' + TOASTS + ']; ')
    card, calls, toasts = settings(then)
    assert ('<p class="note" style="margin:0">SwitchView meldet Ereignisse per Mail und per Webhook (Microsoft Teams oder JSON). Dieselbe Meldung geht '
            'innerhalb von 60 Minuten einmal hinaus, je Weg höchstens 30 in der Stunde.</p>') in card
    for piece in ('<legend>Mail (SMTP)</legend>', '<input id="a-mail-on" type="checkbox" checked> Mail senden</label>',
                  '<span>Mailserver</span><input id="a-host" value="mail.example.org"',
                  '<span>Port</span><input id="a-port" type="number" min="1" max="65535" value="587"',
                  '<option value="starttls" selected>STARTTLS (Port 587)</option>', '<option value="tls">TLS (Port 465)</option>',
                  '<option value="none">Ohne Verschlüsselung (Port 25, ohne Anmeldung)</option>',
                  '<input id="a-mtls" type="checkbox" checked> TLS-Zertifikat prüfen</label>',
                  '<span>Benutzer</span><input id="a-user" value="sv"',
                  '<label for="a-pass">Kennwort</label><input id="a-pass" type="password" autocomplete="new-password" placeholder="' + KEPT,
                  '<span>Absender</span><input id="a-from" value="switchview@example.org"',
                  '<span>Empfänger (eine Adresse je Zeile)</span><textarea id="a-to" rows="3">netz@example.org\nnoc@example.org</textarea>',
                  '<input type="checkbox" data-mev="reachability" checked> Switch nicht erreichbar oder wieder erreichbar</label>',
                  '<input type="checkbox" data-mev="watch"> Beobachtete MAC-Adresse gesehen</label>', 'id="a-mtest">Test-Mail senden</button>',
                  '<legend>Webhook</legend>', '<input id="a-hook-on" type="checkbox"> Webhook senden</label>',
                  '<label for="a-url">Webhook-Adresse</label><input id="a-url" type="password" autocomplete="new-password" placeholder="' + KEPT,
                  '<span class="hint" id="a-url-hint">Ziel: https://workflow.example.com</span>',
                  '<option value="teams">Microsoft Teams (Workflow)</option>', '<option value="json" selected>JSON</option>',
                  '<input id="a-htls" type="checkbox"> TLS-Zertifikat prüfen</label>',
                  '<input type="checkbox" data-hev="drift" checked> Änderung außerhalb von SwitchView</label>', 'id="a-htest">Test senden</button>',
                  'id="a-save">Benachrichtigungen speichern</button>', 'Ohne PUBLIC_URL enthalten die Meldungen keinen Link zu SwitchView.',
                  'Letzte Meldungen'):
        assert piece in card, piece
    assert not re.search(r"<label\b(?:(?!</label>).)*<p\b", card, re.S)
    puts = [c for c in calls if c[0] == "PUT"]
    assert puts == [["PUT", "/api/settings/alerts", {"mail_on": True, "smtp_host": "mail.example.org", "smtp_port": 587, "smtp_security": "starttls",
                                                     "smtp_verify_tls": True, "smtp_user": "sv", "smtp_pass": None, "mail_from": "switchview@example.org",
                                                     "mail_to": ["netz@example.org", "noc@example.org"], "mail_events": ["reachability", "watch"],
                                                     "hook_on": False, "webhook_url": None, "hook_format": "json", "hook_verify_tls": False,
                                                     "hook_events": ["drift"]}]]
    # saved, the card is read again (the *_set of a new secret, the messages a channel switched off dropped)
    assert [c[1] for c in calls if c[0] == "GET" and c[1] == "/api/settings/alerts"] == ["/api/settings/alerts"] * 2
    assert toasts == ["Gespeichert"]


# Beyond the brief: a new password and a new webhook address go out as typed (the address trimmed), a new mail server (not the same
# one in another spelling, api_switches.same_destination) shows the note that the stored password goes, the toast names the
# password deleted and the messages dropped, and PUBLIC_URL drops its note
def test_a_new_mail_server_names_what_saving_deletes():
    alerts = {**ALERTS, "public_url": "https://sv.example.org"}
    then = ('const a = [$("#view").innerHTML]; ' + FILL % json.dumps("netz@example.org") + '$("#a-host").value = " MAIL.Example.org/ "; '
            '$("#a-host").fire("input"); a.push($("#a-host-note").hidden); $("#a-host").value = " neu.example.org "; $("#a-host").fire("input"); '
            'a.push($("#a-host-note").hidden, $("#a-host").getAttribute("aria-describedby")); '
            '$("#a-pass").value = " geheim "; $("#a-url").value = " https://x.example.org/hook "; ' + click("a-save")
            + 'return [...a, calls.filter(c => c[0] === "PUT")[0][2], ' + TOASTS + ']; ')
    card, hidden, shown, described, body, toasts = settings(then, alerts=alerts, put='{ok: true, cleared: ["smtp_pass"], dropped: 2}')
    assert ('<p class="note warn" id="a-host-note" style="margin:0" hidden>Neuer Mailserver: Das gespeicherte Kennwort gilt nur für den alten '
            'Mailserver. Was du hier nicht neu eingibst, löscht das Speichern.</p>') in card and "PUBLIC_URL" not in card
    assert (hidden, shown, described) == (True, False, "a-host-note")
    assert body["smtp_host"] == "neu.example.org" and body["smtp_pass"] == " geheim " and body["webhook_url"] == "https://x.example.org/hook"
    assert toasts == ["Gespeichert. Gelöscht wegen neuer Adresse: Mail-Kennwort. 2 wartende Meldungen verworfen"]


def test_an_unreadable_alert_secret_is_noted():
    card = settings('return $("#view").innerHTML; ', alerts={**ALERTS, "unreadable": ["smtp_pass", "webhook_url"], "webhook_target": ""})
    assert '<span class="note warn" id="a-pass-unread">lässt sich nicht entschlüsseln – bitte neu eingeben</span>' in card
    assert '<span class="note warn" id="a-url-unread">lässt sich nicht entschlüsseln – bitte neu eingeben</span>' in card
    assert re.search(r'<input id="a-pass" [^>]*aria-describedby="a-pass-unread"', card)
    assert re.search(r'<input id="a-url" [^>]*aria-describedby="a-url-hint a-url-unread"', card) and "Ziel:" not in card


@pytest.mark.parametrize("role", ["freigeben", "aendern", "lesen"])
def test_below_admin_the_alert_card_is_one_sentence_and_asks_nothing(role):
    card, calls = settings('return [$("#view").innerHTML, calls.map(c => c[1])]; ', role=role)
    assert '<p class="note gate">Benachrichtigungen einrichten braucht die Rolle „Admin“.</p>' in card and 'id="a-save"' not in card
    assert "/api/settings/alerts" not in calls and "/api/alerts/deliveries" not in calls and "/api/compliance/rules" in calls


def test_a_bad_recipient_is_named_before_anything_is_sent():
    then = FILL % json.dumps("netz@example.org\nkein-at") + click("a-save") + 'return [calls.filter(c => c[0] === "PUT").length, ' + TOASTS + ']; '
    assert settings(then) == [0, ["Mail-Adresse ungültig: kein-at"]]


# Beyond the brief: the limits of PUT /api/settings/alerts before the server's 422 answers in English - at most 20 recipients, a port
# of 1-65535
@pytest.mark.parametrize("to, port, said", [("\n".join(f"a{i}@b.de" for i in range(21)), "587", "Höchstens 20 Empfänger"),
                                            ("a@b.de", "0", "Port: eine ganze Zahl von 1 bis 65535"), ("a@b.de", "", "Port: eine ganze Zahl von 1 bis 65535"),
                                            ("a@b.de", "25.5", "Port: eine ganze Zahl von 1 bis 65535")])
def test_the_card_names_the_limits_before_anything_is_sent(to, port, said):
    then = (FILL % json.dumps(to) + f'$("#a-port").value = {json.dumps(port)}; ' + click("a-save")
            + 'return [calls.filter(c => c[0] === "PUT").length, ' + TOASTS + ']; ')
    assert settings(then) == [0, [said]]


def test_the_test_buttons_send_and_show_the_answer():
    put = '(u, b) => (u === "/api/alerts/test" && b.channel === "mail" ? {ok: false, error: "HTTP 500"} : {ok: true, error: null})'
    then = click("a-mtest") + click("a-htest") + 'return [calls.filter(c => c[0] === "POST"), ' + TOASTS + ', $("#a-mtest").disabled]; '
    posts, toasts, disabled = settings(then, put=put)
    assert posts == [["POST", "/api/alerts/test", {"channel": "mail"}], ["POST", "/api/alerts/test", {"channel": "webhook"}]]
    assert toasts == ["Test fehlgeschlagen: HTTP 500", "Test gesendet"] and disabled is False


def test_deliveries_show_their_state():
    rows = in_dom(f"deliveryRows({json.dumps(DELIVERIES)})")
    assert rows.count("<tr>") == 5 and rows.index("Alt") < rows.index("SW: Port 5")       # the one not delivered first, then newest first
    assert '<td>SW: Port 5 &lt;geändert&gt; · 2× wiederholt</td><td><span class="pill ok">zugestellt</span></td>' in rows
    assert '<td>Webhook</td><td>MAC gesehen</td><td><span class="pill neutral">wartet</span> · Versuch 2</td>' in rows
    assert '<td>Neu</td><td><span class="pill neutral">wartet</span></td>' in rows
    assert '<td>Alt</td><td><span class="pill crit">nicht zugestellt</span><span class="cellnote">HTTP 500 &lt;x&gt;</span></td>' in rows
    assert '<td>Mail</td><td>Zu viel</td><td><span class="pill neutral">unterdrückt (Obergrenze)</span></td>' in rows


# Beyond the brief: the card asks GET /api/alerts/deliveries (the latest 20) and shows them under "Letzte Meldungen"; none yet, or
# an answer without rows, reads "Noch keine Meldungen."; an answer of the settings without events draws the card without a field
@pytest.mark.parametrize("deliveries, want", [({"rows": DELIVERIES[:1], "next": None}, "<th>Zeit</th><th>Weg</th><th>Meldung</th><th>Stand</th>"),
                                              ({"rows": [], "next": None}, "Noch keine Meldungen."), ({"ok": True}, "Noch keine Meldungen.")])
def test_the_card_lists_the_latest_messages(deliveries, want):
    html, calls = settings('return [$("#a-deliv").innerHTML, calls.map(c => c[1])]; ', deliveries=deliveries)
    assert want in html and "/api/alerts/deliveries" in calls


@pytest.mark.parametrize("answer", ['{ok: true}', 'Promise.reject(new Error("Nicht erlaubt"))'], ids=["no-fields", "failed"])
def test_a_card_without_its_fields_draws_empty(answer):
    cards, calls = settings('return [$("#view").innerHTML.split("<h2>Benachrichtigungen</h2>")[1].split("<h2>Sitzungen</h2>")[0], calls.map(c => c[1])]; ',
                            alerts=answer, rules=answer)
    assert 'id="a-save"' not in cards and "data-rule" not in cards and "<h2>Sicherheitsregeln</h2>" in cards and "/api/alerts/deliveries" not in calls
    assert cards.count("Nicht erlaubt") == (2 if "reject" in answer else 0)


def test_the_rules_card_switches_rules_and_keeps_custom_ones():
    row = '({dataset: {crow: %s}, querySelector: s => ({"[data-cname]": {value: %s}, "[data-cmode]": {value: %s}, "[data-ctext]": {value: %s}})[s]})'
    rows = ", ".join(row % tuple(json.dumps(v) for v in r) for r in [("c1", "Kein VLAN 666", "must_not", 'vlan 666 "x"'),
                                                                      ("", " Banner ", "must", " banner motd "), ("", "", "must_not", " ")])
    banner = {"id": "c2", "label": "Banner", "severity": "warn", "source": "custom", "hint": "", "on": True, "custom": True, "mode": "must",
              "text": "banner motd"}
    saved = {"rules": [*RULES["rules"], banner]}
    then = ('const card = $("#view").innerHTML; const added = []; $("#r-custom").insertAdjacentHTML = (w, h) => added.push([w, h]); '
            '$("#r-custom").lastElementChild = {querySelector: s => (s === "[data-cname]" ? $("#new-name") : null)}; '
            + click("r-add") + 'const afterAdd = document.activeElement && document.activeElement.sel; '
            'document.lists["[data-rule]"] = [{dataset: {rule: "telnet"}, checked: false}, '
            '{dataset: {rule: "web_plaintext"}, checked: true}]; '
            f'document.lists["#r-custom [data-crow]"] = [{rows}]; ' + click("r-save")
            + 'return [card, added, afterAdd, calls.filter(c => c[0] === "PUT"), $("#rules-card").innerHTML, ' + TOASTS + ']; ')
    card, added, focused, puts, after, toasts = settings(then, put=json.dumps(saved))
    assert ('<label class="check"><input type="checkbox" data-rule="telnet" checked aria-describedby="rh-telnet"> <b>Telnet-Server an</b></label>'
            '<span class="hint" id="rh-telnet">Ab Werk an. Abschalten: no telnet-server (SSH bleibt).</span>') in card
    assert '<span class="hint" id="rh-web_plaintext">Nur &lt;HTTPS&gt;.</span>' in card and 'data-rule="c1"' not in card
    assert ('<div class="crule" data-crow="c1"><input data-cname name="r-name" aria-label="Name der Regel" placeholder="Name" maxlength="80" '
            'value="Kein VLAN 666"><select data-cmode name="r-mode" aria-label="Art der Regel"><option value="must_not" selected>keine Zeile enthält</option>'
            '<option value="must">eine Zeile enthält</option>'
            '</select><input data-ctext name="r-text" aria-label="Text der Regel" placeholder="Text, z. B. vlan 666" maxlength="200" '
            'value="vlan 666 &quot;x&quot;">'
            '<button class="btn small" type="button" data-cdel aria-label="Entfernen: Kein VLAN 666">Entfernen</button></div>') in card
    assert 'id="r-add">Regel hinzufügen</button>' in card and 'id="r-save">Regeln speichern</button>' in card
    assert added == [["beforeend", '<div class="crule" data-crow=""><input data-cname name="r-name" aria-label="Name der Regel" placeholder="Name" '
                                   'maxlength="80" value="">'
                                   '<select data-cmode name="r-mode" aria-label="Art der Regel"><option value="must_not" selected>keine Zeile enthält</option>'
                                   '<option value="must">eine Zeile enthält</option></select><input data-ctext name="r-text" aria-label="Text der Regel" '
                                   'placeholder="Text, z. B. vlan 666" maxlength="200" value=""><button class="btn small" type="button" data-cdel '
                                   'aria-label="Entfernen">Entfernen</button></div>']]
    assert focused == "#new-name"    # the new row takes the focus in its name field (browser check)
    # a row left empty is dropped, the others go trimmed, a new one without an id; saved, the card shows the server's answer
    custom = [{"id": "c1", "name": "Kein VLAN 666", "mode": "must_not", "text": 'vlan 666 "x"'},
              {"id": None, "name": "Banner", "mode": "must", "text": "banner motd"}]
    assert puts == [["PUT", "/api/compliance/rules", {"off": ["telnet"], "custom": custom}]]
    assert 'data-crow="c2"' in after and toasts == ["Gespeichert"]


# Beyond the brief: a custom rule with only a name or only a text is named before anything is sent (the server's 422 for an empty
# field would read in English); "Entfernen" takes its row away and leaves the focus on "Regel hinzufügen"
@pytest.mark.parametrize("name, text, said", [("Banner", "", "Eigene Regel ohne Text"), ("", "banner", "Eigene Regel ohne Namen")])
def test_a_half_custom_rule_is_named_and_a_row_can_go(name, text, said):
    row = '{dataset: {crow: ""}, querySelector: s => ({"[data-cname]": {value: %s}, "[data-cmode]": {value: "must"}, "[data-ctext]": {value: %s}})[s]}'
    then = (f'document.lists["#r-custom [data-crow]"] = [{row % (json.dumps(name), json.dumps(text))}]; ' + click("r-save")
            + 'let gone = false; const r = {remove: () => { gone = true; }}; '
            '$("#r-custom").handlers.click[0]({target: {closest: s => s === "[data-cdel]" ? {closest: x => (x === "[data-crow]" ? r : null)} : null}}); '
            'return [calls.filter(c => c[0] === "PUT").length, ' + TOASTS + ', gone, document.activeElement && document.activeElement.sel]; ')
    assert settings(then) == [0, [said], True, "#r-add"]


@pytest.mark.parametrize("role", ["lesen", "freigeben"])
def test_below_admin_the_rules_are_locked(role):
    view, handlers = settings('return [$("#view").innerHTML, Object.keys($("#r-save").handlers)]; ', role=role)
    card = view.split("<h2>Sicherheitsregeln</h2>")[1].split("<h2>Sitzungen</h2>")[0]
    assert '<p class="note gate">Regeln ändern braucht die Rolle „Admin“.</p>' in card and "r-add" not in card and "r-save" not in card
    boxes = re.findall(r"<(?:input|select)\b[^>]*>", card)
    assert len(boxes) == 5 and all(re.search(r"\sdisabled\b", b) for b in boxes) and "Entfernen" not in card and handlers == []


WATCH = [{"mac": "aa:bb:cc:00:00:01", "note": "Laptop <Büro>", "created_by": "anna", "created_at": "2026-11-07 10:00:00",
          "last": {"mac": "aa:bb:cc:00:00:01", "switch": "SW-HP", "port": "2", "vlan": "20", "last_seen": "2026-11-07 12:00:00"}},
         {"mac": "aa:bb:cc:00:00:05", "note": "", "created_by": "bob", "created_at": "2026-11-07 11:00:00", "last": None}]
# modal answers the question of confirmModal at once: its second button confirms, its first cancels
WATCH_VIEW = ('(async () => { %s const calls = []; let list = %s; '
              'modal = (t, x, buttons) => { calls.push(["confirm", t, x]); buttons[%s ? 1 : 0].onClick(); }; '
              'api = async (m, u, b) => { calls.push([m, u, b === undefined ? null : b]); return m === "POST" ? {mac: "aa:bb:cc:00:00:03", note: "Beamer", '
              'created_by: "Anna", created_at: "2026-11-08 09:00:00", last: null} : m === "DELETE" ? {ok: true} : list; }; '
              'const el = $("#w-card"); await renderWatchInto(el); %s })()')


def watch(then, role="aendern", answer=WATCH, confirmed="true"):
    return in_dom(WATCH_VIEW % (role_me(role), json.dumps(answer), confirmed, then))


def test_the_watch_list_adds_and_removes_with_aendern_only():
    then = ('const a = [$("#w-card").innerHTML, $("#w-rows").innerHTML]; $("#w-mac").value = " AA-BB-CC-00-00-03 "; $("#w-note").value = " Beamer "; '
            'await $("#w-form").handlers.submit[0]({preventDefault() {}, target: $("#w-form")}); a.push($("#w-rows").innerHTML, $("#w-mac").value); '
            'await $("#w-rows").handlers.click[0]({target: {closest: s => s === "[data-wdel]" ? {dataset: {wdel: "aa:bb:cc:00:00:01"}} : null}}); '
            'return [...a, $("#w-rows").innerHTML, calls, ' + TOASTS + ']; ')
    form, rows, added, field, removed, calls, toasts = watch(then)
    assert ('<input type="text" id="w-mac" placeholder="MAC-Adresse" aria-label="MAC-Adresse" maxlength="20" autocomplete="off">' in form
            and '<input type="text" id="w-note" placeholder="Notiz (optional)" aria-label="Notiz" maxlength="200" autocomplete="off">' in form
            and '<button class="btn small primary" type="submit" id="w-add">Beobachten</button>' in form)
    assert "<th>MAC</th><th>Notiz</th><th>Zuletzt gesehen</th><th>Angelegt von</th><th></th>" in rows and "Laptop &lt;Büro&gt;" in rows
    assert "SW-HP · Port 2<span class=\"cellnote\">" in rows and '<span class="muted">nicht gesehen</span>' in rows
    assert '<button class="btn small" type="button" data-wdel="aa:bb:cc:00:00:01" aria-label="Entfernen: aa:bb:cc:00:00:01">Entfernen</button>' in rows
    assert [c for c in calls if c[0] == "POST"] == [["POST", "/api/watch", {"mac": "AA-BB-CC-00-00-03", "note": "Beamer"}]] and field == ""
    # the answer takes its place in the list by MAC; "Entfernen" asks first, then deletes the encoded MAC and the row
    assert added.index("aa:bb:cc:00:00:01") < added.index("aa:bb:cc:00:00:03") < added.index("aa:bb:cc:00:00:05")
    assert ["confirm", "Nicht mehr beobachten", '<p style="margin:0"><b>aa:bb:cc:00:00:01</b> nicht mehr beobachten?</p>'] in calls
    assert ["DELETE", "/api/watch/aa%3Abb%3Acc%3A00%3A00%3A01", None] in calls and "aa:bb:cc:00:00:01" not in removed
    assert toasts == ["Wird beobachtet", "Nicht mehr beobachtet"]
    lesen = watch('return [$("#w-card").innerHTML, $("#w-rows").innerHTML]; ', role="lesen")
    assert '<p class="note gate" style="margin:12px 16px">Die Beobachtungsliste ändern braucht die Rolle „Ändern“.</p>' in lesen[0]
    assert "w-mac" not in lesen[0] and "Entfernen" not in lesen[1] and "<th></th>" not in lesen[1]


# Beyond the brief: "Entfernen" cancelled deletes nothing; an empty list says so, as does an answer that is no list (the stubs of the
# device tests answer every URL with the unknown devices or an object); a refused MAC is the server's text
@pytest.mark.parametrize("answer", [[], {"ok": True}], ids=["empty", "no-list"])
def test_an_empty_watch_list_says_so(answer):
    assert watch('return $("#w-rows").innerHTML; ', answer=answer) == '<div class="empty">Keine MAC-Adresse beobachtet.</div>'


def test_a_cancelled_or_refused_watch_changes_nothing():
    then = ('await $("#w-rows").handlers.click[0]({target: {closest: s => s === "[data-wdel]" ? {dataset: {wdel: "aa:bb:cc:00:00:01"}} : null}}); '
            'api = async () => { throw new Error("MAC-Adresse ungültig"); }; $("#w-mac").value = "x"; '
            'await $("#w-form").handlers.submit[0]({preventDefault() {}, target: $("#w-form")}); '
            'return [calls.filter(c => c[0] === "DELETE").length, $("#w-rows").innerHTML.includes("aa:bb:cc:00:00:01"), $("#w-mac").value, ' + TOASTS + ']; ')
    assert watch(then, confirmed="false") == [0, True, "x", ["MAC-Adresse ungültig"]]


def test_the_devices_view_appends_the_watch_list():
    js = ('(async () => { ' + role_me("lesen") + 'const calls = []; api = async (m, u) => { calls.push(u); return u === "/api/devices" ? [] '
          ': u === "/api/pf/roles" ? {configured: true, roles: []} : u === "/api/watch" ? %s : []; }; await renderDevices(); '
          'return [$("#view").innerHTML, $("#w-rows").innerHTML, calls]; })()') % json.dumps(WATCH)
    view, rows, calls = in_dom(js)
    assert ('<section class="card"><div class="card-h"><h2>Beobachtungsliste</h2><span class="sub">meldet, wenn eine dieser MAC-Adressen auftaucht, '
            'den Port wechselt oder wiederkommt</span></div><div id="w-card">') in view
    assert view.index("Unbekannte Geräte an Zugangsports") < view.index("Beobachtungsliste") and "/api/watch" in calls and "aa:bb:cc:00:00:05" in rows


NETMAP = {"switches": [{"id": 1, "k": "SW", "zone": "", "host": "10.0.0.1", "ok": True, "error": "", "ports": [], "caps": []}], "links": [], "vlans": {}}
OVERVIEW = ('(async () => { %s const calls = []; const gone = []; go = v => gone.push(v); '
            'api = async (m, u) => { calls.push(u); return u === "/api/netmap" ? %s '
            ': u === "/api/alerts/deliveries?status=failed&limit=20" ? %s : u.startsWith("/api/events?") ? {rows: [], next: null} : {}; }; '
            'await renderOverview(); const html = $("#view").innerHTML; '
            'const m = /data-iss="(\\d+):0"/.exec(html.split("Benachrichtigungen nicht zugestellt")[1] || ""); '
            'if (m) $("#view").onclick({target: {closest: s => s === "[data-iss]" ? {dataset: {iss: m[1] + ":0"}} : null}}); return [html, calls, gone]; })()')


def utc(hours_ago):
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")


def test_an_admin_sees_undelivered_alerts_in_the_overview():
    failed = {"rows": [{**DELIVERIES[3], "id": 9, "created_at": utc(1), "title": "SW antwortet <nicht>"},
                       {**DELIVERIES[3], "id": 8, "created_at": utc(30), "title": "Gestern"}], "next": None}
    html, calls, gone = in_dom(OVERVIEW % (role_me("admin"), json.dumps(NETMAP), json.dumps(failed)))
    assert ('<span class="pill crit">Fehler</span><span class="t">Benachrichtigungen nicht zugestellt</span><span class="cnt">1</span>' in html
            and '<span class="d">1 Meldung in den letzten 24 Stunden</span>' in html)
    assert '<div class="issue"><span class="t">SW antwortet &lt;nicht&gt;</span><span class="d">Webhook: HTTP 500 &lt;x&gt;</span>' in html
    assert "Gestern" not in html
    assert "/api/alerts/deliveries?status=failed&limit=20" in calls and gone == ["settings"]
    assert '<span class="k">Zu prüfen</span><span class="v">1</span>' in html


# Beyond the brief: below Admin the overview asks nothing of the deliveries (the route is Admin); an Admin with none of the last
# 24 hours, a failed request or an answer without rows gets no group; 20 of the last 24 hours with more behind say "mehr als 20"
@pytest.mark.parametrize("role, answer, group", [("freigeben", {"rows": [{**DELIVERIES[3], "created_at": utc(1)}], "next": None}, None),
                                                 ("admin", {"rows": [{**DELIVERIES[3], "created_at": utc(25)}], "next": None}, None),
                                                 ("admin", {}, None), ("admin", "Promise.reject(new Error(\"x\"))", None),
                                                 ("admin", {"rows": [{**DELIVERIES[3], "id": 50 - i, "created_at": utc(1)} for i in range(20)], "next": 31},
                                                  "mehr als 20 Meldungen in den letzten 24 Stunden")])
def test_undelivered_alerts_only_for_an_admin_and_only_of_a_day(role, answer, group):
    html, calls, _ = in_dom(OVERVIEW % (role_me(role), json.dumps(NETMAP), answer if isinstance(answer, str) else json.dumps(answer)))
    assert ("Benachrichtigungen nicht zugestellt" in html) == bool(group) and (group is None or f'<span class="d">{group}</span>' in html)
    assert ("/api/alerts/deliveries?status=failed&limit=20" in calls) == (role == "admin") and ("Nichts auffällig." in html) == (group is None)


def test_the_css_of_the_cards_takes_only_existing_tokens():
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    # Browser check: at 390 px a fieldset kept the width of the security choice's longest option and the page scrolled sideways; the
    # events' legend took the uppercase of the fieldsets' legends; a rule's hint stood 4 px left of its name
    assert "#alert-card .fs { min-width: 0; }" in css and "#alert-card select { min-width: 0; max-width: 100%; }" in css
    assert "text-transform: none; letter-spacing: 0; }" in css.split(".evs legend {")[1].split("\n")[0] and ".rule .hint { padding-left: 28px;" in css
    new = re.findall(r"^(?:\.toolrow input\[type=text\]|\.au-tools|\.card-h\.sub-h|\.card-h h3|\.evs|\.rules?\b|\.crule|#alert-card)[^{]*\{[^}]*\}", css, re.M)
    tokens = {t for rule in new for t in re.findall(r"var\((--[\w-]+)\)", rule)}
    assert len(new) >= 12 and tokens <= {"--surface", "--surface-2", "--border", "--border-strong", "--fg", "--fg-2", "--muted", "--accent", "--accent-bg",
                                         "--warn", "--warn-bg", "--crit", "--crit-bg", "--r"}
