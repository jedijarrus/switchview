"""Phase 4c, Task 11: the triage in the devices view - app/static/sv-triage.js and its hooks in sv-auth.js (renderParkedInto) and
sv-admin.js (renderDevices, editDevice, AUDIT_LABELS) - against the recording DOM stub of tests/test_frontend_dom.py: the server's
suggestion with its reasons in the lists "Ohne Zugriff" and "Ohne Anmeldung", "Freigeben" filling the form with it, several devices
released with one type and role after the server's check, the CSV import with its preview, and "Neu bewerten" for a released device
PacketFence parks anyway and in the dialog of a known device. The stub parses no HTML: a test sets the fields of a dialog itself
($("#tb-…").value, $("#imp-…").value) and reads what was preselected from the markup. Skipped without node."""
import json
import re
import shutil

import pytest
from test_frontend_dom import in_dom, role_me

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

PHONE, PC, PRINTER, KNOWN = "80:5e:c0:00:00:01", "aa:bb:cc:00:00:02", "00:80:77:00:00:04", "aa:bb:cc:00:00:03"
NO_IDEA = {"kind": None, "label": None, "role": None, "role_count": 0, "port_mode": None, "why": [], "hint": None}
UNKNOWN = [
    {"mac": PHONE, "vlan": "3999", "ip": "", "name": "", "vendor": "Yealink", "sw": "SW-A", "sid": 1, "port": "3", "st": "known", "flags": [],
     "lldp": "SIP-T10X <x>", "mc": 1, "first_seen": "2026-11-08 09:00:00", "new": True, "poe": {"on": True, "status": 3, "mw": 4200},
     "suggest": {"kind": "telefon", "label": "Telefon", "role": "voice", "role_count": 7, "port_mode": "known",
                 "why": ["Hersteller Yealink", "LLDP „SIP-T10X <x>“", "PoE: liefert Strom"], "hint": None}},
    {"mac": PC, "vlan": "20", "ip": "10.0.0.9", "name": "pc-17.example.local", "vendor": "", "sw": "SW-A", "sid": 1, "port": "4", "st": "protected",
     "flags": [], "lldp": "", "mc": 1, "first_seen": None, "new": False, "poe": None, "suggest": NO_IDEA},
    {"mac": PRINTER, "vlan": "20", "ip": "", "name": "", "vendor": "Brother", "sw": "SW-A", "sid": 1, "port": "5", "st": "protected", "flags": [],
     "lldp": "", "mc": 1, "first_seen": "2026-11-08 09:30:00", "new": True, "poe": None,
     "suggest": {"kind": "drucker", "label": "Drucker", "role": "printer", "role_count": 1, "port_mode": "known", "why": ["Hersteller Brother"],
                 "hint": "Port steht auf „Protected“: eine Freigabe wirkt erst an einem Port „Bekannte Geräte“ oder „RADIUS“"}}]
PARKED = {"how": "mac", "park": True, "user": "", "role": "vlan_3999", "vlan": "3999", "switch_id": 1, "switch_name": "SW-A"}
SESSIONS = {"configured": True, "ok": True, "sessions": [
    {**PARKED, "mac": PHONE, "since": "2026-11-08 09:00:05", "port": "3", "device": ""},              # parked and unknown: parked[0]
    {**PARKED, "mac": KNOWN, "since": "2026-11-08 08:00:00", "port": "7", "device": "Drucker EK"}]}   # released, parked anyway: parked[1]
DEVICES = [{"mac": KNOWN, "name": "Drucker EK", "kind": "drucker", "role": "printer", "allowed": 1, "pf_state": "ok", "pf_error": ""}]
IMPORTED = {"rows": [{"line": 1, "mac": PRINTER, "name": "Brother 00:00:04", "role": "vlan_140", "kind": "sonstiges", "status": "ok", "reason": ""},
                     {"line": 2, "mac": "zz", "name": "", "role": "", "kind": "", "status": "error", "reason": "MAC-Adresse ungültig"}],
            "ok": 1, "exists": 0, "errors": 1, "roles_checked": True, "note": None}
# a check without a faulty row: both can be taken over
GOOD = {**IMPORTED, "rows": [IMPORTED["rows"][0], {**IMPORTED["rows"][0], "line": 2, "mac": PC, "name": "pc-17"}], "ok": 2, "errors": 0}
# the entries as a server from before Task 10 answers them
OLD = [{k: v for k, v in d.items() if k not in ("suggest", "first_seen", "new")} for d in UNKNOWN]
ROLES = {"configured": True, "roles": [{"name": "vlan_140"}, {"name": "voice"}, {"name": "printer"}]}
CSV = "MAC;Rolle;Name;Typ\n00:80:77:00:00:04;;;\nzz"

TICK = "await new Promise(r => setTimeout(r, 5)); "
TOASTS = '$("#toasts").children.map(t => t.textContent)'
# the newest footer button of that label (the stub's innerHTML = "" keeps the buttons of the dialogs before)
CLICK = 'await $("#m-foot").children.slice().reverse().find(b => b.textContent === "%s").handlers.click[0](); '
# what a test records instead of the form and of the questions to PacketFence after a change
OPENED = 'editDevice = (d, isNew, release) => { opened.push([d, isNew, release]); }; '
AFTER = 'authAfterChange = mac => { after.push(mac === undefined ? null : mac); return Promise.resolve(false); }; '
PARK = '$("#park-card").onclick({target: {closest: s => s === "[data-park]" ? {dataset: {park: "%s"}} : null}}); '
RE = '$("#park-card").onclick({target: {closest: s => s === "[data-re]" ? {dataset: {re: "%s"}} : null}}); '
PICK = '$("#%s").onchange({target: {closest: () => ({dataset: {pickMac: "%s"}, checked: %s})}}); '
BATCH_FIELDS = '$("#tb-kind").value = "sonstiges"; $("#tb-role").value = "vlan_140"; '
IMPORT_FIELDS = '$("#imp-kind").value = "sonstiges"; $("#imp-role").value = "vlan_140"; '
OPEN_CSV = 'await renderDevices(); await $("#d-csv").handlers.click[0](); ' + IMPORT_FIELDS
POSTS = 'calls.filter(c => c[0] === "POST")'


def triage(then, role="aendern", unknown=UNKNOWN, sessions=SESSIONS, devices=DEVICES, imported=IMPORTED, refused=None, roles=ROLES):
    """The statements then (their return is the test's value) in the devices view, against an api stub that records every call as
    [method, url, body] and answers GET /api/devices with devices, /api/pf/roles with roles, /api/pf/sessions with sessions,
    /api/devices/unknown with unknown, POST /api/devices/import with imported (with dry_run false: without errors and with created
    2), POST …/reevaluate with {ok: true}, anything else []; refused: the error every POST throws instead. shown is the dialog
    opened last (title, body, the labels of its buttons); opened and after record with OPENED and AFTER."""
    js = ('(async () => { ' + role_me(role) + 'current = "devices"; const calls = [], opened = [], after = []; let shown = null; '
          'const realModal = modal; '
          'modal = (t, b, btns = []) => { shown = {title: t, body: b, labels: btns.map(x => x.label)}; return realModal(t, b, btns); }; '
          'const imported = ' + json.dumps(imported) + ', refused = ' + json.dumps(refused) + '; '
          'api = async (m, u, b) => { calls.push([m, u, b === undefined ? null : b]); '
          'if (m === "POST" && refused) throw new Error(refused); '
          'if (u === "/api/devices") return ' + json.dumps(devices) + '; if (u === "/api/pf/roles") return ' + json.dumps(roles) + '; '
          'if (u.startsWith("/api/pf/sessions")) return ' + json.dumps(sessions) + '; if (u === "/api/devices/unknown") return ' + json.dumps(unknown) + '; '
          'if (u === "/api/devices/import") return b.dry_run ? imported : {...imported, errors: 0, created: 2}; '
          'if (u.endsWith("/reevaluate")) return {ok: true}; return []; }; ' + then + ' })()')
    return in_dom(js, tz="UTC")


def row_of(html, text):
    """The table row of html that names text."""
    return next(r for r in re.findall(r"<tr>.*?</tr>", html, re.S) if text in r)


LISTS = 'await renderDevices(); return [$("#park-card").innerHTML, $("#ulist").innerHTML, $("#view").innerHTML]; '


def test_the_parked_card_shows_the_suggestion_and_its_reasons_escaped():
    card, n, off = triage('await renderDevices(); return [$("#park-card").innerHTML, $("#tr-n-park").textContent, $("#tr-batch-park").disabled]; ')
    assert "<th></th><th>Gerät</th><th>MAC</th><th>Switch · Port</th><th>Seit</th><th>Vorschlag</th><th></th>" in card
    phone = row_of(card, PHONE)
    assert ('<td><b>Telefon</b> · Rolle voice · <span class="muted">so bei 7 bekannten Geräten dieses Typs</span> · Port-Modus „Bekannte Geräte“'
            '<ul class="blist"><li>Hersteller Yealink</li><li>LLDP „SIP-T10X &lt;x&gt;“</li><li>PoE: liefert Strom</li></ul></td>') in phone
    assert phone.startswith(f'<tr><td><input type="checkbox" data-pick-mac="{PHONE}" aria-label="{PHONE} auswählen"></td><td>Yealink')
    assert "<x>" not in card and card.count("data-pick-mac") == 1
    # a known device has an empty cell where the choice and the suggestion stand
    assert ('<tr><td></td><td>Drucker EK<span class="cellnote">freigegeben, PacketFence parkt es trotzdem</span></td>'
            f'<td class="mono">{KNOWN}</td><td>SW-A · 7</td><td class="num">2026-11-08 08:00:00</td><td></td><td>') in card
    # the bar between head and table
    assert ('</div><div class="toolrow tr-bar"><span id="tr-n-park"></span><button class="btn small primary" type="button" id="tr-batch-park" disabled>'
            'Ausgewählte freigeben</button></div><div class="tbl-wrap">') in card
    assert (n, off) == ("0 Geräte ausgewählt", True)


def test_the_list_without_login_shows_suggestion_new_and_first_seen():
    _, ulist, _ = triage(LISTS)
    assert PHONE not in ulist                                                          # it has a session: it stands under "Ohne Zugriff"
    assert "<th></th><th>Gerät</th><th>MAC</th><th>Ort</th><th>Port-Zustand</th><th>Vorschlag</th><th></th>" in ulist
    printer, pc = row_of(ulist, PRINTER), row_of(ulist, PC)
    assert ('<td><b>Drucker</b> · Rolle printer · <span class="muted">so bei 1 bekanntem Gerät dieses Typs</span> · Port-Modus „Bekannte Geräte“'
            '<ul class="blist"><li>Hersteller Brother</li></ul><span class="cellnote">Port steht auf „Protected“: eine Freigabe wirkt erst an einem Port '
            '„Bekannte Geräte“ oder „RADIUS“</span></td>') in printer
    assert '<td>Brother <span class="pill warn">neu</span><span class="cellnote">zuerst gesehen 08.11.26, 09:30</span></td>' in printer
    assert '<td><span class="muted">kein Vorschlag</span></td>' in pc and ">neu</span>" not in pc and "zuerst gesehen" not in pc
    assert f'<td><input type="checkbox" data-pick-mac="{PC}" aria-label="{PC} auswählen"></td>' in pc and ulist.count("data-pick-mac") == 2
    assert ulist.startswith('<div class="toolrow tr-bar"><span id="tr-n-net"></span><button class="btn small primary" type="button" id="tr-batch-net" '
                            'disabled>Ausgewählte freigeben</button></div><div class="tbl-wrap">')


def test_release_fills_the_form_with_the_suggestion():
    opened = triage(OPENED + 'await renderDevices(); ' + PARK % "0" + '$("#ulist").onclick({target: {closest: () => ({dataset: {u: "0"}})}}); return opened; ')
    assert opened == [[{"mac": PHONE, "name": "", "kind": "telefon", "role": "voice", "location": "SW-A Port 3"}, True, True],
                      [{"mac": PC, "name": "pc-17", "kind": "sonstiges", "location": "SW-A Port 4"}, True, True]]
    assert "role" not in opened[1][0]


def test_an_answer_without_suggestions_draws_the_lists_as_before():                    # pin: a server from before Task 10
    card, ulist, opened = triage(OPENED + 'await renderDevices(); ' + PARK % "0" + 'return [$("#park-card").innerHTML, $("#ulist").innerHTML, opened]; ',
                                 unknown=OLD)
    for html in (card, ulist):
        assert "Vorschlag" not in html and "data-pick-mac" not in html and "tr-batch-" not in html and "zuerst gesehen" not in html
    assert "<thead><tr><th>Gerät</th><th>MAC</th><th>Switch · Port</th><th>Seit</th><th></th></tr></thead>" in card
    assert ('<tr><td>Yealink<span class="cellnote">unbekannt</span></td><td class="mono">80:5e:c0:00:00:01</td><td>SW-A · 3</td>'
            '<td class="num">2026-11-08 09:00:05</td><td><button class="btn small primary" type="button" data-park="0">Freigeben</button></td></tr>') in card
    assert ulist.startswith('<div class="tbl-wrap"><table><thead><tr><th>Gerät</th><th>MAC</th><th>Ort</th><th>Port-Zustand</th><th></th></tr></thead>')
    assert opened == [[{"mac": PHONE, "name": "", "kind": "sonstiges", "location": "SW-A Port 3"}, True, True]]


def test_a_parked_device_the_switches_have_not_learned_has_no_suggestion():            # beyond the brief
    """Parked without an entry of the unknown list (seen null): its cell is empty, it can still be picked and released as today."""
    card, opened = triage(OPENED + 'await renderDevices(); ' + PARK % "0" + 'return [$("#park-card").innerHTML, opened]; ',
                          sessions={**SESSIONS, "sessions": [{**SESSIONS["sessions"][0], "mac": "02:00:00:00:00:09"}, SESSIONS["sessions"][0]]})
    fresh = row_of(card, "02:00:00:00:00:09")
    assert "<th>Vorschlag</th>" in card and 'data-pick-mac="02:00:00:00:00:09"' in fresh
    assert '<td class="num">2026-11-08 09:00:05</td><td></td><td><button class="btn small primary" type="button" data-park="0">' in fresh
    assert opened == [[{"mac": "02:00:00:00:00:09", "name": "", "kind": "sonstiges", "location": "SW-A Port 3"}, True, True]]


PICK_TWO = 'await renderDevices(); ' + PICK % ("ulist", PC, "true") + PICK % ("ulist", PRINTER, "true")
ROWS_BODY = {"rows": [{"mac": PC}, {"mac": PRINTER}], "kind": "sonstiges", "role": "vlan_140", "valid_until": None}


def test_several_devices_are_released_with_one_role():
    n, off, form, preview, posts = triage(
        PICK_TWO + 'const bar = [$("#tr-n-net").textContent, $("#tr-batch-net").disabled]; await $("#tr-batch-net").onclick(); const form = shown; '
        + BATCH_FIELDS + CLICK % "Prüfen" + 'return [...bar, form, shown, ' + POSTS + ']; ')
    assert (n, off) == ("2 Geräte ausgewählt", False)
    assert form["title"] == "2 Geräte freigeben" and form["labels"] == ["Abbrechen", "Prüfen"]
    # no suggestion in common: the type "Sonstiges" and the role of a new device
    assert '<option value="sonstiges" selected>Sonstiges</option>' in form["body"] and '<option value="vlan_140" selected>vlan_140</option>' in form["body"]
    assert form["body"].count(" selected>") == 2
    assert f'<ul class="blist"><li>pc-17 <span class="mono">{PC}</span></li><li><span class="mono">{PRINTER}</span></li></ul>' in form["body"]
    assert posts == [["POST", "/api/devices/import", {**ROWS_BODY, "dry_run": True}]]
    # the preview: both rows with the server's reason; with a faulty row there is no button to release
    assert preview["title"] == "2 Geräte freigeben" and preview["labels"] == ["Zurück", "Abbrechen"]
    assert '<p class="note warn" style="margin:0 0 8px">Erst die fehlerhaften Zeilen beheben.</p>' in preview["body"]
    assert "<b>1 übernehmen, 0 schon bekannt, 1 fehlerhaft</b>" in preview["body"]
    assert (f'<tr><td class="num">1</td><td class="mono">{PRINTER}</td><td>Brother 00:00:04</td><td>vlan_140</td><td>Sonstiges</td>'
            '<td><span class="pill ok">wird freigegeben</span></td></tr>') in preview["body"]
    assert ('<tr><td class="num">2</td><td class="mono">zz</td><td></td><td>default</td><td></td>'
            '<td><span class="pill crit">Fehler</span><span class="cellnote">MAC-Adresse ungültig</span></td></tr>') in preview["body"]


def test_a_checked_selection_is_released_and_the_view_drawn_anew():
    labels, posts, toasts, after, picked, reads, hidden = triage(
        AFTER + PICK_TWO + 'await $("#tr-batch-net").onclick(); ' + BATCH_FIELDS + CLICK % "Prüfen" + 'const labels = shown.labels; ' + CLICK % "Freigeben"
        + TICK + 'return [labels, ' + POSTS + ', ' + TOASTS + ', after, [...triagePicked], calls.filter(c => c[1] === "/api/devices").length, '
        '$("#modal").hidden]; ', imported=GOOD)
    assert labels == ["Zurück", "Abbrechen", "Freigeben"]
    assert posts == [["POST", "/api/devices/import", {**ROWS_BODY, "dry_run": True}], ["POST", "/api/devices/import", {**ROWS_BODY, "dry_run": False}]]
    assert toasts == ["2 Geräte freigegeben – PacketFence wird abgeglichen"]
    # the kept sessions dropped once, not asked per device; nothing stays picked, the dialog is closed and the view read again
    assert (after, picked, reads, hidden) == ([None], [], 2, True)


def test_a_suggestion_every_picked_device_shares_is_preselected():
    form = triage('await renderDevices(); ' + PICK % ("ulist", PRINTER, "true") + 'await $("#tr-batch-net").onclick(); return shown; ')
    assert form["title"] == "1 Gerät freigeben"
    assert '<option value="drucker" selected>Drucker</option>' in form["body"] and '<option value="printer" selected>printer</option>' in form["body"]
    assert form["body"].count(" selected>") == 2


def test_a_pick_can_be_taken_back_and_survives_a_redraw():                               # beyond the brief
    n, off, again, n2 = triage(PICK_TWO + PICK % ("ulist", PC, "false") + 'const bar = [$("#tr-n-net").textContent, $("#tr-batch-net").disabled]; '
                               'await renderDevices(); return [...bar, $("#ulist").innerHTML, $("#tr-n-net").textContent]; ')
    assert (n, off, n2) == ("1 Gerät ausgewählt", False, "1 Gerät ausgewählt")
    assert f'data-pick-mac="{PRINTER}" aria-label="{PRINTER} auswählen" checked>' in again and f'data-pick-mac="{PC}" aria-label="{PC} auswählen">' in again


def test_a_picked_device_that_is_not_shown_is_not_released():                            # beyond the brief
    """"auch hinter anderen Geräten" off hides the PC (a port with many devices): picked before, it neither counts nor goes out."""
    unknown = [UNKNOWN[0], {**UNKNOWN[1], "flags": ["many"], "mc": 9}, UNKNOWN[2]]
    n, posts = triage('devBehind = true; ' + PICK_TWO + 'devBehind = false; await renderDevices(); const n = $("#tr-n-net").textContent; '
                      'await $("#tr-batch-net").onclick(); ' + BATCH_FIELDS + CLICK % "Prüfen" + 'return [n, ' + POSTS + ']; ', unknown=unknown)
    assert n == "1 Gerät ausgewählt" and posts[0][2]["rows"] == [{"mac": PRINTER}]


def test_the_selection_counts_per_list():                                                # beyond the brief
    """One set of picks, two bars: the parked phone counts under "Ohne Zugriff" only, and its bar releases only it."""
    park, net, form = triage(PICK_TWO + PICK % ("park-card", PHONE, "true") + 'const n = [$("#tr-n-park").textContent, $("#tr-n-net").textContent]; '
                             'await $("#tr-batch-park").onclick(); return [...n, shown]; ')
    assert (park, net) == ("1 Gerät ausgewählt", "2 Geräte ausgewählt")
    assert form["title"] == "1 Gerät freigeben" and f'<li><span class="mono">{PHONE}</span></li>' in form["body"]
    assert '<option value="telefon" selected>Telefon</option>' in form["body"] and '<option value="voice" selected>voice</option>' in form["body"]


def test_back_keeps_the_values_and_a_refusal_stands_in_the_dialog():                     # beyond the brief
    back, toasts = triage(
        PICK_TWO + 'await $("#tr-batch-net").onclick(); $("#tb-kind").value = "drucker"; $("#tb-role").value = "printer"; $("#tb-until").value = "2027-01-31"; '
        + CLICK % "Prüfen" + CLICK % "Zurück" + 'return [shown, ' + TOASTS + ']; ')
    assert back["labels"] == ["Abbrechen", "Prüfen"] and '<option value="drucker" selected>' in back["body"]
    assert '<option value="printer" selected>' in back["body"] and 'id="tb-until" type="date" value="2027-01-31"' in back["body"] and toasts == []
    failed = triage(PICK_TWO + 'await $("#tr-batch-net").onclick(); ' + BATCH_FIELDS + CLICK % "Prüfen" + 'return shown; ', refused="PacketFence <weg>")
    assert failed["labels"] == ["Abbrechen", "Prüfen"] and failed["body"].startswith('<div class="error">PacketFence &lt;weg&gt;</div>')


def test_a_dialog_closed_while_the_server_checks_stays_closed():                        # beyond the brief
    labels, hidden = triage(PICK_TWO + 'await $("#tr-batch-net").onclick(); ' + BATCH_FIELDS + 'let answer; const slow = api; '
                           'api = (m, u, b) => m === "POST" ? new Promise(r => { answer = () => r(imported); }) : slow(m, u, b); '
                           'const click = $("#m-foot").children.slice().reverse().find(b => b.textContent === "Prüfen").handlers.click[0](); '
                           + TICK + 'closeModal(); answer(); await click; return [shown.labels, $("#modal").hidden]; ')
    assert labels == ["Abbrechen", "Prüfen"] and hidden is True


def test_the_csv_import_previews_and_blocks_on_errors():
    view, form, preview, posts = triage(
        'await renderDevices(); const view = $("#view").innerHTML; await $("#d-csv").handlers.click[0](); const form = shown; ' + IMPORT_FIELDS
        + '$("#imp-text").value = ' + json.dumps(CSV) + '; ' + CLICK % "Prüfen" + 'return [view, form, shown, ' + POSTS + ']; ')
    assert ('<button class="btn small" type="button" id="d-sync">Mit PacketFence abgleichen</button><button class="btn small" type="button" id="d-csv">'
            'CSV importieren</button><button class="btn small primary" type="button" id="d-add">Gerät freigeben</button>') in view
    assert form["title"] == "CSV importieren" and form["labels"] == ["Abbrechen", "Prüfen"]
    assert ('Eine Zeile je Gerät: MAC;Rolle;Name;Typ – Rolle, Name und Typ sind optional, „;“ oder „,“ trennen, eine Kopfzeile ist erlaubt. '
            'Höchstens 200 Zeilen.') in form["body"]
    assert '<input type="file" id="imp-file" accept=".csv,text/csv,text/plain">' in form["body"] and 'id="imp-text"' in form["body"]
    assert '<option value="sonstiges" selected>Sonstiges</option>' in form["body"] and '<option value="vlan_140" selected>vlan_140</option>' in form["body"]
    assert posts == [["POST", "/api/devices/import", {"csv": CSV, "kind": "sonstiges", "role": "vlan_140", "valid_until": None, "dry_run": True}]]
    assert "<b>1 übernehmen, 0 schon bekannt, 1 fehlerhaft</b>" in preview["body"] and '<span class="cellnote">MAC-Adresse ungültig</span>' in preview["body"]
    assert preview["labels"] == ["Zurück", "Abbrechen"] and "Erst die fehlerhaften Zeilen beheben." in preview["body"]


def test_a_csv_file_is_read_in_the_browser_and_taken_over_without_errors():
    posts, labels, toasts, after, back = triage(
        AFTER + OPEN_CSV + '$("#imp-text").value = "ignored"; $("#imp-file").files = [{text: async () => ' + json.dumps(CSV) + '}]; ' + CLICK % "Prüfen"
        + 'const labels = shown.labels; ' + CLICK % "Zurück" + 'const back = shown.body; $("#imp-file").files = []; $("#imp-text").value = ' + json.dumps(CSV)
        + '; ' + CLICK % "Prüfen" + CLICK % "Übernehmen" + TICK + 'return [' + POSTS + ', labels, ' + TOASTS + ', after, back]; ', imported=GOOD)
    body = {"csv": CSV, "kind": "sonstiges", "role": "vlan_140", "valid_until": None}
    assert [p[2] for p in posts] == [{**body, "dry_run": True}, {**body, "dry_run": True}, {**body, "dry_run": False}]
    assert labels == ["Zurück", "Abbrechen", "Übernehmen"]
    assert toasts == ["2 Geräte übernommen – PacketFence wird abgeglichen"] and after == [None]
    # "Zurück" puts the file's text into the text field: a faulty row is corrected there
    assert '<textarea id="imp-text" rows="6" spellcheck="false">MAC;Rolle;Name;Typ\n00:80:77:00:00:04;;;\nzz</textarea>' in back


@pytest.mark.parametrize("text, said", [("  \n", "Bitte eine Datei wählen oder Text einfügen"),
                                        ("a" * 50001, "Die Liste ist zu lang (höchstens 50.000 Zeichen)")], ids=["empty", "too-long"])
def test_an_empty_or_too_long_list_is_not_sent(text, said):                             # beyond the brief
    posts, toasts = triage(OPEN_CSV + '$("#imp-text").value = ' + json.dumps(text) + '; ' + CLICK % "Prüfen" + 'return [' + POSTS + ', ' + TOASTS + ']; ')
    assert posts == [] and toasts == [said]


def test_a_check_with_nothing_new_offers_no_take_over():                                 # beyond the brief
    known = {**IMPORTED, "rows": [{**IMPORTED["rows"][0], "status": "exists", "reason": "schon in der Datenbank – bleibt, wie es ist"}], "ok": 0,
             "exists": 1, "errors": 0, "note": "Rollen nicht geprüft: <aus>"}
    preview = triage(OPEN_CSV + '$("#imp-text").value = "x"; ' + CLICK % "Prüfen" + 'return shown; ', imported=known)
    assert preview["labels"] == ["Zurück", "Abbrechen"] and '<p class="note warn" style="margin:0 0 8px">Kein Gerät zu übernehmen.</p>' in preview["body"]
    assert '<span class="pill neutral">bleibt</span><span class="cellnote">schon in der Datenbank – bleibt, wie es ist</span></td>' in preview["body"]
    assert '<p class="note" style="margin:0 0 8px">Rollen nicht geprüft: &lt;aus&gt;</p>' in preview["body"]


def test_the_rows_of_a_check_are_escaped():                                              # beyond the brief
    html = in_dom('importRowsHtml({rows: [{line: 3, mac: "<m>", name: "<n>", role: "<r>", kind: "<k>", status: "error", reason: "Typ „<k>“ unbekannt"}], '
                  'ok: 0, exists: 0, errors: 1, note: null})')
    assert ('<td class="num">3</td><td class="mono">&lt;m&gt;</td><td>&lt;n&gt;</td><td>&lt;r&gt;</td><td>&lt;k&gt;</td>'
            '<td><span class="pill crit">Fehler</span><span class="cellnote">Typ „&lt;k&gt;“ unbekannt</span></td>') in html
    assert "<th>Zeile</th><th>MAC</th><th>Name</th><th>Rolle</th><th>Typ</th><th>Ergebnis</th></tr>" in html


ASK = 'await renderDevices(); ' + RE % "1" + 'const asked = shown; '
RE_URL = "/api/devices/aa%3Abb%3Acc%3A00%3A00%3A03/reevaluate"


def test_reevaluate_is_offered_for_a_released_device_that_is_parked():
    card, asked, posts, toasts, after = triage(AFTER + 'await renderDevices(); const card = $("#park-card").innerHTML; ' + RE % "1" + 'const asked = shown; '
                                               + CLICK % "Neu bewerten" + TICK + 'return [card, asked, ' + POSTS + ', ' + TOASTS + ', after]; ')
    assert re.findall(r'data-re="(\d+)"', card) == ["1"] and "data-re" not in row_of(card, PHONE)
    assert ('<td><div class="actions"><button class="btn small primary" type="button" data-park="1">Freigeben</button>'
            '<button class="btn small" type="button" data-re="1">Neu bewerten</button></div></td></tr>') in row_of(card, KNOWN)
    assert asked == {"title": "Neu bewerten", "labels": ["Abbrechen", "Neu bewerten"],
                     "body": f'<p style="margin:0"><span class="mono">{KNOWN}</span>: PacketFence bewertet die Anmeldung neu (CoA). Das Gerät meldet sich am '
                             'Port neu an.</p>'}
    assert posts == [["POST", RE_URL, None]] and toasts == ["Neu bewertet · der Port schaltet gleich um"] and after == [KNOWN]


def test_a_refused_or_cancelled_reevaluation_asks_packetfence_no_further():
    posts, toasts, after = triage(AFTER + ASK + CLICK % "Neu bewerten" + TICK + 'return [' + POSTS + ', ' + TOASTS + ', after]; ',
                                  refused="Neubewertung (CoA) fehlgeschlagen: HTTP 500")
    assert posts == [["POST", RE_URL, None]] and toasts == ["Neubewertung (CoA) fehlgeschlagen: HTTP 500"] and after == []
    assert triage(AFTER + ASK + CLICK % "Abbrechen" + TICK + 'return [' + POSTS + ', ' + TOASTS + ', after]; ') == [[], [], []]


def test_a_locked_device_that_is_parked_has_no_reevaluate():
    card = triage('await renderDevices(); return $("#park-card").innerHTML; ', devices=[{**DEVICES[0], "allowed": 0}])
    assert "data-re" not in card and "in den MAC-Freigaben gesperrt" in card
    assert '<td><button class="btn small primary" type="button" data-park="1">Entsperren</button></td></tr>' in card


@pytest.mark.parametrize("call, role, want", [
    ('editDevice({mac: "%s", name: "Drucker EK", allowed: 1}, false)' % KNOWN, "aendern", ["Löschen", "Neu bewerten", "Abbrechen", "Speichern"]),
    ('editDevice({mac: "%s", name: "Drucker EK", allowed: 1}, false, true)' % KNOWN, "aendern", ["Löschen", "Abbrechen", "Freigeben"]),
    ('editDevice({mac: "", name: "", kind: "drucker"}, true)', "aendern", ["Abbrechen", "Freigeben"])], ids=["known", "release", "new"])
def test_the_device_dialog_offers_reevaluate_for_a_known_device(call, role, want):
    assert triage('ROLES = ' + json.dumps(ROLES) + '; await ' + call + '; return shown.labels; ', role=role) == want


def test_reevaluate_from_the_dialog_closes_it_and_asks():                                # beyond the brief
    asked, posts = triage(AFTER + 'ROLES = ' + json.dumps(ROLES) + '; await editDevice({mac: "%s", name: "Drucker EK", allowed: 1}, false); ' % KNOWN
                          + CLICK % "Neu bewerten" + 'const asked = shown.title; ' + CLICK % "Neu bewerten" + TICK + 'return [asked, ' + POSTS + ']; ')
    assert asked == "Neu bewerten" and posts == [["POST", RE_URL, None]]


def test_below_aendern_the_triage_only_reads():
    card, ulist, view = triage(LISTS, role="lesen")
    assert "<th>Seit</th><th>Vorschlag</th></tr>" in card and "<th>Port-Zustand</th><th>Vorschlag</th></tr>" in ulist
    assert "<b>Telefon</b> · Rolle voice" in card and "<b>Drucker</b> · Rolle printer" in ulist
    for html in (card, ulist, view):
        assert "data-pick-mac" not in html and "tr-batch-" not in html and "data-re" not in html and 'id="d-csv"' not in html


def test_the_audit_names_reevaluate():
    assert in_dom("AUDIT_LABELS.device_reevaluate") == "Gerät neu bewertet"


def test_the_helpers_draw_nothing_without_their_data():                                  # beyond the brief
    assert in_dom('[suggestHtml(null), suggestHtml(undefined), firstSeenHtml({}), firstSeenHtml({new: false, first_seen: null}), pickCell("m", false), '
                  'triageOn([]), triageOn([null, {mac: "m"}]), triageOn([null, {suggest: null}])]') == ["", "", "", "", "<td></td>", False, False, True]
    # without a type the hint still stands (a port that delivers power); a type without a role names no count
    assert in_dom('[suggestHtml({kind: null, why: [], hint: "Gerät mit PoE – <x>"}), '
                  'suggestHtml({kind: "kamera", label: "Kamera", role: null, role_count: 0, port_mode: null, why: [], hint: null})]') == [
        '<span class="muted">kein Vorschlag</span><span class="cellnote">Gerät mit PoE – &lt;x&gt;</span>', "<b>Kamera</b>"]
