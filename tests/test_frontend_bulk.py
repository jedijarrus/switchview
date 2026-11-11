"""Phase 4c, Task 9: the bulk change in the UI - app/static/sv-bulk.js and its hooks in sv-switch.js, sv-main.js and sv-admin.js -
against the recording DOM stub of tests/test_frontend_dom.py: the view #bulk with the switches the user may change, ports per switch
or every access port untagged in a VLAN and the change; the preview per switch with the skipped ones and their reasons, run or
requested for approval, optionally with confirmation; the run in a dialog asked every 2 s while it is open and live, with "Abbrechen"
and "Alle bestätigen"; the last bulk changes; the entry in the switch view, the bulk change of a change in the change list and the
audit's labels. The stub parses no HTML: a test names the form's fields itself (document.lists for the boxes and the port fields,
$("#b-…").value for the rest). Bulk requests under "Freigaben" are tested in tests/test_frontend_approvals.py. Skipped without node."""
import json
import re
import shutil

import pytest
from test_frontend_dom import DETAIL, LIST, MAP_SW, NO_VIEWS, ROWS, in_dom, role_me

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

A, B, C = 1, 2, 3
# SW-A and SW-C write over SSH, SW-B has no write way; SW-A and SW-B stand in zone EK, SW-C in VK
MAP = {"switches": [{"id": A, "k": "SW-A", "zone": "EK", "model": "2530 <48G>", "ssh": True, "snmp_write": False, "caps": ["cli"], "ports": []},
                    {"id": B, "k": "SW-B", "zone": "EK", "model": "", "ssh": False, "snmp_write": False, "caps": ["cli"], "ports": []},
                    {"id": C, "k": "SW-C", "zone": "VK", "model": "", "ssh": True, "snmp_write": False, "caps": ["cli"], "ports": []}],
       "links": [], "vlans": {"20": "Büro", "30": "Telefon"}}
POSSIBLE = {"possible": True, "why": None, "default_minutes": 5, "max_minutes": 30}
PLAN_A = {"kind": "ports", "summary": "Port 1, 2: VLAN 30", "mechanism": "ssh", "commands": ["vlan 30 untagged 1,2"], "warnings": [], "blocked": [],
          "before": {}, "desired": {}, "token": "t-a", "autosave": False, "insecure_write": None, "approval": False, "confirm": POSSIBLE}
REASON = "Port 24: Uplink/Trunk: nur im Expertenmodus"
SEC_A = {"switch_id": A, "switch": "SW-A", "zone": "EK", "ports": ["1", "2"], "selection": "", "status": "ready", "reason": "", "preview": PLAN_A}
SEC_C = {"switch_id": C, "switch": "SW-C", "zone": "VK", "ports": ["24"], "selection": "", "status": "blocked", "reason": REASON,
         "preview": {**PLAN_A, "summary": "Port 24: VLAN 30", "commands": [], "blocked": [{"port": "24", "reason": "Uplink/Trunk: nur im Expertenmodus"}],
                     "token": "t-c"}}
PREVIEW = {"sections": [SEC_A, SEC_C], "summary": "VLAN 30 · 2 Ports an 1 Switch", "token": "T", "approval": False, "ready": 1, "skipped": 1,
           "ports": 2, "confirm": POSSIBLE}
CHANGE = {"untagged": "30"}
ITEM = {"pos": 0, "switch_id": A, "switch": "SW-A", "zone": "EK", "ports": ["1", "2"], "status": "done", "detail": "",
        "change": {"id": 41, "status": "pending", "error": None, "saved": 0, "confirm_until": "2026-11-10 09:10:00", "confirmed_by": None,
                   "reverted_by": None}}
RUN = {"id": 5, "created_at": "2026-11-10 09:00:00", "username": "Anna", "role": "aendern", "approved_by": None,
       "summary": "VLAN 30 · 4 Ports an 3 Switches", "change": CHANGE, "expert": False, "on_error": "stop", "confirm_minutes": 5, "status": "running",
       "cancel_requested": False, "finished_at": None,
       "items": [ITEM,
                 {**ITEM, "pos": 1, "switch_id": B, "switch": "SW-<B>", "ports": ["7"], "status": "running",
                  "change": {**ITEM["change"], "id": 42, "status": "running", "confirm_until": None}},
                 {**ITEM, "pos": 2, "switch_id": C, "switch": "SW-C", "zone": "VK", "ports": ["5"], "status": "waiting", "change": None}],
       "counts": {"done": 1, "failed": 0, "skipped": 0, "not_started": 0, "waiting": 1, "running": 1, "pending": 1}}
ROW = {"id": 5, "created_at": "2026-11-10 09:00:00", "username": "a<nna", "summary": "VLAN 30 · 4 Ports <an> 3 Switches", "status": "failed",
       "counts": {"done": 1, "failed": 1, "skipped": 0, "not_started": 1, "waiting": 0, "running": 0, "pending": 0}}

TICK = "await new Promise(r => setTimeout(r, 5)); "
TOASTS = '$("#toasts").children.map(t => t.textContent)'
LABELS = '$("#m-foot").children.map(b => b.textContent)'
# the newest footer button of that label (the stub's innerHTML = "" keeps the buttons of the dialogs before)
CLICK = 'await $("#m-foot").children.slice().reverse().find(b => b.textContent === "%s").handlers.click[0](); '
PREVIEW_CLICK = 'await $("#b-preview").handlers.click[0](); '


def bulk(then, me=None, preview=PREVIEW, run=RUN, rows=(), netmap=MAP):
    """The statements then (their return is the test's value) in the view "Sammeländerung", against an api stub that records every
    call as [method, url, body] and answers POST /api/bulk/plan with preview, POST /api/bulk with {id: 5}, GET /api/bulk/5 with run, GET
    /api/bulk with rows, POST /api/bulk/5/confirm with one confirmed change, POST /api/approvals with {id: 9}, anything else {ok:
    true}. pick({<switch id>: <ports text>}) ticks those switches and fills their port fields. The dialog of a run does not ask on:
    its 2 s never pass in a test that does not shorten them."""
    js = ('(async () => { ' + (me or role_me("admin", username="anna")) + 'MAP = ' + json.dumps(netmap) + '; current = "bulk"; const calls = []; '
          'refreshApprovals = async () => {}; '
          'api = async (m, u, b) => { calls.push([m, u, b === undefined ? null : b]); '
          'if (u === "/api/bulk/plan") return ' + json.dumps(preview) + '; if (m === "POST" && u === "/api/bulk") return {id: 5}; '
          'if (u === "/api/bulk/5") return ' + json.dumps(run) + '; if (u === "/api/bulk") return ' + json.dumps(list(rows)) + '; '
          'if (u === "/api/bulk/5/confirm") return {confirmed: [41], refused: []}; if (u === "/api/approvals") return {id: 9}; return {ok: true}; }; '
          'const pick = sel => { document.lists["[data-bulk-sw]"] = Object.keys(sel).map(id => ({dataset: {bulkSw: id}, checked: true})); '
          'document.lists["[data-bulk-ports]"] = Object.entries(sel).map(([id, t]) => ({dataset: {bulkPorts: id}, value: t})); }; '
          'const posts = () => calls.filter(c => c[0] === "POST"); ' + then + ' })()')
    return in_dom(js, tz="UTC")


FORM = 'await renderBulk(); return $("#view").innerHTML; '
# the form filled as the brief's case: SW-A with "1-2", SW-C with "5", untagged VLAN 30
FILLED = 'await renderBulk(); pick({1: "1-2", 3: "5"}); $("#b-u").value = "30"; '
PLAN_REQUEST = {"targets": [{"switch_id": A, "ports": ["1", "2"]}, {"switch_id": C, "ports": ["5"]}], "change": CHANGE, "expert": False}
BODY = {"items": [{"switch_id": A, "ports": ["1", "2"], "token": "t-a", "mechanism": "ssh"}], "skipped": [{"switch_id": C, "reason": REASON}],
        "change": CHANGE, "expert": False, "on_error": "stop"}


@pytest.mark.parametrize("me, want", [(role_me("aendern", zones=["EK"]), ["1"]), (role_me("admin"), ["1", "3"])], ids=["aendern-in-EK", "admin"])
def test_the_bulk_view_lists_only_switches_the_user_may_change(me, want):
    html = bulk(FORM, me=me)
    assert re.findall(r'<input type="checkbox" data-bulk-sw="(\d+)"', html) == want
    assert re.findall(r'data-bulk-ports="(\d+)"', html) == want and "SW-B" not in html
    # under its zone, with name and model (escaped), and a port field of its own that starts hidden
    assert '<div class="zonehead">EK</div>' in html and ('<div class="zonehead">VK</div>' in html) == ("3" in want)
    assert ('<div class="toolrow"><label class="check"><input type="checkbox" data-bulk-sw="1"> <span>SW-A <span class="muted">2530 &lt;48G&gt;</span></span>'
            '</label><input type="text" data-bulk-ports="1" placeholder="z. B. 1-4, 7" aria-label="Ports an SW-A" autocomplete="off" value="" hidden>'
            '</div>') in html


def test_lesen_sees_the_list_but_no_form():
    html, calls = bulk('await renderBulk(); return [$("#view").innerHTML, calls]; ', me=role_me("lesen"), rows=[ROW])
    assert '<p class="note gate">Sammeländerungen starten braucht die Rolle „Ändern“.</p>' in html
    assert 'id="b-preview"' not in html and "data-bulk-sw" not in html
    assert calls == [["GET", "/api/bulk", None]] and "<h2>Letzte Sammeländerungen</h2>" in html and 'data-bulk-open="5"' in html


def test_the_preview_request_carries_the_selection_and_the_change():
    listed = bulk(FILLED + PREVIEW_CLICK + 'return posts()[0]; ')
    assert listed == ["POST", "/api/bulk/plan", PLAN_REQUEST]
    by_vlan = bulk(FILLED + '$("#b-mode").value = "vlan"; $("#b-vlan").value = "20"; ' + PREVIEW_CLICK + 'return posts()[0]; ')
    assert by_vlan == ["POST", "/api/bulk/plan", {"targets": [{"switch_id": A, "untagged_in": "20"}, {"switch_id": C, "untagged_in": "20"}],
                                                   "change": CHANGE, "expert": False}]


# Beyond the brief: every field of the change reaches the request as the port form sends it - the name with "_" for blanks, "Name
# entfernen" as the empty name, PoE as a boolean, the tagged VLANs as lists, the expert mode
@pytest.mark.parametrize("fill, change, expert", [
    ('$("#b-st").value = "off"; $("#b-name").value = " Drucker  EK "; $("#b-poe").value = "off"; ',
     {"status": "off", "name": "Drucker_EK", "poe": False}, False),
    ('$("#b-tadd").value = "20, 30"; $("#b-trem").value = "40 50"; $("#b-nclear").checked = true; $("#b-name").value = "x"; $("#b-poe").value = "on"; '
     '$("#b-expert").checked = true; ', {"tagged_add": ["20", "30"], "tagged_remove": ["40", "50"], "name": "", "poe": True}, True)],
    ids=["state-name-poe", "tagged-clear-expert"])
def test_the_change_of_the_form_is_the_port_change_of_the_request(fill, change, expert):
    sent = bulk('await renderBulk(); pick({1: "7"}); ' + fill + PREVIEW_CLICK + 'return posts()[0][2]; ')
    assert sent == {"targets": [{"switch_id": A, "ports": ["7"]}], "change": change, "expert": expert}


def test_expert_mode_is_offered_only_to_who_may_use_it():                               # beyond the brief
    """Freigeben, or Ändern with the four-eyes principle on (expertOk); without it the box is not drawn and never sent."""
    with_box = bulk(FORM, me=role_me("aendern", four_eyes=True))
    assert 'id="b-expert" aria-describedby="b-4eyes"' in with_box
    assert 'id="b-expert"' not in bulk(FORM, me=role_me("aendern"))
    sent = bulk('await renderBulk(); pick({1: "7"}); $("#b-u").value = "30"; $("#b-expert").checked = true; ' + PREVIEW_CLICK
                + 'return posts()[0][2]; ', me=role_me("aendern"))
    assert sent["expert"] is False


@pytest.mark.parametrize("fill, said", [
    ('$("#b-u").value = "30"; ', "Bitte mindestens einen Switch wählen"),
    ('pick({1: "1"}); ', "Nichts ausgewählt, was sich ändern soll"),
    ('pick({1: "5-1"}); $("#b-u").value = "30"; ', "SW-A: Bereich „5-1“ ist rückwärts"),
    ('pick({1: " ", 3: "5"}); $("#b-u").value = "30"; ', "SW-A: Bitte Ports eintragen"),
    # beyond the brief: the VLAN filter without a VLAN, a tagged VLAN that is no number
    ('pick({1: ""}); $("#b-mode").value = "vlan"; $("#b-u").value = "30"; ', "Bitte das VLAN wählen, in dem die Ports ungetaggt sind"),
    ('pick({1: "1"}); $("#b-tadd").value = "20, x"; ', "Getaggte VLANs: „x“ ist keine VLAN-Nummer")],
    ids=["no-switch", "no-change", "backward-range", "no-ports", "no-vlan", "bad-tagged"])
def test_a_form_that_cannot_be_asked_says_why_and_asks_nothing(fill, said):
    toasts, asked, hidden = bulk('await renderBulk(); ' + fill + PREVIEW_CLICK + 'return [' + TOASTS + ', posts(), $("#modal").hidden]; ')
    assert (toasts, asked, hidden) == ([said], [], True)


def test_the_preview_runs_only_the_ready_sections():
    title, body, labels, calls = bulk(FILLED + PREVIEW_CLICK + 'const d = [$("#m-title").textContent, $("#m-body").innerHTML, ' + LABELS + ']; '
                                      + CLICK % "Ausführen (1 Switch)" + TICK + 'return [...d, calls]; ')
    assert title == "Sammeländerung: Vorschau" and labels == ["Zurück", "Abbrechen", "Ausführen (1 Switch)"]
    assert "<b>VLAN 30 · 2 Ports an 1 Switch</b>" in body and "1 Switch bereit, 1 übersprungen" in body and "Vier-Augen-Prinzip" not in body
    # the ready switch with its preview (previewBody), the skipped one with its reason
    assert '<b>SW-A</b> <span class="pill ok">bereit</span>' in body and '<pre class="code">vlan 30 untagged 1,2</pre>' in body
    assert '<b>SW-C</b> <span class="pill neutral">übersprungen</span>' in body and f'<p class="note gate">{REASON}</p>' in body
    assert 'id="p-confirm"' in body
    posted = [c for c in calls if c[0] == "POST"]
    assert posted == [["POST", "/api/bulk/plan", PLAN_REQUEST], ["POST", "/api/bulk", BODY]]
    # then the run's dialog asks for the bulk change (and the view under it is drawn anew, with an empty form)
    assert ["GET", "/api/bulk/5", None] in calls[calls.index(posted[1]):]


@pytest.mark.parametrize("fill, want", [
    ('$("#b-continue").checked = true; ', {"on_error": "continue"}),
    ('$("#p-confirm").checked = true; $("#p-confirm-min").value = "10"; ', {"confirm_minutes": 10}),
    ('$("#p-confirm-min").value = "10"; ', {})], ids=["continue", "with-confirmation", "minutes-not-ticked"])
def test_the_run_carries_continue_and_the_minutes_only_when_chosen(fill, want):
    # #b-continue is read with the form (before the preview), the confirmation's box at the click
    first = fill if "b-continue" in fill else ""
    sent = bulk(FILLED + first + PREVIEW_CLICK + (fill if not first else "") + CLICK % "Ausführen (1 Switch)" + 'return posts()[1]; ')
    assert sent == ["POST", "/api/bulk", {**BODY, **want}]


# Phase 4c, Task 12 (browser check): "Bestätigen" saves only over SSH (over SNMP the change stays unsaved, as each section says),
# so the bulk's choice promises a save only when every ready switch runs over SSH
@pytest.mark.parametrize("ways, saves", [(["ssh"], True), (["snmp"], False), (["ssh", "snmp"], False)], ids=["ssh", "snmp", "mixed"])
def test_the_bulk_choice_promises_a_save_only_when_every_switch_saves(ways, saves):
    ready = [{**SEC_A, "switch_id": i + 1, "preview": {**PLAN_A, "mechanism": w}} for i, w in enumerate(ways)]
    body = bulk(FILLED + PREVIEW_CLICK + 'return $("#m-body").innerHTML; ', preview={**PREVIEW, "sections": [*ready, SEC_C]})
    assert 'id="p-confirm"' in body and ("erst speichern, wenn ich bestätige" in body) == saves
    assert "Mit Bestätigung ausführen: " + ("erst speichern, wenn ich bestätige – " if saves else "") + "ohne Bestätigung nach <select" in body


def test_a_skipped_section_shows_its_reason_escaped():
    odd = {**PREVIEW, "sections": [SEC_A, {**SEC_C, "switch": "SW-<C>", "reason": "Lesen <fehlgeschlagen> & mehr", "selection": "Zugangsports <x>"}]}
    body = bulk(FILLED + PREVIEW_CLICK + 'return $("#m-body").innerHTML; ', preview=odd)
    assert '<b>SW-&lt;C&gt;</b> <span class="pill neutral">übersprungen</span>' in body
    assert '<p class="note gate">Lesen &lt;fehlgeschlagen&gt; &amp; mehr</p>' in body and "Zugangsports &lt;x&gt;" in body
    assert "<fehlgeschlagen>" not in body and "SW-<C>" not in body


def test_with_four_eyes_the_bulk_is_requested():
    body, labels, sent, toasts, hidden = bulk(
        FILLED + PREVIEW_CLICK + 'const d = [$("#m-body").innerHTML, ' + LABELS + ']; ' + CLICK % "Freigabe anfordern"
        + 'return [...d, posts()[1], ' + TOASTS + ', $("#modal").hidden]; ', preview={**PREVIEW, "approval": True})
    assert body.startswith('<div class="banner warn"><span><b>Vier-Augen-Prinzip:</b> Diese Sammeländerung wird erst ausgeführt, wenn eine zweite Person '
                           'mit der Rolle „Freigeben“ sie freigibt. Niemand kann die eigene Anfrage freigeben.</span></div>')
    assert labels == ["Zurück", "Abbrechen", "Freigabe anfordern"]
    assert sent == ["POST", "/api/approvals", {"kind": "bulk_change", "bulk": BODY}]
    assert toasts == ["Freigabe angefordert (Anfrage #9)"] and hidden


def test_no_ready_switch_offers_no_run():
    none = {**PREVIEW, "sections": [{**SEC_A, "status": "nothing", "reason": "Es gibt nichts zu ändern"}, SEC_C], "ready": 0, "skipped": 2,
            "confirm": {**POSSIBLE, "possible": False}}
    body, labels = bulk(FILLED + PREVIEW_CLICK + 'return [$("#m-body").innerHTML, ' + LABELS + ']; ', preview={**none, "approval": True})
    assert '<div class="banner">Kein Switch ist bereit.</div>' in body and labels == ["Zurück", "Abbrechen"]
    assert "0 Switches bereit, 2 übersprungen" in body and "Vier-Augen-Prinzip" not in body and "p-confirm" not in body


# Beyond the brief: what the preview's other buttons do, a refusal, a plan that fails and a dialog closed while the switches are read
def test_back_keeps_the_form_and_cancel_empties_it():
    read = 'return [$("#modal").hidden, bulkForm && bulkForm.ports["1"], $("#view").innerHTML.includes(\'data-bulk-ports="1"\')]; '
    assert bulk(FILLED + PREVIEW_CLICK + CLICK % "Zurück" + read) == [True, "1-2", True]
    hidden, form, drawn = bulk(FILLED + PREVIEW_CLICK + '$("#view").innerHTML = ""; ' + CLICK % "Abbrechen" + TICK + read)
    assert (hidden, form, drawn) == (True, None, True)


def test_the_form_keeps_its_state_over_a_new_render():
    html = bulk(FILLED + '$("#b-continue").checked = true; $("#b-name").value = "a\\"b"; collectBulk(); await renderBulk(); return $("#view").innerHTML; ')
    assert '<input type="checkbox" data-bulk-sw="1" checked>' in html and '<input type="checkbox" data-bulk-sw="3" checked>' in html
    assert 'aria-label="Ports an SW-A" autocomplete="off" value="1-2">' in html and 'aria-label="Ports an SW-C" autocomplete="off" value="5">' in html
    assert '<option value="30" selected>30 · Telefon</option>' in html and 'id="b-continue" checked>' in html and 'value="a&quot;b"' in html


def test_a_refused_start_names_the_reason_and_frees_the_button():
    then = (FILLED + PREVIEW_CLICK + 'const real = api; api = async (m, u, b) => { if (u === "/api/bulk") throw new Error("Die Vorschau ist veraltet"); '
            'return real(m, u, b); }; const b = $("#m-foot").children.find(x => x.textContent === "Ausführen (1 Switch)"); await b.handlers.click[0](); '
            'return [' + TOASTS + ', b.disabled, $("#modal").hidden, $("#m-title").textContent]; ')
    assert bulk(then) == [["Die Vorschau ist veraltet"], False, False, "Sammeländerung: Vorschau"]


def test_a_preview_that_fails_says_why_and_one_closed_meanwhile_stays_closed():
    failed = (FILLED + 'const real = api; api = async (m, u, b) => { if (u === "/api/bulk/plan") throw new Error("Höchstens <20> Switches"); '
              'return real(m, u, b); }; ' + PREVIEW_CLICK + 'return [$("#m-body").innerHTML, ' + LABELS + ']; ')
    assert bulk(failed) == ['<div class="error">Höchstens &lt;20&gt; Switches</div>', ["Zurück", "Schließen"]]
    closed = (FILLED + 'const real = api; api = async (m, u, b) => { if (u === "/api/bulk/plan") closeModal(); return real(m, u, b); }; ' + PREVIEW_CLICK
              + 'return [$("#modal").hidden, $("#m-body").innerHTML, ' + LABELS + ']; ')
    assert bulk(closed) == [True, '<div class="empty">Plane 2 Switches …</div>', []]


def test_the_form_shows_port_fields_only_for_ticked_switches_and_the_vlan_only_for_its_filter():   # beyond the brief
    then = ('await renderBulk(); const boxes = [{dataset: {bulkSw: "1"}, checked: true}, {dataset: {bulkSw: "3"}, checked: false}]; '
            'const fields = [{dataset: {bulkPorts: "1"}, hidden: true}, {dataset: {bulkPorts: "3"}, hidden: true}]; '
            'document.lists["[data-bulk-sw]"] = boxes; document.lists["[data-bulk-ports]"] = fields; const seen = []; '
            '$("#b-form").handlers.change[0](); seen.push(fields.map(f => f.hidden), $("#b-vlan").hidden); '
            '$("#b-mode").value = "vlan"; $("#b-form").handlers.change[0](); seen.push(fields.map(f => f.hidden), $("#b-vlan").hidden); return seen; ')
    assert bulk(then) == [[False, True], True, [True, True], False]


def test_without_a_switch_to_change_there_is_no_form():                                # beyond the brief
    """A browser has no #b-form then ($ answers null): the view binds nothing and still lists the bulk changes."""
    read_only = {**MAP, "switches": [MAP["switches"][1]]}
    html = bulk('const q = document.querySelector; document.querySelector = s => (s === "#b-form" || s === "#b-preview" ? null : q(s)); ' + FORM,
                netmap=read_only)
    assert '<p class="note gate">Kein Switch, an dem du ändern darfst und an dem SwitchView schreiben kann.</p>' in html
    assert 'id="b-form"' not in html and "<h2>Letzte Sammeländerungen</h2>" in html


def test_the_link_of_a_change_closes_the_run_dialog():                                 # beyond the brief
    then = OPEN + ('$("#m-body").onclick({target: {closest: () => null}}); const a = $("#modal").hidden; '
                   '$("#m-body").onclick({target: {closest: s => (s === "a[href]" ? {} : null)}}); return [a, $("#modal").hidden]; ')
    assert bulk(then) == [False, True]


def test_the_view_lists_the_last_bulk_changes():
    html, opened = bulk('let opened = null; openBulk = id => { opened = id; }; await renderBulk(); '
                        'await $("#view").onclick({target: {closest: s => s === "[data-bulk-open]" ? {dataset: {bulkOpen: "5"}} : null}}); '
                        'return [$("#view").innerHTML, opened]; ', rows=[ROW, {**ROW, "id": 4, "status": "running", "counts": RUN["counts"]}])
    assert "".join(re.findall(r"<th>([^<]*)</th>", html)) == "#ZeitvonÄnderungStatus"
    assert ('<tr><td class="num">5</td><td class="num">10.11.26, 09:00</td><td>a&lt;nna</td><td>VLAN 30 · 4 Ports &lt;an&gt; 3 Switches</td>'
            '<td><span class="pill crit">mit Fehlern</span><span class="cellnote">1 erledigt · 1 fehlgeschlagen · 1 nicht gestartet</span></td>'
            '<td><div class="actions"><button class="btn small" type="button" data-bulk-open="5">Anzeigen</button></div></td></tr>') in html
    assert ('<span class="pill neutral">läuft</span><span class="cellnote">1 erledigt · 0 fehlgeschlagen · 0 nicht gestartet · 1 wartet auf '
            'Bestätigung</span>') in html
    assert opened == 5
    assert '<div class="empty">Noch keine Sammeländerungen.</div>' in bulk(FORM)
    failed = bulk('const real = api; api = async (m, u, b) => { if (u === "/api/bulk") throw new Error("Server <weg>"); return real(m, u, b); }; ' + FORM)
    assert '<div class="empty">Server &lt;weg&gt;</div>' in failed and 'id="b-preview"' in failed


def test_the_states_of_a_bulk_change_and_of_its_switches():
    st, run = bulk("return [BULK_ST, BULK_RUN]; ")
    assert st == {"waiting": ["wartet", "neutral"], "running": ["läuft", "neutral"], "done": ["erledigt", "ok"], "failed": ["fehlgeschlagen", "crit"],
                  "skipped": ["übersprungen", "neutral"], "not_started": ["nicht gestartet", "neutral"]}
    assert run == {"queued": ["wartet", "neutral"], "running": ["läuft", "neutral"], "done": ["fertig", "ok"], "failed": ["mit Fehlern", "crit"],
                   "cancelled": ["abgebrochen", "neutral"], "interrupted": ["durch Neustart abgebrochen", "warn"]}


OPEN = 'openBulk(5); ' + TICK
FOOT = '$("#m-foot").children.slice(1).map(b => b.textContent)'


def test_the_run_dialog_shows_each_switch_and_offers_cancel_and_confirm_all():
    title, html, foot, posted, toasts = bulk(OPEN + 'const d = [$("#m-title").textContent, $("#bulk-run").innerHTML, ' + FOOT + ']; '
                                             + CLICK % "Abbrechen" + CLICK % "Alle bestätigen" + 'return [...d, posts(), ' + TOASTS + ']; ',
                                             me=role_me("aendern", username="anna"))
    assert title == "Sammeländerung #5" and foot == ["Abbrechen", "Alle bestätigen", "Schließen"]
    assert "<b>VLAN 30 · 4 Ports an 3 Switches</b>" in html and '<span class="pill neutral">läuft</span>' in html
    assert "1 erledigt · 0 fehlgeschlagen · 0 nicht gestartet" in html and "bei einem Fehler: stoppen" in html and "mit Bestätigung (5 Minuten)" in html
    assert "".join(re.findall(r"<th>([^<]*)</th>", html)) == "SwitchPortsZustandÄnderungDetail"
    # done with a change that waits, running, waiting: the pill, the change as a link to its switch, the name escaped
    assert ('<tr><td style="white-space:nowrap">SW-A</td><td class="mono">1, 2</td><td><span class="pill warn">wartet auf Bestätigung</span></td>'
            '<td><a href="#sw=1">#41</a></td><td>–</td></tr>') in html
    assert ('<tr><td style="white-space:nowrap">SW-&lt;B&gt;</td><td class="mono">7</td><td><span class="pill neutral">läuft</span></td>'
            '<td><a href="#sw=2">#42</a></td><td>–</td></tr>') in html
    assert ('<tr><td style="white-space:nowrap">SW-C</td><td class="mono">5</td><td><span class="pill neutral">wartet</span></td><td>–</td><td>–</td>'
            '</tr>') in html
    assert posted == [["POST", "/api/bulk/5/cancel", None], ["POST", "/api/bulk/5/confirm", None]]
    assert toasts == ["Abbruch angefordert", "1 Änderung bestätigt"]


@pytest.mark.parametrize("me, run, want", [
    (role_me("aendern", username="ben"), RUN, ["Alle bestätigen", "Schließen"]),                       # another user with Ändern
    (role_me("freigeben", username="ben"), RUN, ["Abbrechen", "Alle bestätigen", "Schließen"]),
    # beyond the brief: Freigeben outside a zone the bulk runs in (the server's 403), a reader, a cancel asked for already, an end
    (role_me("freigeben", username="ben", zones=["EK"]), RUN, ["Alle bestätigen", "Schließen"]),
    (role_me("lesen", username="anna"), RUN, ["Schließen"]),
    (role_me("aendern", username="anna"), {**RUN, "cancel_requested": True}, ["Alle bestätigen", "Schließen"]),
    (role_me("aendern", username="anna"), {**RUN, "status": "done", "counts": {**RUN["counts"], "pending": 0}}, [])],
    ids=["other", "freigeben", "freigeben-other-zone", "lesen", "cancel-asked", "ended"])
def test_cancel_and_confirm_all_are_offered_to_who_may(me, run, want):
    # a footer that stays "Schließen" (the dialog's own) is not set again
    foot = bulk(OPEN + 'return ' + FOOT + '; ', me=me, run=run)
    assert foot == (want if want != ["Schließen"] else [])


def test_who_may_cancel_a_bulk_change():
    then = ('const b = {username: "Anna", items: [{status: "done", switch_id: 1, zone: "EK"}, {status: "skipped", switch_id: 3, zone: "VK"}, '
            '{status: "waiting", switch_id: null, zone: ""}]}; return [mayCancelBulk(b), mayCancelBulk({...b, username: "ben"})]; ')
    assert bulk(then, me=role_me("aendern", username="anna")) == [True, False]
    # Freigeben: the zones of the switches it runs at, a skipped or deleted one not counted
    assert bulk(then, me=role_me("freigeben", username="carl", zones=["EK"])) == [True, True]
    assert bulk(then, me=role_me("freigeben", username="carl", zones=["VK"])) == [False, False]


@pytest.mark.parametrize("change, detail, pill", [
    ({**ITEM["change"], "status": "unclear"}, "Änderung #41 nicht bestätigt, zurückgenommen", '<span class="pill warn">nicht bestätigt</span>'),
    ({**ITEM["change"], "status": "ok", "saved": 1, "confirmed_by": "anna"}, "", '<span class="pill ok">erledigt</span>'),
    ({**ITEM["change"], "status": "unclear", "confirm_until": None}, "", '<span class="pill ok">erledigt</span>')],
    ids=["unconfirmed", "confirmed", "never-waited"])
def test_a_done_switch_names_a_change_that_ended_unconfirmed(change, detail, pill):
    run = {**RUN, "status": "failed", "items": [{**ITEM, "change": change, "detail": detail}], "counts": {**RUN["counts"], "pending": 0}}
    html = bulk(OPEN + 'return $("#bulk-run").innerHTML; ', run=run)
    assert f'<td>{pill}</td><td><a href="#sw=1">#41</a></td><td>{detail or "–"}</td></tr>' in html
    assert '<span class="pill crit">mit Fehlern</span>' in html


def test_the_run_dialog_names_the_approver_a_cancel_and_a_deleted_switch():           # beyond the brief
    gone = {**ITEM, "switch_id": None, "switch": "SW-alt", "status": "failed", "detail": "Switch <gelöscht>",
            "change": {**ITEM["change"], "status": "failed"}}
    run = {**RUN, "approved_by": "b<en", "cancel_requested": True, "on_error": "continue", "confirm_minutes": None, "items": [gone]}
    html = bulk(OPEN + 'return $("#bulk-run").innerHTML; ', run=run)
    assert "freigegeben von b&lt;en" in html and "Abbruch angefordert" in html and "bei einem Fehler: weitermachen" in html
    assert "mit Bestätigung" not in html
    assert '<td><span class="pill crit">fehlgeschlagen</span></td><td>#41</td><td>Switch &lt;gelöscht&gt;</td></tr>' in html


# The dialog of a run with its 2 s shortened to 5 ms and every delay recorded; waitFor as in tests/test_frontend_confirm.py
POLL = ('const delays = [], st = setTimeout; setTimeout = (f, ms) => { delays.push(ms); return st(f, ms === 2000 ? 5 : ms); }; '
        'const waitFor = async ok => { const end = Date.now() + 5000; while (!ok() && Date.now() < end) await new Promise(r => st(r, 2)); }; '
        'const gets = () => calls.filter(c => c[1] === "/api/bulk/5" && c[0] === "GET").length; ')


def test_the_run_dialog_asks_every_two_seconds_while_the_bulk_is_live():
    n, delays = bulk(POLL + 'openBulk(5); await waitFor(() => gets() >= 3); return [gets(), delays]; ')
    assert n >= 3 and set(delays) == {2000}


@pytest.mark.parametrize("run, asks_on", [
    ({**RUN, "status": "done", "counts": {**RUN["counts"], "pending": 1}}, True),          # ended, a change still waits for its confirmation
    ({**RUN, "status": "queued", "counts": {**RUN["counts"], "pending": 0}}, True),
    ({**RUN, "status": "failed", "counts": {**RUN["counts"], "pending": 0}}, False),
    ({**RUN, "status": "cancelled", "counts": {**RUN["counts"], "pending": 0}}, False)], ids=["pending", "queued", "failed", "cancelled"])
def test_the_run_dialog_stops_asking_once_nothing_can_change(run, asks_on):
    # asking on: until it asked again (at most 5 s); not asking: a window for an absence, which a loaded machine can only let pass
    wait = "await waitFor(() => gets() >= 2); " if asks_on else "await new Promise(r => st(r, 60)); "
    n = bulk(POLL + 'openBulk(5); ' + wait + 'return gets(); ', run=run)
    assert (n > 1) == asks_on


def test_a_closed_run_dialog_stops_asking_and_a_failed_read_says_why():
    then = POLL + 'openBulk(5); await waitFor(() => gets() >= 2); closeModal(); const n = gets(); await new Promise(r => st(r, 40)); return [n, gets()]; '
    n, after = bulk(then)
    assert n >= 2 and after <= n + 1          # the one request under way when it closed may still come back
    failed = ('const real = api; api = async (m, u, b) => { if (u === "/api/bulk/5") throw new Error("Sammeländerung <nicht> gefunden"); '
              'return real(m, u, b); }; ' + OPEN + 'return $("#bulk-run").innerHTML; ')
    assert bulk(failed) == '<div class="error">Sammeländerung &lt;nicht&gt; gefunden</div>'


def test_a_refused_confirm_all_names_how_many_and_why():                               # beyond the brief
    then = ('const real = api; api = async (m, u, b) => u === "/api/bulk/5/confirm" ? {confirmed: [41, 43], refused: [{id: 44, detail: "Zu spät"}]} '
            ': real(m, u, b); ' + OPEN + CLICK % "Alle bestätigen" + 'api = async () => { throw new Error("Keine Berechtigung"); }; '
            'const b = $("#m-foot").children.find(x => x.textContent === "Abbrechen"); await b.handlers.click[0](); return [' + TOASTS + ', b.disabled]; ')
    assert bulk(then) == [["2 Änderungen bestätigt, 1 nicht: Zu spät", "Keine Berechtigung"], False]


def test_the_sections_of_a_request_name_switch_ports_and_commands():
    # SW-A over SSH (its driver's autosave says nothing there), SW-C without a plan, SW-D over SNMP at a switch that does not save
    secs = [{"switch_id": A, "switch": "SW-<A>", "ports": ["1", "2"], "mechanism": "ssh", "commands": ["vlan 30 untagged 1,2", "x <y>"],
             "warnings": ["Port 1: <Achtung>"], "token": "t", "autosave": True},
            {"switch_id": C, "switch": "SW-C", "ports": ["5"], "mechanism": None, "commands": [], "warnings": [], "token": None, "status": "error",
             "reason": "Switch <deaktiviert>", "matches": False},
            {"switch_id": 4, "switch": "SW-D", "ports": ["Gi1/0/2"], "mechanism": "snmp", "commands": ["Port Gi1/0/2: Access-VLAN 1 → 20"],
             "warnings": [], "token": "t-d", "autosave": False}]
    plain, review = bulk(f'return [bulkSectionsHtml({json.dumps(secs)}), bulkSectionsHtml({json.dumps(secs)}, true)]; ')
    assert ('<div class="bulk-sec"><p style="margin:0"><b>SW-&lt;A&gt;</b> <span class="muted">· 2 Ports: <span class="mono">1, 2</span></span></p>'
            '<div class="banner warn"><ul class="blist"><li>Port 1: &lt;Achtung&gt;</li></ul></div>'
            '<pre class="code">vlan 30 untagged 1,2\nx &lt;y&gt;</pre></div>') in plain
    assert ('<span class="muted">· 1 Port: <span class="mono">5</span></span></p><p class="note gate">Switch &lt;deaktiviert&gt;</p>'
            '<pre class="code">–</pre>') in plain
    # Final review of Phase 4c, finding 5: the reviewer is told that this switch is changed over SNMP and not saved
    assert ('<b>SW-D</b> <span class="muted">· 1 Port: <span class="mono">Gi1/0/2</span> · per SNMP, nicht gespeichert</span></p>'
            '<pre class="code">Port Gi1/0/2: Access-VLAN 1 → 20</pre>') in plain
    assert plain.count("per SNMP") == review.count("per SNMP") == 1
    assert "passt nicht mehr" not in plain and review.count('<span class="pill warn">passt nicht mehr</span>') == 1
    assert review.index("SW-C") < review.index("passt nicht mehr")


@pytest.mark.parametrize("autosave, mark", [(False, " · per SNMP, nicht gespeichert"), (True, " · per SNMP, automatisch gespeichert"),
                                            (None, " · per SNMP")], ids=["unsaved", "saves-itself", "request-from-before"])
def test_a_section_over_snmp_says_whether_the_switch_keeps_the_change(autosave, mark):
    """Finding 5 of the final review: as the requester's preview (previewBody) says it - a ProCurve over SNMP saves every SET by
    itself (snmp_autosave), any other switch keeps the change unsaved; a request stored before the review has no autosave."""
    sec = {"switch_id": A, "switch": "SW-A", "ports": ["5"], "mechanism": "snmp", "commands": ["x"], "warnings": [], "token": "t"}
    html = bulk(f'return bulkSectionsHtml({json.dumps([sec if autosave is None else {**sec, "autosave": autosave}])}); ')
    assert f'<b>SW-A</b> <span class="muted">· 1 Port: <span class="mono">5</span>{mark}</span></p>' in html


def test_the_view_is_reached_by_its_hash():
    """VIEWS.bulk: #bulk, and the link of the alert bulk_problem (_view "bulk")."""
    assert in_dom('(async () => { const is = VIEWS.bulk === renderBulk; ' + NO_VIEWS + '$("#app").hidden = false; location.hash = "#bulk"; '
                  'window.fire("hashchange"); return [is, current]; })()') == [True, "bulk"]


@pytest.mark.parametrize("role, offered", [("aendern", True), ("admin", True), ("lesen", False)])
def test_the_switch_view_offers_the_entry_to_aendern_only(role, offered):
    html = in_dom(role_me(role) + DETAIL % (json.dumps(MAP_SW), 1))
    button = '<button type="button" class="btn small add" id="btn-bulk">Sammeländerung</button>'
    assert (button in html) == offered
    if role == "admin":                 # at the end of the side bar, before "Switch hinzufügen"
        assert html.index('id="btn-bulk"') < html.index('id="btn-add"') < html.index("</nav>")


def test_the_entry_opens_the_bulk_view():
    js = ('(async () => { ' + role_me("aendern") + NO_VIEWS + 'api = async () => []; bindSide(); $("#btn-bulk").handlers.click[0](); '
          'return [current, location.hash]; })()')
    assert in_dom(js) == ["bulk", "#bulk"]


def test_the_change_list_names_the_bulk():
    rows = [{**ROWS[0], "bulk_id": 5}, {**ROWS[1], "bulk_id": None}]
    html = in_dom(LIST % (json.dumps(rows), 10, "return el.innerHTML;"))
    assert html.count("Sammeländerung #") == 1 and '<td>Port 2: VLAN 20<span class="cellnote">Sammeländerung #5</span></td>' in html


def test_the_audit_labels_of_bulk_changes():
    keys = ["bulk_start", "bulk_done", "bulk_failed", "bulk_cancel", "bulk_cancelled", "bulk_interrupted"]
    assert in_dom(f"{json.dumps(keys)}.map(k => AUDIT_LABELS[k])") == [
        "Sammeländerung gestartet", "Sammeländerung fertig", "Sammeländerung mit Fehlern", "Abbruch einer Sammeländerung angefordert",
        "Sammeländerung abgebrochen", "Sammeländerung durch Neustart abgebrochen"]


# Task 12 (browser check): with the four-eyes principle on every bulk change is requested, not only one in expert mode - the form
# said the port form's sentence ("Im Expertenmodus braucht die Änderung eine Freigabe …") under its expert box
BULK_FOUR_EYES = ('<p class="note" id="b-4eyes" style="margin:0">Vier-Augen-Prinzip: Jede Sammeländerung braucht die Freigabe durch eine zweite '
                  'Person, mit und ohne Expertenmodus – die Vorschau fordert sie an.</p>')


@pytest.mark.parametrize("role, four", [("aendern", True), ("freigeben", True), ("freigeben", False), ("aendern", False)])
def test_the_form_says_that_every_bulk_change_needs_an_approval(role, four):
    html = bulk(FORM, me=role_me(role, four_eyes=four))
    assert (BULK_FOUR_EYES in html) == four and "Im Expertenmodus braucht die Änderung" not in html and 'id="f-4eyes"' not in html
    if four:    # after the choice what a failure does, before "Vorschau"; the expert box names it as its description
        assert html.index('id="b-continue"') < html.index('id="b-4eyes"') < html.index('id="b-preview"')
        assert 'id="b-expert" aria-describedby="b-4eyes"' in html
    elif role == "freigeben":
        assert 'id="b-expert">' in html


# Final review of Phase 4c, finding 1: the status of a bulk change is that of its run - with confirmation it ends "fertig" while its
# changes wait, and a change taken back after the run leaves it so; the counts say what its changes do now (bulk.COUNTED)
@pytest.mark.parametrize("counts, note", [
    ({"pending": 1}, "1 erledigt · 0 fehlgeschlagen · 0 nicht gestartet · 1 wartet auf Bestätigung"),
    ({"pending": 2, "unconfirmed": 1}, "1 erledigt · 0 fehlgeschlagen · 0 nicht gestartet · 2 warten auf Bestätigung · 1 nicht bestätigt"),
    ({"pending": 0, "unconfirmed": 1}, "1 erledigt · 0 fehlgeschlagen · 0 nicht gestartet · 1 nicht bestätigt"),
    ({"pending": 0, "unconfirmed": 0}, "1 erledigt · 0 fehlgeschlagen · 0 nicht gestartet")], ids=["waits", "both", "unconfirmed", "neither"])
def test_a_listed_bulk_names_its_changes_that_wait_or_ended_unconfirmed(counts, note):
    row = {**ROW, "status": "done", "counts": {**ROW["counts"], "failed": 0, "not_started": 0, **counts}}
    assert f'<span class="pill ok">fertig</span><span class="cellnote">{note}</span></td>' in bulk(FORM, rows=[row])


def test_the_run_dialog_names_the_changes_that_wait_or_ended_unconfirmed():
    run = {**RUN, "status": "done", "counts": {**RUN["counts"], "running": 0, "pending": 1, "unconfirmed": 2}}
    html = bulk(OPEN + 'return $("#bulk-run").innerHTML; ', run=run)
    assert ('<span class="pill ok">fertig</span> · 1 erledigt · 0 fehlgeschlagen · 0 nicht gestartet · 1 wartet auf Bestätigung · 2 nicht bestätigt'
            ' · bei einem Fehler: stoppen') in html
