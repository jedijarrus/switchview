"""Phase 4b Task 10: the audit view asks the server, against the recording DOM stub of tests/test_frontend_dom.py - every change of a
filter is a question to GET /api/audit (the text and the user 300 ms after the last key, the choices at once), 100 entries a page
with "Mehr laden" by the cursor, "Als CSV" with the same filters, and the filters outlive a new render. The tests of renderAudit
from tests/test_frontend_dom.py moved here; their answers are {rows, next}, and what they said about filtering in the browser is
said about the URL asked. Skipped without node."""
import json
import re
import shutil

import pytest
from test_frontend_dom import in_dom
from test_frontend_logic import AUDIT  # the audit rows of the old filter test of Phase 5 Task 8

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

NETMAP = {"switches": [{"id": 1, "k": "SW-HP", "ports": []}, {"id": 2, "k": "SW <2>", "ports": []}], "links": [], "vlans": {}}
# The view with the answer page (a JS expression over u, the URL asked) to every GET /api/audit, the netmap and [] to anything else
# (the change list); calls: every URL asked. then: the statements after the first render, its value the test's
VIEW = ('(async () => { const calls = []; let page = %s; MAP = %s; api = async (m, u) => { calls.push(u); return u.startsWith("/api/audit?") '
        '? (typeof page === "function" ? page(u) : page) : []; }; await renderAudit(); %s })()')
PAUSE = "await new Promise(r => setTimeout(r, 380)); "
TICK = "await new Promise(r => setTimeout(r, 5)); "
FIELD = '$("#%s").value = %s; $("#%s").fire("%s"); '


def view(page, then, map_=NETMAP, tz=None):
    return in_dom(VIEW % (page if isinstance(page, str) else json.dumps(page), json.dumps(map_), then), tz=tz)


def type_in(field, text):
    return FIELD % (field, json.dumps(text), field, "input")


def pick(field, value):
    return FIELD % (field, json.dumps(value), field, "change")


def audit_calls(calls):
    return [u for u in calls if u.startswith("/api/audit")]


def test_the_audit_shows_details_and_asks_the_server_for_the_text():          # was test_the_audit_shows_details_and_filters
    full, asked_now, bob, calls = view({"rows": AUDIT, "next": None},
                                       'const a = [$("#au-list").innerHTML]; page = {rows: [%s], next: null}; ' % json.dumps(AUDIT[1])
                                       + type_in("au-q", "bob") + 'a.push(calls.filter(u => u.startsWith("/api/audit")).length); ' + PAUSE
                                       + 'return [...a, $("#au-list").innerHTML, calls]; ')
    assert '<span class="cellnote">host: 10.0.0.1 → 10.0.0.2</span>' in full and full.count("<tr>") == 4    # the head and three entries
    assert audit_calls(calls) == ["/api/audit?limit=100", "/api/audit?q=bob&limit=100"] and asked_now == 1
    assert bob.count("<tr>") == 2 and "<td>bob</td><td>–</td><td>Anmeldung</td>" in bob    # Phase 4a Task 8: the role between user and action


def test_the_audit_asks_the_server_with_its_filters():
    calls = view({"rows": [], "next": None}, pick("au-role", "aendern") + pick("au-from", "2026-11-07") + "return calls;", tz="Europe/Berlin")
    assert audit_calls(calls) == ["/api/audit?limit=100", "/api/audit?role=aendern&limit=100",
                                  "/api/audit?role=aendern&since=2026-11-06T23%3A00%3A00.000Z&limit=100"]


# Beyond the brief: each field reaches its parameter (the switch by its id, "Bis" as the midnight after its day), the text and the
# user wait for the pause after the last key (one question for three keys), the choices ask at once
def test_each_filter_reaches_its_parameter_and_the_fields_wait_for_the_pause():
    then = (pick("au-act", "login") + pick("au-sw", "2") + pick("au-to", "2026-11-07") + 'const before = calls.length; '
            + type_in("au-user", "A") + type_in("au-user", "An") + type_in("au-user", "Anna") + 'const typed = calls.length; '
            + PAUSE + 'return [before, typed, calls]; ')
    before, typed, calls = view({"rows": [], "next": None}, then, tz="Europe/Berlin")
    assert before == typed and audit_calls(calls) == [
        "/api/audit?limit=100", "/api/audit?action=login&limit=100", "/api/audit?action=login&switch_id=2&limit=100",
        "/api/audit?action=login&switch_id=2&until=2026-11-07T23%3A00%3A00.000Z&limit=100",
        "/api/audit?action=login&user=Anna&switch_id=2&until=2026-11-07T23%3A00%3A00.000Z&limit=100"]


def test_the_audit_pages_and_keeps_its_filter_across_a_new_render():          # Phase 5 review, Minor 7, now with the server's answer
    first = {"rows": [{**AUDIT[0], "id": 9}, {**AUDIT[1], "id": 8}], "next": 8}
    more = '{target: {closest: s => s === "[data-more]" ? {disabled: false} : null}}'
    then = ('const a = [$("#au-list").innerHTML]; page = {rows: [%s], next: null}; await $("#au-list").onclick(%s); a.push($("#au-list").innerHTML); '
            % (json.dumps({**AUDIT[2], "id": 7}), more)
            + type_in("au-q", "anna") + pick("au-act", "login") + pick("au-role", "none") + pick("au-sw", "1") + pick("au-from", "2026-11-01")
            + type_in("au-user", "bob") + 'await renderAudit(); return [...a, $("#view").innerHTML, calls]; ')
    paged, appended, html, calls = view(first, then, tz="Europe/Berlin")
    assert '<button class="btn small" type="button" data-more>Mehr laden</button>' in paged and paged.count("<tr>") == 3
    assert "data-more" not in appended and appended.count("<tr>") == 4 and appended.index("Switch geändert") < appended.index("Anmeldung fehlgeschlagen")
    asked = audit_calls(calls)
    assert asked[1] == "/api/audit?cursor=8&limit=100"
    assert ('id="au-q" placeholder="Benutzer, Aktion, Ziel, Details" aria-label="Protokoll durchsuchen" value="anna"' in html
            and '<option value="login" selected>Anmeldung</option>' in html and '<option value="none" selected>ohne Rolle</option>' in html
            and '<option value="1" selected>SW-HP</option>' in html and 'id="au-from" aria-label="Von" value="2026-11-01"' in html
            and 'id="au-user" placeholder="Benutzer" aria-label="Benutzer" value="bob"' in html)
    # the new render asks at once with every filter kept, the text and the user too (their pause was overtaken by the render)
    assert asked[-1] == "/api/audit?q=anna&action=login&user=bob&role=none&switch_id=1&since=2026-10-31T23%3A00%3A00.000Z&limit=100"


def test_the_audit_csv_link_carries_the_filters():
    then = ('const a = [$("#view").innerHTML]; ' + pick("au-role", "aendern") + pick("au-from", "2026-11-07") + type_in("au-q", "x & y")
            + 'a.push($("#au-csv").getAttribute("href")); return a; ')
    html, href = view({"rows": [], "next": None}, then, tz="Europe/Berlin")
    assert '<a class="btn small" id="au-csv" href="/api/audit.csv" download>Als CSV</a>' in html
    # the filters as typed, before the pause: the link is what the fields say, without the page's cursor and limit
    assert href == "/api/audit.csv?q=x%20%26%20y&role=aendern&since=2026-11-06T23%3A00%3A00.000Z"


def test_the_audit_lists_every_action_sorted_by_its_text():                    # was test_the_audit_drops_a_kept_action_..., T1-f
    labels = in_dom("AUDIT_LABELS")
    for key, text in {"alert_settings": "Benachrichtigungen geändert", "alert_test": "Benachrichtigung getestet",
                      "alert_failed": "Benachrichtigung nicht zugestellt", "compliance_rules": "Sicherheitsregeln geändert",
                      "watch_add": "MAC beobachtet", "watch_remove": "MAC nicht mehr beobachtet",
                      "pf_snmp_settings": "SNMP-Benutzer für PacketFence geändert"}.items():
        assert labels[key] == text
    rows = [{**AUDIT[0], "action": "neu_im_server"}]     # an action without a label shows its key, the choice offers only the labelled ones
    html, body = view({"rows": rows, "next": None}, 'return [$("#view").innerHTML, $("#au-list").innerHTML]; ')
    select = re.search(r'<select id="au-act" aria-label="Aktion">(.*?)</select>', html).group(1)
    options = re.findall(r'<option value="([^"]*)"[^>]*>([^<]*)</option>', select)

    def fold(t):
        return t.lower().replace("ä", "a").replace("ö", "o").replace("ü", "u").replace("ß", "ss")
    assert options[0] == ("", "Alle Aktionen") and [k for k, _ in options[1:]] == sorted(labels, key=lambda k: fold(labels[k]))
    assert [t for _, t in options[1:]] == [labels[k] for k, _ in options[1:]] and "<td>neu_im_server" in body


def test_the_audit_shows_the_role():
    rows = [{**AUDIT[0], "role": "aendern"}, {**AUDIT[1], "role": None}]
    html = view({"rows": rows, "next": None}, 'return $("#au-list").innerHTML; ')
    assert "<td>anna</td><td>Ändern</td>" in html and "<td>bob</td><td>–</td>" in html and "<th>Rolle</th>" in html


# Beyond the brief: the fields of the filter as the brief names them; an answer without rows reads "Noch keine Einträge." and,
# with a filter, "Keine Einträge für diesen Filter."; a switch kept in the filter that the netmap no longer has is dropped (no
# filter that the view does not show)
def test_the_filter_fields_and_the_empty_answers():
    then = ('const a = [$("#view").innerHTML, $("#au-list").innerHTML]; ' + pick("au-role", "lesen") + TICK + 'a.push($("#au-list").innerHTML); '
            + pick("au-sw", "2") + 'MAP = {switches: [{id: 1, k: "SW-HP", ports: []}], links: [], vlans: {}}; await renderAudit(); '
            'return [...a, $("#view").innerHTML, calls]; ')
    html, empty, filtered, again, calls = view({"rows": [], "next": None}, then)
    assert '<span class="sub">neueste zuerst · gefiltert am Server</span>' in html
    assert ('<select id="au-role" aria-label="Rolle"><option value="">Alle Rollen</option><option value="lesen">Lesen</option>'
            '<option value="aendern">Ändern</option><option value="freigeben">Freigeben</option><option value="admin">Admin</option>'
            '<option value="none">ohne Rolle</option></select>') in html
    assert ('<select id="au-sw" aria-label="Switch"><option value="">Alle Switches</option><option value="1">SW-HP</option>'
            '<option value="2">SW &lt;2&gt;</option></select>') in html
    assert '<input type="date" id="au-from" aria-label="Von" value="">' in html and '<input type="date" id="au-to" aria-label="Bis" value="">' in html
    assert empty == '<div class="empty">Noch keine Einträge.</div>' and filtered == '<div class="empty">Keine Einträge für diesen Filter.</div>'
    assert '<option value="2" selected>' not in again and audit_calls(calls)[-1] == "/api/audit?role=lesen&limit=100"


# Beyond the brief: a key while a question is on its way drops its answer (the answer to "an" never shows under "anna"), and a
# failed question names the server's text in the list
def test_typing_drops_the_answer_to_the_filter_before():
    page = ('u => u.includes("q=an&") ? new Promise(r => setTimeout(() => r({rows: [%s], next: null}), 150)) '
            ': u.includes("q=anna") ? {rows: [], next: null} : u.includes("role=") ? Promise.reject(new Error("Zeitpunkt ungültig")) '
            ': {rows: [], next: null}') % json.dumps(AUDIT[1])
    # "an" asks at 300 ms and its answer comes at 450 ms, after "anna" was typed (320 ms) and before "anna" asks (620 ms)
    then = (type_in("au-q", "an") + PAUSE.replace("380", "320") + type_in("au-q", "anna") + PAUSE.replace("380", "200")
            + 'const a = [$("#au-list").innerHTML]; ' + PAUSE + 'a.push($("#au-list").innerHTML); '
            + type_in("au-q", "") + pick("au-role", "admin") + 'await new Promise(r => setTimeout(r, 20)); return [...a, $("#au-list").innerHTML, calls]; ')
    between, anna, failed, calls = view(page, then)
    assert between == '<div class="empty">Noch keine Einträge.</div>' and anna == '<div class="empty">Keine Einträge für diesen Filter.</div>'
    assert failed == '<div class="empty">Zeitpunkt ungültig</div>' and "/api/audit?q=an&limit=100" in calls


# Browser check: "Mehr laden" is disabled while its page loads, and a browser drops the focus of a disabled button to body; the list
# takes it first (loadPaged, sv-history.js), so it stays in the list (the stub's button drops it as a browser does)
def test_more_keeps_the_focus_in_the_list_while_its_button_is_disabled():
    then = ('const m = {get disabled() { return false; }, set disabled(v) { if (v && document.activeElement === m) document.activeElement = document.body; }}; '
            'document.activeElement = m; page = {rows: [], next: null}; '
            'await $("#au-list").onclick({target: {closest: s => (s === "[data-more]" ? m : null)}}); '
            'return [document.activeElement.sel, $("#au-list").getAttribute("tabindex")]; ')
    assert view({"rows": [{**AUDIT[0], "id": 9}], "next": 9}, then) == ["#au-list", "-1"]
