"""Phase 4b Task 9: the history in the UI, against the recording DOM stub of tests/test_frontend_dom.py - the view "Verlauf" (where a
device was seen, the events of every switch), the way there from the global search, "Bisher an diesem Port" in the port panel, the
cards "Ereignisse" and "Sicherheitsbefunde" of the switch view, the mark of a backup changed outside SwitchView, and the findings and
outside changes among the overview's "Auffälligkeiten". Skipped without node."""
import json
import re
import shutil
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest
from test_frontend_dom import INDEX, NO_VIEWS, SEARCH, STATIC, in_dom, role_me

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

ROW = {"id": 3, "mac": "aa:bb:cc:00:00:01", "vendor": "Acme", "ip": "10.0.0.5", "name": "<b>pc</b>", "switch_id": 1, "switch": "SW", "port": "5",
       "vlan": "20", "first_seen": "2026-11-01 10:00:00", "last_seen": "2026-11-07 09:00:00", "suspect": False}
SW1 = {"id": 1, "k": "SW", "zone": "", "caps": ["cli", "backup"], "ports": [], "ok": True, "error": "", "ssh": True, "snmp_write": False}
VIEW = ('(async () => { MAP = {switches: [%s], links: [], vlans: {}}; const calls = []; api = async (m, u) => { calls.push(u); return %s; }; histTerm = %s; '
        'await renderVerlauf(); %s })()')
HISTORY = 'u.startsWith("/api/history?") ? {rows: [%s], next: null} : {rows: [], next: null}'
MORE = '<div class="more-row"><button class="btn small" type="button" data-more>Mehr laden</button></div>'
EXPLAIN = '<div class="empty">MAC, IP oder Namen eingeben: SwitchView zeigt, wo das Gerät gesehen wurde.</div>'
HELP = "Bitte nach MAC, IP oder Name suchen (mindestens 2 Zeichen) oder Switch und Port angeben"
SUSPECT = ' <span class="pill warn" title="Der Port war damals vielleicht ein Uplink">Uplink (unbestätigt)</span>'
DOWN = {"id": 5, "ts": "2026-11-07 08:00:00", "switch_id": 1, "switch": "SW", "kind": "switch_down", "label": "Antwortet nicht", "port": "",
        "text": "SW antwortet seit 3 Abfragen nicht: <Timeout>", "detail": {"failures": 3}}
DRIFT = {"id": 6, "ts": "2026-11-07 02:30:00", "switch_id": 1, "switch": "SW", "kind": "drift_config",
         "label": "Konfiguration außerhalb von SwitchView geändert", "port": "",
         "text": "Konfiguration außerhalb von SwitchView geändert (Sicherung vom 2026-11-07 02:30:00 UTC)", "detail": {"backup": 9, "previous": 8}}
BDIFF = '<button class="btn small" type="button" data-bdiff="9">Vergleich</button>'


def click(attr, data):
    """The argument of an onclick whose target lies inside the element with attr (the stub's closest() answers only that selector)."""
    return '{target: {closest: s => s === "[%s]" ? {dataset: %s} : null}}' % (attr, json.dumps(data))


def test_the_history_view_searches_and_shows_the_sightings():
    answer = 'u.startsWith("/api/history?") ? {rows: [%s], next: null} : {rows: [], next: null}' % json.dumps(ROW)
    html, calls = in_dom(VIEW % (json.dumps(SW1), answer, '"pc"', 'return [$("#hi-list").innerHTML, calls];'))
    assert "/api/history?q=pc&limit=50" in calls and '<button type="button" class="linkbtn" data-hsw="1" data-hport="5">5</button>' in html


def test_history_rows_escape_what_they_show():                                         # Review Focus 5
    answer = 'u.startsWith("/api/history?") ? {rows: [%s], next: null} : {rows: [], next: null}' % json.dumps(ROW)
    html = in_dom(VIEW % (json.dumps(SW1), answer, '"pc"', 'return $("#hi-list").innerHTML;'))
    assert "&lt;b&gt;pc&lt;/b&gt;" in html and "<b>pc</b>" not in html


def test_the_sightings_table_has_its_columns_and_the_view_its_texts():
    html, view = in_dom(VIEW % (json.dumps(SW1), HISTORY % json.dumps(ROW), '"pc"', 'return [$("#hi-list").innerHTML, $("#view").innerHTML];'))
    heads = re.findall(r"<th>([^<]*)</th>", html)
    assert heads == ["Zuletzt gesehen", "Zuerst gesehen", "MAC", "IP", "Name", "Switch", "Port", "VLAN"]
    assert "<h2>Wo war ein Gerät?</h2>" in view and "nach MAC, IP oder Name · zuletzt gesehen zuerst" in view
    assert 'id="hi-q"' in view and 'placeholder="MAC, IP oder Name"' in view and 'aria-label="Verlauf durchsuchen"' in view and 'value="pc"' in view
    assert ">Acme<" in html and ">10.0.0.5<" in html and ">20<" in html and SUSPECT not in html
    assert html.count('<td class="num time">') == 2


def test_more_loads_the_next_page_with_its_cursor():
    second = {**ROW, "id": 2, "mac": "aa:bb:cc:00:00:02", "last_seen": "2026-11-06 09:00:00"}
    answer = ('u.startsWith("/api/history?") ? (u.includes("cursor=") ? {rows: [%s], next: null} : {rows: [%s], next: "2026-11-07 09:00:00|3"}) '
              ': {rows: [], next: null}') % (json.dumps(second), json.dumps(ROW))
    more = ('const first = $("#hi-list").innerHTML; await $("#hi-list").onclick(%s); return [first, $("#hi-list").innerHTML, calls];'
            % click("data-more", {}))
    first, html, calls = in_dom(VIEW % (json.dumps(SW1), answer, '"pc"', more))
    assert first.endswith(MORE) and "/api/history?q=pc&limit=50&cursor=2026-11-07%2009%3A00%3A00%7C3" in calls
    assert html.count("<tbody>") == 1 and "aa:bb:cc:00:00:01" in html and "aa:bb:cc:00:00:02" in html and MORE not in html
    assert html.index("aa:bb:cc:00:00:01") < html.index("aa:bb:cc:00:00:02")


def test_without_a_term_the_view_explains_and_a_short_one_names_the_server():
    empty, calls = in_dom(VIEW % (json.dumps(SW1), "{rows: [], next: null}", '""', 'return [$("#hi-list").innerHTML, calls];'))
    assert empty == EXPLAIN and not any(u.startswith("/api/history") for u in calls)
    answer = 'u.startsWith("/api/history?") ? Promise.reject(new Error(%s)) : {rows: [], next: null}' % json.dumps(HELP)
    short, tools = in_dom(VIEW % (json.dumps(SW1), answer, '"a"', 'return [$("#hi-list").innerHTML, $("#hi-tools").innerHTML];'))
    assert short == f'<div class="empty">{HELP}</div>' and tools == ""


@pytest.mark.parametrize("term, href", [("pc", "/api/history.csv?q=pc"), ("Büro 2", "/api/history.csv?q=B%C3%BCro%202")])
def test_the_csv_link_carries_the_search(term, href):
    tools = in_dom(VIEW % (json.dumps(SW1), HISTORY % json.dumps(ROW), json.dumps(term), 'return $("#hi-tools").innerHTML;'))
    assert tools == f'<a class="btn small" id="hi-csv" href="{href}" download>Als CSV</a>'


def test_a_search_without_hits_says_so_and_offers_no_csv():
    html, tools = in_dom(VIEW % (json.dumps(SW1), "{rows: [], next: null}", '"<i>pc"', 'return [$("#hi-list").innerHTML, $("#hi-tools").innerHTML];'))
    assert html == '<div class="empty">Keine Sichtungen für „&lt;i&gt;pc“.</div>' and tools == ""


@pytest.mark.parametrize("switch_id", [7, None], ids=["not-in-the-map", "deleted"])
def test_a_suspect_sighting_is_marked_and_a_gone_switch_is_text(switch_id):
    row = {**ROW, "suspect": True, "switch_id": switch_id, "switch": "SW-alt"}
    html = in_dom(VIEW % (json.dumps(SW1), HISTORY % json.dumps(row), '"pc"', 'return $("#hi-list").innerHTML;'))
    assert f"<td>5{SUSPECT}</td>" in html and "data-hsw" not in html and "<td>SW-alt</td>" in html


def test_a_port_of_a_sighting_opens_its_switch_and_port_panel():
    act = (NO_VIEWS + 'let opened = null; openPort = (s, n) => { opened = [s.id, n]; }; await $("#view").onclick(%s); '
           'await new Promise(r => setTimeout(r, 20)); return [opened, current];' % click("data-hsw", {"hsw": "1", "hport": "5"}))
    assert in_dom(VIEW % (json.dumps(SW1), HISTORY % json.dumps(ROW), '"pc"', act)) == [[1, "5"], "switches"]


def test_typing_in_the_history_field_searches_after_a_pause_and_enter_at_once():
    act = ('const f = $("#hi-q"); f.value = "aa-bb"; f.fire("input"); const a = calls.length; await new Promise(r => setTimeout(r, 400)); '
           'const b = calls.slice(a); f.value = "10.0.0.5"; f.fire("input"); f.fire("keydown", {key: "Enter"}); await new Promise(r => setTimeout(r, 20)); '
           'const c = calls.slice(a + b.length); await new Promise(r => setTimeout(r, 400)); return [b, c, calls.length - a - b.length, histTerm];')
    later, now, n, term = in_dom(VIEW % (json.dumps(SW1), HISTORY % json.dumps(ROW), '""', act))
    assert later == ["/api/history?q=aa-bb&limit=50"] and now == ["/api/history?q=10.0.0.5&limit=50"] and n == 1 and term == "10.0.0.5"


@pytest.mark.parametrize("then", ["", "pcx"], ids=["emptied", "typed-on"])
def test_a_late_answer_of_an_older_search_is_not_drawn(then):
    """A search still waiting for the server when the field is emptied, or typed on (its own search waits for the pause), draws
    nothing when it answers: the list keeps what it showed."""
    act = ('let answer; api = (m, u) => { calls.push(u); '
           'return u.startsWith("/api/history?") ? new Promise(ok => { answer = ok; }) : Promise.resolve({rows: []}); }; '
           'const f = $("#hi-q"); f.value = "pc"; f.fire("keydown", {key: "Enter"}); f.value = %s; f.fire("input"); '
           'answer({rows: [%s], next: null}); await new Promise(r => setTimeout(r, 20)); return [$("#hi-list").innerHTML, $("#hi-tools").innerHTML];'
           % (json.dumps(then), json.dumps(ROW)))
    assert in_dom(VIEW % (json.dumps(SW1), "{rows: [], next: null}", '""', act)) == [EXPLAIN, ""]


def test_the_event_filter_asks_by_group():
    act = ('$("#ev-kind").value = "drift"; $("#ev-kind").fire("change"); await new Promise(r => setTimeout(r, 20)); '
           'return [calls, histKind, $("#view").innerHTML];')
    calls, kind, view = in_dom(VIEW % (json.dumps(SW1), "{rows: [], next: null}", '""', act))
    assert calls == ["/api/events?limit=50", "/api/events?kind=drift&limit=50"] and kind == "drift"
    assert ('<select id="ev-kind" aria-label="Art der Ereignisse"><option value="">Alle</option><option value="reach">Erreichbarkeit</option>'
            '<option value="lldp">LLDP-Nachbarn</option><option value="drift">Außerhalb von SwitchView</option></select>') in view
    assert "<h2>Ereignisse</h2>" in view and "Erreichbarkeit, LLDP-Nachbarn und Änderungen außerhalb von SwitchView · neueste zuerst" in view


def test_the_event_filter_outlives_a_new_render():
    js = VIEW.replace("histTerm = %s;", 'histTerm = %s; histKind = "lldp";')
    calls, view = in_dom(js % (json.dumps(SW1), "{rows: [], next: null}", '""', 'return [calls, $("#view").innerHTML];'))
    assert calls == ["/api/events?kind=lldp&limit=50"] and '<option value="lldp" selected>' in view


def test_the_events_name_their_kind_and_a_backup_drift_offers_the_comparison():
    answer = 'u.startsWith("/api/events?") ? {rows: [%s, %s], next: 5} : {rows: [], next: null}' % (json.dumps(DRIFT), json.dumps(DOWN))
    html = in_dom(VIEW % (json.dumps(SW1), answer, '""', 'return $("#ev-list").innerHTML;'))
    assert re.findall(r"<th>([^<]*)</th>", html) == ["Zeit", "Switch", "Art", "Was"] and html.count(BDIFF) == 1 and html.endswith(MORE)
    assert "<td>Antwortet nicht</td>" in html and "SW antwortet seit 3 Abfragen nicht: &lt;Timeout&gt;" in html and "<Timeout>" not in html
    assert html.count('<td class="num time">') == 2
    empty = in_dom(VIEW % (json.dumps(SW1), "{rows: [], next: null}", '""', 'return $("#ev-list").innerHTML;'))
    assert empty == '<div class="empty">Noch keine Ereignisse.</div>'


HIST_OPTION = ('<button type="button" role="option" id="hit-%d" aria-selected="false" tabindex="-1" data-i="%d" class="hist">'
               '<span class="r1">Im Verlauf suchen</span><span class="r2">„%s“</span></button>')
NONE = '<div class="none" role="option" aria-disabled="true">Nichts gefunden. Uplinks mit vielen Geräten werden nicht durchsucht.</div>'


def test_the_search_offers_the_history_as_its_last_option():
    js = ('(async () => { ' + SEARCH + NO_VIEWS + 'const q = $("#q"); q.value = "vk"; q.fire("input"); await new Promise(r => setTimeout(r, 400)); '
          'const html = $("#results").innerHTML; q.fire("keydown", {key: "ArrowUp"}); const active = q.getAttribute("aria-activedescendant"); '
          'q.fire("keydown", {key: "Enter"}); await new Promise(r => setTimeout(r, 50)); return [html, active, histTerm, current, $("#results").hidden]; })()')
    html, active, term, view, hidden = in_dom(js)
    assert html.count('role="option"') == 2 and html.endswith(HIST_OPTION % (1, 1, "vk"))
    assert active == "hit-1" and (term, view, hidden) == ("vk", "verlauf", True)


def test_without_a_hit_the_search_still_offers_the_history():
    """Under „Nichts gefunden …“ the history entry is the only option; a click on it searches the text as typed."""
    js = ('(async () => { ' + SEARCH + NO_VIEWS + 'const q = $("#q"); q.value = " Zz<b> "; q.fire("input"); await new Promise(r => setTimeout(r, 400)); '
          'const html = $("#results").innerHTML; $("#results").fire("click", %s); await new Promise(r => setTimeout(r, 50)); '
          'return [html, searchFound.length, histTerm, current]; })()' % click("data-i", {"i": "0"}))
    assert in_dom(js) == [NONE + HIST_OPTION % (0, 0, "Zz&lt;b&gt;"), 1, "Zz<b>", "verlauf"]


def test_the_history_takes_at_most_the_100_characters_of_the_server():
    """GET /api/history takes q up to 100 characters (beyond them FastAPI's 422 is English): the field says so, the entry cuts."""
    js = ('(async () => { ' + SEARCH + NO_VIEWS + 'const q = $("#q"); q.value = "x".repeat(120); q.fire("input"); await new Promise(r => setTimeout(r, 400)); '
          'return searchFound[searchFound.length - 1].text.length; })()')
    assert in_dom(js) == 100
    view = in_dom(VIEW % (json.dumps(SW1), "{rows: [], next: null}", '""', 'return $("#view").innerHTML;'))
    assert re.search(r'<input type="search" id="hi-q"[^>]* maxlength="100"', view)


PORT5 = {"n": "5", "l": [], "d": [], "u": ["20"], "t": [], "mc": 0, "tr": "", "a": "", "pv": "20", "st": "", "mb": [], "o": True, "ad": True, "s": 1000}
PANEL5 = ('(async () => { ' + role_me("lesen") + 'MAP = {switches: [%s], links: [], vlans: {}}; const calls = []; '
          'api = async (m, u) => { calls.push(u); return %s; }; const p = %s; portIdx = {[p.n]: p}; openPort({...MAP.switches[0], ports: [p]}, p.n); %s })()')
HIST_BUTTON = ('<p class="eyebrow">Bisher an diesem Port</p><div id="dr-hist"><button class="btn small" type="button" id="dr-hist-btn">'
               'Anzeigen</button></div>')
NO_HIST = '<p class="eyebrow">Bisher an diesem Port</p><p class="note">An Trunks und bestätigten Uplinks zeichnet SwitchView keine Geräte auf.</p>'


def test_the_port_panel_loads_its_history_on_demand():
    act = ('const before = [$("#dr-body").innerHTML, calls.length]; await $("#dr-hist-btn").handlers.click[0](); '
           'return [before, calls, $("#dr-hist").innerHTML];')
    (body, n), calls, hist = in_dom(PANEL5 % (json.dumps(SW1), '{rows: [%s], next: "2026-11-07 09:00:00|3"}' % json.dumps(ROW), json.dumps(PORT5), act))
    assert HIST_BUTTON in body and body.index("Nachbar (LLDP)") < body.index(HIST_BUTTON) and n == 0
    assert calls == ["/api/history?switch_id=1&port=5&limit=20"] and "aa:bb:cc:00:00:01" in hist and "&lt;b&gt;pc&lt;/b&gt;" in hist
    assert '<div class="devs">' in hist and hist.endswith(MORE)


@pytest.mark.parametrize("port", [{"n": "Trk1", "tr": "Trk1", "mb": ["4", "5"]}, {"tr": "Trk1"}, {"up": True, "uc": True}],
                         ids=["trunk", "member", "confirmed-uplink"])
def test_a_trunk_port_says_it_keeps_no_history(port):
    body = in_dom(PANEL5 % (json.dumps(SW1), "{rows: []}", json.dumps({**PORT5, **port}), 'return $("#dr-body").innerHTML;'))
    assert NO_HIST in body and "dr-hist" not in body


def test_an_unconfirmed_uplink_keeps_its_history():
    """The access-port rule of topology.device_port: an uplink nobody confirms is a device port (its sightings are marked)."""
    row = {**ROW, "suspect": True}
    act = 'await $("#dr-hist-btn").handlers.click[0](); return [$("#dr-body").innerHTML, $("#dr-hist").innerHTML];'
    body, hist = in_dom(PANEL5 % (json.dumps(SW1), '{rows: [%s], next: null}' % json.dumps(row), json.dumps({**PORT5, "up": True, "uc": False}), act))
    assert HIST_BUTTON in body and NO_HIST not in body and "Uplink (unbestätigt)" in hist and MORE not in hist


def test_an_empty_port_history_says_so():
    act = 'await $("#dr-hist-btn").handlers.click[0](); return $("#dr-hist").innerHTML;'
    hist = in_dom(PANEL5 % (json.dumps(SW1), "{rows: [], next: null}", json.dumps(PORT5), act))
    assert hist == '<p class="note">Noch keine Geräte an diesem Port aufgezeichnet.</p>'


FINDINGS = [{"id": 1, "rule": "telnet", "label": "Telnet-Server an", "severity": "crit", "line_no": None, "line": "", "detail": "",
             "first_seen": "2026-11-07 02:30:00"},
            {"id": 2, "rule": "snmp_write_community", "label": "SNMPv2c-Community mit Schreibrecht", "severity": "warn", "line_no": 12,
             "line": 'snmp-server community "<x>" unrestricted', "detail": "Community „<x>“", "first_seen": "2026-11-07 02:30:00"}]
SWITCH = ('(async () => { ' + role_me("lesen") + 'MAP = {switches: [%s], links: [], vlans: {}}; selSwitch = 1; const calls = []; '
          'api = async (m, u) => { calls.push(u); return u.startsWith("/api/events?") ? %s : u.endsWith("/findings") ? %s : []; }; '
          'applySwFilter = () => {}; document.els[".dhead .actions"] = $("#acts"); await renderSwitchDetail(); await new Promise(r => setTimeout(r, 20)); '
          'return [$("#view").innerHTML, $("#sw-events").innerHTML, $("#sw-findings").innerHTML, calls]; })()')
EVENTS_CARD = ('<section class="card"><div class="card-h"><h2>Ereignisse</h2><span class="sub">an diesem Switch, neueste zuerst</span></div>'
               '<div id="sw-events">')


@pytest.mark.parametrize("caps, sub", [(["cli", "backup"], "aus der zuletzt gelesenen Konfiguration und den SNMP-Zugangsdaten"),
                                       (["snmp_vlan"], "aus den SNMP-Zugangsdaten (dieser Treiber hat keine Konfigurationssicherung)")])
def test_the_switch_view_shows_its_events_and_findings(caps, sub):
    sw = {**SW1, "caps": caps}
    view, events, findings, calls = in_dom(SWITCH % (json.dumps(sw), '{rows: [%s, %s], next: 5}' % (json.dumps(DRIFT), json.dumps(DOWN)),
                                                     json.dumps({"findings": FINDINGS})))
    assert "/api/events?switch_id=1&limit=10" in calls and "/api/switches/1/findings" in calls
    assert EVENTS_CARD in view and f'<h2>Sicherheitsbefunde</h2><span class="sub">{sub}</span>' in view
    assert view.index("<h2>Ereignisse</h2>") < view.index("<h2>Sicherheitsbefunde</h2>") < view.index("<h2>Verbindungen</h2>")
    assert BDIFF in events and "<td>Antwortet nicht</td>" in events and "<th>Switch</th>" not in events and events.endswith(MORE)
    assert '<tr><td><span class="pill crit">kritisch</span></td><td><b>Telnet-Server an</b></td><td class="mono">–</td></tr>' in findings
    assert ('<tr><td><span class="pill warn">prüfen</span></td><td><b>SNMPv2c-Community mit Schreibrecht</b><span class="cellnote">Community „&lt;x&gt;“'
            '</span></td><td class="mono">Zeile 12: snmp-server community &quot;&lt;x&gt;&quot; unrestricted</td></tr>') in findings


def test_the_switch_cards_draw_empty_on_an_answer_without_their_fields():
    """renderSwitchDetail's existing DOM tests answer every URL with []: the cards are empty, nothing throws."""
    _, events, findings, _ = in_dom(SWITCH % (json.dumps(SW1), "[]", "[]"))
    assert events == '<div class="empty">Noch keine Ereignisse.</div>' and findings == '<div class="empty">Keine Befunde.</div>'


def test_the_comparison_of_an_event_opens_in_the_switch_view():
    act = SWITCH.replace("return [", 'await $("#view").onclick(%s); return [$("#m-title").textContent, ' % click("data-bdiff", {"bdiff": "9"}))
    title, *_, calls = in_dom(act % (json.dumps(SW1), '{rows: [%s], next: null}' % json.dumps(DRIFT), "[]"))
    assert title == "Änderungen zur vorigen Sicherung" and calls[-1] == "/api/backups/9/diff"


BACKUPS = [{"id": 9, "taken_at": "2026-11-07 02:30:00", "sha": "x", "trigger": "nightly", "size": 2048, "outside": 1},
           {"id": 8, "taken_at": "2026-11-06 02:30:00", "sha": "y", "trigger": "manual", "size": 2048, "outside": 0},
           {"id": 7, "taken_at": "2026-11-05 02:30:00", "sha": "z", "trigger": "lesen", "size": 2048, "outside": None}]
SWITCH_ROW = {"id": 1, "name": "SW", "driver": "procurve", "caps": ["cli", "backup"], "ssh_pass_set": True}
DIFF_TEXT = '+ interface 2 name "Fremd"'


def test_an_outside_backup_is_marked_and_its_event_opens_the_comparison():
    js = ('(async () => { ' + role_me("lesen") + 'const calls = []; api = async (m, u) => { calls.push(u); return u === "/api/switches" ? [%s] '
          ': u.endsWith("/backups") ? %s : u.endsWith("/diff") ? %s : []; }; $("#b-sw").value = "1"; await renderBackups(); '
          'await new Promise(r => setTimeout(r, 20)); const list = $("#b-list").innerHTML; '
          'await $("#b-list").handlers.click[0](%s); return [list, $("#m-title").textContent, $("#m-body").innerHTML, calls]; })()'
          ) % (json.dumps(SWITCH_ROW), json.dumps(BACKUPS), json.dumps(DIFF_TEXT), click("data-diff", {"diff": "9"}))
    rows, title, body, calls = in_dom(js)
    assert rows.count("außerhalb von SwitchView") == 1 and '<td>nächtlich <span class="pill warn">außerhalb von SwitchView</span></td>' in rows
    assert "<td>von Hand</td>" in rows and "<td>gelesen</td>" in rows
    assert calls[-1] == "/api/backups/9/diff" and title == "Änderungen zur vorigen Sicherung"
    assert body == '<pre class="code"><span class="add">+ interface 2 name &quot;Fremd&quot;</span></pre>'
    act = ('const list = $("#ev-list").innerHTML; await $("#view").onclick(%s); return [list, calls, $("#m-title").textContent, $("#m-body").innerHTML];'
           % click("data-bdiff", {"bdiff": "9"}))
    answer = ('u.startsWith("/api/events?") ? {rows: [%s], next: null} : u.endsWith("/diff") ? %s : {rows: []}'
              % (json.dumps(DRIFT), json.dumps(DIFF_TEXT)))
    events, calls, title, shown = in_dom(VIEW % (json.dumps(SW1), answer, '""', act))
    assert BDIFF in events and calls[-1] == "/api/backups/9/diff" and (title, shown) == ("Änderungen zur vorigen Sicherung", body)


def test_a_comparison_that_fails_is_a_toast():
    js = ('(async () => { const shown = []; toast = m => shown.push(m); api = async () => { throw new Error("Sicherung nicht gefunden"); }; '
          'await openBackupDiff(9); return [shown, $("#modal").hidden]; })()')
    assert in_dom(js) == [["Sicherung nicht gefunden"], True]


NETMAP = {"switches": [{"id": 1, "k": "SW", "zone": "", "host": "10.0.0.1", "ok": True, "error": "", "ports": [], "caps": []}], "links": [], "vlans": {}}
OVERVIEW = ('(async () => { ' + role_me("lesen") + 'const calls = []; api = async (m, u) => { calls.push(u); return u === "/api/netmap" ? %s '
            ': u === "/api/compliance" ? %s : u.startsWith("/api/events?") ? %s : {}; }; await renderOverview(); return [$("#view").innerHTML, calls]; })()')
DRIFT_PORT = {**DRIFT, "id": 7, "kind": "drift_port", "label": "Port außerhalb von SwitchView geändert", "port": "5",
              "text": "Port 5 außerhalb von SwitchView geändert: PVID 10 → 20", "detail": {"changes": {"pvid": ["10", "20"]}}}
GROUP = '<span class="pill %s">%s</span><span class="t">%s</span><span class="cnt">%d</span>'
ISSUE = '<div class="issue"><span class="t">%s</span><span class="d">%s</span>'


def test_the_overview_counts_findings_and_outside_changes():
    comp = {"total": 3, "crit": 1, "switches": [{"id": 1, "name": "SW", "count": 3, "crit": 1}]}
    html, calls = in_dom(OVERVIEW % (json.dumps(NETMAP), json.dumps(comp), json.dumps({"rows": [DRIFT_PORT], "next": None})))
    assert GROUP % ("crit", "Fehler", "Sicherheitsbefunde", 1) in html and '<span class="d">3 Befunde an 1 Switch</span>' in html
    assert ISSUE % ("SW", "3 Befunde, davon 1 kritisch") in html
    assert GROUP % ("warn", "Prüfen", "Änderungen außerhalb von SwitchView", 1) in html and '<span class="d">1 in den letzten 7 Tagen</span>' in html
    assert ISSUE % ("SW", "Port 5 außerhalb von SwitchView geändert: PVID 10 → 20") in html
    assert '<span class="k">Zu prüfen</span><span class="v">2</span>' in html and "Nichts auffällig." not in html
    assert html.index("Sicherheitsbefunde") < html.index("Änderungen außerhalb von SwitchView")
    asked = [u for u in calls if u.startswith("/api/events?")]
    assert "/api/compliance" in calls and len(asked) == 1 and re.fullmatch(r"/api/events\?kind=drift&since=[^&]+&limit=20", asked[0])
    since = datetime.fromisoformat(unquote(asked[0].split("since=")[1].split("&")[0]).replace("Z", "+00:00"))
    assert abs(since - (datetime.now(timezone.utc) - timedelta(days=7))) < timedelta(minutes=2)


@pytest.mark.parametrize("comp, sev, item, total", [
    ({"total": 1, "crit": 0, "switches": [{"id": 1, "name": "SW", "count": 1, "crit": 0}]}, ("warn", "Prüfen"), "1 Befund", "1 Befund an 1 Switch"),
    ({"total": 5, "crit": 0, "switches": [{"id": 1, "name": "SW", "count": 2, "crit": 0}, {"id": 2, "name": "B", "count": 3, "crit": 0}]},
     ("warn", "Prüfen"), "2 Befunde", "5 Befunde an 2 Switches")], ids=["singular", "plural"])
def test_the_findings_group_counts_in_singular_and_plural(comp, sev, item, total):
    html, _ = in_dom(OVERVIEW % (json.dumps(NETMAP), json.dumps(comp), '{rows: [], next: null}'))
    assert GROUP % (*sev, "Sicherheitsbefunde", len(comp["switches"])) in html and f'<span class="d">{total}</span>' in html
    assert ISSUE % ("SW", item) in html and "Änderungen außerhalb von SwitchView" not in html


def test_more_than_twenty_outside_changes_say_so():
    rows = [{**DRIFT_PORT, "id": 100 - i} for i in range(20)]
    html, _ = in_dom(OVERVIEW % (json.dumps(NETMAP), '{total: 0, crit: 0, switches: []}', json.dumps({"rows": rows, "next": 81})))
    assert GROUP % ("warn", "Prüfen", "Änderungen außerhalb von SwitchView", 20) in html and '<span class="d">mehr als 20 in den letzten 7 Tagen</span>' in html
    assert "Sicherheitsbefunde" not in html


@pytest.mark.parametrize("answer", ['Promise.reject(new Error("x"))', "({})", "[]"], ids=["rejected", "no-fields", "list"])
def test_the_overview_still_draws_when_the_extras_fail(answer):
    html, calls = in_dom(OVERVIEW % (json.dumps(NETMAP), answer, answer))
    assert "Nichts auffällig." in html and "Sicherheitsbefunde" not in html and "außerhalb von SwitchView" not in html
    assert '<span class="k">Zu prüfen</span><span class="v">0</span>' in html and "/api/compliance" in calls


def test_the_history_tab_follows_the_devices_and_its_script_the_approvals():
    tabs = re.findall(r'<button type="button" data-view="(\w+)"', INDEX)
    assert tabs[tabs.index("devices") + 1] == "verlauf" and '<button type="button" data-view="verlauf">Verlauf</button>' in INDEX
    scripts = re.findall(r'<script src="/static/([\w.\-]+)"></script>', INDEX)
    # Task 10 loads sv-alerts.js between them (its cards, then the router)
    assert scripts[scripts.index("sv-approvals.js") + 1:] == ["sv-history.js", "sv-alerts.js", "sv-main.js"]
    assert in_dom('[VIEWS.verlauf === renderVerlauf, SVLogic.parseHash("#verlauf").view]') == [True, "verlauf"]


def test_the_new_css_rules_take_only_existing_tokens():
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    # Browser check: "Als CSV" is the first link with the look of a button; without the rule it was blue and underlined
    assert ".results .hist {" in css and "#dr-hist .dev" in css and "a.btn { color: var(--fg); text-decoration: none; }" in css
    # Browser check: the port history stood flush against „Gelernte Geräte“ below it
    assert "#dr-hist { margin-bottom: 14px; }" in css and "#dr-body .note + .eyebrow { margin-top: 14px; }" in css
    # Browser check: in the switch view's events table the time wrapped onto two lines
    assert "td.time { white-space: nowrap; }" in css
    new = re.findall(r"^(?:\.results \.hist|#dr-hist|a\.btn)[^{]*\{[^}]*\}", css, re.M)
    tokens = {t for rule in new for t in re.findall(r"var\((--[\w-]+)\)", rule)}
    assert new and tokens <= {"--surface", "--surface-2", "--surface-3", "--border", "--border-strong", "--fg", "--fg-2", "--muted", "--accent",
                              "--accent-bg", "--warn", "--warn-bg", "--crit", "--crit-bg", "--r"}
