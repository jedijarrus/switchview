"""Phase 4a Task 9, moved in Phase 4b Task 1: the four-eyes principle in the UI, against the recording DOM stub of
tests/test_frontend_dom.py (in_dom and its constants are imported from there). The preview requests an expert-mode change that needs
an approval, the tab "Freigaben" counts the open requests, the view lists them with what the role and the owner may do, the review
shows a fresh preview and approves only the requester's, and an Admin switches the principle in the settings. Skipped without node."""
import json
import re
import shutil

import pytest
from test_frontend_dom import LIST, NO_VIEWS, PANEL, ROWS, SETTINGS_ANSWER, SNMP_PLAN, STATIC, body_of, in_dom, role_me, trk

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


# Phase 4a Task 9: the four-eyes principle in the UI - the preview requests an expert-mode change that needs an approval, the tab
# "Freigaben" counts the open requests, the view lists them with what the role and the owner may do, the review shows a fresh
# preview and approves only the requester's, and an Admin switches the principle in the settings
APPROVAL_PLAN = {**SNMP_PLAN, "approval": True}


def test_a_preview_that_needs_approval_requests_it():
    js = ('(async () => { const calls = []; api = async (m, u, b) => { calls.push([m, u, b]); return u.endsWith("/plan") ? %s : {id: 9}; }; '
          'refreshApprovals = async () => {}; '
          'await previewChange({id: 1, k: "SW", caps: []}, {mode: "ports", ports: ["2"], change: {untagged: "20"}, expert: true}); '
          'const labels = $("#m-foot").children.map(b => b.textContent); const body = $("#m-body").innerHTML; '
          'await $("#m-foot").children[$("#m-foot").children.length - 1].handlers.click[0](); '
          'return [labels.slice(-1), body.includes("<b>Vier-Augen-Prinzip:</b>"), calls[1], $("#toasts").children.map(t => t.textContent)]; })()'
          ) % json.dumps(APPROVAL_PLAN)
    assert in_dom(js) == [["Freigabe anfordern"], True, ["POST", "/api/approvals", {"kind": "port_change", "switch_id": 1, "plan": {
        "mode": "ports", "ports": ["2"], "change": {"untagged": "20"}, "expert": True, "mechanism": "snmp", "token": "t"}}],
        ["Freigabe angefordert (Anfrage #9)"]]


# Beyond the brief: the banner's text, the dialog closes, the count is asked again (and the list redrawn when it is shown: "Neu
# anfordern" starts there); a refused request names the server's reason and frees the button; a plan that cannot run requests
# nothing, and without approval the preview runs as before
REQUEST = ('(async () => { const calls = []; let n = 0, drawn = 0; refreshApprovals = async () => { n++; }; renderApprovals = async () => { drawn++; }; %s '
           'api = async (m, u, b) => { calls.push([m, u]); if (u.endsWith("/plan")) return %s; %s }; '
           'await previewChange({id: 1, k: "SW", caps: []}, {mode: "ports", ports: ["2"], change: {untagged: "20"}, expert: true}); '
           'const labels = $("#m-foot").children.map(b => b.textContent), body = $("#m-body").innerHTML, b = $("#m-foot").children[labels.length - 1]; '
           'if (labels.includes("Freigabe anfordern")) await b.handlers.click[0](); '
           'return [labels, body, b.disabled, $("#modal").hidden, $("#toasts").children.map(t => t.textContent), n, drawn, calls.map(c => c[1])]; })()')
FOUR_EYES_BANNER = ('<div class="banner warn"><span><b>Vier-Augen-Prinzip:</b> Diese Änderung im Expertenmodus wird erst ausgeführt, wenn eine '
                    'zweite Person mit der Rolle „Freigeben“ sie freigibt. Niemand kann die eigene Anfrage freigeben.</span></div>')


@pytest.mark.parametrize("where, drawn", [('current = "switches";', 0), ('current = "approvals";', 1)], ids=["switch-view", "approvals-view"])
def test_a_requested_change_closes_the_preview_and_counts_again(where, drawn):
    labels, body, disabled, hidden, toasts, n, got, calls = in_dom(REQUEST % (where, json.dumps(APPROVAL_PLAN), "return {id: 9};"))
    assert labels == ["Abbrechen", "Freigabe anfordern"] and body.startswith(FOUR_EYES_BANNER) and "Danach liest SwitchView" in body
    assert (hidden, toasts, n, got, calls) == (True, ["Freigabe angefordert (Anfrage #9)"], 1, drawn, ["/api/switches/1/plan", "/api/approvals"])


def test_a_refused_request_names_the_reason_and_frees_the_button():
    labels, body, disabled, hidden, toasts, n, drawn, calls = in_dom(REQUEST % ("", json.dumps(APPROVAL_PLAN), 'throw new Error("Keine Berechtigung: x");'))
    assert (disabled, hidden, toasts, n, calls) == (False, False, ["Keine Berechtigung: x"], 0, ["/api/switches/1/plan", "/api/approvals"])


@pytest.mark.parametrize("plan, want", [({**APPROVAL_PLAN, "commands": []}, ["Abbrechen"]), ({**APPROVAL_PLAN, "approval": False}, ["Abbrechen", "Ausführen"])],
                         ids=["nothing-to-run", "no-approval"])
def test_only_a_runnable_change_that_needs_approval_is_requested(plan, want):
    labels, body, *_ = in_dom(REQUEST % ("", json.dumps(plan), "return {id: 9};"))
    assert labels == want and "Vier-Augen-Prinzip" not in body


@pytest.mark.parametrize("me, rows, hidden, count", [
    ({"role": "freigeben", "four_eyes": False}, [], True, None), ({"role": "freigeben", "four_eyes": True}, [], False, None),
    ({"role": "freigeben", "four_eyes": True}, [{"status": "open", "own": False}], False, "1"),
    ({"role": "aendern", "four_eyes": False}, [{"status": "open", "own": True}], False, "1")])
def test_the_tab_shows_the_open_requests(me, rows, hidden, count):
    js = ('(async () => { ME = %s; api = async () => %s; await refreshApprovals(); '
          'return [$("#tab-appr").hidden, $("#appr-n").hidden ? null : $("#appr-n").textContent]; })()') % (json.dumps(me), json.dumps(rows))
    assert in_dom(js) == [hidden, count]


# Beyond the brief: the tab names the count for a screen reader (the pill alone reads as a bare number), asks once for the open
# ones, asks nothing without a signed-in user, and a failed request leaves the tab as it was without a message
@pytest.mark.parametrize("rows, label", [([{"status": "open", "own": False}, {"status": "open", "own": False}], "Freigaben, 2 offen"), ([], "Freigaben")])
def test_the_tab_names_its_count_for_screen_readers(rows, label):
    js = ('(async () => { const calls = []; ME = {role: "freigeben", zones: null, four_eyes: true}; api = async (m, u) => { calls.push(u); return %s; }; '
          'await refreshApprovals(); return [$("#tab-appr").getAttribute("aria-label"), calls]; })()') % json.dumps(rows)
    assert in_dom(js) == [label, ["/api/approvals?status=open"]]


@pytest.mark.parametrize("before, answer", [("ME = null;", "[]"), ('ME = {role: "freigeben", four_eyes: true};', 'Promise.reject(new Error("weg"))')],
                         ids=["signed-out", "error"])
def test_the_tab_stays_as_it_is_without_a_user_or_an_answer(before, answer):
    js = ('(async () => { let n = 0; %s api = () => { n++; return %s; }; await refreshApprovals(); '
          'return [n, $("#tab-appr").hidden, $("#appr-n").hidden, $("#toasts").children.length]; })()') % (before, answer)
    assert in_dom(js) == [0 if before == "ME = null;" else 1, True, True, 0]


def test_the_view_and_every_navigation_count_the_open_requests():
    """VIEWS knows the view; go() asks for the count each time (not awaited, never by timer: T9-a), start() through its go()."""
    js = ('(async () => { const isView = VIEWS.approvals === renderApprovals; ' + NO_VIEWS + 'const calls = []; '
          'api = async (m, u) => { calls.push(u); return u === "/api/auth/me" ? {name: "x", role: "aendern", zones: null, four_eyes: true} : []; }; '
          'await start(); await new Promise(r => setTimeout(r, 0)); const a = calls.slice(); go("vlans"); go("audit"); '
          'return [isView, a, calls.slice(a.length)]; })()')
    assert in_dom(js) == [True, ["/api/auth/me", "/api/approvals?status=open"], ["/api/approvals?status=open"] * 2]


A = {"id": 4, "kind": "port_change", "kind_label": "Port-Änderung im Expertenmodus", "switch_id": 1, "switch_name": "SW", "switch_zone": "",
     "summary": "Port 6: VLAN 20", "status": "open", "requested_by": "anna", "requester_name": "Anna", "requester_role": "aendern",
     "requested_at": "2026-11-07T08:00:00+00:00",
     "expires_at": "2026-11-08T08:00:00+00:00", "decided_by": None, "comment": None, "reason": None, "change_id": None}


@pytest.mark.parametrize("role, own, status, buttons", [
    ("freigeben", False, "open", ["data-ar", "data-ad"]), ("freigeben", True, "open", ["data-aw", "data-ad"]), ("aendern", False, "open", ["data-ad"]),
    ("aendern", True, "stale", ["data-an", "data-ad"]), ("admin", False, "approved", ["data-ad"])])
def test_the_list_offers_what_the_role_and_the_owner_may(role, own, status, buttons):
    js = ('(async () => { ME = {role: %s, zones: null, four_eyes: true}; api = async () => [%s]; await renderApprovals(); '
          'return $("#view").innerHTML; })()') % (json.dumps(role), json.dumps({**A, "own": own, "status": status}))
    html = in_dom(js)
    assert [b for b in ("data-ar", "data-aw", "data-an", "data-ad") if f'{b}="4"' in html] == buttons


DRAW = 'await renderApprovals(); return $("#view").innerHTML; })()'


# Beyond the brief: "Prüfen" only at a switch of the reviewer's zones (the empty zone too), "Neu anfordern" for each of the three
# ends a requester can start again from, and nothing for an own request withdrawn or approved
@pytest.mark.parametrize("zones, zone, offered", [(["EK"], "VK", False), (["VK"], "VK", True), ([""], "", True), (["EK"], "", False)])
def test_review_is_offered_only_in_the_reviewers_zones(zones, zone, offered):
    js = ('(async () => { ME = {role: "freigeben", zones: %s, four_eyes: true}; api = async () => [%s]; ' + DRAW) % (
        json.dumps(zones), json.dumps({**A, "own": False, "switch_zone": zone}))
    assert ('data-ar="4"' in in_dom(js)) == offered


@pytest.mark.parametrize("own, status, again", [(True, "stale", True), (True, "expired", True), (True, "rejected", True), (True, "withdrawn", False),
                                             (True, "approved", False), (True, "open", False), (False, "stale", False)])
def test_an_own_request_is_offered_again_after_it_ended_without_running(own, status, again):
    js = ('(async () => { ME = {role: "aendern", zones: null, four_eyes: true}; api = async () => [%s]; ' + DRAW) % json.dumps(
        {**A, "own": own, "status": status})
    assert ('data-an="4">Neu anfordern</button>' in in_dom(js)) == again


# Final review: "Zurückziehen" needs what the withdraw route needs (Ändern), "Neu anfordern" what the /plan of its change needs
# (Ändern, the switch's zone, expert mode: Freigeben, or Ändern with four eyes on) - someone demoted, a zone no longer covering the
# switch or four eyes switched off leave no button that ends in a 403 (T8-a)
@pytest.mark.parametrize("role, zones, four, status, button, offered", [
    ("lesen", None, True, "open", "data-aw", False), ("aendern", ["VK"], False, "open", "data-aw", True),
    ("lesen", None, True, "stale", "data-an", False), ("aendern", ["VK"], True, "stale", "data-an", False),
    ("aendern", ["EK"], True, "stale", "data-an", True), ("aendern", None, False, "stale", "data-an", False),
    ("freigeben", None, False, "stale", "data-an", True)])
def test_withdraw_and_ask_again_hold_the_role_and_the_zone(role, zones, four, status, button, offered):
    js = ('(async () => { ME = {role: %s, zones: %s, four_eyes: %s}; api = async () => [%s]; ' + DRAW) % (
        json.dumps(role), json.dumps(zones), json.dumps(four), json.dumps({**A, "own": True, "status": status, "switch_zone": "EK"}))
    assert (f'{button}="4"' in in_dom(js)) == offered


# Beyond the brief: the card says whether the principle is on, why a role below Freigeben does not review, and each row names the
# requester with the role, the change with its kind and the status with the expiry of an open one (escaped)
@pytest.mark.parametrize("role, four, sentence, gate", [
    # (Phase 4c, Task 12: since Task 8 every bulk change needs the approval as well, the sentence names both)
    ("aendern", True, "Vier-Augen-Prinzip an: Änderungen im Expertenmodus und Sammeländerungen werden erst nach der Freigabe durch eine "
                      "zweite Person mit der Rolle „Freigeben“ ausgeführt.", True),
    ("freigeben", False, "Vier-Augen-Prinzip aus: offene Anfragen lassen sich weiter prüfen, ablehnen oder zurückziehen.", False)])
def test_the_view_says_whether_four_eyes_are_on_and_names_each_request(role, four, sentence, gate):
    rows = [{**A, "own": True},
            {**A, "id": 3, "own": False, "status": "rejected", "requester_name": "<x>", "requester_role": "freigeben", "switch_name": "SW-<2>"}]
    js = ('(async () => { ME = {role: %s, zones: null, four_eyes: %s}; api = async () => %s; ' + DRAW) % (json.dumps(role), json.dumps(four), json.dumps(rows))
    html = in_dom(js)
    assert "<h2>Freigaben</h2>" in html and sentence in html
    assert ('<p class="note gate">Anfragen prüfen und freigeben braucht die Rolle „Freigeben“.</p>' in html) == gate
    assert "".join(re.findall(r"<th>([^<]*)</th>", html)) == "#AngefordertvonSwitchÄnderungStatus"
    assert 'Anna<span class="cellnote">Ändern</span>' in html and '&lt;x&gt;<span class="cellnote">Freigeben</span>' in html and "SW-&lt;2&gt;" in html
    assert 'Port 6: VLAN 20<span class="cellnote">Port-Änderung im Expertenmodus</span>' in html
    assert '<span class="pill warn">offen</span><span class="cellnote">läuft ab ' in html and '<span class="pill crit">abgelehnt</span></td>' in html


def test_an_empty_list_and_a_failed_one_say_so():
    empty = in_dom('(async () => { ME = {role: "aendern", zones: null, four_eyes: true}; api = async () => []; ' + DRAW)
    failed = in_dom('(async () => { ME = {role: "aendern", zones: null}; api = async () => { throw new Error("weg"); }; ' + DRAW)
    assert '<div class="empty">Keine Anfragen.</div>' in empty and "<table" not in empty
    assert failed == '<div class="card"><div class="empty">weg</div></div>'


# The clicks of the list: the view's onclick with a target whose closest() names the button; DIALOG reads the dialog shown
DIALOG = '[$("#m-title").textContent, $("#m-body").innerHTML, $("#m-foot").children.map(b => b.textContent)]'
VIEW_CLICK = ('(async () => { ME = {name: "Anna", role: "aendern", zones: null, four_eyes: true}; const calls = []; let n = 0; '
              'refreshApprovals = async () => { n++; }; '
              'api = async (m, u, b) => { calls.push([m, u]); return %s; }; current = "approvals"; await renderApprovals(); '
              'const click = k => $("#view").onclick({target: {closest: s => s === "[data-" + k + "]" ? {dataset: {[k]: "4"}} : null}}); %s })()')
LIST_ANSWER = 'u.startsWith("/api/approvals?") ? [%s] : u === "/api/approvals/4" ? %s : u === "/api/netmap" ? %s : {ok: true}'
NETMAP_SW = {"switches": [{"id": 1, "k": "SW", "caps": []}], "links": [], "vlans": {}}
PAYLOAD = {"mode": "ports", "ports": ["6"], "change": {"untagged": "20"}, "expert": True}
FULL = {**A, "own": True, "payload": PAYLOAD, "preview": {"commands": ["Port 6: VLAN ungetaggt 1 → 20"], "mechanism": "snmp", "token": "t"}}


def view_click(act, row=None, full=None):
    return in_dom(VIEW_CLICK % (LIST_ANSWER % (json.dumps(row or {**A, "own": True}), json.dumps(full or FULL), json.dumps(NETMAP_SW)), act))


@pytest.mark.parametrize("button, posted", [(1, True), (0, False)], ids=["confirmed", "cancelled"])
def test_withdraw_asks_first_then_redraws_and_counts(button, posted):
    act = ('const p = click("aw"); const asked = [$("#m-title").textContent, $("#m-body").innerHTML, $("#m-foot").children.map(b => b.textContent)]; '
           '$("#m-foot").children[%d].handlers.click[0](); await p; return [asked, calls, $("#toasts").children.map(t => t.textContent), n]; ') % button
    asked, calls, toasts, n = view_click(act)
    assert asked == ["Anfrage zurückziehen", '<p style="margin:0">Anfrage #4 „Port 6: VLAN 20“ zurückziehen? Danach kann sie niemand mehr freigeben.</p>',
                     ["Abbrechen", "Zurückziehen"]]
    listed = ["GET", "/api/approvals?status=all&limit=100"]
    assert (calls, toasts, n) == (([listed, ["POST", "/api/approvals/4/withdraw"], listed], ["Zurückgezogen"], 1) if posted else ([listed], [], 0))


@pytest.mark.parametrize("map_before, read", [("MAP = null;", True),
                                              ("MAP = %s;" % json.dumps({**NETMAP_SW, "switches": [{"id": 1, "k": "SW-alt", "caps": []}]}), False)],
                         ids=["map-loaded", "map-there"])
def test_request_again_opens_the_preview_of_the_stored_change(map_before, read):
    act = map_before + 'let got = null; previewChange = (s, p) => { got = [s.id, s.k, p]; }; await click("an"); return [got, calls.map(c => c[1])];'
    got, calls = view_click(act, row={**A, "own": True, "status": "stale"}, full={**FULL, "status": "stale"})
    assert got == [1, "SW" if read else "SW-alt", PAYLOAD]
    assert calls == ["/api/approvals?status=all&limit=100", "/api/approvals/4"] + (["/api/netmap"] if read else [])


@pytest.mark.parametrize("full, said", [
    ({**FULL, "own": False, "status": "approved", "decided_by": "ben", "comment": "passt <so>", "change_id": 12},
     ["<dt>Status</dt><dd><span class=\"pill ok\">freigegeben</span></dd>", "<dt>Prüfer</dt><dd>ben</dd>", "<dt>Kommentar</dt><dd>passt &lt;so&gt;</dd>",
      "<dt>Änderung</dt><dd>#12</dd>", "<dt>Grund</dt><dd>–</dd>"]),
    ({**FULL, "status": "stale", "decided_by": "ben", "reason": "Nicht ausführbar: 6: belegt"},
     ["<span class=\"pill neutral\">veraltet</span>", "<dt>Grund</dt><dd>Nicht ausführbar: 6: belegt</dd>", "<dt>Änderung</dt><dd>–</dd>"]),
    ({**FULL, "status": "open"}, ["<dt>Prüfer</dt><dd>–</dd>", "<dt>Kommentar</dt><dd>–</dd>", "läuft ab "]),
    ({**FULL, "status": "withdrawn", "decided_by": "anna"}, ["<span class=\"pill neutral\">zurückgezogen</span>", "<dt>Prüfer</dt><dd>–</dd>"])],
    ids=["approved", "stale", "open", "withdrawn-by-its-requester"])
def test_details_show_the_request_with_the_requesters_preview(full, said):
    title, body, foot = view_click('await click("ad"); return ' + DIALOG + ';',
                                   full=full)
    assert title == "Anfrage #4" and foot == ["Schließen"] and "<b>Port 6: VLAN 20</b>" in body and "Port-Änderung im Expertenmodus" in body
    assert "<dt>Angefordert von</dt><dd>Anna (Ändern) · " in body and '<pre class="code">Port 6: VLAN ungetaggt 1 → 20</pre>' in body
    assert all(s in body for s in said), body


REVIEW_A = {**A, "own": False, "payload": {}, "preview": {"commands": ["alt"], "token": "t"}}


@pytest.mark.parametrize("matches, approve", [(True, True), (False, False)])
def test_the_review_offers_approval_only_for_the_requesters_preview(matches, approve):
    js = ('(async () => { MAP = {switches: [{id: 1, k: "SW", caps: []}], links: [], vlans: {}}; ME = {role: "freigeben", zones: null}; const calls = []; '
          'api = async (m, u, b) => { calls.push([u, b]); return u.endsWith("/preview") ? %s : u.endsWith("/approve") ? {id: 12, approval: 4} : %s; }; '
          'let ran = null; runProgress = (s, id) => { ran = id; }; refreshApprovals = async () => {}; await reviewApproval(4); '
          'const labels = $("#m-foot").children.map(b => b.textContent); const body = $("#m-body").innerHTML; $("#ap-comment").value = "passt"; '
          'if (labels.includes("Freigeben und ausführen")) await $("#m-foot").children[$("#m-foot").children.length - 1].handlers.click[0](); '
          'return [labels.slice(-1)[0], body.includes("Freigeben geht nicht"), ran, calls.slice(-1)[0]]; })()') % (
        json.dumps({**SNMP_PLAN, "matches": matches}), json.dumps(REVIEW_A))
    label, said, ran, last = in_dom(js)
    assert (label == "Freigeben und ausführen", said, ran) == (approve, not matches, 12 if approve else None)
    if approve:
        assert last == ["/api/approvals/4/approve", {"token": "t", "comment": "passt"}]


# Beyond the brief: the review's dialog and body, rejecting, a refused approval, a failed preview, a dialog closed while the switch
# is read, and the map read when the view was opened directly (#approvals)
REVIEW = ('(async () => { %s ME = {role: "freigeben", zones: null}; const calls = []; let n = 0, drawn = 0, ran = null; '
          'refreshApprovals = async () => { n++; }; renderApprovals = async () => { drawn++; }; runProgress = (s, id) => { ran = [s.k, id]; }; '
          'api = async (m, u, b) => { calls.push([m, u, b]); %s }; %s })()')
SW_MAP = 'MAP = {switches: [{id: 1, k: "SW", caps: []}], links: [], vlans: {}};'


def review(answers, act, map_before=SW_MAP):
    return in_dom(REVIEW % (map_before, answers, act))


def answers(preview="return %s;" % json.dumps({**SNMP_PLAN, "matches": True}), decide="return {id: 12, approval: 4};"):
    return ('if (u.endsWith("/preview")) { %s } if (u.endsWith("/approve") || u.endsWith("/reject")) { %s } '
            'if (u === "/api/netmap") return {switches: [{id: 1, k: "SW-NETMAP", caps: []}], links: [], vlans: {}}; return %s;') % (
        preview, decide, json.dumps(REVIEW_A))


@pytest.mark.parametrize("matches", [True, False])
def test_the_review_shows_who_asked_the_fresh_preview_and_a_comment_field(matches):
    title, body, labels = review(answers(preview="return %s;" % json.dumps({**SNMP_PLAN, "matches": matches})),
                                 'await reviewApproval(4); return ' + DIALOG + ';')
    assert title == "Anfrage #4 prüfen" and body.startswith('<p class="note" style="margin:0">Angefordert von <b>Anna</b> (Ändern) · ')
    assert "<b>Port 2: VLAN 20</b> <span class=\"muted\">· SW</span>" in body and '<pre class="code">Port 2: VLAN ungetaggt 99 → 20</pre>' in body
    assert body.endswith('<label class="field"><span>Kommentar (optional)</span><textarea id="ap-comment" rows="2" maxlength="500"></textarea></label>')
    stale = ('<div class="error"><b>Freigeben geht nicht:</b> Der Switch hat sich seit der Anfrage geändert, diese Vorschau weicht von der des '
             'Antragstellers ab. Ablehnen oder neu anfordern lassen.</div>')
    theirs = '<details class="adv"><summary>Vorschau des Antragstellers</summary><pre class="code">alt</pre></details>'
    assert (stale in body, theirs in body) == (not matches, not matches) and "Vier-Augen-Prinzip:" not in body
    assert labels == ["Abbrechen", "Ablehnen"] + (["Freigeben und ausführen"] if matches else [])


@pytest.mark.parametrize("where, drawn", [('current = "approvals";', 1), ('current = "overview";', 0)], ids=["approvals-view", "other-view"])
def test_reject_sends_the_comment_closes_and_counts_again(where, drawn):
    act = (where + 'await reviewApproval(4); $("#ap-comment").value = "nein"; '
           'await $("#m-foot").children.find(b => b.textContent === "Ablehnen").handlers.click[0](); '
           'return [calls.slice(-1)[0], $("#modal").hidden, $("#toasts").children.map(t => t.textContent), n, drawn];')
    assert review(answers(decide="return {ok: true};"), act) == [["POST", "/api/approvals/4/reject", {"comment": "nein"}], True, ["Abgelehnt"], 1, drawn]


@pytest.mark.parametrize("label", ["Ablehnen", "Freigeben und ausführen"])
def test_a_refused_decision_names_the_reason_and_frees_its_button(label):
    act = ('current = "approvals"; await reviewApproval(4); const b = $("#m-foot").children.find(x => x.textContent === %s); await b.handlers.click[0](); '
           'return [b.disabled, $("#modal").hidden, $("#toasts").children.map(t => t.textContent), ran, n, drawn];') % json.dumps(label)
    assert review(answers(decide='throw new Error("Anfrage #4 ist schon entschieden");'), act) == [
        False, False, ["Anfrage #4 ist schon entschieden"], None, 1, 1]


def test_an_approval_shows_the_progress_of_its_change_and_counts_again():
    act = ('current = "approvals"; await reviewApproval(4); '
           'await $("#m-foot").children.find(x => x.textContent === "Freigeben und ausführen").handlers.click[0](); '
           'return [ran, n, drawn, calls.slice(-1)[0]];')
    assert review(answers(), act) == [["SW", 12], 1, 1, ["POST", "/api/approvals/4/approve", {"token": "t", "comment": ""}]]


# Beyond the brief: the emergency login may reject but never approves (T7-e, 403 at the server): its review says so instead of
# offering the button
@pytest.mark.parametrize("method, approve", [("local", False), ("entra", True)])
def test_the_emergency_login_is_not_offered_to_approve(method, approve):
    act = ('ME.method = %s; await reviewApproval(4); return [$("#m-body").innerHTML, $("#m-foot").children.map(b => b.textContent)];') % json.dumps(method)
    body, labels = review(answers(), act)
    note = '<p class="note gate">Der Notfall-Login gibt keine Anfrage frei: er ist kein persönliches Konto.</p>'
    assert (labels, note in body) == ((["Abbrechen", "Ablehnen", "Freigeben und ausführen"], False) if approve else (["Abbrechen", "Ablehnen"], True))


COMMENT_FIELD = '<label class="field"><span>Kommentar (optional)</span><textarea id="ap-comment" rows="2" maxlength="500"></textarea></label>'


# Task 10 (browser check): a fresh preview that fails (the switch not readable, disabled, a write way that does not go) says why; an
# open request can still be rejected there - rejecting needs no preview, and the request would otherwise wait for its expiry. A
# request that could not be read, or one that is no longer open, only closes
@pytest.mark.parametrize("answer, reject", [
    (answers(preview='throw new Error("Switch ist deaktiviert");'), True),
    ('if (u === "/api/approvals/4") throw new Error("Switch ist deaktiviert"); return {};', False),
    ('if (u.endsWith("/preview")) throw new Error("Switch ist deaktiviert"); return %s;' % json.dumps({**REVIEW_A, "status": "approved"}), False)],
    ids=["open", "unread", "decided"])
def test_a_failed_review_says_why(answer, reject):
    title, body, labels = review(answer, 'await reviewApproval(4); return ' + DIALOG + ';')
    assert (title, body, labels) == ("Anfrage #4 prüfen", '<div class="error">Switch ist deaktiviert</div>' + (COMMENT_FIELD if reject else ""),
                                     ["Schließen"] + (["Ablehnen"] if reject else []))


def test_a_failed_review_rejects_with_the_comment_and_counts_again():
    act = ('current = "approvals"; await reviewApproval(4); $("#ap-comment").value = "Switch weg"; '
           'await $("#m-foot").children.find(b => b.textContent === "Ablehnen").handlers.click[0](); '
           'return [calls.slice(-1)[0], $("#modal").hidden, $("#toasts").children.map(t => t.textContent), n, drawn];')
    assert review(answers(preview='throw new Error("Switch ist deaktiviert");', decide="return {ok: true};"), act) == [
        ["POST", "/api/approvals/4/reject", {"comment": "Switch weg"}], True, ["Abgelehnt"], 1, 1]


@pytest.mark.parametrize("preview", ["closeModal(); return %s;" % json.dumps({**SNMP_PLAN, "matches": True}), 'closeModal(); throw new Error("weg");'],
                         ids=["answer", "error"])
def test_a_review_closed_while_the_switch_is_read_stays_closed(preview):
    act = 'await reviewApproval(4); return [$("#modal").hidden, $("#m-title").textContent, $("#m-foot").children.length];'
    assert review(answers(preview=preview), act) == [True, "Anfrage #4 prüfen", 0]


def test_the_review_reads_the_map_when_the_view_was_opened_directly():
    act = 'await reviewApproval(4); return [calls.map(c => c[1]), $("#m-body").innerHTML.includes("· SW-NETMAP")];'
    assert review(answers(), act, map_before="MAP = null;") == [["/api/approvals/4", "/api/netmap", "/api/approvals/4/preview"], True]


# The settings: an Admin switches the principle and its hours; below Admin both fields are locked and the button is gone
SETTINGS_4E = SETTINGS_ANSWER[:-1] + ", four_eyes: false, approval_hours: 24}"
FOUR_EYES_CARD = ('(async () => { const calls = []; %s api = async (m, u, b) => { calls.push([m, u, b]); return u === "/api/settings" ? ' + SETTINGS_4E
                  + ' : u === "/api/zone-scopes" ? {entries: []} : u === "/api/auth/me" ? {name: "x", role: "admin", zones: null, four_eyes: true} : '
                  'u.startsWith("/api/approvals") ? [] : {ok: true}; }; await renderSettings(); const html = $("#view").innerHTML; %s })()')
ONE_PERSON = ("Niemand kann die eigene Anfrage freigeben, auch nicht mit „Admin“, und der Notfall-Login gibt nichts frei. Mit nur einer Person mit "
              "„Freigeben“ oder „Admin“ gehen Änderungen im Expertenmodus und Sammeländerungen dann nicht.")
ADMIN = 'ME = {name: "x", role: "admin", zones: null, four_eyes: false};'


def test_the_four_eyes_card_saves_and_rereads_the_user():
    act = ('$("#s-4e").checked = true; $("#s-4h").value = "48"; await $("#s-4save").handlers.click[0]({target: $("#s-4save")}); '
           'return [html, calls.filter(c => c[0] === "PUT" || c[1] === "/api/auth/me"), $("#toasts").children.map(t => t.textContent), ME.four_eyes, '
           'calls.slice(-1)[0][1], $("#s-4save").disabled];')
    html, calls, toasts, four, last, disabled = in_dom(FOUR_EYES_CARD % (ADMIN, act))
    assert calls == [["PUT", "/api/settings/approvals", {"four_eyes": True, "hours": 48}], ["GET", "/api/auth/me", None]]
    assert (toasts, four, last, disabled) == (["Gespeichert"], True, "/api/approvals?status=open", False)
    assert ('<label class="check"><input type="checkbox" id="s-4e"> Änderungen im Expertenmodus und Sammeländerungen brauchen die Freigabe durch '
            'eine zweite Person (Rolle „Freigeben“ oder „Admin“)</label>') in html
    assert ('<label class="field" style="max-width:220px"><span>Anfragen verfallen nach (Stunden)</span><input id="s-4h" type="number" min="1" '
            'max="168" value="24"></label>') in html
    assert f'<p class="note warn" style="margin:0">{ONE_PERSON}</p>' in html
    assert 'id="s-4save" aria-label="Vier-Augen-Prinzip speichern">Speichern</button>' in html
    assert html.index("<h2>Zonen</h2>") < html.index("<h2>Vier-Augen-Prinzip</h2>") < html.index("<h2>Sitzungen</h2>")
    freigeben = in_dom((FOUR_EYES_CARD % (role_me("freigeben"), "return html;")).replace("four_eyes: false, approval_hours: 24",
                                                                                     "four_eyes: true, approval_hours: 24"))
    assert 'id="s-4save"' not in freigeben and ONE_PERSON in freigeben
    assert '<input type="checkbox" id="s-4e" checked disabled>' in freigeben and 'max="168" value="24" disabled>' in freigeben


# Beyond the brief: hours outside 1-168 or not whole are named in German before anything is sent (the server's 422 would answer in
# pydantic's English, as T8-m found for the zones)
@pytest.mark.parametrize("hours", ["0", "169", "1.5", ""])
def test_the_four_eyes_card_names_hours_out_of_range(hours):
    act = ('$("#s-4h").value = %s; await $("#s-4save").handlers.click[0]({target: $("#s-4save")}); '
           'return [calls.filter(c => c[0] === "PUT").length, $("#toasts").children.map(t => t.textContent)];') % json.dumps(hours)
    assert in_dom(FOUR_EYES_CARD % (ADMIN, act)) == [0, ["Anfragen verfallen nach 1 bis 168 Stunden: bitte eine ganze Zahl eintragen"]]


def test_a_failed_save_of_the_four_eyes_card_names_the_reason():
    act = ('api = async () => { throw new Error("Keine Berechtigung: x"); }; $("#s-4h").value = "24"; '
           'await $("#s-4save").handlers.click[0]({target: $("#s-4save")}); '
           'return [$("#toasts").children.map(t => t.textContent), ME.four_eyes, $("#s-4save").disabled];')
    assert in_dom(FOUR_EYES_CARD % (ADMIN, act)) == [["Keine Berechtigung: x"], False, False]


# The forms say it under the expert-mode box, which names the note as its description
FOUR_EYES_NOTE = '<p class="note" id="f-4eyes">Im Expertenmodus braucht die Änderung eine Freigabe durch eine zweite Person (Vier-Augen-Prinzip).</p>'


@pytest.mark.parametrize("four", [True, False])
def test_the_forms_say_that_expert_mode_needs_an_approval(four):
    port = (PANEL + role_me("aendern", four_eyes=four) + 'portIdx["1"].tr = "Trk1"; let cap = null; modal = (t, b) => { cap = b; }; '
            'editPorts({id: 1, k: "A", ssh: true, caps: ["cli"], ports: []}, ["1"]); cap')
    trunk = role_me("freigeben", four_eyes=four) + trk() + 'editTrunk(sw, "Trk1"); cap.b'
    for b in (in_dom(port), in_dom(trunk)):
        assert (FOUR_EYES_NOTE in b) == four and bool(re.search(r'id="f-expert"[^>]*aria-describedby="f-4eyes"', b)) == four
        assert b.index('id="f-expert"') < b.index('id="f-4eyes"') if four else True


@pytest.mark.parametrize("approved_by, said", [("ben", " · freigegeben von ben"), ("b<n", " · freigegeben von b&lt;n"), (None, None)])
def test_change_details_name_who_approved(approved_by, said):
    c = {**ROWS[0], "approved_by": approved_by, "commands": [], "steps": [], "mechanism": "ssh"}
    act = ('api = async (m, u) => (%s); await el.onclick({target: {closest: s => s === "[data-cd]" ? {dataset: {cd: "7"}} : null}}); '
           'return $("#m-body").innerHTML;') % json.dumps(c)
    html = in_dom(LIST % (json.dumps(ROWS), 10, act))
    assert (said in html) if said else "freigegeben von" not in html


def test_the_commands_of_a_request_come_from_one_helper():                              # 4a, Später 4b (fails before: the expression twice)
    text = (STATIC / "sv-approvals.js").read_text(encoding="utf-8")
    assert text.count("(a.preview && a.preview.commands)") == 1
    assert "apprCmds(a)" in body_of("sv-approvals.js", "approvalDetails") and "apprCmds(a)" in body_of("sv-approvals.js", "reviewApproval")


# Phase 4c Task 9: a bulk request (kind bulk_change) has no switch of its own - the list says "mehrere Switches" and offers "Prüfen"
# without the zone check of the browser (the server checks the zone of every switch), the review shows the fresh sections
# (bulkSectionsHtml of sv-bulk.js) instead of one preview, approving opens the run of the bulk change, the details show the
# requester's sections, and "Neu anfordern" opens the bulk preview of the stored switches and ports
BULK_SECS = [{"switch_id": 1, "switch": "SW-A", "ports": ["1", "2"], "mechanism": "ssh", "commands": ["vlan 30 untagged 1,2"], "warnings": [], "token": "t-a"},
             {"switch_id": 3, "switch": "SW-C", "ports": ["5"], "mechanism": "ssh", "commands": ["vlan 30 untagged 5"], "warnings": [], "token": "t-c"}]
BULK_PAYLOAD = {"items": [{"switch_id": 1, "ports": ["1", "2"], "token": "t-a", "mechanism": "ssh"},
                          {"switch_id": 3, "ports": ["5"], "token": "t-c", "mechanism": "ssh"}],
                "skipped": [{"switch_id": 2, "reason": "Es gibt nichts zu ändern"}], "change": {"untagged": "30"}, "expert": False, "on_error": "continue",
                "confirm_minutes": None}
BULK_A = {**A, "kind": "bulk_change", "kind_label": "Sammeländerung", "switch_id": None, "switch_name": None, "switch_zone": None,
          "summary": "VLAN 30 · 3 Ports an 2 Switches", "bulk_id": None, "own": False, "payload": BULK_PAYLOAD,
          "preview": {"summary": "VLAN 30 · 3 Ports an 2 Switches", "token": "T", "sections": BULK_SECS,
                      "skipped": [{"switch_id": 2, "switch": "SW-<B>", "reason": "Es gibt <nichts> zu ändern"}]}}
FRESH = [{**s, "status": "ready", "reason": "", "matches": True} for s in BULK_SECS]
BULK_FRESH = {"kind": "bulk_change", "summary": BULK_A["summary"], "sections": FRESH, "token": "T", "matches": True}
MOVED = {**BULK_FRESH, "matches": False, "token": "X", "sections": [FRESH[0], {**FRESH[1], "commands": ["vlan 30 untagged 5", "no vlan 40 tagged 5"],
                                                                              "token": "t-x", "matches": False}]}


def bulk_answers(preview=BULK_FRESH, full=BULK_A):
    return ('if (u.endsWith("/preview")) return %s; if (u.endsWith("/approve")) return {id: 8, approval: 4, kind: "bulk_change"}; '
            'if (u === "/api/netmap") throw new Error("a bulk request reads no netmap"); return %s;') % (json.dumps(preview), json.dumps(full))


BULK_REVIEW = 'let opened = null; openBulk = id => { opened = id; }; await reviewApproval(4); '


def test_a_bulk_request_shows_its_switches_and_runs_as_a_bulk():
    # the list: no switch of its own, and "Prüfen" although no zone of the reviewer is known to hold it
    js = ('(async () => { ME = {role: "freigeben", zones: ["EK"], four_eyes: true}; api = async () => [%s]; ' + DRAW) % json.dumps(BULK_A)
    html = in_dom(js)
    assert "<td>mehrere Switches</td>" in html and 'data-ar="4">Prüfen</button>' in html
    assert 'VLAN 30 · 3 Ports an 2 Switches<span class="cellnote">Sammeländerung</span>' in html
    # the review: the fresh sections, then approving starts the bulk change and opens its run
    act = (BULK_REVIEW + 'const d = ' + DIALOG + '; $("#ap-comment").value = "passt"; '
           'await $("#m-foot").children.find(x => x.textContent === "Freigeben und ausführen").handlers.click[0](); '
           'return [d, opened, ran, $("#modal").hidden, calls.map(c => c[1]), calls.slice(-1)[0], n];')
    (title, body, labels), opened, ran, hidden, urls, last, n = review(bulk_answers(), act, map_before="MAP = null;")
    assert title == "Anfrage #4 prüfen" and labels == ["Abbrechen", "Ablehnen", "Freigeben und ausführen"]
    assert body.startswith('<p class="note" style="margin:0">Angefordert von <b>Anna</b> (Ändern) · ')
    assert "<b>VLAN 30 · 3 Ports an 2 Switches</b>" in body and '<b>SW-A</b> <span class="muted">· 2 Ports: <span class="mono">1, 2</span></span></p>' in body
    assert '<pre class="code">vlan 30 untagged 5</pre>' in body and "passt nicht mehr" not in body and "Freigeben geht nicht" not in body
    assert body.endswith(COMMENT_FIELD)
    assert (opened, ran, hidden, n) == (8, None, True, 1)
    assert urls == ["/api/approvals/4", "/api/approvals/4/preview", "/api/approvals/4/approve"]
    assert last == ["POST", "/api/approvals/4/approve", {"token": "T", "comment": "passt"}]


def test_a_bulk_request_that_no_longer_matches_cannot_be_approved():
    title, body, labels = review(bulk_answers(preview=MOVED), BULK_REVIEW + 'return ' + DIALOG + ';')
    assert labels == ["Abbrechen", "Ablehnen"]
    assert ('<div class="error"><b>Freigeben geht nicht:</b> Mindestens ein Switch passt nicht mehr zur Anfrage: er hat sich seit der Anfrage geändert, '
            'ist gesperrt oder nicht lesbar. Ablehnen oder neu anfordern lassen.</div>') in body
    assert body.count('<span class="pill warn">passt nicht mehr</span>') == 1
    assert body.index("SW-C") < body.index("passt nicht mehr") < body.index("no vlan 40 tagged 5")
    # the requester's sections to compare, folded
    theirs = body[body.index('<details class="adv"><summary>Vorschau des Antragstellers</summary>'):]
    assert '<pre class="code">vlan 30 untagged 5</pre>' in theirs and "no vlan 40" not in theirs


@pytest.mark.parametrize("full, said", [
    ({**BULK_A, "status": "approved", "decided_by": "ben", "bulk_id": 8}, "<dt>Änderung</dt><dd>Sammeländerung #8</dd>"),
    ({**BULK_A, "own": True}, "<dt>Änderung</dt><dd>–</dd>")], ids=["approved", "open"])
def test_the_details_of_a_bulk_request_show_its_sections_and_its_bulk_change(full, said):
    title, body, foot = view_click('await click("ad"); return ' + DIALOG + ';', row=full, full=full)
    assert title == "Anfrage #4" and foot == ["Schließen"] and said in body
    assert '<b>VLAN 30 · 3 Ports an 2 Switches</b> <span class="muted">· mehrere Switches · Sammeländerung</span>' in body
    assert body.count('<div class="bulk-sec">') == 2 and '<pre class="code">vlan 30 untagged 1,2</pre>' in body
    assert "passt nicht mehr" not in body
    # the switches the preview skipped, with their reason (escaped)
    assert "<p class=\"eyebrow\">Übersprungen</p>" in body and "<li>SW-&lt;B&gt;: Es gibt &lt;nichts&gt; zu ändern</li>" in body


@pytest.mark.parametrize("role, four, offered", [("aendern", False, True), ("aendern", True, True), ("lesen", True, False)])
def test_a_bulk_request_is_asked_again_through_the_bulk_preview(role, four, offered):
    """A port request needs the expert mode to be asked again, a bulk request only Ändern: every bulk change needs an approval."""
    stale = {**BULK_A, "own": True, "status": "stale"}
    js = ('(async () => { ME = {role: %s, zones: ["EK"], four_eyes: %s}; api = async () => [%s]; ' + DRAW) % (
        json.dumps(role), json.dumps(four), json.dumps(stale))
    assert ('data-an="4">Neu anfordern</button>' in in_dom(js)) == offered
    act = ('let got = null; previewBulk = (req, o) => { got = [req, o]; }; previewChange = () => { got = "port"; }; await click("an"); '
           'return [got, calls.map(c => c[1])];')
    got, calls = view_click(act, row=stale, full=stale)
    assert got == [{"targets": [{"switch_id": 1, "ports": ["1", "2"]}, {"switch_id": 3, "ports": ["5"]}], "change": {"untagged": "30"}, "expert": False},
                   {"onError": "continue"}]
    assert calls == ["/api/approvals?status=all&limit=100", "/api/approvals/4"]          # no netmap: the preview reads what it needs


# Phase 4c, Task 12 (browser check): how a request will run once approved stands in neither preview - with confirmation it waits
# for "Bestätigen" and is taken back without it, a bulk change stops at its first failure or goes on. The review and the details
# say it from the request's payload; a port request without confirmation says nothing, as before.
RUN_CONFIRM = "mit Bestätigung (%s) – ohne „Bestätigen“ nimmt SwitchView sie danach zurück"
RUNS = [(REVIEW_A, None),
        ({**REVIEW_A, "payload": {**PAYLOAD, "confirm_minutes": 5}}, RUN_CONFIRM % "5 Minuten"),
        ({**REVIEW_A, "payload": {**PAYLOAD, "confirm_minutes": 1}}, RUN_CONFIRM % "1 Minute"),
        (BULK_A, "bei einem Fehler weitermachen"),
        ({**BULK_A, "payload": {**BULK_PAYLOAD, "on_error": "stop", "confirm_minutes": 2}}, "bei einem Fehler stoppen · " + RUN_CONFIRM % "2 Minuten")]
RUN_IDS = ["port", "port-confirm", "port-one-minute", "bulk-continue", "bulk-stop-confirm"]


@pytest.mark.parametrize("full, said", RUNS, ids=RUN_IDS)
def test_the_review_says_how_the_request_will_run(full, said):
    fresh = BULK_FRESH if full["kind"] == "bulk_change" else {**SNMP_PLAN, "matches": True}
    title, body, labels = review(bulk_answers(preview=fresh, full=full), BULK_REVIEW + 'return ' + DIALOG + ';')
    assert labels == ["Abbrechen", "Ablehnen", "Freigeben und ausführen"]
    if said is None:
        assert 'id="ap-run"' not in body and "Ausführung" not in body
    else:    # after the preview, right before the comment
        assert body.endswith('<p class="note" id="ap-run" style="margin:0">Ausführung: %s</p>' % said + COMMENT_FIELD)


@pytest.mark.parametrize("full, said", RUNS, ids=RUN_IDS)
def test_the_details_say_how_the_request_will_run(full, said):
    full = {**full, "own": True}
    title, body, foot = view_click('await click("ad"); return ' + DIALOG + ';', row=full, full=full)
    assert title == "Anfrage #4" and ("<dt>Ausführung</dt><dd>%s</dd>" % said in body if said else "Ausführung" not in body)
    assert body.index("<dt>Grund</dt>") < body.index("<dt>Änderung</dt>")
    if said:
        assert body.index("<dt>Änderung</dt>") < body.index("<dt>Ausführung</dt>") < body.index("Vorschau des Antragstellers")
