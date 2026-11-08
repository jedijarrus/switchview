"""Phase 4c, Task 5: the change with confirmation in the UI - app/static/sv-confirm.js and its hooks in sv-switch.js - against the
recording DOM stub of tests/test_frontend_dom.py: "Mit Bestätigung ausführen" in the preview where the server says it is possible
(else why not, and nothing for a revert or from a server before the update), the minutes in /apply and in a four-eyes request only
when ticked, a waiting change in its progress with its deadline, "Bestätigen" and "Jetzt zurücknehmen" (set once, asked every 3 s),
the change list naming the waiting and the unconfirmed change and offering "Bestätigen", and the audit's two labels. Skipped
without node."""
import json
import shutil
from datetime import datetime, timedelta, timezone

import pytest
from test_frontend_dom import ADMIN_ME, in_dom, role_me

import api_changes

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

POSSIBLE = {"possible": True, "why": None, "default_minutes": 5, "max_minutes": 30}
PLAN_ANSWER = {"kind": "ports", "summary": "Port 2: Aus", "mechanism": "ssh", "commands": ["interface 2 disable"], "warnings": [], "blocked": [],
               "before": {}, "desired": {}, "token": "t", "autosave": False, "insecure_write": None, "approval": False, "confirm": POSSIBLE}
PORTS = {"mode": "ports", "ports": ["2"], "change": {"status": "off"}}
# previewChange of payload at switch SW against an api stub that answers POST …/plan with answer and records every call as [method,
# url, body] (any other call answers {id: 7}); runProgress and the approvals' refresh are stubs; then: the statements after, their
# value the test's
PREVIEW = ('(async () => { %s const calls = []; api = async (m, u, b) => { calls.push([m, u, b === undefined ? null : b]); '
           'return u.endsWith("/plan") ? %s : {id: 7}; }; runProgress = () => {}; refreshApprovals = async () => {}; '
           'await previewChange({id: 1, k: "SW", caps: ["cli"]}, %s); %s })()')
TICK = "await new Promise(r => setTimeout(r, 5)); "
CLICK = '$("#m-foot").children.find(b => b.textContent === "%s").fire("click"); '
TOASTS = '$("#toasts").children.map(t => t.textContent)'


def preview(then, answer=PLAN_ANSWER, payload=PORTS, me=ADMIN_ME):
    return in_dom(PREVIEW % (me, json.dumps(answer), json.dumps(payload), then))


@pytest.mark.parametrize("answer, payload, box, why", [
    (PLAN_ANSWER, PORTS, True, None),
    ({**PLAN_ANSWER, "confirm": {**POSSIBLE, "possible": False, "why": api_changes.CONFIRM_AUTOSAVE}}, PORTS, False, api_changes.CONFIRM_AUTOSAVE),
    ({**PLAN_ANSWER, "summary": "Rückgängig #3: Port 2: Aus"}, {"mode": "revert", "of": 3}, False, None),
    ({**PLAN_ANSWER, "confirm": {**POSSIBLE, "possible": False, "why": api_changes.CONFIRM_ONLY_PORTS}}, {"mode": "revert", "of": 3}, False, None),
    ({k: v for k, v in PLAN_ANSWER.items() if k != "confirm"}, PORTS, False, None)],      # beyond the brief: a server from before the update
    ids=["possible", "autosave", "revert", "revert-refused", "old-server"])
def test_the_preview_offers_confirmation_where_it_is_possible(answer, payload, box, why):
    html = preview('return $("#m-body").innerHTML; ', answer, payload)
    assert ('id="p-confirm"' in html, '<option value="5" selected>5</option>' in html, 'id="p-confirm-min"' in html) == (box, box, box)
    assert ('id="p-confirm-why"' in html) == (why is not None)
    if box:
        assert ('<label class="check"><input type="checkbox" id="p-confirm"><span>Mit Bestätigung ausführen: erst speichern, wenn ich bestätige – '
                'ohne Bestätigung nach <select id="p-confirm-min" aria-label="Minuten bis zur automatischen Rücknahme">') in html
        assert [f'<option value="{m}"' in html for m in (2, 5, 10, 15, 30)] == [True] * 5
        assert "</select> Minuten automatisch zurücknehmen</span></label>" in html
    if why:
        assert f'<p class="note" id="p-confirm-why">{why}.</p>' in html


@pytest.mark.parametrize("ticked, want", [(True, {"confirm_minutes": 10}), (False, {})], ids=["ticked", "not-ticked"])
def test_apply_sends_the_minutes_only_when_ticked(ticked, want):
    tick = '$("#p-confirm").checked = true; $("#p-confirm-min").value = "10"; ' if ticked else '$("#p-confirm-min").value = "10"; '
    calls = preview(tick + CLICK % "Ausführen" + TICK + "return calls; ")
    assert calls[1] == ["POST", "/api/switches/1/apply", {**PORTS, "mechanism": "ssh", "token": "t", **want}]


# Beyond the brief: a four-eyes request carries the minutes in its plan the same way (Interfaces: "bei „Freigabe anfordern“")
@pytest.mark.parametrize("ticked, want", [(True, {"confirm_minutes": 15}), (False, {})], ids=["ticked", "not-ticked"])
def test_a_request_sends_the_minutes_only_when_ticked(ticked, want):
    tick = '$("#p-confirm").checked = true; $("#p-confirm-min").value = "15"; ' if ticked else ""
    calls = preview(tick + CLICK % "Freigabe anfordern" + TICK + "return calls; ", {**PLAN_ANSWER, "approval": True})
    assert calls[1] == ["POST", "/api/approvals", {"kind": "port_change", "switch_id": 1, "plan": {**PORTS, "mechanism": "ssh", "token": "t", **want}}]


def waiting(minutes=4, **k) -> dict:
    """A change waiting for its confirmation for `minutes` more, as GET /api/changes/{id} answers it."""
    until = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    return {"id": 7, "summary": "Port 2: Aus", "status": "pending", "confirm_until": until, "confirm_minutes": 5, "confirmed_by": None,
            "username": "anna", "approved_by": None, "can_revert": True, "can_save": False, "switch_zone": "", "expert": 0, "kind": "ports",
            "mechanism": "ssh", "sent": 1, "saved": 0, "error": None, "reverted_by": None, "output": "",
            "steps": [["2026-11-08 10:00:00", "Prüfung ok", "info"]]} | k


# runProgress of change 7 against an api stub that answers GET with c, and a POST (the confirm) with {ok: true} - from then on c is
# running; every call recorded as [method, url]. setTimeout of 3000 ms (the wait of a waiting change) takes 5 ms here, and every
# delay asked for is recorded; the map and the views are stubs. The stub's innerHTML = "" keeps the first footer's "Schließen"
# (modal()), so a footer set later stands after it. waitFor(ok) waits (real timers, 2 ms steps) until ok() holds, at most 5 s - a
# condition, not a fixed window, so a loaded machine only makes it slower; the statements run once runProgress waited twice
PROGRESS = ('(async () => { %s current = "audit"; loadMap = async () => {}; const calls = [], delays = []; let c = %s; '
            'const st = setTimeout; setTimeout = (f, ms) => { delays.push(ms); return st(f, ms === 3000 ? 5 : ms); }; '
            'const waitFor = async ok => { const end = Date.now() + 5000; while (!ok() && Date.now() < end) await new Promise(r => st(r, 2)); }; '
            'api = async (m, u) => { calls.push([m, u]); if (m === "POST") { c = {...c, status: "running"}; return {ok: true, id: 7}; } return c; }; '
            'runProgress({id: 1, k: "SW"}, 7); await waitFor(() => delays.filter(d => d === 3000).length >= 2); %s })()')
FOOT = '$("#m-foot").children.slice(1).map(b => b.textContent)'


@pytest.mark.parametrize("me, want", [
    (role_me("aendern", username="anna"), ["Bestätigen", "Jetzt zurücknehmen", "Schließen"]),
    (role_me("aendern", username="ben"), ["Jetzt zurücknehmen", "Schließen"]),          # another user with Ändern
    (role_me("freigeben", username="ben"), ["Bestätigen", "Jetzt zurücknehmen", "Schließen"]),
    (role_me("aendern", username="Anna", zones=["VK"]), ["Schließen"]),                 # beyond the brief: outside the user's zones
    (role_me("lesen", username="anna"), ["Schließen"])],
    ids=["starter", "other", "freigeben", "other-zone", "lesen"])
def test_a_pending_change_shows_its_deadline_and_both_actions(me, want):
    html, foot, delays = in_dom(PROGRESS % (me, json.dumps(waiting()), f'return [$("#prog").innerHTML, {FOOT}, delays];'), tz="UTC")
    assert "<b>Geprüft und aktiv, aber nicht gespeichert.</b> Bestätigen bis " in html
    assert "(noch 4 Minuten), sonst nimmt SwitchView die Änderung zurück." in html
    assert '<div class="banner warn">' in html and "Prüfung ok" in html
    # the footer is set once although the change was asked several times, every 3000 ms
    assert foot == want and delays.count(3000) > 1 and 1200 not in delays


# Beyond the brief: one minute left reads in the singular, a deadline past "Frist abgelaufen"
@pytest.mark.parametrize("minutes, want", [(0.5, "(noch 1 Minute)"), (-1, "(Frist abgelaufen)")])
def test_the_deadline_counts_down_to_its_end(minutes, want):
    html = in_dom(PROGRESS % (ADMIN_ME, json.dumps(waiting(minutes)), 'return $("#prog").innerHTML;'))
    assert want in html


# Beyond the brief: a waiting change is asked only while its dialog is open (T5-f); closed, the asking stops (a window for an
# absence: a loaded machine fits fewer 5 ms polls into it, which can only let it pass, never fail)
def test_a_closed_dialog_stops_asking():
    then = 'closeModal(); const n = calls.length; await new Promise(r => st(r, 40)); return [n, calls.length];'
    n, after = in_dom(PROGRESS % (ADMIN_ME, json.dumps(waiting()), then))
    assert n > 1 and after <= n + 1        # the one request under way when it closed may still come back


def test_confirm_posts_and_keeps_watching():
    # until the change was asked again after the confirm and its footer is set back (or 5 s)
    then = (CLICK % "Bestätigen" + 'await waitFor(() => calls.slice(calls.findIndex(x => x[0] === "POST") + 1).some(x => x[0] === "GET") '
            f'&& {FOOT}.length === 4); return [calls, {TOASTS}, {FOOT}, $("#prog").innerHTML];')
    calls, toasts, foot, html = in_dom(PROGRESS % (role_me("aendern", username="anna"), json.dumps(waiting()), then))
    i = calls.index(["POST", "/api/changes/7/confirm"])
    assert calls[:i] and set(map(tuple, calls[:i])) == {("GET", "/api/changes/7")} and ["GET", "/api/changes/7"] in calls[i + 1:]
    # running again: the waiting footer gives way to "Schließen", the banner goes
    assert toasts == ["Bestätigt"] and foot == ["Bestätigen", "Jetzt zurücknehmen", "Schließen", "Schließen"] and "Geprüft und aktiv" not in html


# Beyond the brief: "Jetzt zurücknehmen" opens the preview of the revert, and a refused confirm says why and can be clicked again
def test_take_back_now_opens_the_preview_of_the_revert():
    then = ('let got = null; previewChange = (s, p) => { got = [s.k, p]; }; ' + CLICK % "Jetzt zurücknehmen" + 'return got;')
    assert in_dom(PROGRESS % (ADMIN_ME, json.dumps(waiting()), then)) == ["SW", {"mode": "revert", "of": 7}]


def test_a_refused_confirm_is_a_message():
    then = ('const real = api; api = async (m, u) => { if (m === "POST") throw new Error("Zu spät"); return real(m, u); }; '
            'const b = $("#m-foot").children.find(x => x.textContent === "Bestätigen"); b.fire("click"); '
            f'await waitFor(() => {TOASTS}.length > 0 && !b.disabled); return [{TOASTS}, b.disabled];')
    assert in_dom(PROGRESS % (ADMIN_ME, json.dumps(waiting()), then)) == [["Zu spät"], False]


# A change list against an api stub (as LIST of tests/test_frontend_dom.py) with the rows given
LIST = ('(async () => { %s const calls = []; api = async (m, u) => { calls.push([m, u]); return m === "POST" ? {ok: true, id: 7} : %s; }; '
        'const el = $("#lst"); await renderChangesInto(el, 1, 10); %s })()')
ROW = {"created_at": "2026-11-08 10:00:00", "switch_id": 1, "switch_name": "SW", "summary": "Port 2: Aus", "reverted_by": None, "expert": 0}


def test_the_change_list_names_the_waiting_and_the_unconfirmed():
    # "nicht bestätigt" only for a change that waited (confirm_until, written only by changes._wait_for_confirm); one with
    # confirmation that ended unclear in its own run, before it waited, is "unklar" (review round 1)
    until = '"2026-11-08 10:05:00"'
    pills = in_dom(f'[chPill({{status: "pending"}}), chPill({{status: "unclear", confirm_minutes: 5, confirm_until: {until}, confirmed_by: null}}), '
                   f'chPill({{status: "unclear", confirm_minutes: 5, confirm_until: {until}, confirmed_by: "anna"}}), chPill({{status: "unclear"}}), '
                   'chPill({status: "unclear", confirm_minutes: 5, confirm_until: null, confirmed_by: null})]')
    assert pills == ['<span class="pill warn">wartet auf Bestätigung</span>', '<span class="pill warn">nicht bestätigt</span>',
                     '<span class="pill warn">unklar</span>', '<span class="pill warn">unklar</span>', '<span class="pill warn">unklar</span>']
    rows = [waiting(id=8), waiting(id=9, username="ben"), {**waiting(id=10), "status": "ok", "saved": 1}]
    html = in_dom(LIST % (role_me("aendern", username="anna"), json.dumps([{**ROW, **r} for r in rows]), "return el.innerHTML;"))
    assert '<button class="btn small" type="button" data-cc="8" data-sw="1">Bestätigen</button>' in html
    assert 'data-cc="9"' not in html and 'data-cc="10"' not in html and "wartet auf Bestätigung" in html


# Beyond the brief: "Bestätigen" in the list confirms and then shows the change's progress (its save and its end)
def test_confirm_in_the_list_shows_the_progress():
    act = ('MAP = {switches: [{id: 1, k: "SW"}], links: [], vlans: {}}; let ran = null; runProgress = (s, id) => { ran = [s.k, id]; }; '
           'await el.onclick({target: {closest: s => s === "[data-cc]" ? {dataset: {cc: "8", sw: "1"}} : null}}); return [ran, calls, '
           + TOASTS + '];')
    ran, calls, toasts = in_dom(LIST % (role_me("aendern", username="anna"), json.dumps([{**ROW, **waiting(id=8)}]), act))
    assert ran == ["SW", 8] and calls[-1] == ["POST", "/api/changes/8/confirm"] and toasts == ["Bestätigt"]


def test_the_audit_names_the_confirm_actions():
    assert in_dom("[AUDIT_LABELS.change_pending, AUDIT_LABELS.change_confirm]") == ["Änderung wartet auf Bestätigung", "Änderung bestätigt"]
