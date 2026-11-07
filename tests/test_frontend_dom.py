"""Phase 5: what the app scripts do, against a recording DOM stub. The scripts of index.html (without msal-browser.min.js) run as
classic scripts in one node vm context, one global scope as in the browser; the stub keeps the state a test reads back (focus,
attributes, hidden / inert, handlers, history). Layout and real focus rules stay with the browser check. Skipped without node."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from test_frontend_logic import AUDIT  # the audit rows of SVLogic.filterAudit's test, shown by renderAudit here (Task 8)

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
STATIC = Path(__file__).resolve().parent.parent / "app" / "static"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
FILES = [str(STATIC / n) for n in re.findall(r'<script src="/static/([\w.\-]+)"></script>', INDEX) if n != "msal-browser.min.js"]
# the ids index.html starts hidden (the hidden attribute, not aria-hidden)
HIDDEN = [i for tag in re.findall(r"<[a-z][^>]*>", INDEX) if re.search(r"\shidden(?=[\s>])", tag) for i in re.findall(r'\bid="([\w-]+)"', tag)]
DOM = r"""
const vm = require("vm"), fs = require("fs");
const [cfgJson, expr, ...files] = process.argv.slice(1), cfg = JSON.parse(cfgJson);
function fire(handlers, type, target, ev) {
  const e = { target, key: "", shiftKey: false, defaultPrevented: false, preventDefault() { e.defaultPrevented = true; }, stopPropagation() {}, ...ev };
  (handlers[type] || []).forEach(f => f(e));
  return e;
}
function El(sel) {
  const cls = new Set(), o = {
    sel, hidden: sel.startsWith("#") && cfg.hidden.includes(sel.slice(1)), inert: false, disabled: false, checked: false, value: "",
    innerHTML: "", textContent: "", dataset: {}, attrs: {}, handlers: {}, children: [], kids: [], rects: [1], parent: null, isConnected: true,
    style: { setProperty() {}, removeProperty() {} },
    classList: { add: (...c) => c.forEach(x => cls.add(x)), remove: (...c) => c.forEach(x => cls.delete(x)), contains: c => cls.has(c),
      toggle: (c, on) => ((on === undefined ? !cls.has(c) : on) ? cls.add(c) : cls.delete(c)) },
    focus() { doc.activeElement = P; }, blur() {}, scrollIntoView() {}, getClientRects: () => o.rects,
    setAttribute(k, v) { o.attrs[k] = String(v); }, getAttribute: k => (k in o.attrs ? o.attrs[k] : null), removeAttribute(k) { delete o.attrs[k]; },
    addEventListener(t, f) { (o.handlers[t] = o.handlers[t] || []).push(f); }, removeEventListener() {},
    fire: (t, ev) => fire(o.handlers, t, P, ev), querySelector: s => doc.querySelector(s), querySelectorAll: () => o.kids,
    closest: () => null, contains: () => true, appendChild(c) { o.children.push(c); c.parent = P; return c; },
    remove() { if (o.parent) { const ch = o.parent.children; ch.splice(ch.indexOf(P), 1); o.parent = null; } o.isConnected = false; } };
  const P = new Proxy(o, { get: (t, k) => (k in t ? t[k] : undefined) });
  return P;
}
const els = {}, lists = {};
const doc = { activeElement: null, handlers: {}, els, lists, contains: () => true,
  querySelector: s => els[s] || (/[\s,>\[:]/.test(s.trim()) ? null : (els[s] = El(s))), querySelectorAll: s => lists[s] || [],
  getElementById: id => doc.querySelector("#" + id), createElement: tag => El("<" + tag + ">"),
  addEventListener(t, f) { (doc.handlers[t] = doc.handlers[t] || []).push(f); }, fire: (t, ev) => fire(doc.handlers, t, doc.activeElement, ev) };
doc.body = El("body");
const win = { handlers: {}, addEventListener(t, f) { (win.handlers[t] = win.handlers[t] || []).push(f); }, scrollTo() {},
  fire: (t, ev) => fire(win.handlers, t, win, ev) };
const loc = { hash: cfg.hash, origin: "http://127.0.0.1" };
const hist = { calls: [], scrollRestoration: "auto", pushState(s, t, u) { hist.calls.push(["push", u]); loc.hash = u; },
  replaceState(s, t, u) { hist.calls.push(["replace", u]); loc.hash = u; } };
const fetched = [];
const ctx = vm.createContext({ document: doc, window: win, history: hist, location: loc, CSS: { escape: s => String(s).replace(/["\\\]]/g, "\\$&") },
  fetch: url => { fetched.push(url); return new Promise(() => {}); }, fetched, setTimeout, clearTimeout, console });
for (const f of files) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });
Promise.resolve(vm.runInContext(expr, ctx)).then(v => process.stdout.write(JSON.stringify(v === undefined ? null : v), () => process.exit(0)),
  e => { process.stderr.write(String((e && e.stack) || e)); process.exit(1); });
"""


def in_dom(expr: str, hash: str = ""):
    """The value (JSON) of the JavaScript expression expr (a Promise is awaited), evaluated after the scripts of index.html ran."""
    out = subprocess.run(["node", "-e", DOM, json.dumps({"hash": hash, "hidden": HIDDEN}), expr, *FILES], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_a_second_dialog_keeps_the_first_opener():
    assert in_dom('$("#opener").focus(); modal("A", "", []); $("#inner").focus(); modal("B", "", []); closeModal(); document.activeElement.sel') == "#opener"


def test_closing_returns_focus_to_a_live_opener_else_the_view():                     # Review Focus 2
    gone = 'const o = $("#opener"); o.focus(); modal("A", "", []); o.isConnected = false; closeModal(); document.activeElement.sel'
    assert in_dom(gone) == "#view" and in_dom('drLast = $("#tile"); ' + gone) == "#tile"


def test_a_dialog_opened_without_focus_gives_it_to_the_view():                        # Review Focus 2
    """Nothing focused (document.activeElement is body, as after a click in Safari): closing focuses #view, not body."""
    assert in_dom('document.body.focus(); modal("A", "", []); closeModal(); document.activeElement.sel') == "#view"


TRAP = ('$(".modal").kids = [$("#a"), $("#b"), $("#c")]; modal("T", "", []); $("%s").focus(); '
        'const e = document.fire("keydown", {key: "Tab", shiftKey: %s}); [document.activeElement.sel, e.defaultPrevented]')


@pytest.mark.parametrize("start, shift, want", [("#c", "false", ["#a", True]), ("#a", "true", ["#c", True]), ("#b", "false", ["#b", False]),
                                                ("#outside", "false", ["#a", True])])
def test_tab_wraps_inside_the_open_dialog(start, shift, want):
    assert in_dom(TRAP % (start, shift)) == want


def test_tab_skips_controls_that_are_not_shown():
    assert in_dom('$(".modal").kids = [$("#a"), $("#b"), $("#c")]; $("#c").rects = []; modal("T", "", []); $("#b").focus(); '
                  'document.fire("keydown", {key: "Tab"}); document.activeElement.sel') == "#a"


def test_tab_wraps_inside_the_open_drawer():
    assert in_dom('$("#drawer").kids = [$("#dr-x"), $("#dr-edit")]; $("#drawer").classList.add("open"); $("#dr-edit").focus(); '
                  'document.fire("keydown", {key: "Tab"}); document.activeElement.sel') == "#dr-x"


def test_escape_closes_the_top_layer_first():
    js = ('$("#drawer").classList.add("open"); modal("T", "", []); document.fire("keydown", {key: "Escape"}); '
          'const a = [$("#modal").hidden, $("#drawer").classList.contains("open")]; document.fire("keydown", {key: "Escape"}); '
          '[...a, $("#drawer").classList.contains("open")]')
    assert in_dom(js) == [True, True, False]


# Phase 4a Task 8: the controls follow the role of ME (/api/auth/me); the shared prefixes of the tests that expect controls sign in
# as Admin unless the test set its own ME before them
ADMIN_ME = 'ME = ME || {name: "x", role: "admin", zones: null, four_eyes: false}; '
PANEL = (ADMIN_ME + 'MAP = {switches: [], links: [], vlans: {}}; portIdx = {"1": {n: "1", l: [], d: [], u: [], t: [], mc: 0, tr: "", a: "", pv: "", '
         'st: "", mb: [], o: true, ad: true, s: 1000}}; ')
OPEN_PANEL = 'openPort({id: 1, k: "A", model: "x", caps: [], ports: []}, "1"); '


def test_the_background_is_inert_while_a_layer_is_open():
    js = (PANEL + 'const a = []; modal("T", "", []); a.push($("#app").inert, $("#drawer").inert); closeModal(); a.push($("#app").inert); '
          + OPEN_PANEL + 'a.push($("#app").inert, $("#drawer").inert); closeDrawer(); a.push($("#app").inert); a')
    assert in_dom(js) == [True, True, False, True, False, False]


@pytest.mark.parametrize("opened, close", [('modal("A", "", []); ', "closeModal(); "), ('drLast = o; ' + OPEN_PANEL, "closeDrawer(); ")])
def test_focus_goes_back_once_the_background_is_live_again(opened, close):                # Review Focus 2
    """In a browser an element inside an inert subtree takes no focus: syncLayers runs before restoreFocus."""
    js = (PANEL + 'const o = $("#opener"); o.focus(); ' + opened + 'let seen = null; const f = o.focus; o.focus = () => { seen = $("#app").inert; f(); }; '
          + close + '[seen, document.activeElement.sel]')
    assert in_dom(js) == [False, "#opener"]


def test_the_login_closes_open_layers():
    assert in_dom('$("#drawer").classList.add("open"); modal("T", "", []); showLogin("x"); '
                  '[$("#modal").hidden, $("#drawer").classList.contains("open"), $("#app").inert]') == [True, False, False]


def test_the_sso_button_hands_the_servers_nonce_to_msal():                             # Phase 4a Task 2: the id_token's nonce
    js = ('(async () => { const calls = []; api = async (m, u, b) => { calls.push([m, u, b]); return u === "/api/auth/nonce" ? {nonce: "n-1"} : {}; }; '
          'start = async () => {}; let req = null; globalThis.msal = {PublicClientApplication: class { async initialize() {} '
          'async loginPopup(r) { req = r; return {idToken: "tok"}; } }}; window.msal = msal; authCfg = {client_id: "c", tenant: "t"}; msalApp = null; '
          'await $("#btn-sso").handlers.click[0](); return [req.nonce, calls]; })()')
    assert in_dom(js) == ["n-1", [["POST", "/api/auth/nonce", None], ["POST", "/api/auth/azure", {"id_token": "tok"}]]]


def test_toasts_stack_up_to_three_and_a_repeat_counts_once():
    assert in_dom('["a", "b", "c", "d", "d"].forEach(m => toast(m)); $("#toasts").children.map(t => t.textContent)') == ["b", "c", "d"]


# Phase 5 Task 4: Back and Forward walk the views (History API). Every view renders to nothing, so a test sees only the router.
NO_VIEWS = "Object.keys(VIEWS).forEach(k => VIEWS[k] = () => {}); "


def test_each_navigation_adds_a_history_entry_once():
    assert in_dom(NO_VIEWS + 'go("vlans"); go("vlans"); go("switches", 3); go("audit"); history.calls') == [
        ["push", "#vlans"], ["replace", "#vlans"], ["push", "#sw=3"], ["push", "#audit"]]


def test_back_and_forward_render_the_view_of_the_hash():
    js = (NO_VIEWS + '$("#app").hidden = false; location.hash = "#sw=3"; window.fire("popstate"); const a = [current, selSwitch]; '
          'location.hash = "#devices"; window.fire("popstate"); [...a, current, history.calls]')
    assert in_dom(js) == ["switches", 3, "devices", []]


def test_a_hash_typed_in_the_address_bar_renders_once():
    assert in_dom('let n = 0; Object.keys(VIEWS).forEach(k => VIEWS[k] = () => { n++; }); $("#app").hidden = false; '
                  'location.hash = "#vlans"; window.fire("popstate"); window.fire("hashchange"); n') == 1


def test_back_closes_an_open_dialog_and_changes_the_view():                           # Review Focus 3
    assert in_dom(NO_VIEWS + '$("#app").hidden = false; modal("Änderung #4", "", []); location.hash = "#vlans"; window.fire("popstate"); '
                  '[$("#modal").hidden, current]') == [True, "vlans"]


def test_back_on_the_login_page_does_nothing():
    assert in_dom(NO_VIEWS + 'location.hash = "#vlans"; window.fire("popstate"); [current, history.calls]') == ["overview", []]


def test_an_old_bookmark_resolves_without_an_extra_history_entry():                   # Review Focus 1
    js = ('(async () => { MAP = {switches: [{id: 7, k: "SW A"}], links: [], vlans: {}}; api = async () => ({name: "x"}); '
          'VIEWS.switches = () => { selSwitch = SVLogic.switchIdOf(MAP.switches, selSwitch); syncHash(); }; await start(); '
          'return [history.calls, location.hash]; })()')
    assert in_dom(js, hash="#switch=SW%20A") == [[["replace", "#switch=SW%20A"], ["replace", "#sw=7"]], "#sw=7"]


@pytest.mark.parametrize("hash, want", [("", "#overview"), ("#%", "#overview"), ("#vlans", "#vlans")])
def test_start_never_pushes(hash, want):
    """No hash and "#%" are not the hash start() shows: a push there would put an extra #overview in front of the page."""
    assert in_dom('(async () => { api = async () => ({name: "x"}); ' + NO_VIEWS + 'await start(); return history.calls; })()',
                  hash=hash) == [["replace", want]]


def test_a_hashchange_alone_renders_the_view_of_the_hash():
    """hashchange on its own, without a popstate before it, shows the view of the hash."""
    assert in_dom(NO_VIEWS + '$("#app").hidden = false; location.hash = "#vlans"; window.fire("hashchange"); [current, history.calls]') == [
        "vlans", []]


def test_the_browser_does_not_restore_the_scroll_position():                           # T4-d
    assert in_dom("history.scrollRestoration") == "manual"


# previewChange with /plan pending until the test answers it (any other call would answer [] at once; since Phase 5 Task 7 the
# preview makes none). The loading dialog has no buttons, so #m-foot lists only those of a dialog opened after it
PENDING_PLAN = (NO_VIEWS + '$("#app").hidden = false; let answer; '
                'api = (m, u) => u.endsWith("/plan") ? new Promise((ok, no) => { answer = [ok, no]; }) : Promise.resolve([]); '
                'const p = previewChange({id: 1, k: "SW A", caps: []}, {mode: "ports", ports: ["1"], change: {untagged: 5}}); ')
PLAN = ('{blocked: [], commands: ["switchport access vlan 5"], warnings: [], summary: "Port 1: VLAN 5", kind: "ports", mechanism: "ssh", '
        'token: "t"}')
SHOWN = '[$("#modal").hidden, $("#app").inert, $("#m-title").textContent, $("#m-foot").children.map(b => b.textContent)]'
BACK = 'location.hash = "#vlans"; window.fire("popstate"); '
ESCAPE = 'document.fire("keydown", {key: "Escape"}); '


@pytest.mark.parametrize("meanwhile, answer, want", [
    ("", "answer[0](%s)" % PLAN, [False, True, "Vorschau", ["Abbrechen", "Ausführen"]]),
    ("", 'answer[1](new Error("SSH: Zeitüberschreitung"))', [False, True, "Vorschau", ["Schließen"]]),
    (BACK, "answer[0](%s)" % PLAN, [True, False, "Vorschau", []]),
    (BACK, 'answer[1](new Error("SSH: Zeitüberschreitung"))', [True, False, "Vorschau", []]),
    (ESCAPE, "answer[0](%s)" % PLAN, [True, False, "Vorschau", []]),
    (ESCAPE + 'modal("Port 2 bearbeiten", "", []); ', "answer[0](%s)" % PLAN, [False, True, "Port 2 bearbeiten", []]),
    ('showLogin(); ', 'answer[1](new Error("Bitte erneut anmelden"))', [True, False, "Vorschau", []])],
    ids=["preview", "error", "back-preview", "back-error", "escape", "escape-other-dialog", "login"])
def test_a_preview_closed_while_the_switch_is_read_stays_closed(meanwhile, answer, want):     # T4-c, Review Focus 3
    """Back, Escape or the login close the loading dialog, or another dialog replaces it: the late answer of /plan opens nothing."""
    assert in_dom('(async () => { ' + PENDING_PLAN + meanwhile + answer + '; await p; return ' + SHOWN + '; })()') == want


# Phase 5 Task 5: the global search is a combobox (WAI-ARIA 1.2): focus stays in #q with aria-activedescendant, the arrows wrap,
# Enter opens, Escape closes; one search runs SEARCH_DELAY after the last keystroke
SEARCH = ('MAP = {switches: [{id: 1, k: "A", sys: "", ports: [{n: "1", a: "drucker-ek", l: [], d: [], mc: 0, tr: ""}, '
          '{n: "2", a: "drucker-vk", l: [], d: [], mc: 0, tr: ""}]}], links: [], vlans: {}}; '
          '$("#q").focus(); $("#q").value = "drucker"; $("#q").fire("input"); await new Promise(r => setTimeout(r, 400)); ')


def test_the_search_is_a_combobox():
    js = ('(async () => { ' + SEARCH + 'return [$("#results").hidden, $("#q").getAttribute("aria-expanded"), '
          '($("#results").innerHTML.match(/role="option"/g) || []).length, /id="hit-1"/.test($("#results").innerHTML)]; })()')
    assert in_dom(js) == [False, "true", 2, True]


def test_arrow_keys_move_the_active_option_and_enter_opens_it():
    js = ('(async () => { ' + SEARCH + NO_VIEWS + 'let opened = null; openPort = (s, n) => { opened = [s.id, n]; }; const q = $("#q"); '
          'q.fire("keydown", {key: "ArrowDown"}); q.fire("keydown", {key: "ArrowDown"}); '
          'const a = [q.getAttribute("aria-activedescendant"), $("#hit-1").getAttribute("aria-selected"), $("#hit-0").getAttribute("aria-selected")]; '
          'q.fire("keydown", {key: "ArrowDown"}); a.push(q.getAttribute("aria-activedescendant")); q.fire("keydown", {key: "Enter"}); '
          'await new Promise(r => setTimeout(r, 50)); return [...a, opened, current, $("#results").hidden, q.getAttribute("aria-expanded")]; })()')
    assert in_dom(js) == ["hit-1", "true", "false", "hit-0", [1, "1"], "switches", True, "false"]


def test_escape_closes_the_results():
    js = ('(async () => { ' + SEARCH + '$("#q").fire("keydown", {key: "Escape"}); '
          'return [$("#results").hidden, $("#q").getAttribute("aria-expanded"), $("#q").getAttribute("aria-activedescendant")]; })()')
    assert in_dom(js) == [True, "false", None]


def test_typing_searches_once_after_a_pause():
    js = ('(async () => { let n = 0; const hits = SVLogic.searchHits; SVLogic.searchHits = (...a) => { n++; return hits(...a); }; ' + SEARCH.replace(
          '$("#q").value = "drucker"; $("#q").fire("input");', '["dr", "dru", "druc", "drucker"].forEach(v => { $("#q").value = v; $("#q").fire("input"); });')
          + 'return n; })()')
    assert in_dom(js) == 1


def test_a_term_too_short_leaves_no_hits_for_the_arrows():
    """Deleting the term below two characters closes the list and forgets its hits: an arrow key does not bring back the hits of a
    text no longer in the field (Chrome's Escape also empties a search field), and moves the field's cursor as without a list."""
    js = ('(async () => { ' + SEARCH + '$("#q").value = "d"; $("#q").fire("input"); await new Promise(r => setTimeout(r, 400)); '
          'const e = $("#q").fire("keydown", {key: "ArrowDown"}); '
          'return [$("#results").hidden, $("#q").getAttribute("aria-expanded"), searchFound.length, e.defaultPrevented]; })()')
    assert in_dom(js) == [True, "false", 0, False]


def test_a_search_that_waited_for_the_netmap_leaves_the_list_to_the_newer_text():
    """The first search after a reload waits for /api/netmap (seconds at hundreds of switches); if the field changed meanwhile, the
    answer does not show the hits of the old text (the search of the new text follows)."""
    js = ('(async () => { let answer; api = () => new Promise(ok => { answer = ok; }); MAP = null; '
          '$("#q").focus(); $("#q").value = "drucker"; $("#q").fire("input"); await new Promise(r => setTimeout(r, 300)); $("#q").value = "drucker-vk"; '
          'answer({switches: [{id: 1, k: "A", sys: "", ports: [{n: "1", a: "drucker-ek", l: [], d: [], mc: 0, tr: ""}]}], links: [], vlans: {}}); '
          'await new Promise(r => setTimeout(r, 50)); return [$("#results").hidden, searchFound.length]; })()')
    assert in_dom(js) == [True, 0]


@pytest.mark.parametrize("close", ['document.fire("keydown", {key: "Escape"}); ', "showLogin(); ", "dropLayers(); ",
                                   'document.fire("click", {target: {closest: () => null}}); '])
def test_every_layer_closer_closes_the_combobox(close):
    """Escape anywhere (onLayerKey), the login page, Back/Forward (dropLayers) and a click outside the search close the list as the
    combobox's own Escape does: aria-expanded and the active option go with it."""
    js = ('(async () => { ' + SEARCH + '$("#q").fire("keydown", {key: "ArrowDown"}); ' + close
          + 'return [$("#results").hidden, $("#q").getAttribute("aria-expanded"), $("#q").getAttribute("aria-activedescendant"), searchActive]; })()')
    assert in_dom(js) == [True, "false", None, -1]


# Task 5 review round 1: the peer test and the search ask the set of switch names (peerSet), and the combobox paths each have a test
def test_only_a_switch_name_makes_an_lldp_neighbour_a_peer():                           # T5-b
    """A nameless LLDP neighbour is no switch, even next to a switch without sysName; k and sys of a switch both count."""
    js = ('MAP = {switches: [{id: 1, k: "A", sys: "", ports: []}, {id: 2, k: "B", sys: "core", ports: []}], links: [], vlans: {}}; '
          '[[["", "1"]], [["A", "1"]], [["core", "1"]], [["x", "1"]]].map(l => isPeer({l}))')
    assert in_dom(js) == [False, True, True, False]


def test_the_search_skips_the_devices_behind_a_switch():                                # T5-b, Review Focus 4
    js = ('(async () => { MAP = {switches: [{id: 1, k: "A", sys: "", ports: ['
          '{n: "1", a: "", l: [["B", "5"]], d: [["aa:bb:cc:00:00:01", "20", "", "hinter-b", "", 0]], mc: 1, tr: ""}, '
          '{n: "2", a: "", l: [], d: [["aa:bb:cc:00:00:02", "20", "", "hinter-b2", "", 0]], mc: 1, tr: ""}]}, '
          '{id: 2, k: "B", sys: "", ports: []}], links: [], vlans: {}}; '
          '$("#q").focus(); $("#q").value = "hinter"; $("#q").fire("input"); await new Promise(r => setTimeout(r, 400)); '
          'return searchFound.map(h => h.port); })()')
    assert in_dom(js) == ["2"]


def test_the_search_field_and_its_list_carry_the_combobox_roles():
    q, res = re.search(r'<input id="q"[^>]*>', INDEX).group(0), re.search(r'<div[^>]*\bid="results"[^>]*>', INDEX).group(0)
    assert all(a in q for a in ('role="combobox"', 'aria-expanded="false"', 'aria-controls="results"', 'aria-autocomplete="list"')), q
    assert all(a in res for a in ('role="listbox"', 'aria-label="Suchtreffer"')), res


OPENED = 'let opened = null; openPort = (s, n) => { opened = [s.id, n]; }; '


def test_a_click_on_a_hit_opens_its_port():
    js = ('(async () => { ' + SEARCH + NO_VIEWS + OPENED
          + '$("#results").fire("click", {target: {closest: s => s === "[data-i]" ? {dataset: {i: "1"}} : null}}); '
          'await new Promise(r => setTimeout(r, 50)); return [opened, current, $("#results").hidden]; })()')
    assert in_dom(js) == [[1, "2"], "switches", True]


def test_a_new_list_has_no_active_hit():
    """An arrow made a hit of the old list active; the list of a new text starts without one, Enter opens nothing."""
    js = ('(async () => { ' + SEARCH + NO_VIEWS + OPENED + 'const q = $("#q"); q.fire("keydown", {key: "ArrowDown"}); '
          'q.fire("keydown", {key: "ArrowDown"}); q.value = "ucker"; q.fire("input"); await new Promise(r => setTimeout(r, 400)); '
          'const a = [q.getAttribute("aria-activedescendant"), searchActive, searchFound.length]; q.fire("keydown", {key: "Enter"}); '
          'await new Promise(r => setTimeout(r, 50)); return [...a, opened]; })()')
    assert in_dom(js) == [None, -1, 2, None]


def test_the_arrows_keep_the_cursor_of_the_field():
    js = ('(async () => { ' + SEARCH + 'const q = $("#q"); return [q.fire("keydown", {key: "ArrowDown"}).defaultPrevented, '
          'q.fire("keydown", {key: "ArrowUp"}).defaultPrevented, q.fire("keydown", {key: "Home"}).defaultPrevented]; })()')
    assert in_dom(js) == [True, True, False]


def test_enter_without_an_active_hit_opens_nothing():
    js = ('(async () => { ' + SEARCH + NO_VIEWS + OPENED + 'const e = $("#q").fire("keydown", {key: "Enter"}); '
          'await new Promise(r => setTimeout(r, 50)); return [opened, e.defaultPrevented, $("#results").hidden]; })()')
    assert in_dom(js) == [None, False, False]


@pytest.mark.parametrize("before, key, then, want", [("", "ArrowDown", "Enter", [[1, "2"], "hit-0"]), ("ArrowDown", "Enter", "", [None, None])],
                         ids=["down-then-enter", "enter-after-a-hit-of-the-old-list"])
def test_a_key_right_after_typing_acts_on_the_list_of_the_new_text(before, key, then, want):
    """The list of "drucker" is shown, "vk" is typed and a key follows before the pause is over: the search of "vk" runs at once.
    Down makes its first hit active (Enter then opens it); Enter opens nothing, not the hit made active in the old list."""
    fire = 'q.fire("keydown", {key: "%s"}); '
    js = ('(async () => { ' + SEARCH + NO_VIEWS + OPENED + 'const q = $("#q"); ' + (fire % before if before else "") + 'q.value = "vk"; '
          'q.fire("input"); ' + fire % key + 'await new Promise(r => setTimeout(r, 0)); const a = q.getAttribute("aria-activedescendant"); '
          + (fire % then if then else "") + 'await new Promise(r => setTimeout(r, 50)); return [opened, a]; })()')
    assert in_dom(js) == want


def test_keys_while_the_search_waits_for_the_netmap_wait_with_it():
    """The search of the field's text waits for /api/netmap (the list shown is of an older text): Down and Enter neither open a hit
    of that list nor fetch the netmap a second time; once the answer is drawn they act on the new list in their order."""
    js = ('(async () => { ' + SEARCH + NO_VIEWS + OPENED + 'let answer, n = 0; api = () => { n++; return new Promise(ok => { answer = ok; }); }; '
          'MAP = null; const q = $("#q"); q.value = "vk"; q.fire("input"); await new Promise(r => setTimeout(r, 300)); '
          'q.fire("keydown", {key: "ArrowDown"}); q.fire("keydown", {key: "Enter"}); await new Promise(r => setTimeout(r, 0)); const a = [opened, n]; '
          'answer({switches: [{id: 1, k: "A", sys: "", ports: [{n: "1", a: "drucker-ek", l: [], d: [], mc: 0, tr: ""}, '
          '{n: "2", a: "drucker-vk", l: [], d: [], mc: 0, tr: ""}]}], links: [], vlans: {}}); await new Promise(r => setTimeout(r, 50)); '
          'return [...a, opened, searchFound.map(h => h.port)]; })()')
    assert in_dom(js) == [None, 1, [1, "2"], ["2"]]


def test_keys_that_waited_for_an_outrun_search_open_nothing():
    """Down and Enter wait for the search of "vk", which waits for the netmap; "vkx" is typed meanwhile, so that search draws
    nothing: the keys act on no list, not on the one still shown and not on the next one."""
    js = ('(async () => { ' + SEARCH + NO_VIEWS + OPENED + 'let answer; api = () => new Promise(ok => { answer = ok; }); MAP = null; '
          'const q = $("#q"); q.value = "vk"; q.fire("input"); await new Promise(r => setTimeout(r, 300)); '
          'q.fire("keydown", {key: "ArrowDown"}); q.fire("keydown", {key: "Enter"}); q.value = "vkx"; q.fire("input"); '
          'answer({switches: [{id: 1, k: "A", sys: "", ports: [{n: "1", a: "drucker-ek", l: [], d: [], mc: 0, tr: ""}, '
          '{n: "2", a: "drucker-vk", l: [], d: [], mc: 0, tr: ""}]}], links: [], vlans: {}}); await new Promise(r => setTimeout(r, 400)); '
          'return [opened, q.getAttribute("aria-activedescendant"), searchFound.length, $("#results").hidden]; })()')
    assert in_dom(js) == [None, None, 0, False]


@pytest.mark.parametrize("to, want", [('$("#btn-logout")', [True, "false"]), ("null", [True, "false"]), ('$("#hit-1")', [False, "true"])],
                         ids=["tab-out", "nowhere", "into-the-list"])
def test_focus_leaving_the_search_closes_the_list(to, want):
    """Tab goes from #q to the next control (the hits take no Tab stop): the list closes with it, as when focus goes nowhere."""
    js = ('(async () => { ' + SEARCH + '$("#results").contains = n => n === $("#hit-0") || n === $("#hit-1"); '
          f'$("#q").fire("focusout", {{relatedTarget: {to}}}); return [$("#results").hidden, $("#q").getAttribute("aria-expanded")]; }})()')
    assert in_dom(js) == want


def test_a_press_on_the_list_keeps_the_focus_in_the_field():
    """A click on a hit does not move the focus out of #q first (which would close the list before the click)."""
    assert in_dom('(async () => { ' + SEARCH + 'return $("#results").fire("mousedown").defaultPrevented; })()') is True


def test_a_search_that_ends_after_the_focus_left_keeps_the_list_closed():
    wait = 'await new Promise(r => setTimeout(r, 400)); '
    js = ('(async () => { ' + SEARCH.replace(wait, '$("#btn-logout").focus(); ' + wait)
          + 'return [$("#results").hidden, $("#q").getAttribute("aria-expanded"), searchFound.length]; })()')
    assert in_dom(js) == [True, "false", 2]


def test_escape_closes_the_list_before_the_field_loses_its_text():
    """The first Escape only closes the list (default prevented: Chrome and Edge empty a type=search field on Escape); with the list
    closed Escape is the browser's again."""
    js = ('(async () => { ' + SEARCH + 'const q = $("#q"), a = q.fire("keydown", {key: "Escape"}), b = q.fire("keydown", {key: "Escape"}); '
          'return [a.defaultPrevented, b.defaultPrevented, $("#results").hidden]; })()')
    assert in_dom(js) == [True, False, True]


# Phase 5 Task 6: the reasons stand in the page, not only in a title (touch and keyboard users see no tooltip), and the hints of a
# partial poll have their tests
UNCONF = 'MAP = {switches: [{id: 1, k: "A", sys: "A", ports: []}, {id: 2, k: "core", sys: "core", ports: []}], links: [], vlans: {}}; '
TAIL = "Eine Verbindung ist nicht erkannt. Ein Gerät am Port kann LLDP und MAC-Adressen fälschen – vor Ort prüfen."
PEER, BM = "Ein LLDP-Nachbar an diesem Port heißt wie ein verwalteter Switch.", "An diesem Port wird die Basis-MAC eines verwalteten Switches gelernt."


@pytest.mark.parametrize("port, want", [
    ({"up": True, "uc": False, "l": [], "tr": ""},
     "Liegt auf einer Verbindung zu einem anderen Switch, die nicht beide Switches bestätigen. Vor Ort prüfen, ob dort wirklich ein Switch steckt."),
    ({"l": [["core", "5"]], "tr": ""}, f"{PEER} {TAIL}"),
    ({"l": [], "bm": True, "tr": ""}, f"{BM} {TAIL}"),
    ({"l": [["core", "5"]], "bm": True, "tr": ""}, f"{PEER} {BM} {TAIL}"),
    ({"up": True, "uc": True, "l": [], "tr": ""}, ""),
    ({"l": [], "tr": "Trk1", "bm": True}, "")])
def test_an_unconfirmed_uplink_says_why(port, want):
    why, pill = in_dom(UNCONF + f"const p = {json.dumps(port)}; [unconfirmedWhy(p), uplinkPill(p)]")
    assert why == want and ((f'title="{want}">Uplink (unbestätigt)' in pill) if want else "unbestätigt" not in pill)


def test_the_port_panel_shows_why_a_port_is_an_unconfirmed_uplink():
    js = (UNCONF + 'const p = {n: "3", l: [], bm: true, tr: "", u: ["1"], t: [], d: [], mc: 0, o: true, ad: true, s: 1000, a: "", pv: "1", st: "", '
          'mb: []}; portIdx = {"3": p}; openPort({id: 1, k: "A", model: "x", caps: [], ports: [p]}, "3"); $("#dr-body").innerHTML')
    html = in_dom(js)
    assert '<dt>Uplink</dt><dd><span class="pill warn">unbestätigt</span> ' + BM in html


LINK = {"a": 1, "b": 2, "an": "A", "bn": "core", "A": {"ports": ["3"], "trunk": "", "speed": 1000}, "B": {"ports": ["5"], "trunk": "", "speed": 1000},
        "onlyA": [], "onlyB": [], "native": []}


@pytest.mark.parametrize("src, confirmed, text", [("mac", True, "<td>MAC-Tabellen</td>"), ("lldp", True, "<td>LLDP (beide Seiten)</td>"),
                                                  ("mac", False, "<td>MAC-Tabellen (unbestätigt)<span class=\"cellnote\">"),
                                                  ("lldp", False, "<td>LLDP (unbestätigt)<span class=\"cellnote\">")])
def test_the_links_table_says_how_a_link_was_found(src, confirmed, text):
    html = in_dom(UNCONF + f"linksTable([{json.dumps({**LINK, 'src': src, 'confirmed': confirmed})}])")
    assert text in html and ("Nicht von beiden Switches bestätigt: A 3, core 5" in html) is (not confirmed)


@pytest.mark.parametrize("ok, error, want", [
    (True, "Teilweise gelesen: fdb fehlgeschlagen", '<div class="banner warn">Abfrage unvollständig: Teilweise gelesen: fdb fehlgeschlagen</div>'),
    (False, "Timeout", '<div class="error">Letzte Abfrage fehlgeschlagen: Timeout</div>'),
    (True, "", None)])
def test_the_switch_view_names_a_partial_or_failed_poll(ok, error, want):              # Phase 3 T10-RR1
    html = in_dom(f"switchBanners({{ok: {json.dumps(ok)}, error: {json.dumps(error)}, caps: ['cli'], ssh: true, cfgAt: '2026-11-06', credWarnings: []}})")
    assert (want in html) if want else ("Abfrage" not in html)


def test_the_overview_groups_a_partial_poll():                                         # Phase 3 T10-RR1
    js = ('MAP = {switches: [{id: 1, k: "A", ok: true, error: "Teilweise gelesen: lldpSys", ports: []}, {id: 2, k: "B", ok: false, error: "x", ports: []}], '
          'links: [], vlans: {}}; issueGroups().map(g => [g.sev, g.t, g.sum, g.items.map(i => i.d)])')
    assert in_dom(js) == [["crit", "Abfrage fehlgeschlagen", "B", ["x"]], ["warn", "Abfrage unvollständig", "A", ["Teilweise gelesen: lldpSys"]]]


def test_an_unread_state_is_named_for_screen_readers():
    assert in_dom('stPill("")') == ('<span class="muted" title="Konfiguration noch nicht gelesen">–<span class="sr-only"> Konfiguration noch nicht '
                                    'gelesen</span></span>')


def test_unknown_device_flags_read_as_text():
    assert in_dom('[Object.keys(UNKNOWN_FLAG_TEXT), UNKNOWN_FLAG_TEXT.uplink_lldp({}), UNKNOWN_FLAG_TEXT.uplink_bm({})]') == [
        ["uplink_lldp", "uplink_bm", "lldp", "many"], "Port gilt als Uplink (unbestätigt)",
        "Port gilt als Uplink (unbestätigt): dort wird die Basis-MAC eines Switches gelernt"]


def test_the_packetfence_reason_is_shown_inline():
    assert in_dom('[pfNote({pf_state: "fehler", pf_error: "HTTP 500 <x>"}), pfNote({pf_state: "ok", pf_error: ""}), '
                  'pfNote({pf_state: "aus", pf_error: "y"})]') == ['<span class="cellnote">HTTP 500 &lt;x&gt;</span>', "", ""]
    js = ('(async () => { ROLES = {configured: true, roles: []}; let cap = null; modal = (t, b) => { cap = b; }; '
          'await editDevice({mac: "aa:bb:cc:00:00:01", name: "Drucker", kind: "drucker", pf_state: "fehler", pf_error: "HTTP 500"}, false); return cap; })()')
    assert '<div class="banner warn"><span><b>PacketFence:</b> HTTP 500</span></div>' in in_dom(js)


SETTINGS_ANSWER = ('{poll_minutes: 15, opnsense_url: "", opnsense_verify_tls: true, radius_server: "", pf_url: "", pf_user: "", pf_verify_tls: true, '
                   'unreadable: ["opnsense_key", "radius_key", "pf_pass"]}')
SETTINGS = ('ME = {name: "x", role: "admin", zones: null, four_eyes: false}; api = async (m, u) => u === "/api/settings" ? ' + SETTINGS_ANSWER
            + ' : u === "/api/zone-scopes" ? {entries: []} : {ok: true, entries: 5, skipped: 2}; await renderSettings(); ')


def test_unreadable_secrets_are_noted_outside_any_label():
    html = in_dom('(async () => { ' + SETTINGS + 'return $("#view").innerHTML; })()')
    assert html.count('<span class="note warn" id="s-') == 3 and 'aria-describedby="s-key-unread"' in html and 'id="s-key-unread"' in html
    assert 'aria-describedby="s-secret-unread"' not in html and 'id="s-pfpass-unread"' in html
    assert not re.search(r"<label\b(?:(?!</label>).)*<p\b", html, re.S)


def test_names_refresh_names_skipped_entries():
    js = ('(async () => { ' + SETTINGS + '$("#s-names").fire("click", {target: $("#s-names")}); await new Promise(r => setTimeout(r, 20)); '
          'return $("#toasts").children.map(t => t.textContent); })()')
    assert in_dom(js) == ["5 Einträge aus der ARP-Tabelle, 2 übersprungen"]


def test_the_shared_secret_keeps_its_hint_as_description():
    """The hint of s-rk left the label with the note (it was part of the field's name): the input names it in aria-describedby, next
    to the note when that is there."""
    html = in_dom('(async () => { ' + SETTINGS + 'return $("#view").innerHTML; })()')
    assert 'aria-describedby="s-rk-hint s-rk-unread"' in html and '<span class="hint" id="s-rk-hint">wie in PacketFence beim Switch hinterlegt</span>' in html


def test_the_device_lists_show_the_packetfence_error_and_the_flags_as_text():
    js = ('(async () => { api = async (m, u) => u === "/api/devices" ? [{mac: "aa:bb:cc:00:00:01", name: "Drucker", kind: "drucker", allowed: 0, '
          'pf_state: "fehler", pf_error: "HTTP 500"}] : u === "/api/pf/roles" ? {configured: true, roles: []} : [{mac: "aa:bb:cc:00:00:02", sw: "A", '
          'sid: 1, port: "3", vlan: "1", st: "", flags: ["uplink_bm"], lldp: "", mc: 2}]; await renderDevices(); '
          'return [$("#dbody").innerHTML, $("#ulist").innerHTML]; })()')
    devices, unknown = in_dom(js)
    assert '<span class="pill crit" title="HTTP 500">Fehler</span><span class="cellnote">HTTP 500</span>' in devices
    assert '<div class="muted">Port gilt als Uplink (unbestätigt): dort wird die Basis-MAC eines Switches gelernt</div>' in unknown


# Phase 5 Task 7: the preview takes autosave and an insecure write identity from the /plan answer (no GET /api/switches); its
# warnings go through warnList. SNMP_PLAN is the brief's PLAN, renamed: PLAN above is the pending-preview fixture of Task 4
SNMP_PLAN = {"kind": "ports", "summary": "Port 2: VLAN 20", "mechanism": "snmp", "commands": ["Port 2: VLAN ungetaggt 99 → 20"],
             "warnings": ["Port 2: VLAN 1 ist das Standard-VLAN"], "blocked": [], "token": "t", "autosave": True, "insecure_write": "v2c"}
PREVIEW = ('(async () => { const calls = []; api = async (m, u) => { calls.push(u); return %s; }; '
           'await previewChange({id: 1, k: "SW", caps: ["cli"]}, {mode: "ports", ports: ["2"], change: {untagged: "20"}}); '
           'return [calls, $("#m-body").innerHTML]; })()')


def test_the_preview_takes_autosave_and_insecurity_from_the_plan_answer():
    calls, html = in_dom(PREVIEW % json.dumps(SNMP_PLAN))
    assert calls == ["/api/switches/1/plan"] and "automatisch gespeichert" in html and "per SNMPv2c, die Community geht im Klartext" in html
    assert '<div class="banner warn"><ul class="blist"><li>Port 2: VLAN 1 ist das Standard-VLAN</li></ul></div>' in html
    calls, html = in_dom(PREVIEW % json.dumps({**SNMP_PLAN, "autosave": False, "insecure_write": None}))
    assert "NICHT dauerhaft gespeichert" in html and "Unsicher" not in html


def test_the_write_hint_names_what_is_wrong():
    assert in_dom('[writeHint({snmp_write_via: "rw"}), writeHint({snmp_write_via: null})]') == [
        "Gespeichert. Hinweis: SNMP schreibt an diesem Switch unsicher – siehe „Zugang bearbeiten“.",
        "Gespeichert. Hinweis: SNMP-Schreiben geht an diesem Switch so nicht – siehe „Zugang bearbeiten“."]
    assert in_dom('[insecureKind({snmp_rw_insecure: true, snmp_write_via: "rw", snmp_rw_user: "rw"}), '
                  'insecureKind({snmp_rw_insecure: true, snmp_write_via: "read", snmp_version: "2c"}), '
                  'insecureKind({snmp_rw_insecure: false})]') == ["v3", "v2c", None]


# Beyond the brief: the save handler of "Zugang bearbeiten" acts on SVLogic.writeAlertMode. SW-HP writes with a v2c community
# (insecure); the form sends what the user typed (%s), the secret fields answer closest(".sec") without the "clr" mark
SAVE_SWITCH = ('(async () => { const shown = []; toast = (m, ms) => shown.push([m, ms == null ? null : ms]); const ended = new Promise(r => { go = r; }); '
               'const S = {id: 1, name: "SW-HP", host: "10.0.0.1", zone: "", sort: 0, enabled: 1, driver: "procurve", snmp_version: "2c", '
               'snmp_write: true, snmp_rw_user: null, snmp_rw_community_set: true, snmp_write_via: "rw", snmp_rw_insecure: true, snmp_write_error: null, '
               'caps: ["cli"]}; api = async (m, u) => u === "/api/drivers" ? [{name: "procurve", caps: ["cli"], notes: ""}] : u === "/api/switches" ? [S] '
               ': m === "PUT" ? {cleared: []} : {}; await editSwitch(S); '
               '["f-comm", "f-apass", "f-ppass", "f-ssh-pass", "f-rwcomm", "f-rwapass", "f-rwppass"]'
               '.forEach(id => { $("#" + id).closest = () => $("#sec"); }); '
               '$("#f-name").value = "SW-HP"; $("#f-host").value = "10.0.0.1"; $("#f-snmpv").value = "2c"; $("#f-driver").value = "procurve"; '
               '$("#f-sw").checked = true; %s $("#m-foot").children.find(b => b.textContent === "Speichern").fire("click"); await ended; '
               'return [shown, $("#modal").hidden, $("#m-title").textContent]; })()')


@pytest.mark.parametrize("typed, want", [
    ('$("#f-zone").value = "Büro";', [[["Gespeichert. Hinweis: SNMP schreibt an diesem Switch unsicher – siehe „Zugang bearbeiten“.", 8000]], True,
                                      "Zugang bearbeiten: SW-HP"]),
    ('$("#f-rwcomm").value = "neu";', [[["Gespeichert", None]], False, "SNMP-Schreiben prüfen: SW-HP"])], ids=["zone-only", "rw-community"])
def test_saving_a_switch_opens_the_write_dialog_only_after_a_write_relevant_change(typed, want):      # R44
    assert in_dom(SAVE_SWITCH % typed) == want


# Phase 5 Task 8: the change lists offer "Trotzdem speichern" (can_save, the server's rule) and "Mehr laden" (limit doubled up to
# 500, the maximum of GET /api/changes); a change that sent nothing reloads only the switch's change list; the audit log filters
# its 200 entries and shows their details (AUDIT: the rows of the filter test in test_frontend_logic.py)

CH = {"created_at": "2026-11-06 10:00:00", "username": "a", "switch_id": 1, "switch_name": "SW", "summary": "Port 2: VLAN 20", "reverted_by": None}
ROWS = [{**CH, "id": 7, "status": "failed", "saved": 0, "can_revert": True, "can_save": True},
        {**CH, "id": 6, "status": "ok", "saved": 1, "can_revert": True, "can_save": False}]
LIST = ('(async () => { ' + ADMIN_ME + 'const calls = []; api = async (m, u) => { calls.push(u); return %s; }; const el = $("#lst"); '
        'await renderChangesInto(el, 1, %d); %s })()')


def test_the_change_list_offers_save_where_the_server_allows_it():
    html = in_dom(LIST % (json.dumps(ROWS), 10, "return el.innerHTML;"))
    assert html.count('data-cs="') == 1 and 'data-cs="7" data-sw="1">Trotzdem speichern</button>' in html and "data-more" not in html


def test_save_in_the_list_opens_the_save_preview():
    act = ('MAP = {switches: [{id: 1, k: "SW"}], links: [], vlans: {}}; let got = null; previewChange = (s, p) => { got = [s.id, p]; }; '
           'await el.onclick({target: {closest: s => s === "[data-cs]" ? {dataset: {cs: "7", sw: "1"}} : null}}); return got;')
    assert in_dom(LIST % (json.dumps(ROWS), 10, act)) == [1, {"mode": "save", "of": 7}]


def test_a_full_list_offers_more_up_to_500():
    assert 'data-more="4"' in in_dom(LIST % (json.dumps(ROWS), 2, "return el.innerHTML;"))
    assert "data-more" not in in_dom(LIST % (json.dumps(ROWS * 250), 500, "return el.innerHTML;"))
    more = 'await el.onclick({target: {closest: s => s === "[data-more]" ? {dataset: {more: "4"}} : null}}); return calls;'
    assert in_dom(LIST % (json.dumps(ROWS), 2, more)) == ["/api/changes?limit=2&switch_id=1", "/api/changes?limit=4&switch_id=1"]


def test_the_audit_shows_details_and_filters():
    js = ('(async () => { api = async (m, u) => u === "/api/audit" ? %s : []; await renderAudit(); const a = [$("#au-body").innerHTML]; '
          '$("#au-q").value = "bob"; $("#au-q").fire("input"); a.push($("#au-body").innerHTML); return [...a, $("#view").innerHTML]; })()') % json.dumps(AUDIT)
    full, bob, view = in_dom(js)
    assert '<span class="cellnote">host: 10.0.0.1 → 10.0.0.2</span>' in full and full.count("<tr") == 3
    assert bob.count("<tr") == 1 and "<td>bob</td><td>–</td><td>Anmeldung</td>" in bob    # Phase 4a Task 8: the role between user and action
    assert view.count('<option value="login">Anmeldung</option>') == 1 and '<option value="">Alle Aktionen</option>' in view


RUN = ('(async () => { ' + ADMIN_ME + 'const seen = []; MAP = {switches: [{id: 1, k: "SW"}], links: [], vlans: {}}; current = "switches"; selSwitch = 1; '
       'loadMap = async () => { seen.push("map"); }; renderSwitchDetail = () => { seen.push("view"); }; syncPicked = () => {}; '
       'renderChangesInto = async (el, id, n) => { seen.push(["list", id, n]); }; '
       'api = async () => (%s); await runProgress({id: 1, k: "SW"}, 4); await new Promise(r => setTimeout(r, 300)); return seen; })()')
DONE = {"id": 4, "summary": "Port 2: Aus", "steps": [], "can_revert": False, "can_save": False, "mechanism": "ssh", "error": "x"}


@pytest.mark.parametrize("c, want", [({**DONE, "status": "failed", "sent": 0, "kind": "ports", "saved": 0}, [["list", 1, 10]]),
                                     ({**DONE, "status": "ok", "sent": 1, "kind": "save", "saved": 1, "error": None}, ["map", "view"])])
def test_a_change_that_sent_nothing_reloads_only_its_list(c, want):
    assert in_dom(RUN % json.dumps(c)) == want


# Beyond the brief: "Mehr laden" is replaced with the list it reloads, so the focus would fall to body (Review Focus 2); it moves to
# the first row the click added, or to the last row when the API had no more. The stub's querySelectorAll answers el.kids.
@pytest.mark.parametrize("kids, want", [('[$("#d7"), $("#d6"), $("#d5")]', "#d5"), ('[$("#d7"), $("#d6")]', "#d6")], ids=["added", "none-added"])
def test_more_gives_the_focus_to_the_first_row_it_added(kids, want):
    act = ('el.kids = %s; await el.onclick({target: {closest: s => s === "[data-more]" ? {dataset: {more: "4"}} : null}}); '
           'return document.activeElement && document.activeElement.sel;') % kids
    assert in_dom(LIST % (json.dumps(ROWS), 2, act)) == want


# Beyond the brief: the action filter redraws on change (the text filter above on input), a filter without hits shows its row, and
# a change that sent nothing leaves the list alone when the view shows another switch or another view
def test_the_audit_filters_by_action_and_says_when_nothing_is_left():
    js = ('(async () => { api = async (m, u) => u === "/api/audit" ? %s : []; await renderAudit(); const a = []; '
          'const q = t => { $("#au-q").value = t; $("#au-q").fire("input"); a.push($("#au-body").innerHTML); }; '
          '$("#au-act").value = "login"; $("#au-act").fire("change"); a.push($("#au-body").innerHTML); q(" BOB "); q("anna"); '
          'return a; })()') % json.dumps(AUDIT)
    login, bob, none = in_dom(js)
    assert login.count("<tr") == 1 and "<td>bob</td><td>–</td><td>Anmeldung</td>" in login and bob == login    # the text is trimmed
    assert none == '<tr><td colspan="5" class="muted">Keine Einträge für diesen Filter.</td></tr>'


def test_more_never_asks_for_more_than_500():
    assert 'data-more="500"' in in_dom(LIST % (json.dumps(ROWS * 150), 300, "return el.innerHTML;"))


@pytest.mark.parametrize("where", ['current = "switches"; selSwitch = 2;', 'current = "audit"; selSwitch = 1;'], ids=["other-switch", "other-view"])
def test_a_change_that_sent_nothing_leaves_another_view_alone(where):
    c = {**DONE, "status": "failed", "sent": 0, "kind": "ports", "saved": 0}
    assert in_dom(RUN.replace('current = "switches"; selSwitch = 1;', where) % json.dumps(c)) == []


# Phase 5 Task 9: a whole trunk is edited from the port panel, its VLANs only and in expert mode (Logik Phase 5, A2 there). The trunk
# Trk1 (members 5, 6) sits untagged in VLAN 1 and tagged in 20; the switch has VLANs 1, 20, 30. modal is replaced to read the form back.
TRK = (ADMIN_ME + 'MAP = {switches: [], links: [], vlans: {"1": "default", "20": "Clients", "30": "Voice"}}; '
       'const trk = {n: %s, u: ["1"], t: ["20"], tr: %s, mb: ["5", "6"], l: [], d: [], mc: 0, o: true, ad: true, s: 2000, a: "", pv: "1", st: ""}; '
       'portIdx = {[trk.n]: trk}; const sw = {id: 1, k: "SW", ssh: true, caps: ["cli", "nac"], vl: ["1", "20", "30"], ports: [trk]}; '
       'let cap = null; modal = (t, b, btns) => { cap = {t, b, btns}; }; ')


def trk(name="Trk1"):
    return TRK % (json.dumps(name), json.dumps(name))


def test_a_trunk_opens_its_own_form_with_vlans_only():
    t, b, labels = in_dom(trk() + 'editTrunk(sw, "Trk1"); [cap.t, cap.b, cap.btns.map(x => x.label)]')
    assert t == "Trunk Trk1 bearbeiten" and labels == ["Abbrechen", "Vorschau"]
    assert all(x in b for x in ('id="f-u"', 'data-ta="30"', 'data-tr="20"', 'id="f-expert"', 'id="f-gate-trk"'))
    assert not any(x in b for x in ('name="f-st"', 'id="f-name"', 'id="f-poe"', 'id="f-lim"', 'id="f-guest"'))


def test_trunk_payload():
    assert in_dom('[trunkPayload("Trk1", "20", ["30"], [], true), trunkPayload("Trk1", "", [], ["20"], false), trunkPayload("Po1", "", [], [], 1)]') == [
        {"mode": "ports", "ports": ["Trk1"], "change": {"untagged": "20", "tagged_add": ["30"]}, "expert": True},
        {"mode": "ports", "ports": ["Trk1"], "change": {"tagged_remove": ["20"]}, "expert": False},
        {"mode": "ports", "ports": ["Po1"], "change": {}, "expert": True}]


def test_a_trunk_preview_needs_expert_mode():
    js = (trk() + 'let got = null; previewChange = (s, p) => { got = p; }; editTrunk(sw, "Trk1"); $("#f-u").value = "20"; cap.btns[1].onClick(); '
          'const a = [$("#toasts").children.map(t => t.textContent), got]; $("#f-expert").checked = true; cap.btns[1].onClick(); [...a, got]')
    assert in_dom(js) == [["Für einen Trunk den Expertenmodus einschalten"], None,
                          {"mode": "ports", "ports": ["Trk1"], "change": {"untagged": "20"}, "expert": True}]


@pytest.mark.parametrize("trunk, port, label", [("Trk1", "Trk1", "Trunk bearbeiten"), ("Trk1", "5", "Port bearbeiten"),
                                                ("Po1", "Po1", "Trunk bearbeiten"), ("Po1", "5", "Port bearbeiten")],
                         ids=["trk", "trk-member", "lag", "lag-member"])
def test_the_port_panel_offers_trunk_editing(trunk, port, label):
    """A ProCurve trunk by its name (TrkN), a LAG (Po1, ae0, ...) by its trunk being itself (isTrunkPort); a member port keeps the port form."""
    js = trk(trunk) + ('const m = {n: "5", u: [], t: [], tr: %s, mb: [], l: [], d: [], mc: 0, o: true, ad: true, s: 1000, a: "", pv: "", st: ""}; '
                       'portIdx["5"] = m; sw.ports.push(m); openPort(sw, %s); $("#dr-body").innerHTML') % (json.dumps(trunk), json.dumps(port))
    assert f'id="dr-edit">{label}</button>' in in_dom(js)


def test_a_trunk_form_escapes_its_name():                                               # Review Focus 5
    """The trunk's name and its members' names (a LAG member is named by the switch, Gi1/0/1 or anything else)."""
    b = in_dom(trk('Po"<1') + 'trk.mb = ["Gi1/0/1", "x\\"<y"]; editTrunk(sw, \'Po"<1\'); cap.b')
    assert "Po&quot;&lt;1" in b and 'Po"<1' not in b
    assert "Gi1/0/1, x&quot;&lt;y" in b and 'x"<y' not in b


# Beyond the brief: the panel's button opens the form of its port (the brief pins the label only), "Vorschau" with nothing chosen,
# "Zurück" from the preview brings the form back as it was (chips read through the stub's document.lists), a click toggles a chip,
# and vlanChipButtons keeps the markup of editPorts' former local chipBtns (a member port's chips carry its gate)
@pytest.mark.parametrize("port, title", [("Trk1", "Trunk Trk1 bearbeiten"), ("5", "Port 5 bearbeiten")])
def test_the_panel_button_opens_the_form_of_its_port(port, title):
    js = trk() + ('const m = {n: "5", u: [], t: [], tr: "Trk1", mb: [], l: [], d: [], mc: 0, o: true, ad: true, s: 1000, a: "", pv: "", st: ""}; '
                  'portIdx["5"] = m; sw.ports.push(m); openPort(sw, %s); $("#dr-edit").fire("click"); '
                  '[cap && cap.t, $("#drawer").classList.contains("open")]') % json.dumps(port)
    assert in_dom(js) == [title, False]


def test_a_trunk_preview_needs_a_field():
    js = (trk() + 'let got = null; previewChange = (s, p) => { got = p; }; editTrunk(sw, "Trk1"); $("#f-expert").checked = true; '
          'cap.btns[1].onClick(); [$("#toasts").children.map(t => t.textContent), got]')
    assert in_dom(js) == [["Nichts ausgewählt, was sich ändern soll"], None]


def test_back_from_the_trunk_preview_keeps_the_form():
    js = (trk() + 'let got = null, back = null; previewChange = (s, p, b) => { got = p; back = b; }; editTrunk(sw, "Trk1"); '
          'document.lists["[data-ta][aria-pressed=true]"] = [{dataset: {ta: "30"}}]; document.lists["[data-tr][aria-pressed=true]"] = [{dataset: {tr: "20"}}]; '
          '$("#f-u").value = "1"; $("#f-expert").checked = true; cap.btns[1].onClick(); back(); [got, cap.t, cap.b]')
    got, t, b = in_dom(js)
    assert got == {"mode": "ports", "ports": ["Trk1"], "change": {"untagged": "1", "tagged_add": ["30"], "tagged_remove": ["20"]}, "expert": True}
    assert t == "Trunk Trk1 bearbeiten"
    assert all(x in b for x in ('<option value="1" selected>', 'data-ta="30" aria-pressed="true"', 'data-tr="20" aria-pressed="true"',
                                'id="f-expert" checked>'))
    assert 'data-ta="20" aria-pressed="false"' in b and '<option value="20" selected>' not in b


def test_a_click_on_a_chip_of_the_trunk_form_toggles_it():
    js = (trk() + 'editTrunk(sw, "Trk1"); const c = $("#chip"); c.setAttribute("aria-pressed", "false"); '
          'const click = () => $("#m-body").onclick({target: {closest: s => s === "[data-ta],[data-tr]" ? c : null}}); '
          'click(); const a = c.getAttribute("aria-pressed"); click(); [a, c.getAttribute("aria-pressed")]')
    assert in_dom(js) == ["true", "false"]


def test_vlan_chip_buttons_keep_the_markup_of_the_port_form():
    js = (trk() + 'const m = {n: "5", u: [], t: [], tr: "Trk1", mb: [], l: [], d: [], mc: 0, o: true, ad: true, s: 1000, a: "", pv: "", st: ""}; '
          'portIdx["5"] = m; editPorts(sw, ["5"]); [vlanChipButtons(["20"], ["20"], "ta"), vlanChipButtons([], [], "tr"), cap.b]')
    chip, none, form = in_dom(js)
    assert chip == ('<div class="chipset"><button type="button" class="vchip small" data-ta="20" aria-pressed="true" style="--vc:hsl(220 55% 50%)">'
                    '<i class="sw"></i><span class="id">20</span><span class="nm">Clients</span></button></div>')
    assert none == '<span class="muted" style="font-size:12.5px">keine</span>'
    assert 'data-ta="30" aria-pressed="false" style="--vc:hsl(330 55% 50%)" disabled aria-describedby="f-gate-mem">' in form   # a member's gate


@pytest.mark.parametrize("error, want", [("Abgebrochen (Prozess beendet), nichts gesendet", "<b>Abgebrochen:</b> Prozess beendet, nichts gesendet"),
                                         ("Abgebrochen durch Neustart von SwitchView, nichts gesendet",
                                          "<b>Abgebrochen:</b> durch Neustart von SwitchView, nichts gesendet"),
                                         ("Abgebrochen (Prozess beendet", "<b>Abgebrochen:</b> (Prozess beendet")])    # Phase 5 review, Minor 8
def test_an_aborted_change_reads_once_as_aborted(error, want):
    assert want in in_dom(f'resultHead({{status: "aborted", error: {json.dumps(error)}, steps: []}})')


# Phase 5 Task 11: what the browser check found. A switch whose poll read no firmware (every sysDescr but a ProCurve's, poller.
# parse_descr) or no model (a switch that never answered) showed empty parts in its meta line ("Firmware  ·", "SW-HP ·"); and a
# focused button stayed inside the panel while closeDrawer hid it, which Chrome refuses ("Blocked aria-hidden on an element because
# its descendant retained focus", "Als Gerät anlegen": the device form opens only after /api/pf/roles answers).
@pytest.mark.parametrize("sw, meta, card", [
    ({"zone": "Büro", "model": "J9729A 2920-48G-POE+", "fw": "WB.16.99.0001"},
     'Büro · J9729A 2920-48G-POE+ · Firmware <span class="mono">WB.16.99.0001</span> · ', 'J9729A 2920-48G-POE+ · <span class="mono">WB.16.99.0001</span>'),
    ({"zone": "", "model": "Cisco IOS Software, C2960X Software (C29", "fw": ""}, "Cisco IOS Software, C2960X Software (C29 · ",
     "Cisco IOS Software, C2960X Software (C29"),
    ({"zone": "Büro", "model": "", "fw": ""}, "Büro · ", ""),
    ({"zone": "", "model": "", "fw": ""}, "", ""),
    ({"zone": "<z>", "model": "<m>", "fw": "<f>"}, '&lt;z&gt; · &lt;m&gt; · Firmware <span class="mono">&lt;f&gt;</span> · ',
     '&lt;m&gt; · <span class="mono">&lt;f&gt;</span>')],
    ids=["procurve", "no-firmware", "no-model", "nothing", "escaped"])
def test_the_meta_line_names_only_what_the_poll_read(sw, meta, card):
    s = {**sw, "host": "192.0.2.11", "driver": "procurve", "lastPoll": None}
    got_meta, got_card = in_dom(f"const s = {json.dumps(s)}; [switchMeta(s), modelFw(s)]")
    assert got_meta == meta + '<span class="mono">192.0.2.11</span> · Treiber <span class="mono">procurve</span> · Stand –' and got_card == card


@pytest.mark.parametrize("model, sub", [("x", "A · x"), ("", "A")])
def test_the_panel_subtitle_names_the_model_only_when_known(model, sub):
    assert in_dom(PANEL + 'openPort({id: 1, k: "A", model: %s, caps: [], ports: []}, "1"); $("#dr-sub").textContent' % json.dumps(model)) == sub


@pytest.mark.parametrize("focused, want", [("#dr-x", ["false", "body"]), ("#q", [None, "#q"])])
def test_closing_the_panel_takes_the_focus_out_of_it_first(focused, want):
    """The focus leaves the panel before aria-hidden="true" is set on it; a focus outside the panel stays where it is."""
    js = (PANEL + OPEN_PANEL + '$("#drawer").contains = n => n === $("#dr-x"); %s.focus(); let hid = null; '
          '$("#dr-x").blur = () => { hid = $("#drawer").getAttribute("aria-hidden"); document.activeElement = document.body; }; '
          'closeDrawer(true); [hid, document.activeElement.sel]') % f'$("{focused}")'
    assert in_dom(js) == want


# Phase 5 final review: the focus after a dialog. The port tile the panel came from (drLast) takes the focus back once, when the
# panel or the dialog chain it started closes; a later dialog whose opener left the DOM (a change list re-rendered after a change
# that sent nothing) gives the focus to #view, not to that tile. go() forgets the tile with the view it leaves.
TILE = PANEL + 'const t = $("#tile"); t.focus(); openPort({id: 1, k: "A", model: "x", caps: [], ports: []}, "1", t); '
LIST_DIALOG = ('const b = $("#list-btn"); b.focus(); modal("Änderung #7", "", []); b.isConnected = false; closeModal(); '
               'a.push(document.activeElement.sel); a')


@pytest.mark.parametrize("used, want", [
    ("closeDrawer(); a.push(document.activeElement.sel); ", ["#tile", "#view"]),
    ('closeDrawer(true); document.body.focus(); modal("Port 1 bearbeiten", "", []); closeModal(); a.push(document.activeElement.sel); ',
     ["#tile", "#view"]),
    (NO_VIEWS + 'go("vlans"); ', ["#view"])], ids=["panel-closed", "dialog-chain-from-the-panel", "navigation"])
def test_the_tile_takes_the_focus_back_only_once(used, want):                             # Review Focus 2
    assert in_dom(TILE + "const a = []; " + used + LIST_DIALOG) == want


def test_a_dialog_over_the_open_panel_leaves_the_tile_to_the_panel():
    """A dialog whose opener is live (here a control in the open panel) takes the focus back there; the tile stays the panel's."""
    js = (TILE + 'const a = []; const x = $("#dr-x"); x.focus(); modal("T", "", []); closeModal(); a.push(document.activeElement.sel); '
          'closeDrawer(); a.push(document.activeElement.sel); a')
    assert in_dom(js) == ["#dr-x", "#tile"]


# A dialog without a field or a footer button (the preview's loading dialog) takes the focus itself (.modal, tabindex -1): the
# focus would stay on its opener, inert behind the dialog. With a control the first one takes it, as before.
FIRST_CONTROL = "#m-body input, #m-body select, #m-foot .btn"


@pytest.mark.parametrize("control, want", [("", ".modal"), (f'document.els["{FIRST_CONTROL}"] = $("#f-u"); ', "#f-u")],
                         ids=["none", "a-field"])
def test_a_dialog_gives_the_focus_to_its_first_control_else_to_itself(control, want):
    assert in_dom(control + '$("#opener").focus(); modal("Vorschau", "<div class=\\"empty\\">Lese …</div>", []); document.activeElement.sel') == want


# runProgress replaces the footer once the change has ended: the focused "Schließen" goes with the old one, and in a browser the focus
# falls to body while the dialog stays open. It moves to the new "Schließen" then; a focus still in the dialog (the ✕) stays, and
# a dialog closed meanwhile takes none. The stub's .modal contains only the ✕ (#m-x).
PROGRESS = ('(async () => { current = "audit"; api = async () => (%s); const x = $("#m-x"); $(".modal").contains = n => n === x; '
            'const p = runProgress({id: 1, k: "SW"}, 4); %s await p; const f = document.activeElement; return [f.sel, f.textContent]; })()')
FAILED_UNSENT = {**DONE, "status": "failed", "sent": 0, "kind": "ports", "saved": 0, "can_revert": False, "can_save": False}


@pytest.mark.parametrize("meanwhile, want", [("document.body.focus();", ["<button>", "Schließen"]), ("x.focus();", ["#m-x", ""]),
                                             ("document.body.focus(); closeModal();", ["#view", ""])],
                         ids=["focus-fell-to-body", "focus-on-the-close-button", "closed-meanwhile"])
def test_the_result_of_a_change_keeps_the_focus_in_its_dialog(meanwhile, want):
    assert in_dom(PROGRESS % (json.dumps(FAILED_UNSENT), meanwhile)) == want


# Phase 5 final review: Escape closes the list for the text in the field, also while its search still waits. The list of "drucker"
# is shown and "vk" typed: Escape within the pause keeps the text (default prevented) and the list stays closed when the pause is
# over; so does a search that waits for /api/netmap. An arrow key after Escape runs that search and opens its list.
NETMAP_VK = ('{switches: [{id: 1, k: "A", sys: "", ports: [{n: "1", a: "drucker-ek", l: [], d: [], mc: 0, tr: ""}, '
             '{n: "2", a: "drucker-vk", l: [], d: [], mc: 0, tr: ""}]}], links: [], vlans: {}}')


def test_escape_during_the_pause_keeps_the_list_closed():
    js = ('(async () => { ' + SEARCH + 'const q = $("#q"); q.value = "vk"; q.fire("input"); const e = q.fire("keydown", {key: "Escape"}); '
          'await new Promise(r => setTimeout(r, 400)); return [e.defaultPrevented, $("#results").hidden, q.getAttribute("aria-expanded"), q.value]; })()')
    assert in_dom(js) == [True, True, "false", "vk"]


def test_escape_while_the_search_waits_for_the_netmap_keeps_the_list_closed():
    js = ('(async () => { ' + SEARCH + 'let answer; api = () => new Promise(ok => { answer = ok; }); MAP = null; const q = $("#q"); '
          'q.value = "vk"; q.fire("input"); await new Promise(r => setTimeout(r, 300)); q.fire("keydown", {key: "Escape"}); '
          f'answer({NETMAP_VK}); await new Promise(r => setTimeout(r, 50)); const a = [$("#results").hidden, searchFound.map(h => h.port)]; '
          'q.fire("keydown", {key: "ArrowDown"}); await new Promise(r => setTimeout(r, 0)); '
          'return [...a, $("#results").hidden, q.getAttribute("aria-activedescendant")]; })()')
    assert in_dom(js) == [True, ["2"], False, "hit-0"]


def test_an_arrow_after_escape_runs_the_search_of_the_field():
    js = ('(async () => { ' + SEARCH + 'const q = $("#q"); q.value = "vk"; q.fire("input"); q.fire("keydown", {key: "Escape"}); '
          'q.fire("keydown", {key: "ArrowDown"}); await new Promise(r => setTimeout(r, 50)); '
          'return [$("#results").hidden, q.getAttribute("aria-activedescendant"), searchFound.map(h => h.port)]; })()')
    assert in_dom(js) == [False, "hit-0", ["2"]]


# Phase 5 final review: a preview whose ports are all blocked (every LAG trunk on a driver that cannot write its VLANs by SNMP) says
# why, not also that there is nothing to change; a plan without commands and without a block still says that
BLOCKED = {**SNMP_PLAN, "commands": [], "warnings": [], "blocked": [{"port": "Po1", "reason": "Trunk-VLANs per SNMP gehen an diesem Treiber nicht"}]}


@pytest.mark.parametrize("plan, blocked, nothing", [(BLOCKED, True, False), ({**BLOCKED, "blocked": []}, False, True)], ids=["blocked", "nothing-to-do"])
def test_a_blocked_preview_does_not_say_there_is_nothing_to_change(plan, blocked, nothing):
    calls, html = in_dom(PREVIEW % json.dumps(plan))
    assert ("<b>Nicht möglich:</b>" in html) is blocked and ("Es gibt nichts zu ändern" in html) is nothing
    assert in_dom(PREVIEW.replace("return [calls, $(\"#m-body\").innerHTML];", "return $(\"#m-foot\").children.map(b => b.textContent);")
                  % json.dumps(plan)) == ["Abbrechen"]


# Phase 4a Task 1: the test gaps of Phase 5 ("Später → Phase 4" in docs/ux-phase5.md) and the open Minor findings of its final
# review. The wiring pins hold behaviour the Phase 5 browser check saw (each dies under its mutation, see the Phase 4a note);
# runProgress writing into a newer dialog and the port panel naming a LAG "Port Po1" were real bugs.
def test_a_repeated_message_restarts_its_timer():                                      # UX Phase 5, Später
    assert in_dom('(async () => { toast("a", 80); await new Promise(r => setTimeout(r, 50)); toast("a", 200); '
                  'await new Promise(r => setTimeout(r, 60)); return $("#toasts").children.length; })()') == 1


def test_an_arrow_in_the_pause_runs_the_search_once():                                 # startSearch's clearTimeout, sync preventDefault
    js = ('(async () => { ' + SEARCH + 'const q = $("#q"); q.value = "vk"; q.fire("input"); const e = q.fire("keydown", {key: "ArrowDown"}); '
          'const sync = e.defaultPrevented; await new Promise(r => setTimeout(r, 400)); return [sync, q.getAttribute("aria-activedescendant")]; })()')
    assert in_dom(js) == [True, "hit-0"]


POE_PREVIEW = ('(async () => { api = async () => (%s); await previewChange({id: 1, k: "SW", caps: %s}, '
               '{mode: "ports", ports: ["2"], change: {poe: true}}); return $("#m-body").innerHTML; })()')


@pytest.mark.parametrize("caps, said", [('["cli"]', True), ("[]", False)])
def test_the_poe_note_names_ssh_only_on_a_driver_with_cli(caps, said):
    assert ("PoE schaltet SwitchView immer per SNMP, auch wenn SSH geht." in in_dom(POE_PREVIEW % (json.dumps(SNMP_PLAN), caps))) == said


def body_of(script: str, fn: str) -> str:
    text = (STATIC / script).read_text(encoding="utf-8")
    start = text.index(f"function {fn}(")
    return text[start:text.index("\n  }\n", start)]


def test_the_switch_view_and_the_card_use_the_shared_builders():                       # Pin (browser-checked in Phase 5)
    head = body_of("sv-switch.js", "renderSwitchDetail")
    assert "${switchMeta(s)}" in head and "${switchBanners(s)}" in head and "modelFw(s)" in body_of("sv-overview.js", "renderOverview")


def test_an_old_progress_never_writes_into_a_newer_dialog():                           # Phase 5 review, Minor 1
    running = {**DONE, "status": "running"}
    done = {**DONE, "status": "ok", "saved": 1, "sent": 1, "kind": "ports", "error": None}
    js = ('(async () => { MAP = {switches: [{id: 1, k: "SW"}], links: [], vlans: {}}; current = "audit"; loadMap = async () => {}; '
          'let n = 0; api = async () => (n++ ? %s : %s); const run = runProgress({id: 1, k: "SW"}, 5); await new Promise(r => setTimeout(r, 50)); '
          'modal("Änderung #6", "", []); $("#prog").innerHTML = "sechs"; await run; '
          'return [$("#prog").innerHTML, $("#toasts").children.map(t => t.textContent)]; })()') % (json.dumps(done), json.dumps(running))
    assert in_dom(js) == ["sechs", ["Änderung erledigt"]]


@pytest.mark.parametrize("port, title, row", [
    ({"n": "Po1", "tr": "Po1", "mb": ["Gi1/0/1", "Gi1/0/2"]}, "Po1", "Ports Gi1/0/1, Gi1/0/2"),
    ({"n": "Trk1", "tr": "", "mb": ["5", "6"]}, "Trk1", "Ports 5, 6"),
    ({"n": "Gi1/0/1", "tr": "Po1", "mb": []}, "Port Gi1/0/1", "Po1")], ids=["lag", "trk", "member"])
def test_the_panel_names_a_lag_as_a_trunk(port, title, row):                          # Phase 5 review, Minor 6
    p = {"l": [], "d": [], "u": [], "t": [], "mc": 0, "a": "", "pv": "", "st": "", "o": True, "ad": True, "s": 1000, **port}
    t, html = in_dom(f'MAP = {{switches: [], links: [], vlans: {{}}}}; portIdx = {{{json.dumps(p["n"])}: {json.dumps(p)}}}; '
                     f'openPort({{id: 1, k: "A", caps: [], ports: []}}, {json.dumps(p["n"])}); [$("#dr-title").textContent, $("#dr-body").innerHTML]')
    assert t == title and f"<dt>Trunk</dt><dd>{row}</dd>" in html


def test_a_failed_reload_of_more_keeps_the_focus_in_the_list():                        # Phase 5 review, Minor 3
    act = ('api = async () => { throw new Error("weg"); }; el.kids = []; '
           'await el.onclick({target: {closest: s => s === "[data-more]" ? {dataset: {more: "4"}} : null}}); '
           'return [document.activeElement && document.activeElement.sel, el.getAttribute("tabindex"), el.innerHTML];')
    assert in_dom(LIST % (json.dumps(ROWS), 2, act)) == ["#lst", "-1", '<div class="empty">weg</div>']


def test_the_audit_keeps_its_filter_across_a_new_render():                            # Phase 5 review, Minor 7
    js = ('(async () => { api = async (m, u) => u === "/api/audit" ? %s : []; await renderAudit(); $("#au-q").value = "bob"; $("#au-q").fire("input"); '
          '$("#au-act").value = "login"; $("#au-act").fire("change"); await renderAudit(); return $("#view").innerHTML; })()') % json.dumps(AUDIT)
    html = in_dom(js)
    assert ('id="au-q" placeholder="Benutzer, Aktion, Ziel, Details" aria-label="Protokoll durchsuchen" value="bob"' in html
            and '<option value="login" selected>' in html)


# Phase 4a Task 8: the header names the user and the role; each view hides or locks what the role or the zone does not allow and
# says why in one sentence; the audit log shows the role; a 401 shows the server's reason on the login page; an Admin keeps the zones
def role_me(role, **k):
    return f"ME = {json.dumps({'name': 'Anna', 'role': role, 'zones': None, 'four_eyes': False, **k})}; "


def test_the_header_names_the_user_and_the_role():
    js = (NO_VIEWS + '(async () => { api = async (m, u) => u === "/api/auth/me" ? {name: "Anna", role: "freigeben", zones: null, four_eyes: false} : []; '
          'await start(); return [$("#user-name").textContent, $("#user-role").textContent]; })()')
    assert in_dom(js) == ["Anna", "Freigeben"]


def test_a_401_shows_the_servers_reason_on_the_login_page():
    js = ('(async () => { fetch = async () => ({status: 401, ok: false, headers: {get: () => "application/json"}, '
          'json: async () => ({detail: "Abgemeldet nach 120 Minuten ohne Aktivität – bitte neu anmelden"})}); '
          'await api("GET", "/api/netmap").catch(() => {}); return [$("#login").hidden, $("#login-error").textContent]; })()')
    assert in_dom(js) == [False, "Abgemeldet nach 120 Minuten ohne Aktivität – bitte neu anmelden"]


# Beyond the brief, a pin of today's behaviour: "Nicht angemeldet" is no news on the login page (no text, the error line stays
# hidden), and an answer without JSON shows the login page without a reason instead of failing
@pytest.mark.parametrize("headers, body", [('"application/json"', '({detail: "Nicht angemeldet"})'), ('"text/plain"', '"x"')], ids=["not-signed-in", "no-json"])
def test_a_401_without_news_shows_no_reason(headers, body):
    js = ('(async () => { fetch = async () => ({status: 401, ok: false, headers: {get: () => %s}, json: async () => %s, text: async () => "x"}); '
          'const e = await api("GET", "/api/netmap").catch(x => x.message); '
          'return [$("#login").hidden, $("#login-error").hidden, $("#login-error").textContent, e]; })()') % (headers, body)
    assert in_dom(js) == [False, True, "", "Bitte erneut anmelden"]


SW = {"id": 1, "k": "SW", "zone": "VK", "ssh": True, "caps": ["cli", "nac"], "ok": True, "error": "", "credWarnings": [], "cfgAt": "2026-11-07", "ports": []}


@pytest.mark.parametrize("me, why", [(("lesen",), "Deine Rolle „Lesen“ kann hier nur ansehen. Ändern braucht die Rolle „Ändern“."),
                                     (("aendern",), ""),
                                     (("aendern", ["EK"]), "Dieser Switch liegt in der Zone „VK“. Du darfst nur an Switches der Zonen „EK“ ändern.")])
def test_the_switch_view_says_why_the_user_may_not_change(me, why):
    role, *zones = me
    html = in_dom(role_me(role, zones=zones[0] if zones else None) + f"switchBanners({json.dumps(SW)})")
    assert (f'<div class="banner">{why}</div>' in html) == bool(why) and ('data-a="edit"' in html) is False


@pytest.mark.parametrize("role, button", [("admin", True), ("freigeben", False)])
def test_edit_access_is_admin_only(role, button):
    assert ('data-a="edit"' in in_dom(role_me(role) + "editAccess()")) == button
    assert in_dom(role_me("lesen") + "editAccess(true)") == '<span class="muted">„Zugang bearbeiten“ braucht die Rolle „Admin“.</span>'


@pytest.mark.parametrize("role, four, edit", [("lesen", False, False), ("aendern", False, True), ("aendern", True, True)])
def test_the_port_panel_offers_editing_by_role(role, four, edit):
    html = in_dom(PANEL + role_me(role, four_eyes=four) + 'openPort({id: 1, k: "A", model: "x", ssh: true, caps: ["cli"], ports: []}, "1"); '
                  '$("#dr-body").innerHTML')
    assert ('id="dr-edit"' in html) == edit and ('id="dr-why"' in html) == (not edit)


@pytest.mark.parametrize("role, four, gated", [("aendern", False, True), ("aendern", True, False), ("freigeben", False, False)])
def test_expert_mode_needs_freigeben_or_four_eyes(role, four, gated):
    js = (PANEL + role_me(role, four_eyes=four) + 'portIdx["1"].tr = "Trk1"; let cap = null; modal = (t, b) => { cap = b; }; '
          'editPorts({id: 1, k: "A", ssh: true, caps: ["cli"], ports: []}, ["1"]); cap')
    b = in_dom(js)
    assert bool(re.search(r'id="f-expert"[^>]*\bdisabled\b[^>]*aria-describedby="f-gate-exp"', b)) == gated
    assert ("Der Expertenmodus braucht die Rolle „Freigeben“." in b) == gated


@pytest.mark.parametrize("role, expert, revert", [("aendern", 0, True), ("aendern", 1, False), ("freigeben", 1, True), ("lesen", 0, False)])
def test_the_change_list_offers_revert_by_role(role, expert, revert):
    rows = [{**ROWS[0], "expert": expert, "switch_zone": ""}]
    html = in_dom(role_me(role) + LIST % (json.dumps(rows), 10, "return el.innerHTML;"))
    assert ('data-cr="7"' in html) == revert and ('data-cs="7"' in html) == (role != "lesen")


def test_settings_are_read_only_below_admin():
    html = in_dom('(async () => { ' + SETTINGS.replace('ME = {name: "x", role: "admin", zones: null, four_eyes: false}; ', role_me("freigeben"))
                  + 'return $("#view").innerHTML; })()')
    assert 'id="s-save"' not in html and "Einstellungen ändern braucht die Rolle „Admin“." in html and (
        'id="s-poll" type="number" min="5" max="1440" value="15" disabled' in html)
    # Beyond the brief: every field of the card is locked, the zone list too; what only reads (names, PacketFence test) and the own
    # sessions stay
    assert all(re.search(r"\sdisabled\b", t) for t in re.findall(r"<(?:input|select|textarea)\b[^>]*>", html))
    assert 'id="s-zones-save"' not in html and all(f'id="{i}"' in html for i in ("s-names", "s-pftest", "s-logout-all"))


def test_the_zones_card_saves_what_the_text_says():
    js = ('(async () => { const puts = []; ME = {name: "x", role: "admin", zones: null, four_eyes: false}; '
          'api = async (m, u, b) => m === "PUT" ? (puts.push([u, b]), {entries: [{principal: "Z.VK", zones: ["", "VK"]}]}) : u === "/api/settings" ? '
          + SETTINGS_ANSWER + ' : u === "/api/zone-scopes" ? {entries: [{principal: "Z.EK", zones: ["EK"]}]} : {}; await renderSettings(); '
          'const a = [$("#s-scopes").value]; const save = () => $("#s-zones-save").handlers.click[0]({target: $("#s-zones-save")}); '
          '$("#s-scopes").value = "kaputt"; await save(); a.push(puts.length, $("#toasts").children.map(t => t.textContent)); '
          '$("#s-scopes").value = "Z.VK = VK, Ohne Zone"; await save(); '
          'return [...a, puts, $("#toasts").children.map(t => t.textContent), $("#s-scopes").value]; })()')
    first, none, bad, puts, toasts, after = in_dom(js)
    assert first == "Z.EK = EK" and none == 0 and bad == ["Zeile 1: „App-Rolle = Zone, Zone“ erwartet"]
    assert puts == [["/api/zone-scopes", {"entries": [{"principal": "Z.VK", "zones": ["VK", ""]}]}]] and toasts[-1] == "Gespeichert"
    assert after == "Z.VK = Ohne Zone, VK"    # beyond the brief: the field shows what the server stored


def test_the_audit_shows_the_role():
    rows = [{**AUDIT[0], "role": "aendern"}, {**AUDIT[1], "role": None}]
    html = in_dom('(async () => { api = async (m, u) => u === "/api/audit" ? %s : []; await renderAudit(); return $("#au-body").innerHTML; })()'
                  % json.dumps(rows))
    assert "<td>anna</td><td>Ändern</td>" in html and "<td>bob</td><td>–</td>" in html and '<th>Rolle</th>' in in_dom(
        '(async () => { api = async (m, u) => u === "/api/audit" ? %s : []; await renderAudit(); return $("#view").innerHTML; })()' % json.dumps(rows))


DEVICES = ('(async () => { api = async (m, u) => u === "/api/devices" ? [{mac: "aa:bb:cc:00:00:01", name: "Drucker", kind: "drucker", allowed: 0, '
           'pf_state: "ok", pf_error: ""}] : u === "/api/pf/roles" ? {configured: true, roles: []} : [{mac: "aa:bb:cc:00:00:02", sw: "A", sid: 1, '
           'port: "3", vlan: "1", st: "", flags: [], lldp: "", mc: 1}]; await renderDevices(); '
           'return [$("#view").innerHTML, $("#dbody").innerHTML, $("#ulist").innerHTML, !!$("#dbody").handlers.click]; })()')


@pytest.mark.parametrize("role, may", [("lesen", False), ("aendern", True)])
def test_devices_need_aendern(role, may):
    view, rows, unknown, click = in_dom(role_me(role) + DEVICES)
    assert ('id="d-add"' in view, 'id="d-sync"' in view, 'data-u="0"' in unknown) == (may, may, may)
    assert ('<p class="note gate" id="d-why"' in view, "Geräte anlegen, ändern und freigeben braucht die Rolle „Ändern“." in view) == (not may, not may)
    assert ("clickrow" in rows, click) == (may, may)    # beyond the comment: a reader's rows open nothing


# Phase 4a Task 8, review round 1: each gate of the brief that no test held, by role and zone (SW lies in zone "VK"); each dies
# under its mutation (see the Phase 4a note, T8-k)
@pytest.mark.parametrize("zone, zones, offered", [("VK", ["EK"], False), ("VK", ["VK"], True), ("VK", None, True), ("", [""], True), ("", ["EK"], False)])
def test_the_change_list_offers_revert_and_save_only_in_the_users_zones(zone, zones, offered):
    rows = [{**ROWS[0], "expert": 0, "switch_zone": zone}]
    html = in_dom(role_me("aendern", zones=zones) + LIST % (json.dumps(rows), 10, "return el.innerHTML;"))
    assert ('data-cr="7"' in html, 'data-cs="7"' in html) == (offered, offered)


# The footer runProgress builds once the change has ended: the stub's innerHTML = "" keeps the first footer's "Schließen" (modal())
FOOT = ('(async () => { current = "audit"; api = async () => (%s); await runProgress({id: 1, k: "SW"}, 4); '
        'return $("#m-foot").children.slice(1).map(b => b.textContent); })()')
FAILED_SENT = {**DONE, "status": "failed", "sent": 1, "kind": "ports", "saved": 0, "can_revert": True, "can_save": True, "switch_zone": "VK"}


@pytest.mark.parametrize("role, zones, expert, want", [
    ("lesen", None, 0, ["Schließen"]), ("aendern", None, 0, ["Rückgängig", "Trotzdem speichern", "Schließen"]),
    ("aendern", None, 1, ["Trotzdem speichern", "Schließen"]), ("freigeben", None, 1, ["Rückgängig", "Trotzdem speichern", "Schließen"]),
    ("aendern", ["EK"], 0, ["Schließen"]), ("aendern", ["VK"], 0, ["Rückgängig", "Trotzdem speichern", "Schließen"])])
def test_the_result_of_a_change_offers_what_role_and_zone_allow(role, zones, expert, want):
    assert in_dom(role_me(role, zones=zones) + FOOT % json.dumps({**FAILED_SENT, "expert": expert})) == want


READY = {"host": True, "coa": True, "tw": True, "eap": True, "active": True, "park": True, "login_radius": False, "others": []}
PREPARE_NOTE = "„Vorbereiten“ braucht die Rolle „Admin“ (es sendet das RADIUS-Secret an den Switch)."


@pytest.mark.parametrize("role, missing, button, note", [("lesen", True, False, True), ("aendern", True, False, True), ("admin", True, True, False),
                                                         ("lesen", False, False, False)])
def test_only_an_admin_is_offered_to_prepare_a_switch(role, missing, button, note):
    html = in_dom(role_me(role) + f"radiusCard({json.dumps({**SW, 'ready': {**READY, 'host': not missing}})})")
    assert ('data-a="prepare"' in html, PREPARE_NOTE in html) == (button, note)


TRUNK_WHY = "Einen Trunk ändern geht nur im Expertenmodus, und der braucht die Rolle „Freigeben“."


@pytest.mark.parametrize("role, four, zones, why", [
    ("aendern", False, None, TRUNK_WHY), ("aendern", True, None, None), ("freigeben", False, None, None),
    ("aendern", True, ["EK"], "Dieser Switch liegt in der Zone „Ohne Zone“. Du darfst nur an Switches der Zonen „EK“ ändern.")])
def test_a_trunk_is_offered_for_editing_only_with_expert_mode(role, four, zones, why):
    html = in_dom(role_me(role, four_eyes=four, zones=zones) + trk() + 'openPort(sw, "Trk1"); $("#dr-body").innerHTML')
    assert ('id="dr-edit">Trunk bearbeiten</button>' in html) == (why is None)
    assert (f'<p class="note gate" id="dr-why">{why}</p>' in html) if why else 'id="dr-why"' not in html


@pytest.mark.parametrize("role, offered", [("lesen", False), ("aendern", True)])
def test_a_learned_device_is_offered_as_a_new_device_with_aendern(role, offered):
    js = (role_me(role) + PANEL + 'Object.assign(portIdx["1"], {mc: 1, d: [["aa:bb:cc:00:00:09", "1", "10.0.0.9", "", "", 0]]}); '
          + OPEN_PANEL + '$("#dr-body").innerHTML')
    assert ('data-newdev="aa:bb:cc:00:00:09">Als Gerät anlegen</button>' in in_dom(js)) == offered


PORT = {"n": "1", "l": [], "d": [], "u": ["1"], "t": [], "mc": 0, "tr": "", "a": "", "pv": "1", "st": "", "o": True, "ad": True, "s": 1000}
MAP_SW = {"switches": [{**SW, "host": "10.0.0.1", "ports": [PORT]}], "links": [], "vlans": {}}
MAY = [("lesen", None, False), ("aendern", None, True), ("aendern", ["EK"], False), ("aendern", ["VK"], True)]


@pytest.mark.parametrize("role, zones, may", MAY)
def test_only_who_may_change_the_switch_picks_its_ports(role, zones, may):
    js = role_me(role, zones=zones) + 'MAP = {switches: [], links: [], vlans: {}}; renderPortRows(%s); $("#ptbody").innerHTML' % json.dumps(
        MAP_SW["switches"][0])
    assert ('data-pick="1"' in in_dom(js)) == may


# renderSwitchDetail with MAP set (no /api/netmap); the stub's closest() answers null, so applySwFilter (the VLAN highlight) is left
# out, and $(".dhead .actions") is named for it
DETAIL = ('(async () => { MAP = %s; selSwitch = %s; api = async () => []; applySwFilter = () => {}; document.els[".dhead .actions"] = $("#acts"); '
          'await renderSwitchDetail(); return $("#view").innerHTML; })()')


@pytest.mark.parametrize("role, zones, may", MAY)
def test_the_switch_view_offers_picking_all_and_the_selection_bar_only_to_who_may_change(role, zones, may):
    html = in_dom(role_me(role, zones=zones) + DETAIL % (json.dumps(MAP_SW), 1))
    assert ('id="pick-all"' in html, 'id="selbar"' in html) == (may, may)


@pytest.mark.parametrize("role, add", [("admin", True), ("freigeben", False)])
def test_only_an_admin_is_offered_to_add_a_switch(role, add):
    empty, full = (in_dom(role_me(role) + DETAIL % (m, s)) for m, s in (("{switches: [], links: [], vlans: {}}", "null"), (json.dumps(MAP_SW), 1)))
    assert ('id="btn-add"' in empty, 'id="btn-add"' in full) == (add, add)
    assert ("Links „Switch hinzufügen“." in empty, "Switches anlegen braucht die Rolle „Admin“." in empty) == (add, not add)


@pytest.mark.parametrize("role, add", [("admin", True), ("lesen", False)])
def test_the_empty_overview_tells_only_an_admin_to_add_a_switch(role, add):
    html = in_dom(role_me(role) + '(async () => { api = async () => ({switches: [], links: [], vlans: {}}); await renderOverview(); '
                  'return $("#view").innerHTML; })()')
    assert ('id="go-add"' in html, "Lege unter „Switches“ den ersten Switch mit seinen Zugangsdaten an." in html) == (add, add)
    assert ("Switches anlegen braucht die Rolle „Admin“." in html) == (not add)


# Review round 1: renderSettings and renderDevices ask twice at once; when the session ended idle, the first answer names the
# reason and deletes the session, the second finds none ("Sitzung abgelaufen"). The login page keeps the reason it shows; one
# shown without a reason takes a later one, and after a new sign-in (start() hides the login page) a 401 names its own again
IDLE_WHY = "Abgemeldet nach 120 Minuten ohne Aktivität – bitte neu anmelden"


@pytest.mark.parametrize("answers, between, want", [
    ([IDLE_WHY, "Sitzung abgelaufen"], "", IDLE_WHY), (["Nicht angemeldet", IDLE_WHY], "", IDLE_WHY),
    ([IDLE_WHY, "Sitzung abgelaufen"], '$("#login").hidden = true; ', "Sitzung abgelaufen")], ids=["kept", "first-without", "signed-in-again"])
def test_a_second_401_keeps_the_reason_the_login_page_shows(answers, between, want):
    js = ('(async () => { const answers = %s; fetch = async () => ({status: 401, ok: false, headers: {get: () => "application/json"}, '
          'json: async () => ({detail: answers.shift()})}); await api("GET", "/api/settings").catch(() => {}); %s'
          'await api("GET", "/api/zone-scopes").catch(() => {}); return [$("#login").hidden, $("#login-error").hidden, $("#login-error").textContent]; })()'
          ) % (json.dumps(answers), between)
    assert in_dom(js) == [False, False, want]


# Review round 1: a stored zone list the field cannot hold as it is (SVLogic.lossyScopes) is named above the field, which names the
# note in aria-describedby; a list it holds has no note
LOSSY = ("Diese Einträge zeigt das Feld nicht so, wie sie gespeichert sind: „A=B“, „Z.H“. Eine Zone mit Komma oder mit dem Namen "
         "„Ohne Zone“ und eine App-Rolle mit „=“ oder „#“ am Anfang lassen sich hier nicht schreiben; „Zonen speichern“ würde sie ändern.")


@pytest.mark.parametrize("entries, noted", [([{"principal": "Z.EK", "zones": ["EK"]}], False),
                                            ([{"principal": "A=B", "zones": ["EK"]}, {"principal": "Z.H", "zones": ["Haus 1, Nord"]}], True)])
def test_the_zones_card_names_entries_the_field_cannot_hold(entries, noted):
    js = '(async () => { ' + SETTINGS.replace("{entries: []}", json.dumps({"entries": entries})) + 'return $("#view").innerHTML; })()'
    html = in_dom(js)
    assert (f'<p class="note warn" id="s-scopes-lossy" style="margin:0">{LOSSY}</p>' in html) == noted
    assert ('aria-describedby="s-scopes-hint s-scopes-lossy"' in html) == noted and ('aria-describedby="s-scopes-hint"' in html) == (not noted)


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
FOUR_EYES_BANNER = ('<div class="banner warn"><span><b>Vier-Augen-Prinzip:</b> Diese Änderung im Expertenmodus führt erst aus, wenn eine zweite '
                    'Person mit der Rolle „Freigeben“ sie freigibt. Niemand kann die eigene Anfrage freigeben.</span></div>')


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


# Beyond the brief: the card says whether the principle is on, why a role below Freigeben does not review, and each row names the
# requester with the role, the change with its kind and the status with the expiry of an open one (escaped)
@pytest.mark.parametrize("role, four, sentence, gate", [
    ("aendern", True, "Vier-Augen-Prinzip an: Änderungen im Expertenmodus führen erst nach der Freigabe durch eine zweite Person mit der Rolle "
                      "„Freigeben“ aus.", True),
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


def test_a_failed_review_says_why():
    act = 'await reviewApproval(4); return [$("#m-title").textContent, $("#m-body").innerHTML, $("#m-foot").children.map(b => b.textContent)];'
    assert review(answers(preview='throw new Error("Switch ist deaktiviert");'), act) == [
        "Anfrage #4 prüfen", '<div class="error">Switch ist deaktiviert</div>', ["Schließen"]]


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
              "„Freigeben“ oder „Admin“ gehen Änderungen im Expertenmodus dann nicht.")
ADMIN = 'ME = {name: "x", role: "admin", zones: null, four_eyes: false};'


def test_the_four_eyes_card_saves_and_rereads_the_user():
    act = ('$("#s-4e").checked = true; $("#s-4h").value = "48"; await $("#s-4save").handlers.click[0]({target: $("#s-4save")}); '
           'return [html, calls.filter(c => c[0] === "PUT" || c[1] === "/api/auth/me"), $("#toasts").children.map(t => t.textContent), ME.four_eyes, '
           'calls.slice(-1)[0][1], $("#s-4save").disabled];')
    html, calls, toasts, four, last, disabled = in_dom(FOUR_EYES_CARD % (ADMIN, act))
    assert calls == [["PUT", "/api/settings/approvals", {"four_eyes": True, "hours": 48}], ["GET", "/api/auth/me", None]]
    assert (toasts, four, last, disabled) == (["Gespeichert"], True, "/api/approvals?status=open", False)
    assert ('<label class="check"><input type="checkbox" id="s-4e"> Änderungen im Expertenmodus brauchen die Freigabe durch eine zweite Person '
            '(Rolle „Freigeben“ oder „Admin“)</label>') in html
    assert ('<label class="field" style="max-width:220px"><span>Anfragen verfallen nach (Stunden)</span><input id="s-4h" type="number" min="1" '
            'max="168" value="24"></label>') in html
    assert f'<p class="note warn" style="margin:0">{ONE_PERSON}</p>' in html and 'id="s-4save">Vier-Augen-Einstellung speichern</button>' in html
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
