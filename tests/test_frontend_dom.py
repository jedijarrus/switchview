"""Phase 5: what the app scripts do, against a recording DOM stub. The scripts of index.html (without msal-browser.min.js) run as
classic scripts in one node vm context, one global scope as in the browser; the stub keeps the state a test reads back (focus,
attributes, hidden / inert, handlers, history). Layout and real focus rules stay with the browser check. Skipped without node."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

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


PANEL = ('MAP = {switches: [], links: [], vlans: {}}; portIdx = {"1": {n: "1", l: [], d: [], u: [], t: [], mc: 0, tr: "", a: "", pv: "", st: "", mb: [], '
         'o: true, ad: true, s: 1000}}; ')
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


SETTINGS = ('ME = {name: "x"}; api = async (m, u) => u === "/api/settings" ? {poll_minutes: 15, opnsense_url: "", opnsense_verify_tls: true, '
            'radius_server: "", pf_url: "", pf_user: "", pf_verify_tls: true, unreadable: ["opnsense_key", "radius_key", "pf_pass"]} : '
            '{ok: true, entries: 5, skipped: 2}; await renderSettings(); ')


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
