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


# previewChange with /plan pending until the test answers it (liveRow's /api/switches answers [] at once). The loading dialog has
# no buttons, so #m-foot lists only those of a dialog opened after it
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
