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
