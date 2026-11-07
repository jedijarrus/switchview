"""Task 12 of Phase 3 (Phase 1 "... app.js aufteilen"): app.js is split into five classic scripts without a build step (sv-core,
sv-overview, sv-switch, sv-admin, sv-main), a pure move. The IIFE is gone, so the scripts share the global scope: every top-level
name of one is visible in the later ones. A let / const declared twice (or one svlogic.js declares too) stops a script from loading;
a function declared twice silently replaces the earlier one, which only the name test catches. The router comes last, its VIEWS
reads the render functions of the earlier scripts at load. The node tests are skipped where node is not installed (no Python
dependency, no build step).
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
SCRIPTS = ["msal-browser.min.js", "svlogic.js", "sv-core.js", "sv-overview.js", "sv-switch.js", "sv-admin.js", "sv-approvals.js",
           "sv-main.js"]


def test_index_loads_every_script_in_order():
    assert re.findall(r'<script src="/static/([\w.\-]+)"></script>', INDEX) == SCRIPTS and not (STATIC / "app.js").exists()


def test_every_script_is_served():
    """Each name passes the pattern of main.static (/static/{name}) and is a file there."""
    assert all(re.fullmatch(r"[\w.\-]+\.(js|css|svg)", n) and (STATIC / n).is_file() for n in SCRIPTS)


def test_every_part_is_strict():
    assert all((STATIC / n).read_text(encoding="utf-8").startswith('"use strict";\n') for n in SCRIPTS[2:])


def test_no_top_level_name_is_declared_twice():
    # Top level = lines with exactly two spaces of indentation (the indentation of the former IIFE body stays)
    names = [m for n in SCRIPTS[2:] for m in re.findall(r"^  (?:const|let|function|async function) (\w+)", (STATIC / n).read_text(encoding="utf-8"), re.M)]
    logic = re.findall(r"^(?:const|let|var|function|async function|class) (\w+)", (STATIC / "svlogic.js").read_text(encoding="utf-8"), re.M)
    assert len(names) == len(set(names)) and logic == ["SVLogic"] and "SVLogic" not in names


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("name", SCRIPTS[1:])
def test_every_script_parses(name):
    assert subprocess.run(["node", "--check", str(STATIC / name)], timeout=30).returncode == 0


# Runs svlogic.js and the app scripts one after another as classic scripts in one node vm context (one global scope, as the browser's
# window): a stub DOM answers every property and call, fetch records its URL and never answers. Prints the views whose render function
# is missing and the URLs fetched by the start call at the end of the last script.
LOAD = """
const vm = require("vm"), fs = require("fs");
const el = new Proxy(function () {}, { get: (t, k) => k === Symbol.toPrimitive ? () => "" : el, apply: () => el });
const fetched = [];
const fetch = url => { fetched.push(url); return new Promise(() => {}); };
const ctx = vm.createContext({ document: el, window: el, history: el, location: { hash: "", origin: "" }, fetch });
for (const f of process.argv.slice(1)) vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: f });
const missing = vm.runInContext("Object.keys(VIEWS).filter(k => typeof VIEWS[k] !== 'function')", ctx);
process.stdout.write(JSON.stringify({ missing: [...missing], fetched }));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_scripts_load_in_order_in_one_global_scope():
    """Beyond node --check: no script throws at load (a let/const another script declares too, a name of a later script used at load),
    every view of the router has its render function, and the start call at the end runs (initLogin asks for /api/auth/config)."""
    files = [str(STATIC / n) for n in re.findall(r'<script src="/static/([\w.\-]+)"></script>', INDEX) if n != "msal-browser.min.js"]
    out = subprocess.run(["node", "-e", LOAD, *files], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == {"missing": [], "fetched": ["/api/auth/config"]}


# The same load, then the value (JSON) of the expression in argv[1], evaluated in that global scope after the scripts ran
EVAL = LOAD.split("const missing")[0].replace("process.argv.slice(1)", "process.argv.slice(2)") + """
process.stdout.write(JSON.stringify(vm.runInContext(process.argv[1], ctx)));
"""


def in_page(expr: str):
    files = [str(STATIC / n) for n in re.findall(r'<script src="/static/([\w.\-]+)"></script>', INDEX) if n != "msal-browser.min.js"]
    out = subprocess.run(["node", "-e", EVAL, expr, *files], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_the_radius_card_says_the_switch_changed_since_the_read_without_naming_a_way():
    """Final review: switch_cfg.stale is set by an SNMP SET and by SSH commands without a read-back (Ruling 175), so the card names
    no way; without the mark it says only when it read."""
    card = "MAP = {}; [true, false].map(st => radiusCard({ssh: true, caps: ['nac'], cfgAt: '2026-11-06 10:00:00', cfgStale: st}))"
    stale, fresh = in_page(card)
    assert " · veraltet (Switch seither geändert)</span>" in stale and "SNMP" not in stale
    assert "veraltet" not in fresh and "Stand " in fresh


# The names a selector may be concatenated from: ids the code itself writes (sv-admin.js), never a value from the switch or the user
CODE_IDS = {"noteId", "inputId", "id", "b.dataset.clr", "box", "url"}


def test_no_selector_is_built_from_unescaped_text():                                  # Review Focus 5
    """Every selector written as a template literal escapes each value it takes (CSS.escape); a port name can hold `"` or `\\`. A
    selector built with + takes only an id of the code (CODE_IDS)."""
    for n in SCRIPTS[2:]:
        text = (STATIC / n).read_text(encoding="utf-8")
        for sel in re.findall(r"(?:querySelector(?:All)?|\$)\((`[^`]*`)", text):
            assert all(v.startswith("CSS.escape(") for v in re.findall(r"\$\{([^}]*)\}", sel)), (n, sel)
        for v in re.findall(r"(?:querySelector(?:All)?|\$)\(\s*[\"'][^\"']*[\"']\s*\+\s*([\w.]+)", text):
            assert v in CODE_IDS, (n, v)


def test_a_german_quote_closes_with_its_own_mark():
    """Phase 5 Task 11 (browser check): a UI text opened with „ closes with “, not with the ASCII double quote (six texts did,
    among them the hint at „Vorbereiten“)."""
    for n in [*SCRIPTS[2:], "index.html"]:
        text = (STATIC / n).read_text(encoding="utf-8")
        assert not re.findall(r'„[^“"\n]*\\?"', text), n
        assert text.count("„") == text.count("“"), n


def test_the_layers_can_take_the_focus():                                              # Review Focus 2
    """A browser focuses a container only with tabindex: restoreFocus's last fallback ($("#view").focus()), modal() without a control
    and trapTab with nothing to tab to focus #view, .modal and #drawer; #drawer is a modal dialog for screen readers like .modal.
    The DOM stub's focus() always succeeds, so only this pin holds the attributes."""
    assert '<main class="wrap" id="view" tabindex="-1">' in INDEX
    assert '<div class="modal" role="dialog" aria-modal="true" aria-labelledby="m-title" tabindex="-1">' in INDEX
    drawer = re.search(r'<aside\b[^>]*\bid="drawer"[^>]*>', INDEX).group(0)
    assert all(a in drawer for a in ('role="dialog"', 'aria-modal="true"', 'tabindex="-1"', 'aria-labelledby="dr-title"')), drawer


def test_the_approvals_tab_sits_between_backups_and_audit():                          # Phase 4a Task 9
    """The tab starts hidden (refreshApprovals shows it), its count too; the count is a pill of the warning colour."""
    tabs = re.findall(r'<button type="button" data-view="(\w+)"', INDEX)
    assert tabs[tabs.index("backups") + 1:tabs.index("audit")] == ["approvals"]
    assert ('<button type="button" data-view="approvals" id="tab-appr" hidden>Freigaben <span class="count" id="appr-n" hidden></span></button>'
            in INDEX)
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert (".tabs .count { margin-left: 6px; padding: 0 6px; border-radius: 999px; background: var(--warn); color: var(--surface); "
            "font-size: 11px; }") in css
    # Browser check: with the tab the header wrapped the user to a second row at 1280 px (the search asked for 220 px before it
    # shrinks); from 160 px the row holds the tab, the search and a name like "Lena Grünwalder" (T9-e)
    assert ".search { position: relative; flex: 1 1 160px; min-width: 0; max-width: 380px; margin-left: auto; }" in css
