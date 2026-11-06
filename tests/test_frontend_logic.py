"""The frontend logic that needs no DOM (app/static/svlogic.js, window.SVLogic in the browser, module.exports in Node), run with node.

Task 8 of Phase 3: the hash names a switch by id ("#sw=<id>"), an old bookmark "#switch=<name>" still works, and a malformed hash
(a lone "%", a broken escape) no longer throws in decodeURIComponent: that error reached start()'s catch and showed the login (Review
§6). Skipped where node is not installed (no Python dependency, no build step).
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"
SVLOGIC = STATIC / "svlogic.js"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")


def run(js: str):
    """The value of the expression js (JSON), with L = require(svlogic.js), in a fresh node process."""
    script = f"const L = require({json.dumps(str(SVLOGIC))});\nprocess.stdout.write(JSON.stringify({js}));"
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.parametrize("hash, want", [
    ("#sw=12", {"view": "switches", "sw": 12, "swName": None}), ("#switch=SW%20A", {"view": "switches", "sw": None, "swName": "SW A"}),
    ("#switch=%E0%A4%A", {"view": "switches", "sw": None, "swName": "%E0%A4%A"}), ("#%", {"view": "%", "sw": None, "swName": None}),
    ("", {"view": "overview", "sw": None, "swName": None}), ("#vlans", {"view": "vlans", "sw": None, "swName": None})])
def test_parse_hash_never_throws(hash, want):
    assert run(f"L.parseHash({json.dumps(hash)})") == want


@pytest.mark.parametrize("hash, want", [
    ("#sw=abc", {"view": "switches", "sw": None, "swName": None}),        # no id: the switch view picks its first switch
    ("#sw=", {"view": "switches", "sw": None, "swName": None}),
    ("#sw=1e3", {"view": "switches", "sw": None, "swName": None}),
    ("#sw=" + "9" * 20, {"view": "switches", "sw": None, "swName": None}),    # beyond Number.MAX_SAFE_INTEGER
    ("#switch=50%25", {"view": "switches", "sw": None, "swName": "50%"}),
    ("#switch=", {"view": "switches", "sw": None, "swName": None}),
    ("#switches", {"view": "switches", "sw": None, "swName": None})])
def test_parse_hash_other_forms(hash, want):
    assert run(f"L.parseHash({json.dumps(hash)})") == want


@pytest.mark.parametrize("sel, want", [(2, 2), (9, 1), ("SW", 2), ("nope", 1), (None, 1)])
def test_switch_id_of(sel, want):
    assert run(f"L.switchIdOf([{{id: 1, k: 'A'}}, {{id: 2, k: 'SW'}}, {{id: 3, k: 'SW'}}], {json.dumps(sel)})") == want


def test_switch_id_of_takes_a_name_that_looks_like_a_number_as_a_name():
    """An old bookmark "#switch=3" names the switch called "3", not the id 3."""
    assert run("L.switchIdOf([{id: 3, k: 'A'}, {id: 7, k: '3'}], '3')") == 7


def test_switch_id_of_an_empty_list_is_null():
    assert run("L.switchIdOf([], 1)") is None


@pytest.mark.parametrize("n, i, shift, want", [(3, 2, False, 0), (3, 0, True, 2), (3, 1, False, None), (3, 1, True, None), (3, -1, False, 0),
                                               (3, -1, True, 2), (0, -1, False, -1), (1, 0, False, 0), (1, 0, True, 0)])
def test_trap_step(n, i, shift, want):
    """Phase 5 Task 3: where Tab / Shift+Tab goes in a dialog of n focusable controls when control i has the focus (-1: none of
    them); null leaves the move to the browser, -1 focuses the dialog itself (it has no control)."""
    assert run(f"L.trapStep({n}, {i}, {json.dumps(shift)})") == want


def test_index_loads_svlogic_before_the_app_scripts():
    """Holds unchanged after Task 12 (app.js split into several scripts)."""
    scripts = re.findall(r'<script src="/static/([\w.\-]+)"></script>', INDEX)
    assert scripts.index("svlogic.js") < min(i for i, s in enumerate(scripts) if s not in ("msal-browser.min.js", "svlogic.js"))
