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


@pytest.mark.parametrize("view, sel, want", [("overview", None, "#overview"), ("vlans", 3, "#vlans"), ("switches", 3, "#sw=3"),
                                             ("switches", "SW A", "#switch=SW%20A"), ("switches", None, "#switches")])
def test_hash_for(view, sel, want):
    """Phase 5 Task 4: the hash of a view (the rule syncHash had inline): a switch by id, a name not resolved yet by name."""
    assert run(f"L.hashFor({json.dumps(view)}, {json.dumps(sel)})") == want


@pytest.mark.parametrize("view, sel, want", [("switches", 12, {"view": "switches", "sw": 12, "swName": None}),
                                             ("switches", "50% & ü", {"view": "switches", "sw": None, "swName": "50% & ü"}),
                                             ("vlans", None, {"view": "vlans", "sw": None, "swName": None})])
def test_hash_for_round_trips_through_parse_hash(view, sel, want):
    assert run(f"L.parseHash(L.hashFor({json.dumps(view)}, {json.dumps(sel)}))") == want


@pytest.mark.parametrize("how, frm, to, want", [("push", "#vlans", "#sw=1", "push"), ("push", "#vlans", "#vlans", "replace"),
                                                ("replace", "#a", "#b", "replace"), ("none", "#a", "#b", None)])
def test_history_op(how, frm, to, want):
    """Phase 5 Task 4: a navigation to the hash already shown replaces its entry instead of adding a second one; "none" (Back,
    Forward, a typed hash) adds nothing."""
    assert run(f"L.historyOp({json.dumps(how)}, {json.dumps(frm)}, {json.dumps(to)})") == want


def test_index_loads_svlogic_before_the_app_scripts():
    """Holds unchanged after Task 12 (app.js split into several scripts)."""
    scripts = re.findall(r'<script src="/static/([\w.\-]+)"></script>', INDEX)
    assert scripts.index("svlogic.js") < min(i for i, s in enumerate(scripts) if s not in ("msal-browser.min.js", "svlogic.js"))


# Phase 5 Task 5: the global search runs over an index built once per netmap (SVLogic.searchIndex) instead of comparing every LLDP
# neighbour with every switch and lower-casing every device field on each keystroke; the VLAN matrix counts in one pass per switch.
SW = [{"id": 1, "k": "A", "sys": "a-sys", "ports": [
         {"n": "1", "a": "Drucker-EK", "l": [], "d": [["aa:bb:cc:00:00:01", "20", "10.0.0.5", "drucker1", "HP", 2]], "mc": 1, "tr": ""},
         {"n": "2", "a": "", "l": [["B", "6"]], "d": [["aa:bb:cc:00:00:02", "20", "", "", "Cisco", 0]], "mc": 1, "tr": ""},
         {"n": "3", "a": "", "l": [["SEP00AB", "Port 1"]], "d": [["aa:bb:cc:00:00:03", "30", "", "phone", "Cisco", 0]], "mc": 1, "tr": ""},
         {"n": "4", "a": "", "l": [], "d": [["aa:bb:cc:00:00:04", "20", "", "x", "", 0]], "mc": 13, "tr": ""},
         {"n": "5", "a": "member", "l": [], "d": [["aa:bb:cc:00:00:05", "20", "", "y", "", 0]], "mc": 1, "tr": "Trk1"},
         {"n": "Trk1", "a": "uplink-trunk", "l": [], "d": [], "mc": 0, "tr": "Trk1"}]},
      {"id": 2, "k": "B", "sys": "", "ports": []}]
# the search of before Phase 5 (sv-admin.js, the input handler of #q), as [sid, port, t, x] per hit
OLD = """(sw, term) => { const isPeer = p => p.l.some(x => sw.some(s => s.sys === x[0] || s.k === x[0])); const hits = [];
  sw.forEach(s => s.ports.forEach(p => { if (p.n.startsWith("Trk")) return;
    if ((p.a || "").toLowerCase().includes(term)) hits.push([s.id, p.n, p.a, "Port-Beschreibung"]);
    p.l.forEach(x => { if ((x[0] + " " + x[1]).toLowerCase().includes(term)) hits.push([s.id, p.n, x[0] + " Port " + x[1], "LLDP-Nachbar"]); });
    if (p.mc <= 12 && !isPeer(p) && !p.tr) p.d.forEach(d => { if (d.some(v => String(v || "").toLowerCase().includes(term)))
      hits.push([s.id, p.n, d[3] || d[4] || d[0], d[0] + (d[2] ? " · " + d[2] : "") + " · VLAN " + d[1]]); }); }));
  return hits; }"""


@pytest.mark.parametrize("term", ["aa:bb", "drucker", "cisco", "port 1", "sep00", "member", "uplink", "10.0.0", "20", "zz"])
def test_search_index_finds_what_the_old_search_found(term):                          # Review Focus 4
    sw = json.dumps(SW)
    new = run(f"L.searchHits(L.searchIndex({sw}, L.peerKeys({sw})), {json.dumps(term)}, 999).map(h => [h.sid, h.port, h.t, h.x])")
    assert new == run(f"({OLD})({sw}, {json.dumps(term)})")


def test_search_hits_stop_at_max():
    assert run(f"L.searchHits(L.searchIndex({json.dumps(SW)}, new Set()), 'aa:bb', 2).length") == 2


def test_peer_keys_skip_empty_names():
    assert run("[...L.peerKeys([{sys: '', k: 'A'}, {sys: 'core', k: ''}, {sys: 'core', k: 'B'}])].sort()") == ["A", "B", "core"]


@pytest.mark.parametrize("cur, n, key, want", [(-1, 3, "ArrowDown", 0), (2, 3, "ArrowDown", 0), (0, 3, "ArrowUp", 2), (-1, 3, "ArrowUp", 2),
                                               (1, 3, "Home", 1), (1, 3, "x", 1), (-1, 0, "ArrowDown", -1)])
def test_next_index(cur, n, key, want):
    assert run(f"L.nextIndex({cur}, {n}, {json.dumps(key)})") == want


PORTS = [{"n": "1", "u": ["20"], "t": ["30"], "tr": ""}, {"n": "2", "u": ["20"], "t": [], "tr": "Trk1"},
         {"n": "Trk1", "u": ["1"], "t": ["20", "30"], "tr": "Trk1"},
         {"n": "Po1", "u": ["40"], "t": [], "tr": "Po1"}, {"n": "3", "u": [], "t": ["99"], "tr": ""}]


def test_vlan_counts_are_the_matrix_of_before():
    assert run(f"L.vlanCounts({json.dumps(PORTS)})") == {"20": {"u": 1, "t": 1}, "30": {"u": 0, "t": 2}, "1": {"u": 1, "t": 0},
                                                          "40": {"u": 0, "t": 0}, "99": {"u": 0, "t": 1}}


# Phase 5 Task 7 (R44): after saving a switch whose SNMP writing goes out insecure or not at all, the dialog only follows a
# write-relevant change (or a new switch, or a write state of the server that moved), else a hint
BAD = {"snmp_write": True, "snmp_write_via": "rw", "snmp_rw_insecure": True, "snmp_write_error": None, "host": "10.0.0.1", "snmp_version": "2c"}
NONE = {**BAD, "snmp_write_via": None, "snmp_write_error": "Keine SNMP-Schreib-Zugangsdaten hinterlegt", "snmp_rw_insecure": False}


@pytest.mark.parametrize("stored, payload, row, want", [
    (None, {"host": "10.0.0.1"}, BAD, "dialog"),
    (BAD, {"host": "10.0.0.1", "snmp_version": "2c", "snmp_community": None, "snmp_rw_community": None}, BAD, "hint"),
    (BAD, {"host": "10.0.0.1", "snmp_write": True}, BAD, "dialog"), (BAD, {"host": "10.0.0.1", "driver": "cisco"}, BAD, "dialog"),
    (BAD, {"host": "10.0.0.1", "snmp_rw_community": "neu"}, BAD, "dialog"), (BAD, {"host": "10.0.0.1", "snmp_rw_community": ""}, BAD, "dialog"),
    (BAD, {"host": "10.0.0.2"}, BAD, "dialog"), (BAD, {"host": "10.0.0.1", "snmp_version": "3"}, BAD, "dialog"),
    ({**BAD, "snmp_rw_insecure": False}, {"host": "10.0.0.1"}, BAD, "dialog"), (BAD, {"host": "10.0.0.1"}, NONE, "dialog"),
    (NONE, {"host": "10.0.0.1"}, NONE, "hint"),
    (BAD, {"host": "10.0.0.1"}, {**BAD, "snmp_rw_insecure": False}, ""), (BAD, {"host": "10.0.0.1"}, {**BAD, "snmp_write": False}, ""),
    (None, {"host": "10.0.0.1"}, None, "")])
def test_write_alert_mode(stored, payload, row, want):
    assert run(f"L.writeAlertMode({json.dumps(stored)}, {json.dumps(payload)}, {json.dumps(row)})") == want


# Beyond the brief: each clause of "moved" on its own (the cases above move the writing identity only together with the rest)
@pytest.mark.parametrize("row", [{**BAD, "snmp_write_via": "read"}, {**NONE, "snmp_write_error": "Community 'public' wird nicht zum Schreiben verwendet"}],
                         ids=["identity", "error"])
def test_write_alert_mode_sees_each_move_of_the_write_state(row):
    stored = BAD if row["snmp_write_via"] else NONE
    assert run(f"L.writeAlertMode({json.dumps(stored)}, {json.dumps({'host': '10.0.0.1'})}, {json.dumps(row)})") == "dialog"


# Phase 5 Task 8: a change that sent nothing reloads only its change list (nothing changed at the switch); the audit filter works in
# the browser on the 200 entries of GET /api/audit, over user, action (its label), target and details
@pytest.mark.parametrize("c, want", [({"sent": 0, "kind": "ports"}, {"reload": "list", "delay": 0}),
                                     ({"sent": 0, "kind": "save"}, {"reload": "list", "delay": 0}),
                                     ({"sent": 1, "kind": "ports"}, {"reload": "map", "delay": 4500}),
                                     ({"sent": None, "kind": "ports"}, {"reload": "map", "delay": 4500}),
                                     ({"sent": 1, "kind": "save"}, {"reload": "map", "delay": 200})])
def test_after_change(c, want):
    assert run(f"L.afterChange({json.dumps(c)})") == want


AUDIT = [{"username": "anna", "action": "switch_update", "target": "3", "detail": "host: 10.0.0.1 → 10.0.0.2"},
         {"username": "bob", "action": "login", "target": "local", "detail": ""},
         {"username": "anna", "action": "login_failed", "target": "local", "detail": None}]
LABELS = {"switch_update": "Switch geändert", "login": "Anmeldung", "login_failed": "Anmeldung fehlgeschlagen"}


@pytest.mark.parametrize("text, action, want", [("", "", [0, 1, 2]), ("anna", "", [0, 2]), ("ANMELDUNG", "", [1, 2]), ("10.0.0.2", "", [0]),
                                                ("", "login", [1]), ("anna", "login", []), ("geändert", "", [0])])
def test_filter_audit(text, action, want):
    assert run(f"(A => L.filterAudit(A, {json.dumps(text)}, {json.dumps(action)}, {json.dumps(LABELS)}).map(r => A.indexOf(r)))({json.dumps(AUDIT)})") == want


# Phase 4a Task 8: the role of the signed-in user (/api/auth/me) as the UI compares and names it, and the zone list of the settings
# as text, one line per app role ("<App-Rolle> = <Zone>, <Zone>", "Ohne Zone" for the empty zone)
def test_at_least_and_the_labels():
    assert run('[L.atLeast("freigeben", "aendern"), L.atLeast("aendern", "freigeben"), L.atLeast(null, "lesen"), L.atLeast("chef", "lesen"), '
               'L.roleLabel("aendern"), L.roleLabel("x"), L.roleLabel(null)]') == [True, False, False, False, "Ändern", "x", "–"]


@pytest.mark.parametrize("text, entries, errors", [
    ("SwitchView.Zone.EK = EK, Lager\n\n# Notiz\nSwitchView.Zone.VK = VK, Ohne Zone",
     [{"principal": "SwitchView.Zone.EK", "zones": ["EK", "Lager"]}, {"principal": "SwitchView.Zone.VK", "zones": ["VK", ""]}], []),
    ("X = A\nX = B, A", [{"principal": "X", "zones": ["A", "B"]}], []),
    ("ohne Zeichen\n = EK\nY = ", [], ["Zeile 1: „App-Rolle = Zone, Zone“ erwartet", "Zeile 2: „App-Rolle = Zone, Zone“ erwartet", "Zeile 3: keine Zone"])])
def test_parse_scopes(text, entries, errors):
    assert run(f"L.parseScopes({json.dumps(text)})") == {"entries": entries, "errors": errors}


def test_format_scopes_reverses_parse_scopes():
    text = "SwitchView.Zone.EK = EK, Lager\nSwitchView.Zone.VK = VK, Ohne Zone"
    assert run(f"L.formatScopes(L.parseScopes({json.dumps(text)}).entries)") == text


# Review round 1: the limits of PUT /api/zone-scopes (api_settings.ZoneScope: an app role 1-200 characters, a zone at most 40, at
# most 100 zones per app role and 200 app roles) as German line errors, before the server's 422 answers in pydantic's English;
# characters as Python counts them (code points: an emoji is one)
def test_parse_scopes_keeps_the_limits_of_the_server():
    many = ", ".join(f"z{i}" for i in range(100))
    text = "\n".join(["X = " + "a" * 40, "Y = " + "a" * 41, "R" * 201 + " = EK", "R" * 200 + " = EK", "E = " + "😀" * 40, "M = " + many, "M = z100"])
    got = run(f"(r => [r.entries.map(e => [e.principal.length, e.zones.length]), r.errors])(L.parseScopes({json.dumps(text)}))")
    assert got == [[[1, 1], [200, 1], [1, 1], [1, 100]],
                   ["Zeile 2: Zone länger als 40 Zeichen", "Zeile 3: App-Rolle länger als 200 Zeichen", "Zeile 7: mehr als 100 Zonen für eine App-Rolle"]]
    roles = "\n".join(f"R{i} = EK" for i in range(201))
    assert run(f"(r => [r.entries.length, r.errors])(L.parseScopes({json.dumps(roles)}))") == [200, ["Zeile 201: mehr als 200 App-Rollen"]]


# Review round 1: the text has no quoting, so a stored entry with a comma in a zone, a zone named "Ohne Zone", an "=" in its app
# role or a "#" at its start does not read back as stored; saving the field would change it, and the zones card names it
def test_lossy_scopes_names_the_entries_the_text_cannot_hold():
    entries = [{"principal": "Z.EK", "zones": ["", "EK"]}, {"principal": "Z.H", "zones": ["Haus 1, Nord"]}, {"principal": "A=B", "zones": ["EK"]},
               {"principal": "#X", "zones": ["EK"]}, {"principal": "Z.O", "zones": ["Ohne Zone"]}, {"principal": "Z.K", "zones": ["Lager", "VK"]}]
    assert run(f"L.lossyScopes({json.dumps(entries)})") == ["Z.H", "A=B", "#X", "Z.O"]
