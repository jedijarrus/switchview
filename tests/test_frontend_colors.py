"""The colours of the views (sv-core.js vcol, app.css) and the devices view's conveniences (sv-admin.js, sv-auth.js): one colour per VLAN
everywhere, apart from the colours of states (the park VLAN amber like every sign of the park, VLAN 1 grey); after a release the
sessions are asked anew until the device's session switched, then its switch polled; the tab kept over a reload; "Ohne Anmeldung"
folded unless opened. Against the recording DOM stub of tests/test_frontend_dom.py; skipped without node."""
import json
import re
import shutil
from pathlib import Path

import pytest
from test_frontend_dom import in_dom, role_me

import radiusprep

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
STATIC = Path(__file__).resolve().parent.parent / "app" / "static"


def test_each_vlan_has_one_colour_apart_from_the_states():
    got = in_dom('[vcol("3999"), vcol(3999), vcol("1"), vcol("140"), vcol("20"), vcol("20"), vcol("x"), PARK_VLAN]')
    assert got[:3] == ["var(--warn)", "var(--warn)", "#a1a1aa"] and got[3] == "#2563eb"
    assert got[4] == got[5] and re.fullmatch(r"#[0-9a-f]{6}", got[4]) and got[6] == "#a1a1aa" and got[7] == radiusprep.PARK_VLAN
    # no VLAN takes a colour of a state: the palette and the table hold none of ok, warn or crit
    palette = set(in_dom("[...VLAN_PALETTE, ...Object.values(VC)]"))
    assert not palette & {"#16a34a", "#4ade80", "#b45309", "#fbbf24", "#b91c1c", "#f87171", "#e11d48", "#ca8a04", "#65a30d"}


def test_a_vlan_looks_the_same_on_every_port_and_chip():
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert ".port.down::before" not in css    # a port without link keeps its VLAN's colour (its frame is dashed)
    chip = css.split(".vchip {", 1)[1].split("}", 1)[0]
    assert "background: var(--surface)" in chip and "var(--vc)" not in chip    # the colour is the swatch's, not the chip's
    assert ".port .sb.r, .port .sb.k { color: var(--fg-2); }" in css


# The devices view after a release: the sessions of PacketFence answer the old session `before` times, then the new one; calls as
# [method, url]; then the value of the promise authAfterChange returns and the calls
OLD = {"mac": "aa:bb:cc:00:00:01", "how": "mac", "park": True, "user": "", "role": "vlan_3999", "vlan": "3999", "since": "2026-11-09 09:00:00",
       "switch_id": 8, "switch_name": "SW-TEST", "port": "7", "device": ""}
NEW = {**OLD, "park": False, "role": "vlan_140", "vlan": "140", "since": "2026-11-09 09:00:20"}
AFTER = ('(async () => { AUTH_POLL_MS = 1; const calls = []; let n = 0; api = async (m, u) => { calls.push([m, u]); '
         'if (u.startsWith("/api/pf/sessions")) { n += 1; return {configured: true, ok: true, sessions: [n > %d ? %s : %s]}; } return {}; }; '
         'await loadAuth(true); calls.length = 0; n = 0; const pending = authPending; const p = authAfterChange("aa:bb:cc:00:00:01"); '
         'const during = authCell("aa:bb:cc:00:00:01"); const switched = await p; return [switched, calls, during, pending.size]; })()')


def test_after_a_release_the_sessions_are_asked_until_the_device_switched_then_its_switch_is_polled():
    switched, calls, during, pending = in_dom(AFTER % (2, json.dumps(NEW), json.dumps(OLD)))
    assert switched is True and during == '<span class="muted">wird umgeschaltet …</span>' and pending == 0
    assert calls == [["GET", "/api/pf/sessions?fresh=1"]] * 3 + [["POST", "/api/switches/8/poll"]]


def test_a_session_that_never_switches_ends_the_asking_without_a_poll():
    switched, calls, _, pending = in_dom(AFTER % (99, json.dumps(NEW), json.dumps(OLD)))
    assert switched is False and pending == 0 and calls == [["GET", "/api/pf/sessions?fresh=1"]] * 12


DEVICES = ('(async () => { %s const kept = {}; globalThis.localStorage = {getItem: k => kept[k] ?? null, setItem: (k, v) => { kept[k] = String(v); }}; '
           'api = async (m, u) => u === "/api/devices" ? [] : u === "/api/pf/roles" ? {configured: true, roles: []} : u === "/api/pf/sessions" '
           '? {configured: true, ok: true, sessions: []} : u === "/api/devices/unknown" ? [{mac: "aa:bb:cc:00:00:02", sw: "SW", sid: 1, port: "3", vlan: "1", '
           'st: "", flags: [], lldp: "", mc: 1}] : []; await renderDevices(); %s })()')


def test_the_tab_is_kept_for_the_next_render():
    then = ('const auto = kept["sv.devTab"] ?? null; $("#dtabs").handlers.click[0]({target: {closest: () => ({dataset: {tab: "watch"}})}}); '
            'return [auto, devTab, kept["sv.devTab"], devStored("sv.devTab")];')
    assert in_dom(DEVICES % (role_me("aendern"), then)) == [None, "watch", "watch", "watch"]


def test_without_a_parked_device_ohne_anmeldung_is_folded_until_opened():
    then = ('const html = $("#view").innerHTML; $("#d-fold").handlers.click[0]({}); '
            'return [html, $("#d-unknown").hidden, $("#d-fold").getAttribute("aria-expanded"), kept["sv.devUnknownOpen"], $("#dn-unknown").textContent];')
    html, hidden, expanded, kept, count = in_dom(DEVICES % (role_me("lesen"), then))
    assert '<button type="button" class="fold" id="d-fold" aria-expanded="false" aria-controls="d-unknown">' in html
    assert '<div id="d-unknown" hidden>' in html and (hidden, expanded, kept, count) == (False, "true", "1", 1)
