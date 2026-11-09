"""Who is logged in on the LAN now, as PacketFence holds it (docs/anmeldungen.md): pf.open_sessions (the open locationlog entries of
the LAN), GET /api/pf/sessions (each session with its switch, port and device of SwitchView, the answer reused for a minute) and the
views of app/static/sv-auth.js (the port tiles and panel of the switch view, the column and the card of the devices view).
PacketFence is a fake httpx (apifix.fake_httpx): nothing leaves the process.
"""
import asyncio
import json
import re
import shutil
from pathlib import Path

import pytest

import api_devices
import apifix
import crypto
import db
import pf

ROOT = Path(__file__).resolve().parent.parent
LAPTOP, PRINTER, GUEST = "00:00:5e:00:53:53", "00:11:22:33:44:55", "aa:bb:cc:00:00:01"


def session(mac: str, kind: str = "Ethernet-EAP", user: str = "PC-ANNA.example.local", role: str = "vlan_140", vlan: str = "140",
            port: str = "1", desc: str = "1", switch_mac: str = "02:00:00:00:00:80", switch_ip: str = "192.0.2.63") -> dict:
    """One open LAN session of PacketFence's locationlog."""
    return {"mac": mac, "connection_type": kind, "dot1x_username": user, "role": role, "vlan": vlan, "switch": switch_ip, "switch_ip": switch_ip,
            "switch_mac": switch_mac, "port": port, "ifDesc": desc, "start_time": "2026-11-09 08:31:32"}


OPEN = [session(LAPTOP), session(PRINTER, kind="Ethernet-NoEAP", user="001122334455", port="10", desc="10"),
        session(GUEST, kind="Ethernet-NoEAP", user="aabbcc000001", role="vlan_3999", vlan="3999", port="2", desc="2"),
        session("de:ad:00:00:00:01", switch_mac="", switch_ip="192.0.2.99", port="5", desc="5")]


class PacketFence(apifix.Remote):
    """PacketFence's API: /login and the locationlog search, which answers sessions (one page)."""

    def __init__(self):
        super().__init__()
        self.sessions: list[dict] = list(OPEN)

    def reply(self, method, url):
        if url == "/login":
            return {"token": "t"}
        if url == "/locationlogs/search":
            return {"items": self.sessions, "nextCursor": None}
        return {}


@pytest.fixture
def packetfence(tmp_path, monkeypatch) -> PacketFence:
    """A fresh database with PacketFence set up (a fake), one switch (SW-TEST: base MAC as PacketFence names it, written differently,
    ports 1, 2 and 10 of ifIndex 1, 2 and 10) and the printer as a device; the answer cache emptied."""
    apifix.fresh_db(tmp_path, monkeypatch)
    remote = PacketFence()
    monkeypatch.setattr(pf, "httpx", apifix.fake_httpx(remote))
    monkeypatch.setattr(api_devices, "_sessions", {"at": 0.0, "items": None})

    async def go():
        async with db.db() as conn:
            await db.write_settings(conn, {"pf_url": "https://pf.example.com:9999", "pf_user": "webapi", "pf_pass": crypto.encrypt("pf-secret")})
            await conn.execute("INSERT INTO switches (id, name, host, base_mac) VALUES (8, 'SW-TEST', '192.0.2.200', '020000-000080')")
            await conn.executemany("INSERT INTO ports (switch_id, ifindex, name) VALUES (8, ?, ?)", [(1, "1"), (2, "2"), (10, "10")])
            await conn.execute("INSERT INTO devices (mac, name, kind, allowed) VALUES (?, 'Drucker EK', 'drucker', 1)", (PRINTER,))
            await conn.commit()
    asyncio.run(go())
    return remote


@pytest.fixture
def api(packetfence, monkeypatch):
    with apifix.signed_in(monkeypatch, apifix.user("lesen")) as client:
        yield client


def test_open_sessions_asks_for_the_open_lan_entries(packetfence):
    assert asyncio.run(pf.open_sessions()) == OPEN
    body = [s["json"] for s in packetfence.sent if "query" in (s.get("json") or {})][0]
    assert body["query"] == {"op": "and", "values": [
        {"op": "or", "values": [{"field": "connection_type", "op": "equals", "value": "Ethernet-EAP"},
                                {"field": "connection_type", "op": "equals", "value": "Ethernet-NoEAP"}]},
        {"field": "end_time", "op": "equals", "value": "0000-00-00 00:00:00"}]}
    assert body["fields"] == pf.SESSION_FIELDS and body["cursor"] == 0


def test_each_session_has_its_switch_port_and_device(api):
    r = api.get("/api/pf/sessions")
    assert r.status_code == 200 and (r.json()["configured"], r.json()["ok"]) == (True, True)
    got = {s["mac"]: s for s in r.json()["sessions"]}
    assert got[LAPTOP] == {"mac": LAPTOP, "how": "dot1x", "park": False, "user": "PC-ANNA.example.local", "role": "vlan_140", "vlan": "140",
                           "since": "2026-11-09 08:31:32", "switch_id": 8, "switch_name": "SW-TEST", "port": "1", "device": ""}
    assert (got[PRINTER]["how"], got[PRINTER]["user"], got[PRINTER]["device"], got[PRINTER]["port"]) == ("mac", "", "Drucker EK", "10")
    assert (got[GUEST]["how"], got[GUEST]["park"]) == ("mac", True)
    # a switch SwitchView does not know under that base MAC or address keeps the address PacketFence names
    assert (got["de:ad:00:00:00:01"]["switch_id"], got["de:ad:00:00:00:01"]["switch_name"]) == (None, "192.0.2.99")
    # sorted by switch, then port as a number
    assert [(s["switch_name"], s["port"]) for s in r.json()["sessions"]] == [("192.0.2.99", "5"), ("SW-TEST", "1"), ("SW-TEST", "2"), ("SW-TEST", "10")]


def test_a_switch_is_found_by_its_address_and_a_port_by_its_ifindex():
    switches = [{"id": 3, "name": "SW-B", "host": "sw-b.example.local", "base_mac": None}]
    ports = [{"switch_id": 3, "ifindex": 49, "name": "A1"}]
    out = api_devices.session_view([session(LAPTOP, switch_mac="", switch_ip="SW-B.example.local", port="49", desc="")], switches, ports, {})
    assert (out[0]["switch_id"], out[0]["switch_name"], out[0]["port"]) == (3, "SW-B", "A1")


def test_the_answer_of_packetfence_is_reused_for_a_minute(api, packetfence, monkeypatch):
    api.get("/api/pf/sessions")
    api.get("/api/pf/sessions")
    assert sum(1 for c in packetfence.calls if c == ("POST", "/locationlogs/search")) == 1
    monkeypatch.setattr(api_devices, "SESSIONS_TTL", -1.0)
    api.get("/api/pf/sessions")
    assert sum(1 for c in packetfence.calls if c == ("POST", "/locationlogs/search")) == 2


def test_a_failure_of_packetfence_is_said_and_not_kept(api, packetfence):
    packetfence.status[("POST", "/locationlogs/search")] = 500
    assert api.get("/api/pf/sessions").json() == {"configured": True, "ok": False, "error": "PacketFence-Verlauf nicht lesbar (HTTP 500)", "sessions": []}
    del packetfence.status[("POST", "/locationlogs/search")]
    assert len(api.get("/api/pf/sessions").json()["sessions"]) == 4


def test_without_packetfence_there_are_no_sessions(api):
    async def go():
        async with db.db() as conn:
            await db.write_settings(conn, {"pf_url": ""})
            await conn.commit()
    asyncio.run(go())
    assert api.get("/api/pf/sessions").json() == {"configured": False, "ok": True, "sessions": []}


def test_the_note_is_linked():
    assert "PacketFence logins notes (German): [docs/anmeldungen.md](docs/anmeldungen.md)" in (ROOT / "README.md").read_text(encoding="utf-8")
    note = (ROOT / "docs" / "anmeldungen.md").read_text(encoding="utf-8")
    for heading in ("## Was gebaut wurde", "## Rechte je Route", "## Bekannte Grenzen", "## Was beim Update zu tun ist"):
        assert f"\n{heading}\n" in note, heading


# ── The views (sv-auth.js) ─────────────────────────────────────────────────
SESS = [{"mac": LAPTOP, "how": "dot1x", "park": False, "user": "host/PC-ANNA.example.local", "role": "vlan_140", "vlan": "140", "since": "2026-11-09 08:31:32",
         "switch_id": 8, "switch_name": "SW-TEST", "port": "1", "device": ""},
        {"mac": PRINTER, "how": "mac", "park": False, "user": "", "role": "vlan_140", "vlan": "140", "since": "2026-11-09 07:00:00", "switch_id": 8,
         "switch_name": "SW-TEST", "port": "10", "device": "Drucker EK"},
        {"mac": GUEST, "how": "mac", "park": True, "user": "", "role": "vlan_3999", "vlan": "3999", "since": "2026-11-09 09:00:00", "switch_id": 8,
         "switch_name": "SW-TEST", "port": "1", "device": ""}]
ANSWER = {"configured": True, "ok": True, "sessions": SESS}
NODE = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def view(then: str, answer=ANSWER) -> object:
    from test_frontend_dom import in_dom
    return in_dom('(async () => { ME = {name: "x", role: "lesen"}; const calls = []; api = async (m, u) => { calls.push(u); return %s; }; %s })()'
                  % (json.dumps(answer), then))


@NODE
def test_the_devices_column_names_way_place_and_role():
    cells = view('const before = authCell("%s"); await loadAuth(); return [before, authCell("%s"), authCell("%s")];' % (PRINTER, PRINTER, "00:00:00:00:00:09"))
    assert cells[0] == '<span class="muted">…</span>'
    assert cells[1] == '<span class="pill au-m">MAC</span><div class="muted" style="font-size:12px">SW-TEST · Port 10 · vlan_140</div>'
    assert cells[2].startswith('<span class="muted" title="keine Sitzung in PacketFence')


@NODE
def test_the_port_panel_lists_the_sessions_of_its_port():
    kv = view('await loadAuth(); return authKv({id: 8}, {n: "1"});')
    assert kv.startswith("<dt>Anmeldung</dt><dd>") and kv.count('<span class="pill') == 2
    assert ('<span class="pill au-x">802.1X</span> <span class="mono">00:00:5e:00:53:53</span>'
            '<div class="muted" style="font-size:12px">PC-ANNA.example.local · vlan_140 · seit 2026-11-09 08:31:32</div>') in kv
    assert '<span class="pill au-p">Park</span>' in kv and view('await loadAuth(); return authKv({id: 8}, {n: "2"});') == ""


@NODE
def test_a_port_tile_shows_its_highest_way():
    then = ('selSwitch = 8; const t1 = {dataset: {p: "1"}, classList: $("#t1").classList}, t10 = {dataset: {p: "10"}, classList: $("#t10").classList}, '
            't3 = {dataset: {p: "3"}, classList: $("#t3").classList}; document.lists["#plate .port"] = [t1, t10, t3]; '
            '$("#plate-legend").querySelector = () => null; let legend = ""; $("#plate-legend").insertAdjacentHTML = (w, h) => { legend = h; }; '
            'await paintAuth({id: 8}); return [["au-x", "au-m", "au-p"].map(c => [t1, t10, t3].map(t => t.classList.contains(c))), legend];')
    marks, legend = view(then)
    assert marks == [[False, False, False], [False, True, False], [True, False, False]]    # port 1: park before 802.1X; port 3 has none
    assert legend.count('<span class="au-lg">') == 3 and "angemeldet: 802.1X" in legend and "nicht angemeldet: Park" in legend


@NODE
@pytest.mark.parametrize("pick, rows", [("all", 2), ("dot1x", 1), ("mac", 1)])
def test_the_card_lists_every_login_and_only_counts_the_parked(pick, rows):
    # A device in the park VLAN is not logged in: the card counts it and points to the unknown devices, where it stands
    then = ('const el = $("#c"); await renderAuthInto(el); %s return el.innerHTML;'
            % ("" if pick == "all" else 'el.onclick({target: {closest: () => ({dataset: {af: "%s"}})}});' % pick))
    html = view(then)
    assert "1 per 802.1X · 1 per MAC-Freigabe · 1 ohne Zugriff im Park-VLAN (Reiter „Ohne Zugriff“)" in html
    assert html.count("<tr><td>") == rows and GUEST not in html and 'data-af="park"' not in html
    if pick == "all":
        assert ('<tr><td>Drucker EK</td><td class="mono">00:11:22:33:44:55</td><td><span class="pill au-m">MAC</span></td><td>vlan_140 · 140</td>'
                '<td>SW-TEST · 10</td><td class="num">2026-11-09 07:00:00</td></tr>') in html
        assert "<tr><td>PC-ANNA.example.local</td>" in html


# The devices view with these sessions: the printer a device of the database (released), the guest parked and unknown (learned with a
# vendor), the laptop logged in by 802.1X, and one learned device without a session
UNKNOWN = [{"mac": m, "sw": "SW-TEST", "sid": 8, "port": p, "vlan": v, "st": "radius", "flags": [], "lldp": "", "mc": 1, "name": "", "vendor": vd}
           for m, p, v, vd in ((LAPTOP, "1", "140", "Example"), (GUEST, "1", "3999", "Acme"), ("00:00:00:00:00:09", "4", "1", ""))]
DEVICES_VIEW = ('(async () => { ME = {name: "x", role: "%s"}; const opened = []; editDevice = (d, isNew, release) => { opened.push([d, isNew, release]); }; '
                'api = async (m, u) => u === "/api/pf/sessions" ? %s : u === "/api/devices/unknown" ? %s '
                ': u === "/api/pf/roles" ? {configured: true, roles: []} '
                ': u === "/api/devices" ? [{mac: "%s", name: "Drucker EK", kind: "drucker", allowed: 1, pf_state: "ok", pf_error: ""}] : []; '
                'await renderDevices(); %s })()')


@NODE
def test_the_unknown_devices_are_those_without_a_session():
    html = view_devices('return $("#ulist").innerHTML;')
    assert LAPTOP not in html and GUEST not in html and html.count('data-u="') == 1 and "00:00:00:00:00:09" in html


@NODE
def test_the_card_without_access_lists_the_parked_and_releases_them():
    card, hidden, opened = view_devices('const c = $("#park-card"); const html = c.innerHTML, hidden = c.hidden; '
                                        'c.onclick({target: {closest: () => ({dataset: {park: "0"}})}}); return [html, hidden, opened];')
    assert hidden is False and '<h2>Ohne Zugriff</h2><span class="sub">1 Gerät im Park-VLAN: MAC-Anmeldung ohne Freigabe</span>' in card
    assert ('<tr><td>Acme<span class="cellnote">unbekannt</span></td><td class="mono">aa:bb:cc:00:00:01</td><td>SW-TEST · 1</td>'
            '<td class="num">2026-11-09 09:00:00</td><td><button class="btn small primary" type="button" data-park="0">Freigeben</button></td></tr>') in card
    assert opened == [[{"mac": GUEST, "name": "", "kind": "sonstiges", "location": "SW-TEST Port 1"}, True, True]]


@NODE
def test_a_known_device_parked_opens_its_own_form_and_a_reader_gets_no_button():
    answer = {**ANSWER, "sessions": [{**SESS[1], "park": True, "role": "vlan_3999"}]}
    card, opened = view_devices('$("#park-card").onclick({target: {closest: () => ({dataset: {park: "0"}})}}); return [$("#park-card").innerHTML, opened];',
                                answer=answer)
    assert '<td>Drucker EK<span class="cellnote">freigegeben, PacketFence parkt es trotzdem</span></td>' in card
    assert opened[0][0]["name"] == "Drucker EK" and opened[0][1:] == [False, True]
    reader = view_devices('return $("#park-card").innerHTML;', role="lesen")
    assert "Ohne Zugriff" in reader and "data-park" not in reader


@NODE
def test_without_a_parked_device_the_card_says_so_and_the_view_opens_on_the_network():
    answer = {**ANSWER, "sessions": [s for s in SESS if not s["park"]]}
    card, tab, count = view_devices('return [$("#park-card").innerHTML, devTab, $("#dn-park").textContent];', answer=answer)
    assert "Gerade kein Gerät ohne Zugriff." in card and tab == "net" and count == ""


@NODE
def test_a_parked_device_opens_the_view_on_its_tab_with_a_count():
    tab, park, net, rel, alert = view_devices('return [devTab, $("#dn-park").textContent, $("#dn-net").textContent, $("#dn-rel").textContent, '
                                              '$("#dn-park").classList.contains("alert")];')
    # the guest parked; logged in: the laptop and the printer; without a session: one learned device; released: the printer
    assert (tab, park, net, rel, alert) == ("park", 1, 3, 1, True)


@NODE
def test_the_devices_behind_other_devices_are_hidden_until_asked_for():
    unknown = [*UNKNOWN, {"mac": "00:00:00:00:00:0a", "sw": "SW-TEST", "sid": 8, "port": "4", "vlan": "1", "st": "", "flags": ["many"], "lldp": "",
                          "mc": 9, "name": "", "vendor": ""}]
    js = (DEVICES_VIEW.replace("%s })()", "") % ("aendern", json.dumps(ANSWER), json.dumps(unknown), PRINTER)
          + 'const before = $("#ulist").innerHTML; $("#d-behind").handlers.change[0]({target: {checked: true}}); '
            'return [before, $("#ulist").innerHTML, $("#d-behind-n").textContent]; })()')
    from test_frontend_dom import in_dom
    before, after, n = in_dom(js)
    assert "00:00:00:00:00:0a" not in before and "00:00:00:00:00:0a" in after and n == "(1)"


@NODE
@pytest.mark.parametrize("dev, is_new, release, title, button, locked", [
    ({}, True, False, "Gerät freigeben", "Freigeben", False), ({}, True, True, "Gerät freigeben", "Freigeben", False),
    ({"name": "Drucker", "allowed": 0}, False, False, "Gerät: Drucker", "Speichern", True),
    ({"name": "Drucker", "allowed": 0}, False, True, "Gerät freigeben", "Freigeben", False),
    ({"name": "Drucker", "allowed": 1}, False, False, "Gerät: Drucker", "Speichern", False)],
    ids=["new", "new-release", "locked", "unlock", "released"])
def test_a_device_is_released_unless_locked(dev, is_new, release, title, button, locked):
    # Saving a device releases it; "Gesperrt" keeps the entry without access, ticked only for a locked device opened to edit
    from test_frontend_dom import in_dom
    got = in_dom('(async () => { ME = {name: "x", role: "aendern"}; ROLES = {configured: true, roles: []}; let cap = null; '
                 'modal = (t, b, btns) => { cap = [t, b, btns.map(x => x.label)]; }; '
                 'await editDevice(%s, %s, %s); return cap; })()'
                 % (json.dumps({"mac": "aa:bb:cc:00:00:01", "name": "", "kind": "sonstiges", **dev}), json.dumps(is_new), json.dumps(release)))
    assert got[0] == title and got[2][-1] == button and "Ohne Zertifikat freigeben" not in got[1]
    assert re.search(r'<input type="checkbox" id="dv-blocked" ?(checked)?> Gesperrt \(Eintrag bleibt, kein Zugang\)</label>', got[1]).group(1) == (
        "checked" if locked else None)


def test_last_seen_is_an_access_port_never_a_trunk(api, packetfence):
    async def go():
        async with db.db() as conn:
            await conn.execute("INSERT INTO switches (id, name, host) VALUES (9, 'SW-CORE', '192.0.2.201')")
            await conn.executemany("INSERT INTO ports (switch_id, ifindex, name, trunk, mac_count) VALUES (?, ?, ?, ?, ?)",
                                   [(9, 300, "Trk2", None, 2), (9, 25, "25", "Trk2", 2)])
            await conn.execute("UPDATE ports SET mac_count = 5 WHERE switch_id = 8 AND name = '10'")
            await conn.executemany("INSERT INTO macs (switch_id, port, mac, vlan, last_seen) VALUES (?, ?, ?, ?, '2026-11-09 14:00:00')",
                                   [(9, "Trk2", PRINTER, "100"), (9, "25", PRINTER, "200"), (8, "10", PRINTER, "100")])
            await conn.commit()
    asyncio.run(go())
    seen = {d["mac"]: d["seen"] for d in api.get("/api/devices").json()}[PRINTER]
    assert (seen["sw"], seen["port"]) == ("SW-TEST", "10")


def view_devices(then: str, answer=ANSWER, role: str = "aendern"):
    from test_frontend_dom import in_dom
    return in_dom(DEVICES_VIEW % (role, json.dumps(answer), json.dumps(UNKNOWN), PRINTER, then))


@NODE
@pytest.mark.parametrize("answer, said", [({"configured": False, "ok": True, "sessions": []}, "PacketFence ist nicht eingerichtet (Einstellungen)."),
                                          ({"configured": True, "ok": False, "error": "HTTP 500 <x>", "sessions": []}, "HTTP 500 &lt;x&gt;")])
def test_the_card_says_why_it_has_nothing(answer, said):
    assert said in view('const el = $("#c"); await renderAuthInto(el); return el.innerHTML;', answer)


@NODE
@pytest.mark.parametrize("dev, is_new, want", [({}, True, "vlan_140"), ({"role": "vlan_130"}, True, "vlan_130"), ({"role": ""}, False, None)],
                         ids=["new", "new-with-role", "stored-default"])
def test_a_new_device_starts_in_the_client_lan(dev, is_new, want):
    from test_frontend_dom import in_dom
    body = in_dom('(async () => { ME = {name: "x", role: "aendern"}; ROLES = {configured: true, roles: [{name: "vlan_140"}, {name: "vlan_130"}, '
                  '{name: "vlan_3999"}]}; let cap = ""; modal = (t, b) => { cap = b; }; await editDevice(%s, %s, true); return cap; })()'
                  % (json.dumps({"mac": "aa:bb:cc:00:00:01", "name": "", "kind": "sonstiges", **dev}), json.dumps(is_new)))
    selected = re.findall(r'<option value="([^"]*)" selected>', body.split('<select id="dv-role">')[1].split("</select>")[0])
    assert selected == ([want] if want else [])


def test_saving_or_deleting_a_device_drops_the_kept_sessions(api, packetfence, monkeypatch):
    with apifix.signed_in(monkeypatch, apifix.user("aendern")) as client:
        client.get("/api/pf/sessions")
        assert api_devices._sessions["items"] is not None
        assert client.post("/api/devices", json={"mac": GUEST, "name": "Gast", "kind": "sonstiges", "role": "vlan_140", "allowed": True}).status_code == 200
        assert api_devices._sessions["items"] is None
        client.get("/api/pf/sessions")
        assert client.delete(f"/api/devices/{GUEST}").status_code == 200 and api_devices._sessions["items"] is None
