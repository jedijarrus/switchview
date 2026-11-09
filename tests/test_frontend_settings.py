"""The settings page (app/static/sv-settings.js) against the recording DOM stub of tests/test_frontend_dom.py: the bar of its sections
(in the order of the cards; a click marks its section and focuses the card), the three cards of GET /api/settings that share one
PUT (each sends its own fields and the stored values of the others, and only it is drawn anew, so another card's input stays), and
the mark of a card with changes not saved (an input sets it, its save clears it, a failed save keeps it; below Admin nothing is
marked and no card has "Speichern"). Skipped without node."""
import json
import re
import shutil

import pytest
from test_frontend_dom import in_dom, role_me

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

STORED = {"poll_minutes": 15, "opnsense_url": "https://fw.example", "opnsense_key_set": True, "opnsense_secret_set": True, "opnsense_verify_tls": True,
          "radius_server": "192.0.2.1", "radius_key_set": True, "pf_url": "https://pf.example:9999", "pf_user": "webapi", "pf_pass_set": True,
          "pf_verify_tls": True, "unreadable": [], "four_eyes": False, "approval_hours": 24}
SECTIONS = ["set-general", "set-names", "set-pf", "alert-card", "set-zones", "set-4e", "rules-card", "set-sessions", "tok-card"]
# renderSettings as role with the stored settings above (every other GET an empty answer, a PUT ok or, failing, refused); calls as
# [method, url, body]; then: the statements after the render, their value the test's
PAGE = ('(async () => { %s const calls = []; const failing = %s; api = async (m, u, b) => { calls.push([m, u, b === undefined ? null : b]); '
        'if (m === "PUT") { if (failing) throw new Error("Keine Berechtigung: x"); return {ok: true, cleared: [], entries: []}; } '
        'return u === "/api/settings" ? ' + json.dumps(STORED) + ' : u === "/api/zone-scopes" ? {entries: []} : {}; }; await renderSettings(); %s })()')
CLICK = 'await $("#%s").handlers.click[0]({target: $("#%s")}); '


def page(then: str, role: str = "admin", failing: bool = False):
    return in_dom(PAGE % (role_me(role), json.dumps(failing), then))


@pytest.mark.parametrize("role", ["admin", "freigeben"])
def test_the_bar_lists_every_card_in_the_order_of_the_page(role):
    html = page('return $("#view").innerHTML; ', role)
    cards = re.findall(r'<section class="card" id="([\w-]+)"', html)
    assert re.findall(r'data-sec="([\w-]+)"', html) == SECTIONS == [c for c in cards if c != "tok-all"]
    assert '<nav class="set-nav" id="set-nav" aria-label="Abschnitte der Einstellungen">' in html
    assert ('<button type="button" id="nav-set-pf" data-sec="set-pf">RADIUS und PacketFence<span class="dot" aria-hidden="true"></span></button>') in html


def test_a_click_in_the_bar_marks_its_section_and_focuses_its_card():
    then = ('$("#set-nav").handlers.click[0]({target: {closest: s => (s === "[data-sec]" ? {dataset: {sec: "set-zones"}} : null)}}); '
            'return [document.activeElement && document.activeElement.sel, $("#set-zones").getAttribute("tabindex"), '
            '$("#nav-set-zones").getAttribute("aria-current"), $("#nav-set-general").getAttribute("aria-current")]; ')
    assert page(then) == ["#set-zones", "-1", "location", None]


# Each card of GET /api/settings: [its section, its save button, the values typed into it, what its PUT sends of its own]
OWN = [("set-general", "s-save", {"s-poll": "20"}, {"poll_minutes": 20}),
       ("set-names", "s-names-save", {"s-url": " https://fw2.example ", "s-key": "k", "s-secret": "", "s-tls": False},
        {"opnsense_url": "https://fw2.example", "opnsense_key": "k", "opnsense_secret": None, "opnsense_verify_tls": False}),
       ("set-pf", "s-pf-save", {"s-rs": " 198.51.100.1 ", "s-rk": "", "s-pfu": "https://pf2.example", "s-pfuser": " api ", "s-pfpass": "pw", "s-pftls": True},
        {"radius_server": "198.51.100.1", "radius_key": None, "pf_url": "https://pf2.example", "pf_user": "api", "pf_pass": "pw", "pf_verify_tls": True})]
REST = {"poll_minutes": 15, "opnsense_url": "https://fw.example", "opnsense_key": None, "opnsense_secret": None, "opnsense_verify_tls": True,
        "radius_server": "192.0.2.1", "radius_key": None, "pf_url": "https://pf.example:9999", "pf_user": "webapi", "pf_pass": None, "pf_verify_tls": True}


@pytest.mark.parametrize("card, save, typed, sent", OWN, ids=[o[0] for o in OWN])
def test_a_card_of_the_settings_sends_its_fields_and_the_stored_rest_and_draws_only_itself(card, save, typed, sent):
    others = [c for c, *_ in OWN if c != card]
    fill = "".join(f'$("#{k}").{"checked" if isinstance(v, bool) else "value"} = {json.dumps(v)}; ' for k, v in typed.items())
    then = (f'$("#{card}").fire("input"); $("#{others[0]}").fire("input"); ' + fill + CLICK % (save, save)
            + f'return [calls.filter(c => c[0] === "PUT"), ["{card}", ...{json.dumps(others)}].map(c => $("#" + c).innerHTML.includes("<h2>")), '
            + f'$("#{card}").classList.contains("dirty"), $("#{others[0]}").classList.contains("dirty"), $("#toasts").children.map(t => t.textContent)]; ')
    puts, drawn, own_dirty, other_dirty, toasts = page(then)
    assert puts == [["PUT", "/api/settings", {**REST, **sent}]]
    assert drawn == [True, False, False] and own_dirty is False and other_dirty is True and toasts == ["Gespeichert"]


@pytest.mark.parametrize("card, save, prep", [("set-zones", "s-zones-save", '$("#s-scopes").value = "Z.EK = EK"; '),
                                              ("set-4e", "s-4save", '$("#s-4h").value = "24"; '),
                                              ("set-general", "s-save", '$("#s-poll").value = "15"; ')])
@pytest.mark.parametrize("failing", [False, True], ids=["saved", "refused"])
def test_an_input_marks_its_card_and_only_its_save_clears_the_mark(card, save, prep, failing):
    then = (f'$("#{card}").fire("change"); const marked = [$("#{card}").classList.contains("dirty"), $("#nav-{card}").classList.contains("dirty")]; '
            + prep + CLICK % (save, save) + f'return [marked, $("#{card}").classList.contains("dirty"), $("#nav-{card}").classList.contains("dirty")]; ')
    assert page(then, failing=failing) == [[True, True], failing, failing]


def test_adding_or_removing_a_custom_rule_marks_the_rules_card():
    then = ('const hit = s => ({target: {closest: x => (x === "#r-add, [data-cdel]" ? {} : null)}}); '
            '$("#rules-card").handlers.click.forEach(f => f(hit())); return $("#rules-card").classList.contains("dirty"); ')
    assert page(then) is True


@pytest.mark.parametrize("role", ["freigeben", "lesen"])
def test_below_admin_no_card_saves_and_nothing_is_marked(role):
    html, handlers = page('return [$("#view").innerHTML, SETTINGS_SECTIONS.map(([id]) => Object.keys($("#" + id).handlers))]; ', role)
    assert ">Speichern</button>" not in html and all("input" not in h for h in handlers)
    assert "Einstellungen ändern braucht die Rolle „Admin“." in html and 'id="s-names">Namen jetzt aktualisieren</button>' in html


def test_every_save_button_of_the_page_is_named_for_its_card():
    html = page('return $("#view").innerHTML; ')
    names = re.findall(r'aria-label="([^"]+)">Speichern</button>', html)
    assert names == ["Allgemein speichern", "Gerätenamen speichern", "RADIUS und PacketFence speichern", "Zonen speichern", "Vier-Augen-Prinzip speichern"]


def test_each_id_of_the_settings_page_is_there_once():
    """A card that took the ids of another (once the card "RMM" took r-save of "Sicherheitsregeln") binds the other's
    buttons: every id of the page with all its cards drawn stands once."""
    from test_frontend_alerts import ALERTS, RULES
    js = ('(async () => { %s api = async (m, u) => u === "/api/settings" ? %s : u === "/api/zone-scopes" ? {entries: []} '
          ': u === "/api/compliance/rules" ? %s : u === "/api/settings/alerts" ? %s : u === "/api/alerts/deliveries" ? {rows: [], next: null} : []; '
          'await renderSettings(); return $("#view").innerHTML; })()')
    html = in_dom(js % (role_me("admin"), json.dumps(STORED), json.dumps(RULES), json.dumps(ALERTS)))
    ids = re.findall(r'\bid="([^"]+)"', html)
    assert "r-save" in ids and "a-save" in ids and sorted({i for i in ids if ids.count(i) > 1}) == []
