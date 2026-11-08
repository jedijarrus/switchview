"""Phase 4c, Task 3: the settings' cards of app/static/sv-tokens.js against the recording DOM stub of tests/test_frontend_dom.py -
"API-Tokens" for every role (one's own tokens with their dates, a new one shown once in a dialog with "Kopieren", the maximum role up
to one's own, "Widerrufen" asked first; the emergency login sees why it gets none and no form) and "Alle API-Tokens" for an Admin
(every token with its user) - and the audit naming the API token of an entry. Skipped without node."""
import json
import re
import shutil

import pytest
from test_frontend_alerts import settings
from test_frontend_dom import in_dom, role_me

import api_tokens

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

MINE = [{"id": 3, "name": "ci <deploy>", "username": "anna", "display_name": "Anna", "max_role": "lesen", "created_at": "2026-11-08 09:00:00",
         "expires_at": "2027-02-06 09:00:00", "last_used_at": None, "expired": False}]
MADE = {"id": 4, "name": "neu", "token": "svt_abcdefgh", "expires_at": "2027-02-06 09:00:00", "max_role": None}
OLD = {"id": 2, "name": "backup", "username": "bob@example.org", "display_name": "Bob", "max_role": None, "created_at": "2026-08-01 07:00:00",
       "expires_at": "2026-11-01 07:00:00", "last_used_at": "2026-10-31 12:30:00", "expired": True}
ALL = [MINE[0], OLD]

# The cards against an api stub that records every call as [method, url, body]: GET /api/tokens answers mine, GET
# /api/settings/tokens all, a POST the new token MADE, a DELETE {ok: true}, anything else {}; then: the statements after, their value
# the test's
TOKENS = ('(async () => { %s const calls = []; let mine = %s, all = %s; '
          'api = async (m, u, b) => { calls.push([m, u, b === undefined ? null : b]); return m === "POST" ? %s : m === "DELETE" ? {ok: true} '
          ': u === "/api/tokens" ? mine : u === "/api/settings/tokens" ? all : {}; }; %s })()')
# modal answers the question of confirmModal at once (confirmModal is a const: the stub replaces the dialog it opens): its second
# button confirms, its first cancels
CONFIRM = 'modal = (t, x, buttons) => { calls.push(["confirm", t, x]); buttons[%s ? 1 : 0].onClick(); }; '
REVOKE = 'await $("#%s").handlers.click[0]({target: {closest: s => s === "[data-tdel]" ? {dataset: {tdel: "3"}} : null}}); '
TICK = "await new Promise(r => setTimeout(r, 5)); "
TOASTS = '$("#toasts").children.map(t => t.textContent)'
ASKED = ("API-Token widerrufen", '<p style="margin:0">„ci &lt;deploy&gt;“ widerrufen? Skripte mit diesem Token werden sofort abgewiesen.</p>')


def tokens(then, role="aendern", mine=MINE, all_=ALL, **me):
    return in_dom(TOKENS % (role_me(role, **me), json.dumps(mine), json.dumps(all_), json.dumps(MADE), then), tz="UTC")


def options(html, select):
    inner = re.search(rf'<select id="{select}">(.*?)</select>', html).group(1)
    return re.findall(r'<option value="([^"]*)"( selected)?>([^<]*)</option>', inner)


def test_my_tokens_are_listed_escaped_with_their_dates():
    html, calls = tokens('await renderTokensInto($("#tok-body")); return [$("#tok-body").innerHTML, calls]; ', mine=[*MINE, OLD])
    assert ('<p class="note" style="margin:0">Ein API-Token meldet ein Skript als dich an (<span class="mono">Authorization: Bearer …</span>), mit deiner '
            'Rolle oder einer niedrigeren. SwitchView zeigt es nur einmal.</p>') in html
    assert "<th>Name</th><th>Höchstrolle</th><th>Angelegt</th><th>Läuft ab</th><th>Zuletzt benutzt</th><th></th>" in html
    assert ('<tr><td>ci &lt;deploy&gt;</td><td>Lesen</td><td class="num time">08.11.26, 09:00</td><td class="num time">06.02.27, 09:00</td>'
            '<td class="num time"><span class="muted">nie benutzt</span></td><td><button class="btn small danger" type="button" data-tdel="3" '
            'aria-label="Widerrufen: ci &lt;deploy&gt;">Widerrufen</button></td></tr>') in html
    # without a maximum role it has its user's; one that ran out says so until the hourly prune deletes it
    assert ('<tr><td>backup</td><td><span class="muted">wie Benutzer</span></td><td class="num time">01.08.26, 07:00</td><td class="num time">01.11.26, 07:00 '
            '<span class="pill warn">abgelaufen</span></td><td class="num time">31.10.26, 12:30</td>') in html
    assert "<deploy>" not in html and "token_hash" not in html and calls == [["GET", "/api/tokens", None]]


# Beyond the brief: no token yet, an answer that is no list (the stubs of older tests answer {}) and a failed request
@pytest.mark.parametrize("answer, want", [("[]", '<div class="empty">Noch keine API-Tokens.</div>'), ("{}", '<div class="empty">Noch keine API-Tokens.</div>'),
                                          ('(() => { throw new Error("Server <weg>"); })()', '<div class="empty">Server &lt;weg&gt;</div>')],
                         ids=["none", "no-list", "failed"])
def test_an_empty_or_failed_list_says_so(answer, want):
    html = tokens(f'const real = api; api = async (m, u, b) => u === "/api/tokens" ? {answer} : real(m, u, b); '
                  'await renderTokensInto($("#tok-body")); return $("#tok-body").innerHTML; ')
    assert want in html


def test_a_new_token_is_shown_once():
    then = ('await renderTokensInto($("#tok-body")); $("#tk-name").value = " neu "; $("#tk-days").value = "90"; $("#tk-role").value = ""; '
            'await $("#tk-create").handlers.click[0]({target: $("#tk-create")}); '
            'const shown = [$("#modal").hidden, $("#m-title").textContent, $("#m-body").innerHTML, $("#m-foot").children.map(b => b.textContent)]; '
            'const copied = []; $("#m-foot").children[0].fire("click"); ' + TICK
            + 'globalThis.navigator = {clipboard: {writeText: async v => { copied.push(v); }}}; $("#m-foot").children[0].fire("click"); ' + TICK
            + '$("#m-foot").children[1].fire("click"); ' + TICK
            + 'const rest = Object.values(document.els).filter(e => e.sel !== "#m-body").map(e => e.innerHTML).join(""); '
            'return [shown, copied, ' + TOASTS + ', $("#modal").hidden, calls, rest.includes("svt_abcdefgh"), $("#m-body").innerHTML, '
            'document.activeElement.sel]; ')
    shown, copied, toasts, hidden, calls, anywhere, body, focused = tokens(then)
    assert shown[:2] == [False, "Neues API-Token"] and shown[3] == ["Kopieren", "Fertig"]
    assert shown[2] == ('<p class="note warn">Nur jetzt sichtbar: kopieren und sicher ablegen. SwitchView zeigt es nie wieder.</p>'
                        '<pre class="code" id="tk-value">svt_abcdefgh</pre>')
    # without a clipboard (no HTTPS) the hint to mark it, with one the token itself
    assert copied == ["svt_abcdefgh"] and toasts == ["Kopieren ging nicht – bitte markieren und kopieren", "Kopiert"]
    # "Fertig" empties and closes the dialog and reads the list again: the token stands nowhere in the DOM any more
    assert hidden and calls == [["GET", "/api/tokens", None], ["POST", "/api/tokens", {"name": "neu", "days": 90, "max_role": None}],
                                ["GET", "/api/tokens", None]]
    assert not anywhere and body == "" and focused == "#tk-create"


def test_a_token_needs_a_name_and_a_refusal_is_the_servers_text():                    # beyond the brief
    then = ('await renderTokensInto($("#tok-body")); $("#tk-name").value = "  "; await $("#tk-create").handlers.click[0]({target: $("#tk-create")}); '
            'api = async () => { throw new Error("Du hast schon ein API-Token mit diesem Namen"); }; $("#tk-name").value = "ci"; $("#tk-days").value = "30"; '
            'await $("#tk-create").handlers.click[0]({target: $("#tk-create")}); '
            'return [calls, ' + TOASTS + ', $("#modal").hidden, $("#tk-create").disabled]; ')
    calls, toasts, hidden, disabled = tokens(then)
    assert calls == [["GET", "/api/tokens", None]] and hidden and not disabled
    assert toasts == ["Bitte einen Namen eintragen", "Du hast schon ein API-Token mit diesem Namen"]


@pytest.mark.parametrize("role, want", [("lesen", ["lesen"]), ("aendern", ["lesen", "aendern"]),
                                        ("admin", ["lesen", "aendern", "freigeben", "admin"])])
def test_the_role_choice_offers_only_roles_up_to_mine(role, want):
    html = tokens('await renderTokensInto($("#tok-body")); return $("#tok-body").innerHTML; ', role=role)
    assert options(html, "tk-role") == [("", "", "wie meine Rolle"), *[(r, "", {"lesen": "Lesen", "aendern": "Ändern", "freigeben": "Freigeben",
                                                                                 "admin": "Admin"}[r]) for r in want]]
    assert options(html, "tk-days") == [("30", "", "30 Tage"), ("90", " selected", "90 Tage"), ("180", "", "180 Tage"), ("365", "", "365 Tage")]
    assert '<input id="tk-name" maxlength="60" autocomplete="off"' in html
    assert '<button class="btn primary" type="button" id="tk-create">Token anlegen</button>' in html


def test_the_emergency_login_sees_why_and_gets_no_form():
    html, calls = tokens('await renderTokensInto($("#tok-body")); return [$("#tok-body").innerHTML, calls]; ', role="admin", method="local")
    assert "Der Notfall-Login bekommt keine API-Tokens: er ist kein persönliches Konto." in html and api_tokens.EMERGENCY + "." in html
    assert 'id="tk-name"' not in html and "tk-create" not in html and calls == []


@pytest.mark.parametrize("confirmed", [True, False])
def test_revoking_asks_and_deletes(confirmed):
    then = (CONFIRM % json.dumps(confirmed) + 'await renderTokensInto($("#tok-body")); ' + REVOKE % "tk-rows" + 'return [calls, ' + TOASTS + ']; ')
    calls, toasts = tokens(then)
    asked = [["GET", "/api/tokens", None], ["confirm", *ASKED]]
    if confirmed:     # deleted, then the list is read again
        assert calls == [*asked, ["DELETE", "/api/tokens/3", None], ["GET", "/api/tokens", None]] and toasts == ["Widerrufen"]
    else:
        assert calls == asked and toasts == []


def test_an_admin_sees_every_token_with_its_user():
    then = (CONFIRM % "true" + 'await renderAllTokensInto($("#tok-all-body")); const html = $("#tok-all-body").innerHTML; ' + REVOKE % "tka-rows"
            + 'return [html, calls]; ')
    html, calls = tokens(then, role="admin")
    assert "<th>Benutzer</th><th>Name</th><th>Höchstrolle</th><th>Läuft ab</th><th>Zuletzt benutzt</th><th></th>" in html
    assert ('<tr><td>Anna<span class="cellnote">anna</span></td><td>ci &lt;deploy&gt;</td><td>Lesen</td><td class="num time">06.02.27, 09:00</td>'
            '<td class="num time"><span class="muted">nie benutzt</span></td><td><button class="btn small danger" type="button" data-tdel="3"') in html
    assert '<tr><td>Bob<span class="cellnote">bob@example.org</span></td><td>backup</td>' in html and '<span class="pill warn">abgelaufen</span>' in html
    # revoked, both lists are read again: an Admin's own token stands in both
    assert calls == [["GET", "/api/settings/tokens", None], ["confirm", *ASKED], ["DELETE", "/api/tokens/3", None], ["GET", "/api/tokens", None],
                     ["GET", "/api/settings/tokens", None]]


@pytest.mark.parametrize("role", ["lesen", "aendern", "freigeben", "admin"])
def test_the_settings_hold_the_token_cards(role):
    then = TICK + 'return [$("#view").innerHTML, $("#tok-body").innerHTML, calls.filter(c => c[1].includes("tokens")).map(c => c[1])]; '
    view, body, asked = settings(then, role=role)
    assert ('<section class="card" id="tok-card"><div class="card-h"><h2>API-Tokens</h2></div><div id="tok-body"><div class="empty">Lade …</div></div>'
            '</section>') in view and view.index("Alle meine Sitzungen beenden") < view.index('id="tok-card"')
    admin = role == "admin"
    assert (('<section class="card" id="tok-all"><div class="card-h"><h2>Alle API-Tokens</h2></div><div id="tok-all-body"><div class="empty">Lade …'
             '</div></div></section>') in view) == admin and ('id="tok-all"' in view) == admin
    # the stub of the settings answers {} for the token lists: the card is drawn empty
    assert "Noch keine API-Tokens." in body and asked == ["/api/tokens", *(["/api/settings/tokens"] if admin else [])]


def test_the_audit_names_the_token():
    row = {"id": 1, "ts": "2026-11-08 10:00:00", "username": "anna", "action": "token_create", "target": "#3", "detail": "", "role": "aendern"}
    named, plain, odd, labels = in_dom(f'[auditRow({json.dumps({**row, "token": "ci (#3)"})}), auditRow({json.dumps({**row, "token": None})}), '
                                       f'auditRow({json.dumps({**row, "token": "a <b> (#4)"})}), [AUDIT_LABELS.token_create, AUDIT_LABELS.token_revoke]]')
    assert '<td>anna<span class="cellnote">API-Token „ci (#3)“</span></td>' in named and "<td>anna</td>" in plain and "cellnote" not in plain
    assert '<span class="cellnote">API-Token „a &lt;b&gt; (#4)“</span>' in odd
    assert labels == ["API-Token angelegt", "API-Token widerrufen"]
