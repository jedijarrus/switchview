"""Phase 4b, Task 8: the audit log filters and pages on the server (GET /api/audit) and exports what it filters as CSV (GET
/api/audit.csv). Filters: a text in user, action, target and details (LIKE, the text as text), an action, a user (without case),
a role (or none), a switch (its id, host or name as the target) and a time range (since inclusive, until exclusive, ISO times as
history.to_utc reads them); a page goes by id, newest first or oldest first, with the id of the last row shown as its cursor. Both
routes need Lesen and are not zone-limited. The CSV goes through app/csvout.py like the history's (Task 3).

A fresh database per test (apifix.fresh_db), the audit entries written directly through dbfix with their ts.
"""
import asyncio
import re

import pytest

import api_settings
import apifix
import dbfix
import history


@pytest.fixture
def api(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def entry(user="anna", action="login", target="", detail="", role="admin", ts="2026-11-07 10:00:00"):
    return dbfix.query("INSERT INTO audit(ts, username, action, target, detail, role) VALUES (?,?,?,?,?,?) RETURNING id",
                       (ts, user, action, target, detail, role))[0][0]


def ids(r) -> list[int]:
    return [row["id"] for row in r.json()["rows"]]


@pytest.mark.parametrize("params, want", [({"q": "drucker"}, [2]), ({"action": "device_create"}, [2]), ({"user": "BEN"}, [3]),
                                          ({"role": "aendern"}, [2]), ({"role": "none"}, [4]),
                                          ({"since": "2026-11-07T00:00:00+01:00", "until": "2026-11-07T23:59:59Z"}, [3, 2]), ({"q": "50%"}, [])])
def test_the_audit_filters_on_the_server(api, params, want):
    entry(ts="2026-11-06 22:00:00")
    entry(action="device_create", detail="Drucker EK", role="aendern", ts="2026-11-07 08:00:00")
    entry(user="ben", action="backup", target="7", ts="2026-11-07 09:00:00")
    entry(user=None, action="login_failed", role=None, ts="2026-11-08 01:00:00")
    assert [r["id"] for r in api.get("/api/audit", params=params).json()["rows"]] == want


def test_a_switch_is_found_by_its_id_host_and_name(api):
    dbfix.insert_switch(id=7, name="SW-7", host="10.0.0.7")
    found = [entry(action="backup", target="7"), entry(action="switch_update", target="10.0.0.7"), entry(action="change_ok", target="SW-7")]
    entry(action="backup", target="8")
    assert ids(api.get("/api/audit", params={"switch_id": 7})) == found[::-1]


def test_pages_in_both_orders_without_gaps(api):
    made = [entry() for _ in range(5)]
    for order, want in (("desc", [made[4:2:-1], made[2:0:-1], made[:1]]), ("asc", [made[:2], made[2:4], made[4:]])):
        pages, cursor = [], None
        for _ in made:                                          # at most one page per row: a pager that never ends fails here
            page = api.get("/api/audit", params={"order": order, "limit": 2, **({"cursor": cursor} if cursor else {})}).json()
            pages.append([r["id"] for r in page["rows"]])
            cursor = page["next"]
            if cursor is None:
                break
        assert (pages, cursor) == (want, None), order


def test_a_bad_time_is_a_german_422(api):
    r = api.get("/api/audit", params={"since": "gestern"})
    assert (r.status_code, r.json()["detail"]) == (422, "Zeitpunkt ungültig")


def test_the_audit_csv_exports_the_filter_with_formula_cells_quoted(api):
    entry(detail="=cmd|' /C calc'!A0")
    entry(action="backup", detail="nicht im Filter")
    r = api.get("/api/audit.csv", params={"action": "login"})
    assert r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"].startswith('attachment; filename="switchview-protokoll-')
    assert r.text.lstrip("\ufeff").splitlines() == ["Zeit (UTC);Benutzer;Rolle;Aktion;Ziel;Details",
                                                    "2026-11-07 10:00:00;anna;Admin;login;;'=cmd|' /C calc'!A0"]


def test_a_zone_limited_user_reads_the_whole_audit(api):
    sid = dbfix.insert_switch(name="VK-1", host="10.0.0.2", zone="VK")
    entry(action="backup", target=str(sid))
    apifix.become(apifix.user("aendern", zones=["EK"]))
    for url in ("/api/audit", "/api/audit.csv"):
        assert api.get(url, params={"switch_id": sid}).status_code == 200, url
    assert len(api.get("/api/audit").json()["rows"]) == 1


# Beyond the plan's block: the cases the interface names that its tests leave open

def test_an_entry_carries_its_fields(api):
    rid = entry(user="ben", action="device_update", target="aa:bb:cc:00:00:01", detail="Drucker freigegeben=1", role="aendern")
    assert api.get("/api/audit").json() == {"rows": [{"id": rid, "ts": "2026-11-07 10:00:00", "username": "ben", "action": "device_update",
                                                      "target": "aa:bb:cc:00:00:01", "detail": "Drucker freigegeben=1", "role": "aendern"}],
                                            "next": None}


def test_a_page_holds_100_entries_unless_asked_for_up_to_500(api):
    dbfix.query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 501) "
                "INSERT INTO audit(username, action, role) SELECT 'anna', 'login', 'admin' FROM n")
    page = api.get("/api/audit").json()
    assert (len(page["rows"]), page["rows"][0]["id"], page["next"]) == (100, 501, 402)
    page = api.get("/api/audit", params={"limit": 500}).json()
    assert (len(page["rows"]), page["next"]) == (500, 2)
    assert ids(api.get("/api/audit", params={"limit": 500, "cursor": 2})) == [1]


@pytest.mark.parametrize("params", [{"q": "x" * 101}, {"action": "x" * 41}, {"user": "x" * 101}, {"role": "gast"}, {"role": ""},
                                    {"since": "2026-11-07" + " " * 31}, {"until": "2026-11-07" + " " * 31}, {"order": "up"}, {"cursor": 0},
                                    {"cursor": 2 ** 63}, {"switch_id": 0}, {"switch_id": 2 ** 63}, {"limit": 0}, {"limit": 501}])
def test_what_is_out_of_bounds_is_a_422(api, params):
    """A larger integer than SQLite stores would fail in the query as a 500 (like the cursor of the history, T3-h)."""
    assert api.get("/api/audit", params=params).status_code == 422
    if "limit" not in params and "cursor" not in params:
        assert api.get("/api/audit.csv", params=params).status_code == 422


@pytest.mark.parametrize("url", ["/api/audit", "/api/audit.csv"])
@pytest.mark.parametrize("params", [{"since": "gestern"}, {"until": "2026-13-01"}, {"since": "2026-11-07", "until": "morgen"}])
def test_each_route_refuses_a_bad_time_in_german(api, url, params):
    r = api.get(url, params=params)
    assert (r.status_code, r.json()["detail"]) == (422, history.BAD_TIME)


@pytest.mark.parametrize("url", ["/api/audit", "/api/audit.csv"])
@pytest.mark.parametrize("params", [{"since": "gestern"}, {"q": "x" * 101}, {"switch_id": 1}])
def test_without_a_session_a_filter_is_never_looked_at(login_api, url, params):
    """The session comes first: a bad time or a bound is no 422, and a switch is not looked up, before the user is known (the filters
    are collected by a dependency that only collects; their condition is built in the route)."""
    assert login_api.get(url, params=params).status_code == 401


def test_since_counts_its_own_second_and_until_does_not(api):
    """T8-b: since inclusive, until exclusive, so the days of a range join without a gap or an entry twice; a date alone is its
    midnight in UTC (history.to_utc)."""
    before, first, last, after = (entry(ts=t) for t in ("2026-11-06 23:59:59", "2026-11-07 00:00:00", "2026-11-07 23:59:59", "2026-11-08 00:00:00"))
    assert ids(api.get("/api/audit", params={"since": "2026-11-07", "until": "2026-11-08"})) == [last, first]
    assert ids(api.get("/api/audit", params={"until": "2026-11-07T00:00:00Z"})) == [before]
    assert ids(api.get("/api/audit", params={"since": "2026-11-08T01:00:00+01:00"})) == [after]


def test_the_text_is_found_in_each_column_as_text(api):
    """Pin of the escaping (the backslash first, then "%" and "_", as in history._question) and of the four columns; a text stays as
    typed: LIKE ignores the case of A-Z only (T3-f), so a capital umlaut is found as written."""
    by_user, by_action, by_target, by_detail = (entry(user="eva.schulz"), entry(action="zone_scopes_update"), entry(target="SW-Lager"),
                                                entry(detail="Drucker Ährenweg"))
    pct, under, slash = entry(detail="50% Rabatt"), entry(detail="a_b"), entry(detail="a\\b")
    entry(detail="pc-50x")
    entry(detail="axb")
    entry(detail="ab")
    for q, want in (("SCHULZ", [by_user]), ("scopes", [by_action]), ("lager", [by_target]), ("Ähren", [by_detail]), ("50%", [pct]),
                    ("a_b", [under]), ("a\\b", [slash])):
        assert ids(api.get("/api/audit", params={"q": q})) == want, q


def test_the_filters_add_up_and_a_text_with_a_cursor_pages_to_its_end(api):
    """Every filter narrows the others (AND), and the four LIKE terms of the text stand in parentheses before the cursor's condition:
    without them a hit in the user would ignore the cursor, and every page began again with the newest rows."""
    hits = [entry(user=f"anna-{i}", role="aendern", ts="2026-11-07 10:00:00") for i in range(5)]
    entry(user="anna-x", role="admin")
    entry(user="anna-y", role="aendern", ts="2026-11-01 10:00:00")
    seen, cursor = [], None
    for _ in hits:
        page = api.get("/api/audit", params={"q": "anna", "role": "aendern", "since": "2026-11-07", "limit": 2,
                                             **({"cursor": cursor} if cursor else {})}).json()
        seen += [r["id"] for r in page["rows"]]
        cursor = page["next"]
        if cursor is None:
            break
    assert (seen, cursor) == (hits[::-1], None)


def test_a_switch_that_is_not_there_is_found_by_its_id_alone(api):
    """Without its row only the id is known; a switch without a name does not take every entry without a target."""
    gone = entry(action="switch_delete", target="9")
    entry(action="settings_update", target="")
    assert ids(api.get("/api/audit", params={"switch_id": 9})) == [gone]
    sid = dbfix.insert_switch(name="", host="10.0.0.3")
    own = entry(action="backup", target=str(sid))
    assert ids(api.get("/api/audit", params={"switch_id": sid})) == [own]


def test_the_csv_names_the_role_in_german_keeps_the_order_and_stops_at_its_maximum(api, monkeypatch):
    for role in ("lesen", "aendern", "freigeben", "admin", None):
        entry(user=None if role is None else "anna", action="login" if role else "login_failed", role=role)
    lines = api.get("/api/audit.csv", params={"order": "asc"}).text.lstrip("\ufeff").splitlines()
    assert [line.split(";")[2] for line in lines[1:]] == ["Lesen", "Ändern", "Freigeben", "Admin", ""]
    assert lines[-1] == "2026-11-07 10:00:00;;;login_failed;;"
    assert api.get("/api/audit.csv").text.lstrip("\ufeff").splitlines()[1].startswith("2026-11-07 10:00:00;;;login_failed")
    monkeypatch.setattr(history, "EXPORT_MAX", 2)
    assert len(api.get("/api/audit.csv").text.lstrip("\ufeff").splitlines()) == 3


def test_the_audit_download_is_named_by_the_date(api):
    entry()
    name = api.get("/api/audit.csv").headers["content-disposition"]
    assert re.fullmatch(r'attachment; filename="switchview-protokoll-\d{4}-\d{2}-\d{2}\.csv"', name), name


@pytest.mark.parametrize("ask, index", [({"action": "login"}, "idx_audit_action"), ({"user": "Anna"}, "idx_audit_user")])
@pytest.mark.parametrize("order", ["desc", "asc"])
@pytest.mark.parametrize("cursor", [None, 5])
def test_an_action_and_a_user_run_on_their_index_and_sort_nothing(api, ask, index, order, cursor):
    """Pin of the two indexes of db.SCHEMA: an action and a user each search their own index in the order of the id, with and without
    a cursor, and nothing is sorted on its own (one line of the plan, no temp b-tree). idx_audit_user carries COLLATE NOCASE: SQLite
    takes no BINARY index for the filter username = ? COLLATE NOCASE."""
    where, args = asyncio.run(api_settings.audit_filter(**ask))
    sql, args = api_settings.audit_select(where, args, order, cursor, 101)
    plan = [row[3] for row in dbfix.query("EXPLAIN QUERY PLAN " + sql, tuple(args))]
    assert len(plan) == 1 and re.search(rf" USING (COVERING )?INDEX {index}\b", plan[0]), plan


def test_an_empty_filter_is_still_a_filter(api):
    """T8-k: a filter applies once it is given, also empty, as the interface writes it - the view leaves empty fields out
    (SVLogic.query). An empty text is part of every entry, an empty action or user is none, an empty role or time is a 422."""
    made = [entry(), entry(user=None, action="login_failed", role=None)]
    assert ids(api.get("/api/audit", params={"q": ""})) == made[::-1]
    assert [ids(api.get("/api/audit", params={k: ""})) for k in ("action", "user")] == [[], []]
    assert [api.get("/api/audit", params={k: ""}).status_code for k in ("role", "since", "until")] == [422, 422, 422]


def test_no_filter_is_the_whole_audit():
    assert asyncio.run(api_settings.audit_filter()) == ("1", [])
