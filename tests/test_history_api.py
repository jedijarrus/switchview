"""Phase 4b, Task 3: searching the history (GET /api/history) and exporting it as CSV (GET /api/history.csv). A search is a MAC in any
usual spelling, an IP address (exact) or a part of a name or MAC (without case), or a switch and a port; the sightings come newest
first (last_seen), paged by the cursor "<last_seen>|<id>" of the last row shown. Both routes need Lesen and are not zone-limited.
The CSV (app/csvout.py) is UTF-8 with a BOM, ";" and CRLF, and a cell that starts like a formula gets a "'" before it.

At the end, Phase 4c Task 1: the watch list (GET/POST /api/watch) holds at most history.WATCH_MAX entries, also with two additions at
once, and is read with every latest sighting in one query.

A fresh database per test (apifix.fresh_db), the rows of sightings written directly through dbfix.
"""
import asyncio
import contextlib
import pathlib
import re
from datetime import datetime, timezone

import pytest

import api_history
import apifix
import csvout
import dbfix
import history

MAC = "aa:bb:cc:00:00:01"


@pytest.fixture
def api(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def sight(mac=MAC, sid=None, switch="A", port="1", vlan="20", ip="", name="", first="2026-11-01 10:00:00", last="2026-11-01 10:00:00",
          suspect=0):
    return dbfix.query("INSERT INTO sightings(mac, switch_id, switch_name, port, vlan, ip, name, suspect, first_seen, last_seen) "
                       "VALUES (?,?,?,?,?,?,?,?,?,?) RETURNING id", (mac, sid, switch, port, vlan, ip, name, suspect, first, last))[0][0]


@pytest.mark.parametrize("q", [MAC, "AA-BB-CC-00-00-01", "aabb.cc00.0001", "aabbcc000001", " aa:bb:cc:00:00:01 "])
def test_a_device_is_found_by_its_mac_in_any_spelling(api, q):
    sight()
    sight(mac="aa:bb:cc:00:00:02")
    assert [r["mac"] for r in api.get("/api/history", params={"q": q}).json()["rows"]] == [MAC]


def test_an_ip_is_found_exactly_and_a_name_in_part(api):
    sight(ip="10.0.0.5", name="Drucker-EK")
    sight(mac="aa:bb:cc:00:00:02", ip="10.0.0.50", name="pc-7")
    assert [r["ip"] for r in api.get("/api/history", params={"q": "10.0.0.5"}).json()["rows"]] == ["10.0.0.5"]
    assert [r["name"] for r in api.get("/api/history", params={"q": "drucker"}).json()["rows"]] == ["Drucker-EK"]
    assert api.get("/api/history", params={"q": "50%"}).json()["rows"] == []                       # % is a character, not a pattern


def test_the_newest_come_first_and_a_cursor_pages_without_gaps(api):
    ids = [sight(port=str(i), last=f"2026-11-0{i} 10:00:00") for i in range(1, 6)]
    seen, cursor = [], None
    while True:
        page = api.get("/api/history", params={"q": MAC, "limit": 2, **({"cursor": cursor} if cursor else {})}).json()
        seen += [r["id"] for r in page["rows"]]
        cursor = page["next"]
        if not cursor:
            break
    assert seen == ids[::-1]


def test_a_port_lists_who_was_there(api):
    sid = dbfix.insert_switch(name="A", host="10.0.0.1")
    sight(sid=sid, port="7")
    sight(mac="aa:bb:cc:00:00:02", sid=sid, port="8")
    assert [r["mac"] for r in api.get("/api/history", params={"switch_id": sid, "port": "7"}).json()["rows"]] == [MAC]


@pytest.mark.parametrize("params, detail", [({}, history.QUERY_HELP), ({"q": "a"}, history.QUERY_HELP), ({"switch_id": 1}, history.QUERY_HELP),
                                            ({"port": "1"}, history.QUERY_HELP), ({"q": "aa", "cursor": "kaputt"}, history.BAD_CURSOR)])
def test_a_bad_question_is_a_german_422(api, params, detail):
    r = api.get("/api/history", params=params)
    assert (r.status_code, r.json()["detail"]) == (422, detail)


def test_a_deleted_switch_keeps_its_sightings_by_name(api):                           # through the route: dbfix's connection has no foreign keys on
    sid = dbfix.insert_switch(name="Alt", host="10.0.0.9")
    sight(sid=sid, switch="Alt")
    assert api.delete(f"/api/switches/{sid}").status_code == 200
    assert [(r["switch_id"], r["switch"]) for r in api.get("/api/history", params={"q": MAC}).json()["rows"]] == [(None, "Alt")]


def test_a_zone_limited_user_reads_every_switch(api):
    sid = dbfix.insert_switch(name="VK-1", host="10.0.0.2", zone="VK")
    sight(sid=sid)
    apifix.become(apifix.user("aendern", zones=["EK"]))
    assert api.get("/api/history", params={"switch_id": sid, "port": "1"}).status_code == 200


@pytest.mark.parametrize("value, cell", [("=1+1", "'=1+1"), ("+49 30 1234", "'+49 30 1234"), ("-x", "'-x"), ("@SUM(A1)", "'@SUM(A1)"),
                                         ("\tx", "'\tx"), ("\rx", "'\rx"), ("\nx", "'\nx"), ("a=b", "a=b"), (None, ""), (5, "5")])
def test_a_cell_that_starts_like_a_formula_is_quoted(value, cell):                       # Review Focus 5
    assert csvout.cell(value) == cell


def test_the_csv_has_a_bom_semicolons_and_quotes_where_needed():
    assert csvout.render(["A", "B"], [["x;y", 'sag "hi"'], ["zwei\nZeilen", "=1"]]) == '\ufeffA;B\r\n"x;y";"sag ""hi"""\r\n"zwei\nZeilen";\'=1\r\n'


def test_the_history_csv_exports_the_search(api):
    sight(name="=HYPERLINK(\"http://x\")")
    r = api.get("/api/history.csv", params={"q": MAC})
    assert r.headers["content-type"].startswith("text/csv") and r.headers["content-disposition"].startswith('attachment; filename="switchview-verlauf-')
    head, row = r.text.lstrip("\ufeff").splitlines()[:2]
    assert head.startswith("MAC;Hersteller;IP;Name;Switch;Port;VLAN;") and "'=HYPERLINK" in row


def test_the_export_stops_at_its_maximum(api, monkeypatch):
    for i in range(3):
        sight(port=str(i))
    monkeypatch.setattr(history, "EXPORT_MAX", 2)
    assert len(api.get("/api/history.csv", params={"q": MAC}).text.lstrip("\ufeff").splitlines()) == 3


# Beyond the plan's block: the cases the interface names that its tests leave open

def test_rows_of_the_same_poll_page_by_their_id(api):
    """Every row a poll records carries that poll's time, so a port or a busy search has many rows with the same last_seen: the
    cursor goes on by id among them, without a gap or a row twice."""
    ids = [sight(mac=f"aa:bb:cc:00:01:{i:02x}") for i in range(5)]
    seen, cursor = [], None
    while True:
        page = api.get("/api/history", params={"q": "aa:bb:cc:00:01", "limit": 2, **({"cursor": cursor} if cursor else {})}).json()
        seen += [r["id"] for r in page["rows"]]
        cursor = page["next"]
        if not cursor:
            break
    assert seen == ids[::-1]


def test_a_row_carries_its_place_its_vendor_and_its_mark(api):
    rid = sight(mac="52:54:00:00:00:01", sid=None, switch="SW-EK", port="5", vlan="30", ip="10.0.0.7", name="vm-1",
                first="2026-11-01 09:00:00", last="2026-11-02 10:00:00", suspect=1)
    assert api.get("/api/history", params={"q": "vm-1"}).json() == {"rows": [{
        "id": rid, "mac": "52:54:00:00:00:01", "vendor": "KVM-VM", "ip": "10.0.0.7", "name": "vm-1", "switch_id": None,
        "switch": "SW-EK", "port": "5", "vlan": "30", "first_seen": "2026-11-01 09:00:00", "last_seen": "2026-11-02 10:00:00",
        "suspect": True}], "next": None}


@pytest.mark.parametrize("q, want", [("192.168.178.100", ("ip", "192.168.178.100")), ("fe80::1", ("ip", "fe80::1")),
                                     ("aabbcc-000001", ("mac", MAC)), ("aa bb cc 00 00 01", ("mac", MAC)), (" Drucker ", ("text", "Drucker"))])
def test_the_kind_of_search_follows_from_the_text(q, want):
    """An IPv4 address with three digits in each part is twelve digits without its dots: it is an IP, not a MAC. A text stays as
    typed: LIKE ignores the case of A-Z by itself."""
    assert history.parse_query(q) == want


def test_a_name_with_an_umlaut_is_found_as_written(api):
    """SQLite's LIKE ignores the case of A-Z only: a text in lower case would never find a capital umlaut."""
    sight(name="Drucker Ährenweg")
    for q in ("Ähren", "DRUCKER Ä"):
        assert [r["name"] for r in api.get("/api/history", params={"q": q}).json()["rows"]] == ["Drucker Ährenweg"], q


def test_a_name_and_a_port_together_are_no_question(api):
    for params in ({"q": MAC, "switch_id": 1, "port": "1"}, {"q": MAC, "port": "1"}, {"switch_id": 1, "port": ""}):
        r = api.get("/api/history", params=params)
        assert (r.status_code, r.json()["detail"]) == (422, history.QUERY_HELP), params


@pytest.mark.parametrize("cursor", ["2026-11-01 10:00:00", "2026-11-01 10:00:00|", "2026-11-01|5", "2026-11-01 10:00:00|-5",
                                    "2026-11-01 10:00:00|1234567890123456789"])
def test_a_cursor_that_does_not_look_like_one_is_refused(api, cursor):
    r = api.get("/api/history", params={"q": MAC, "cursor": cursor})
    assert (r.status_code, r.json()["detail"]) == (422, history.BAD_CURSOR)


def test_the_csv_refuses_a_bad_question_and_marks_a_possible_uplink(api):
    sight(suspect=1)
    assert api.get("/api/history.csv", params={"q": "a"}).json()["detail"] == history.QUERY_HELP
    row = api.get("/api/history.csv", params={"q": MAC}).text.splitlines()[1]
    assert row == "aa:bb:cc:00:00:01;;;;A;1;20;2026-11-01 10:00:00;2026-11-01 10:00:00;ja"


# Review round 1 of Task 3: a guard for the BOM, and pins of behaviour no test above fails without

TEXT_FILES = {".py", ".js", ".html", ".css", ".md", ".json", ".txt", ".svg"}    # the fonts are binary and may hold any bytes


def test_no_file_carries_an_invisible_bom():
    """The BOM of the CSV is written as its escape (backslash, u, feff), never as the invisible character U+FEFF itself: an editor or
    a tool that strips a stray BOM would take it from csvout and from the expected text of the tests at once, the tests would still
    agree, and Excel would show broken umlauts."""
    root = pathlib.Path(__file__).resolve().parents[1]
    bom = "\ufeff".encode()
    found = [str(p.relative_to(root)) for top in ("app", "tests", "docs") for p in sorted((root / top).rglob("*"))
             if p.suffix in TEXT_FILES and bom in p.read_bytes()]
    assert found == []


def test_a_percent_sign_an_underscore_and_a_backslash_are_found_as_themselves(api):
    """Pin: the text of a search is text, not a LIKE pattern (history._question escapes the backslash first, then "%" and "_").
    Unescaped, "50%" found "pc-50x" as well, "a_b" every row (the MAC holds "a:b"), and "a\\b" found "ab" instead of "a\\b"."""
    for name in ("50% Rabatt", "pc-50x", "a_b", "axb", "a\\b", "ab"):
        sight(name=name)
    for q, want in (("50%", ["50% Rabatt"]), ("a_b", ["a_b"]), ("a\\b", ["a\\b"])):
        assert [r["name"] for r in api.get("/api/history", params={"q": q}).json()["rows"]] == want, q


def test_a_search_by_name_pages_to_its_end(api):
    """Pin: the two LIKE terms of a text search stand in parentheses before the cursor's condition. Without them a name hit ignored
    the cursor (name LIKE x OR (mac LIKE x AND cursor)): every page began again with the newest rows and "next" never ran out, so a
    pager in the UI would loop for ever."""
    ids = [sight(mac=f"aa:bb:cc:00:02:{i:02x}", name=f"pc-{i}") for i in range(5)]
    seen, cursor = [], None
    for _ in ids:                                              # at most one page per row: a pager that never ends fails here
        page = api.get("/api/history", params={"q": "pc-", "limit": 2, **({"cursor": cursor} if cursor else {})}).json()
        seen += [r["id"] for r in page["rows"]]
        cursor = page["next"]
        if not cursor:
            break
    assert (seen, cursor) == (ids[::-1], None)


@pytest.fixture
def ran_sql(monkeypatch):
    """Every statement history runs on its connections, as (text, arguments), recorded on its way to the real database."""
    ran = []
    real = history.db

    @contextlib.asynccontextmanager
    async def recording():
        async with real() as conn:
            execute = conn.execute

            def logged(sql, args=()):
                ran.append((sql, tuple(args)))
                return execute(sql, args)

            conn.execute = logged
            yield conn

    monkeypatch.setattr(history, "db", recording)
    return ran


@pytest.mark.parametrize("ask, index", [({"q": MAC}, "idx_sightings_mac"), ({"q": "10.0.0.5"}, "idx_sightings_ip"),
                                        ({"switch_id": 1, "port": "7"}, "idx_sightings_port"), ({"q": "drucker"}, "idx_sightings_seen")])
@pytest.mark.parametrize("cursor", [None, "2026-11-01 10:00:00|5"])
def test_each_search_runs_on_its_index_and_sorts_nothing(api, ran_sql, ask, index, cursor):
    """Pin of the plans under "Kosten der Erfassung", with and without a cursor: a MAC, an IP and a port each search their own index,
    a part of a name walks idx_sightings_seen from the newest row, and none sorts on its own (one line of the plan, no temp b-tree).
    The partial index idx_sightings_ip serves only a query that names its condition: with "ip = ?" alone SQLite walks
    idx_sightings_seen over the whole history, about half a second at 500 000 rows."""
    assert api.get("/api/history", params={**ask, **({"cursor": cursor} if cursor else {})}).status_code == 200
    (sql, args), = ran_sql
    plan = [row[3] for row in dbfix.query("EXPLAIN QUERY PLAN " + sql, args)]
    assert len(plan) == 1 and re.search(rf" USING (COVERING )?INDEX {index}\b", plan[0]), plan


class LateEvening(datetime):
    """23:30 UTC on 2026-11-07, already 00:30 on the 8th in Berlin: now() without a zone answers the local time."""

    @classmethod
    def now(cls, tz=None):
        utc = datetime(2026, 11, 7, 23, 30, tzinfo=timezone.utc)
        return utc.astimezone(tz) if tz else datetime(2026, 11, 8, 0, 30)


def test_the_download_is_named_by_the_date_in_utc(api, monkeypatch):
    """Pin of csvout.response: the whole name, <stem>-<YYYY-MM-DD>.csv with today's date in UTC (the times in the file are UTC too)."""
    sight()
    monkeypatch.setattr(csvout, "datetime", LateEvening)
    r = api.get("/api/history.csv", params={"q": MAC})
    assert (r.headers["content-type"], r.headers["content-disposition"]) == (
        "text/csv; charset=utf-8", 'attachment; filename="switchview-verlauf-2026-11-07.csv"')


def watch_999() -> None:
    """999 watched MACs (02:00:00:00:00:00 on), written directly: room for exactly one more."""
    dbfix.query("WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 998) INSERT INTO watch_macs(mac, note, created_at) "
                "SELECT printf('02:00:00:00:%02x:%02x', i / 256, i % 256), '', '2026-11-08 00:00:00' FROM n")


def test_the_watch_list_holds_at_most_1000_macs(api):                                    # 4b, Später 4c
    watch_999()
    assert api.post("/api/watch", json={"mac": "aa:bb:cc:dd:ee:fe", "note": ""}).status_code == 200       # the 1000th still fits
    r = api.post("/api/watch", json={"mac": "aa:bb:cc:dd:ee:ff", "note": ""})
    assert (r.status_code, r.json()["detail"]) == (422, api_history.WATCH_FULL) and dbfix.query("SELECT count(*) FROM watch_macs") == [(1000,)]


@pytest.fixture
def database(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)


async def test_two_additions_at_once_cannot_pass_the_limit(database, monkeypatch):
    """Pin of BEGIN IMMEDIATE in history.watch_add: each INSERT waits 0.2 s after its count, so without the write transaction both
    would count 999 and both insert. With it the second count waits for the first commit and sees 1000."""
    watch_999()
    real = history.db

    @contextlib.asynccontextmanager
    async def slow_insert():
        async with real() as conn:
            execute = conn.execute

            async def later(sql, args):
                await asyncio.sleep(0.2)
                return await execute(sql, args)

            conn.execute = lambda sql, args=(): later(sql, args) if sql.startswith("INSERT INTO watch_macs") else execute(sql, args)
            yield conn

    monkeypatch.setattr(history, "db", slow_insert)
    both = await asyncio.gather(*(history.watch_add(mac, "", apifix.user("aendern")) for mac in ("aa:bb:cc:dd:ee:fe", "aa:bb:cc:dd:ee:ff")),
                                return_exceptions=True)
    assert sorted(type(r).__name__ for r in both) == ["WatchFull", "dict"] and dbfix.query("SELECT count(*) FROM watch_macs") == [(1000,)]


def test_the_watch_list_reads_every_latest_sighting_in_one_query(api, ran_sql):         # 4b, Später 4c
    for mac in ("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"):
        api.post("/api/watch", json={"mac": mac, "note": ""})
    dbfix.query("INSERT INTO sightings(mac, switch_name, port, vlan, first_seen, last_seen) VALUES "
                "('aa:bb:cc:00:00:01', 'SW', '5', '20', '2026-11-01 08:00:00', '2026-11-01 09:00:00'), "
                "('aa:bb:cc:00:00:01', 'SW', '6', '20', '2026-11-02 08:00:00', '2026-11-02 09:00:00')")
    want = asyncio.run(history.search(q="aa:bb:cc:00:00:01"))["rows"][0]
    ran_sql.clear()
    got = api.get("/api/watch").json()
    assert [(w["mac"], w["last"]) for w in got] == [("aa:bb:cc:00:00:01", want), ("aa:bb:cc:00:00:02", None)]
    assert ran_sql == [(history._WATCH_LIST, ())]                                         # one statement for both entries
