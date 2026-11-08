"""Phase 4b, Task 4: discrete events (app/monitor.py, table events) - a switch that stops answering after three failed polls and
answers again with the first good one, an LLDP neighbour that appears, changes (another sysName or PortId) or vanishes, a port
changed outside SwitchView at a switch SwitchView does not back up (drift (b): untagged, tagged, PVID, status, name), and a backup
that differs from the one before without a SwitchView change between them (drift (a), config_backups.outside). A change explains a
drift when it may have sent something (changes.sent != 0) and ran in the window; a field of a walk that failed or broke off or of
a PVID, status or name table that answered without a row, the VLANs of an empty VLAN table, and a field the poll before could not
read (each field after a poll from before the update with gaps) count for nothing. GET /api/events lists them, newest first.

The network of tests/netfix.py (fixture `net` from tests/conftest.py), polled by the real poller; the clock of poll_switch is
poller.utc_now (clock of tests/test_history.py). CATALYST is the Catalyst of tests/test_uplinks.py (driver cisco: no backup, so it
has drift (b)): Po1 (bp 56) with the members Gi1/0/3 and Gi1/0/4, Gi1/0/1 on bp 1 with PVID 10, Gi1/0/2 on bp 2. Backups go
through sshcli.store_backup on a fresh database (apifix.fresh_db).
"""
import json

import pytest

import apifix
import crypto
import dbfix
import history
import monitor
import poller
import snmp
import sshcli
from netfix import add, lldp, merge
from switchfix import W_SAMPLE, WALK_BASES, edit_walks
from test_history import clock
from test_uplinks import CATALYST

OIDS = poller.O
P = [f"2000-01-01 10:{m:02}:00" for m in range(0, 60, 5)]          # the poll times of the clock: 10:00, 10:05, ... 10:55
BETWEEN = "2000-01-01 10:02:00"                                     # a time between the first two polls


@pytest.fixture
def database(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)


@pytest.fixture
def api(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def refuse(monkeypatch, host: str, oid: str | None = None) -> dict:
    """From now on snmp.walk raises SnmpError("Timeout") for host (only for oid, if given) while the returned switch is on."""
    gate, walk = {"on": True}, snmp.walk

    async def refusing(h, cred, o, **kw):
        if gate["on"] and h == host and oid in (None, o):
            raise snmp.SnmpError("Timeout")
        return await walk(h, cred, o, **kw)

    monkeypatch.setattr(snmp, "walk", refusing)
    return gate


def cut(monkeypatch, host: str, oid: str, keep: int = 1) -> dict:
    """From now on the walk of oid at host breaks off after its first keep rows while the returned switch is on, as a lenient
    snmp.walk returns one whose snmpbulkwalk ended with an exit code != 0 (snmp.Rows with broken_off, as tests/test_poll_robust.py
    builds one)."""
    gate, walk = {"on": True}, snmp.walk

    async def cutting(h, cred, o, **kw):
        rows = await walk(h, cred, o, **kw)
        return snmp.Rows(rows[:keep], broken_off="Timeout") if gate["on"] and (h, o) == (host, oid) else rows

    monkeypatch.setattr(snmp, "walk", cutting)
    return gate


def revalue(net, host: str, W: dict, **edits) -> None:
    """The recording of host anew from edit_walks(W, **edits) and its sysName, as netfix.add builds it."""
    net.rec[host] = merge({WALK_BASES[k]: rows for k, rows in edit_walks(W, **edits).items()}, {OIDS["sysName"]: net.rec[host][OIDS["sysName"]]})


def change_row(sid: int, *, ports: str = '["Gi1/0/1"]', sent: int | None = 1, kind: str = "ports", mechanism: str = "snmp",
               at: str = BETWEEN, finished: str | None = "") -> int:
    """A changes row of switch sid, status ok, created at `at` and finished then too (finished=None: still running); its id."""
    return dbfix.query("INSERT INTO changes(switch_id, created_at, finished_at, kind, summary, ports, status, sent, mechanism) "
                       "VALUES (?,?,?,?,?,?,?,?,?) RETURNING id",
                       (sid, at, at if finished == "" else finished, kind, "Test", ports, "ok", sent, mechanism))[0][0]


def events() -> list[tuple]:
    return dbfix.query("SELECT kind, port, text FROM events ORDER BY id")


# ── The pure parts ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("old, new, want", [
    ({"1": []}, {"1": [["B", "2", "2"]]}, [("1", "lldp_new")]), ({"1": [["B", "2", "2"]]}, {"1": []}, [("1", "lldp_gone")]),
    ({"1": [["B", "2", "2"]]}, {"1": [["C", "5", "5"]]}, [("1", "lldp_changed")]),
    ({"1": [["B", "2", "2"]]}, {"1": [["B", "GigabitEthernet2", "2"]]}, []),           # the same neighbour, another PortDesc
    ({}, {"1": [["B", "2", "2"]]}, [])], ids=["new", "gone", "changed", "desc", "unknown-port"])
def test_lldp_changes(old, new, want):
    assert [(p, k) for p, k, _, _ in monitor.lldp_changes(old, new)] == want


@pytest.mark.parametrize("old, new, want", [
    ({"1": [["B", "2", "2"], ["C", "5", "5"]]}, {"1": [["C", "5", "5"], ["B", "2", "2"]]}, []),          # another order is no change
    ({"1": [["B", "2"]]}, {"1": [["B", "Port 2", "2"]]}, []),                         # an entry from before R40: its PortId is element 1
    ({"2": [], "1": []}, {"1": [["B", "2", "2"]], "2": [["C", "5", "5"]]}, [("1", "lldp_new"), ("2", "lldp_new")])],
    ids=["order", "before-r40", "port-order-of-new"])
def test_lldp_changes_compare_the_neighbours_as_a_set_in_the_port_order_of_now(old, new, want):
    assert [(p, k) for p, k, _, _ in monitor.lldp_changes(old, new)] == want


OLD = {"1": {"untagged": '["20"]', "tagged": '["30"]', "pvid": "20", "admin": 1, "alias": "Raum", "trunk": ""}}


def now_port(**kw):
    return [{"name": "1", "untagged": ["20"], "tagged": ["30"], "pvid": "20", "admin": 1, "alias": "Raum", "trunk": "", **kw}]


@pytest.mark.parametrize("kw, unreadable, want", [({"untagged": ["99"]}, set(), {"1": {"untagged": (["20"], ["99"])}}),
    ({"alias": "Neu", "admin": 0}, set(), {"1": {"admin": (1, 0), "alias": ("Raum", "Neu")}}), ({"alias": "Neu"}, {"alias"}, {}),
    ({}, set(), {})])
def test_port_drift(kw, unreadable, want):
    assert monitor.port_drift(OLD, now_port(**kw), unreadable) == want


def test_a_port_the_last_poll_did_not_know_is_no_drift():
    assert monitor.port_drift(OLD, [{**now_port()[0], "name": "2", "pvid": "99"}], set()) == {}


@pytest.mark.parametrize("failed, vlans, want", [
    (set(), {"1": "default"}, set()), ({"vlanEgress"}, {"1": "default"}, {"untagged", "tagged"}),
    ({"ifStack"}, {"1": "default"}, {"untagged", "tagged", "pvid"}), ({"ifAlias", "ifAdmin"}, {"1": "default"}, {"alias", "admin"}),
    ({"fdb", "lldpSys"}, {"1": "default"}, set()), (set(), {}, {"untagged", "tagged"})],
    ids=["complete", "vlan-walk", "ifstack", "alias-admin", "other-walks", "empty-vlan-table"])
def test_the_fields_a_poll_could_not_read(failed, vlans, want):
    assert monitor.unread_fields(failed, {"vlans": vlans}) == want


def test_the_text_of_a_drift_names_each_field_in_order_and_ends_at_500():
    fields = {"alias": ("Raum", ""), "admin": (1, 0), "pvid": ("", "20"), "tagged": ([], ["30", "40"]), "untagged": (["20"], [])}
    assert monitor.drift_text("1", fields) == ("Port 1 außerhalb von SwitchView geändert: ungetaggt 20 → –; getaggt – → 30, 40; "
                                               "PVID – → 20; Status an → aus; Name „Raum“ → „“")
    text = monitor.drift_text("1", {"tagged": ([], [str(v) for v in range(100, 400)])})
    assert len(text) == 500 and text.endswith("…")


@pytest.mark.parametrize("value, want", [
    ("2026-11-07T00:00:00+01:00", "2026-11-06 23:00:00"), ("2026-11-06T23:00:00.000Z", "2026-11-06 23:00:00"),
    ("2026-11-07 10:00:00", "2026-11-07 10:00:00"), ("2026-11-07", "2026-11-07 00:00:00"), (" 2026-11-07T10:00Z ", "2026-11-07 10:00:00")],
    ids=["offset", "z-millis", "no-zone", "date", "trimmed"])
def test_to_utc(value, want):
    assert history.to_utc(value) == want


@pytest.mark.parametrize("value", ["gestern", "", "2026-13-01", "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_to_utc_refuses_what_is_no_time(value):
    with pytest.raises(ValueError, match="^Zeitpunkt ungültig$"):
        history.to_utc(value)


# ── Reachability ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_three_failed_polls_mark_a_switch_unreachable_once(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    refuse(monkeypatch, "10.0.0.1")                                     # from now on snmp.walk raises for that host
    for _ in range(4):
        await poller.poll_switch(sid)
    assert dbfix.query("SELECT kind FROM events") == [("switch_down",)] and dbfix.query(
        "SELECT poll_failures, down_since IS NOT NULL FROM switches") == [(4, 1)]


async def test_the_down_event_says_how_often_and_why(net, monkeypatch):
    clock(monkeypatch, *P)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    refuse(monkeypatch, "10.0.0.1")
    for _ in range(3):
        await poller.poll_switch(sid)
    assert dbfix.query("SELECT ts, switch_id, port, text, json_extract(detail, '$.failures') FROM events") == [
        (P[3], sid, "", "A antwortet seit 3 Abfragen nicht: Timeout", 3)]
    assert dbfix.query("SELECT down_since, last_ok_at FROM switches") == [(P[3], P[0])]


async def test_a_good_poll_after_that_says_it_answers_again(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    gate = refuse(monkeypatch, "10.0.0.1")
    for _ in range(3):
        await poller.poll_switch(sid)
    gate["on"] = False
    await poller.poll_switch(sid)
    assert [k for k, _, _ in events()] == ["switch_down", "switch_up"] and events()[1][2].startswith("A antwortet wieder (nach ")
    assert dbfix.query("SELECT poll_failures, down_since FROM switches") == [(0, None)]


@pytest.mark.parametrize("up_at, text", [("2000-01-01 10:01:30", "A antwortet wieder (nach 1 Minute)"),
                                         ("2000-01-01 10:45:00", "A antwortet wieder (nach 45 Minuten)")], ids=["one", "many"])
async def test_the_up_event_counts_the_minutes_since_the_switch_last_answered(net, monkeypatch, up_at, text):
    clock(monkeypatch, "2000-01-01 10:00:00", "2000-01-01 10:00:20", "2000-01-01 10:00:40", "2000-01-01 10:01:00", up_at)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    gate = refuse(monkeypatch, "10.0.0.1")
    for _ in range(3):
        await poller.poll_switch(sid)
    gate["on"] = False
    await poller.poll_switch(sid)
    assert events()[-1] == ("switch_up", "", text) and dbfix.query("SELECT last_ok_at FROM switches") == [(up_at,)]


async def test_two_failed_polls_say_nothing(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    refuse(monkeypatch, "10.0.0.1")
    for _ in range(2):
        await poller.poll_switch(sid)
    assert events() == [] and dbfix.query("SELECT poll_failures, down_since FROM switches") == [(2, None)]


async def test_a_good_poll_between_failed_ones_starts_the_count_again(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    gate = refuse(monkeypatch, "10.0.0.1")
    for on in (True, True, False, True, True):
        gate["on"] = on
        await poller.poll_switch(sid)
    assert events() == [] and dbfix.query("SELECT poll_failures FROM switches") == [(2,)]


async def test_a_failing_down_check_never_changes_the_failed_poll(net, monkeypatch, caplog):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    refuse(monkeypatch, "10.0.0.1")
    monkeypatch.setattr(monitor, "poll_failed", dbfix.raising_async_fn(RuntimeError("kaputt")))
    assert await poller.poll_switch(sid) == {"ok": False, "error": "Timeout"} and "Ereignisse 10.0.0.1" in caplog.text


# ── LLDP neighbours ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_poll_records_a_new_lldp_neighbour_and_marks_an_uplink(net, monkeypatch):
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    net.rec["10.0.0.1"] |= lldp("2", "B", "2", "2")
    await poller.poll_switch(sid)
    assert dbfix.query("SELECT kind, port, text, json_extract(detail, '$.uplink') FROM events") == [
        ("lldp_new", "2", "Port 2: neuer LLDP-Nachbar B (Port 2)", 1)]


async def test_a_neighbour_that_changes_and_goes_is_told_each_time(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "ap-1", "eth0", "Uplink AP"))
    rec = dict(net.rec["10.0.0.1"])
    net.rec["10.0.0.1"] = rec | merge(lldp("2", "ap-2", "eth0", "AP"), lldp("2", "phone", "", "LAN", rem=2))
    await poller.poll_switch(sid)
    net.rec["10.0.0.1"] = rec | {OIDS[k]: [] for k in poller.LLDP_WALKS}
    await poller.poll_switch(sid)
    assert dbfix.query("SELECT kind, port, text, json_extract(detail, '$.uplink') FROM events ORDER BY id") == [
        ("lldp_changed", "2", "Port 2: LLDP-Nachbar ap-1 (Port eth0) → ap-2 (Port eth0), phone (Port LAN)", 0),
        ("lldp_gone", "2", "Port 2: LLDP-Nachbar ap-2 (Port eth0), phone (Port LAN) nicht mehr da", 0)]
    assert json.loads(dbfix.query("SELECT detail FROM events ORDER BY id")[0][0]) == {
        "uplink": False, "before": [["ap-1", "Uplink AP", "eth0"]], "after": [["ap-2", "AP", "eth0"], ["phone", "LAN", ""]]}


async def test_a_neighbour_on_a_trunk_member_is_at_an_uplink(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    net.rec["10.0.0.1"] |= lldp("4", "core-unmanaged", "25", "25")       # port 4 is a member of Trk1
    await poller.poll_switch(sid)
    assert dbfix.query("SELECT kind, port, json_extract(detail, '$.uplink') FROM events") == [("lldp_new", "4", 1)]


async def test_the_first_poll_reports_nothing(net, monkeypatch):
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "B", "2", "2"))
    assert events() == []


async def test_a_failed_lldp_walk_reports_no_vanished_neighbour(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "B", "2", "2"))
    refuse(monkeypatch, "10.0.0.1", OIDS["lldpSys"])
    await poller.poll_switch(sid)
    assert events() == []


async def test_a_neighbour_seen_while_an_lldp_walk_fails_is_no_event(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "B", "2", "2"))
    net.rec["10.0.0.1"] = merge(net.rec["10.0.0.1"], lldp("6", "C", "5", "5"))
    refuse(monkeypatch, "10.0.0.1", OIDS["lldpPortId"])               # C is read without its PortId: not to be compared
    await poller.poll_switch(sid)
    assert events() == []


# ── Port drift (b) ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_vlan_changed_outside_switchview_is_drift(net, monkeypatch):
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    await poller.poll_switch(sid)
    assert dbfix.query("SELECT kind, port, text FROM events") == [
        ("drift_port", "Gi1/0/1", "Port Gi1/0/1 außerhalb von SwitchView geändert: PVID 10 → 20")]
    assert json.loads(dbfix.query("SELECT detail FROM events")[0][0]) == {"changes": {"pvid": ["10", "20"]}}


async def test_every_field_of_a_port_is_compared(net, monkeypatch):
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    revalue(net, "10.0.0.3", CATALYST, ifAlias={"10101": "Büro"}, ifAdmin={"10101": "2"},
            vlanUntagged={"10": "00 00 00 00 00 00 00 00", "20": "90 00 00 00 00 00 00 00"},
            vlanEgress={"10": "00 00 00 00 00 00 01 00", "20": "D0 00 00 00 00 00 01 00"})
    await poller.poll_switch(sid)
    assert events() == [("drift_port", "Gi1/0/1", "Port Gi1/0/1 außerhalb von SwitchView geändert: ungetaggt 10 → 20; Status an → aus; "
                                                  "Name „Drucker“ → „Büro“")]


async def test_a_change_by_switchview_on_that_port_is_no_drift(net, monkeypatch):    # Review Focus 3
    clock(monkeypatch, *P)
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    change_row(sid)
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    await poller.poll_switch(sid)
    assert events() == []


async def test_a_change_that_sent_nothing_explains_nothing(net, monkeypatch):
    clock(monkeypatch, *P)
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    change_row(sid, sent=0)
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    await poller.poll_switch(sid)
    assert events() == [("drift_port", "Gi1/0/1", "Port Gi1/0/1 außerhalb von SwitchView geändert: PVID 10 → 20")]


@pytest.mark.parametrize("ports, at, finished", [('["Gi1/0/2"]', BETWEEN, ""), ('["Gi1/0/1"]', "1999-12-31 10:00:00", ""),
                                                 ('["Gi1/0/1"]', "2000-01-01 09:00:00", "2000-01-01 09:59:59")],
                         ids=["another-port", "before-the-window", "ended-before-the-last-poll"])
async def test_a_change_elsewhere_or_before_explains_nothing(net, monkeypatch, ports, at, finished):
    clock(monkeypatch, *P)
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    change_row(sid, ports=ports, at=at, finished=finished)
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    await poller.poll_switch(sid)
    assert [k for k, _, _ in events()] == ["drift_port"]


@pytest.mark.parametrize("kind", ["prepare", "save"])
async def test_a_change_of_the_whole_switch_explains_every_port(net, monkeypatch, kind):
    clock(monkeypatch, *P)
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    change_row(sid, ports="[]", kind=kind, mechanism="ssh", finished=None)        # still running counts as well
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    await poller.poll_switch(sid)
    assert events() == []


async def test_a_change_that_starts_while_the_poll_reads_explains_its_port(net, monkeypatch):
    clock(monkeypatch, *P)
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    walk = snmp.walk

    async def a_change_meanwhile(h, cred, o, **kw):                    # created after the poll's start, before it reads the PVIDs
        if o == OIDS["pvid"]:
            change_row(sid, at="2000-01-01 10:05:10")
        return await walk(h, cred, o, **kw)

    monkeypatch.setattr(snmp, "walk", a_change_meanwhile)
    await poller.poll_switch(sid)
    assert events() == []


@pytest.mark.parametrize("explained", [True, False], ids=["with-the-change", "without"])
async def test_a_trunk_change_explains_its_members(net, monkeypatch, explained):
    clock(monkeypatch, *P)
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    if explained:
        change_row(sid, ports='["Po1"]')
    revalue(net, "10.0.0.3", CATALYST, vlanEgress={"20": "50 00 00 00 00 00 00 00"})    # bp 56 (Po1) leaves VLAN 20
    await poller.poll_switch(sid)
    assert events() == ([] if explained else [
        ("drift_port", port, f"Port {port} außerhalb von SwitchView geändert: getaggt 10, 20 → 10") for port in ("Po1", "Gi1/0/3", "Gi1/0/4")])


async def test_a_failed_vlan_walk_is_no_drift(net, monkeypatch):                    # Review Focus 1
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    refuse(monkeypatch, "10.0.0.3", OIDS["vlanEgress"])                # every port would read without its tagged VLANs
    await poller.poll_switch(sid)
    assert events() == []


async def test_a_broken_off_walk_is_no_drift(net, monkeypatch):
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    cut(monkeypatch, "10.0.0.3", OIDS["pvid"])                         # only bp 1's PVID: Gi1/0/2 and Po1 with its members read none
    await poller.poll_switch(sid)
    assert events() == []


async def test_an_empty_vlan_table_is_no_drift(net, monkeypatch):
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    revalue(net, "10.0.0.3", CATALYST)
    for key in ("vlanName", "vlanEgress", "vlanUntagged"):            # a narrowed SNMP view
        net.rec["10.0.0.3"][OIDS[key]] = []
    await poller.poll_switch(sid)
    assert events() == []


@pytest.mark.parametrize("gap", ["failed", "broken-off", "empty"])
async def test_the_poll_after_a_gap_is_no_drift_but_the_one_after_that_compares_again(net, monkeypatch, gap):
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    if gap == "failed":
        gate = refuse(monkeypatch, "10.0.0.3", OIDS["vlanEgress"])
    elif gap == "broken-off":
        gate = cut(monkeypatch, "10.0.0.3", OIDS["vlanEgress"])
    else:
        gate = {"on": False}
        for key in ("vlanName", "vlanEgress"):
            net.rec["10.0.0.3"][OIDS[key]] = []
    await poller.poll_switch(sid)                                       # the gap: stored without (some) tagged VLANs
    gate["on"] = False
    revalue(net, "10.0.0.3", CATALYST)
    await poller.poll_switch(sid)                                       # complete again, compared with the gap: no drift
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    await poller.poll_switch(sid)                                       # and the next one compares again
    assert events() == [("drift_port", "Gi1/0/1", "Port Gi1/0/1 außerhalb von SwitchView geändert: PVID 10 → 20")]


@pytest.mark.parametrize("tables", [("vlanName", "vlanEgress", "vlanUntagged", "pvid"), ("pvid",), ("ifAdmin",), ("ifAlias",),
                                    ("ifAdmin", "ifAlias")], ids=["without-q-bridge", "pvid", "ifadmin", "ifalias", "if-mib"])
async def test_a_narrowed_view_is_no_drift_when_it_comes_nor_when_it_goes(net, monkeypatch, tables):
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    revalue(net, "10.0.0.3", CATALYST)
    for key in tables:                                                  # answering without a single row: a narrowed SNMP view
        net.rec["10.0.0.3"][OIDS[key]] = []
    await poller.poll_switch(sid)                                       # every port would read PVID "", status off or no name
    assert events() == []
    revalue(net, "10.0.0.3", CATALYST)                                  # the view restored
    await poller.poll_switch(sid)                                       # compared with the narrowed poll: no drift either
    assert events() == []
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"}, ifAlias={"10101": "Büro"}, ifAdmin={"10101": "2"})
    await poller.poll_switch(sid)                                       # and the next one compares again, every field of it
    assert events() == [("drift_port", "Gi1/0/1", "Port Gi1/0/1 außerhalb von SwitchView geändert: PVID 10 → 20; Status an → aus; "
                                                   "Name „Drucker“ → „Büro“")]


@pytest.mark.parametrize("note, want", [("Teilweise gelesen: vlanEgress fehlgeschlagen (Timeout)", []), (None, ["Gi1/0/1"])],
                         ids=["partial", "complete"])
async def test_the_first_poll_after_the_update_compares_only_with_a_complete_poll_from_before(net, monkeypatch, note, want):
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    gate = refuse(monkeypatch, "10.0.0.3", OIDS["vlanEgress"])
    gate["on"] = note is not None
    await poller.poll_switch(sid)                                       # with a note: stored without its tagged VLANs
    assert dbfix.query("SELECT last_error FROM switches") == [(note,)]
    dbfix.query("UPDATE switches SET unread_fields = NULL, last_ok_at = NULL")    # as a poll from before the update left it
    gate["on"] = False
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    await poller.poll_switch(sid)
    assert [port for _, port, _ in events()] == want


async def test_a_switch_with_backups_gets_no_port_drift(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    dbfix.query("UPDATE switches SET ssh_user = 'manager', ssh_pass = ? WHERE id = ?", (crypto.encrypt("ssh-s3cret"), sid))
    revalue(net, "10.0.0.1", W_SAMPLE, pvid={"3": "30"})
    await poller.poll_switch(sid)
    assert events() == []


async def test_a_procurve_without_ssh_gets_port_drift(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    revalue(net, "10.0.0.1", W_SAMPLE, pvid={"3": "30"})
    await poller.poll_switch(sid)
    assert events() == [("drift_port", "1", "Port 1 außerhalb von SwitchView geändert: PVID 20 → 30")]


async def test_a_failing_monitor_never_fails_the_poll(net, monkeypatch, caplog):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    monkeypatch.setattr(monitor, "poll_succeeded", dbfix.raising_async_fn(RuntimeError("kaputt")))
    assert (await poller.poll_switch(sid))["ok"] is True and "Ereignisse 10.0.0.1" in caplog.text


async def test_the_poll_hands_the_monitor_what_it_read(net, monkeypatch):
    seen = []

    async def spy(row, old, data, failed, at):
        seen.append((row["name"], sorted(old), [p["name"] for p in data["ports"]], sorted(failed), at))
        return []

    clock(monkeypatch, *P)
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    monkeypatch.setattr(monitor, "poll_succeeded", spy)
    refuse(monkeypatch, "10.0.0.3", OIDS["ifAlias"])
    cut(monkeypatch, "10.0.0.3", OIDS["vlanName"])
    await poller.poll_switch(sid)
    names = ["Po1", "Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"]
    assert seen == [("C", sorted(names), names, ["ifAlias", "vlanName"], P[1])]


async def test_explained_ports_names_the_ports_of_each_change_that_may_have_sent(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    for ports, sent, kind, at, finished in [('["1", "2"]', 1, "ports", "2000-01-01 10:01:00", ""), ('["3"]', None, "ports", BETWEEN, ""),
                                            ('["4"]', 0, "ports", BETWEEN, ""), ('["5"]', 1, "ports", "2000-01-01 09:00:00", ""),
                                            ('["6"]', 1, "ports", "2000-01-01 11:00:00", ""), ('["7"]', 1, "ports", "2000-01-01 09:00:00", None)]:
        change_row(sid, ports=ports, sent=sent, kind=kind, at=at, finished=finished)
    assert await monitor.explained_ports(sid, "2000-01-01 10:00:00", "2000-01-01 10:05:00") == {"1", "2", "3", "7"}
    assert await monitor.explained_ports(sid, "2000-01-01 10:00:00", "2000-01-01 10:05:00", exclude=1) == {"3", "7"}
    change_row(sid, ports="[]", kind="save", mechanism="ssh")
    assert "*" in await monitor.explained_ports(sid, "2000-01-01 10:00:00", "2000-01-01 10:05:00")
    assert await monitor.explained_ports(sid + 1, "2000-01-01 10:00:00", "2000-01-01 10:05:00") == set()


# ── Configuration drift (a) ───────────────────────────────────────────────────────────────────────────────────────────────────────
CFG_A, CFG_B = 'hostname "SW"\nvlan 1\n   untagged 1-4\n   exit\n', 'hostname "SW"\nvlan 1\n   untagged 1-4\n   exit\ninterface 2\n   name "Fremd"\n   exit\n'


async def backups(sid, *steps):
    """steps: ("backup", text, trigger) or ("change", sent, kind[, mechanism]); each step a minute after the one before, from
    2000-01-01 09:00. A backup goes through sshcli.store_backup, then its new row (if it made one) gets the step's time as taken_at;
    a change is a changes row created and finished at the step's time, status ok, ports ["2"], mechanism ssh unless given."""
    for i, (what, *args) in enumerate(steps):
        at = f"2000-01-01 09:{i:02}:00"
        if what == "backup":
            if await sshcli.store_backup(sid, args[0], args[1]):
                dbfix.query("UPDATE config_backups SET taken_at = ? WHERE id = (SELECT max(id) FROM config_backups)", (at,))
        else:
            sent, kind, *mechanism = args
            change_row(sid, ports='["2"]', sent=sent, kind=kind, mechanism=(mechanism or ["ssh"])[0], at=at)


def outside() -> list[tuple]:
    return dbfix.query("SELECT outside FROM config_backups ORDER BY id")


async def test_a_backup_that_differs_without_a_change_is_outside(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await backups(sid, ("backup", CFG_A, "nightly"), ("backup", CFG_B, "nightly"))
    assert dbfix.query("SELECT outside FROM config_backups ORDER BY id") == [(None,), (1,)]
    assert dbfix.query("SELECT kind, json_extract(detail, '$.previous') FROM events") == [("drift_config", 1)]


async def test_the_drift_event_names_the_backup_and_its_time(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await sshcli.store_backup(sid, CFG_A, "nightly")
    await sshcli.store_backup(sid, CFG_B, "manual")
    (taken_at,), = dbfix.query("SELECT taken_at FROM config_backups WHERE id = 2")
    assert dbfix.query("SELECT ts, switch_id, port, text, detail FROM events") == [
        (taken_at, sid, "", f"Konfiguration außerhalb von SwitchView geändert (Sicherung vom {taken_at} UTC)",
         json.dumps({"backup": 2, "previous": 1}))]


async def test_the_backups_around_a_change_are_not_outside(database):                 # Review Focus 3
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await backups(sid, ("backup", CFG_A, "nightly"), ("change", 1, "ports"), ("backup", CFG_A, "vor #1"), ("backup", CFG_B, "nach #1"))
    assert outside() == [(None,), (0,)] and events() == []


async def test_the_backup_after_a_change_is_explained_by_it_also_when_the_one_before_it_differs(database):
    # run_change stores "vor #1" and "nach #1" after the change ended: the window between them holds no change, #1 explains "nach #1"
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    cfg_c = CFG_B.replace("Fremd", "Neu")
    await backups(sid, ("backup", CFG_A, "nightly"), ("change", 1, "ports"), ("backup", CFG_B, "vor #1"), ("backup", cfg_c, "nach #1"))
    assert outside() == [(None,), (1,), (0,)]


async def test_the_backup_after_a_change_that_sent_nothing_is_outside(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await backups(sid, ("backup", CFG_A, "nightly"), ("change", 0, "ports"), ("backup", CFG_B, "nach #1"))
    assert outside() == [(None,), (1,)]


async def test_the_backup_before_a_change_that_differs_is_outside(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await backups(sid, ("backup", CFG_A, "nightly"), ("change", 1, "ports"), ("backup", CFG_B, "vor #1"))
    assert outside() == [(None,), (1,)]


async def test_an_snmp_change_between_two_backups_explains_the_difference(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await backups(sid, ("backup", CFG_A, "nightly"), ("change", 1, "ports", "snmp"), ("backup", CFG_B, "nightly"))
    assert outside() == [(None,), (0,)]


async def test_a_change_before_the_last_backup_explains_nothing(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await backups(sid, ("change", 1, "ports", "snmp"), ("backup", CFG_A, "nightly"), ("backup", CFG_B, "nightly"))
    assert outside() == [(None,), (1,)]


async def test_a_secret_only_change_outside_is_outside(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    key = 'radius-server host 10.0.0.9 key "{}"\n'
    await backups(sid, ("backup", CFG_A + key.format("eins"), "nightly"), ("backup", CFG_A + key.format("zwei"), "nightly"))
    assert outside() == [(None,), (1,)] and dbfix.query("SELECT count(DISTINCT sha) FROM config_backups") == [(1,)]


async def test_a_failing_drift_check_keeps_the_backup(database, monkeypatch, caplog):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await sshcli.store_backup(sid, CFG_A, "nightly")

    async def half_done(conn, switch_id, backup_id, trigger, taken_at):
        await conn.execute("UPDATE config_backups SET outside = 1 WHERE id = ?", (backup_id,))
        raise RuntimeError("kaputt")

    monkeypatch.setattr(monitor, "backup_outside", half_done)
    assert await sshcli.store_backup(sid, CFG_B, "nightly") is True
    assert outside() == [(None,), (None,)] and events() == [] and f"Ereignisse der Sicherung von Switch {sid}" in caplog.text


async def test_the_list_of_backups_names_outside(api):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await backups(sid, ("backup", CFG_A, "nightly"), ("backup", CFG_B, "nightly"))
    assert [r["outside"] for r in api.get(f"/api/switches/{sid}/backups").json()] == [1, None]


# ── The list ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def event(sid, kind, ts="2026-11-07 10:00:00", port="", text="x", detail="{}") -> int:
    return dbfix.query("INSERT INTO events(ts, switch_id, kind, port, text, detail) VALUES (?,?,?,?,?,?) RETURNING id",
                       (ts, sid, kind, port, text, detail))[0][0]


async def test_events_list_newest_first_by_switch_and_kind_with_a_cursor(api):
    a, b = dbfix.insert_switch(name="A", host="10.0.0.1"), dbfix.insert_switch(name="B", host="10.0.0.2")
    ids = [event(a, "drift_port", port="1"), event(b, "drift_port"), event(a, "switch_down"), event(a, "drift_config"),
           event(a, "lldp_new"), event(a, "drift_port", port="2", detail='{"changes": {"pvid": ["1", "2"]}}')]
    page = api.get("/api/events", params={"switch_id": a, "kind": "drift", "limit": 2}).json()
    assert [r["id"] for r in page["rows"]] == [ids[5], ids[3]] and page["next"] == ids[3]
    assert page["rows"][0] == {"id": ids[5], "ts": "2026-11-07 10:00:00", "switch_id": a, "switch": "A", "kind": "drift_port",
                               "label": "Port außerhalb von SwitchView geändert", "port": "2", "text": "x",
                               "detail": {"changes": {"pvid": ["1", "2"]}}}
    page = api.get("/api/events", params={"switch_id": a, "kind": "drift", "limit": 2, "cursor": page["next"]}).json()
    assert [r["id"] for r in page["rows"]] == [ids[0]] and page["next"] is None
    assert [r["id"] for r in api.get("/api/events", params={"kind": "drift_port"}).json()["rows"]] == [ids[5], ids[1], ids[0]]
    assert [r["id"] for r in api.get("/api/events").json()["rows"]] == ids[::-1]
    r = api.get("/api/events", params={"kind": "x"})
    assert r.status_code == 422 and r.json()["detail"] == "Unbekannte Art von Ereignis"


async def test_events_since_a_time_in_any_iso_spelling(api):
    sid = dbfix.insert_switch(name="A", host="10.0.0.1")
    old, new = event(sid, "switch_down", ts="2026-11-06 22:59:59"), event(sid, "switch_up", ts="2026-11-06 23:00:00")
    for since in ("2026-11-07T00:00:00+01:00", "2026-11-06T23:00:00.000Z", "2026-11-06 23:00:00"):
        assert [r["id"] for r in api.get("/api/events", params={"since": since}).json()["rows"]] == [new]
    assert [r["id"] for r in api.get("/api/events", params={"since": "2026-11-06"}).json()["rows"]] == [new, old]
    r = api.get("/api/events", params={"since": "gestern"})
    assert r.status_code == 422 and r.json()["detail"] == "Zeitpunkt ungültig"


@pytest.mark.parametrize("params", [{"kind": "k" * 21}, {"since": "2" * 41}, {"limit": 0}, {"limit": 201}, {"cursor": 0},
                                    {"cursor": 2 ** 63}, {"switch_id": 2 ** 63}])
async def test_the_events_list_refuses_what_is_out_of_bounds(api, params):
    assert api.get("/api/events", params=params).status_code == 422


async def test_a_deleted_switch_takes_its_events(api):
    sid = dbfix.insert_switch(name="A", host="10.0.0.1")
    event(sid, "switch_down")
    assert api.delete(f"/api/switches/{sid}").status_code == 200 and dbfix.query("SELECT count(*) FROM events") == [(0,)]


async def test_the_purge_deletes_old_events(database):
    sid = dbfix.insert_switch(name="A", host="10.0.0.1")
    event(sid, "switch_down", ts="2000-01-01 00:00:00")
    event(sid, "switch_up", ts="2999-01-01 00:00:00")
    assert await history.purge(180) == {"events": 1} and dbfix.query("SELECT kind FROM events") == [("switch_up",)]
