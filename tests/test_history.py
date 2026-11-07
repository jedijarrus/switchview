"""Phase 4b, Task 2: every poll records where each device was seen (app/history.py, table sightings). A place is (MAC, switch, port,
VLAN); a new row comes only when the place changes (or its IP does), otherwise the row's last_seen moves on. MACs on trunks and
confirmed uplinks are no place, a possible uplink is recorded and marked suspect, the base MACs of the switches never; only MAC rows
of the poll that read them count. The retention (HISTORY_DAYS) is purged nightly in batches.

The network of tests/netfix.py (fixture `net` from tests/conftest.py), polled by the real poller; the clock of poll_switch is
poller.utc_now. In W_SAMPLE bridge port 3 is the port "1", 2 the port "3", 1 the port "2", 7 the trunk Trk1.
"""
import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

import api_devices
import dbfix
import history
import main
import poller
import snmp
import topology
from netfix import add, fdb, lldp, merge
from switchfix import W_SAMPLE

OIDS = poller.O
MAC, MAC2, BASE_B = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "00:1a:2b:00:00:22"
PORT1, PORT2, PORT3, TRK = "3", "1", "2", "7"
T = [f"2026-11-07 {10 + m // 60:02}:{m % 60:02}:00" for m in range(0, 120, 15)]          # 10:00, 10:15, ... 11:45


def clock(monkeypatch, *times):
    it = iter(times)
    monkeypatch.setattr(poller, "utc_now", lambda: next(it))


def learn(net, host, *rows):
    got = merge(*rows) if rows else {}
    for key in ("fdb", "fid"):
        net.rec[host][OIDS[key]] = got.get(OIDS[key], [])


def rows():
    return dbfix.query("SELECT mac, switch_name, port, vlan, first_seen, last_seen FROM sightings ORDER BY id")


async def poll_and_record(sid):
    assert (await poller.poll_switch(sid, record=False))["ok"]
    return await history.record([sid])


async def test_a_poll_records_where_each_device_was_seen(net, monkeypatch):
    clock(monkeypatch, T[0])
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    assert rows() == [(MAC, "A", "1", "20", T[0], T[0])]


async def test_a_second_poll_at_the_same_place_only_updates_last_seen(net, monkeypatch):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    await poller.poll_switch(sid)
    assert rows() == [(MAC, "A", "1", "20", T[0], T[1])]


async def test_a_move_to_another_port_adds_a_row_and_tells_it(net, monkeypatch):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    learn(net, "10.0.0.1", fdb(PORT3, MAC, "20"))
    news = await poll_and_record(sid)
    assert rows() == [(MAC, "A", "1", "20", T[0], T[0]), (MAC, "A", "3", "20", T[1], T[1])]
    assert [(n["port"], n["first"], n["moved"], n["back"], n["baseline"]) for n in news] == [("3", False, True, False, False)]


async def test_the_first_recording_of_a_switch_is_its_baseline(net, monkeypatch):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"))
    assert [(n["first"], n["baseline"], n["known"]) for n in await poll_and_record(sid)] == [(True, True, False)]


async def test_a_device_seen_at_two_places_at_once_grows_nothing(net, monkeypatch):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"), fdb(PORT1, MAC, "30"))
    for _ in range(4):
        await poller.poll_switch(sid)
    assert [r[:4] for r in rows()] == [(MAC, "A", "1", "20"), (MAC, "A", "1", "30")]


def at(minute: int, second: int = 0) -> str:
    return (datetime(2026, 11, 7, 10) + timedelta(minutes=minute, seconds=second)).strftime(history.TIME)


async def rounds(*orders: list[int]) -> list[dict]:
    """One round per order, as poll_all runs it: the switches polled one after the other (each at its own time), then one record for
    all of them. Returns what the records returned."""
    news = []
    for order in orders:
        for sid in order:
            assert (await poller.poll_switch(sid, record=False))["ok"]
        news += await history.record(order)
    return news


async def behind_an_unconfirmed_uplink(net, monkeypatch, n: int, *more_at_a: dict) -> tuple[int, int]:
    """A one-sided LLDP link A:2 -> B:2 (B does not name A: unconfirmed) and MAC at B's access port 1, seen at A:2 as well (and the
    rows more_at_a at A). A is added (and polled) at 10:00:00, B at 10:00:30; the clock then gives each of n rounds its two polls at
    :00 and :30, 15 minutes on."""
    clock(monkeypatch, at(0), at(0, 30), *(at(15 * i, s) for i in range(1, n + 1) for s in (0, 30)))
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "B", "2", "2"), fdb(PORT2, MAC, "20"), *more_at_a)
    b = await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    return a, b


@pytest.mark.parametrize("steady", [0, 3])
async def test_a_device_behind_an_unconfirmed_uplink_grows_only_with_its_moves(net, monkeypatch, steady):    # Review Focus 2
    # The uplink switch A is polled first in each round, so the place at B begins after the last sighting at A: no move at A for that
    a, b = await behind_an_unconfirmed_uplink(net, monkeypatch, steady + 3)
    news = await rounds(*[[a, b]] * steady)
    learn(net, "10.0.0.2", fdb(PORT3, MAC, "20"))                       # MAC moves from B:1 to B:3, A:2 still sees it
    news += await rounds(*[[a, b]] * 3)
    assert [r[1:4] for r in rows()] == [("A", "2", "20"), ("B", "1", "20"), ("B", "3", "20")]
    assert [(n["switch"], n["port"], n["moved"]) for n in news] == [("B", "3", True)]


async def test_a_device_seen_at_two_switches_at_once_keeps_its_rows_whatever_the_order_of_the_polls(net, monkeypatch):
    a, b = await behind_an_unconfirmed_uplink(net, monkeypatch, 30)
    assert await rounds(*[[a, b], [b, a]] * 15) == []                   # the last round polls B first
    assert dbfix.query("SELECT switch_name, port, first_seen, last_seen FROM sightings ORDER BY id") == [
        ("A", "2", at(0), at(450, 30)), ("B", "1", at(0, 30), at(450))]


async def test_a_device_that_ages_out_at_the_uplink_while_it_moves_gets_no_new_row_there(net, monkeypatch):
    # MAC2 keeps A's poll without MAC on record: MAC was gone from A:2 for a round, and B:3 began meanwhile, but B:3 is seen now too
    a, b = await behind_an_unconfirmed_uplink(net, monkeypatch, 3, fdb(PORT1, MAC2, "20"))
    news = await rounds([a, b])
    learn(net, "10.0.0.1", fdb(PORT1, MAC2, "20"))                      # the uplink's entry of MAC ages out ...
    learn(net, "10.0.0.2", fdb(PORT3, MAC, "20"))                       # ... while MAC moves from B:1 to B:3
    news += await rounds([a, b])
    learn(net, "10.0.0.1", fdb(PORT2, MAC, "20"), fdb(PORT1, MAC2, "20"))    # and A:2 sees it again
    news += await rounds([a, b])
    assert [r[1:4] for r in rows() if r[0] == MAC] == [("A", "2", "20"), ("B", "1", "20"), ("B", "3", "20")]
    assert [(n["switch"], n["port"], n["moved"]) for n in news] == [("B", "3", True)]


@pytest.mark.parametrize("a_first", [True, False])
async def test_a_device_that_comes_back_from_another_switch_gets_a_new_row(net, monkeypatch, a_first):
    clock(monkeypatch, *(at(15 * i, s) for i in range(3) for s in (0, 30)))
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"), fdb(PORT3, MAC2, "20"))
    b = await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE)
    order = [a, b] if a_first else [b, a]
    learn(net, "10.0.0.1", fdb(PORT3, MAC2, "20"))
    learn(net, "10.0.0.2", fdb(PORT1, MAC, "20"))                       # MAC to B:1 for one round
    news = await rounds(order)
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"), fdb(PORT3, MAC2, "20"))
    learn(net, "10.0.0.2")                                              # and back to A:1
    news += await rounds(order)
    assert [r[1:4] for r in rows() if r[0] == MAC] == [("A", "1", "20"), ("B", "1", "20"), ("A", "1", "20")]
    assert [(n["switch"], n["port"], n["moved"]) for n in news] == [("B", "1", True), ("A", "1", True)]


async def test_a_device_that_comes_back_after_a_move_gets_a_new_row(net, monkeypatch):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    learn(net, "10.0.0.1", fdb(PORT3, MAC, "20"))
    await poller.poll_switch(sid)
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"))
    await poller.poll_switch(sid)
    assert [(r[2], r[4], r[5]) for r in rows()] == [("1", T[0], T[0]), ("3", T[1], T[1]), ("1", T[2], T[2])]


async def test_a_quiet_device_keeps_its_row(net, monkeypatch):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    learn(net, "10.0.0.1")
    await poller.poll_switch(sid)
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"))
    await poller.poll_switch(sid)
    assert rows() == [(MAC, "A", "1", "20", T[0], T[2])]


async def test_a_device_back_after_an_absence_is_told_as_back(net, monkeypatch):
    clock(monkeypatch, "2026-11-07 08:00:00", "2026-11-07 10:00:00")
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    assert [(n["first"], n["moved"], n["back"]) for n in await poll_and_record(sid)] == [(False, False, True)]     # 120 min > max(60, 2 × 15)


def test_back_after():
    assert [history.back_after(m) for m in (5, 15, 30, 120)] == [60, 60, 60, 240]


async def test_a_mac_on_a_trunk_is_no_location(net, monkeypatch):                     # the access-port rule of the unknown devices
    clock(monkeypatch, *T)
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(TRK, MAC), fdb(PORT1, MAC2, "20"))
    assert [r[0] for r in rows()] == [MAC2] and [u["mac"] for u in await api_devices.unknown_devices({})] == [MAC2]


async def test_a_confirmed_uplink_is_no_location_and_a_possible_one_is_marked(net, monkeypatch):
    clock(monkeypatch, *T)
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "B", "2", "2"), fdb(PORT2, MAC))      # A:2 → B:2, one-sided
    b = await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, fdb(PORT2, MAC2), base_mac=BASE_B)
    await poller.poll_all()                                                  # now both switches are known: the link A:2 - B:2 is unconfirmed
    assert dbfix.query("SELECT mac, port, suspect FROM sightings ORDER BY id") == [(MAC, "2", 1), (MAC2, "2", 1)]
    net.rec["10.0.0.2"] |= lldp("2", "A", "2", "2")
    await poller.poll_all()
    dbfix.query("DELETE FROM sightings")
    await history.record([a, b])
    assert dbfix.query("SELECT mac FROM sightings") == []                                                    # both sides confirm: no location


async def test_the_base_mac_of_a_managed_switch_is_no_device(net, monkeypatch):
    clock(monkeypatch, *T)
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, base_mac=BASE_B)
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, BASE_B, "20"), fdb(PORT1, MAC, "20"))
    assert [r[0] for r in rows()] == [MAC]


async def test_a_port_whose_lldp_neighbour_is_named_like_a_managed_switch_is_marked(net, monkeypatch):
    clock(monkeypatch, *T)
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE)
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "B", "99", "99"), fdb(PORT2, MAC, "20"))    # no port 99 at B: no link
    assert dbfix.query("SELECT mac, switch_name, port, suspect FROM sightings") == [(MAC, "A", "2", 1)]


async def test_a_port_that_learns_the_base_mac_of_a_managed_switch_is_marked(net, monkeypatch):
    clock(monkeypatch, *T)
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, base_mac=BASE_B)
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, BASE_B, "20"), fdb(PORT1, MAC, "20"))
    assert dbfix.query("SELECT mac, switch_name, port, suspect FROM sightings") == [(MAC, "A", "1", 1)]


@pytest.mark.parametrize("ifindex", [0, 999], ids=["first", "last"])
async def test_a_port_name_twice_on_a_switch_is_one_place_marked_if_either_is(net, monkeypatch, ifindex):
    clock(monkeypatch, *T)
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE)
    a = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    dbfix.query("DELETE FROM sightings")
    dbfix.query("INSERT INTO ports(switch_id, ifindex, name, alias, oper, admin, speed, pvid, untagged, tagged, trunk, members, lldp, "
                "mac_count) SELECT switch_id, ?, name, alias, oper, admin, speed, pvid, untagged, tagged, trunk, members, ?, mac_count "
                "FROM ports WHERE switch_id = ? AND name = '1'", (ifindex, '[["B", "99", "99"]]', a))      # the second one: an LLDP name
    await history.record([a])
    assert dbfix.query("SELECT mac, port, suspect FROM sightings") == [(MAC, "1", 1)]


async def test_an_ip_and_a_name_no_longer_known_are_kept(net, monkeypatch):
    clock(monkeypatch, *T)
    dbfix.query("INSERT INTO names(mac, ip, name) VALUES (?, '10.0.0.5', 'pc-5')", (MAC,))
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    dbfix.query("DELETE FROM names")
    await poller.poll_switch(sid)
    assert dbfix.query("SELECT ip, name, first_seen, last_seen FROM sightings") == [("10.0.0.5", "pc-5", T[0], T[1])]


async def test_a_device_of_the_device_database_is_known_by_its_name(net, monkeypatch):
    clock(monkeypatch, *T)
    dbfix.query("INSERT INTO names(mac, ip, name) VALUES (?, '10.0.0.5', 'pc-5')", (MAC,))
    dbfix.query("INSERT INTO devices(mac, name) VALUES (?, 'Drucker EK')", (MAC,))
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"), fdb(PORT3, MAC2, "20"))
    news = await poll_and_record(sid)
    assert [(n["mac"], n["ip"], n["name"], n["known"]) for n in news] == [(MAC, "10.0.0.5", "Drucker EK", True), (MAC2, "", "", False)]
    assert dbfix.query("SELECT mac, ip, name FROM sightings ORDER BY id") == [(MAC, "10.0.0.5", "Drucker EK"), (MAC2, "", "")]


async def test_a_renamed_switch_renames_its_rows(net, monkeypatch):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    dbfix.query("UPDATE switches SET name = 'Lager' WHERE id = ?", (sid,))
    await poller.poll_switch(sid)
    assert rows() == [(MAC, "Lager", "1", "20", T[0], T[1])]


async def test_rows_kept_from_a_failed_mac_walk_are_no_sighting(net, monkeypatch):    # Review Focus 1
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    walk = snmp.walk

    async def failing(host, cred, oid, **kw):
        if oid == OIDS["fdb"]:
            raise snmp.SnmpError("Timeout")
        return await walk(host, cred, oid, **kw)
    monkeypatch.setattr(snmp, "walk", failing)
    await poller.poll_switch(sid)
    assert rows() == [(MAC, "A", "1", "20", T[0], T[0])]


async def test_a_new_ip_at_the_same_place_adds_a_row_and_a_missing_one_fills_in(net, monkeypatch):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    dbfix.query("INSERT INTO names(mac, ip, name) VALUES (?, '10.0.0.5', 'pc-5')", (MAC,))
    await poller.poll_switch(sid)
    dbfix.query("UPDATE names SET ip = '10.0.0.6'")
    await poller.poll_switch(sid)
    assert dbfix.query("SELECT ip, name, first_seen, last_seen FROM sightings ORDER BY id") == [("10.0.0.5", "pc-5", T[0], T[1]),
                                                                                                ("10.0.0.6", "pc-5", T[2], T[2])]


async def test_poll_all_records_once_for_the_whole_cycle(net, monkeypatch):
    clock(monkeypatch, *T)
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, fdb(PORT1, MAC2, "20"))
    calls, real = [], topology.build_map

    async def counted():
        calls.append(1)
        return await real()
    monkeypatch.setattr(topology, "build_map", counted)
    await poller.poll_all()
    assert len(calls) == 1 and sorted(r[5] for r in rows()) == [T[2], T[3]]          # the two polls of the cycle run at once, in either order


async def test_a_failing_record_never_fails_the_poll(net, monkeypatch, caplog):
    clock(monkeypatch, *T)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    monkeypatch.setattr(history, "record", dbfix.raising_async_fn(RuntimeError("kaputt")))
    assert (await poller.poll_switch(sid))["ok"] is True and "Verlauf 10.0.0.1" in caplog.text


@pytest.mark.parametrize("n, text", [(1, "Verlauf der Abfragerunde (1 Switch)"), (2, "Verlauf der Abfragerunde (2 Switches)")],
                         ids=["one", "two"])
async def test_a_failing_record_never_fails_the_round(net, monkeypatch, caplog, n, text):
    clock(monkeypatch, *T)
    for i in range(n):
        await add(net, f"S{i}", f"10.0.0.{i + 1}", "procurve", W_SAMPLE)
    monkeypatch.setattr(history, "record", dbfix.raising_async_fn(RuntimeError("kaputt")))
    await poller.poll_all()
    assert text in caplog.text and dbfix.query("SELECT count(*) FROM switches WHERE last_poll_ok = 1") == [(n,)]


@pytest.mark.parametrize("days, text", [(1, "Verlauf älter als 1 Tag gelöscht"), (2, "Verlauf älter als 2 Tage gelöscht")],
                         ids=["one", "two"])
async def test_the_purge_logs_what_it_deleted(net, caplog, days, text):
    dbfix.query("INSERT INTO sightings(mac, port, vlan, first_seen, last_seen) VALUES (?, '1', '1', '2000-01-01 00:00:00', "
                "'2000-01-01 00:00:00')", (MAC,))
    caplog.set_level("INFO", logger="switchview.history")
    assert await history.purge(days) == {"sightings": 1} and f"{text}: sightings 1" in caplog.text


async def test_purge_deletes_what_is_older_than_the_retention_in_batches(net, monkeypatch):
    for seen in ("2000-01-01 00:00:00",) * 5 + ("2999-01-01 00:00:00",):
        dbfix.query("INSERT INTO sightings(mac, port, vlan, first_seen, last_seen) VALUES (?, '1', '1', ?, ?)", (MAC, seen, seen))
    monkeypatch.setattr(history, "PURGE_BATCH", 2)
    assert await history.purge(0) == {} and len(rows()) == 6
    assert await history.purge(180) == {"sightings": 5} and [r[5] for r in rows()] == ["2999-01-01 00:00:00"]


async def test_the_nightly_purge_keeps_history_days(net, monkeypatch):        # the job calls purge() without days
    for seen in ("2000-01-01 00:00:00", datetime.now(timezone.utc).strftime(history.TIME)):
        dbfix.query("INSERT INTO sightings(mac, port, vlan, first_seen, last_seen) VALUES (?, '1', '1', ?, ?)", (MAC, seen, seen))
    monkeypatch.setattr(history, "settings", dataclasses.replace(history.settings, history_days=0))
    assert await history.purge() == {} and len(rows()) == 2
    monkeypatch.setattr(history, "settings", dataclasses.replace(history.settings, history_days=180))
    assert await history.purge() == {"sightings": 1} and len(rows()) == 1


def test_the_start_refuses_a_negative_history_days():                                 # also a case of test_the_start_refuses (test_roles.py)
    with pytest.raises(RuntimeError, match="HISTORY_DAYS muss 0 oder größer sein"):
        main.check_startup_config(dataclasses.replace(main.settings, history_days=-1))
