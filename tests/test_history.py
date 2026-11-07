"""Phase 4b, Task 2: every poll records where each device was seen (app/history.py, table sightings). A place is (MAC, switch, port,
VLAN); a new row comes only when the place changes (or its IP does), otherwise the row's last_seen moves on. MACs on trunks and
confirmed uplinks are no place, a possible uplink is recorded and marked suspect, the base MACs of the switches never; only MAC rows
of the poll that read them count. The retention (HISTORY_DAYS) is purged nightly in batches.

The network of tests/netfix.py (fixture `net` from tests/conftest.py), polled by the real poller; the clock of poll_switch is
poller.utc_now. In W_SAMPLE bridge port 3 is the port "1", 2 the port "3", 1 the port "2", 7 the trunk Trk1.
"""
import dataclasses

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


async def test_purge_deletes_what_is_older_than_the_retention_in_batches(net, monkeypatch):
    for seen in ("2000-01-01 00:00:00",) * 5 + ("2999-01-01 00:00:00",):
        dbfix.query("INSERT INTO sightings(mac, port, vlan, first_seen, last_seen) VALUES (?, '1', '1', ?, ?)", (MAC, seen, seen))
    monkeypatch.setattr(history, "PURGE_BATCH", 2)
    assert await history.purge(0) == {} and len(rows()) == 6
    assert await history.purge(180) == {"sightings": 5} and [r[5] for r in rows()] == ["2999-01-01 00:00:00"]


def test_the_start_refuses_a_negative_history_days():                                 # also a case of test_the_start_refuses (test_roles.py)
    with pytest.raises(RuntimeError, match="HISTORY_DAYS muss 0 oder größer sein"):
        main.check_startup_config(dataclasses.replace(main.settings, history_days=-1))
