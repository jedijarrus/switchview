"""Phase 4b, Task 7: what alerts tell (app/alerts.py announce_events, announce_sightings, announce_findings, change_ended, on_approval)
and the MAC watch list (app/history.py, table watch_macs, routes in app/api_history.py).

The sources, each hooked where its data comes from and each wrapped (an alert never changes a poll, a backup or a change): a switch
that stops answering (after three polls) and answers again, every change of it told (its key carries the event's id); a new unknown
device at an access port - the first sighting ever of a MAC not in the device database, not at a possible uplink, never in the
first recording of a switch; drift of both kinds; a new security finding after the baseline, from a backup and from a poll; a change
that failed, stayed unclear, aborted or took another one back, from run_change and from _close; an LLDP change at an uplink; every
step of a four-eyes request, linked to #approvals; a watched MAC that appears, moves or comes back. Everything else is told once per
subject within alerts.DEDUP_MINUTES.

The mail channel on with every event through the helper configure of tests/test_alerts.py; queued() reads what emit queued. The
network of tests/netfix.py (fixture `net`), the ProCurve over SSH of tests/sshfix.py (fixture `ssh_env`), otherwise a fresh database
per test (apifix.fresh_db). No network: a delivered mail goes to FakeSMTP.
"""
import json
import logging
from datetime import datetime, timedelta, timezone

import pytest
from conftest import SAMPLE_RUNNING_CONFIG as CFG

import alerts
import apifix
import approvals
import changes
import config
import crypto
import db
import dbfix
import history
import poller
import sshcli
import sshfix
from netfix import add, fdb, lldp, merge
from switchfix import W_SAMPLE
from test_alerts import configure, fake_smtp
from test_change_outcome import OFF, queued_change, run_ports, run_revert, switch_runs
from test_history import MAC, MAC2, PORT1, PORT2, PORT3, T, clock, learn
from test_monitor import CFG_A, CFG_B, refuse, revalue
from test_uplinks import CATALYST

MAC3 = "aa:bb:cc:00:00:03"
EVERY = list(alerts.EVENTS)


@pytest.fixture
def database(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)


@pytest.fixture
def api(tmp_path, monkeypatch):
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


def queued() -> list[tuple]:
    return dbfix.query("SELECT event, title FROM alert_outbox ORDER BY id")


def told() -> list[tuple]:
    """Every queued row with what it says: event, title, text, the dedup key, the switch and the facts."""
    return [(e, t, x, k, s, n, json.loads(f)) for e, t, x, k, s, n, f in dbfix.query(
        "SELECT event, title, text, dedup_key, switch_id, switch_name, facts FROM alert_outbox ORDER BY id")]


async def change_of(cid: int):
    """The changes row cid as run_change reads it (an aiosqlite Row)."""
    async with db.db() as conn:
        async with conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)) as cur:
            return await cur.fetchone()


def later(monkeypatch, hours: int) -> None:
    """The clock of alerts that many hours ahead: the dedup window of an earlier message has passed."""
    monkeypatch.setattr(alerts, "_now", lambda: datetime.now(timezone.utc) + timedelta(hours=hours))


# ── Reachability ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_switch_that_stops_answering_is_told_once_and_again_when_it_answers(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    await configure(mail=True, events=EVERY)
    gate = refuse(monkeypatch, "10.0.0.1")
    for _ in range(4):
        await poller.poll_switch(sid)
    gate["on"] = False
    await poller.poll_switch(sid)
    assert queued() == [("reachability", "Switch A antwortet nicht"), ("reachability", "Switch A antwortet wieder")]
    down, up = dbfix.query("SELECT id FROM events ORDER BY id")
    facts = {"Switch": "A", "Adresse": "10.0.0.1"}
    assert [r[2:] for r in told()] == [("A antwortet seit 3 Abfragen nicht: Timeout", f"reachability:{sid}:{down[0]}", sid, "A", facts),
                                       (dbfix.query("SELECT text FROM events WHERE kind = 'switch_up'")[0][0], f"reachability:{sid}:{up[0]}",
                                        sid, "A", facts)]


async def test_each_change_of_reachability_is_told_within_the_hour(net, monkeypatch):           # T7-d: never folded together
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    await configure(mail=True, events=EVERY)
    gate = refuse(monkeypatch, "10.0.0.1")
    for on in (True, True, True, False, True, True, True):
        gate["on"] = on
        await poller.poll_switch(sid)
    assert [t for _, t in queued()] == ["Switch A antwortet nicht", "Switch A antwortet wieder", "Switch A antwortet nicht"]


async def test_a_failing_announcement_never_fails_the_poll(net, monkeypatch, caplog):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    for name in ("announce_events", "announce_findings", "announce_sightings"):
        monkeypatch.setattr(alerts, name, dbfix.raising_async_fn(RuntimeError("kaputt")))
    dbfix.query("UPDATE switches SET snmp_community = ? WHERE id = ?", (crypto.encrypt("public"), sid))    # a new finding
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"))                                                         # a new device
    net.rec["10.0.0.1"] |= lldp("2", "A", "2", "2")                                                       # an LLDP event
    assert (await poller.poll_switch(sid))["ok"] is True
    assert dbfix.query("SELECT count(*) FROM sightings") == [(1,)] and dbfix.query("SELECT kind FROM events") == [("lldp_new",)]
    assert "Meldungen 10.0.0.1" in caplog.text and "Meldungen des Verlaufs" in caplog.text
    gate = refuse(monkeypatch, "10.0.0.1")
    for _ in range(3):
        assert (await poller.poll_switch(sid))["ok"] is False
    gate["on"] = False
    assert (await poller.poll_switch(sid))["ok"] is True
    assert dbfix.query("SELECT kind FROM events ORDER BY id") == [("lldp_new",), ("switch_down",), ("switch_up",)]


# ── New devices and the watch list ────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_new_unknown_device_is_told_but_not_in_the_baseline_nor_a_known_one(net, monkeypatch):
    await configure(mail=True, events=EVERY)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))     # the switch's first recording: its stock
    assert queued() == []
    dbfix.query("INSERT INTO devices(mac, name) VALUES (?, 'Drucker')", (MAC3,))
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"), fdb(PORT1, MAC2, "20"), fdb(PORT1, MAC3, "20"))
    await poller.poll_switch(sid)
    assert queued() == [("unknown_device", "Neues unbekanntes Gerät an A Port 1")]
    assert told()[0][2:] == ("MAC aa:bb:cc:00:00:02 im VLAN 20, zum ersten Mal gesehen.", f"unknown_device:unknown:{MAC2}", sid, "A",
                             {"Switch": "A", "Port": "1"})


async def test_a_new_device_names_its_ip_and_name_and_is_told_once(net, monkeypatch):
    await configure(mail=True, events=EVERY)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))
    dbfix.query("INSERT INTO names(mac, ip, name) VALUES (?, '10.0.20.7', 'pc-7')", (MAC2,))
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"), fdb(PORT1, MAC2, "20"), fdb(PORT1, MAC2, "30"))    # first seen in two VLANs at once
    await poller.poll_switch(sid)
    assert [r[2] for r in told()] == ["MAC aa:bb:cc:00:00:02, IP 10.0.20.7, Name pc-7 im VLAN 20, zum ersten Mal gesehen."]
    assert dbfix.query("SELECT repeats FROM alert_outbox") == [(0,)]


async def test_a_new_device_behind_a_possible_uplink_is_not_told(net, monkeypatch):            # T7-a
    await configure(mail=True, events=EVERY)
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE, fdb(PORT1, MAC3, "20"))
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, lldp("2", "B", "2", "2"), fdb(PORT1, MAC, "20"))
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"), fdb(PORT2, MAC2, "20"))                # MAC2 at A:2, whose neighbour is B
    await poller.poll_switch(sid)
    assert dbfix.query("SELECT port, suspect FROM sightings WHERE mac = ?", (MAC2,)) == [("2", 1)] and queued() == []


async def test_a_watched_mac_is_told_when_it_appears_moves_or_comes_back(net, monkeypatch):
    clock(monkeypatch, T[0], T[1], T[2], T[7])
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    await configure(mail=True, events=["watch"])
    await history.watch_add(MAC, "Laptop Büro", apifix.user("aendern"))
    learn(net, "10.0.0.1", fdb(PORT1, MAC, "20"))
    await poller.poll_switch(sid)                                                  # 10:15 first seen at port 1
    learn(net, "10.0.0.1", fdb(PORT3, MAC, "20"))
    await poller.poll_switch(sid)                                                  # 10:30 at port 3
    later(monkeypatch, 2)                                                          # the hour of that message has passed
    await poller.poll_switch(sid)                                                  # 11:45 at port 3 again, after 75 minutes away
    assert queued() == [("watch", "Beobachtete MAC aa:bb:cc:00:00:01 gesehen: A Port 1"),
                        ("watch", "Beobachtete MAC aa:bb:cc:00:00:01 gesehen: A Port 3"),
                        ("watch", "Beobachtete MAC aa:bb:cc:00:00:01 gesehen: A Port 3")]
    assert [r[2:4] for r in told()] == [("Laptop Büro: zum ersten Mal gesehen (VLAN 20).", f"watch:watch:{MAC}:{sid}:1"),
                                        ("Laptop Büro: an einem anderen Port (VLAN 20).", f"watch:watch:{MAC}:{sid}:3"),
                                        ("Laptop Büro: wieder da (VLAN 20).", f"watch:watch:{MAC}:{sid}:3")]


async def test_a_watched_mac_without_a_note_names_its_ip_and_is_told_in_the_baseline_too(net, monkeypatch):
    await configure(mail=True, events=["watch", "unknown_device"])
    await history.watch_add(MAC, "", apifix.user("aendern"))
    dbfix.query("INSERT INTO names(mac, ip, name) VALUES (?, '10.0.20.9', '')", (MAC,))
    await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE, fdb(PORT1, MAC, "20"))     # the switch's first recording
    assert [r[:3] for r in told()] == [("watch", f"Beobachtete MAC {MAC} gesehen: A Port 1", "zum ersten Mal gesehen (VLAN 20, IP 10.0.20.9).")]


async def test_the_watch_list_answers_by_mac_with_the_last_sighting(database):
    anna = apifix.user("aendern", "anna")
    first = await history.watch_add(MAC2, "Kamera", anna)
    assert first == {"mac": MAC2, "note": "Kamera", "created_by": "anna", "created_at": first["created_at"], "last": None}
    await history.watch_add(MAC, "", anna)
    with pytest.raises(KeyError):
        await history.watch_add(MAC, "noch einmal", anna)
    sid = dbfix.insert_switch(name="A", host="10.0.0.1")
    for port, seen in (("1", "2026-11-07 10:00:00"), ("3", "2026-11-07 11:00:00")):
        dbfix.query("INSERT INTO sightings(mac, switch_id, switch_name, port, vlan, first_seen, last_seen) VALUES (?, ?, 'A', ?, '20', ?, ?)",
                    (MAC, sid, port, seen, seen))
    got = await history.watch_list()
    assert [(w["mac"], w["note"]) for w in got] == [(MAC, ""), (MAC2, "Kamera")] and got[1]["last"] is None
    assert got[0]["last"] == (await history.search(q=MAC, limit=1))["rows"][0] and got[0]["last"]["port"] == "3"
    assert await history.watched({MAC, MAC3}) == {MAC: ""} and await history.watched(set()) == {}
    assert await history.watch_remove(MAC) is True and await history.watch_remove(MAC) is False
    assert [w["mac"] for w in await history.watch_list()] == [MAC2]


def test_the_watch_list_takes_aendern_and_audits(api):
    apifix.become(apifix.user("aendern", "anna"))
    r = api.post("/api/watch", json={"mac": "AA-BB-CC-00-00-01", "note": " Laptop Büro "})
    assert r.status_code == 200 and r.json() == {"mac": MAC, "note": "Laptop Büro", "created_by": "anna",
                                                 "created_at": r.json()["created_at"], "last": None}
    r = api.post("/api/watch", json={"mac": "aabb.cc00.0001", "note": ""})
    assert r.status_code == 409 and r.json()["detail"] == "Diese MAC-Adresse wird schon beobachtet"
    r = api.post("/api/watch", json={"mac": "aa:bb:cc", "note": ""})
    assert r.status_code == 422 and r.json()["detail"] == "MAC-Adresse ungültig"
    sid = dbfix.insert_switch(name="A", host="10.0.0.1")
    dbfix.query("INSERT INTO sightings(mac, switch_id, switch_name, port, vlan, first_seen, last_seen) VALUES (?, ?, 'A', '1', '20', "
                "'2026-11-07 10:00:00', '2026-11-07 10:15:00')", (MAC, sid))
    apifix.become(apifix.user("lesen", "lea"))
    [entry] = api.get("/api/watch").json()
    assert (entry["mac"], entry["last"]["switch"], entry["last"]["port"], entry["last"]["last_seen"]) == (MAC, "A", "1", "2026-11-07 10:15:00")
    assert api.delete(f"/api/watch/{MAC}").status_code == 403
    apifix.become(apifix.user("aendern", "anna"))
    assert api.delete("/api/watch/AA:BB:CC:00:00:01").json() == {"ok": True}
    r = api.delete(f"/api/watch/{MAC}")
    assert r.status_code == 404 and r.json()["detail"] == "Nicht in der Beobachtungsliste"
    assert api.delete("/api/watch/kein-mac").status_code == 422
    assert dbfix.query("SELECT username, action, target, detail, role FROM audit WHERE action LIKE 'watch%' ORDER BY id") == [
        ("anna", "watch_add", MAC, "Laptop Büro", "aendern"), ("anna", "watch_remove", MAC, "", "aendern")]


@pytest.mark.parametrize("body", [{"mac": "a" * 21, "note": ""}, {"mac": MAC, "note": "n" * 201}, {"note": "x"}])
def test_the_watch_list_refuses_what_is_out_of_bounds(api, body):
    assert api.post("/api/watch", json=body).status_code == 422 and dbfix.query("SELECT count(*) FROM watch_macs") == [(0,)]


# ── Drift and LLDP ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_drift_of_both_kinds_is_told(net, database, monkeypatch):
    sid = await add(net, "C", "10.0.0.3", "cisco", CATALYST)
    await configure(mail=True, events=EVERY)
    revalue(net, "10.0.0.3", CATALYST, pvid={"1": "20"})
    await poller.poll_switch(sid)
    sw = dbfix.insert_switch(name="SW", host="10.0.0.9")
    await sshcli.store_backup(sw, CFG_A, "nightly")
    await sshcli.store_backup(sw, CFG_B, "nightly")
    assert queued() == [("drift", "Änderung außerhalb von SwitchView: C Port Gi1/0/1"), ("drift", "Konfiguration außerhalb von SwitchView geändert: SW")]
    (taken_at, backup), = dbfix.query("SELECT taken_at, id FROM config_backups WHERE switch_id = ? AND outside = 1", (sw,))
    assert [r[2:] for r in told()] == [
        ("Port Gi1/0/1 außerhalb von SwitchView geändert: PVID 10 → 20", f"drift:drift_port:{sid}:Gi1/0/1", sid, "C",
         {"Switch": "C", "Adresse": "10.0.0.3"}),
        (f"Konfiguration außerhalb von SwitchView geändert (Sicherung vom {taken_at} UTC). Den Vergleich zeigt SwitchView unter Sicherungen.",
         f"drift:drift_config:{sw}:{backup}", sw, "SW", {"Switch": "SW", "Adresse": "10.0.0.9"})]


async def test_a_failing_announcement_never_fails_the_backup(database, monkeypatch, caplog):
    sw = dbfix.insert_switch(name="SW", host="10.0.0.9")
    await sshcli.store_backup(sw, CFG_A, "nightly")
    for name in ("announce_events", "announce_findings"):
        monkeypatch.setattr(alerts, name, dbfix.raising_async_fn(RuntimeError("kaputt")))
    assert await sshcli.store_backup(sw, CFG_B + "include-credentials\n", "nightly") is True
    assert dbfix.query("SELECT outside FROM config_backups ORDER BY id") == [(None,), (1,)]
    assert "manager_password" in [r for (r,) in dbfix.query("SELECT rule FROM findings WHERE resolved_at IS NULL")]
    assert f"Meldungen der Sicherung von Switch {sw}" in caplog.text


async def test_an_lldp_change_is_told_only_on_an_uplink(net, monkeypatch):
    await add(net, "B", "10.0.0.2", "procurve", W_SAMPLE)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    await configure(mail=True, events=EVERY)
    net.rec["10.0.0.1"] |= merge(lldp("2", "B", "2", "2"), lldp("3", "Telefon", "1", "LAN"))
    await poller.poll_switch(sid)
    assert queued() == [("lldp_uplink", "LLDP-Nachbar an Uplink geändert: A Port 2")]
    assert told()[0][2:4] == ("Port 2: neuer LLDP-Nachbar B (Port 2)", f"lldp_uplink:lldp:{sid}:2")
    assert dbfix.query("SELECT kind, port FROM events ORDER BY id") == [("lldp_new", "2"), ("lldp_new", "3")]


# ── Security findings ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_new_finding_is_told_after_the_baseline(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await configure(mail=True, events=["compliance"])
    await sshcli.store_backup(sid, CFG, "nightly")
    assert queued() == []
    await sshcli.store_backup(sid, CFG + "include-credentials\n", "nightly")
    assert queued() == [("compliance", "Neuer Sicherheitsbefund an SW: Manager ohne Kennwort")]
    (fid,), = dbfix.query("SELECT id FROM findings WHERE rule = 'manager_password'")
    assert told()[0][2:] == ("Die Konfiguration zeigt Kennwörter (include-credentials), aber keins für manager.",    # no detail, no line: the hint
                             f"compliance:compliance:{sid}:{fid}", sid, "SW", {"Switch": "SW", "Adresse": "10.0.0.1"})


async def test_a_finding_with_a_line_names_it_masked(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await configure(mail=True, events=["compliance"])
    await sshcli.store_backup(sid, CFG, "nightly")
    await sshcli.store_backup(sid, CFG + 'snmp-server community "private" unrestricted\n', "nightly")
    n = len(CFG.splitlines()) + 1
    assert [r[1:3] for r in told()] == [
        ("Neuer Sicherheitsbefund an SW: SNMP-Community „public“ oder „private“",
         f'Community „private“ Zeile {n}: snmp-server community "***" unrestricted'),
        ("Neuer Sicherheitsbefund an SW: SNMPv2c-Community mit Schreibrecht", f'Zeile {n}: snmp-server community "***" unrestricted')]


async def test_a_new_snmp_finding_is_told_after_the_baseline(net, monkeypatch):
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)      # community "read-s3cret": the baseline, nothing told
    await configure(mail=True, events=["compliance"])
    dbfix.query("UPDATE switches SET snmp_community = ? WHERE id = ?", (crypto.encrypt("public"), sid))
    await poller.poll_switch(sid)
    assert queued() == [("compliance", "Neuer Sicherheitsbefund an A: SwitchView liest mit „public“ oder „private“")]
    assert told()[0][2] == "SwitchView liest per SNMPv2c mit der Community „public“"


# ── The end of a change ───────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("status, revert_of, title", [("failed", None, "Änderung #7 an SW fehlgeschlagen"), ("unclear", None, "Änderung #7 an SW unklar"),
                                                     ("aborted", None, "Änderung #7 an SW abgebrochen"), ("ok", 3, "Änderung #3 an SW zurückgenommen"),
                                                     ("ok", None, None)])
async def test_the_end_of_a_change_is_told_when_it_went_wrong_or_took_one_back(database, status, revert_of, title):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await configure(mail=True, events=["change_problem"])
    await alerts.change_ended({"switch_id": sid, "summary": "Port 2: VLAN 20", "username": "anna", "revert_of": revert_of}, 7, status, "kaputt")
    assert [t for _, t in queued()] == ([title] if title else [])


async def test_the_texts_of_a_change_that_went_wrong_and_of_a_revert(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await configure(mail=True, events=["change_problem"])
    ch = {"switch_id": sid, "summary": "Port 2: VLAN 20", "username": "anna", "revert_of": None}
    await alerts.change_ended(ch, 7, "failed", "kaputt")
    await alerts.change_ended(ch, 8, "unclear", None)
    await alerts.change_ended({**ch, "revert_of": 7}, 9, "ok", None)
    await alerts.change_ended({**ch, "switch_id": sid + 1}, 10, "aborted", "weg")         # a switch gone meanwhile
    assert [r[2:] for r in told()] == [("Port 2: VLAN 20 (von anna): kaputt", "change_problem:change:7", sid, "SW", {"Switch": "SW"}),
                                       ("Port 2: VLAN 20 (von anna)", "change_problem:change:8", sid, "SW", {"Switch": "SW"}),
                                       ("Zurückgenommen mit #9 von anna.", "change_problem:change:9", sid, "SW", {"Switch": "SW"}),
                                       ("Port 2: VLAN 20 (von anna): weg", "change_problem:change:10", sid + 1, f"Switch {sid + 1}",
                                        {"Switch": f"Switch {sid + 1}"})]
    assert queued()[3][1] == f"Änderung #10 an Switch {sid + 1} abgebrochen"


@pytest.mark.parametrize("way", ["run_change", "close"])
@pytest.mark.parametrize("broken", ["emit", "change_ended"])
async def test_a_failing_alert_never_changes_the_end_of_a_change(ssh_env, monkeypatch, caplog, way, broken):
    await configure(mail=True, events=["change_problem"])
    monkeypatch.setattr(alerts, broken, dbfix.raising_async_fn(RuntimeError("kaputt")))
    if way == "run_change":
        ssh_env.on_connect = RuntimeError("down")
        cid, status = await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}}), "failed"
    else:
        cid, status = queued_change(ssh_env, 0), "aborted"
        await changes._refuse(cid, await change_of(cid), "x")
    assert ssh_env.change(cid)["status"] == status
    assert dbfix.query("SELECT action, target FROM audit WHERE action LIKE 'change_%'") == [(f"change_{status}", str(ssh_env.sid))]
    assert "Benachrichtigung" in caplog.text and queued() == []


async def test_a_change_that_ends_through_close_is_told(database):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await configure(mail=True, events=["change_problem"])
    cid = dbfix.query("INSERT INTO changes(switch_id, username, kind, summary, commands, status, steps, sent, mechanism) "
                      "VALUES (?, 'anna', 'ports', 'Port 2: Aus', '[]', 'queued', '[]', 0, 'snmp') RETURNING id", (sid,))[0][0]
    await changes._refuse(cid, await change_of(cid), "x")
    assert queued() == [("change_problem", f"Änderung #{cid} an SW abgebrochen")] and told()[0][2] == "Port 2: Aus (von anna): x"


async def test_a_change_run_over_ssh_is_told_masked(ssh_env, monkeypatch):
    # run_change's error is unmasked until its end (_upd masks it): with an error text that keeps the secret, the alert masks it too
    monkeypatch.setattr(changes, "_error_text", lambda e, mask: f"{type(e).__name__}: {e}")
    await configure(mail=True, events=["change_problem"])
    ssh_env.on_connect = RuntimeError("Anmeldung mit ssh-s3cret abgelehnt")
    cid = await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}})
    assert queued() == [("change_problem", f"Änderung #{cid} an SW-EK-01 fehlgeschlagen")]
    assert told()[0][2] == "Port-Änderung (von tester): RuntimeError: Anmeldung mit *** abgelehnt"
    assert ssh_env.change(cid)["error"] == "RuntimeError: Anmeldung mit *** abgelehnt"


async def test_a_revert_that_ends_ok_is_told_as_taken_back(ssh_env, monkeypatch):
    switch_runs(monkeypatch, OFF, sshfix.RUNNING)
    first = await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}})
    await configure(mail=True, events=["change_problem"])
    second = await run_revert(ssh_env, first)
    assert ssh_env.change(second)["status"] == "ok"
    assert told()[0][1:3] == (f"Änderung #{first} an SW-EK-01 zurückgenommen", f"Zurückgenommen mit #{second} von tester.")


# ── Four-eyes requests ────────────────────────────────────────────────────────────────────────────────────────────────────────────
REQUEST = {"id": 4, "kind": "port_change", "summary": "Port 2: VLAN 20", "status": "open", "requested_by": "anna", "requester_name": "Anna",
           "decided_by": None, "comment": None, "reason": None, "switch_name": "SW"}


async def test_every_step_of_a_request_is_told(database, monkeypatch):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await configure(mail=True, events=["approval"])
    monkeypatch.setattr(alerts, "settings", config.Settings(public_url="https://sv.example.org"))
    smtp = fake_smtp(monkeypatch)
    a = {**REQUEST, "switch_id": sid}
    await approvals.emit("requested", a)
    await approvals.emit("rejected", {**a, "status": "rejected", "decided_by": "bert", "comment": "Nicht heute"})
    assert queued() == [("approval", "Freigabe #4 angefordert"), ("approval", "Freigabe #4 abgelehnt")]
    assert [r[2:] for r in told()] == [
        ("Port 2: VLAN 20 an SW, angefordert von Anna", "approval:approval:4:requested", sid, "SW", {"Switch": "SW", "_view": "approvals"}),
        ("Port 2: VLAN 20 an SW, angefordert von Anna, entschieden von bert: Nicht heute", "approval:approval:4:rejected", sid, "SW",
         {"Switch": "SW", "_view": "approvals"})]
    assert await alerts.deliver_due() == 2
    bodies = [m.get_content() for m in smtp.sent]
    assert all("In SwitchView öffnen: https://sv.example.org/#approvals" in b and "_view" not in b and "Switch: SW" in b for b in bodies)


@pytest.mark.parametrize("event, extra, title, text", [
    ("approved", {"decided_by": "bert", "comment": "passt"}, "Freigabe #4 freigegeben", ", entschieden von bert: passt"),
    ("withdrawn", {"decided_by": "anna"}, "Freigabe #4 zurückgezogen", ", entschieden von anna"),
    ("expired", {}, "Freigabe #4 abgelaufen", ""),
    ("stale", {"decided_by": "bert", "reason": "Die Befehle von jetzt sind andere als die der Vorschau der Anfrage"}, "Freigabe #4 veraltet",
     ", entschieden von bert – Die Befehle von jetzt sind andere als die der Vorschau der Anfrage")])
async def test_each_decision_of_a_request_has_its_title_and_text(database, event, extra, title, text):
    sid = dbfix.insert_switch(name="SW", host="10.0.0.1")
    await configure(mail=True, events=["approval"])
    await alerts.on_approval(event, {**REQUEST, "switch_id": sid, **extra})
    assert [r[1:3] for r in told()] == [(title, "Port 2: VLAN 20 an SW, angefordert von Anna" + text)]


async def test_a_step_no_one_knows_is_not_told_and_a_broken_request_never_raises(database, caplog):
    await configure(mail=True, events=["approval"])
    await alerts.on_approval("reopened", {**REQUEST, "switch_id": None})
    await alerts.on_approval("requested", {"id": 5})
    assert queued() == [] and "Benachrichtigung" in caplog.text


def test_the_listener_is_subscribed_at_import():
    assert alerts.on_approval in approvals._listeners


async def test_no_source_queues_anything_while_no_channel_is_on(net, monkeypatch, caplog):     # emit decides, the sources only ask
    caplog.set_level(logging.ERROR)
    sid = await add(net, "A", "10.0.0.1", "procurve", W_SAMPLE)
    gate = refuse(monkeypatch, "10.0.0.1")
    for _ in range(3):
        await poller.poll_switch(sid)
    gate["on"] = False
    await poller.poll_switch(sid)
    await alerts.change_ended({"switch_id": sid, "summary": "x", "username": "anna", "revert_of": None}, 1, "failed", "kaputt")
    assert queued() == [] and caplog.text == ""
