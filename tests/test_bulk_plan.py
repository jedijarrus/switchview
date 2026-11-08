"""Phase 4c, Task 6: the preview of a bulk change (POST /api/bulk/plan, app/bulk.py, app/api_bulk.py).

A request names the change once (the fields of api_changes.PortChange, plus expert) and per switch its ports: a list, or the filter
"every access port untagged in VLAN N by the last poll" (untagged_in). The preview has a section per switch in the order of the
request, each planned by the per-switch planner (api_changes._make_plan) with its own preview token, at most five switches at once;
a switch outside the user's zones, with a blocked port, with nothing to do or that cannot be planned is skipped with its reason, and
a port the filter took from the poll that the fresh read finds in another VLAN blocks its switch. The answer adds the combined
token, whether the bulk needs an approval and whether it can run with confirmation. Nothing starts.

The app runs in-process through FastAPI's TestClient, signed in per request as the user its X-Test-User header names
(apifix.by_header). The world (tests/bulkfix.py) has switches A and B in zone EK and C in VK, a fake planner and a fake poll
inventory; the last test plans with the real planner against the fake ProCurve running-config of tests/sshfix.py. No switch, no
network.
"""
import asyncio

import pytest
from bulkfix import fake_plan, make_world
from fastapi import HTTPException
from test_approvals import H

import api_changes
import apifix
import bulk
import changes
import db
import dbfix
import roles
import sshfix
from cfgparse import parse_config

USERS = {"anna": apifix.user("aendern", "anna"), "ek": apifix.user("aendern", "ek", zones=["EK"]), "ben": apifix.user("freigeben", "ben")}


@pytest.fixture
def world(tmp_path, monkeypatch):
    return make_world(tmp_path, monkeypatch)


@pytest.fixture
def client(world, monkeypatch):
    """A TestClient signed in per request as USERS[<X-Test-User>]."""
    with apifix.signed_in(monkeypatch) as c:
        apifix.by_header(USERS)
        yield c


def plan(client, who="anna", **body):
    return client.post("/api/bulk/plan", json={"change": {"untagged": "30"}, **body}, headers=H(who))


def test_the_preview_has_a_section_per_switch_each_with_its_own_preview_token(world, client):
    r = plan(client, targets=[{"switch_id": world.a, "ports": ["2", "1"]}, {"switch_id": world.b, "ports": ["5"]}]).json()
    assert [(s["switch"], s["status"], s["ports"], s["reason"]) for s in r["sections"]] == [("A", "ready", ["2", "1"], ""),
                                                                                         ("B", "ready", ["5"], "")]
    tokens = [changes.cmd_token(["vlan 30 untagged 2,1"]), changes.cmd_token(["vlan 30 untagged 5"])]
    assert [s["preview"]["token"] for s in r["sections"]] == tokens and r["token"] == bulk.token_of([(world.a, tokens[0]), (world.b, tokens[1])])
    assert (r["ready"], r["skipped"], r["ports"], r["approval"], r["summary"]) == (2, 0, 3, False, "VLAN 30 · 3 Ports an 2 Switches")
    assert dbfix.query("SELECT count(*) FROM changes") == [(0,)]


def test_a_blocked_or_empty_switch_is_skipped_with_its_reason(world, client):
    world.plans |= {"B": {"blocked": [{"port": "5", "reason": "Uplink/Trunk: nur im Expertenmodus"}]}, "C": {"shown": []}}
    r = plan(client, "ben", targets=[{"switch_id": s, "ports": ["5"]} for s in (world.a, world.b, world.c)]).json()
    assert [(s["status"], s["reason"]) for s in r["sections"]] == [("ready", ""), ("blocked", "Port 5: Uplink/Trunk: nur im Expertenmodus"),
                                                                  ("nothing", bulk.NOTHING)]
    assert (r["ready"], r["skipped"]) == (1, 2) and r["token"] == bulk.token_of([(world.a, r["sections"][0]["preview"]["token"])])


def test_a_switch_outside_the_zones_is_denied_in_its_section(world, client):
    r = plan(client, "ek", targets=[{"switch_id": world.a, "ports": ["1"]}, {"switch_id": world.c, "ports": ["1"]}]).json()
    assert [(s["status"], s["reason"]) for s in r["sections"]] == [("ready", ""), ("denied", roles.zone_denial("VK", ["EK"]))]


def test_a_planning_error_stays_in_its_section(world, client):
    world.plans["B"] = HTTPException(502, "Konfiguration des Switches per SNMP nicht lesbar: Timeout")
    dbfix.query("UPDATE switches SET enabled = 0 WHERE id = ?", (world.c,))
    r = plan(client, "ben", targets=[{"switch_id": s, "ports": ["1"]} for s in (world.a, world.b, world.c, 999)]).json()
    assert [(s["status"], s["reason"]) for s in r["sections"]] == [
        ("ready", ""), ("error", "Konfiguration des Switches per SNMP nicht lesbar: Timeout"), ("error", api_changes.DISABLED),
        ("error", "Switch nicht gefunden")]


def test_the_vlan_filter_takes_the_access_ports_untagged_in_that_vlan(world, client):
    world.inv[world.a] = {"ports": {"1": {"n": "1", "u": ["20"], "tr": ""}, "2": {"n": "2", "u": ["20"], "tr": "Trk1"},
                                    "3": {"n": "3", "u": ["20"], "tr": ""}, "4": {"n": "4", "u": ["30"], "tr": ""},
                                    "10": {"n": "10", "u": ["20"], "tr": ""}, "Trk1": {"n": "Trk1", "u": ["20"], "tr": ""}}, "uplinks": {"3"}}
    [s] = plan(client, targets=[{"switch_id": world.a, "untagged_in": "20"}]).json()["sections"]
    assert (s["ports"], s["status"]) == (["1", "10"], "ready") and s["selection"].startswith("Zugangsports ungetaggt in VLAN 20 laut Poll vom ")


def test_a_port_that_left_the_vlan_since_the_poll_blocks_its_switch(world, client):
    world.inv[world.a] = {"ports": {p: {"n": p, "u": ["20"], "tr": ""} for p in ("1", "5")}, "uplinks": set()}
    world.plans["A"] = {"before": {"1": {"u": "20"}, "5": {"u": "40"}}}
    [s] = plan(client, targets=[{"switch_id": world.a, "untagged_in": "20"}]).json()["sections"]
    assert (s["status"], s["reason"]) == ("blocked", bulk.MOVED.format(port="5", vlan="20", now="40"))


def test_no_access_port_in_the_vlan_is_nothing_to_do(world, client):
    world.inv[world.a] = {"ports": {"1": {"n": "1", "u": ["20"], "tr": ""}}, "uplinks": set()}
    [s] = plan(client, targets=[{"switch_id": world.a, "untagged_in": "99"}]).json()["sections"]
    assert (s["status"], s["reason"], s["preview"]) == ("nothing", bulk.NO_MATCH.format(vlan="99"), None)


@pytest.mark.parametrize("targets, detail", [
    (lambda w: [{"switch_id": i, "ports": ["1"]} for i in range(1, 22)], bulk.TOO_MANY_SWITCHES),
    (lambda w: [{"switch_id": w.a, "ports": ["1"]}, {"switch_id": w.a, "ports": ["2"]}], "Switch #{a} steht doppelt in der Sammeländerung"),
    (lambda w: [{"switch_id": w.a, "ports": ["1"], "untagged_in": "20"}], "Für Switch #{a} entweder Ports oder „ungetaggt in VLAN“ angeben, nicht beides"),
    (lambda w: [{"switch_id": w.a}], "Für Switch #{a} sind keine Ports gewählt")])
def test_the_limits_of_a_bulk(world, client, targets, detail):
    r = plan(client, "ben", targets=targets(world))
    assert (r.status_code, r.json()["detail"]) == (422, detail.format(a=world.a))


def test_more_than_1000_ports_are_refused(world, client):
    for i in range(6):
        world.extra(f"S{i}")                                                               # six more switches in zone EK
    r = plan(client, "ben", targets=[{"switch_id": s, "ports": [str(p) for p in range(1, 201)]} for s in world.extra_ids])
    assert (r.status_code, r.json()["detail"]) == (422, bulk.TOO_MANY_PORTS)


def test_more_than_1000_ports_through_the_vlan_filter_are_refused(world, client):       # the second check, over the resolved ports
    for i in range(6):
        world.extra(f"S{i}")
    for s in world.extra_ids:
        world.inv[s] = {"ports": {str(p): {"n": str(p), "u": ["20"], "tr": ""} for p in range(1, 201)}, "uplinks": set()}
    r = plan(client, "ben", targets=[{"switch_id": s, "untagged_in": "20"} for s in world.extra_ids])
    assert (r.status_code, r.json()["detail"]) == (422, bulk.TOO_MANY_PORTS)


def test_planning_runs_at_most_five_switches_at_once(world, client, monkeypatch):
    for i in range(12):
        world.extra(f"S{i}")
    busy, peak = [0], [0]

    async def slow(row, body):
        busy[0] += 1
        peak[0] = max(peak[0], busy[0])
        await asyncio.sleep(0.05)
        busy[0] -= 1
        return await fake_plan(row, body)

    monkeypatch.setattr(api_changes, "_make_plan", slow)
    assert plan(client, "ben", targets=[{"switch_id": s, "ports": ["1"]} for s in world.extra_ids]).status_code == 200 and peak[0] == bulk.PARALLEL


def test_the_preview_says_whether_an_approval_is_needed_and_whether_confirmation_can_go(world, client):
    asyncio.run(db.set_setting("four_eyes", "1"))
    world.plans["B"] = {"mechanism": "snmp"}                                              # B is a ProCurve: an SNMP SET saves by itself
    r = plan(client, targets=[{"switch_id": world.a, "ports": ["1"]}, {"switch_id": world.b, "ports": ["1"]}]).json()
    assert r["approval"] is True and r["confirm"] == {"possible": False, "why": api_changes.CONFIRM_AUTOSAVE, "default_minutes": 5, "max_minutes": 30}


def test_uplinks_stay_protected_per_switch_by_the_real_planner(tmp_path, monkeypatch):
    """No fake planner: a ProCurve with SSH access (sshfix.procurve), its running-config from changes.fresh_cfg (sshfix.RUNNING), port 24
    an uplink in the inventory. Without expert mode the section is blocked by plan_ports' own rule; with it (Freigeben) it is ready."""
    apifix.fresh_db(tmp_path, monkeypatch)
    sid = dbfix.insert_switch(**sshfix.procurve())

    async def fresh_cfg(sid, max_age_s=changes.CFG_MAX_AGE_S):
        return parse_config(sshfix.RUNNING)                 # the preview's read: the real one opens a netmiko session (sshcli._open)

    async def inventory(sid):
        return {"ports": {p: {"n": p, "tr": "", "l": [], "o": False} for p in ("1", "24")}, "uplinks": {"24"}}

    monkeypatch.setattr(changes, "fresh_cfg", fresh_cfg)
    monkeypatch.setattr(changes, "inventory", inventory)
    body = {"targets": [{"switch_id": sid, "ports": ["1", "24"]}], "change": {"status": "off"}}
    with apifix.signed_in(monkeypatch) as client:
        apifix.by_header(USERS)
        [s] = client.post("/api/bulk/plan", json=body, headers=H("anna")).json()["sections"]
        assert (s["status"], s["reason"]) == ("blocked", "Port 24: Uplink/Trunk: nur im Expertenmodus")
        [s] = client.post("/api/bulk/plan", json=body | {"expert": True}, headers=H("ben")).json()["sections"]
    assert (s["status"], s["reason"], s["preview"]["commands"], s["preview"]["mechanism"]) == ("ready", "", ["interface 1,24 disable"], "ssh")


# ── Beyond the plan's tests of Task 6: what the interface names and no test above holds ───────────────────────────────────────────
def test_the_selection_names_the_last_good_poll(world, client):
    """The filter's ports come from the last good poll (last_ok_at): a failed poll after it keeps those ports, so the selection still
    names the good one (R-32)."""
    world.inv[world.a] = {"ports": {"1": {"n": "1", "u": ["20"], "tr": ""}}, "uplinks": set()}
    selected = "Zugangsports ungetaggt in VLAN 20 laut Poll vom 2026-11-08 09:00:00 UTC"
    assert plan(client, targets=[{"switch_id": world.a, "untagged_in": "20"}]).json()["sections"][0]["selection"] == selected
    dbfix.query("UPDATE switches SET last_poll = '2026-11-08 09:05:00', last_poll_ok = 0 WHERE id = ?", (world.a,))
    assert plan(client, targets=[{"switch_id": world.a, "untagged_in": "20"}]).json()["sections"][0]["selection"] == selected


def test_the_filter_leaves_out_a_trunk_by_its_members_and_more_than_200_ports_are_an_error(world, client):
    """A LAG of another vendor (Po1, ae0) is no access port: one a member names as its trunk, and one with members of its own; nor
    is a ProCurve trunk without a member in the poll (Trk2)."""
    world.inv[world.a] = {"ports": {"1": {"n": "1", "u": ["20"], "tr": "Po1"}, "Po1": {"n": "Po1", "u": ["20"], "tr": ""},
                                    "ae0": {"n": "ae0", "u": ["20"], "tr": "", "mb": ["ge-0/0/1"]}, "2": {"n": "2", "u": ["20"], "tr": ""},
                                    "Trk2": {"n": "Trk2", "u": ["20"], "tr": ""}}, "uplinks": set()}
    world.inv[world.b] = {"ports": {str(p): {"n": str(p), "u": ["20"], "tr": ""} for p in range(1, 202)}, "uplinks": set()}
    a, b = plan(client, targets=[{"switch_id": s, "untagged_in": "20"} for s in (world.a, world.b)]).json()["sections"]
    assert (a["ports"], a["status"]) == (["2"], "ready") and (b["status"], b["reason"], b["preview"]) == ("error", bulk.OVER_200, None)


def test_a_block_of_the_whole_switch_is_named_without_a_port(world, client):
    world.plans["A"] = {"blocked": [{"port": "*", "reason": "Switch ist nicht für RADIUS vorbereitet: aaa"}, {"port": "1", "reason": "x"}]}
    [s] = plan(client, targets=[{"switch_id": world.a, "ports": ["1"]}]).json()["sections"]
    assert (s["status"], s["reason"]) == ("blocked", "Switch ist nicht für RADIUS vorbereitet: aaa; Port 1: x") and s["preview"]["blocked"]


def test_the_expert_mode_without_four_eyes_is_denied_below_freigeben(world, client):
    r = plan(client, targets=[{"switch_id": world.a, "ports": ["1"]}], expert=True).json()
    assert [(s["status"], s["reason"]) for s in r["sections"]] == [("denied", roles.denial(roles.FREIGEBEN, roles.AENDERN, "Der Expertenmodus"))]
    assert (r["ready"], r["skipped"], r["token"], r["confirm"]["possible"], r["confirm"]["why"]) == (0, 1, bulk.token_of([]), False, None)


def test_the_summary_counts_in_singular_and_plural():
    assert api_changes._change_parts(api_changes.PortChange(untagged="30", tagged_add=["40"], poe=False)) == ["VLAN 30", "getaggt +40", "PoE aus"]
    assert bulk.summary(api_changes.PortChange(untagged="30"), 1, 1) == "VLAN 30 · 1 Port an 1 Switch"
    assert bulk.summary(api_changes.PortChange(status="off", name=""), 2, 5) == "Aus, Name entfernt · 5 Ports an 2 Switches"
    assert bulk.summary(api_changes.PortChange(), 0, 0) == "– · 0 Ports an 0 Switches"


def test_a_switch_outside_the_zones_is_denied_before_its_ports_are_chosen(world, client):
    """The rights before resolve (pre-flight ruling): C has no port in the VLAN, yet ek hears the zone, not "nothing to do"."""
    [s] = plan(client, "ek", targets=[{"switch_id": world.c, "untagged_in": "20"}]).json()["sections"]
    assert (s["status"], s["reason"], s["selection"]) == ("denied", roles.zone_denial("VK", ["EK"]), "")
