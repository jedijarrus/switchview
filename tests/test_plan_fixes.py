"""Phase 3 Task 4: planning fixes in changes.plan_ports and snmpwrite.snmp_block_reason.

  * An SSH revert to "no untagged VLAN" (u -> None) is sent as `no vlan <old> untagged <port>`, after every tagged line; before the fix
    it was the invalid `vlan None untagged <port>`. A VID that switches between untagged and tagged on one port takes only its
    positive line (review round 1).
  * A trunk member takes a name and on / off (changes.MEMBER_FIELDS) over SSH and SNMP, under the uplink / expert rule of every port
    (a member of an uplink trunk is an uplink, also when only the fresh read knows it as a member: review round 1); any other field
    (VLANs, NAC, PoE) is still refused with "gehört zu <trunk>, bitte <trunk> wählen".
  * The unauth VLAN of a port with 802.1X and MAC auth is taken off 802.1X only by a request that touches NAC (a NAC status, a limit,
    a guest VLAN); "on", a VLAN or a name change keep it.
  * With a RADIUS server in the settings (radius_server), a NAC change needs exactly that server on the switch; run_change re-plans with
    it (ssh_env of tests/conftest.py). The preview and revert routes are covered in tests/test_make_plan_routing.py, as is the 422 for
    one VLAN in tagged_add and tagged_remove.

The SSH switch is SAMPLE_RUNNING_CONFIG (tests/conftest.py): A1 untagged 20 + tagged 30 with 802.1X, Trk1 = A5 + A6. Its inventory is
make_inv() of tests/test_changes_mechanism.py (parse_config does not list A5 / A6 as ports), the SNMP switch W_SAMPLE of
tests/switchfix.py (ports 4 + 5 in Trk1, without a bridge port of their own) as its agent holds it, planned with plan_snmp from there.
"""
import pytest

import cfgparse
import changes
import db
from conftest import SAMPLE_RUNNING_CONFIG
from drivers import DRIVERS
from switchfix import IF_ADMIN, W_SAMPLE, agent
from test_changes_mechanism import make_inv, plan_snmp

FW = "K.15.99.0001"
PROCURVE = DRIVERS["procurve"]
SAMPLE = agent(W_SAMPLE)    # as the simulated agent holds it (free text as hex), the form plan_snmp reads
cfg = cfgparse.parse_config(SAMPLE_RUNNING_CONFIG)
inv = make_inv()
# A2 with 802.1X + MAC auth and unauth-vid 99 on 802.1X, switched off
NAC_CFG = cfgparse.parse_config(SAMPLE_RUNNING_CONFIG + "interface A2\n   disable\n   exit\naaa port-access authenticator A2\n"
                                "aaa port-access authenticator A2 unauth-vid 99\naaa port-access mac-based A2\n")


def test_an_ssh_revert_to_no_untagged_vlan_removes_it():                        # Phase 1: "vlan None untagged"
    plan = changes.plan_ports(FW, inv, cfg, {"desired": {"A1": {"u": None}}})
    assert plan["commands"] == ["no vlan 20 untagged A1"] and plan["blocked"] == []


def test_the_untagged_removal_comes_after_the_tagged_lines():
    plan = changes.plan_ports(FW, inv, cfg, {"desired": {"A1": {"u": None, "t": ["30", "99"]}}})
    assert plan["commands"] == ["vlan 99 tagged A1", "no vlan 20 untagged A1"]


def test_an_ssh_revert_round_trip_verifies():                                     # passes before the fix too: the read-back fits the plan
    after = cfgparse.parse_config(SAMPLE_RUNNING_CONFIG.replace("   untagged A1\n", ""))
    assert changes.verify_ports(after, changes.plan_ports(FW, inv, cfg, {"desired": {"A1": {"u": None}}})["desired"]) == []


# SAMPLE_RUNNING_CONFIG with A1 tagged in 20 and 30 and no untagged VLAN
TAGGED_ONLY = cfgparse.parse_config(SAMPLE_RUNNING_CONFIG.replace("   untagged A1\n   tagged Trk1\n", "   tagged A1,Trk1\n"))


def test_a_revert_that_makes_the_untagged_vlan_tagged_sends_only_the_tagged_line():
    """Review round 1: undoing "untagged 20 + tagged_remove 20" on a tagged-only port. `vlan 20 tagged A1` already turns A1's untagged
    membership in VLAN 20 into a tagged one; a `no vlan 20 untagged A1` after it would fail or set A1 to "No" in VLAN 20
    (docs/procurve-cli-referenz.md 3.4), the opposite of the revert."""
    plan = changes.plan_ports(FW, inv, cfg, {"desired": {"A1": {"u": None, "t": ["20", "30"]}}})
    assert (plan["commands"], plan["blocked"]) == (["vlan 20 tagged A1"], [])
    assert changes.verify_ports(TAGGED_ONLY, plan["desired"]) == []


def test_making_a_tagged_vlan_the_untagged_one_sends_only_the_untagged_line():
    """The forward change of the test above: `vlan 20 untagged A1` turns A1's tagged membership in VLAN 20 into the untagged one; a
    `no vlan 20 tagged A1` after it would take A1 out of VLAN 20 again. Its revert (desired = before) is the tagged line alone."""
    plan = changes.plan_ports(FW, inv, TAGGED_ONLY, {"ports": ["A1"], "set": {"untagged": "20", "tagged_remove": ["20"]}})
    assert (plan["commands"], plan["blocked"]) == (["vlan 20 untagged A1"], [])
    assert changes.verify_ports(cfg, plan["desired"]) == []
    assert changes.plan_ports(FW, inv, cfg, {"desired": plan["before"]})["commands"] == ["vlan 20 tagged A1"]


def test_no_untagged_line_for_a_port_without_an_untagged_vlan():
    """_commands on its own: u None on a port that has no untagged VLAN renders nothing (plan_ports drops such a field before)."""
    assert changes._commands(cfg, {"A5": {"u": None}}) == []


@pytest.mark.parametrize("change, command", [({"name": "Uplink-A"}, "interface A5 name Uplink-A"), ({"status": "off"}, "interface A5 disable")])
def test_a_trunk_member_takes_name_and_on_off(change, command):
    plan = changes.plan_ports(FW, inv, cfg, {"ports": ["A5"], "set": change, "expert": True})
    assert plan["blocked"] == [] and plan["commands"] == [command]


def test_a_trunk_member_still_refuses_vlans_and_poe():
    for change in ({"untagged": "20"}, {"tagged_add": ["30"]}, {"status": "radius"}, {"poe": False}):
        assert changes.plan_ports(FW, inv, cfg, {"ports": ["A5"], "set": change, "expert": True})["blocked"] == [
            {"port": "A5", "reason": "gehört zu Trk1, bitte Trk1 wählen"}]


def test_a_trunk_member_without_fields_is_not_blocked():
    """A member whose request changes nothing ("on", which it already is) is neither blocked nor planned."""
    plan = changes.plan_ports(FW, inv, cfg, {"ports": ["A5"], "set": {"status": "on"}, "expert": True})
    assert (plan["blocked"], plan["commands"], plan["desired"]) == ([], [], {})


def test_a_member_of_an_uplink_trunk_needs_expert_mode():                        # Review Focus 4
    assert changes.plan_ports(FW, make_inv(uplinks={"Trk1", "A5", "A6"}), cfg, {"ports": ["A5"], "set": {"status": "off"}})["blocked"] == [
        {"port": "A5", "reason": "Uplink/Trunk: nur im Expertenmodus"}]


def _poll_says_trk2(inv: dict) -> dict:
    inv["ports"]["A5"]["tr"] = "Trk2"
    return inv


@pytest.mark.parametrize("port_inv", [
    pytest.param(make_inv(uplinks={"Trk1"}, stale={"A5"}), id="the-poll-does-not-know-the-member"),
    pytest.param(_poll_says_trk2(make_inv(uplinks={"Trk1"})), id="the-poll-knows-it-in-another-trunk"),
])
def test_a_member_of_an_uplink_trunk_only_the_fresh_read_knows_needs_expert_mode(port_inv):
    """Review round 1: the running-config puts A5 in Trk1, an uplink, while the poll does not (stale or still in another trunk), so
    changes.inventory does not list A5 as an uplink. Its name / on-off still needs expert mode, as an uplink port would (R40: the uplink
    and trunk protection never gets weaker; before Task 4 such a member was refused outright)."""
    req = {"ports": ["A5"], "set": {"status": "off"}}
    plan = changes.plan_ports(FW, port_inv, cfg, req)
    assert (plan["blocked"], plan["commands"]) == ([{"port": "A5", "reason": "Uplink/Trunk: nur im Expertenmodus"}], [])
    assert changes.plan_ports(FW, port_inv, cfg, {**req, "expert": True})["commands"] == ["interface A5 disable"]


def test_a_member_of_an_uplink_trunk_the_poll_does_not_know_needs_expert_mode_over_snmp():
    plan = plan_snmp(SAMPLE, PROCURVE, {"ports": ["4"], "set": {"status": "off"}}, uplinks={"Trk1"}, stale={"4"})
    assert (plan["blocked"], plan["ops"]) == ([{"port": "4", "reason": "Uplink/Trunk: nur im Expertenmodus"}], [])


def test_a_trunk_member_takes_name_and_on_off_over_snmp():                      # W_SAMPLE: 4 + 5 in Trk1, without a bridge port of their own
    plan = plan_snmp(SAMPLE, PROCURVE, {"ports": ["4"], "set": {"status": "off"}, "expert": True})
    assert plan["blocked"] == [] and plan["ops"] == [(f"{IF_ADMIN}.4", "i", "2")]
    assert plan_snmp(SAMPLE, PROCURVE, {"ports": ["4"], "set": {"poe": False}, "expert": True})["blocked"][0]["reason"].startswith(
        "gehört zu Trk1")


@pytest.mark.parametrize("change", [{"status": "on"}, {"untagged": "30"}, {"name": "X"}])
def test_a_non_nac_change_keeps_the_unauth_vlan(change):
    cmds = changes.plan_ports(FW, inv, NAC_CFG, {"ports": ["A2"], "set": change})["commands"]
    assert not any("unauth-vid" in c for c in cmds)


def test_a_nac_change_still_normalises_the_unauth_vlan():
    assert "no aaa port-access authenticator A2 unauth-vid" in changes.plan_ports(FW, inv, NAC_CFG, {"ports": ["A2"], "set": {"status": "radius"}})["commands"]


def test_radius_needs_the_configured_server():
    plan = changes.plan_ports(FW, inv, cfg, {"ports": ["A2"], "set": {"status": "radius"}}, radius_server="203.0.113.99")
    assert {"port": "*", "reason": "Switch ist nicht für RADIUS vorbereitet: RADIUS-Server 203.0.113.99"} in plan["blocked"]
    assert not changes.plan_ports(FW, inv, cfg, {"ports": ["A2"], "set": {"status": "radius"}}, radius_server="203.0.113.10")["blocked"]


# The ProCurve of ssh_env (tests/sshfix.py), prepared for RADIUS with server 203.0.113.10
RADIUS_READY = ('hostname "SW-EK-01"\nvlan 1\n   name "DEFAULT_VLAN"\n   untagged 1-24\n   exit\nradius-server host 203.0.113.10 key "x"\n'
                "aaa authentication port-access eap-radius\naaa port-access authenticator active\n")
RADIUS_REQ = {"ports": ["2"], "set": {"status": "radius"}}


async def _run_radius_change(env, monkeypatch, server: str) -> tuple[dict, list[str]]:
    """A RADIUS change of port 2, previewed without a RADIUS server in the settings, run by run_change with `server` stored: its row
    and the commands of its preview."""
    env.running = RADIUS_READY
    port_inv = {"ports": {"2": {"n": "2", "tr": "", "l": [], "o": False}}, "uplinks": set()}

    async def inventory(sid):
        return port_inv
    monkeypatch.setattr(changes, "inventory", inventory)
    plan = changes.plan_ports(FW, port_inv, cfgparse.parse_config(RADIUS_READY), RADIUS_REQ)
    assert plan["blocked"] == [] and plan["commands"]
    cid = await changes.create_change(env.sid, "tester", "ports", "Port 2: RADIUS", RADIUS_REQ, plan)
    await db.set_setting("radius_server", server)
    await changes.run_change(cid)
    return env.change(cid), plan["commands"]


async def test_run_change_needs_the_configured_radius_server(ssh_env, monkeypatch):
    """Review §3 in run_change: its re-plan gets the server of the settings (radius_settings()["server"]) and aborts, nothing sent."""
    row, _ = await _run_radius_change(ssh_env, monkeypatch, "203.0.113.99")
    assert (row["status"], row["error"]) == ("aborted", "*: Switch ist nicht für RADIUS vorbereitet: RADIUS-Server 203.0.113.99")
    assert ssh_env.sent == []


async def test_run_change_sends_with_the_configured_radius_server_on_the_switch(ssh_env, monkeypatch):
    """The same change with the server the switch has goes out (the fake's read-back does not change, so it ends "unclear")."""
    row, commands = await _run_radius_change(ssh_env, monkeypatch, "203.0.113.10")
    assert ssh_env.sent == [commands] and row["status"] == "unclear"
