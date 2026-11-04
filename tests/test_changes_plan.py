"""Golden tests for the safety-critical pure part of app/changes.py: planning a port change (_desired_from_set,
plan_ports), rendering it as ProCurve CLI lines (_commands) and checking the config read back from the switch
(verify_ports).

These are characterization tests: they pin what the code does TODAY, so that the SNMP/multivendor work (plan_ports gets
a mechanism and a driver) cannot silently change what is sent to a switch over SSH. Expected values are worked out by
hand from the code and from `sample_running_config` (tests/conftest.py), not pasted from a run. Everything tested here
is pure: cfg / inv / req are plain dicts, exactly as cfgparse.parse_config() and changes.inventory() build them, so no
database, crypto, SSH or SNMP is involved. changes and cfgparse are imported flat (app/ is on sys.path via pytest.ini),
the way the app imports them.

The sample switch the expectations rely on: A1 = untagged 20, tagged 30, 802.1X (client-limit 2, unauth-vid 99), name
"Platz-107"; A2-A4 and A7-A24 = untagged 1; A3 disabled (name "unused"); Trk1 (members A5, A6) = tagged 20/30/99;
VLANs 1/20/30/99; RADIUS host, eap-radius and "authenticator active" are configured, i.e. the switch is RADIUS-ready.
"""
import re

import pytest

import cfgparse
import changes

FW = "K.15.99.0001"  # the release named in the sample config header; changes.limit_max() allows 32 devices per port there
R_NAC = "RADIUS/bekannte Geräte gehen nicht auf Uplinks und Trunks"
R_EXPERT = "Uplink/Trunk: nur im Expertenmodus"


@pytest.fixture
def cfg(sample_running_config):
    return cfgparse.parse_config(sample_running_config)


def make_inv(uplinks=(), lldp=None, link=()):
    """Inventory in the shape changes.inventory() returns, cut down to what plan_ports reads per port: tr (the trunk the
    port belongs to), l (LLDP neighbours as [system name, port]) and o (link is up). A1-A24 plus Trk1; A5/A6 are Trk1's members."""
    lldp = lldp or {}
    names = [f"A{i}" for i in range(1, 25)] + ["Trk1"]
    ports = {n: {"n": n, "tr": "Trk1" if n in ("A5", "A6") else "", "l": lldp.get(n, []), "o": n in link} for n in names}
    return {"ports": ports, "uplinks": set(uplinks)}


def a2_moved_to_vlan_20(text: str) -> str:
    """What `show running-config` prints once `vlan 20 untagged A2` has been applied: A2 leaves VLAN 1's untagged list
    and joins the one of VLAN 20."""
    old_v1, new_v1 = "   untagged A2-A4,A7-A24\n", "   untagged A3-A4,A7-A24\n"
    old_v20, new_v20 = "   untagged A1\n", "   untagged A1-A2\n"
    assert old_v1 in text and old_v20 in text  # the edit below must really hit the fixture
    return text.replace(old_v1, new_v1).replace(old_v20, new_v20)


# ── _desired_from_set: request -> only the fields that differ from the current port ───────────────────────────────
@pytest.mark.parametrize("untagged", ["20", 20])
def test_desired_from_set_untagged(cfg, untagged):
    """A2 sits untagged in VLAN 1. Only the field that changes is wanted, and the VLAN id is always a string."""
    assert changes._desired_from_set(cfg, ["A2"], {"untagged": untagged}) == {"A2": {"u": "20"}}


@pytest.mark.parametrize("port, change, wanted", [
    # already the way it should be: the port stays in the result with nothing to do
    ("A1", {"untagged": "20"}, {}),
    ("A2", {"status": "protected"}, {}),
    ("A2", {"limit": 5}, {}),                                 # a device limit means nothing on a port without 802.1X / MAC auth
    # tagged VLANs: relative to the current list (A1 is tagged in 30), sorted numerically
    ("A1", {"tagged_add": ["99"], "tagged_remove": ["30"]}, {"t": ["99"]}),
    ("A2", {"tagged_add": ["100", "20"]}, {"t": ["20", "100"]}),
    # description; an empty one removes it
    ("A2", {"name": "Drucker"}, {"name": "Drucker"}),
    ("A3", {"name": ""}, {"name": ""}),
    # status. Switching 802.1X / MAC auth on always sets a device limit: without client-limit 802.1X works per port,
    # so after one login the port would be open for every further device. A fresh limit defaults to 1.
    ("A2", {"status": "radius"}, {"x": True, "m": True, "cl": 1, "al": 1}),
    ("A2", {"status": "known"}, {"m": True, "al": 1}),
    ("A2", {"status": "radius", "limit": 3}, {"x": True, "m": True, "cl": 3, "al": 3}),
    ("A2", {"status": "known", "guest": "99"}, {"m": True, "al": 1, "muv": "99"}),
    ("A1", {"limit": 5}, {"cl": 5}),                          # A1 runs 802.1X already: only its client-limit changes
    # switching NAC off leaves limits and guest VLAN in the config on purpose (verify_ports knows about that)
    ("A1", {"status": "protected"}, {"x": False}),
    ("A1", {"status": "off"}, {"en": False}),
    ("A3", {"status": "protected"}, {"en": True}),            # every status except "off" also re-enables a disabled port
    # A1 (802.1X) gets MAC auth as well: the MAC limit follows the 802.1X client-limit (2), and since only the MAC
    # authenticator may carry an unauth-vid (observed on a 2520G/J.15) it is taken off 802.1X
    ("A1", {"status": "radius"}, {"m": True, "al": 2, "xuv": None}),
    ("A1", {"guest": ""}, {"xuv": None}),                     # an empty guest VLAN removes it
])
def test_desired_from_set_golden(cfg, port, change, wanted):
    assert changes._desired_from_set(cfg, [port], change) == {port: wanted}


# ── _commands: desired -> ProCurve CLI lines ──────────────────────────────────────────────────────────────────────
def test_commands_untagged_change(cfg, sample_running_config):
    """Move A2 from untagged VLAN 1 to untagged VLAN 20: one line, and the read-back of the switch confirms it."""
    req = {"ports": ["A2"], "set": {"untagged": "20"}}
    plan = changes.plan_ports(FW, make_inv(), cfg, req)
    assert plan["commands"] == ["vlan 20 untagged A2"]   # never "no vlan 1 untagged A2" first: the old membership goes by itself
    assert changes._commands(cfg, plan["desired"]) == ["vlan 20 untagged A2"]

    cfg_after = cfgparse.parse_config(a2_moved_to_vlan_20(sample_running_config))
    assert cfg_after["ports"]["A2"]["u"] == "20"          # the edited fixture really shows A2 in VLAN 20
    assert changes.verify_ports(cfg_after, plan["desired"]) == []


@pytest.mark.parametrize("desired, line", [
    ({"A1": {"x": False}}, "no aaa port-access authenticator A1"),
    ({"A2": {"m": False}}, "no aaa port-access mac-based A2"),
    ({"A2": {"u": "20"}}, "vlan 20 untagged A2"),
    ({"A2": {"t": ["30"]}}, "vlan 30 tagged A2"),
    ({"A1": {"t": []}}, "no vlan 30 tagged A1"),             # A1 is tagged in 30 now
    ({"A2": {"name": "Drucker"}}, "interface A2 name Drucker"),
    ({"A3": {"name": ""}}, "no interface A3 name"),
    ({"A3": {"en": True}}, "interface A3 enable"),
    ({"A1": {"en": False}}, "interface A1 disable"),
    ({"A2": {"x": True}}, "aaa port-access authenticator A2"),
    ({"A1": {"cl": 3}}, "aaa port-access authenticator A1 client-limit 3"),
    ({"A1": {"xuv": "30"}}, "aaa port-access authenticator A1 unauth-vid 30"),
    ({"A1": {"xuv": None}}, "no aaa port-access authenticator A1 unauth-vid"),
    ({"A2": {"m": True}}, "aaa port-access mac-based A2"),
])
def test_commands_render_each_command(cfg, desired, line):
    """The exact CLI syntax of every command the planner can emit (the MAC-based limit / unauth-vid ones are below)."""
    assert changes._commands(cfg, desired) == [line]


@pytest.mark.parametrize("desired, line", [
    ({"A4": {"al": 3}}, "aaa port-access mac-based A4 addr-limit 3"),
    ({"A4": {"muv": "30"}}, "aaa port-access mac-based A4 unauth-vid 30"),
    ({"A4": {"muv": None}}, "no aaa port-access mac-based A4 unauth-vid"),
])
def test_commands_render_mac_based_commands(desired, line):
    # The sample config has no MAC-authenticated port, and _commands only looks at cfg["ports"][port]: A4 runs MAC auth here.
    mac_cfg = {"ports": {"A4": {"m": True, "al": 1, "muv": "99"}}}
    assert changes._commands(mac_cfg, desired) == [line]


@pytest.mark.parametrize("desired", [
    {"A2": {"cl": 3}},
    {"A2": {"xuv": "30"}},
    {"A2": {"al": 3}},
    {"A2": {"muv": "30"}},
])
def test_commands_nothing_for_an_auth_method_that_is_off(cfg, desired):
    """Limits and guest VLANs are only sent for a method that is on (or switched on in the same change). A2 runs neither."""
    assert changes._commands(cfg, desired) == []


def test_commands_group_ports_per_command(cfg):
    desired = {"A7": {"u": "20"}, "A2": {"u": "20"}, "A4": {"u": "20"}, "A3": {"u": "20"}, "A9": {"u": "30"}}
    assert changes._commands(cfg, desired) == [
        "vlan 20 untagged A2-A4,A7",   # one line per command and value, ports sorted and compressed to ranges
        "vlan 30 untagged A9",
    ]


def test_commands_order_teardown_first(cfg):
    """Authentication goes off before the VLAN membership changes, then name and admin state."""
    desired = {"A1": {"x": False, "u": "1", "t": ["99"], "name": "", "en": False}}
    assert changes._commands(cfg, desired) == [
        "no aaa port-access authenticator A1",
        "vlan 1 untagged A1",
        "vlan 99 tagged A1",
        "no vlan 30 tagged A1",
        "no interface A1 name",
        "interface A1 disable",
    ]


def test_commands_order_authentication_last(cfg):
    """Name and admin state first, authentication is switched on last: 802.1X, then MAC auth, each with limit and guest VLAN."""
    desired = {"A2": {"name": "Drucker", "en": True, "x": True, "m": True, "cl": 2, "al": 2, "muv": "99"}}
    assert changes._commands(cfg, desired) == [
        "interface A2 name Drucker",
        "interface A2 enable",
        "aaa port-access authenticator A2",
        "aaa port-access authenticator A2 client-limit 2",
        "aaa port-access mac-based A2",
        "aaa port-access mac-based A2 addr-limit 2",
        "aaa port-access mac-based A2 unauth-vid 99",
    ]


def test_commands_split_long_lines():
    """A port list that would push a line past 110 characters is split on a port boundary (J.15 has a limited terminal width)."""
    ports = [f"{module}{n}" for module in "ABC" for n in range(1, 24, 2)]  # A1,A3,...,C23: never adjacent, so no ranges
    lines = changes._commands({}, {p: {"u": "20"} for p in ports})
    assert lines == [
        # "vlan 20 untagged " is 17 characters, the list up to C3 is 91: 108. Adding ",C5" would make 111.
        "vlan 20 untagged A1,A3,A5,A7,A9,A11,A13,A15,A17,A19,A21,A23,B1,B3,B5,B7,B9,B11,B13,B15,B17,B19,B21,B23,C1,C3",
        "vlan 20 untagged C5,C7,C9,C11,C13,C15,C17,C19,C21,C23",
    ]
    assert all(len(line) <= 110 for line in lines)


# ── plan_ports: the whole plan ────────────────────────────────────────────────────────────────────────────────────
def test_plan_ports_untagged_change_golden(cfg):
    """The complete plan dict, key for key: the plan of the SSH path has to keep exactly this shape (Task 9 added only "mechanism")."""
    plan = changes.plan_ports(FW, make_inv(), cfg, {"ports": ["A2"], "set": {"untagged": "20"}})
    assert plan == {
        "commands": ["vlan 20 untagged A2"],
        "shown": ["vlan 20 untagged A2"],
        "desired": {"A2": {"u": "20"}},
        "before": {"A2": {"u": "1"}},       # the snapshot "revert" plans from
        "blocked": [],
        "warnings": [],
        "expert": False,
        "mechanism": "ssh",                  # Task 9: the plan names its write path; SSH is the default
    }


def test_plan_ports_radius_on_access_port_golden(cfg, sample_running_config):
    """Allowed NAC change on an ordinary access port: A2 to RADIUS, with an access point (LLDP) hanging on it."""
    inv = make_inv(lldp={"A2": [["ap-1.example", "Port 1"]]})
    plan = changes.plan_ports(FW, inv, cfg, {"ports": ["A2"], "set": {"status": "radius"}})
    assert plan == {
        "commands": [
            "aaa port-access authenticator A2",
            "aaa port-access authenticator A2 client-limit 1",
            "aaa port-access mac-based A2",
            "aaa port-access mac-based A2 addr-limit 1",
        ],
        "shown": [
            "aaa port-access authenticator A2",
            "aaa port-access authenticator A2 client-limit 1",
            "aaa port-access mac-based A2",
            "aaa port-access mac-based A2 addr-limit 1",
        ],
        "desired": {"A2": {"x": True, "m": True, "cl": 1, "al": 1}},
        "before": {"A2": {"x": False, "m": False, "cl": None, "al": None}},
        "blocked": [],
        "warnings": ["Port A2: dort hängt ap-1.example (LLDP). Muss sich danach selbst anmelden können"],
        "expert": False,
        "mechanism": "ssh",
    }
    # The switch does not print "addr-limit 1" (the default); the parser fills it in, so the read-back still verifies.
    after = sample_running_config + (
        "aaa port-access authenticator A2\n"
        "aaa port-access authenticator A2 client-limit 1\n"
        "aaa port-access mac-based A2\n"
    )
    assert changes.verify_ports(cfgparse.parse_config(after), plan["desired"]) == []


@pytest.mark.parametrize("expert", [False, True])
@pytest.mark.parametrize("status", ["known", "radius"])
@pytest.mark.parametrize("port, uplinks", [
    ("A24", {"A24"}),                 # a plain uplink port
    ("Trk1", {"Trk1", "A5", "A6"}),   # an uplink trunk (inventory() puts the members into the set as well)
])
def test_plan_ports_blocks_uplink(cfg, port, uplinks, status, expert):
    """MAC / 802.1X authentication is never applied to an uplink or a trunk, not even in expert mode."""
    req = {"ports": [port], "set": {"status": status}, "expert": expert}
    plan = changes.plan_ports(FW, make_inv(uplinks=uplinks), cfg, req)
    assert plan["blocked"] == [{"port": port, "reason": R_NAC}]
    assert plan["commands"] == [] and plan["desired"] == {}
    assert plan["expert"] is expert


@pytest.mark.parametrize("port, change, expert, uplinks, reason", [
    pytest.param("A24", {"untagged": "20"}, False, {"A24"}, R_EXPERT, id="uplink-needs-expert"),
    pytest.param("Trk1", {"untagged": "20"}, False, set(), R_EXPERT, id="trunk-needs-expert"),
    pytest.param("Trk1", {"name": "uplink"}, True, set(), "Name und An/Aus nur an den Mitglied-Ports des Trunks", id="trunk-no-name"),
    pytest.param("Trk1", {"status": "off"}, True, set(), "Name und An/Aus nur an den Mitglied-Ports des Trunks", id="trunk-no-off"),
    pytest.param("A5", {"untagged": "20"}, False, set(), "gehört zu Trk1, bitte Trk1 wählen", id="trunk-member"),
    pytest.param("A99", {"untagged": "20"}, False, set(), "Port gibt es auf diesem Switch nicht", id="no-such-port"),
    pytest.param("A2", {"untagged": "77"}, False, set(), "VLAN 77 gibt es auf diesem Switch nicht", id="unknown-untagged-vlan"),
    pytest.param("A2", {"tagged_add": ["88"]}, False, set(), "VLAN 88 gibt es auf diesem Switch nicht", id="unknown-tagged-vlan"),
    pytest.param("A1", {"untagged": "30"}, False, set(), "VLAN 30 kann nicht ungetaggt und getaggt zugleich sein", id="untagged-and-tagged"),
    pytest.param("Trk1", {"tagged_remove": ["20", "30", "99"]}, True, set(), "Port wäre in keinem VLAN mehr", id="no-vlan-left"),
])
def test_plan_ports_blocks(cfg, port, change, expert, uplinks, reason):
    plan = changes.plan_ports(FW, make_inv(uplinks=uplinks), cfg, {"ports": [port], "set": change, "expert": expert})
    assert plan["blocked"] == [{"port": port, "reason": reason}]
    assert plan["commands"] == []   # a blocked port is dropped from the plan


def test_plan_ports_expert_allows_uplink_vlan_change(cfg):
    req = {"ports": ["A24"], "set": {"untagged": "20"}, "expert": True}
    plan = changes.plan_ports(FW, make_inv(uplinks={"A24"}), cfg, req)
    assert plan["blocked"] == []
    assert plan["commands"] == ["vlan 20 untagged A24"]
    assert plan["expert"] is True


def test_plan_ports_nac_needs_radius_ready_switch(cfg):
    """Port-level NAC changes need the switch-wide RADIUS prerequisites; plain VLAN changes do not.

    Note (observed, deliberately not asserted): a switch-level block ("port": "*") leaves plan["commands"] filled in, since
    no single port is dropped. apply_change and run_change refuse to run whenever plan["blocked"] is non-empty.
    """
    nac = {"ports": ["A2"], "set": {"status": "radius"}}
    bare = {**cfg, "radius": {}, "eap_radius": False, "auth_active": False}
    plan = changes.plan_ports(FW, make_inv(), bare, nac)
    assert plan["blocked"] == [{
        "port": "*",
        "reason": "Switch ist nicht für RADIUS vorbereitet: RADIUS-Server, 802.1X-Methode eap-radius, 802.1X global aktiv",
    }]
    no_eap = changes.plan_ports(FW, make_inv(), {**cfg, "eap_radius": False}, nac)
    assert no_eap["blocked"] == [{"port": "*", "reason": "Switch ist nicht für RADIUS vorbereitet: 802.1X-Methode eap-radius"}]
    assert changes.plan_ports(FW, make_inv(), bare, {"ports": ["A2"], "set": {"untagged": "20"}})["blocked"] == []


@pytest.mark.parametrize("port, change, inv_kw, warnings", [
    # a VLAN change does not reach a running 802.1X session until it logs off; VLAN 1 is the default VLAN
    ("A1", {"untagged": "1"}, {}, [
        "Port A1: läuft gerade eine Anmeldung, greift das neue VLAN erst nach der Abmeldung",
        "Port A1: VLAN 1 ist das Standard-VLAN",
    ]),
    # tagged VLANs can get lost under MAC authentication (A1 is tagged in 30)
    ("A1", {"status": "known"}, {}, ["Port A1: hat getaggte VLANs (30). Bei MAC-Anmeldung können sie wegfallen"]),
    # a device on the port (access point, phone) has to authenticate on its own afterwards
    ("A2", {"status": "radius"}, {"lldp": {"A2": [["ap-1.example", "Port 1"]]}}, [
        "Port A2: dort hängt ap-1.example (LLDP). Muss sich danach selbst anmelden können",
    ]),
    # switching off a port that has link
    ("A1", {"status": "off"}, {"link": {"A1"}}, ["Port A1: hat Link, das Gerät verliert die Verbindung"]),
])
def test_plan_ports_warnings(cfg, port, change, inv_kw, warnings):
    plan = changes.plan_ports(FW, make_inv(**inv_kw), cfg, {"ports": [port], "set": change})
    assert plan["blocked"] == []
    assert plan["warnings"] == warnings


@pytest.mark.parametrize("req, fw, message", [
    # the description goes verbatim into `interface <port> name <text>`: nothing that could end or extend that line
    ({"ports": ["A1"], "set": {"name": "two words"}}, FW, "Beschreibung"),
    ({"ports": ["A1"], "set": {"name": "x\nreload"}}, FW, "Beschreibung"),
    ({"ports": ["A1"], "set": {"name": "a" * 65}}, FW, "Beschreibung"),
    ({"ports": ["A1"], "set": {"status": "bogus"}}, FW, "Unbekannter Port-Status"),
    ({"ports": ["A1"], "set": {"limit": 3}}, "J.15.09", "Geräte pro Port: 1–2 auf dieser Firmware"),
    ({"ports": ["A1"], "set": {"limit": 0}}, FW, "Geräte pro Port: 1–32 auf dieser Firmware"),
    ({"ports": [], "set": {"untagged": "20"}}, FW, "Keine Ports gewählt"),
    ({"desired": {}}, FW, "Keine Ports gewählt"),
])
def test_plan_ports_rejects_invalid_requests(cfg, req, fw, message):
    with pytest.raises(ValueError, match=message):
        changes.plan_ports(fw, make_inv(), cfg, req)


@pytest.mark.parametrize("fw, maximum", [
    ("J.15.09", 2),        # 2520G
    ("YA.15.16", 2),
    ("YB.15.14", 2),
    ("K.15.99.0001", 32),
    ("WB.16.10.0003", 32),
    ("", 32),
])
def test_limit_max(fw, maximum):
    assert changes.limit_max(fw) == maximum


def test_plan_ports_revert_restores_before_snapshot(cfg, sample_running_config):
    """Revert plans from the stored `before` snapshot (request form {"desired": ...}) and sends the old value back."""
    inv = make_inv()
    plan = changes.plan_ports(FW, inv, cfg, {"ports": ["A2"], "set": {"untagged": "20"}})
    cfg_after = cfgparse.parse_config(a2_moved_to_vlan_20(sample_running_config))

    revert = changes.plan_ports(FW, inv, cfg_after, {"desired": plan["before"]})
    assert revert["commands"] == ["vlan 1 untagged A2"]
    assert revert["blocked"] == []
    assert revert["warnings"] == ["Port A2: VLAN 1 ist das Standard-VLAN"]
    # once the switch is back at the old state there is nothing left to revert
    assert changes.plan_ports(FW, inv, cfg, {"desired": plan["before"]})["commands"] == []


# ── verify_ports: config read back from the switch vs. desired ─────────────────────────────────────────────────────
def test_verify_ports_flags_unapplied_change(cfg):
    """The switch silently ignored the change: the read-back still shows A2 untagged in VLAN 1."""
    assert changes.verify_ports(cfg, {"A2": {"u": "20"}}) == ["Port A2: u ist '1', erwartet '20'"]


def test_verify_ports_tagged_lists_compare_numerically_and_unordered():
    cfg_after = {"ports": {"A1": {"t": ["20", "100"]}}}
    assert changes.verify_ports(cfg_after, {"A1": {"t": ["100", "20"]}}) == []
    assert changes.verify_ports(cfg_after, {"A1": {"t": ["20"]}}) == ["Port A1: t ist ['20', '100'], erwartet ['20']"]


def test_verify_ports_ignores_limits_of_an_auth_method_that_is_off():
    """After `no aaa port-access ...` limit and guest VLAN stay in the config but have no effect: not compared then."""
    wanted = {"A2": {"cl": 5, "xuv": "7", "al": 3, "muv": "8"}}
    off = {"ports": {"A2": {"x": False, "m": False, "cl": 2, "xuv": "99", "al": 2, "muv": "99"}}}
    assert changes.verify_ports(off, wanted) == []
    on = {"ports": {"A2": {"x": True, "m": True, "cl": 2, "xuv": None, "al": 1, "muv": "99"}}}
    assert changes.verify_ports(on, wanted) == [
        "Port A2: cl ist 2, erwartet 5",
        "Port A2: xuv ist None, erwartet '7'",
        "Port A2: al ist 1, erwartet 3",
        "Port A2: muv ist '99', erwartet '8'",
    ]


def test_verify_ports_always_checks_the_auth_flags(cfg):
    assert changes.verify_ports(cfg, {"A1": {"x": False}}) == ["Port A1: x ist True, erwartet False"]


# ── cmd_token: ties "apply" to the previewed commands ───────────────────────────────────────────────────────────────
def test_cmd_token_follows_the_commands():
    cmds = ["vlan 20 untagged A2", "interface A2 enable"]
    token = changes.cmd_token(cmds)
    assert re.fullmatch(r"[0-9a-f]{16}", token)
    assert changes.cmd_token(list(cmds)) == token
    assert changes.cmd_token(cmds[:1]) != token
    assert changes.cmd_token(cmds[::-1]) != token
