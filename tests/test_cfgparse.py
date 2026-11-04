"""Golden tests for app/cfgparse.py (running-config parser, port-list helpers, secret masking).

These are characterization tests: they pin what the module does TODAY so later SNMP/multivendor
work cannot silently change the SSH/CLI path. Expected values are written out by hand from the
`sample_running_config` fixture (tests/conftest.py), not generated from the parser's own output.
cfgparse is imported flat (app/ is on sys.path via pytest.ini), exactly as the app itself imports it.
"""
import pytest

from cfgparse import compress_ports, expand_ports, mask_secrets, parse_config


def test_parse_config_golden(sample_running_config):
    cfg = parse_config(sample_running_config)

    assert cfg["hostname"] == "SW-EK-01"
    assert cfg["vlans"] == {"1": "DEFAULT_VLAN", "20": "Clients", "30": "Voice", "99": "Guest"}
    assert cfg["voice_vlans"] == ["30"]
    assert cfg["trunks"] == {"Trk1": ["A5", "A6"]}

    # Access port: untagged in 20, tagged (voice) in 30, 802.1X with client-limit 2 and guest VLAN 99.
    assert cfg["ports"]["A1"] == {
        "u": "20", "t": ["30"], "name": "Platz-107", "en": True,
        "x": True, "m": False, "cl": 2, "al": None, "xuv": "99", "muv": None,
    }
    # Plain access port in the default VLAN, and an administratively disabled one.
    assert cfg["ports"]["A2"]["u"] == "1"
    assert cfg["ports"]["A3"]["en"] is False
    # The trunk is tagged-only: member of every non-default VLAN, untagged in none.
    assert cfg["ports"]["Trk1"]["u"] is None
    assert cfg["ports"]["Trk1"]["t"] == ["20", "30", "99"]

    # Global 802.1X / RADIUS state; the parsed config records that a key exists, never the key itself.
    assert cfg["auth_active"] is True
    assert cfg["eap_radius"] is True
    assert cfg["radius"] == {"203.0.113.10": {"key": True, "dyn": True, "time_window": None}}


@pytest.mark.parametrize("spec", [
    "A1-A3,A5",        # expected by the plan
    "1-3,7,Trk1",      # fixed-port numbering plus a trunk
    "1/A1-1/A3,2/B4",  # stacked members
    "A22-A24,B1-B2",   # ranges are never merged across module boundaries
])
def test_expand_compress_roundtrip(spec):
    assert compress_ports(expand_ports(spec)) == spec


@pytest.mark.parametrize("line", [
    "radius-server host 10.0.0.10 key SECRET",
    'radius-server host 10.0.0.10 key "SECRET"',            # as printed by the switch
    'radius-server host 10.0.0.10 encrypted-key "SECRET"',
])
def test_mask_secrets_radius_key(line):
    masked = mask_secrets(line)
    assert "SECRET" not in masked
    assert "***" in masked
    assert masked.startswith("radius-server host 10.0.0.10 ")  # only the secret is masked


def test_expand_ports_modest_range_expands():
    """Documents today's behaviour: a realistic range is expanded in full."""
    assert expand_ports("A1-A50") == [f"A{i}" for i in range(1, 51)]


@pytest.mark.xfail(
    strict=True,
    # Only the intended outcome ("DID NOT RAISE", i.e. no cap yet) counts as the expected failure;
    # an unrelated crash inside expand_ports() stays a real failure instead of being swallowed.
    raises=pytest.fail.Exception,
    reason="cfgparse-unbounded-range-expansion: unbounded range expansion — hardening tracked in security findings, not yet fixed",
)
def test_expand_ports_rejects_huge_range():
    """Desired bound, NOT current behaviour: expand_ports() has no cap on range size, so an absurd range
    is materialised as a giant list instead of raising ValueError. strict=True turns this red as soon as
    the hardening lands, as a reminder to drop the xfail marker."""
    with pytest.raises(ValueError):
        expand_ports("1-100000")
