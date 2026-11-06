"""Golden tests for app/cfgparse.py (running-config parser, port-list helpers, secret masking).

These are characterization tests: they pin what the module does TODAY so later SNMP/multivendor
work cannot silently change the SSH/CLI path. Expected values are written out by hand from the
`sample_running_config` fixture (tests/conftest.py), not generated from the parser's own output.
cfgparse is imported flat (app/ is on sys.path via pytest.ini), exactly as the app itself imports it.
"""
import re
import time

import pytest

import cfgparse
from cfgparse import compress_ports, expand_ports, mask_secrets, parse_config, port_sort_key, port_state


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


def test_expand_ports_rejects_huge_range():
    """NV cfgparse-unbounded-range-expansion: an absurd range raises ValueError instead of being materialised as a giant list
    (it was an xfail until the cap of Phase 2 landed)."""
    with pytest.raises(ValueError):
        expand_ports("1-100000")


# ── Limits and int-safety (F5, NV cfgparse-unbounded-range-expansion) ─────────────────────────────────────────────────────────────
# A running-config comes from the switch, so a compromised or MITM'd one controls it: no token may raise out of parse_config, and
# no line may make it allocate or loop beyond the limits (the parse runs on the single worker's event loop).
BIG = "9" * 5000    # more digits than int() reads from a str (its default limit is 4300): int(BIG) raises ValueError


def test_expand_ports_limits():
    """A range has at most MAX_RANGE ports, a list at most MAX_EXPAND; both checked before anything is materialised."""
    assert (cfgparse.MAX_RANGE, cfgparse.MAX_EXPAND, cfgparse.MAX_REFS) == (1024, 4096, 1_000_000)
    assert len(expand_ports("A1-A1024")) == 1024 and len(expand_ports("Trk1-Trk1024")) == 1024
    for spec in ("A1-A1025", "1-1025", "Trk1-Trk1025", "1/A1-1/A2000"):
        with pytest.raises(ValueError, match="^Portbereich zu groß: "):
            expand_ports(spec)
    four = "A1-A1024,B1-B1024,C1-C1024,D1-D1024"
    assert len(expand_ports(four)) == 4096
    for spec in (four + ",E1", four + ",E1-E2", ",".join(["1"] * 4097)):
        with pytest.raises(ValueError, match="^Portliste zu lang: "):
            expand_ports(spec)


@pytest.mark.parametrize("line", ["untagged vlan abc", "untagged vlan 1-x", "tagged vlan 0", "tagged vlan 4095", "tagged vlan 9-3"])
def test_unusable_vlan_tokens_are_skipped(line):                              # F5, Eingabe des Audits
    cfg = parse_config(f"vlan 1\n   untagged 1\n   exit\ninterface 1\n   {line}\n   exit\n")
    assert cfg["ports"]["1"]["u"] == "1" and cfg["ports"]["1"]["t"] == []


def test_usable_vlan_tokens_next_to_unusable_ones_still_count():
    """Only the bad tokens of a list are skipped (a leading zero, an empty token, a reversed or half-numeric range, 0, 4095); every
    VLAN ID 1..4094 and every range a-b inside it stays, and no VLAN is made up from a skipped token."""
    cfg = parse_config("vlan 1\n   untagged 1\n   exit\ninterface 1\n   tagged vlan 20,030,,30-32,9-3,1-x,0,4095,4094,abc\n   exit\n")
    assert cfg["ports"]["1"]["t"] == ["20", "30", "31", "32", "4094"]
    assert list(cfg["vlans"]) == ["1", "20", "30", "31", "32", "4094"]


@pytest.mark.parametrize("text", [
    f"vlan {BIG}\n   untagged 1\n   exit\n",                                      # a top-level VLAN beyond int(): its block is skipped
    "vlan 4095\n   untagged 1\n   exit\n",                                        # ... and one outside 1..4094
    "vlan 0100\n   untagged 1\n   exit\n",                                        # ... and one with a leading zero
    "interface 1\n   aaa port-access authenticator client-limit \u00b2\n   exit\n",  # "²".isdigit() is True, int("²") raises
    f"interface 1\n   aaa port-access mac-based addr-limit {BIG}\n   exit\n",
    f"aaa port-access authenticator 1 client-limit {BIG}\n",
    f"radius-server host 10.0.0.1 time-window {BIG}\n",
    f"trunk 2-3 Trk{BIG}\n",
    "interface " + "1" * 5000 + "\n   disable\n   exit\n",                          # a port token beyond 6 digits (cfgparse._TOKEN)
    "interface ٣\n   disable\n   exit\n",                                       # an Arabic-Indic digit: \d took it, [0-9] does not
], ids=["vlan-beyond-int", "vlan-4095", "vlan-leading-zero", "client-limit-superscript", "addr-limit-beyond-int",
        "global-client-limit-beyond-int", "time-window-beyond-int", "trunk-beyond-int", "interface-5000-digits", "interface-arabic-digit"])
def test_a_number_the_parser_cannot_use_never_stops_it(text):
    """F5 beyond the VLAN tokens: every int() of parse_config reads a switch token, and each unusable one is skipped, not raised. A
    port token is ASCII digits only and bounded (cfgparse._TOKEN / _TRK): no other port than 1 comes out of these lines."""
    cfg = parse_config("vlan 1\n   untagged 1\n   exit\n" + text)
    assert cfg["vlans"] == {"1": ""} and cfg["trunks"] == {}
    assert set(cfg["ports"]) == {"1"}
    assert (cfg["ports"]["1"]["u"], cfg["ports"]["1"]["cl"], cfg["ports"]["1"]["al"]) == ("1", None, None)
    assert cfg["radius"].get("10.0.0.1", {}).get("time_window") is None


def test_usable_numbers_still_parse():
    """The guard of the test above: the same lines with ordinary numbers keep their values."""
    cfg = parse_config("vlan 1\n   untagged 1-3\n   exit\ninterface 1\n   aaa port-access authenticator client-limit 2\n"
                       "   aaa port-access mac-based addr-limit 3\n   exit\nradius-server host 10.0.0.1 time-window 0\ntrunk 2-3 Trk07\n")
    assert (cfg["ports"]["1"]["cl"], cfg["ports"]["1"]["al"], cfg["radius"]["10.0.0.1"]["time_window"]) == (2, 3, 0)
    assert cfg["trunks"] == {"Trk7": ["2", "3"]}


def test_a_giant_range_is_skipped():                                          # NV, Eingabe des Audits (verkleinert)
    cfg = parse_config("interface A1-A200000\n   disable\n   exit\nvlan 1\n   untagged A1\n   exit\n")
    assert "A5" not in cfg["ports"] and cfg["ports"]["A1"]["u"] == "1"


def test_more_than_max_refs_is_refused():                                     # 5 × 1000 Ports × 201 VLANs ≈ 1,01 Mio.
    with pytest.raises(ValueError, match="Konfiguration zu groß"):
        parse_config("".join(f"interface {m}1-{m}1000\n   tagged vlan 1-201\n   exit\n" for m in "ABCDE"))


def test_the_refs_limit_is_exact_and_its_message_fixed():
    """The limit is MAX_REFS entries: 500 blocks of 1000 ports (the range) plus 1000 × 1 VLAN entries are exactly 1 000 000 and parse;
    one port more is refused with the message as written, raised out of parse_config (no per-line except swallows it)."""
    at_limit = "interface 1-1000\n   tagged vlan 1\n   exit\n" * 500
    assert parse_config(at_limit)["ports"]["1000"]["t"] == ["1"]
    with pytest.raises(ValueError, match=f"^{re.escape('Konfiguration zu groß: mehr als 1000000 Port-/VLAN-Einträge')}$"):
        parse_config(at_limit + "interface 1\n   exit\n")


@pytest.mark.parametrize("text", [
    "interface 1-1000\n" + "   disable\n" * 1000 + "   exit\n",                        # each line of a block runs once per port
    "vlan 1\n" + "   tagged 1-1000\n" * 1001 + "   exit\n",                            # each expanded port list counts
    "".join(f"aaa port-access authenticator 1-1000 client-limit {i}\n" for i in range(1001)),
    "".join(f"trunk 1-1000 Trk{i}\n" for i in range(1001)),
    "interface 1\n   tagged vlan " + ",".join(["1-4094"] * 245) + "\n   exit\n",       # a repeated VLAN counts each time
    "interface 1\n   tagged vlan " + ",".join(["4094-1,1-4094"] * 245) + "\n   exit\n",  # a reversed range offsets nothing
], ids=["lines-of-a-wide-block", "vlan-port-lists", "global-port-access", "trunks", "repeated-vlan-ranges", "reversed-ranges"])
def test_every_expansion_counts_against_max_refs(text):
    with pytest.raises(ValueError, match="^Konfiguration zu groß"):
        parse_config(text)


def test_many_tagged_vlans_parse_in_linear_time():                           # unter der Grenze: kein langer Stillstand im Event-Loop
    t = time.process_time()
    cfg = parse_config("interface 1-100\n   tagged vlan 1-4000\n   exit\n")              # 400 000 Einträge; gemessen: 0,5 s, heute 9 s
    assert time.process_time() - t < 3 and cfg["ports"]["100"]["t"] == [str(v) for v in range(1, 4001)]


# ── Lines no other test of the suite reaches (Phase 3, Task 1: cfgparse coverage) ────────────────────────────────────────────────
@pytest.mark.parametrize("spec, ports", [("1,,2", ["1", "2"]), ("trk2", ["Trk2"]), ("A1-a3", ["A1", "A2", "A3"])])
def test_expand_ports_skips_empty_parts_and_normalises(spec, ports):
    assert expand_ports(spec) == ports


@pytest.mark.parametrize("spec", ["1-A3", "A1-B2", "x", "1/1-2/3"])
def test_expand_ports_refuses_what_it_cannot_read(spec):
    pytest.raises(ValueError, expand_ports, spec)


def test_port_sort_key_orders_ports_trunks_and_the_rest():
    assert sorted(["Trk2", "10", "x/y", "A1", "2", "Trk1", "1/3"], key=port_sort_key) == ["2", "10", "A1", "1/3", "Trk1", "Trk2", "x/y"]


def test_compress_ports_refuses_another_vendors_name():
    pytest.raises(ValueError, compress_ports, ["Gi1/0/1"])


def test_global_lines_set_their_fields():
    cfg = parse_config("primary-vlan 20\nmanagement-vlan 99\naaa authentication ssh login radius\naaa port-access mac-based addr-format no-delimiter\n"
                       "aaa port-access authenticator quiet-period 30\naaa port-access mac-based 4\naaa port-access mac-based 4 unauth-vid 0\n"
                       "aaa port-access mac-based 5 unauth-vid 7\n")
    assert (cfg["primary_vlan"], cfg["mgmt_vlan"], cfg["login_radius"], cfg["addr_format"]) == ("20", "99", True, "no-delimiter")
    assert cfg["ports"]["4"]["m"] is True and cfg["ports"]["4"]["al"] == 1 and cfg["ports"]["4"]["muv"] is None and cfg["ports"]["5"]["muv"] == "7"
    assert "quiet-period" not in cfg["ports"]


def test_aaa_with_nothing_after_it_changes_nothing():
    st = cfgparse._empty_port()
    cfgparse._aaa(st, "  ")
    assert st == cfgparse._empty_port()


def test_port_state_of_an_unknown_port_is_the_empty_port():
    assert port_state({"ports": {}}, "9") == cfgparse._empty_port()


# ── Masking (§6 (d), Thema A, NV masking:changes-error-and-steps-persisted-unmasked) ─────────────────────────────────────────────
@pytest.mark.parametrize("line", ['snmpv3 user "u" auth sha-256 "X1" priv aes-256 "Y1"', 'snmpv3 user "u" auth sha256 "X1" priv aes128 "Y1"',
                                  'key-chain "k" key 1 key-string "Z1"', 'tacacs-server host 10.0.0.9 key "T1"',
                                  'snmp-server host 10.0.0.9 community "C1"', 'password manager user-name "admin" sha256 "H1"'])
def test_mask_secrets_covers(line):                                           # §6 (d), Thema A
    assert not re.search(r"[XYZTCH]1", mask_secrets(line))


@pytest.mark.parametrize("line", ['snmpv3 user "u" auth MD5 "X1" priv DES "Y1"', 'snmpv3 user "u" auth SHA-512 "X1" priv 3DES "Y1"',
                                  'snmpv3 user "u" auth sha "X1" priv aes "Y1"', 'snmpv3 user "u" auth sha1 "X1" priv des56 "Y1"',
                                  'key-chain "k" key 1 encrypted-key-string "Z1"'])
def test_mask_secrets_covers_every_v3_spelling(line):
    """Each SNMPv3 protocol spelling of the brief (md5, sha with or without -N, des with digits, 3des, aes with or without -N), in any
    case, and the encrypted key-string form."""
    assert not re.search(r"[XYZ]1", mask_secrets(line))


def test_mask_secrets_masks_every_form_of_a_known_secret():
    """A value from extra is masked as it is, as re.escape writes it, and as repr() then shows that (netmiko's ReadTimeout text is
    "Pattern not detected: {repr(re.escape(cmd))}"), the longest form first, so no rest of it stays; an empty value masks nothing."""
    secret = "S3cr3t.Key!"
    cmd = f"radius-server host 203.0.113.10 key {secret}"
    for text in (cmd, re.escape(cmd), repr(re.escape(cmd)), f"Pattern not detected: {re.escape(cmd)!r} in output."):
        masked = mask_secrets(text, [secret])
        assert "S3cr3t" not in masked and "Key!" not in masked and "***" in masked, masked
    assert mask_secrets("abc abcd", ["abc", "abcd", ""]) == "*** ***"
    assert mask_secrets("nothing to hide", ["", None]) == "nothing to hide"
