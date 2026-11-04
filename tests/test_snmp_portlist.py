"""Tests for the PortList bit-encode helpers in app/snmp.py: portlist_has_bit, portlist_set_bit, portlist_clear_bit, portlist_to_hex.

They are the write-side twin of snmp.bitmap_ports. A switch reports a VLAN's members as one PortList octet string; to move a
single port the app reads that string, flips exactly that port's bit and writes the WHOLE string back. If any other bit moved,
or the string came back shorter or longer than the switch sent it, other ports would silently change VLAN. So these tests pin
the bit numbering, "only the target bit changes" and "the length is kept" for every port of a small list, not just for a few
examples.

The numbering is the Q-BRIDGE one that bitmap_ports decodes: bridge port 1 is the most significant bit of byte 0, port 8 its
least significant bit, port 9 the most significant bit of byte 1, and so on. Expected bytes below are worked out by hand from
that definition. Where a test checks a result by decoding it, the decoder is the long-standing snmp.bitmap_ports (pinned in
test_snmp_decode.py), an oracle that is independent of the helpers under test. Pure byte math: no net-snmp binary, no network,
no mocks. snmp is imported flat (app/ is on sys.path via pytest.ini), exactly as the app imports it.
"""
import pytest

import snmp

# Three-byte lists (ports 1-24) that between them hold every bit pattern the single-bit flips below have to survive.
PATTERNS = [
    pytest.param(b"\x00\x00\x00", id="none"),
    pytest.param(b"\xff\xff\xff", id="all"),
    pytest.param(b"\xa5\x5a\xc3", id="mixed"),             # 1010 0101, 0101 1010, 1100 0011
    pytest.param(b"\x80\x00\x01", id="first-and-last"),    # ports 1 and 24
]


def _ports(raw: bytes) -> set[int]:
    """The ports a PortList holds, read back the way the app reads a switch's answer: hex text, then bitmap_ports."""
    return snmp.bitmap_ports(snmp.portlist_to_hex(raw))


def _build(ports) -> bytes:
    """A PortList holding exactly these ports, grown from the empty string one set_bit at a time."""
    raw = b""
    for port in ports:
        raw = snmp.portlist_set_bit(raw, port)
    return raw


@pytest.mark.parametrize("ports", [
    pytest.param(set(), id="empty"),                       # nothing set: stays the empty string
    pytest.param({1}, id="port-1"),
    pytest.param({8}, id="port-8"),                        # last bit of byte 0
    pytest.param({9}, id="port-9"),                        # first bit of byte 1
    pytest.param({1, 8, 9, 16}, id="byte-edges"),
    pytest.param({3, 5, 17, 20, 24}, id="scattered"),
    pytest.param({1, 144}, id="long-list"),                # 18 bytes: the PortList of test_wrapped_hex_value_decodes_to_ports
    pytest.param(set(range(1, 49)), id="48-ports"),
])
def test_roundtrip_with_bitmap(ports):
    """Build a list port by port from nothing; decoding what the helpers produced gives back exactly the ports that were set."""
    raw = _build(sorted(ports))
    assert snmp.bitmap_ports(snmp.portlist_to_hex(raw)) == ports
    assert len(raw) == (max(ports, default=0) + 7) // 8    # exactly as long as the highest port needs, not longer
    assert _build(sorted(ports, reverse=True)) == raw      # the order in which the ports are set makes no difference


def test_set_preserves_others():
    raw = snmp.portlist_set_bit(b"\x80\x00", 16)
    assert _ports(raw) == {1, 16}                          # port 1 is still there next to the new port 16
    assert raw == b"\x80\x01"                              # nothing else moved, and the string kept its two bytes


@pytest.mark.parametrize("raw", PATTERNS)
def test_set_changes_only_the_target_bit(raw):
    """Setting each of the 24 ports in turn adds exactly that port: every other bit survives and the string keeps its length."""
    before = _ports(raw)
    for port in range(1, 25):
        after = snmp.portlist_set_bit(raw, port)
        assert len(after) == len(raw)
        assert _ports(after) == before | {port}


def test_clear_preserves_others():
    raw = snmp.portlist_clear_bit(b"\x80\x01", 1)          # ports {1, 16} without port 1
    assert _ports(raw) == {16}
    assert raw == b"\x00\x01"                              # byte 0 is all zero now, but it is still there: the length is kept


@pytest.mark.parametrize("raw", PATTERNS)
def test_clear_changes_only_the_target_bit(raw):
    """Clearing each of the 24 ports in turn removes exactly that port: every other bit survives and the string keeps its length."""
    before = _ports(raw)
    for port in range(1, 25):
        after = snmp.portlist_clear_bit(raw, port)
        assert len(after) == len(raw)
        assert _ports(after) == before - {port}


def test_set_grows_length():
    raw = snmp.portlist_set_bit(b"\x80", 20)               # port 20 is in byte 2 (ports 17-24); the list only has byte 0
    assert raw == b"\x80\x00\x10"                          # grown by zero bytes to exactly 3; port 20 = 0001 0000 in byte 2
    assert _ports(raw) == {1, 20}


def test_clear_beyond_the_end_pads_like_set():
    """Interface contract: set AND clear extend a string that is too short. The bit is 0 either way, so no port appears."""
    raw = snmp.portlist_clear_bit(b"\x80", 20)
    assert raw == b"\x80\x00\x00"
    assert _ports(raw) == {1}


@pytest.mark.parametrize("port, expected", [
    (1, True),         # most significant bit of byte 0
    (2, False),
    (8, False),        # least significant bit of byte 0
    (9, False),        # most significant bit of byte 1
    (15, False),
    (16, True),        # least significant bit of byte 1
    (17, False),       # beyond the end of the string: not set, and not an error
    (1000, False),
])
def test_has_bit_known(port, expected):
    assert snmp.portlist_has_bit(b"\x80\x01", port) is expected    # ports {1, 16}; `is` because the result must be a real bool


@pytest.mark.parametrize("raw", [*PATTERNS, pytest.param(b"", id="empty")])
def test_has_bit_agrees_with_bitmap_ports(raw):
    """For every port of the list and eight beyond its end (those must read as not set), has_bit says what the decoder says."""
    held = _ports(raw)
    for port in range(1, 8 * len(raw) + 9):
        assert snmp.portlist_has_bit(raw, port) is (port in held)


@pytest.mark.parametrize("raw, port, expected", [
    (b"", 1, b"\x80"),                       # port 1 = most significant bit of byte 0
    (b"", 8, b"\x01"),                       # port 8 = least significant bit of byte 0
    (b"", 9, b"\x00\x80"),                   # port 9 = most significant bit of byte 1: the string grows by one byte
    (b"", 16, b"\x00\x01"),
    (b"\x00\x00\x00", 5, b"\x08\x00\x00"),   # 0000 1000
    (b"\x00\x00\x00", 17, b"\x00\x00\x80"),
    (b"\x01", 1, b"\x81"),                   # next to a bit that is already set in the same byte
    (b"\x40", 2, b"\x40"),                   # already set: nothing changes
])
def test_set_bit_known_bytes(raw, port, expected):
    assert snmp.portlist_set_bit(raw, port) == expected


@pytest.mark.parametrize("raw, port, expected", [
    (b"\xff", 1, b"\x7f"),
    (b"\xff", 8, b"\xfe"),
    (b"\xff\xff", 9, b"\xff\x7f"),
    (b"\xff\xff", 16, b"\xff\xfe"),
    (b"\xa5", 3, b"\x85"),                   # 1010 0101 -> 1000 0101
    (b"\x80\x00", 1, b"\x00\x00"),           # a byte that becomes zero stays in the string
    (b"\x00\x00", 5, b"\x00\x00"),           # not set: nothing changes
])
def test_clear_bit_known_bytes(raw, port, expected):
    assert snmp.portlist_clear_bit(raw, port) == expected


@pytest.mark.parametrize("raw", PATTERNS)
def test_flip_and_flip_back_restores_the_original(raw):
    """What a revert relies on: undoing a change on the captured bytes gives the captured bytes back, bit for bit."""
    for port in range(1, 25):
        if snmp.portlist_has_bit(raw, port):
            assert snmp.portlist_set_bit(snmp.portlist_clear_bit(raw, port), port) == raw
        else:
            assert snmp.portlist_clear_bit(snmp.portlist_set_bit(raw, port), port) == raw


@pytest.mark.parametrize("func", ["portlist_set_bit", "portlist_clear_bit"])
def test_returns_new_bytes_and_leaves_the_input_alone(func):
    raw = bytearray(b"\x80\x01")                           # the one kind of input that could be modified in place
    out = getattr(snmp, func)(raw, 9)
    assert type(out) is bytes
    assert raw == bytearray(b"\x80\x01")


@pytest.mark.parametrize("port", [0, -1, -8, -9])
@pytest.mark.parametrize("func", ["portlist_has_bit", "portlist_set_bit", "portlist_clear_bit"])
def test_port_below_one_is_rejected(func, port):
    """Bridge ports start at 1. Without the check, port 0 would index byte -1 and silently change the LAST byte of the string."""
    with pytest.raises(ValueError):
        getattr(snmp, func)(b"\x80\x00", port)


@pytest.mark.parametrize("raw, text", [
    (b"", ""),
    (b"\x80\x00", "8000"),
    (b"\x00\x01", "0001"),                   # a byte is always two digits, leading zeros included
    (b"\x0a\x0b\x0c", "0A0B0C"),
    (b"\xab\xcd\xef", "ABCDEF"),             # upper case
    (b"\x80" + bytes(16) + b"\x01", "80" + "00" * 16 + "01"),    # 18 bytes as one token: no spaces or line breaks to quote around
])
def test_portlist_to_hex(raw, text):
    assert snmp.portlist_to_hex(raw) == text
