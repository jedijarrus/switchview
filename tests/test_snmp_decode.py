"""Golden tests for the SNMP decode helpers in app/snmp.py: hex_to_bytes, bitmap_ports and the output parser _parse.

These are characterization tests: they pin what the module does TODAY, so that the later multivendor work (PortList
bit encoding, SNMP writes) cannot silently change how the existing read path decodes a switch's answers. Expected
values are written out by hand from the Q-BRIDGE PortList definition (bit 1 = most significant bit of the first
byte = bridge port 1) and from net-snmp's text output, not generated from the code. _parse() works on plain text, so
no net-snmp binary and no network is involved. snmp is imported flat (app/ is on sys.path via pytest.ini), exactly
as the app itself imports it.
"""
import pytest

import snmp


@pytest.mark.parametrize("value, ports", [
    ("80 00", {1}),                                        # MSB of the first byte is bridge port 1
    ("00 01", {16}),                                       # LSB of the second byte is bridge port 16
    ("", set()),
    ("00 00 00", set()),
    ("FF", {1, 2, 3, 4, 5, 6, 7, 8}),
    ("A0", {1, 3}),                                        # 1010 0000
    ("ff 0f", {1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16}),   # lower-case hex; second byte 0000 1111 = ports 13-16
    ("40 00 00 01", {2, 32}),                              # bit 2 of byte 0, last bit of byte 3
    ("8000", {1}),                                         # the separators between the bytes are optional
])
def test_bitmap_ports_known(value, ports):
    assert snmp.bitmap_ports(value) == ports


@pytest.mark.parametrize("value, raw", [
    ("80 00", b"\x80\x00"),
    ("ab CD eF", b"\xab\xcd\xef"),            # case does not matter
    ("0a:0b-0c", b"\x0a\x0b\x0c"),            # every non-hex character counts as a separator
    ("80 00\n00 01", b"\x80\x00\x00\x01"),    # so does a line break inside a wrapped hex string
    ("80 0", b"\x80"),                        # an odd number of digits: the dangling nibble is dropped
    ("", b""),
    ("zz", b""),                              # nothing hex at all
])
def test_hex_to_bytes(value, raw):
    assert snmp.hex_to_bytes(value) == raw


def test_parse_continuation():
    """A string value that net-snmp prints over two lines comes back as one value, joined with a newline."""
    text = '.1.3.6.1.2.1.1.1.0 "first line\nsecond line"\n.1.3.6.1.2.1.1.5.0 "sw-01"\n'
    assert snmp._parse(text) == [
        ("1.3.6.1.2.1.1.1.0", "first line\nsecond line"),
        ("1.3.6.1.2.1.1.5.0", "sw-01"),
    ]


def test_parse_rows_strip_leading_dot_and_quotes():
    text = (
        '.1.3.6.1.2.1.31.1.1.1.1.1 "A1"\n'
        '.1.3.6.1.2.1.31.1.1.1.1.2 "A2"\n'
        ".1.3.6.1.2.1.1.3.0 123456\n"
        '.1.3.6.1.2.1.1.5.0 ""\n'
    )
    assert snmp._parse(text) == [
        ("1.3.6.1.2.1.31.1.1.1.1.1", "A1"),        # leading dot of the numeric OID is dropped, quotes are dropped
        ("1.3.6.1.2.1.31.1.1.1.1.2", "A2"),
        ("1.3.6.1.2.1.1.3.0", "123456"),           # unquoted values (-Oq prints numbers bare) stay as they are
        ("1.3.6.1.2.1.1.5.0", ""),                 # an empty string
    ]


@pytest.mark.parametrize("marker", [
    "No Such Object available on this agent at this OID",
    "No Such Instance currently exists at this OID",
    "No more variables left in this MIB View (It is past the end of the MIB tree)",
])
def test_parse_drops_missing_values(marker):
    text = f".1.3.6.1.2.1.1.5.0 {marker}\n.1.3.6.1.2.1.1.3.0 42\n"
    assert snmp._parse(text) == [("1.3.6.1.2.1.1.3.0", "42")]


def test_parse_ignores_blank_lines_and_text_before_the_first_oid():
    text = "some banner before the first OID\n\n.1.3.6.1.2.1.1.3.0 42\n\n"
    assert snmp._parse(text) == [("1.3.6.1.2.1.1.3.0", "42")]


def test_wrapped_hex_value_decodes_to_ports():
    """End to end for a long PortList: the hex string comes back on two lines, _parse joins them, bitmap_ports ignores the break.

    Bytes 0-15 are on the first line, bytes 16 and 17 on the second: 0x80 in byte 0 is port 1,
    0x01 in byte 17 is port 17*8 + 8 = 144.
    """
    first = " ".join(["80"] + ["00"] * 15)
    rows = snmp._parse(f".1.3.6.1.2.1.17.7.1.4.3.1.2.20 {first}\n00 01\n")
    assert len(rows) == 1
    oid, value = rows[0]
    assert oid == "1.3.6.1.2.1.17.7.1.4.3.1.2.20"
    assert snmp.bitmap_ports(value) == {1, 144}
