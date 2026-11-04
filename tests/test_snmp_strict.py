"""Tests for the strict mode of snmp.walk: a walk that ends with an error after it has already printed rows.

snmpbulkwalk prints every varbind as it arrives. If the agent stops answering in the middle of a table (timeout, error packet),
snmpbulkwalk reports that on stderr and exits non-zero, but the rows it got so far are already on stdout. snmp._run only raises
when stdout is empty, so by default (what the display poller relies on) such a partial walk still counts as a result, exactly as
before. strict=True, which the SNMP write path uses (snmpwrite.read_cfg), turns EVERY non-zero exit into an SnmpError, so a write is
never planned or verified against half a table. A strict hex walk (the PortLists) also refuses any value that is not pure hex, so
no stray line can turn into bridge-port bits.

These tests keep the real snmp._run and only fake the process it starts. snmp is imported flat (app/ is on sys.path via pytest.ini),
exactly as the app imports it.
"""
import pytest

import snmp

HOST = "203.0.113.21"
CRED = {"snmp_version": "2c", "snmp_community": "ro-s3cret"}
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
# Two rows of ifName, then the agent stopped answering: what snmpbulkwalk leaves on stdout / stderr in that case.
PARTIAL = f'.{IF_NAME}.1 "1"\n.{IF_NAME}.2 "2"\n'.encode()
ROWS = [(f"{IF_NAME}.1", "1"), (f"{IF_NAME}.2", "2")]
TIMEOUT = f"Timeout: No Response from {HOST}\n".encode()


class _FakeProc:
    """Stands in for the asyncio subprocess that _run starts: it has already finished, with the given output and exit code."""

    def __init__(self, out=b"", err=b"", returncode=0):
        self.returncode = returncode
        self._out, self._err = out, err

    async def communicate(self):
        return self._out, self._err

    def kill(self):    # only reached on a timeout of _run itself, which these tests do not simulate
        pass


class _Spawner:
    """What the faked create_subprocess_exec hands to _run next (set with answer), and the argv of every start."""

    def __init__(self):
        self.proc, self.started = _FakeProc(), []

    def answer(self, out=b"", err=b"", returncode=0):
        self.proc = _FakeProc(out, err, returncode)


@pytest.fixture
def process(monkeypatch):
    """Let the real snmp._run run, but hand it the process `process.answer(...)` describes instead of starting snmpbulkwalk."""
    spawner = _Spawner()

    async def fake_exec(*argv, **kwargs):
        spawner.started.append(argv)
        return spawner.proc

    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", fake_exec)
    return spawner


async def test_by_default_a_partial_walk_still_counts(process):
    """Unchanged lenient default (the display poller): exit 2 after two rows gives the two rows, no error."""
    process.answer(out=PARTIAL, err=TIMEOUT, returncode=2)
    assert await snmp.walk(HOST, CRED, IF_NAME) == ROWS
    assert await snmp.walk(HOST, CRED, IF_NAME, strict=False) == ROWS


async def test_strict_refuses_a_partial_walk(process):
    """strict=True: the same exit 2 after two rows is an SnmpError with snmpbulkwalk's own reason, never the two rows."""
    process.answer(out=PARTIAL, err=TIMEOUT, returncode=2)
    with pytest.raises(snmp.SnmpError, match=f"^Timeout: No Response from {HOST}$"):
        await snmp.walk(HOST, CRED, IF_NAME, strict=True)


async def test_strict_without_a_reason_names_the_exit_code(process):
    process.answer(out=PARTIAL, err=b"", returncode=2)
    with pytest.raises(snmp.SnmpError, match="^snmp Exit-Code 2$"):
        await snmp.walk(HOST, CRED, IF_NAME, strict=True)


@pytest.mark.parametrize("strict", [False, True])
async def test_a_clean_walk_is_fine_in_both_modes(process, strict):
    """Exit 0 is success in both modes, with rows or without (an empty table is no error)."""
    process.answer(out=PARTIAL, returncode=0)
    assert await snmp.walk(HOST, CRED, IF_NAME, strict=strict) == ROWS
    process.answer(out=b"", returncode=0)
    assert await snmp.walk(HOST, CRED, IF_NAME, strict=strict) == []


@pytest.mark.parametrize("strict", [False, True])
async def test_no_answer_at_all_fails_in_both_modes(process, strict):
    """Non-zero exit without any output was an SnmpError before and stays one in both modes."""
    process.answer(err=TIMEOUT, returncode=1)
    with pytest.raises(snmp.SnmpError, match=f"^Timeout: No Response from {HOST}$"):
        await snmp.walk(HOST, CRED, IF_NAME, strict=strict)


# ── strict hex walks: a PortList value is hex and nothing else ──────────────────────────────────────────────────────────────────
# _parse appends every line that does not start with an OID to the value before it (net-snmp wraps long values). Behind a PortList
# a stray line such as "End of MIB" would end up in the value, and hex_to_bytes would read its letters E, d, f, B as two more
# bytes: bits for bridge ports that do not exist, which a read-modify-write would send back to the switch. So a strict hex walk
# only accepts hex digits and whitespace in a value, also on its continuation lines.
EGRESS = "1.3.6.1.2.1.17.7.1.4.3.1.2"       # dot1qVlanStaticEgressPorts, walked with -Ox
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
STRAY = f".{EGRESS}.20 80 00\nEnd of MIB\n".encode()


async def test_strict_hex_walk_refuses_a_stray_line_after_a_portlist(process):
    process.answer(out=STRAY)
    with pytest.raises(snmp.SnmpError, match=rf"^Unerwartete Ausgabe in einem Hex-Wert \({EGRESS}\.20\)"):
        await snmp.walk(HOST, CRED, EGRESS, hex_values=True, strict=True)


async def test_lenient_hex_walk_keeps_the_old_behaviour(process):
    """The display poller (lenient) still gets the joined value, phantom bytes included: exactly what the strict check keeps out."""
    process.answer(out=STRAY)
    rows = await snmp.walk(HOST, CRED, EGRESS, hex_values=True)
    assert rows == [(f"{EGRESS}.20", "80 00\nEnd of MIB")]
    assert snmp.hex_to_bytes(rows[0][1]) == bytes.fromhex("8000EDFB")


async def test_strict_hex_walk_refuses_a_value_that_is_no_hex(process):
    process.answer(out=f".{EGRESS}.20 kaputt\n".encode())
    with pytest.raises(snmp.SnmpError, match="Hex-Wert"):
        await snmp.walk(HOST, CRED, EGRESS, hex_values=True, strict=True)


async def test_strict_hex_walk_takes_a_wrapped_value(process):
    """A long PortList that net-snmp wraps over two lines is pure hex on both lines: it parses, byte for byte (bridge ports 1, 144)."""
    first = " ".join(["80"] + ["00"] * 15)
    process.answer(out=f".{EGRESS}.20 {first}\n00 01 \n".encode())
    rows = await snmp.walk(HOST, CRED, EGRESS, hex_values=True, strict=True)
    assert len(rows) == 1 and rows[0][0] == f"{EGRESS}.20"
    assert snmp.hex_to_bytes(rows[0][1]) == bytes([0x80] + [0] * 16 + [0x01])
    assert snmp.bitmap_ports(rows[0][1]) == {1, 144}


async def test_strict_hex_walk_still_drops_missing_values_and_keeps_empty_ones(process):
    """The usual markers for "nothing there" are dropped before the hex check, an empty octet string ("") is a valid value."""
    process.answer(out=f'.{EGRESS}.20 ""\n.{EGRESS}.30 No Such Instance currently exists at this OID\n'.encode())
    assert await snmp.walk(HOST, CRED, EGRESS, hex_values=True, strict=True) == [(f"{EGRESS}.20", "")]


async def test_strict_text_walk_keeps_multi_line_strings(process):
    """The hex check is only for hex walks: a string over two lines (an ifAlias with a line break) stays a valid value."""
    process.answer(out=f'.{IF_ALIAS}.1 "Platz 107\nTuer links"\n'.encode())
    assert await snmp.walk(HOST, CRED, IF_ALIAS, strict=True) == [(f"{IF_ALIAS}.1", "Platz 107\nTuer links")]


async def test_strict_does_not_change_the_command(process):
    """strict is decided in Python after the process ended; snmpbulkwalk is started with the very same argv in both modes."""
    await snmp.walk(HOST, CRED, IF_NAME, hex_values=True)
    await snmp.walk(HOST, CRED, IF_NAME, hex_values=True, strict=True)
    assert len(process.started) == 2
    assert process.started[0] == process.started[1] == (
        "snmpbulkwalk", "-v2c", "-c", "ro-s3cret", "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", "-Cr25", "-Ox", HOST, IF_NAME)
