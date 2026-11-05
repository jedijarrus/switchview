"""Tests for the strict mode of snmp.walk: a walk that ends with an error after it has already printed rows.

snmpbulkwalk prints every varbind as it arrives. If the agent stops answering in the middle of a table (timeout, error packet),
snmpbulkwalk reports that on stderr and exits non-zero, but the rows it got so far are already on stdout. snmp._run only raises
when stdout is empty, so by default (what the display poller relies on) such a partial walk still counts as a result, exactly as
before. strict=True, which the SNMP write path uses (snmpwrite.read_cfg), turns EVERY non-zero exit into an SnmpError, so a write is
never planned or verified against half a table. A strict hex walk (the PortLists) also refuses any value that is not pure hex, so
no stray line can turn into bridge-port bits.

A strict text walk (every other walk of read_cfg) refuses any line that does not belong to a value: only a quoted string can go on
over several lines.

These tests keep the real snmp._run and only fake the process it starts (switchfix.FakeProcess). snmp is imported flat (app/ is on
sys.path via pytest.ini), exactly as the app imports it.
"""
import random
import re

import pytest

import snmp
from switchfix import FakeProcess

HOST = "203.0.113.21"
CRED = {"snmp_version": "2c", "snmp_community": "ro-s3cret"}
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
# Two rows of ifName, then the agent stopped answering: what snmpbulkwalk leaves on stdout / stderr in that case.
PARTIAL = f'.{IF_NAME}.1 "1"\n.{IF_NAME}.2 "2"\n'.encode()
ROWS = [(f"{IF_NAME}.1", "1"), (f"{IF_NAME}.2", "2")]
TIMEOUT = f"Timeout: No Response from {HOST}\n".encode()


class _Spawner:
    """What the faked create_subprocess_exec hands to _run next (set with answer: a process that has already finished, with the given
    output and exit code), and the argv of every start. Each start gets a fresh copy, so one answer serves several walks."""

    def __init__(self):
        self.proc, self.started = FakeProcess(), []

    def answer(self, out=b"", err=b"", returncode=0):
        self.proc = FakeProcess(out, err, returncode)


@pytest.fixture
def process(monkeypatch):
    """Let the real snmp._run run, but hand it the process `process.answer(...)` describes instead of starting snmpbulkwalk."""
    spawner = _Spawner()

    async def fake_exec(*argv, **kwargs):
        spawner.started.append(argv)
        return spawner.proc.fresh()

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


# ── strict text walks: only a quoted string wraps ───────────────────────────────────────────────────────────────────────────────────
# Without -Ox net-snmp prints a printable OCTET STRING in quotes (with \" and \\ inside it escaped by a backslash) and every number,
# enum and OID bare. A string with a line break goes on over the next lines up to its closing quote; nothing else ever wraps. So in a
# strict text walk (every walk of read_cfg but the two PortLists: ifName, ifAlias, vlanName, ifAdmin, bp2if, pvid, ifStack, ifType,
# vmVlan) a line without an OID is only taken while a quoted string is open. Anywhere else it is a stray line, which the lenient
# parse glues to the value before it: an ifAlias that a revert would write back, a bridge port that is no number any more. And a
# string has to end with its closing quote, before the next row and before the end of the output.
PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"         # dot1qPvid: a number
STRAY_AFTER_NUMBER = f".{PVID}.1 99\n.{PVID}.2 1\nEnd of MIB\n".encode()
STRAY_AFTER_STRING = f'.{IF_ALIAS}.1 "Platz 107"\nEnd of MIB\n'.encode()


@pytest.mark.parametrize("out, oid, last", [(STRAY_AFTER_NUMBER, PVID, f"{PVID}.2"), (STRAY_AFTER_STRING, IF_ALIAS, f"{IF_ALIAS}.1")],
                         ids=["after-a-number", "after-a-closed-string"])
async def test_strict_text_walk_refuses_a_stray_line(process, out, oid, last):
    process.answer(out=out)
    with pytest.raises(snmp.SnmpError, match=rf"^Unerwartete Zeile hinter dem Wert von {re.escape(last)}: 'End of MIB'$"):
        await snmp.walk(HOST, CRED, oid, strict=True)


async def test_lenient_text_walk_keeps_the_old_behaviour(process):
    """The display poller (lenient) still gets the stray line glued to the value before it, exactly as before; and what the strict
    walk refuses about strings (one without end, text behind the closing quote) still comes through, no error. One thing changed on
    purpose (Phase 2, the row injection): a string that is still open keeps the lines behind it, even those that start with "."
    and would otherwise form new rows, up to its closing quote; text behind that quote ends the string there."""
    process.answer(out=STRAY_AFTER_NUMBER)
    assert await snmp.walk(HOST, CRED, PVID) == [(f"{PVID}.1", "99"), (f"{PVID}.2", "1\nEnd of MIB")]
    process.answer(out=STRAY_AFTER_STRING)
    assert await snmp.walk(HOST, CRED, IF_ALIAS) == [(f"{IF_ALIAS}.1", '"Platz 107"\nEnd of MIB')]
    process.answer(out=f'.{IF_ALIAS}.1 "Raum\n.{IF_ALIAS}.2 "AP" 7\n.{IF_ALIAS}.3 "x\n'.encode())
    assert await snmp.walk(HOST, CRED, IF_ALIAS) == [(f"{IF_ALIAS}.1", f'"Raum\n.{IF_ALIAS}.2 "AP" 7'), (f"{IF_ALIAS}.3", '"x')]


async def test_strict_text_walk_takes_a_string_over_several_lines(process):
    """An escaped quote (\\") does not close a string, a quote alone on its line does. The rows are exactly the lenient ones (the
    escapes stay in the value, as they always did)."""
    process.answer(out=f'.{IF_ALIAS}.1 "Raum \\"2.14\\"\nTuer links\n"\n.{IF_ALIAS}.2 "AP"\n.{IF_ALIAS}.3 ""\n'.encode())
    rows = await snmp.walk(HOST, CRED, IF_ALIAS, strict=True)
    assert rows == [(f"{IF_ALIAS}.1", 'Raum \\"2.14\\"\nTuer links\n'), (f"{IF_ALIAS}.2", "AP"), (f"{IF_ALIAS}.3", "")]
    assert rows == await snmp.walk(HOST, CRED, IF_ALIAS)


@pytest.mark.parametrize("out", [
    f'.{IF_ALIAS}.1 "Platz 107\n',                          # the output ends inside the string
    f'.{IF_ALIAS}.1 "Platz 107\n.{IF_ALIAS}.2 "AP"\n',      # the next row starts inside it
    f'.{IF_ALIAS}.1 "Raum \\"2.14\\"\n',                    # an escaped quote does not end it
], ids=["end-of-output", "next-row", "escaped-quote"])
async def test_strict_text_walk_refuses_a_string_without_end(process, out):
    process.answer(out=out.encode())
    with pytest.raises(snmp.SnmpError, match=rf"^String ohne Ende in {IF_ALIAS}\.1: "):
        await snmp.walk(HOST, CRED, IF_ALIAS, strict=True)


@pytest.mark.parametrize("out", [f'.{IF_ALIAS}.1 "Raum" 2.14\n', f'.{IF_ALIAS}.1 "Raum\n2" 14\n'], ids=["first-line", "continuation"])
async def test_strict_text_walk_refuses_text_after_the_closing_quote(process, out):
    process.answer(out=out.encode())
    with pytest.raises(snmp.SnmpError, match=rf"^Text hinter dem Ende des Strings in {IF_ALIAS}\.1: "):
        await snmp.walk(HOST, CRED, IF_ALIAS, strict=True)


@pytest.mark.parametrize("strict", [False, True])
async def test_blank_lines_and_text_before_the_first_row_belong_to_no_value(process, strict):
    """In both modes an empty line is skipped (inside a string too, as always), and so is anything before the first OID."""
    process.answer(out=f'banner\n\n.{PVID}.1 99\n\n.{IF_ALIAS}.2 "a\n\nb"\n\n'.encode())
    assert await snmp.walk(HOST, CRED, PVID, strict=strict) == [(f"{PVID}.1", "99"), (f"{IF_ALIAS}.2", "a\nb")]


def _printed(rng: random.Random) -> str:
    """A random printable string the way net-snmp prints it: in quotes, \\ and \" escaped, line breaks kept as they are. No line after
    the first starts with "." (for every parser that is the start of the next row)."""
    while True:
        s = "".join(rng.choice('ab 9.:-"\\\n') for _ in range(rng.randint(0, 12)))
        if not any(line.startswith(".") for line in s.split("\n")[1:]):
            return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _walk_rows(rng: random.Random) -> list[str]:
    """Rows of a walk as snmpbulkwalk -On -Oq prints them: numbers bare, strings in quotes (perhaps over several lines), now and then
    a missing value."""
    rows = []
    for i in range(rng.randint(0, 6)):
        roll = rng.random()
        value = str(rng.randint(0, 5000)) if roll < 0.4 else "No Such Instance currently exists at this OID" if roll < 0.5 else _printed(rng)
        rows.append(f".{IF_ALIAS}.{i + 1} {value}")
    return rows


def test_strict_text_parse_is_the_lenient_parse_or_an_error():
    """On 3000 random walk outputs: well formed, the strict text parse gives exactly the lenient rows; with a stray line behind any
    complete row it raises; on random noise (lines of OIDs, quotes, backslashes, dots, words) it gives the lenient rows or raises,
    never anything else."""
    rng = random.Random(15)
    outcomes = {"same": 0, "refused": 0}
    for case in range(3000):
        rows = _walk_rows(rng)
        text = "\n".join(rows) + rng.choice(("", "\n"))
        assert snmp._parse(text, text_strict=True) == snmp._parse(text), case
        if rows:
            k = rng.randrange(len(rows))
            broken = "\n".join([*rows[:k + 1], rng.choice(("End of MIB", "x", "42", '"', 'Raum"')), *rows[k + 1:]])
            with pytest.raises(snmp.SnmpError):
                snmp._parse(broken, text_strict=True)
        tokens = (f".{IF_ALIAS}.1 ", ".", '"', "\\", "x", " ", "7")
        noise = "\n".join("".join(rng.choice(tokens) for _ in range(rng.randint(0, 5))) for _ in range(rng.randint(0, 6)))
        lenient = snmp._parse(noise)    # the lenient parse never refuses anything
        try:
            strict = snmp._parse(noise, text_strict=True)
        except snmp.SnmpError:
            outcomes["refused"] += 1
            continue
        assert strict == lenient, case
        outcomes["same"] += 1
    assert min(outcomes.values()) > 300, outcomes    # the noise really exercises both outcomes


async def test_strict_does_not_change_the_command(process):
    """strict is decided in Python after the process ended; snmpbulkwalk is started with the very same argv in both modes."""
    await snmp.walk(HOST, CRED, IF_NAME, hex_values=True)
    await snmp.walk(HOST, CRED, IF_NAME, hex_values=True, strict=True)
    assert len(process.started) == 2
    assert process.started[0] == process.started[1] == (
        "snmpbulkwalk", "-v2c", "-c", "ro-s3cret", "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", "-Cr25", "-Ox", HOST, IF_NAME)
