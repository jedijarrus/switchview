"""Tests for the strict mode of snmp.walk: a walk that ends with an error after it has already printed rows.

snmpbulkwalk prints every varbind as it arrives. If the agent stops answering in the middle of a table (timeout, error packet),
snmpbulkwalk reports that on stderr and exits non-zero, but the rows it got so far are already on stdout. snmp._run only raises
when stdout is empty, so by default (what the display poller relies on) such a partial walk still counts as a result, exactly as
before. strict=True, which the SNMP write path uses (snmpwrite.read_cfg), turns EVERY non-zero exit into an SnmpError, so a write is
never planned or verified against half a table.

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


async def test_strict_does_not_change_the_command(process):
    """strict is decided in Python after the process ended; snmpbulkwalk is started with the very same argv in both modes."""
    await snmp.walk(HOST, CRED, IF_NAME, hex_values=True)
    await snmp.walk(HOST, CRED, IF_NAME, hex_values=True, strict=True)
    assert len(process.started) == 2
    assert process.started[0] == process.started[1] == (
        "snmpbulkwalk", "-v2c", "-c", "ro-s3cret", "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", "-Cr25", "-Ox", HOST, IF_NAME)
