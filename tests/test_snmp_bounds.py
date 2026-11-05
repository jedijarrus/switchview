"""Bounded SNMP output and a robust parse (Phase 2, Task 4): what a hostile or broken SNMP agent can make snmp._run, snmp._parse,
poller._build and snmpwrite.build_cfg do.

  * _run reads stdout and stderr together, in chunks, up to EOF and under the one timeout. Over snmp.MAX_STDOUT it kills the process
    (SnmpError "zu groß"); of stderr it keeps the first snmp.MAX_STDERR bytes but reads it to its end, so a chatty process never
    blocks on a full pipe.
  * _parse refuses more than snmp.MAX_ROWS values (rows with an OID; continuation lines do not count). The lenient parse (the display
    poller) keeps a line that starts with "." inside a quoted string that is still open, so a value can no longer inject a row (the
    audit's forged LLDP neighbour). Every mode parses in time linear in the output, and the strict modes give exactly the rows and
    errors of before (the oracle: the parse of before, copied verbatim below).
  * A PortList longer than snmp.MAX_PORTLIST_BYTES (8192 bytes, bridge ports up to 65535) is refused on every path, VLAN membership is
    a bit test on the PortList bytes (no set per VLAN), and poll_switch builds its result in a worker thread, off the event loop.
  * A big legitimate switch (32 768 MACs, 4094 VLANs, 128-byte PortLists) stays well within all of it.

Nothing here starts a process or touches the network: create_subprocess_exec hands out a switchfix.FakeProcess (spawn), and the poll
runs against a database under tmp_path with snmp.walk answered from switchfix.RECORDING (sid).
"""
import asyncio
import random
import time

import pytest

import config
import db
import poller
import snmp
import snmpwrite
from switchfix import HOST, IF_ALIAS, IF_NAME, RECORDING, VLAN_EGRESS, W_SAMPLE, FakeProcess, edit_walks, walk_answer

CRED = {"snmp_version": "2c", "snmp_community": "ro-s3cret"}
W0 = {k: W_SAMPLE.get(k, []) for k in poller.O}    # every walk of the display poller, the ones W_SAMPLE has not empty


class _Spawn:
    """The faked create_subprocess_exec: every start is recorded in `started` (its argv) and gets the process answer() set last, or,
    without one, a process that prints nothing and exits 0."""

    def __init__(self):
        self.started: list[tuple] = []
        self._next = FakeProcess()

    def answer(self, proc: FakeProcess) -> FakeProcess:
        self._next = proc
        return proc

    async def exec(self, *argv, **kwargs) -> FakeProcess:
        self.started.append(argv)
        proc, self._next = self._next, FakeProcess()
        return proc


@pytest.fixture
def spawn(monkeypatch) -> _Spawn:
    """The real snmp.walk / _run / _parse; only the process they would start is faked (see _Spawn)."""
    spawner = _Spawn()
    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", spawner.exec)
    return spawner


@pytest.fixture
async def sid(tmp_path, monkeypatch) -> int:
    """A fresh database under tmp_path (the app's own init_db) with one ProCurve at HOST, v2c without a community; snmp.walk answers
    from RECORDING (the sample switch W_SAMPLE); fresh poll locks. Returns the switch id."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    await db.init_db()
    async with db.db() as conn:
        cur = await conn.execute("INSERT INTO switches(name, host, driver, snmp_version) VALUES (?, ?, 'procurve', '2c')", ("SW-EK-01", HOST))
        await conn.commit()
        switch_id = cur.lastrowid

    async def walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        return walk_answer(RECORDING.get(oid, []), oid, hex_values)

    monkeypatch.setattr(snmp, "walk", walk)
    monkeypatch.setattr(poller, "_locks", {})
    return switch_id


# ── The tests of the plan ────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_an_agent_flooding_stdout_is_cut_off(spawn):                    # NV, the input: endless output
    proc = spawn.answer(FakeProcess(endless=True))
    with pytest.raises(snmp.SnmpError, match="zu groß"):
        await snmp.walk(HOST, CRED, IF_NAME)
    assert proc.killed and proc.bytes_served <= snmp.MAX_STDOUT + 65536


def test_a_portlist_beyond_65535_ports_is_refused():                          # NV, the input: a huge PortList
    with pytest.raises(ValueError):
        snmp.bitmap_ports("FF " * 8193)
    with pytest.raises(snmp.SnmpError):
        snmpwrite.build_cfg(edit_walks(W_SAMPLE, vlanEgress={"1": "FF " * 8193}))


def test_too_many_rows_are_refused():
    with pytest.raises(snmp.SnmpError, match="100000 Zeilen"):
        snmp._parse("".join(f'.1.3.6.1.2.1.31.1.1.1.1.{i} "p{i}"\n' for i in range(100_001)))


def test_an_injected_lldp_row_stays_inside_its_value():                       # NV, the audit's input, as net-snmp prints it
    text = '.1.0.8802.1.1.2.1.4.1.1.9.0.5.1 "evilhost\n.1.0.8802.1.1.2.1.4.1.1.9.0.3.1 FORGED-NEIGHBOR-ON-PORT-3"\n'
    rows = snmp._parse(text)
    assert rows == [("1.0.8802.1.1.2.1.4.1.1.9.0.5.1", "evilhost\n.1.0.8802.1.1.2.1.4.1.1.9.0.3.1 FORGED-NEIGHBOR-ON-PORT-3")]
    lldp = {p["name"]: p["lldp"] for p in poller._build(W0 | {"lldpSys": rows}, "procurve")["ports"]}
    assert lldp["3"] == [] and lldp["5"][0][0].startswith("evilhost")       # ProCurve: port name = ifIndex in W_SAMPLE


def test_a_big_legitimate_switch_fits():                                      # Review Focus 5
    fdb = "".join(f".1.3.6.1.2.1.17.7.1.2.2.1.2.1.0.26.43.{i >> 16}.{(i >> 8) & 255}.{i & 255} 1\n" for i in range(32_768))
    names = "".join(f'.1.3.6.1.2.1.17.7.1.4.3.1.1.{v} "V{v}"\n' for v in range(1, 4095))
    egress = "".join(f".1.3.6.1.2.1.17.7.1.4.3.1.2.{v} {' '.join(['FF'] * 128)}\n" for v in range(1, 4095))
    assert max(len(fdb), len(egress)) < snmp.MAX_STDOUT
    data = poller._build(W0 | {"fdb": snmp._parse(fdb), "vlanName": snmp._parse(names),
                               "vlanEgress": snmp._parse(egress, hex_strict=True)}, "procurve")
    assert len(data["vlans"]) == 4094 and max(p["mac_count"] for p in data["ports"]) == 32_768


async def test_build_runs_off_the_event_loop(sid, monkeypatch):              # sid: a ProCurve with W_SAMPLE behind a fake snmp.walk
    seen = []

    async def to_thread(fn, *args):
        seen.append(fn)
        return fn(*args)

    monkeypatch.setattr(poller.asyncio, "to_thread", to_thread)
    assert (await poller.poll_switch(sid))["ok"] is True
    assert poller._build in seen


# ── Beyond the plan: rules of the task that no test above would catch ───────────────────────────────────────────────────────────
def _stderr_first(proc: FakeProcess) -> FakeProcess:
    """proc as a process that writes all of its stderr before its first stdout byte and, blocked on the full pipe, writes stdout and
    exits only once stderr has been read to its end."""
    drained = asyncio.Event()
    read_out, read_err, wait = proc.stdout.read, proc.stderr.read, proc.wait

    async def stderr_read(n):
        chunk = await read_err(n)
        if not chunk:
            drained.set()
        return chunk

    async def stdout_read(n):
        await drained.wait()
        return await read_out(n)

    async def exit_code():
        await drained.wait()
        return await wait()

    proc.stdout.read, proc.stderr.read, proc.wait = stdout_read, stderr_read, exit_code
    return proc


async def test_stderr_is_read_alongside_stdout_and_to_its_end(spawn):
    """A process that fills its stderr pipe first (here with more than MAX_STDERR bytes of warnings) goes on only once stderr has been
    read to its end. Reading stdout to EOF before stderr, or no further than MAX_STDERR, would wait for the timeout instead."""
    warnings = b"snmpbulkwalk: warning\n" * (snmp.MAX_STDERR // 10)
    spawn.answer(_stderr_first(FakeProcess(out=f'.{IF_NAME}.1 "1"\n'.encode(), err=warnings)))
    assert await snmp.walk(HOST, CRED, IF_NAME, timeout=2) == [(f"{IF_NAME}.1", "1")]


async def test_only_the_start_of_stderr_is_kept(spawn):
    """The error message comes from the first MAX_STDERR bytes of stderr; whatever the process prints behind them is read and dropped."""
    err = f"Timeout: No Response from {HOST}\n".encode() + b" " * snmp.MAX_STDERR + b"\nsnmpbulkwalk: beyond the cap\n"
    spawn.answer(FakeProcess(err=err, returncode=1))
    with pytest.raises(snmp.SnmpError, match=f"^Timeout: No Response from {HOST}$"):
        await snmp.walk(HOST, CRED, IF_NAME)


def test_text_behind_a_closing_quote_ends_the_string():
    """Lenient: a string ends at its closing quote even when text follows it, on its first line as on a continuation line, and the next
    line with an OID is a row again (the strict text walk refuses both values)."""
    text = f'.{IF_ALIAS}.1 "AP" 7\n.{IF_ALIAS}.2 "Raum\n2" 14\n.{IF_ALIAS}.3 "x"\n'
    assert snmp._parse(text) == [(f"{IF_ALIAS}.1", '"AP" 7'), (f"{IF_ALIAS}.2", '"Raum\n2" 14'), (f"{IF_ALIAS}.3", "x")]


@pytest.mark.parametrize("strict", [False, True], ids=["lenient", "strict"])
def test_continuation_lines_are_no_rows(strict):
    """Exactly MAX_ROWS values parse, whatever their continuation lines: every value here is a string over two lines, and in the
    lenient parse its second line starts with "." (a line inside an open string, not a row)."""
    tail = ".more" if not strict else "more"
    text = "".join(f'.{IF_ALIAS}.{i} "p{i}\n{tail}"\n' for i in range(snmp.MAX_ROWS))
    rows = snmp._parse(text, text_strict=strict)
    assert len(rows) == snmp.MAX_ROWS
    assert rows[-1] == (f"{IF_ALIAS}.{snmp.MAX_ROWS - 1}", f"p{snmp.MAX_ROWS - 1}\n{tail}")


def test_the_portlist_cap_holds_on_the_display_path_too():
    """8192 bytes (bridge ports up to 65535, the last bit spare) still count, one byte more is refused, by the display poller too."""
    assert snmp.portlist_bytes("FF " * 8192) == b"\xff" * 8192
    with pytest.raises(ValueError):
        snmp.portlist_bytes("FF " * 8193)
    with pytest.raises(ValueError):
        poller._build(W0 | {"vlanEgress": [(f"{VLAN_EGRESS}.1", "FF " * 8193)]}, "procurve")


def test_a_value_over_many_lines_parses_in_linear_time():
    """One quoted value over 400 000 lines (800 kB, a tenth of what MAX_STDOUT lets through), lenient and strict: each parse stays far
    below the bound, with the value intact. A parse that joins or scans the value again for every line it adds takes minutes here
    (the strict parse of before: hours), on the event loop."""
    text = f'.{IF_ALIAS}.1 "a\n' + "x\n" * 400_000 + '"\n'
    want = [(f"{IF_ALIAS}.1", "a\n" + "x\n" * 400_000)]
    for strict in (False, True):
        start = time.process_time()
        assert snmp._parse(text, text_strict=strict) == want
        assert time.process_time() - start < 3, strict


# The parse before this task (snmp._string_open and snmp._parse at 7902149), copied verbatim: the oracle for the strict modes.
def _string_open_before(oid: str, val: str) -> bool:
    if not val.startswith('"'):
        return False
    i = 1
    while i < len(val):
        if val[i] == "\\":
            i += 2
        elif val[i] == '"':
            if i != len(val) - 1:
                raise snmp.SnmpError(f"Text hinter dem Ende des Strings in {oid}: {val[:80]!r}")
            return False
        else:
            i += 1
    return True


def _parse_before(text: str, hex_strict: bool = False, text_strict: bool = False) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    open_string = False
    for line in text.splitlines():
        if line.startswith("."):
            if open_string:
                raise snmp.SnmpError(f"String ohne Ende in {rows[-1][0]}: {rows[-1][1][:80]!r}")
            oid, _, val = line.partition(" ")
            rows.append((oid.lstrip("."), val.strip()))
            open_string = text_strict and _string_open_before(*rows[-1])
        elif rows and line.strip():
            if text_strict and not open_string:
                raise snmp.SnmpError(f"Unerwartete Zeile hinter dem Wert von {rows[-1][0]}: {line[:80]!r}")
            oid, val = rows[-1]
            rows[-1] = (oid, val + "\n" + line)
            open_string = text_strict and _string_open_before(*rows[-1])
    if open_string:
        raise snmp.SnmpError(f"String ohne Ende in {rows[-1][0]}: {rows[-1][1][:80]!r}")
    out = []
    for oid, val in rows:
        if "No Such Object" in val or "No Such Instance" in val or "No more variables" in val:
            continue
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        if hex_strict and not snmp._HEX_VALUE.fullmatch(val):
            raise snmp.SnmpError(f"Unerwartete Ausgabe in einem Hex-Wert ({oid}): {val[:80]!r}")
        out.append((oid, val))
    return out


def _outcome(parse, text: str, **mode) -> tuple[str, object]:
    try:
        return "rows", parse(text, **mode)
    except snmp.SnmpError as e:
        return "error", str(e)


def test_the_strict_modes_parse_exactly_as_before():
    """On 4000 random outputs (lines of OIDs, quotes, backslashes, dots, words, hex pairs, markers, blank lines, a backslash at the end
    of a line) both strict modes give the rows, or the error with its very message, of the parse before; so does the lenient parse of
    an output without a quote (numbers, hex, OIDs: no string that could stay open)."""
    rng = random.Random(4)
    tokens = (f".{IF_ALIAS}.1 ", f".{IF_ALIAS}.2 ", ".", '"', '"', "\\", "x", " ", "7", "80 ", "FF", "End of MIB", "No Such Instance")
    seen = {"rows": 0, "error": 0}
    for case in range(4000):
        text = "\n".join("".join(rng.choice(tokens) for _ in range(rng.randint(0, 6))) for _ in range(rng.randint(0, 8)))
        for mode in ({"text_strict": True}, {"hex_strict": True}):
            got = _outcome(snmp._parse, text, **mode)
            assert got == _outcome(_parse_before, text, **mode), (case, mode, text)
            seen[got[0]] += 1
        if '"' not in text:
            assert snmp._parse(text) == _parse_before(text), (case, text)
    assert min(seen.values()) > 1000, seen    # the noise exercises both outcomes
