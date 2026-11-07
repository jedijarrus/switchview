"""Phase 3 Task 10: the SNMP reads hold up against a cancel, a big or hostile agent and a walk that fails.

  * snmp._exec kills its net-snmp process on every exception while it waits other than the timeout, a cancel above all (a closed
    request or a stopping container left the walk running), and raises it on.
  * snmp.walk and snmp.get parse in a worker thread (asyncio.to_thread), off the event loop.
  * One byte budget per query: poll_switch and read_cfg run the walks of their gather under snmp.byte_budget(snmp.MAX_POLL_BYTES), a
    ContextVar the walks inherit; _collect takes every stdout chunk from it and cuts a walk off once it is spent, as over MAX_STDOUT.
  * The display poller walks ifAlias and vlanName with -Ox like the write path (TEXT_AS_HEX) and decodes real hex pairs
    (poller._display_text, snmp.octets_text): umlauts show as text.
  * Numbers the poller cannot use never stop it (_build), VLAN rows without a VLAN ID 1-4094 are skipped and counted, more than
    poller.MAX_PORTS ports are refused (_build and snmpwrite._synth).
  * A failed FDB or LLDP walk keeps the MACs and LLDP neighbours of the last poll (both carry the uplink protection), and what the
    poll read of the same table joins them, so a link only the fresh rows show stays protected; bp2if counts for both (for LLDP at a
    driver by ifType), and a failed baseMac walk keeps the stored base MAC. A lenient walk that broke off after some rows
    (snmp.Rows.broken_off) counts as failed there. The poll says "Teilweise gelesen", and "behalten" only where the last poll had
    something to keep; a walk the driver does not use (ifType at a ProCurve) says nothing. A fresh neighbour a kept one at the same
    port covers (same sysName, every field equal except one the failed walk left missing) is left out, so it is not listed twice
    (poller.merge_lldp, Phase 5 Task 10).

No network, no net-snmp: the process is a switchfix.FakeProcess (spawn), the switches are the test network of tests/netfix.py (the
`net` fixture of tests/conftest.py), the database a fresh one under tmp_path.
"""
import asyncio
import threading

import pytest

import changes
import main
import poller
import snmp
import snmpwrite
from dbfix import query
from drivers import DRIVERS
from netfix import add, fdb, lldp
from switchfix import (BASES, CATALYST_VMVLAN, FREE_TEXT, HOST, IF_NAME, RECORDING, ROW, W_CATALYST, W_SAMPLE, WALK_BASES, FakeProcess,
                       edit_walks, hex_text, walk_answer)

CRED = {"snmp_version": "2c", "snmp_community": "ro-s3cret"}
TIMEOUT = "Zeitüberschreitung bei der SNMP-Abfrage"
A_HOST, B_HOST, C_HOST = "10.0.0.1", "10.0.0.2", "10.0.0.3"
MAC_A, MAC_B, MAC1 = "00:1a:2b:00:00:0a", "00:1a:2b:00:00:0b", "aa:bb:cc:00:00:01"    # base MACs as in tests/test_uplink_rules.py
FREE_TEXT_OIDS = {BASES[k] for k in FREE_TEXT}
RECORDED = {WALK_BASES[k]: rows for k, rows in W_SAMPLE.items()}
# The Catalyst of switchfix with its vmVlan rows and Gi1/0/2 up, as in tests/test_uplinks.py: the cisco driver selects by ifType and
# walks lldpLocPortTable (poller.LLDP_LOC)
CATALYST = edit_walks({**W_CATALYST, "vmVlan": CATALYST_VMVLAN}, ifAdmin={"10102": "1"})


class _Spawn:
    """The faked create_subprocess_exec, as in tests/test_snmp_bounds.py: every start is recorded in `started` (its argv) and gets the
    next process answer() queued, or, without one, a process that prints nothing and exits 0."""

    def __init__(self):
        self.started: list[tuple] = []
        self._queue: list[FakeProcess] = []

    def answer(self, proc: FakeProcess) -> FakeProcess:
        self._queue.append(proc)
        return proc

    async def exec(self, *argv, **kwargs) -> FakeProcess:
        self.started.append(argv)
        return self._queue.pop(0) if self._queue else FakeProcess()


@pytest.fixture
def spawn(monkeypatch) -> _Spawn:
    """The real snmp.walk / get / _run / _parse; only the process they would start is faked (see _Spawn)."""
    spawner = _Spawn()
    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", spawner.exec)
    return spawner


@pytest.fixture
def net_hexing(net, monkeypatch):
    """The network of `net` behind a walk that answers free text like net-snmp: walked without hex_values, an ifAlias or vlanName
    comes as it is when it is ASCII and as bare hex otherwise (without MIBs net-snmp prints an OCTET STRING with a byte it does not
    count as printable, such as each byte of an umlaut in UTF-8, as hex); walked with hex_values, and every other walk, as
    switchfix.walk_answer (the free text as hex, as with -Ox)."""
    async def walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        net.walked[host].append(oid)
        rows = net.rec[host].get(oid, [])
        if oid in FREE_TEXT_OIDS and not hex_values:
            return [(row_oid, value if value.isascii() else hex_text(value)) for row_oid, value in rows]
        return walk_answer(rows, oid, hex_values)

    monkeypatch.setattr(snmp, "walk", walk)
    return net


@pytest.fixture
def failing(monkeypatch):
    """failing(net, host, oid, error=TIMEOUT, rows=None): from now on the walk of oid at host raises SnmpError(error), or, with rows,
    returns them as a lenient snmp.walk returns a walk that broke off after them (snmp.Rows with broken_off=error: snmpbulkwalk ended
    with an exit code != 0 after it had printed these rows); every other walk goes to net.walk as before. Each call adds one more."""
    broken: dict[tuple[str, str], tuple[str, list | None]] = {}

    def fail(net, host: str, oid: str, error: str = TIMEOUT, rows: list | None = None) -> None:
        async def walk(h, cred, o, hex_values=False, timeout=60, strict=False):
            if (h, o) in broken:
                message, partial = broken[(h, o)]
                if partial is None:
                    raise snmp.SnmpError(message)
                return snmp.Rows(walk_answer(partial, o, hex_values), broken_off=message)
            return await net.walk(h, cred, o, hex_values=hex_values, timeout=timeout, strict=strict)

        if not broken:
            monkeypatch.setattr(snmp, "walk", walk)
        broken[(host, oid)] = (error, rows)

    return fail


def walks(edit: dict | None = None) -> dict:
    """The walks of W_SAMPLE by OID as poll_switch hands them to _build (every key of poller.O and LLDP_LOC, the ones W_SAMPLE has
    not empty), as in tests/test_uplinks.py::test_procurve_attribution_stays_by_ifindex; each row of edit (walk key -> {index:
    value}) set, or appended where the walk has no row of that index."""
    W = {k: list(RECORDED.get(base, [])) for k, base in poller.O.items()} | {k: [] for k in poller.LLDP_LOC}
    for key, rows in (edit or {}).items():
        merged = dict(W[key])
        merged.update({f"{poller.O[key]}.{index}": value for index, value in rows.items()})
        W[key] = list(merged.items())
    return W


def walks_with_ports(n: int) -> dict:
    """n Ethernet interfaces (ifType 6) with ifIndex 1..n, named p1..pn and up; every other walk empty."""
    W = {k: [] for k in poller.O} | {k: [] for k in poller.LLDP_LOC}
    for key, value in (("ifName", "p{}"), ("ifType", "6"), ("ifAdmin", "1")):
        W[key] = [(f"{poller.O[key]}.{i}", value.format(i)) for i in range(1, n + 1)]
    return W


async def mac_linked_pair(net) -> tuple[int, int]:
    """Two ProCurves with W_SAMPLE, linked A:2 <-> B:3 by base MACs only (A learns B's on bridge port 1 = port 2, B learns A's on
    bridge port 2 = port 3), no LLDP; both polled once. Port 2 is A's uplink."""
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE, fdb("1", MAC_B), base_mac=MAC_A)
    b = await add(net, "B", B_HOST, "procurve", W_SAMPLE, fdb("2", MAC_A), base_mac=MAC_B)
    assert "2" in (await changes.inventory(a))["uplinks"]
    return a, b


def last_error(sid: int) -> str | None:
    return query("SELECT last_error FROM switches WHERE id = ?", (sid,))[0][0]


def port(m: dict, n: str, k: str = "A") -> dict:
    """Port n of the switch named k in a netmap."""
    return next(p for s in m["switches"] if s["k"] == k for p in s["ports"] if p["n"] == n)


# ── The tests of the plan ────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_cancelled_walk_kills_its_process(spawn):
    proc = spawn.answer(FakeProcess(hang=True))
    task = asyncio.create_task(snmp.walk(HOST, CRED, IF_NAME))
    while not spawn.started:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert proc.killed


async def test_parsing_runs_off_the_event_loop(spawn, monkeypatch):
    seen, real = [], snmp._parse
    monkeypatch.setattr(snmp, "_parse", lambda *a, **k: seen.append(threading.get_ident()) or real(*a, **k))
    spawn.answer(FakeProcess(out=b'.1.3.6.1.2.1.31.1.1.1.1.1 "1"\n'))
    await snmp.walk(HOST, CRED, IF_NAME)
    assert seen and seen[0] != threading.get_ident()


async def test_the_walks_of_one_query_share_a_byte_budget(spawn):
    with snmp.byte_budget(100):
        spawn.answer(FakeProcess(out=b".1.3.6.1.2.1.31.1.1.1.1.1 " + b'"x"' * 30 + b"\n"))
        with pytest.raises(snmp.SnmpError, match="zusammen"):
            await snmp.walk(HOST, CRED, IF_NAME)


async def test_umlauts_show_in_the_port_list(net_hexing):                         # ifAlias "Büro", vlanName "Küche"
    await add(net_hexing, "A", A_HOST, "procurve", edit_walks(W_SAMPLE, ifAlias={"1": "Büro"}, vlanName={"20": "Küche"}))
    m = await main.build_map()
    assert port(m, "1")["a"] == "Büro" and m["vlans"]["20"] == "Küche"


@pytest.mark.parametrize("edit", [{"vlanName": {"1.2": "x"}}, {"ifHighSpeed": {"1": "fast"}}, {"sysUpTime": {"0": "²"}}, {"bp2if": {"3.0": "1"}},
                                  {"fdb": {"1.0.17.42.x.0.1": "1"}}])
def test_numbers_the_poller_cannot_use_never_stop_it(edit):                       # before: ValueError
    assert poller._build(walks(edit), "procurve")["ports"]


def test_vlan_rows_outside_1_to_4094_are_skipped():
    assert set(poller._build(walks({"vlanName": {"5000": "x", "0": "y"}}), "procurve")["vlans"]) == {"1", "20", "30", "99"}


def test_more_than_max_ports_is_refused():                                        # 4097 interfaces of ifType 6
    pytest.raises(snmp.SnmpError, poller._build, walks_with_ports(4097), "generic")


async def test_a_failed_fdb_walk_keeps_the_mac_uplink_protected(net, failing):   # Review Focus 5
    a, b = await mac_linked_pair(net)                                             # A:2 <-> B:3 by base MACs only (fdb, base_mac)
    failing(net, A_HOST, poller.O["fdb"])                                         # a wrapper around net.walk: SnmpError(TIMEOUT)
    assert (await poller.poll_switch(a))["ok"] is True
    assert "2" in (await changes.inventory(a))["uplinks"]
    assert last_error(a) == "Teilweise gelesen: fdb fehlgeschlagen (Zeitüberschreitung bei der SNMP-Abfrage); MAC-Tabelle vom letzten Poll behalten"


async def test_a_failed_lldp_walk_keeps_the_last_neighbours(net, failing):       # first with LLDP on port 6, then lldpSys fails
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE, lldp("6", "B", "6", "6"))
    await add(net, "B", B_HOST, "procurve", W_SAMPLE, lldp("6", "A", "6", "6"))
    failing(net, A_HOST, poller.O["lldpSys"])
    assert (await poller.poll_switch(a))["ok"] is True
    assert port(await main.build_map(), "6")["l"] == [["B", "6", "6"]] and last_error(a).endswith("; LLDP vom letzten Poll behalten")


async def test_a_procurve_ignores_its_unused_iftype_walk(net, failing):          # ifType fails at a ProCurve
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE)
    failing(net, A_HOST, poller.O["ifType"])
    assert (await poller.poll_switch(a))["ok"] is True and last_error(a) is None


# ── Beyond the plan: the rest of each rule ───────────────────────────────────────────────────────────────────────────────────────
async def test_a_cancelled_get_kills_its_process_too(spawn):
    """snmp.get goes through the same _exec: a cancel kills its snmpget as well."""
    proc = spawn.answer(FakeProcess(hang=True))
    task = asyncio.create_task(snmp.get(HOST, CRED, [f"{IF_NAME}.1"]))
    while not spawn.started:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert proc.killed


async def test_a_timeout_still_kills_and_says_so(spawn):
    """The timeout keeps its own message (and its kill)."""
    proc = spawn.answer(FakeProcess(hang=True))
    with pytest.raises(snmp.SnmpError, match=f"^{TIMEOUT}$"):
        await snmp.walk(HOST, CRED, IF_NAME, timeout=0.05)
    assert proc.killed


async def test_get_parses_off_the_event_loop(spawn, monkeypatch):
    seen, real = [], snmp._parse
    monkeypatch.setattr(snmp, "_parse", lambda *a, **k: seen.append(threading.get_ident()) or real(*a, **k))
    spawn.answer(FakeProcess(out=f'.{IF_NAME}.1 "1"\n'.encode()))
    assert await snmp.get(HOST, CRED, [f"{IF_NAME}.1"]) == {f"{IF_NAME}.1": "1"}
    assert seen and seen[0] != threading.get_ident()


async def test_two_walks_together_over_the_budget(spawn):
    """Each walk alone stays under the budget, together they are over it: one of them is cut off with the "zusammen" message, its
    process killed, the other keeps its rows. Without a budget both go through."""
    row = f'.{IF_NAME}.1 "{"x" * 60}"\n'.encode()    # 88 bytes
    want = [(f"{IF_NAME}.1", "x" * 60)]
    procs = [spawn.answer(FakeProcess(out=row)), spawn.answer(FakeProcess(out=row))]
    with snmp.byte_budget(150):
        results = await asyncio.gather(snmp.walk(HOST, CRED, IF_NAME), snmp.walk(HOST, CRED, IF_NAME), return_exceptions=True)
    errors = [r for r in results if isinstance(r, snmp.SnmpError)]
    assert [r for r in results if r == want] and len(errors) == 1
    assert str(errors[0]) == f"SNMP-Abfrage zu groß (über {snmp.MAX_POLL_BYTES // (1024 * 1024)} MiB zusammen), abgebrochen"
    assert [p.killed for p in procs].count(True) == 1
    spawn.answer(FakeProcess(out=row))
    spawn.answer(FakeProcess(out=row))
    assert await asyncio.gather(snmp.walk(HOST, CRED, IF_NAME), snmp.walk(HOST, CRED, IF_NAME)) == [want, want]


def test_a_budget_is_spent_once_and_for_good():
    budget = snmp.ByteBudget(10)
    assert budget.take(4) is True and budget.take(6) is True and budget.take(1) is False and budget.take(0) is False
    assert snmp._BUDGET.get() is None
    with snmp.byte_budget(5):
        inner = snmp._BUDGET.get()
        assert isinstance(inner, snmp.ByteBudget) and inner.take(5) is True and inner.take(1) is False
    assert snmp._BUDGET.get() is None


async def test_the_walks_of_a_poll_share_one_budget(net, monkeypatch):
    """poll_switch runs every walk of its gather under one budget of MAX_POLL_BYTES, set only for the poll."""
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE)
    seen = []

    async def walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        seen.append(snmp._BUDGET.get())
        return await net.walk(host, cred, oid, hex_values=hex_values, timeout=timeout, strict=strict)

    monkeypatch.setattr(snmp, "walk", walk)
    assert (await poller.poll_switch(a))["ok"] is True
    budget = seen[0]
    assert len(seen) >= len(poller.O) and all(b is budget for b in seen) and isinstance(budget, snmp.ByteBudget)
    assert budget.take(snmp.MAX_POLL_BYTES) is True and budget.take(1) is False    # nothing taken by the fake, the whole budget left
    assert snmp._BUDGET.get() is None


async def test_the_walks_of_a_change_read_share_one_budget(monkeypatch):
    """read_cfg, the live read of every SNMP change, runs its walks under one budget of MAX_POLL_BYTES as well."""
    seen = []

    async def walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        seen.append(snmp._BUDGET.get())
        return walk_answer(RECORDING.get(oid, []), oid, hex_values)

    monkeypatch.setattr(snmp, "walk", walk)
    await snmpwrite.read_cfg(ROW, DRIVERS["procurve"])
    budget = seen[0]
    assert len(seen) == len(snmpwrite.WALKS) and all(b is budget for b in seen) and isinstance(budget, snmp.ByteBudget)
    assert budget.take(snmp.MAX_POLL_BYTES) is True and budget.take(1) is False
    assert snmp._BUDGET.get() is None


def test_the_display_walks_the_free_text_as_hex_like_the_write_path():
    assert poller.TEXT_AS_HEX == ("ifAlias", "vlanName") and snmpwrite.TEXT_AS_HEX is poller.TEXT_AS_HEX


@pytest.mark.parametrize("value, text", [("42 C3 BC 72 6F", "Büro"), ("42 FC 72 6F", "Büro"), ("", ""), ("4B FC 63 68 65", "Küche"),
                                         ("42 C3 BC 72 6F 20 45 72 64 67 65 73 63 68 6F 73\n73 ", "Büro Erdgeschoss"), ("4243", "BC")])
def test_octets_text_reads_utf8_and_else_latin1(value, text):
    assert snmp.octets_text(value) == text


@pytest.mark.parametrize("value", ["52 6", "52 XY", "5 2", "Platz-107"])
def test_octets_text_refuses_what_is_no_hex(value):
    with pytest.raises(ValueError):
        snmp.octets_text(value)


@pytest.mark.parametrize("value, shown", [("42 C3 BC 72 6F", "Büro"), ("42 C3 BC 72 6F 20 45 72 64 67 65 73 63 68 6F 73\n73 ", "Büro Erdgeschoss"),
                                          ("Platz-107", "Platz-107"), ("", ""), ("CAFE", "CAFE"), ("52 6", "52 6"), ("41 42", "41 42"),
                                          ("41 42 x", "41 42 x")])
def test_only_whole_hex_pairs_are_decoded_for_display(value, shown):
    """Hex pairs separated by ASCII whitespace (net-snmp's -Ox output, its last line ending in a space) are decoded; anything else
    stays as it is, text of a fake walk as much as a pair around a non-ASCII space, which bytes.fromhex would refuse."""
    assert poller._display_text(value) == shown


async def test_the_poll_walks_the_free_text_as_hex_and_decodes_it(net, monkeypatch):
    """poll_switch asks for ifAlias and vlanName with -Ox, and what comes back as hex is stored as text, latin-1 as well."""
    a = await add(net, "A", A_HOST, "procurve", edit_walks(W_SAMPLE, ifAlias={"1": "Büro Erdgeschoss"}, vlanName={"99": "Gäste"}))
    asked = []

    async def walk(host, cred, oid, hex_values=False, timeout=60, strict=False):
        asked.append((oid, hex_values))
        rows = await net.walk(host, cred, oid, hex_values=hex_values, timeout=timeout, strict=strict)
        return [(o, hex_text("Büro", "latin-1")) if o.endswith(".6") else (o, v) for o, v in rows] if oid == BASES["ifAlias"] else rows

    monkeypatch.setattr(snmp, "walk", walk)
    assert (await poller.poll_switch(a))["ok"] is True
    assert {oid: hx for oid, hx in asked if oid in FREE_TEXT_OIDS} == dict.fromkeys(FREE_TEXT_OIDS, True)
    assert query("SELECT name, alias FROM ports WHERE switch_id = ? AND name IN ('1', '2', '6') ORDER BY ifindex", (a,)) == [
        ("1", "Büro Erdgeschoss"), ("2", ""), ("6", "Büro")]
    assert query("SELECT name FROM vlans WHERE switch_id = ? AND vid = '99'", (a,)) == [("Gäste",)]


def test_unusable_numbers_fall_back_one_value_at_a_time():
    """Each unusable number costs only its own value: a speed that is no number or longer than 9 digits is 0, an uptime that is no
    ASCII number (or longer than a TimeTicks, 10 digits) is None, a bridge port index "3.0" is no bridge port (port 1 keeps bridge
    port 3 and its VLANs), an FDB row without six ASCII numbers 0-255 in its MAC is skipped, every other row stays."""
    data = poller._build(walks({"ifHighSpeed": {"1": "fast", "2": "1234567890", "3": "1000"}, "sysUpTime": {"0": "²"}, "bp2if": {"3.0": "1"},
                                "fdb": {"1.0.17.42.x.0.1": "1", "1.0.17.42.256.0.1": "1", "1.0.17.42.0.0.1": "1", "1.0.17.42.0.0": "1",
                                        "1.0.17.42.٣.0.1": "1"}}), "procurve")
    ports = {p["name"]: p for p in data["ports"]}
    assert (ports["1"]["speed"], ports["2"]["speed"], ports["3"]["speed"], data["uptime"]) == (0, 0, 1000, None)
    assert (ports["1"]["untagged"], ports["1"]["tagged"], ports["1"]["pvid"]) == (["20"], ["30"], "20")
    assert data["macs"] == [("2", "00:11:2a:00:00:01", "1")]
    assert poller._build(walks({"sysUpTime": {"0": "1" * 5000}}), "procurve")["uptime"] is None
    assert poller._build(walks({"sysUpTime": {"0": "12345"}}), "procurve")["uptime"] == 123


def test_the_vlan_rows_skipped_are_counted():
    """Rows of the VLAN table (name, egress, untagged) without a VLAN ID 1-4094 as a walk prints it (no leading zero) are skipped and
    counted once per index; the ports keep the bits of the real VLANs only."""
    data = poller._build(walks({"vlanName": {"5000": "x", "0": "y", "1.2": "z", "020": "w"}, "vlanEgress": {"5000": "FF", "4095": "FF"},
                                "vlanUntagged": {"5000": "FF"}}), "procurve")
    assert set(data["vlans"]) == {"1", "20", "30", "99"} and data["vlan_rows_skipped"] == 5
    assert {p["name"]: p["untagged"] for p in data["ports"]} == {p["name"]: p["untagged"] for p in poller._build(walks(), "procurve")["ports"]}
    assert poller._build(walks(), "procurve")["vlan_rows_skipped"] == 0


@pytest.mark.parametrize("vid, ok", [("1", True), ("4094", True), ("0", False), ("4095", False), ("01", False), ("1.2", False), ("", False),
                                     ("٣", False), ("²", False), ("99999", False)])
def test_is_vlan_index(vid, ok):
    assert poller.is_vlan_index(vid) is ok


def test_max_ports_is_the_last_count_that_polls():
    assert len(poller._build(walks_with_ports(poller.MAX_PORTS), "generic")["ports"]) == poller.MAX_PORTS
    with pytest.raises(snmp.SnmpError, match=f"^Mehr als {poller.MAX_PORTS} Ports gemeldet, Abfrage abgebrochen$"):
        poller._build(walks_with_ports(poller.MAX_PORTS + 1), "generic")


def test_the_write_path_refuses_more_than_max_ports():
    assert len(snmpwrite.build_cfg(walks_with_ports(poller.MAX_PORTS), "generic")[0]["ports"]) == poller.MAX_PORTS
    with pytest.raises(snmp.SnmpError, match=f"^Mehr als {poller.MAX_PORTS} Ports gemeldet, Abfrage abgebrochen$"):
        snmpwrite.build_cfg(walks_with_ports(poller.MAX_PORTS + 1), "generic")


def test_the_write_path_skips_numeric_vlan_rows_outside_1_to_4094():
    """build_cfg reads a switch with VLAN rows 0, 5000 and 020 (full PortLists in all three columns) exactly as without them."""
    full = {"0": "FF", "5000": "FF", "020": "FF"}
    W = edit_walks(W_SAMPLE, vlanName={"0": "y", "5000": "x", "020": "w"}, vlanEgress=full, vlanUntagged=full)
    assert snmpwrite.build_cfg(W) == snmpwrite.build_cfg(W_SAMPLE)


def test_the_write_path_still_refuses_a_vlan_index_that_is_no_number():
    """A VLAN index that is no number at all is no VLAN the write path could address: the read fails closed, as before."""
    W = edit_walks(W_SAMPLE, vlanName={"1.2": "x"}, vlanEgress={"1.2": "00"}, vlanUntagged={"1.2": "00"})
    with pytest.raises(snmp.SnmpError, match=r"^Unerwartete SNMP-Daten \(Index oder Wert nicht lesbar\): "):
        snmpwrite.build_cfg(W)


async def test_a_failed_fid_walk_keeps_the_macs_and_their_counts(net, failing):
    """The FDB rows need dot1qVlanFdbId to name their VLAN: without it the MAC rows and counts of the last poll stay, row for row (the
    switch still learns the same MAC, so the row read now is the same row)."""
    a, _ = await mac_linked_pair(net)
    macs = query("SELECT port, mac, vlan FROM macs WHERE switch_id = ?", (a,))
    counts = query("SELECT name, mac_count FROM ports WHERE switch_id = ? ORDER BY ifindex", (a,))
    assert ("2", 1) in counts and macs
    failing(net, A_HOST, poller.O["fid"])
    assert (await poller.poll_switch(a))["ok"] is True
    assert query("SELECT port, mac, vlan FROM macs WHERE switch_id = ?", (a,)) == macs
    assert query("SELECT name, mac_count FROM ports WHERE switch_id = ? ORDER BY ifindex", (a,)) == counts
    assert last_error(a) == f"Teilweise gelesen: fid fehlgeschlagen ({TIMEOUT}); MAC-Tabelle vom letzten Poll behalten"


async def test_the_next_good_poll_reads_the_macs_again(net, failing, monkeypatch):
    """Kept means until the next good walk: then the MAC table is the switch's again and the note is gone."""
    a, _ = await mac_linked_pair(net)
    failing(net, A_HOST, poller.O["fdb"])
    await poller.poll_switch(a)
    monkeypatch.setattr(snmp, "walk", net.walk)
    net.rec[A_HOST][poller.O["fdb"]] = fdb("5", MAC1)[poller.O["fdb"]]    # bridge port 5 = port 6; MAC_B is gone
    assert (await poller.poll_switch(a))["ok"] is True
    assert query("SELECT port, mac FROM macs WHERE switch_id = ?", (a,)) == [("6", MAC1)] and last_error(a) is None
    assert query("SELECT name FROM ports WHERE switch_id = ? AND mac_count > 0", (a,)) == [("6",)]


@pytest.mark.parametrize("key", ["lldpSys", "lldpPortDesc", "lldpPortId", *poller.LLDP_LOC])
async def test_a_failed_lldp_walk_keeps_the_neighbours_at_every_driver(net, failing, key):
    """At a Catalyst (ports by ifType, lldpLocPortTable walked as well) each of the LLDP walks keeps the neighbours of the last poll
    when it fails, and the neighbour the other LLDP walks now name joins them (first): without lldpSys there is none."""
    c = await add(net, "C", C_HOST, "cisco", CATALYST, lldp("1", "B", "Gi1/0/2", "Gi1/0/2"))    # number 1 = bridge port 1 = Gi1/0/1
    assert port(await main.build_map(), "Gi1/0/1", "C")["l"] == [["B", "Gi1/0/2", "Gi1/0/2"]]
    net.rec[C_HOST].update(lldp("1", "D", "Gi1/0/3", "Gi1/0/3"))
    failing(net, C_HOST, {**poller.O, **poller.LLDP_LOC}[key])
    assert (await poller.poll_switch(c))["ok"] is True
    neighbours = port(await main.build_map(), "Gi1/0/1", "C")["l"]
    assert neighbours[-1] == ["B", "Gi1/0/2", "Gi1/0/2"] and [n[0] for n in neighbours] == (["B"] if key == "lldpSys" else ["D", "B"])
    assert last_error(c) == f"Teilweise gelesen: {key} fehlgeschlagen ({TIMEOUT}); LLDP vom letzten Poll behalten"


async def test_skipped_vlan_rows_are_named_by_the_poll(net):
    a = await add(net, "A", A_HOST, "procurve", edit_walks(W_SAMPLE, vlanName={"5000": "x", "0": "y"}, vlanEgress={"5000": "FF"}))
    assert last_error(a) == "Teilweise gelesen: 2 VLAN-Zeilen ohne gültige VLAN-ID (1–4094) übersprungen"
    assert query("SELECT vid FROM vlans WHERE switch_id = ? ORDER BY CAST(vid AS INTEGER)", (a,)) == [("1",), ("20",), ("30",), ("99",)]


async def test_every_reason_of_a_partial_poll_is_named_once(net, failing):
    """Failed walks in walk order with the first one's error, then what was kept, then the skipped VLAN rows; ifType at a ProCurve is
    not one of them (it does not use it)."""
    a = await add(net, "A", A_HOST, "procurve", edit_walks(W_SAMPLE, vlanName={"5000": "x"}), lldp("6", "B", "6", "6"), fdb("1", MAC_B))
    failing(net, A_HOST, poller.O["lldpPortId"])
    failing(net, A_HOST, poller.O["ifType"])
    failing(net, A_HOST, poller.O["fdb"])
    failing(net, A_HOST, poller.O["sysDescr"], f"Timeout: No Response from {A_HOST}")
    assert (await poller.poll_switch(a))["ok"] is True
    assert last_error(a) == (f"Teilweise gelesen: sysDescr, fdb, lldpPortId fehlgeschlagen (Timeout: No Response from {A_HOST}); "
                             "MAC-Tabelle vom letzten Poll behalten; LLDP vom letzten Poll behalten; 1 VLAN-Zeilen ohne gültige VLAN-ID "
                             "(1–4094) übersprungen")
    assert query("SELECT last_poll_ok FROM switches WHERE id = ?", (a,)) == [(1,)]


async def test_a_failed_walk_other_than_mac_or_lldp_is_named_too(net, failing):
    """A walk the display uses but keeps nothing of (ifAlias): the poll is partial, nothing is said to be kept."""
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE)
    failing(net, A_HOST, poller.O["ifAlias"])
    assert (await poller.poll_switch(a))["ok"] is True
    assert last_error(a) == f"Teilweise gelesen: ifAlias fehlgeschlagen ({TIMEOUT})"


async def test_a_failed_needed_walk_still_fails_the_poll(net, failing):
    """sysName and ifName stay walks without which there is no result: the poll fails as before, the MACs of the last poll stay."""
    a, _ = await mac_linked_pair(net)
    failing(net, A_HOST, poller.O["ifName"])
    assert await poller.poll_switch(a) == {"ok": False, "error": TIMEOUT}
    assert query("SELECT last_poll_ok, last_error FROM switches WHERE id = ?", (a,)) == [(0, TIMEOUT)]
    assert query("SELECT port, mac FROM macs WHERE switch_id = ?", (a,)) == [("2", MAC_B)]


# ── Review round 1: kept values never cost a fresh uplink, and every walk that carries the protection keeps ──────────────────────
FDB_OID = poller.O["fdb"]
BROKE_OFF = f"Timeout: No Response from {A_HOST}"
# The switch of the next test by driver: (host, walks, LLDP local port number, the port it means)
LLDP_PORT = {"procurve": (A_HOST, W_SAMPLE, "6", "6"), "cisco": (C_HOST, CATALYST, "1", "Gi1/0/1")}


async def test_a_new_mac_link_during_a_failed_fid_walk_is_an_uplink(net, failing):
    """Only the VLAN of the FDB rows is missing, the walk of the rows went through: the MACs it read join the kept ones (here none), so
    a base MAC A first learns in this poll protects its port, as before Task 10."""
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE, base_mac=MAC_A)
    await add(net, "B", B_HOST, "procurve", W_SAMPLE, base_mac=MAC_B)
    assert "2" not in (await changes.inventory(a))["uplinks"]
    net.rec[A_HOST][FDB_OID] = fdb("1", MAC_B)[FDB_OID]    # bridge port 1 = port 2
    failing(net, A_HOST, poller.O["fid"])
    assert (await poller.poll_switch(a))["ok"] is True
    assert "2" in (await changes.inventory(a))["uplinks"]
    assert query("SELECT port, mac FROM macs WHERE switch_id = ?", (a,)) == [("2", MAC_B)]


async def test_the_macs_read_join_the_kept_ones(net, failing):
    """A failed fid walk: the rows of the last poll stay, the rows read now are added (MAC1 on port 6), and mac_count counts the
    port's rows of the merged table."""
    a, _ = await mac_linked_pair(net)
    net.rec[A_HOST][FDB_OID] = fdb("5", MAC1)[FDB_OID]    # MAC_B no longer read, MAC1 on bridge port 5 = port 6
    failing(net, A_HOST, poller.O["fid"])
    assert (await poller.poll_switch(a))["ok"] is True
    assert sorted(query("SELECT port, mac, vlan FROM macs WHERE switch_id = ?", (a,))) == [("2", MAC_B, "1"), ("6", MAC1, "1")]
    assert query("SELECT name, mac_count FROM ports WHERE switch_id = ? AND mac_count > 0 ORDER BY ifindex", (a,)) == [("2", 1), ("6", 1)]
    assert "2" in (await changes.inventory(a))["uplinks"]


@pytest.mark.parametrize("driver, key", [("procurve", "lldpPortDesc"), ("procurve", "lldpPortId"), ("cisco", "lldpPortDesc"),
                                         ("cisco", "lldpPortId"), ("cisco", "lldpLocPortId"), ("cisco", "lldpLocPortDesc")])
async def test_a_new_lldp_neighbour_during_a_failed_lldp_walk_is_an_uplink(net, failing, driver, key):
    """lldpSys went through, another LLDP walk failed: the neighbours this poll read join the kept ones (here none), so a managed
    switch first seen by LLDP in this poll protects its port, as before Task 10."""
    host, W, num, name = LLDP_PORT[driver]
    sid = await add(net, "A", host, driver, W)
    await add(net, "B", B_HOST, "procurve", W_SAMPLE)
    assert name not in (await changes.inventory(sid))["uplinks"]
    net.rec[host].update(lldp(num, "B", "6", "6"))
    failing(net, host, {**poller.O, **poller.LLDP_LOC}[key])
    assert (await poller.poll_switch(sid))["ok"] is True
    assert name in (await changes.inventory(sid))["uplinks"]
    assert [n[0] for n in port(await main.build_map(), name)["l"]] == ["B"]


async def test_a_failed_bp2if_walk_keeps_the_mac_uplink_protected(net, failing):
    """bp2if ties the FDB rows to their ports: without it no MAC is read, and the MAC rows of the last poll stay. A ProCurve counts its
    LLDP ports by ifIndex, so the note says nothing about LLDP."""
    a, _ = await mac_linked_pair(net)
    failing(net, A_HOST, poller.O["bp2if"])
    assert (await poller.poll_switch(a))["ok"] is True
    assert "2" in (await changes.inventory(a))["uplinks"]
    assert query("SELECT port, mac FROM macs WHERE switch_id = ?", (a,)) == [("2", MAC_B)]
    assert last_error(a) == f"Teilweise gelesen: bp2if fehlgeschlagen ({TIMEOUT}); MAC-Tabelle vom letzten Poll behalten"


async def test_a_failed_bp2if_walk_keeps_the_neighbours_at_a_driver_by_iftype(net, failing):
    """At a Catalyst the LLDP port number is a bridge port (lldp_ports): without bp2if the neighbour of the last poll stays."""
    c = await add(net, "C", C_HOST, "cisco", CATALYST, lldp("1", "B", "Gi1/0/2", "Gi1/0/2"))
    failing(net, C_HOST, poller.O["bp2if"])
    assert (await poller.poll_switch(c))["ok"] is True
    assert port(await main.build_map(), "Gi1/0/1", "C")["l"] == [["B", "Gi1/0/2", "Gi1/0/2"]]
    assert last_error(c).endswith("; LLDP vom letzten Poll behalten")


async def test_a_failed_base_mac_walk_keeps_the_neighbours_uplink_protected(net, failing):
    """B protects its port 3 only through A's base MAC: a failed baseMac walk at A keeps A's stored base MAC."""
    a, b = await mac_linked_pair(net)
    assert "3" in (await changes.inventory(b))["uplinks"]
    failing(net, A_HOST, poller.O["baseMac"])
    assert (await poller.poll_switch(a))["ok"] is True
    assert "3" in (await changes.inventory(b))["uplinks"]
    assert query("SELECT base_mac FROM switches WHERE id = ?", (a,)) == [(MAC_A,)]
    assert last_error(a) == f"Teilweise gelesen: baseMac fehlgeschlagen ({TIMEOUT}); Basis-MAC vom letzten Poll behalten"


async def test_an_fdb_walk_that_breaks_off_keeps_the_mac_uplink_protected(net, failing):
    """A lenient FDB walk that ended with an exit code != 0 after some rows (snmp.Rows.broken_off) is incomplete: it counts as failed,
    the rows it read join those of the last poll, and the MAC-only uplink whose row it did not reach stays protected."""
    a, _ = await mac_linked_pair(net)
    failing(net, A_HOST, FDB_OID, BROKE_OFF, rows=fdb("5", MAC1)[FDB_OID])
    assert (await poller.poll_switch(a))["ok"] is True
    assert "2" in (await changes.inventory(a))["uplinks"]
    assert sorted(query("SELECT port, mac FROM macs WHERE switch_id = ?", (a,))) == [("2", MAC_B), ("6", MAC1)]
    assert last_error(a) == f"Teilweise gelesen: fdb fehlgeschlagen ({BROKE_OFF}); MAC-Tabelle vom letzten Poll behalten"


async def test_an_lldp_walk_that_breaks_off_keeps_the_last_neighbours(net, failing):
    """lldpSys broke off after the row of port 1: B, the neighbour on port 6 it did not reach, stays, and both ports are uplinks."""
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE, lldp("6", "B", "6", "6"))
    await add(net, "B", B_HOST, "procurve", W_SAMPLE)
    new = lldp("1", "B", "5", "5")
    for oid, rows in new.items():
        net.rec[A_HOST][oid] = net.rec[A_HOST][oid] + rows
    failing(net, A_HOST, poller.O["lldpSys"], BROKE_OFF, rows=new[poller.O["lldpSys"]])
    assert (await poller.poll_switch(a))["ok"] is True
    assert {"1", "6"} <= (await changes.inventory(a))["uplinks"]
    assert last_error(a) == f"Teilweise gelesen: lldpSys fehlgeschlagen ({BROKE_OFF}); LLDP vom letzten Poll behalten"


@pytest.mark.parametrize("key", ["ifAlias", "vlanEgress"])
async def test_a_walk_that_keeps_nothing_still_takes_what_came(net, failing, key):
    """Only the walks with kept values count a walk that broke off as failed; the display takes the rows of every other one as before."""
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE)
    failing(net, A_HOST, poller.O[key], BROKE_OFF, rows=net.rec[A_HOST][poller.O[key]])
    assert (await poller.poll_switch(a))["ok"] is True and last_error(a) is None


async def test_a_lenient_walk_that_breaks_off_says_why(spawn):
    """snmpbulkwalk exits != 0 after some rows (a timeout in the middle of a table): the lenient walk gives the rows and, in
    broken_off, the last line of stderr (else the exit code); a complete walk has none."""
    row = f".{FDB_OID}.1.0.26.43.0.0.11 1\n".encode()
    spawn.answer(FakeProcess(out=row, err=f"Timeout: No Response from {HOST}\n".encode(), returncode=1))
    rows = await snmp.walk(HOST, CRED, FDB_OID)
    assert rows == [(f"{FDB_OID}.1.0.26.43.0.0.11", "1")] and rows.broken_off == f"Timeout: No Response from {HOST}"
    spawn.answer(FakeProcess(out=row, returncode=2))
    assert (await snmp.walk(HOST, CRED, FDB_OID)).broken_off == "snmp Exit-Code 2"
    spawn.answer(FakeProcess(out=row))
    assert (await snmp.walk(HOST, CRED, FDB_OID)).broken_off is None


async def test_the_reason_a_walk_broke_off_shows_no_secret(spawn):
    spawn.answer(FakeProcess(out=f".{FDB_OID}.1.0.26.43.0.0.11 1\n".encode(), err=b"Unknown community ro-s3cret\n", returncode=2))
    assert (await snmp.walk(HOST, CRED, FDB_OID)).broken_off == "Unknown community ***"


@pytest.mark.parametrize("first", [True, False])
async def test_nothing_to_keep_is_not_called_kept(net, failing, first):
    """With no MAC rows, no LLDP neighbour and no base MAC from the last poll (or no last poll at all) the note says what is missing,
    not that something was kept."""
    if first:
        for key in ("baseMac", "fdb", "lldpSys"):
            failing(net, A_HOST, poller.O[key])
        a = await add(net, "A", A_HOST, "procurve", W_SAMPLE)
    else:
        a = await add(net, "A", A_HOST, "procurve", W_SAMPLE)
        for key in ("baseMac", "fdb", "lldpSys"):
            failing(net, A_HOST, poller.O[key])
        assert (await poller.poll_switch(a))["ok"] is True
    assert last_error(a) == (f"Teilweise gelesen: baseMac, fdb, lldpSys fehlgeschlagen ({TIMEOUT}); MAC-Tabelle unvollständig (nichts vom "
                             "letzten Poll zu behalten); LLDP unvollständig (nichts vom letzten Poll zu behalten); Basis-MAC unbekannt "
                             "(nichts vom letzten Poll zu behalten)")


def test_one_rule_refuses_too_many_ports():
    """The display and the write path refuse more than MAX_PORTS ports with the one message of poller.check_port_count."""
    poller.check_port_count(["1"] * poller.MAX_PORTS)
    with pytest.raises(snmp.SnmpError, match=f"^Mehr als {poller.MAX_PORTS} Ports gemeldet, Abfrage abgebrochen$"):
        poller.check_port_count(["1"] * (poller.MAX_PORTS + 1))


def fdb_row(fid: str, mac: str, bridge_port: str) -> tuple[str, str]:
    """One dot1qTpFdbPort row: <fid>.<mac as 6 decimals> = bridge port (netfix.fdb takes the VLAN ID as FID)."""
    return f"{FDB_OID}.{fid}.{'.'.join(str(int(x, 16)) for x in mac.split(':'))}", bridge_port


async def test_a_failed_fid_walk_adds_no_second_row_under_the_fid(net, failing):
    """Without dot1qVlanFdbId a row read now carries its FID as VLAN: a MAC the kept table has at that port already keeps its row (VLAN
    20, last_seen now) and gets no second one under FID 5; a MAC on another port is added under its FID."""
    fid = poller.O["fid"]
    a = await add(net, "A", A_HOST, "procurve", W_SAMPLE, {FDB_OID: [fdb_row("5", MAC_B, "1")], fid: [(f"{fid}.0.20", "5")]})
    assert query("SELECT port, mac, vlan FROM macs WHERE switch_id = ?", (a,)) == [("2", MAC_B, "20")]
    query("UPDATE macs SET last_seen = '2000-01-01 00:00:00' WHERE switch_id = ?", (a,))
    net.rec[A_HOST][FDB_OID] = [fdb_row("5", MAC_B, "1"), fdb_row("5", MAC1, "5")]    # MAC1 on bridge port 5 = port 6
    failing(net, A_HOST, fid)
    assert (await poller.poll_switch(a))["ok"] is True
    assert sorted(query("SELECT port, mac, vlan FROM macs WHERE switch_id = ?", (a,))) == [("2", MAC_B, "20"), ("6", MAC1, "5")]
    assert query("SELECT last_seen FROM macs WHERE switch_id = ? AND mac = ?", (a, MAC_B)) != [("2000-01-01 00:00:00",)]
    assert query("SELECT name, mac_count FROM ports WHERE switch_id = ? AND mac_count > 0 ORDER BY ifindex", (a,)) == [("2", 1), ("6", 1)]


# ── Phase 5 Task 10: a kept neighbour is not listed twice ────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("fresh, kept, failed, want", [
    ([["B", "Gi1/0/2", "Gi1/0/2"]], [["B", "GigabitEthernet1/0/2", "Gi1/0/2"]], {"lldpPortDesc"}, [["B", "GigabitEthernet1/0/2", "Gi1/0/2"]]),
    ([["B", "GigabitEthernet1/0/2", ""]], [["B", "GigabitEthernet1/0/2", "Gi1/0/2"]], {"lldpPortId"}, [["B", "GigabitEthernet1/0/2", "Gi1/0/2"]]),
    ([["B", "", ""]], [["B", "y", "1"]], {"lldpPortDesc", "lldpPortId"}, [["B", "y", "1"]]),
    ([["B", "Gi1/0/3", "Gi1/0/3"]], [["B", "GigabitEthernet1/0/2", "Gi1/0/2"]], {"lldpPortDesc"},
     [["B", "Gi1/0/3", "Gi1/0/3"], ["B", "GigabitEthernet1/0/2", "Gi1/0/2"]]),
    ([["C", "x", "x"]], [["B", "y", "y"]], {"lldpPortDesc", "lldpPortId"}, [["C", "x", "x"], ["B", "y", "y"]]),
    ([["B", "x", "1"]], [["B", "y", "1"], ["B", "x", "1"]], set(), [["B", "x", "1"], ["B", "y", "1"]])])
def test_merge_lldp(fresh, kept, failed, want):
    assert poller.merge_lldp(fresh, kept, failed) == want


@pytest.mark.parametrize("key", ["lldpPortDesc", "lldpPortId"])
async def test_a_kept_neighbour_is_not_listed_twice_while_one_lldp_walk_fails(net, failing, key):     # Phase 3 T10-RR2
    c = await add(net, "C", C_HOST, "cisco", CATALYST, lldp("1", "B", "Gi1/0/2", "GigabitEthernet1/0/2"))
    failing(net, C_HOST, poller.O[key])
    assert (await poller.poll_switch(c))["ok"] is True
    assert port(await main.build_map(), "Gi1/0/1", "C")["l"] == [["B", "GigabitEthernet1/0/2", "Gi1/0/2"]]


@pytest.mark.parametrize("fresh, kept, failed", [
    ([["B", "Uplink", "Gi1/0/3"]], [["B", "Uplink", "Gi1/0/2"]], {"lldpPortId"}),
    ([["B", "1/1/3", "aa:bb:cc:00:00:01"]], [["B", "1/1/2", "aa:bb:cc:00:00:01"]], {"lldpPortDesc"})])
def test_merge_lldp_keeps_what_a_walk_that_broke_off_did_read(fresh, kept, failed):
    """A field of a failed walk counts as missing only where it came out so (field 1 equal to field 2, field 2 empty): a walk that
    broke off after this row did read it, and a neighbour whose port changed stays listed with both entries, as before Phase 5."""
    assert poller.merge_lldp(fresh, kept, failed) == fresh + kept


def test_merge_lldp_takes_a_kept_entry_from_before_r40():
    """A port stored before R40 has entries of two fields: no IndexError, and such an entry covers only through its first two."""
    assert poller.merge_lldp([["B", "x", ""]], [["B", "x"]], {"lldpPortId"}) == [["B", "x"]]
    assert poller.merge_lldp([["B", "x", "1"]], [["B", "x"]], {"lldpPortDesc"}) == [["B", "x", "1"], ["B", "x"]]


async def test_a_neighbour_a_broken_off_walk_did_read_keeps_its_new_port(net, failing):
    """lldpPortId broke off after the row of port 1, which now names B's Gi1/0/3 (the description "Uplink" stayed): the fresh entry
    is no shortened copy of the kept one and stays next to it, so the claim of the new port is not lost for this poll."""
    c = await add(net, "C", C_HOST, "cisco", CATALYST, lldp("1", "B", "Gi1/0/2", "Uplink"))
    new = lldp("1", "B", "Gi1/0/3", "Uplink")
    net.rec[C_HOST].update(new)
    failing(net, C_HOST, poller.O["lldpPortId"], BROKE_OFF, rows=new[poller.O["lldpPortId"]])
    assert (await poller.poll_switch(c))["ok"] is True
    assert port(await main.build_map(), "Gi1/0/1", "C")["l"] == [["B", "Uplink", "Gi1/0/3"], ["B", "Uplink", "Gi1/0/2"]]
