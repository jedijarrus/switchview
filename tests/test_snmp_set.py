"""Tests for snmp.set_vars, the snmpset wrapper: the write-side twin of snmp.walk / snmp.get.

set_vars does one job: turn (host, cred, varbinds) into the argv of ONE snmpset call and hand it to snmp._run. A wrong token
order is the dangerous kind of bug on a write path, because the command reaches a live switch: the host swallowed as the
argument of a flag, a value shifted onto the next OID, a PortList written as text instead of bytes. So these tests record the
argv that set_vars passes to _run and compare it token by token with a command line written out by hand.

Nothing here touches net-snmp, the network or a switch (snmpset is not even installed on the development host). Most tests
replace snmp._run by a recorder. The last two keep the real _run and only fake the process it starts, to show that the argv
reaches create_subprocess_exec as a plain list (no shell) and that a failed snmpset becomes an SnmpError. snmp is imported flat
(app/ is on sys.path via pytest.ini), exactly as the app imports it.

Two different things are both spelled "x" in snmpset commands, and the tests keep them apart:
  * the varbind TYPE letter (i, u, s, x) is a positional token between the OID and the value; `x` there says "the value is a
    hex string", which is how a PortList is written (snmp.portlist_to_hex);
  * `-x` is the SNMPv3 flag for the privacy protocol (AES, DES, ...), one of the options snmp._auth_args puts before the host.
"""
import pytest

import snmp
from switchfix import FakeProcess

HOST = "203.0.113.21"
RW = "rw-s3cret"    # not "public": the community in the command must come from the cred that was passed in
V2C = {"snmp_version": "2c", "snmp_community": RW}
V3 = {
    "snmp_version": "3", "snmp_user": "svrw",
    "snmp_auth_proto": "SHA", "snmp_auth_pass": "authpass1",
    "snmp_priv_proto": "AES", "snmp_priv_pass": "privpass1",
}
RESPONSE = ".1.3.6.1.2.1.2.2.1.7.5 = INTEGER: 2\n"    # what snmpset echoes after a successful SET (the fake _run returns it)
# The SET's own timing (M5): 5 s per try and one retry. net-snmp's defaults (-t 1 -r 5) would send up to six identical SETs to a
# ProCurve that writes its flash on every SET and answers slower than a second. Reads keep theirs (-t 3 -r 1).
SET_TIMING = ["-t", "5", "-r", "1"]

IF_ADMIN_3 = "1.3.6.1.2.1.2.2.1.7.3"           # ifAdminStatus of ifIndex 3 (1 = up, 2 = down), type i
IF_ADMIN_5 = "1.3.6.1.2.1.2.2.1.7.5"
IF_ALIAS_3 = "1.3.6.1.2.1.31.1.1.1.18.3"       # ifAlias of ifIndex 3 (the port name), type s
PVID_3 = "1.3.6.1.2.1.17.7.1.4.5.1.1.3"        # dot1qPvid of bridge port 3 (Unsigned32), type u
EGRESS_20 = "1.3.6.1.2.1.17.7.1.4.3.1.2.20"    # dot1qVlanStaticEgressPorts of VLAN 20 (a PortList), type x


@pytest.fixture
def run_calls(monkeypatch):
    """Replace snmp._run by a recorder. Every call is appended as (cmd, timeout); the fake answers with RESPONSE."""
    calls = []

    async def fake_run(cmd, timeout, strict=False):    # strict: walk passes it on
        calls.append((cmd, timeout))
        return RESPONSE

    monkeypatch.setattr(snmp, "_run", fake_run)
    return calls


async def test_set_vars_argv(run_calls):
    """v2c with the RW community and one integer varbind: the whole command line, token by token."""
    out = await snmp.set_vars(HOST, V2C, [(IF_ADMIN_5, "i", "2")])

    assert out == RESPONSE    # whatever snmpset printed comes back unchanged
    assert len(run_calls) == 1
    argv, timeout = run_calls[0]
    assert argv == ["snmpset", "-v2c", "-c", RW, *SET_TIMING, "-On", HOST, IF_ADMIN_5, "i", "2"]
    assert timeout == 20      # the documented default
    # The host is positional, laid out like walk and get: right after the last option (-On, which takes no separate argument,
    # so the host cannot be taken for the argument of a flag), no "--" separator, and only oid/type/value triples behind it.
    host_at = argv.index(HOST)
    assert argv[host_at - 1] == "-On"
    assert "--" not in argv
    assert argv[host_at + 1:] == [IF_ADMIN_5, "i", "2"]


async def test_set_vars_sets_its_own_timeout_and_one_retry(run_calls):
    """M5: snmpset gets an explicit -t 5 -r 1 (once, before the host), not net-snmp's -t 1 -r 5; walk and get keep -t 3 -r 1."""
    await snmp.set_vars(HOST, V2C, [(IF_ADMIN_5, "i", "2")])
    await snmp.get(HOST, V2C, [IF_ADMIN_5])
    await snmp.walk(HOST, V2C, "1.3.6.1.2.1.2.2.1.7")

    (set_argv, _), (get_argv, _), (walk_argv, _) = run_calls
    host_at = set_argv.index(HOST)
    assert set_argv[host_at - 5:host_at] == [*SET_TIMING, "-On"]
    assert set_argv.count("-t") == set_argv.count("-r") == 1
    assert get_argv == ["snmpget", "-v2c", "-c", RW, "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", HOST, IF_ADMIN_5]
    assert walk_argv == ["snmpbulkwalk", "-v2c", "-c", RW, "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", "-Cr25", HOST,
                         "1.3.6.1.2.1.2.2.1.7"]


async def test_set_vars_appends_the_varbinds_in_order(run_calls):
    """Several varbinds go out in ONE call as consecutive oid/type/value triples, in the order given, all four types."""
    varbinds = [
        (EGRESS_20, "x", "0080"),
        (PVID_3, "u", "20"),
        (IF_ALIAS_3, "s", "Platz 107"),
        (IF_ADMIN_3, "i", "2"),
    ]
    given = list(varbinds)

    await snmp.set_vars(HOST, V2C, varbinds)

    assert len(run_calls) == 1
    argv, _ = run_calls[0]
    assert argv == [
        "snmpset", "-v2c", "-c", RW, *SET_TIMING, "-On", HOST,
        EGRESS_20, "x", "0080",
        PVID_3, "u", "20",
        IF_ALIAS_3, "s", "Platz 107",
        IF_ADMIN_3, "i", "2",
    ]
    assert varbinds == given    # the caller's list is neither reordered nor consumed


async def test_set_vars_v3_argv(run_calls):
    """A v3 cred puts the v3 options before the host, exactly the ones _auth_args builds for walk and get."""
    await snmp.set_vars(HOST, V3, [(IF_ADMIN_5, "i", "1")])

    assert len(run_calls) == 1
    argv, _ = run_calls[0]
    assert argv == [
        "snmpset", "-v3", "-u", "svrw", "-l", "authPriv", "-a", "SHA", "-A", "authpass1", "-x", "AES", "-X", "privpass1",
        *SET_TIMING, "-On", HOST, IF_ADMIN_5, "i", "1",
    ]


async def test_set_vars_hex_type_letter_is_not_the_v3_privacy_flag(run_calls):
    """The `x` of a PortList varbind and the `-x` privacy flag of a v3 cred each stay where they belong in the argv."""
    await snmp.set_vars(HOST, V3, [(EGRESS_20, "x", "0080")])    # 0080 = bridge port 9 (0x80 in byte 1)

    assert len(run_calls) == 1
    argv, _ = run_calls[0]
    host_at = argv.index(HOST)
    options, varbinds = argv[1:host_at], argv[host_at + 1:]
    # before the host: the flag -x with the privacy protocol as its argument, and no bare type letter
    assert options.count("-x") == 1 and options[options.index("-x") + 1] == "AES"
    assert "x" not in options
    # behind the host: the type letter as its own token between OID and value, and no flag
    assert varbinds == [EGRESS_20, "x", "0080"]
    assert "-x" not in varbinds


@pytest.mark.parametrize("typ, value", [
    pytest.param("s", "Platz 107", id="space"),
    pytest.param("s", "Büro 2, Süd", id="umlauts-and-comma"),
    pytest.param("s", "  padded  ", id="surrounding-blanks"),
    pytest.param("s", "say \"hi\" & 'bye'", id="quotes"),
    pytest.param("s", "a; b $(c) `d` | e > f", id="shell-metacharacters"),
    pytest.param("s", "-v1", id="looks-like-an-option"),
    pytest.param("s", "", id="empty"),                  # clearing a port name
    pytest.param("i", "-1", id="negative-number"),
])
async def test_set_vars_values_stay_single_argv_elements(run_calls, typ, value):
    """No shell: oid, type and value are each exactly one argv element, passed on verbatim (no splitting, quoting or trimming).

    The second varbind proves nothing shifted behind it, which matters most for the empty value: dropping that argv element
    would turn the next OID into the value of the first varbind.
    """
    await snmp.set_vars(HOST, V2C, [(IF_ALIAS_3, typ, value), (IF_ADMIN_3, "i", "1")])

    assert len(run_calls) == 1
    argv, _ = run_calls[0]
    assert argv[argv.index(HOST) + 1:] == [IF_ALIAS_3, typ, value, IF_ADMIN_3, "i", "1"]
    assert all(isinstance(token, str) for token in argv)    # a list of strings, not one command line to be split by a shell


@pytest.mark.parametrize("kwargs, expected", [
    pytest.param({}, 20, id="default"),
    pytest.param({"timeout": 7.5}, 7.5, id="explicit"),
])
async def test_set_vars_forwards_the_timeout(run_calls, kwargs, expected):
    await snmp.set_vars(HOST, V2C, [(IF_ADMIN_5, "i", "1")], **kwargs)

    assert run_calls[0][1] == expected


async def test_set_vars_raises_on_error(monkeypatch):
    """A failed snmpset surfaces as the very SnmpError that _run raised: not swallowed, not wrapped, not turned into a return value."""
    boom = snmp.SnmpError("notWritable")

    async def failing_run(cmd, timeout):
        raise boom

    monkeypatch.setattr(snmp, "_run", failing_run)

    with pytest.raises(snmp.SnmpError) as excinfo:
        await snmp.set_vars(HOST, V2C, [(IF_ADMIN_5, "i", "2")])
    assert excinfo.value is boom


# --- through the real _run: only the process it would start is faked (switchfix.FakeProcess) ---------------------------------------

def _fake_process(monkeypatch, proc):
    """Let the real snmp._run run, but hand it `proc` instead of starting a program. Returns the argv tuples it was asked to start.

    Starting anything through a shell fails the test.
    """
    started = []

    async def fake_exec(*argv, **kwargs):
        started.append(argv)
        return proc

    def no_shell(*args, **kwargs):
        raise AssertionError("snmpset must not be started through a shell")

    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(snmp.asyncio, "create_subprocess_shell", no_shell)
    return started


async def test_set_vars_through_the_real_run_starts_snmpset_without_a_shell(monkeypatch):
    """The argv list reaches create_subprocess_exec as separate arguments (a value with a space is ONE argument); the output comes back."""
    echo = ".1.3.6.1.2.1.31.1.1.1.18.3 = STRING: Platz 107\n"
    started = _fake_process(monkeypatch, FakeProcess(out=echo.encode()))

    out = await snmp.set_vars(HOST, V2C, [(IF_ALIAS_3, "s", "Platz 107")])

    assert started == [("snmpset", "-v2c", "-c", RW, *SET_TIMING, "-On", HOST, IF_ALIAS_3, "s", "Platz 107")]
    assert out == echo


async def test_set_vars_through_the_real_run_failed_snmpset_raises_snmp_error(monkeypatch):
    """snmpset exits nonzero without any output on stdout (no answer, request refused, ...): the real _run turns that into SnmpError."""
    started = _fake_process(monkeypatch, FakeProcess(err=f"Timeout: No Response from {HOST}.\n".encode(), returncode=1))

    with pytest.raises(snmp.SnmpError):
        await snmp.set_vars(HOST, V2C, [(IF_ADMIN_5, "i", "2")])
    assert len(started) == 1    # the SET was attempted exactly once: set_vars itself never retries a write
