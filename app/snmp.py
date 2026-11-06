"""SNMP-Zugriff ueber net-snmp: Lesen mit snmpbulkwalk/snmpget (walk, get), Schreiben mit snmpset (set_vars).

Lesen: Ausgabe immer numerisch (-On), ohne Typ (-Oq), Enums als Zahl (-Oe),
Timeticks als Zahl (-Ot). Bitmaps (VLAN-Portlisten, MACs) mit -Ox als Hex, ebenso der Freitext ifAlias / vlanName (octets_text).

A walk or get parses its output in a worker thread, off the event loop (_parse). A cancelled call kills its net-snmp process (_exec).
One query (a display poll, the live read of a change) shares one byte budget over all of its walks (byte_budget, _collect).

Credentials never go into the argv, which every process list shows (R45): the community and the v3 passphrases reach net-snmp through
a snmp.conf of the call's own (see _run).
"""
import asyncio
import contextlib
import contextvars
import logging
import os
import re
import shutil
import tempfile

log = logging.getLogger("switchview.snmp")

AUTH_PROTOS = {"SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "MD5"}
PRIV_PROTOS = {"AES", "AES-192", "AES-256", "DES"}
# snmpset: 5 s je Versuch, eine Wiederholung (siehe set_vars)
SET_TIMING = ("-t", "5", "-r", "1")
# What one SNMP call may hand to the app, whatever the agent sends (a hostile or broken one must not fill the memory):
MAX_STDOUT = 8 * 1024 * 1024    # bytes of stdout per call; 64 000 MACs are about 4 MB (see _exec)
MAX_STDERR = 64 * 1024          # bytes of stderr kept per call; the rest is read and dropped (see _exec)
MAX_POLL_BYTES = 32 * 1024 * 1024    # bytes of stdout of all the walks of one query together (byte_budget; poller, snmpwrite.read_cfg)
MAX_ROWS = 100_000              # values per walk, rows with an OID (see _parse)
MAX_PORTLIST_BYTES = 8192       # a PortList over bridge ports 1..65535 (dot1dBasePort) needs no more (see portlist_bytes)
MAX_BRIDGE_PORT = 65535         # the last dot1dBasePort (BRIDGE-MIB); set / clear refuse a higher one (see portlist_set_bit)
READ_CHUNK = 64 * 1024          # _exec reads stdout and stderr in pieces of this size
SHM_DIR = "/dev/shm"            # where _run puts a call's snmp.conf when it may: a tmpfs, so a secret never reaches a disk
CONF_FORBIDDEN = "\x00\r\n"     # characters that end a snmp.conf line: a secret with one of them never goes into the file


class SnmpError(Exception):
    pass


class ByteBudget:
    """The stdout bytes one query may still read, over all of its walks (see byte_budget)."""

    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    def take(self, n: int) -> bool:
        """Count n more bytes; False once the budget is exceeded, and from then on for good."""
        self.used += n
        return self.used <= self.limit


# The budget of the query this call belongs to, None outside one. A ContextVar, not a parameter of walk: the walks of a query run in one
# asyncio.gather, and each of its tasks starts with a copy of the context of the caller, so all of them share the one ByteBudget object.
_BUDGET: contextvars.ContextVar[ByteBudget | None] = contextvars.ContextVar("snmp_byte_budget", default=None)


@contextlib.contextmanager
def byte_budget(limit: int):
    """For the duration of the with block, every SNMP call started in it (and in the tasks it starts) takes its stdout from one
    ByteBudget of limit bytes; over it, _collect cuts the call off like one over MAX_STDOUT. Yields the budget."""
    budget = ByteBudget(limit)
    token = _BUDGET.set(budget)
    try:
        yield budget
    finally:
        _BUDGET.reset(token)


def _level(cred: dict) -> str:
    """The SNMPv3 security level of cred: authPriv with both pairs (protocol and passphrase), authNoPriv with the auth pair, otherwise
    noAuthNoPriv."""
    if cred.get("snmp_auth_proto") and cred.get("snmp_auth_pass"):
        return "authPriv" if cred.get("snmp_priv_proto") and cred.get("snmp_priv_pass") else "authNoPriv"
    return "noAuthNoPriv"


def _auth_args(cred: dict) -> list[str]:
    """The net-snmp options of cred's identity, without any secret (they show in every process list): v2c only the version, v3 the
    user, the security level (_level) and the protocols that level uses. The secrets go into the call's snmp.conf (_conf_lines)."""
    if cred.get("snmp_version") == "3":
        level = _level(cred)
        args = ["-v3", "-u", cred.get("snmp_user") or "", "-l", level]
        if level != "noAuthNoPriv":
            args += ["-a", cred["snmp_auth_proto"]]
        if level == "authPriv":
            args += ["-x", cred["snmp_priv_proto"]]
        return args
    return ["-v2c"]


def _conf_value(value: str) -> str:
    """value as a quoted snmp.conf word that net-snmp reads back unchanged (read_config.c copy_nword: inside the quotes a backslash
    takes the next character literally), so a backslash and a quote get one in front. SnmpError for a NUL, CR or LF (CONF_FORBIDDEN):
    it would end the line, and what follows would be read as a directive of its own."""
    if any(c in value for c in CONF_FORBIDDEN):
        raise SnmpError("SNMP-Zugangsdaten enthalten ein unzulässiges Steuerzeichen")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _conf_lines(cred: dict) -> list[str]:
    """The snmp.conf lines (snmp.conf(5)) with cred's secrets, the counterpart of _auth_args: v2c the community (without one "public",
    net-snmp needs one), v3 the passphrases its security level uses (_level), none for noAuthNoPriv."""
    if cred.get("snmp_version") == "3":
        level = _level(cred)
        lines = []
        if level != "noAuthNoPriv":
            lines.append(f"defAuthPassphrase {_conf_value(cred['snmp_auth_pass'])}")
        if level == "authPriv":
            lines.append(f"defPrivPassphrase {_conf_value(cred['snmp_priv_pass'])}")
        return lines
    return [f"defCommunity {_conf_value(cred.get('snmp_community') or 'public')}"]


def _secrets(cred: dict) -> tuple[str, ...]:
    """The values of cred that no message may show: the community unless it is "public" (any case, outer whitespace ignored: no
    secret, R-T), the auth and the priv passphrase; only the ones that are set."""
    community = cred.get("snmp_community") or ""
    if community.strip().lower() == "public":
        community = ""
    return tuple(v for v in (community, cred.get("snmp_auth_pass"), cred.get("snmp_priv_pass")) if v)


def _mask(text: str, secrets: tuple[str, ...]) -> str:
    """text with each of secrets replaced by "***", the longest first: a secret inside a longer one must not leave the rest standing."""
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


def _conf_parent() -> str | None:
    """SHM_DIR when it is a directory this process may create entries in, otherwise None (tempfile's default directory)."""
    return SHM_DIR if os.path.isdir(SHM_DIR) and os.access(SHM_DIR, os.W_OK | os.X_OK) else None


def _new_conf_dir() -> str:
    """A new, empty directory (mkdtemp, so 0700) in SHM_DIR when that is writable (_conf_parent), otherwise in the default temporary
    directory. SnmpError when it cannot be made."""
    try:
        return tempfile.mkdtemp(prefix="switchview-snmp-", dir=_conf_parent())
    except OSError as e:
        raise SnmpError(f"SNMP-Konfiguration für den Aufruf ließ sich nicht anlegen: {e}") from None


def _write_conf(conf_dir: str, lines: list[str]) -> None:
    """The file snmp.conf in conf_dir, new (never one that exists already), readable and writable by this user only, holding lines in
    UTF-8. SnmpError when it cannot be written."""
    try:
        fd = os.open(os.path.join(conf_dir, "snmp.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write("".join(line + "\n" for line in lines))
    except OSError as e:
        raise SnmpError(f"SNMP-Konfiguration für den Aufruf ließ sich nicht anlegen: {e}") from None


def _remove(conf_dir: str) -> None:
    """Delete conf_dir with its snmp.conf. A failure is logged, not raised: it must not hide the outcome of the call."""
    try:
        shutil.rmtree(conf_dir)
    except OSError:
        log.warning("SNMP-Konfiguration %s ließ sich nicht löschen", conf_dir, exc_info=True)


async def _run(cmd: list[str], timeout: float, strict: bool = False, *, cred: dict | None = None) -> str:
    """Start cmd without a shell and return its stdout (see _exec for how it is read and when it fails).

    With cred, its secrets reach the process through a snmp.conf of this call alone (_conf_lines), never through the argv (R45): the
    file is 0600 (_write_conf), in a directory of its own (_new_conf_dir), empty when cred has no secret to send, and SNMPCONFPATH
    points the process at that directory, so net-snmp reads no other snmp.conf. The directory goes when the call ends, however it ends
    (output, error, timeout, cancel, a failed write). A secret with a NUL, CR or LF is a SnmpError before anything is created or
    started. No SnmpError message carries one of cred's secrets (_secrets): each one is "***"."""
    if cred is None:
        return await _exec(cmd, timeout, strict, {})
    secrets = _secrets(cred)
    try:
        lines = _conf_lines(cred)
        conf_dir = _new_conf_dir()
        try:
            _write_conf(conf_dir, lines)
            return await _exec(cmd, timeout, strict, {"SNMPCONFPATH": conf_dir})
        finally:
            _remove(conf_dir)
    except SnmpError as e:
        masked = _mask(str(e), secrets)
        if masked == str(e):
            raise
        raise SnmpError(masked) from None    # not chained: the original's message, in a logged traceback, would show the secret


async def _exec(cmd: list[str], timeout: float, strict: bool, extra_env: dict) -> str:
    """Start cmd without a shell, with os.environ plus MIBS="" plus extra_env, and return its stdout. stdout and stderr are read together,
    READ_CHUNK bytes at a time, up to EOF, then the exit is awaited, all under the one timeout. SnmpError on a timeout; when stdout
    grows beyond MAX_STDOUT or the query's byte budget (the process is killed, see _collect); and on an exit code != 0 without output,
    with strict on EVERY exit code != 0, even when stdout has rows already (see walk). The message of a failed call is the last line
    of stderr, of which only the first MAX_STDERR bytes are kept. Every other exception while it waits, a cancel above all (a request
    that went away, SwitchView stopping), kills the process as well and is raised on: no walk outlives its call."""
    env = dict(os.environ, MIBS="", **extra_env)
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
    )
    try:
        out, err, returncode = await asyncio.wait_for(_collect(proc), timeout=timeout)
    except asyncio.TimeoutError:
        _kill(proc)
        raise SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
    except BaseException:
        _kill(proc)
        raise
    text = out.decode("utf-8", "replace")
    if returncode != 0 and (strict or not text.strip()):
        msg = err.decode("utf-8", "replace").strip().splitlines()
        msg = [m for m in msg if "Cannot find module" not in m and "MIB search path" not in m]
        raise SnmpError(msg[-1] if msg else f"snmp Exit-Code {returncode}")
    return text


async def _collect(proc) -> tuple[bytearray, bytes, int]:
    """(stdout, the first MAX_STDERR bytes of stderr, exit code) of proc, read the way _exec says. Every stdout chunk is taken from the
    byte budget of the query, if one is set (byte_budget). Once stdout grows beyond MAX_STDOUT, or the budget is exceeded, proc is
    killed and, after its exit, SnmpError raised. Both pipes are read to EOF in every case, stderr alongside stdout: a process
    blocked on a full stderr pipe would never finish its stdout, and asyncio closes the process transport only once both pipes have
    closed. A pipe whose reader has paused because nobody reads it any more never does, not even after the kill: its transport would
    leak, and a wait() that came before the exit was noticed would hang."""
    budget = _BUDGET.get()
    stderr = asyncio.create_task(_drain(proc.stderr, MAX_STDERR))
    try:
        out, too_big = bytearray(), None
        while chunk := await proc.stdout.read(READ_CHUNK):
            out += chunk
            spent = budget is not None and not budget.take(len(chunk))
            if len(out) > MAX_STDOUT:
                too_big = f"SNMP-Antwort zu groß (über {MAX_STDOUT // (1024 * 1024)} MiB), Abfrage abgebrochen"
            elif spent:
                too_big = f"SNMP-Abfrage zu groß (über {MAX_POLL_BYTES // (1024 * 1024)} MiB zusammen), abgebrochen"
            if too_big:
                _kill(proc)
                await _drain(proc.stdout, 0)    # what the killed process left in the pipe, dropped
                break
        err = await stderr
        returncode = await proc.wait()
    finally:
        stderr.cancel()    # still running only when the timeout cancels the call: the reader must not outlive it
    if too_big:
        raise SnmpError(too_big)
    return out, err, returncode


async def _drain(stream, keep: int) -> bytes:
    """Read stream up to EOF, READ_CHUNK bytes at a time, and return its first `keep` bytes."""
    kept = bytearray()
    while chunk := await stream.read(READ_CHUNK):
        if len(kept) < keep:
            kept += chunk[:keep - len(kept)]
    return bytes(kept)


def _kill(proc) -> None:
    """Kill proc; one that has exited in the meantime is no error."""
    try:
        proc.kill()
    except ProcessLookupError:
        pass


def _host(host: str) -> str:
    """host, wenn er als Ziel an net-snmp gehen darf. Er steht als eigenes Argument hinter den Optionen, und getopt laese ein "-..."
    dort als Option: SnmpError statt eines Aufrufs. main prueft den Host beim Speichern (HOST_RE), Zeilen von vorher aber nicht."""
    if host.startswith("-"):
        raise SnmpError(f"Host {host!r} darf nicht mit '-' beginnen (net-snmp läse ihn als Option)")
    return host


_HEX_VALUE = re.compile(r"[0-9A-Fa-f\s]*")
# The inside of a quoted string as net-snmp prints it: any character but a quote or a backslash, or a backslash with the character
# after it (\" and \\ are the escapes net-snmp writes). Possessive, so a match runs once over the text, never back.
_STRING_BODY = re.compile(r'(?:[^"\\]++|\\.)*+', re.DOTALL)


def _quote_end(segment: str, start: int) -> int:
    """Where a quoted string that is open at segment[start] ends: the index of its closing quote in segment, or -1 when segment ends
    inside the string. An escaped quote closes nothing; a backslash at the very end takes the line break behind it, and the next line
    goes on inside the string, unescaped."""
    end = _STRING_BODY.match(segment, start).end()
    return end if end < len(segment) and segment[end] == '"' else -1


def _head(value: str, tail: list[str]) -> str:
    """The first 80 characters of value with its continuation lines tail (for a message)."""
    for line in tail:
        if len(value) >= 80:
            break
        value += "\n" + line[:80]
    return value[:80]


def _parse(text: str, hex_strict: bool = False, text_strict: bool = False) -> list[tuple[str, str]]:
    """Lines "OID value" -> [(oid, value)]. A line without an OID belongs to the value before it as a continuation (net-snmp wraps long
    values and prints a line break inside a string as it is); blank lines, and lines before the first OID, belong to no value. More than
    MAX_ROWS values (lines with an OID; continuation lines do not count) are an SnmpError. Time and memory stay linear in the output:
    continuation lines are joined once, each string is scanned once.

    Lenient (neither strict mode: the display poller, get): a quoted string goes on up to its closing quote, and as long as it is open,
    a line that starts with "." is a continuation too, not a new row. net-snmp prints every printable OCTET STRING in quotes, with \\"
    and \\\\ escaped, so a value such as an LLDP system name "evilhost<line break>.<oid> FORGED" stays one value and injects no row. Text
    behind a closing quote ends the string there, no error; a string that never ends keeps every line behind it.

    The two strict modes change nothing about the rows, they only refuse (SnmpError) what cannot belong to a value:

    hex_strict (a strict hex walk, with -Ox): every value, with its continuation lines, must be pure hex. A stray line behind a PortList
    (such as "End of MIB") would otherwise be appended, and hex_to_bytes would turn its letters a-f into bits for bridge ports that do
    not exist. Every line that starts with "." is a row here (with -Ox nothing is quoted text).

    text_strict (a strict walk without -Ox): only a quoted string wraps, numbers and other bare values never. A continuation line counts
    only while a string is open; any other (behind a number, behind a closed string) is a stray line that would otherwise end up in the
    last value, say in an ifAlias that a revert would write back to the switch. A string must be closed before the next line with an
    OID and before the end of the output, and nothing may follow its closing quote (net-snmp never prints that)."""
    lenient = not (hex_strict or text_strict)
    track = lenient or text_strict    # follow quoted strings
    rows: list[tuple[str, str]] = []
    tail: list[str] = []    # the continuation lines of rows[-1], joined to its value once the row is complete
    open_string = False     # (track) the value of rows[-1] is a quoted string whose closing quote is still missing
    for line in text.splitlines():
        if line.startswith(".") and not (lenient and open_string):
            if open_string:
                raise SnmpError(f"String ohne Ende in {rows[-1][0]}: {_head(rows[-1][1], tail)!r}")
            if len(rows) >= MAX_ROWS:
                raise SnmpError(f"SNMP-Antwort mit mehr als {MAX_ROWS} Zeilen, Abfrage abgebrochen")
            if tail:
                rows[-1] = (rows[-1][0], rows[-1][1] + "\n" + "\n".join(tail))
                tail = []
            oid, _, val = line.partition(" ")
            oid, val = oid.lstrip("."), val.strip()
            rows.append((oid, val))
            open_string = False
            if track and val.startswith('"'):
                end = _quote_end(val, 1)
                if text_strict and end not in (-1, len(val) - 1):
                    raise SnmpError(f"Text hinter dem Ende des Strings in {oid}: {val[:80]!r}")
                open_string = end == -1
        elif rows and line.strip():
            if text_strict and not open_string:
                raise SnmpError(f"Unerwartete Zeile hinter dem Wert von {rows[-1][0]}: {line[:80]!r}")
            tail.append(line)
            if open_string and '"' in line:    # a line without a quote cannot close the string
                end = _quote_end(line, 0)
                if text_strict and end not in (-1, len(line) - 1):
                    raise SnmpError(f"Text hinter dem Ende des Strings in {rows[-1][0]}: {_head(rows[-1][1], tail)!r}")
                open_string = end == -1
    if open_string and text_strict:
        raise SnmpError(f"String ohne Ende in {rows[-1][0]}: {_head(rows[-1][1], tail)!r}")
    if tail:
        rows[-1] = (rows[-1][0], rows[-1][1] + "\n" + "\n".join(tail))
    out = []
    for oid, val in rows:
        if "No Such Object" in val or "No Such Instance" in val or "No more variables" in val:
            continue
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        if hex_strict and not _HEX_VALUE.fullmatch(val):
            raise SnmpError(f"Unerwartete Ausgabe in einem Hex-Wert ({oid}): {val[:80]!r}")
        out.append((oid, val))
    return out


async def walk(host: str, cred: dict, oid: str, hex_values: bool = False, timeout: float = 60, strict: bool = False) -> list[tuple[str, str]]:
    """snmpbulkwalk unter oid. snmpbulkwalk gibt jede Zeile sofort aus; bricht der Walk mittendrin ab (Timeout, Fehlerpaket), endet
    es mit Exit-Code != 0, die Zeilen bis dahin stehen aber schon in stdout. strict=False (Standard, der Poller): das gilt als
    Ergebnis, die Anzeige nimmt, was kam. strict=True (der Schreibweg): jeder Exit-Code != 0 ist ein SnmpError, nie eine halbe Tabelle;
    dazu muss jede Zeile zu einem Wert gehoeren: mit hex_values ist jeder Wert reines Hex, ohne kann nur ein String umbrechen (siehe
    _parse). Ein host mit "-" vorne: SnmpError, ohne Aufruf (_host).
    The output is parsed in a worker thread: up to MAX_STDOUT of crafted continuation lines cost seconds of CPU, which must not hold up
    the event loop, the UI and the other polls.
    """
    cmd = ["snmpbulkwalk", *_auth_args(cred), "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", "-Cr25"]
    if hex_values:
        cmd.append("-Ox")
    cmd += [_host(host), oid]
    text = await _run(cmd, timeout, strict=strict, cred=cred)
    return await asyncio.to_thread(_parse, text, hex_strict=strict and hex_values, text_strict=strict and not hex_values)


async def get(host: str, cred: dict, oids: list[str], timeout: float = 15) -> dict[str, str]:
    """snmpget of oids -> {oid: value}, parsed in a worker thread like walk."""
    cmd = ["snmpget", *_auth_args(cred), "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", _host(host), *oids]
    text = await _run(cmd, timeout, cred=cred)
    return dict(await asyncio.to_thread(_parse, text))


async def set_vars(host: str, cred: dict, varbinds: list[tuple[str, str, str]], timeout: float = 20) -> str:
    """snmpset: schreibt alle `varbinds` = [(oid, typ, wert), ...] mit EINEM Aufruf und liefert die Ausgabe von snmpset.

    `cred` ist die Schreib-Identitaet (RW-Community bzw. v3-User); der Aufrufer baut sie, hier geht sie unveraendert an _auth_args und _run (snmp.conf).
    `typ` ist der snmpset-Typbuchstabe: i = INTEGER, u = Unsigned32/Gauge, s = String, x = Hex-String (Wert ohne Trennzeichen, siehe
    portlist_to_hex). Dieses `x` ist ein eigenes Argument zwischen OID und Wert, nicht das `-x` (v3-Privacy-Protokoll) aus _auth_args.
    Wie bei walk/get steht der Host positional hinter den Optionen, und es gibt keine Shell: jedes Argument ist ein eigenes Argv-Element,
    Werte mit Leerzeichen oder leere Werte brauchen kein Quoting. Fehler kommen als SnmpError aus _run; ein SnmpError heisst nicht
    "nicht gesetzt": nach einem Timeout ist offen, ob der Switch den Wert schon uebernommen hat (darum Read-back-Verify beim Aufrufer).
    Ein host mit "-" vorne: SnmpError, ohne Aufruf (_host).
    Eigenes Timing (SET_TIMING) statt der net-snmp-Vorgabe -t 1 -r 5: ein ProCurve schreibt bei jedem SET den Flash und antwortet
    langsamer als 1 s, er bekaeme sonst bis zu sechs gleiche SETs. Das Lesen behaelt sein -t 3 -r 1.
    """
    cmd = ["snmpset", *_auth_args(cred), *SET_TIMING, "-On", _host(host)]
    for oid, typ, val in varbinds:
        cmd += [oid, typ, val]
    return await _run(cmd, timeout, cred=cred)


def octets_text(value: str) -> str:
    """An OCTET STRING as a walk with -Ox gives it ("42 C3 BC 72 6F", also over several lines; "" is empty) as text: UTF-8, and where
    that fails latin-1 (one character per byte, which never fails). ValueError when value is not whole bytes of hex."""
    data = bytes.fromhex(value)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def hex_to_bytes(val: str) -> bytes:
    h = re.sub(r"[^0-9A-Fa-f]", "", val)
    if len(h) % 2:
        h = h[:-1]
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""


def portlist_bytes(val: str) -> bytes:
    """The bytes of a Q-BRIDGE PortList as a walk prints it (hex_to_bytes). ValueError beyond MAX_PORTLIST_BYTES: bridge ports run from
    1 to 65535 (dot1dBasePort), 8192 bytes hold every one of them, and a longer list is no answer of a switch."""
    raw = hex_to_bytes(val)
    if len(raw) > MAX_PORTLIST_BYTES:
        raise ValueError(f"PortList mit {len(raw)} Bytes ist länger als {MAX_PORTLIST_BYTES} Bytes (Bridge-Ports bis 65535)")
    return raw


def bitmap_ports(val: str) -> set[int]:
    """Q-BRIDGE PortList as the set of its bridge ports: bit 1 (MSB of the first byte) = bridge port 1. ValueError beyond
    MAX_PORTLIST_BYTES (portlist_bytes). The poller and the write path test single bits instead (portlist_has_bit), no set per VLAN."""
    b = portlist_bytes(val)
    return {i * 8 + j + 1 for i, byte in enumerate(b) for j in range(8) if byte & (0x80 >> j)}


# PortList schreiben: Gegenstueck zu bitmap_ports mit derselben Zaehlung (1-basiert, Bit 1 = MSB von Byte 0, also 0x80 >> j). Beim
# Read-Modify-Write eines VLAN-Eintrags darf genau ein Bit der vom Switch gelesenen Bytes kippen: alle anderen Bits und die Laenge
# bleiben erhalten. set/clear liefern darum immer eine NEUE Bytefolge, kuerzen nie und verlaengern nur, wenn der Port dahinter liegt.
def _portlist_pos(port: int) -> tuple[int, int]:
    """Byte-Index und Bitmaske von Bridge-Port `port` in einer PortList."""
    if port < 1:
        # Port 0 oder negativ ergaebe einen negativen Index und wuerde stillschweigend das LETZTE Byte aendern statt zu scheitern.
        raise ValueError(f"PortList-Portnummern beginnen bei 1, nicht bei {port}")
    i, j = divmod(port - 1, 8)
    return i, 0x80 >> j


def portlist_has_bit(raw: bytes, port: int) -> bool:
    """Ist Bridge-Port `port` in der PortList `raw` gesetzt? Ports hinter dem letzten Byte gelten als nicht gesetzt."""
    i, mask = _portlist_pos(port)
    return i < len(raw) and bool(raw[i] & mask)


def _portlist_write_pos(port: int) -> tuple[int, int]:
    """_portlist_pos for set / clear, which also refuse a port beyond MAX_BRIDGE_PORT (ValueError, before anything is allocated): a
    written PortList then never grows past MAX_PORTLIST_BYTES, whatever bridge port number an agent made up (its bit would otherwise
    stretch the list to (port - 1) // 8 + 1 bytes, 512 MiB for 4294967295). portlist_has_bit needs no such bound, it allocates nothing."""
    if port > MAX_BRIDGE_PORT:
        raise ValueError(f"PortList-Portnummern enden bei {MAX_BRIDGE_PORT} (BRIDGE-MIB), nicht bei {port}")
    return _portlist_pos(port)


def portlist_set_bit(raw: bytes, port: int) -> bytes:
    """Neue PortList mit gesetztem Bit fuer `port`, alle anderen Bits unveraendert. Zu kurzes `raw` wird mit Nullbytes verlaengert."""
    i, mask = _portlist_write_pos(port)
    buf = bytearray(raw.ljust(i + 1, b"\x00"))
    buf[i] |= mask
    return bytes(buf)


def portlist_clear_bit(raw: bytes, port: int) -> bytes:
    """Neue PortList mit geloeschtem Bit fuer `port`, alle anderen Bits und die Laenge unveraendert (zu kurzes `raw` wie bei set verlaengert)."""
    i, mask = _portlist_write_pos(port)
    buf = bytearray(raw.ljust(i + 1, b"\x00"))
    buf[i] &= 0xFF ^ mask
    return bytes(buf)


def portlist_to_hex(raw: bytes) -> str:
    """PortList als Hex ohne Trennzeichen in Grossbuchstaben (ein Token, z. B. als Wert vom Typ `x` bei snmpset)."""
    return raw.hex().upper()


def fmt_mac(raw: bytes) -> str:
    return ":".join(f"{x:02x}" for x in raw[:6])
