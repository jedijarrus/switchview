"""SNMP-Zugriff ueber net-snmp: Lesen mit snmpbulkwalk/snmpget (walk, get), Schreiben mit snmpset (set_vars).

Lesen: Ausgabe immer numerisch (-On), ohne Typ (-Oq), Enums als Zahl (-Oe),
Timeticks als Zahl (-Ot). Bitmaps (VLAN-Portlisten, MACs) mit -Ox als Hex.
"""
import asyncio
import os
import re

AUTH_PROTOS = {"SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "MD5"}
PRIV_PROTOS = {"AES", "AES-192", "AES-256", "DES"}
# snmpset: 5 s je Versuch, eine Wiederholung (siehe set_vars)
SET_TIMING = ("-t", "5", "-r", "1")
# What one SNMP call may hand to the app, whatever the agent sends (a hostile or broken one must not fill the memory):
MAX_STDOUT = 8 * 1024 * 1024    # bytes of stdout per call; 64 000 MACs are about 4 MB (see _run)
MAX_STDERR = 64 * 1024          # bytes of stderr kept per call; the rest is read and dropped (see _run)
MAX_ROWS = 100_000              # values per walk, rows with an OID (see _parse)
MAX_PORTLIST_BYTES = 8192       # a PortList over bridge ports 1..65535 (dot1dBasePort) needs no more (see portlist_bytes)
READ_CHUNK = 64 * 1024          # _run reads stdout and stderr in pieces of this size


class SnmpError(Exception):
    pass


def _auth_args(cred: dict) -> list[str]:
    if cred.get("snmp_version") == "3":
        user = cred.get("snmp_user") or ""
        args = ["-v3", "-u", user]
        ap, apass = cred.get("snmp_auth_proto"), cred.get("snmp_auth_pass")
        pp, ppass = cred.get("snmp_priv_proto"), cred.get("snmp_priv_pass")
        if ap and apass and pp and ppass:
            args += ["-l", "authPriv", "-a", ap, "-A", apass, "-x", pp, "-X", ppass]
        elif ap and apass:
            args += ["-l", "authNoPriv", "-a", ap, "-A", apass]
        else:
            args += ["-l", "noAuthNoPriv"]
        return args
    return ["-v2c", "-c", cred.get("snmp_community") or "public"]


async def _run(cmd: list[str], timeout: float, strict: bool = False) -> str:
    """Start cmd without a shell and return its stdout. stdout and stderr are read together, READ_CHUNK bytes at a time, up to EOF, then
    the exit is awaited, all under the one timeout. SnmpError on a timeout; when stdout grows beyond MAX_STDOUT (the process is killed,
    see _collect); and on an exit code != 0 without output, with strict on EVERY exit code != 0, even when stdout has rows already (see
    walk). The message of a failed call is the last line of stderr, of which only the first MAX_STDERR bytes are kept."""
    env = dict(os.environ, MIBS="")
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
    )
    try:
        out, err, returncode = await asyncio.wait_for(_collect(proc), timeout=timeout)
    except asyncio.TimeoutError:
        _kill(proc)
        raise SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
    text = out.decode("utf-8", "replace")
    if returncode != 0 and (strict or not text.strip()):
        msg = err.decode("utf-8", "replace").strip().splitlines()
        msg = [m for m in msg if "Cannot find module" not in m and "MIB search path" not in m]
        raise SnmpError(msg[-1] if msg else f"snmp Exit-Code {returncode}")
    return text


async def _collect(proc) -> tuple[bytearray, bytes, int]:
    """(stdout, the first MAX_STDERR bytes of stderr, exit code) of proc, read the way _run says. Once stdout grows beyond MAX_STDOUT,
    proc is killed and, after its exit, SnmpError raised. Both pipes are read to EOF in every case, stderr alongside stdout: a process
    blocked on a full stderr pipe would never finish its stdout, and asyncio closes the process transport only once both pipes have
    closed. A pipe whose reader has paused because nobody reads it any more never does, not even after the kill: its transport would
    leak, and a wait() that came before the exit was noticed would hang."""
    stderr = asyncio.create_task(_drain(proc.stderr, MAX_STDERR))
    try:
        out = bytearray()
        while chunk := await proc.stdout.read(READ_CHUNK):
            out += chunk
            if len(out) > MAX_STDOUT:
                _kill(proc)
                await _drain(proc.stdout, 0)    # what the killed process left in the pipe, dropped
                break
        err = await stderr
        returncode = await proc.wait()
    finally:
        stderr.cancel()    # still running only when the timeout cancels the call: the reader must not outlive it
    if len(out) > MAX_STDOUT:
        raise SnmpError(f"SNMP-Antwort zu groß (über {MAX_STDOUT // (1024 * 1024)} MiB), Abfrage abgebrochen")
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
    """
    cmd = ["snmpbulkwalk", *_auth_args(cred), "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", "-Cr25"]
    if hex_values:
        cmd.append("-Ox")
    cmd += [_host(host), oid]
    return _parse(await _run(cmd, timeout, strict=strict), hex_strict=strict and hex_values, text_strict=strict and not hex_values)


async def get(host: str, cred: dict, oids: list[str], timeout: float = 15) -> dict[str, str]:
    cmd = ["snmpget", *_auth_args(cred), "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", _host(host), *oids]
    return dict(_parse(await _run(cmd, timeout)))


async def set_vars(host: str, cred: dict, varbinds: list[tuple[str, str, str]], timeout: float = 20) -> str:
    """snmpset: schreibt alle `varbinds` = [(oid, typ, wert), ...] mit EINEM Aufruf und liefert die Ausgabe von snmpset.

    `cred` ist die Schreib-Identitaet (RW-Community bzw. v3-User); der Aufrufer baut sie, hier geht sie unveraendert an _auth_args.
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
    return await _run(cmd, timeout)


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


def portlist_set_bit(raw: bytes, port: int) -> bytes:
    """Neue PortList mit gesetztem Bit fuer `port`, alle anderen Bits unveraendert. Zu kurzes `raw` wird mit Nullbytes verlaengert."""
    i, mask = _portlist_pos(port)
    buf = bytearray(raw.ljust(i + 1, b"\x00"))
    buf[i] |= mask
    return bytes(buf)


def portlist_clear_bit(raw: bytes, port: int) -> bytes:
    """Neue PortList mit geloeschtem Bit fuer `port`, alle anderen Bits und die Laenge unveraendert (zu kurzes `raw` wie bei set verlaengert)."""
    i, mask = _portlist_pos(port)
    buf = bytearray(raw.ljust(i + 1, b"\x00"))
    buf[i] &= 0xFF ^ mask
    return bytes(buf)


def portlist_to_hex(raw: bytes) -> str:
    """PortList als Hex ohne Trennzeichen in Grossbuchstaben (ein Token, z. B. als Wert vom Typ `x` bei snmpset)."""
    return raw.hex().upper()


def fmt_mac(raw: bytes) -> str:
    return ":".join(f"{x:02x}" for x in raw[:6])
