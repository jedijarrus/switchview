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
    """Startet cmd ohne Shell und liefert stdout. SnmpError bei Zeitueberschreitung und bei einem Exit-Code != 0 ohne Ausgabe;
    mit strict bei JEDEM Exit-Code != 0, auch wenn stdout schon Zeilen hat (siehe walk)."""
    env = dict(os.environ, MIBS="")
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
    text = out.decode("utf-8", "replace")
    if proc.returncode != 0 and (strict or not text.strip()):
        msg = err.decode("utf-8", "replace").strip().splitlines()
        msg = [m for m in msg if "Cannot find module" not in m and "MIB search path" not in m]
        raise SnmpError(msg[-1] if msg else f"snmp Exit-Code {proc.returncode}")
    return text


def _host(host: str) -> str:
    """host, wenn er als Ziel an net-snmp gehen darf. Er steht als eigenes Argument hinter den Optionen, und getopt laese ein "-..."
    dort als Option: SnmpError statt eines Aufrufs. main prueft den Host beim Speichern (HOST_RE), Zeilen von vorher aber nicht."""
    if host.startswith("-"):
        raise SnmpError(f"Host {host!r} darf nicht mit '-' beginnen (net-snmp läse ihn als Option)")
    return host


_HEX_VALUE = re.compile(r"[0-9A-Fa-f\s]*")


def _string_open(oid: str, val: str) -> bool:
    """Ist val ein String in Anfuehrungszeichen, dessen schliessendes Anfuehrungszeichen noch fehlt? net-snmp schreibt \\" und \\\\ im
    String mit Backslash, die schliessen ihn nicht. SnmpError, wenn hinter dem schliessenden Anfuehrungszeichen noch etwas steht: das
    gibt net-snmp nie aus. Ein Wert ohne fuehrendes Anfuehrungszeichen (Zahl, Hex, OID) ist nie offen."""
    if not val.startswith('"'):
        return False
    i = 1
    while i < len(val):
        if val[i] == "\\":
            i += 2
        elif val[i] == '"':
            if i != len(val) - 1:
                raise SnmpError(f"Text hinter dem Ende des Strings in {oid}: {val[:80]!r}")
            return False
        else:
            i += 1
    return True


def _parse(text: str, hex_strict: bool = False, text_strict: bool = False) -> list[tuple[str, str]]:
    """Zeilen "OID Wert" -> [(oid, wert)]; eine Zeile ohne OID gehoert als Fortsetzung zum Wert davor (lange Werte bricht net-snmp
    um). Leerzeilen und Zeilen vor der ersten OID gehoeren zu keinem Wert. Die beiden strikten Modi aendern an den Zeilen nichts, sie
    lehnen nur ab (SnmpError), was nicht zu einem Wert gehoeren kann:

    hex_strict (ein strikter Hex-Walk, mit -Ox): jeder Wert, mit seinen Fortsetzungszeilen, muss reines Hex sein. Eine fremde Zeile
    hinter einer PortList (etwa "End of MIB") wuerde sonst angehaengt, und hex_to_bytes machte aus ihren Buchstaben a-f Bits fuer
    Bridge-Ports, die es nicht gibt.

    text_strict (ein strikter Walk ohne -Ox): umbrechen kann nur ein String in Anfuehrungszeichen, Zahlen und andere nackte Werte
    nie. Eine Fortsetzungszeile gilt also nur, solange ein String offen ist; jede andere (hinter einer Zahl, hinter einem
    geschlossenen String) ist eine fremde Zeile, die sonst im letzten Wert landete, etwa in einem ifAlias, den ein Revert auf den
    Switch zurueckschriebe. Ein String muss vor der naechsten Zeile mit OID und vor dem Ende der Ausgabe geschlossen sein, und
    hinter seinem schliessenden Anfuehrungszeichen darf nichts mehr stehen (siehe _string_open)."""
    rows: list[tuple[str, str]] = []
    open_string = False  # nur text_strict: der Wert der letzten Zeile ist ein String, dessen Ende noch fehlt
    for line in text.splitlines():
        if line.startswith("."):
            if open_string:
                raise SnmpError(f"String ohne Ende in {rows[-1][0]}: {rows[-1][1][:80]!r}")
            oid, _, val = line.partition(" ")
            rows.append((oid.lstrip("."), val.strip()))
            open_string = text_strict and _string_open(*rows[-1])
        elif rows and line.strip():
            if text_strict and not open_string:
                raise SnmpError(f"Unerwartete Zeile hinter dem Wert von {rows[-1][0]}: {line[:80]!r}")
            # Fortsetzung eines mehrzeiligen Strings
            oid, val = rows[-1]
            rows[-1] = (oid, val + "\n" + line)
            open_string = text_strict and _string_open(*rows[-1])
    if open_string:
        raise SnmpError(f"String ohne Ende in {rows[-1][0]}: {rows[-1][1][:80]!r}")
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


def bitmap_ports(val: str) -> set[int]:
    """Q-BRIDGE PortList: Bit 1 (MSB des ersten Bytes) = Bridge-Port 1."""
    b = hex_to_bytes(val)
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
