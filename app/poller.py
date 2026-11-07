"""SNMP-Abfrage eines Switches und Ablage in der DB (nur lesend)."""
import asyncio
import json
import logging
import re
from collections import Counter
from collections.abc import Container
from datetime import datetime, timezone

import drivers
import snmp
from crypto import decrypt, unreadable
from db import db

log = logging.getLogger("switchview.poller")

O = {  # noqa: E741  (poller.O is used by every walk and the tests)
    "sysDescr": "1.3.6.1.2.1.1.1",
    "sysUpTime": "1.3.6.1.2.1.1.3",
    "sysName": "1.3.6.1.2.1.1.5",
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ifOper": "1.3.6.1.2.1.2.2.1.8",
    "ifAdmin": "1.3.6.1.2.1.2.2.1.7",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "bp2if": "1.3.6.1.2.1.17.1.4.1.2",
    "baseMac": "1.3.6.1.2.1.17.1.1",
    "vlanName": "1.3.6.1.2.1.17.7.1.4.3.1.1",
    "vlanEgress": "1.3.6.1.2.1.17.7.1.4.3.1.2",
    "vlanUntagged": "1.3.6.1.2.1.17.7.1.4.3.1.4",
    "pvid": "1.3.6.1.2.1.17.7.1.4.5.1.1",
    "fid": "1.3.6.1.2.1.17.7.1.4.2.1.3",
    "fdb": "1.3.6.1.2.1.17.7.1.2.2.1.2",
    "ifStack": "1.3.6.1.2.1.31.1.2.1.3",
    "lldpSys": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "lldpPortId": "1.0.8802.1.1.2.1.4.1.1.7",
}
HEX = {"baseMac", "vlanEgress", "vlanUntagged"}
# Free text the display poller walks with -Ox like the write path (R18, snmpwrite.TEXT_AS_HEX is this tuple): without MIBs net-snmp prints
# an OCTET STRING with a byte it does not count as printable (each byte of an umlaut in UTF-8) as bare hex, a printable one as text,
# and the two cannot be told apart; with -Ox every value is hex, and _display_text turns it back into text. LLDP stays a text walk:
# lldpRemPortId can be a binary value (a MAC), and _links compares it as the switch sends it.
TEXT_AS_HEX = ("ifAlias", "vlanName")
# The walks whose failure keeps the values of the last poll (poll_switch), a failure being an error or a walk that broke off after some
# rows (snmp.Rows.broken_off): the MAC table needs both FDB walks and bp2if (which port a bridge port is), the LLDP neighbours all of
# the remote table's walks (and, at a driver that selects its ports by ifType, bp2if and lldpLocPortTable, see lldp_walks). Both
# carry the uplink protection (changes.inventory): an empty or cut table would leave a link that only they show unprotected. So does
# the base MAC (baseMac) for every other switch that learns it: a failed baseMac walk keeps the stored one.
MAC_WALKS = ("fdb", "fid", "bp2if")
LLDP_WALKS = ("lldpSys", "lldpPortDesc", "lldpPortId")
# What a partial poll says about a value it kept because its walk failed (partial_note): kept from the last poll, or, where that one
# had none (or there was no last poll), what is missing instead
KEPT_NOTES = {
    "macs": ("MAC-Tabelle vom letzten Poll behalten", "MAC-Tabelle unvollständig (nichts vom letzten Poll zu behalten)"),
    "lldp": ("LLDP vom letzten Poll behalten", "LLDP unvollständig (nichts vom letzten Poll zu behalten)"),
    "baseMac": ("Basis-MAC vom letzten Poll behalten", "Basis-MAC unbekannt (nichts vom letzten Poll zu behalten)"),
}
MAX_PORTS = 4096    # ports per switch (select_ports); more is refused by check_port_count (_build, snmpwrite._synth): no real switch has that many
# LLDP-MIB lldpLocPortTable (lldpLocalSystemData .7, Eintrag .1), Index lldpLocPortNum: welcher eigene Port hinter einer lokalen
# LLDP-Portnummer steht, als PortId und PortDesc, wie der Switch sie sendet. Nicht in O: gewalkt nur fuer einen Treiber, der seine Ports
# nach ifType waehlt (by_iftype), siehe lldp_ports; ProCurve zaehlt LLDP-Ports nach ifIndex.
LLDP_LOC = {"lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3", "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4"}

# Portauswahl nach ifType (IANAifType; der Walk liefert die Zahl), siehe select_ports
PHYS_IFTYPES = frozenset({"6", "117"})  # ethernetCsmacd, gigabitEthernet: physische Ports
LAG_IFTYPE = "161"  # ieee8023adLag: Trunk / LAG (Port-channel, ae, Bridge-Aggregation, lag, ...)
# propVirtual (53) und propMultiplexor (54): als LAG nur mit LAG_NAME und physischem Port darunter (klassisches IOS meldet
# Port-channels so)
NAMED_LAG_IFTYPES = frozenset({"53", "54"})
# Namen, die ein LAG dieser Typen haben muss, jeweils direkt gefolgt von einer Ziffer 0-9, Gross-/Kleinschreibung egal:
#   Po, Port-channel           Cisco (IOS-ifName "Po1"), Arista ("Port-Channel1"), Dell ("Po1", OS10 "port-channel1")
#   ae                         Juniper ("ae0")
#   Bridge-Aggregation, BAGG   HPE/H3C Comware (lang und kurz)
#   lag                        Aruba AOS-CX ("lag1")
#   ch                         Channel-Gruppen mancher Smart-Switches ("ch1")
#   Trk                        HPE ProCurve / AOS-S ("Trk1"), falls so ein Switch unter einem anderen Treiber laeuft
LAG_NAME = re.compile(r"(?:Po|Port-channel|ae|Bridge-Aggregation|BAGG|lag|ch|Trk)[0-9]", re.IGNORECASE)

# PoE (Faehigkeit snmp_poe): Walk-Schluessel -> Schluessel der OID in driver.oids. Nicht in O: die OIDs kommen aus dem Treiber (R4), sie
# haengen an ihm (Leistung und Zuordnung je Hersteller), und gewalkt wird nur, wo er PoE hat (siehe poe_walks, poe_ports).
POE_OIDS = {"poeAdmin": "poe_admin", "poeStatus": "poe_status", "poeEntPhy": "poe_entphy", "entAlias": "ent_alias", "poePower": "poe_power"}
_SUBID = r"(?:0|[1-9][0-9]{0,9})"    # ein OID-Bestandteil, wie net-snmp ihn druckt (32 Bit: hoechstens 10 Ziffern, keine fuehrende Null)
_POE_INDEX = re.compile(rf"({_SUBID})\.({_SUBID})")    # <pethPsePortGroupIndex>.<pethPsePortIndex>
_NUMBER = re.compile(_SUBID)
_IFINDEX_ROW = re.compile(r"\.?1\.3\.6\.1\.2\.1\.2\.2\.1\.1\.([1-9][0-9]{0,9})")    # RowPointer auf eine ifTable-Zeile: ifIndex.<N>
_VLAN_INDEX = re.compile(r"[1-9][0-9]{0,3}")    # a VLAN ID as a walk prints it: ASCII digits, no leading zero (1..4094 checks int)
# Hex pairs as a walk with -Ox prints an OCTET STRING, separated by ASCII whitespace only (bytes.fromhex skips no other)
_HEX_PAIRS = re.compile(r"[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*", re.ASCII)

_locks: dict[int, asyncio.Lock] = {}


WRITE_DISABLED = "SNMP-Schreiben ist für diesen Switch nicht aktiviert"
NO_WRITE_CREDS = "Keine SNMP-Schreib-Zugangsdaten hinterlegt"
PUBLIC_COMMUNITY = "Community 'public' wird nicht zum Schreiben verwendet – bitte eine eigene Schreib-Community hinterlegen"


def creds_of(row, write: bool = False) -> dict:
    """Die SNMP-Identitaet einer switches-Zeile als cred fuer snmp.walk / get / set_vars (Schluessel, wie snmp._auth_args und
    snmp._conf_lines sie lesen).

    write=False: die Lese-Identitaet (snmp_version, snmp_community bzw. snmp_user ...), unveraendert wie seit jeher.
    write=True: die Schreib-Identitaet fuer SNMP-SETs, oder snmp.SnmpError mit dem Grund; Regel und Gruende siehe write_identity.
    """
    if write:
        return write_identity(row)[1]
    return {
        "snmp_version": row["snmp_version"],
        "snmp_community": decrypt(row["snmp_community"]),
        "snmp_user": row["snmp_user"],
        "snmp_auth_proto": row["snmp_auth_proto"],
        "snmp_auth_pass": decrypt(row["snmp_auth_pass"]),
        "snmp_priv_proto": row["snmp_priv_proto"],
        "snmp_priv_pass": decrypt(row["snmp_priv_pass"]),
    }


# How a warning of credential_warnings says that a stored secret does not decrypt
UNREADABLE = "lässt sich nicht entschlüsseln (SECRET_KEY geändert?)"


def credential_warnings(row) -> list[str]:
    """What the read path of the switch row does in silence, as German sentences for the switch list, the network map, the connection
    test and the log (poll_switch). creds_of keeps its fallbacks, which keep a switch that answers to them reachable (a community that
    does not decrypt asks with "public", snmp._conf_lines; a v3 passphrase that does not decrypt or is not used lowers the level,
    snmp._level); this names each of them. In this order:
    v2c (every snmp_version but "3", like snmp._auth_args): a stored community that does not decrypt, or none at all;
    v3: no user; an auth passphrase that does not decrypt, or one that decrypts but is not used (no auth protocol); a priv passphrase that
    does not decrypt, or one that decrypts but is not used (the level is not authPriv);
    and for a driver with SSH-CLI an SSH password that does not decrypt (sshcli._device then refuses the session, nothing is sent)."""
    out = []
    if row["snmp_version"] == "3":
        level = snmp._level(creds_of(row))
        if not row["snmp_user"]:
            out.append("SNMPv3 ohne Benutzer – die Abfrage geht mit leerem Benutzernamen.")
        if unreadable(row["snmp_auth_pass"]):
            out.append(f"SNMPv3-Auth-Kennwort {UNREADABLE} – SwitchView fragt ohne Authentifizierung (noAuthNoPriv). Bitte neu eingeben.")
        elif row["snmp_auth_pass"] and level == "noAuthNoPriv":
            out.append("SNMPv3-Auth-Kennwort ohne Auth-Verfahren – SwitchView fragt ohne Authentifizierung (noAuthNoPriv).")
        if unreadable(row["snmp_priv_pass"]):
            out.append(f"SNMPv3-Priv-Kennwort {UNREADABLE} – SwitchView fragt ohne Verschlüsselung. Bitte neu eingeben.")
        elif row["snmp_priv_pass"] and level != "authPriv":
            out.append("SNMPv3-Priv-Kennwort wird nicht benutzt (ohne Verschlüsselungsverfahren oder ohne Authentifizierung) – SwitchView "
                       "fragt ohne Verschlüsselung.")
    elif unreadable(row["snmp_community"]):
        out.append(f"Lese-Community {UNREADABLE} – SwitchView fragt mit „public“. Bitte neu eingeben.")
    elif not row["snmp_community"]:
        out.append("Keine Lese-Community hinterlegt – SwitchView fragt mit „public“.")
    if drivers.can(drivers.driver_for(row), "cli") and unreadable(row["ssh_pass"]):
        out.append(f"SSH-Kennwort {UNREADABLE} – SSH geht erst nach neuer Eingabe.")
    return out


def write_identity(row) -> tuple[str, dict]:
    """Mit welcher Identitaet SNMP-SETs an diesen Switch gehen: ("rw" | "read", cred). Die EINE Stelle, die das entscheidet
    (creds_of(row, write=True) ist ihr cred, die Anzeige in main._public ihre Quelle). Read-only-Zugangsdaten werden nie still
    schreibfaehig, darum snmp.SnmpError mit dem Grund statt eines Ersatzes:

    1. snmp_write aus: Fehler, auch wenn Schreib-Zugangsdaten hinterlegt sind.
    2. eine eigene RW-Identitaet ("rw"): der v3-Benutzer snmp_rw_user mit snmp_rw_auth_* / snmp_rw_priv_*, sonst die v2c-Community
       snmp_rw_community. Der v3-Benutzer gewinnt, wenn beide gesetzt sind (die Community bleibt dann ungelesen).
    3. sonst die Lese-Identitaet ("read", muss am Geraet schreiben duerfen), nach snmp_version und nur eine echte: v3 mit Benutzer,
       v2c mit nicht leerer Community. Aus einer leeren Community machte snmp._conf_lines "public".
    4. sonst Fehler: keine Schreib-Zugangsdaten.
    Die Community "public" (gleich welche Schreibweise, Leerraum aussen egal) schreibt nie (R25), weder als snmp_rw_community noch
    ueber die Lese-Identitaet: Fehler statt eines Rueckgriffs auf die naechste Identitaet. Sticht der v3-Benutzer eine RW-Community
    "public" aus, schreibt sie nicht und ist kein Grund zur Ablehnung.
    Ein Geheimnis der gewaehlten Identitaet, das sich nicht entschluesseln laesst, und ein v3-Kennwort, das snmp._conf_lines nicht
    verwenden wuerde, sind ebenfalls Fehler: sonst ginge der SET still mit einer anderen Identitaet oder einer schwaecheren Stufe
    hinaus. Ein Protokoll ohne Kennwort ist dagegen kein Fehler (das Switch-Formular schickt die Protokoll-Auswahl immer mit), es
    heisst: unbenutzt.
    """
    if not row["snmp_write"]:
        raise snmp.SnmpError(WRITE_DISABLED)
    if row["snmp_rw_user"]:
        return "rw", _write_v3(row, "snmp_rw_")
    if row["snmp_rw_community"]:
        return "rw", _write_v2c(row, "snmp_rw_community")
    if row["snmp_version"] == "3":
        if row["snmp_user"]:
            return "read", _write_v3(row, "snmp_")
    elif row["snmp_community"]:
        return "read", _write_v2c(row, "snmp_community")
    raise snmp.SnmpError(NO_WRITE_CREDS)


def write_authpriv(row) -> bool:
    """Whether SNMP SETs to this switch go out with SNMPv3 authPriv (write_identity, its level as snmp._level computes it): neither a
    v2c community nor v3 without privacy shows to whoever answers at the address. False also without a write identity (snmp.SnmpError).
    api_changes._choose_mechanism lets SNMP take over after a refused SSH host key only then."""
    try:
        return snmp._level(write_identity(row)[1]) == "authPriv"
    except snmp.SnmpError:
        return False


def _write_secret(row, key: str) -> str | None:
    """Das Geheimnis row[key] im Klartext fuer die Schreib-Identitaet, None wenn keins gespeichert ist. Ein gespeichertes, das sich nicht
    entschluesseln laesst (decrypt gibt dann None), ist ein Fehler und nie "nicht gesetzt"."""
    if not row[key]:
        return None
    value = decrypt(row[key])
    if not value:
        raise snmp.SnmpError(f"SNMP-Schreib-Zugangsdaten nicht lesbar: {key} lässt sich nicht entschlüsseln (SECRET_KEY geändert?)")
    return value


def _write_v2c(row, key: str) -> dict:
    """v2c mit der Community row[key]; nur fuer einen gesetzten key, also nie leer und nie "public" per Vorgabe. Eine gespeicherte
    Community "public" ist ein Fehler (R25)."""
    community = _write_secret(row, key)
    if community.strip().lower() == "public":
        raise snmp.SnmpError(PUBLIC_COMMUNITY)
    return {"snmp_version": "2c", "snmp_community": community, "snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None,
            "snmp_priv_proto": None, "snmp_priv_pass": None}


def _write_v3(row, prefix: str) -> dict:
    """v3 mit dem Benutzer row[prefix + "user"] und dessen auth/priv-Spalten (prefix "snmp_rw_" oder "snmp_"). Stufe wie snmp._auth_args:
    authPriv mit beiden Paaren, authNoPriv mit Auth-Paar, sonst noAuthNoPriv."""
    ap, apass = row[prefix + "auth_proto"], _write_secret(row, prefix + "auth_pass")
    pp, ppass = row[prefix + "priv_proto"], _write_secret(row, prefix + "priv_pass")
    auth = bool(ap and apass)
    if apass and not auth:
        raise snmp.SnmpError("SNMPv3-Schreib-Zugang unvollständig: Auth-Kennwort ohne Auth-Verfahren")
    if ppass and not (auth and pp):
        raise snmp.SnmpError("SNMPv3-Schreib-Zugang unvollständig: Priv-Kennwort ohne Verschlüsselungsverfahren oder ohne Authentifizierung")
    return {"snmp_version": "3", "snmp_community": None, "snmp_user": row[prefix + "user"], "snmp_auth_proto": ap, "snmp_auth_pass": apass,
            "snmp_priv_proto": pp, "snmp_priv_pass": ppass}


def parse_descr(descr: str) -> tuple[str, str]:
    m = re.search(r"\b(J\w{4,5}|JL\w{3,4})\s+(?:Switch\s+)?([\w\-+]+)", descr or "")
    model = f"{m.group(1)} {m.group(2)}" if m else (descr or "")[:40]
    f = re.search(r"revision\s+([\w.]+)", descr or "")
    return model, (f.group(1) if f else "")


def _tbl(rows: list[tuple[str, str]], base: str) -> dict[str, str]:
    p = base + "."
    return {oid[len(p):]: val for oid, val in rows if oid.startswith(p)}


def is_vlan_index(v: str) -> bool:
    """Is v (an index of the VLAN table) a VLAN ID 1..4094 as a walk prints it: ASCII digits, no leading zero?"""
    return bool(_VLAN_INDEX.fullmatch(v)) and int(v) <= 4094


def _display_text(value: str) -> str:
    """A free-text value of the display poll (TEXT_AS_HEX, walked with -Ox) as text: hex pairs, outer whitespace aside, decoded by
    snmp.octets_text (UTF-8, else latin-1); any other value stays as it is."""
    hexed = value.strip()
    return snmp.octets_text(hexed) if _HEX_PAIRS.fullmatch(hexed) else value


def _ascii_number(value: str, digits: int) -> int | None:
    """value as a number when it is 1 to `digits` ASCII digits, else None (int() takes other digits, such as "²", and fails on them,
    or on more than 4300 digits)."""
    return int(value) if 0 < len(value) <= digits and value.isascii() and value.isdigit() else None


def _fdb_mac(octets: list[str]) -> str | None:
    """The MAC of an FDB index's last six parts ("0.26.43.0.0.10" -> "00:1a:2b:00:00:0a"), None unless each is an ASCII number 0..255."""
    values = [_ascii_number(x, 3) for x in octets]
    if len(values) != 6 or any(v is None or v > 255 for v in values):
        return None
    return ":".join(f"{v:02x}" for v in values)


def lldp_walks(driver_name: str) -> tuple[str, ...]:
    """The walks the LLDP neighbours of a poll come from (poll_switch): LLDP_WALKS, and where the driver selects its ports by ifType
    bp2if and LLDP_LOC, the tables lldp_ports finds a neighbour's port with (only there is lldpLocPortTable walked; a ProCurve counts
    its LLDP ports by ifIndex)."""
    return LLDP_WALKS + (("bp2if", *LLDP_LOC) if by_iftype(driver_name) else ())


def check_port_count(ports: list[str]) -> None:
    """snmp.SnmpError when select_ports found more than MAX_PORTS ports: the display (_build) and the write path (snmpwrite._synth)
    refuse such a switch with this one message (no real switch has that many, and every port is tested against every VLAN)."""
    if len(ports) > MAX_PORTS:
        raise snmp.SnmpError(f"Mehr als {MAX_PORTS} Ports gemeldet, Abfrage abgebrochen")


def by_iftype(driver_name: str) -> bool:
    """Waehlt select_ports die Ports dieses Treibers nach ifType? Ja fuer jeden ausser procurve, auch fuer einen unbekannten Namen
    (drivers.driver_for nimmt dafuer generic). Nur dann braucht es den ifType-Walk."""
    return driver_name != "procurve"


def select_ports(ifname: dict[str, str], iftype: dict[str, str], ifstack: dict[str, str], driver_name: str
                 ) -> tuple[list[str], dict[str, str], dict[str, list[str]]]:
    """Welche Interfaces Ports sind und welche Trunks sie bilden. Die eine Stelle, an der Anzeige (_build) und Schreibweg
    (snmpwrite.build_cfg) das entscheiden, damit beide denselben Switch sehen.

    Eingaben sind _tbl-Tabellen: ifname {ifIndex: ifName}, iftype {ifIndex: ifType}, ifstack {"hoeher.tiefer": Status}. Ergebnis, alles
    als ifIndex: (Ports in ifIndex-Reihenfolge, member_of {Mitglied: Trunk}, members {Trunk: [Mitglieder in ifStack-Reihenfolge]}).
    Ein Port braucht in jedem Fall einen ifName und einen ganzzahligen ifIndex.

    procurve, genau wie seit jeher (iftype bleibt ungenutzt): Port ist ein Interface mit ifIndex < 1000, dessen Name weder VLAN
    enthaelt noch mit LO beginnt noch LOOPBACK enthaelt (Gross-/Kleinschreibung egal). Mitglied ist, was im ifStack unter einem
    Interface namens Trk... steht; members fuehrt nur Trunks mit Mitgliedern (ein leerer TrkN ist ueber seinen Namen Trunk).

    Jeder andere Treiber, nach ifType, ohne ifIndex-Grenze: Port ist ein Interface vom Typ 6 / 117 (physisch) oder ein LAG. LAG
    ist ein Interface vom Typ 161, und eines vom Typ 53 (propVirtual) oder 54 (propMultiplexor), dessen Name zu LAG_NAME passt und
    unter dem im ifStack direkt mindestens ein physischer Port steht (so meldet klassisches IOS seine Port-channels; Name und
    physisches Mitglied halten SVIs, Stack-Ports und logische Units wie ge-0/0/0.0 oder ae0.0 heraus). Alles andere ist kein Port,
    auch ein Interface ohne ifType-Zeile: VLAN-Interfaces, Loopback, Null, Tunnel, Subinterfaces, Stack-Ports, ... Trunk ist jeder
    LAG-Port: members fuehrt ihn, ein 161er auch ohne Mitglieder (dann mit []). Mitglied ist, was im ifStack direkt unter ihm steht;
    was unter einem anderen Interface steht (unter einem Subinterface oder einer logischen Unit), ist kein Mitglied.
    """
    member_of: dict[str, str] = {}
    members: dict[str, list[str]] = {}
    order = sorted(ifname, key=lambda x: int(x) if x.isdigit() else 10**9)
    if not by_iftype(driver_name):
        for k in ifstack:
            hi, _, lo = k.partition(".")
            if hi != "0" and lo != "0" and ifname.get(hi, "").startswith("Trk"):
                member_of[lo] = hi
                members.setdefault(hi, []).append(lo)
        ports = []
        for ifi in order:
            if not ifi.isdigit() or int(ifi) >= 1000:
                continue
            up = ifname[ifi].upper()
            if "VLAN" in up or up.startswith("LO") or "LOOPBACK" in up:
                continue
            ports.append(ifi)
        return ports, member_of, members
    physical = {ifi for ifi in ifname if ifi.isdigit() and iftype.get(ifi) in PHYS_IFTYPES}
    over_physical = set()  # Interfaces, unter denen im ifStack direkt ein physischer Port steht (wie unten ein Mitglied)
    for k in ifstack:
        hi, _, lo = k.partition(".")
        if hi != "0" and lo != "0" and lo in physical:
            over_physical.add(hi)

    def is_lag(ifi: str) -> bool:
        if iftype.get(ifi) == LAG_IFTYPE:
            return True
        return iftype.get(ifi) in NAMED_LAG_IFTYPES and ifi in over_physical and LAG_NAME.match(ifname[ifi]) is not None

    ports = [ifi for ifi in order if ifi in physical or (ifi.isdigit() and is_lag(ifi))]
    members = {ifi: [] for ifi in ports if ifi not in physical}
    for k in ifstack:
        hi, _, lo = k.partition(".")
        if hi != "0" and lo != "0" and hi in members:
            member_of[lo] = hi
            members[hi].append(lo)
    return ports, member_of, members


def trunk_ports(ifname: dict[str, str], ports: list[str], members: dict[str, list[str]], driver_name: str) -> set[str]:
    """Die Trunks unter den Ports von select_ports (ifIndex): bei ProCurve jedes Interface namens Trk..., auch ein leeres, sonst jeder LAG
    (select_ports fuehrt ihn in members). Die uebrigen Ports sind physisch."""
    if by_iftype(driver_name):
        return {ifi for ifi in ports if ifi in members}
    return {ifi for ifi in ports if ifname[ifi].startswith("Trk")}


def poe_walks(driver: drivers.Driver, power: bool = False) -> dict[str, str]:
    """Die PoE-Walks fuer driver, {Walk-Schluessel: Basis-OID aus driver.oids}: leer ohne snmp_poe (R31), sonst pethPsePortAdminEnable und
    pethPsePortDetectionStatus, bei poe_index "cisco_entity" dazu die beiden Tabellen der Zuordnung (cpeExtPsePortEntPhyIndex,
    entAliasMappingIdentifier); mit power (nur die Anzeige) die Leistung je Port, wo der Treiber eine OID dafuer hat."""
    if not drivers.can(driver, "snmp_poe"):
        return {}
    keys = ["poeAdmin", "poeStatus"]
    if driver.poe_index == "cisco_entity":
        keys += ["poeEntPhy", "entAlias"]
    if power and "poe_power" in driver.oids:
        keys.append("poePower")
    return {k: driver.oids[POE_OIDS[k]] for k in keys}


def _poe_order(index: str) -> tuple[int, int]:
    """Sortierschluessel eines PoE-Index "<Gruppe>.<Port>": nach Gruppe, dann Port, als Zahlen; ein unlesbarer dahinter."""
    m = _POE_INDEX.fullmatch(index)
    return (int(m.group(1)), int(m.group(2))) if m else (2**32, 2**32)


def poe_listing(indexes) -> str:
    """PoE-Indexe fuer eine Meldung: nach Gruppe und Port, hoechstens fuenf, dann ", ..."."""
    listed = sorted(indexes, key=lambda k: (_poe_order(k), k))
    return ", ".join(listed[:5]) + (", ..." if len(listed) > 5 else "")


def _poe_number(table: dict[str, str], index: str, column: str, strict: bool, allowed: tuple[str, ...] = ()) -> int | None:
    """Der Wert von column.<index> als Zahl (None ohne Zeile). Nur einer aus allowed, sonst jede Zahl; einen anderen gibt es mit strict
    als ValueError, sonst als None."""
    value = table.get(index)
    if value is None:
        return None
    if (value in allowed) if allowed else bool(_NUMBER.fullmatch(value)):
        return int(value)
    if strict:
        raise ValueError(f"{column}.{index} ist weder 1 (an) noch 2 (aus): {value!r}" if allowed else f"{column}.{index} ist keine Zahl: {value!r}")
    return None


def poe_ports(driver: drivers.Driver, tables: dict[str, dict[str, str]], ifname: dict[str, str], ports: list[str], members: dict[str, list[str]],
              strict: bool = False) -> tuple[dict[str, dict], list[str]]:
    """Welcher PoE-Eintrag zu welchem Port gehoert, und was er sagt: die EINE Stelle dafuer, fuer die Anzeige (_build) und den Schreibweg
    (snmpwrite.build_cfg). Ein PoE-SET auf den falschen Eintrag schaltet ein anderes Geraet ab (Telefon, Access Point, Kamera), darum
    zaehlt nur eine sichere Zuordnung: was nicht sicher passt, gehoert zu keinem Port, und ein Port ohne Eintrag hat kein PoE, weder in
    der Anzeige noch zum Schreiben.

    tables: _tbl-Tabellen der Walks aus poe_walks(driver) (ein fehlender Walk ist leer); ifname, ports, members: wie select_ports sie
    fuer driver.name liefert. Zugeordnet wird nur ein physischer Port, einer der ports ohne die von trunk_ports: PoE hat nur ein
    physischer Port. Ein Trunk-Mitglied ist einer und behaelt so seinen PoE-Zustand (Anzeige, cfg, raw); schreiben laesst ihn die
    Mitglied-Regel nicht (R36). Die PoE-Eintraege sind die Indexe der Admin- und der Status-Spalte. Wie ihr
    <pethPsePortGroupIndex>.<pethPsePortIndex> zum ifIndex steht, legt RFC 3621 nicht fest; das sagt driver.poe_index:
      ifindex       (nur ProCurve, R35) Gruppe 1 und pethPsePortIndex = ifIndex. Ein Eintrag einer anderen Gruppe (ein weiteres
                    Stack-Mitglied, ein Modul) gehoert zu keinem Port. Zeigt ein Eintrag der Gruppe 1 auf keinen physischen Port (kein
                    Interface, eins, das kein Port ist, ein Trunk), gilt die Annahme fuer diesen Switch nicht, etwa weil er Ports
                    durchzaehlt, statt den ifIndex zu nehmen: dann gehoert KEIN Eintrag zu einem Port, auch keiner, der zufaellig passte.
      cisco_entity  cpeExtPsePortEntPhyIndex des Eintrags (entPhysicalIndex seines Ports, 0 = keiner) und dessen
                    entAliasMappingIdentifier-Zeilen (ENTITY-MIB): zeigen sie, bei jedem logischen Index, auf genau ein ifIndex.N und
                    ist N ein physischer Port, gehoert der Eintrag zu ihm. Eine Zeile, die auf etwas anderes zeigt (keine ifTable-Zeile,
                    0.0), zaehlt nicht: neben einer ifIndex-Zeile entscheidet die (wie im Beispiel von RFC 6933), allein laesst sie den
                    Eintrag ohne Port.
      none, jede andere  kein Eintrag gehoert zu einem Port.
    Zeigen zwei Eintraege auf denselben Port, gehoert keiner von beiden zu ihm.

    Ergebnis: ({ifIndex: {"group", "index", "admin", "status", "power"}}, [PoE-Indexe "<Gruppe>.<Port>" ohne Port, nach Gruppe und Port]).
    group / index sind Zahlen, admin (1 an, 2 aus), status (pethPsePortDetectionStatus) und power (mW, aus poePower) Zahlen, None ohne
    lesbare Zeile.

    strict (der Schreibweg, R5): nichts wird uebersprungen. snmp.SnmpError, wenn die Spalten einer Tabellenzeile nicht dieselben Eintraege
    haben (Admin und Status; bei cisco_entity cpeExtPsePortEntPhyIndex, er erweitert pethPsePortEntry; fehlt er ganz, etwa auf einem IOS
    ohne ihn, ist kein Eintrag zuordenbar, aber nichts falsch); ValueError fuer einen Index, der nicht <Gruppe>.<Port> ist, einen
    Admin-Wert ausser 1 / 2, einen Status oder entPhysicalIndex, der keine Zahl ist, und einen Index von entAliasMappingIdentifier, der
    nicht <entPhysicalIndex>.<logischer Index> ist. Ohne strict (die Anzeige) faellt nur das Unlesbare weg."""
    trunks = trunk_ports(ifname, ports, members, driver.name)
    phys = {ifi for ifi in ports if ifi not in trunks}
    admin, status = tables.get("poeAdmin", {}), tables.get("poeStatus", {})
    if strict and set(admin) != set(status):
        raise snmp.SnmpError("PoE-Tabelle unvollständig gelesen: Admin- und Status-Spalte passen nicht zusammen "
                             f"(Eintrag {poe_listing(set(admin) ^ set(status))})")
    rows: dict[str, tuple[int, int]] = {}    # PoE-Index -> (Gruppe, Port), nach Gruppe und Port
    for k in sorted(set(admin) | set(status), key=lambda k: (_poe_order(k), k)):
        m = _POE_INDEX.fullmatch(k)
        if m:
            rows[k] = (int(m.group(1)), int(m.group(2)))
        elif strict:
            raise ValueError(f"PoE-Index {k!r} ist nicht <Gruppe>.<Port>")
    entries = {k: {"group": g, "index": i, "admin": _poe_number(admin, k, "pethPsePortAdminEnable", strict, ("1", "2")),
                   "status": _poe_number(status, k, "pethPsePortDetectionStatus", strict),
                   "power": _poe_number(tables.get("poePower", {}), k, "poePower", False)} for k, (g, i) in rows.items()}
    if driver.poe_index == "ifindex":
        first = {k: k.partition(".")[2] for k, (g, _) in rows.items() if g == 1}
        target = first if all(ifi in phys for ifi in first.values()) else {}
    elif driver.poe_index == "cisco_entity":
        target = _poe_entities(rows, tables, phys, strict)
    else:
        target = {}
    claims = Counter(target.values())
    found = {ifi: entries[k] for k, ifi in target.items() if claims[ifi] == 1}
    return found, [k for k in rows if k not in target or claims[target[k]] > 1]


def _poe_entities(rows: dict[str, tuple[int, int]], tables: dict[str, dict[str, str]], phys: set[str], strict: bool) -> dict[str, str]:
    """poe_index "cisco_entity" (siehe poe_ports): {PoE-Index: ifIndex} ueber cpeExtPsePortEntPhyIndex und entAliasMappingIdentifier."""
    entphy, alias = tables.get("poeEntPhy", {}), tables.get("entAlias", {})
    if strict and entphy and set(entphy) != set(rows):
        raise snmp.SnmpError("PoE-Tabelle unvollständig gelesen: cpeExtPsePortEntPhyIndex passt nicht zu den PoE-Einträgen "
                             f"(Eintrag {poe_listing(set(entphy) ^ set(rows))})")
    ifis: dict[str, set[str]] = {}    # entPhysicalIndex -> ifIndexe, auf die seine Alias-Zeilen zeigen
    for k, v in alias.items():
        e, dot, logical = k.partition(".")
        if not (_NUMBER.fullmatch(e) and dot and _NUMBER.fullmatch(logical)):
            if strict:
                raise ValueError(f"entAliasMappingIdentifier: Index {k!r} ist nicht <entPhysicalIndex>.<logisch>")
            continue
        m = _IFINDEX_ROW.fullmatch(v)
        if m:
            ifis.setdefault(e, set()).add(m.group(1))
    target = {}
    for k in rows:
        e = entphy.get(k)
        if e is None:
            continue
        if not _NUMBER.fullmatch(e):
            if strict:
                raise ValueError(f"cpeExtPsePortEntPhyIndex.{k} ist keine Zahl: {e!r}")
            continue
        candidates = ifis.get(e, set())
        if e != "0" and len(candidates) == 1 and next(iter(candidates)) in phys:
            target[k] = next(iter(candidates))
    return target


def lldp_ports(num: str, ports: list[str], ifname: dict[str, str], bp2if: dict[str, str], loc: dict[str, dict[str, str]]) -> set[str]:
    """Zu welchen Ports (ifIndex aus ports, select_ports) ein LLDP-Eintrag mit der lokalen Portnummer num (lldpRemLocalPortNum) gehoert,
    bei einem Treiber, der seine Ports nach ifType waehlt (R40). LLDP-MIB zaehlt lokale Ports nach LldpPortNumber, bei einer Bridge der
    dot1dBasePort; nur ProCurve nimmt dafuer den ifIndex (dort gilt num = ifIndex, wie seit jeher, ohne diese Funktion). Weil Hersteller
    das eine wie das andere tun, und manche eine eigene Zaehlung, die lldpLocPortTable aufloest (loc: _tbl-Tabellen von LLDP_LOC), gehoert
    der Eintrag zu ALLEN Ports, die num meinen kann:
      - bp2if[num], wenn num ein Bridge-Port ist,
      - dem Port mit dem ifIndex num,
      - dem Port, dessen ifName lldpLocPortId[num] oder lldpLocPortDesc[num] ist, nur wenn genau ein Port passt.
    Derselbe Nachbar kann so an mehr als einem Port stehen: im Zweifel mehr Uplinks (mehr Schutz), nie einer zu wenig."""
    out = {ifi for ifi in (bp2if.get(num), num) if ifi in ports}
    names = {v.strip() for v in (loc.get("lldpLocPortId", {}).get(num), loc.get("lldpLocPortDesc", {}).get(num)) if v and v.strip()}
    named = [ifi for ifi in ports if ifname[ifi] in names]
    if len(named) == 1:
        out.add(named[0])
    return out


def utc_now() -> str:
    """Now in UTC as the poll stores it (switches.last_poll, macs.last_seen; history.record takes a sighting's time from there):
    YYYY-MM-DD HH:MM:SS. poll_switch takes its time only from here (the clock of the tests)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


async def poll_switch(switch_id: int, *, record: bool = True) -> dict:
    """Polls the switch and stores what it read; the result is {"ok": True, "ports": n, "macs": n} or {"ok": False, "error": text}.
    Each poll keeps its switch's poll state (poll_failures, down_since, last_ok_at, unread_fields) and then tells its events
    (monitor.poll_succeeded with the ports it replaced, or monitor.poll_failed), wrapped: a failure is logged ("Ereignisse <host>")
    and changes nothing of the result. With record (a single poll: "Jetzt abfragen", the poll after a change) a good poll records
    its sightings right away (history.record), wrapped as well. poll_all records once for its whole round."""
    import monitor  # late: monitor → poller
    lock = _locks.setdefault(switch_id, asyncio.Lock())
    async with lock:
        async with db() as conn:
            async with conn.execute("SELECT * FROM switches WHERE id = ?", (switch_id,)) as cur:
                row = await cur.fetchone()
        if not row:
            raise ValueError("Switch nicht gefunden")
        host, cred = row["host"], creds_of(row)
        for warning in credential_warnings(row):    # the fallbacks creds_of keeps, told once per poll
            log.warning("%s: %s", host, warning)
        driver_name = row["driver"] or "procurve"
        # Walks, ohne die es kein Ergebnis gibt: sysName und ifName, dazu ifType, wo select_ports nach ihm waehlt (ohne ifType
        # stuende der Switch sonst bis zum naechsten Poll ohne Ports da)
        needed = ("sysName", "ifName", "ifType") if by_iftype(driver_name) else ("sysName", "ifName")
        # Dazu die PoE-Walks des Treibers mit der Leistung, nachsichtig wie jeder andere hier (ohne snmp_poe keiner), und wo die Ports nach
        # ifType gewaehlt werden die LLDP-Tabelle der eigenen Ports (lldp_ports)
        walks = {**O, **poe_walks(drivers.driver_for(row), power=True), **(LLDP_LOC if by_iftype(driver_name) else {})}
        now = utc_now()
        failed: dict[str, Exception] = {}    # walks that failed and that _build uses for this driver, in walk order
        broken: set[str] = set()    # walks that broke off after some rows (snmp.Rows.broken_off), kept ones or not (monitor)
        keeping = set(MAC_WALKS) | set(lldp_walks(driver_name))    # the walks with kept values: one that broke off counts as failed
        try:
            keys = list(walks)
            # One byte budget for all the walks of this poll (the tasks of gather inherit it): a hostile agent fills at most
            # snmp.MAX_POLL_BYTES of stdout per poll, not 8 MiB (snmp.MAX_STDOUT) for each of its 20-odd walks
            with snmp.byte_budget(snmp.MAX_POLL_BYTES):
                results = await asyncio.gather(*(snmp.walk(host, cred, walks[k], hex_values=k in HEX or k in TEXT_AS_HEX) for k in keys),
                                               return_exceptions=True)
            W = {}
            for k, r in zip(keys, results):
                if isinstance(r, Exception):
                    if k in needed:
                        raise r
                    log.warning("%s: Walk %s fehlgeschlagen: %s", host, k, r)
                    if k != "ifType" or by_iftype(driver_name):    # a ProCurve does not use ifType (select_ports)
                        failed[k] = r
                    r = []
                elif getattr(r, "broken_off", None):
                    # A lenient walk that ended with an exit code != 0 after some rows (snmp.Rows): its table is cut. Of the walks with
                    # kept values, a row it did not reach may be the one that protects an uplink: failed, like one without rows, its rows
                    # join the kept ones. Any other one is taken as it came, but its table counts as unread for the drift (monitor).
                    broken.add(k)
                    if k in keeping:
                        log.warning("%s: Walk %s abgebrochen: %s", host, k, r.broken_off)
                        failed[k] = snmp.SnmpError(r.broken_off)
                W[k] = r
            if by_iftype(driver_name) and _tbl(W["ifName"], O["ifName"]) and not _tbl(W["ifType"], O["ifType"]):
                # Kein Fehler, aber keine einzige Zeile (leere oder verbotene View): ohne ifType kaemen keine Ports heraus, und das
                # Speichern unten loeschte die des letzten guten Polls. Also wie ein gescheiterter Pflicht-Walk.
                raise snmp.SnmpError("ifType-Walk lieferte keine Zeile, ifName schon: ohne ifType lassen sich die Ports nicht bestimmen")
            # In a worker thread: a big (or hostile) switch must not hold up the event loop, the UI and the other polls meanwhile
            data = await asyncio.to_thread(_build, W, driver_name)
        except Exception as e:  # noqa: BLE001
            async with db() as conn:
                await conn.execute("UPDATE switches SET last_poll = ?, last_poll_ok = 0, last_error = ?, poll_failures = poll_failures + 1 "
                                   "WHERE id = ?", (now, str(e)[:300], switch_id))
                await conn.commit()
            log.warning("Abfrage %s fehlgeschlagen: %s", host, e)
            try:
                await monitor.poll_failed(row, str(e), now)
            except Exception:  # noqa: BLE001
                log.exception("Ereignisse %s", host)
            return {"ok": False, "error": str(e)}

        # Every walk this poll did not read completely: a failed one, and one that broke off, also outside `keeping` (its rows are taken
        # as they came, but a cut VLAN or PVID table would read as a change). Its fields are stored with the poll (unread_fields), so
        # the next poll does not compare against them either (monitor.unread_fields is pure)
        incomplete = set(failed) | broken
        unread = json.dumps(sorted(monitor.unread_fields(incomplete, data)))

        # A failed walk that carries the uplink protection keeps what the last poll stored, and what this poll read of the same table
        # joins it (an empty or cut table would leave a link only it shows unprotected; a fresh row may be the only one that shows a
        # new link): the MAC rows stay and the rows read now go on top (mac_count is then the port's rows of the merged table), the
        # LLDP neighbours of a port (by its name) are the ones read now and then the kept ones, without a fresh one that a kept one
        # covers (merge_lldp: the same neighbour, shortened by the failed walk); a failed baseMac walk keeps the stored base MAC,
        # which every other switch that learns it protects its port with
        keep_macs = any(k in failed for k in MAC_WALKS)
        keep_lldp = any(k in failed for k in lldp_walks(driver_name))
        keep_base = "baseMac" in failed
        async with db() as conn:
            kept: dict[str, bool] = {}    # KEPT_NOTES key -> whether the last poll had any of it (partial_note)
            last_lldp: dict[str, list] = {}    # port name -> LLDP entries as the last poll stored them
            # The ports as the last good poll stored them, by name: what this one replaces (monitor.poll_succeeded compares them)
            async with conn.execute("SELECT name, alias, admin, pvid, untagged, tagged, trunk, lldp FROM ports WHERE switch_id = ?",
                                    (switch_id,)) as cur:
                old = {r["name"]: r for r in await cur.fetchall()}
            if keep_macs:
                async with conn.execute("SELECT 1 FROM macs WHERE switch_id = ? LIMIT 1", (switch_id,)) as cur:
                    kept["macs"] = await cur.fetchone() is not None
            if keep_lldp:
                last_lldp = {name: json.loads(r["lldp"] or "[]") for name, r in old.items()}
                kept["lldp"] = any(last_lldp.values())
            if keep_base:
                kept["baseMac"] = bool(row["base_mac"])    # read under this switch's poll lock: no other poll wrote it since
            note = partial_note(failed, kept, data["vlan_rows_skipped"])
            base_mac = row["base_mac"] if keep_base else data["baseMac"]

            await conn.execute(
                "UPDATE switches SET sys_name=?, sys_descr=?, model=?, firmware=?, base_mac=?, uptime=?, last_poll=?, last_poll_ok=1, "
                "last_error=?, poll_failures=0, down_since=NULL, last_ok_at=?, unread_fields=? WHERE id=?",
                (data["sysName"], data["sysDescr"], data["model"], data["firmware"], base_mac, data["uptime"], now, note, now, unread,
                 switch_id),
            )
            await conn.execute("DELETE FROM ports WHERE switch_id = ?", (switch_id,))
            await conn.execute("DELETE FROM vlans WHERE switch_id = ?", (switch_id,))
            fresh = data["macs"]
            if not keep_macs:
                await conn.execute("DELETE FROM macs WHERE switch_id = ?", (switch_id,))
            elif "fid" in failed:
                # Without dot1qVlanFdbId a row read now carries its FID as VLAN (_build): a MAC the kept table has at that port already
                # only refreshes the last_seen of its rows, a second row under the FID would show it twice
                async with conn.execute("SELECT port, mac FROM macs WHERE switch_id = ?", (switch_id,)) as cur:
                    known = {(r["port"], r["mac"]) for r in await cur.fetchall()}
                await conn.executemany("UPDATE macs SET last_seen = ? WHERE switch_id = ? AND port = ? AND mac = ?",
                                       [(now, switch_id, port, mac) for port, mac, _ in fresh if (port, mac) in known])
                fresh = [(port, mac, vlan) for port, mac, vlan in fresh if (port, mac) not in known]
            await conn.executemany(
                "INSERT OR REPLACE INTO macs(switch_id, port, mac, vlan, last_seen) VALUES (?,?,?,?,?)",
                [(switch_id, port, mac, vlan, now) for port, mac, vlan in fresh],
            )
            counts: dict[str, int] = {}    # port name -> its rows in the merged MAC table (keep_macs)
            if keep_macs:
                async with conn.execute("SELECT port, COUNT(*) AS n FROM macs WHERE switch_id = ? GROUP BY port", (switch_id,)) as cur:
                    counts = {r["port"]: r["n"] for r in await cur.fetchall()}

            def mac_count(p: dict) -> int:
                # the MAC rows sit at the trunk of a member (as build_map reads them), and _build counts the trunk's for it
                return counts.get(p["trunk"] or p["name"], 0) if keep_macs else p["mac_count"]

            def lldp(p: dict) -> str:
                return json.dumps(merge_lldp(p["lldp"], last_lldp.get(p["name"], []), failed))

            await conn.executemany(
                "INSERT INTO ports(switch_id, ifindex, name, alias, oper, admin, speed, pvid, untagged, tagged, trunk, members, lldp, mac_count, "
                "poe_admin, poe_status, poe_power) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(switch_id, p["if"], p["name"], p["alias"], p["oper"], p["admin"], p["speed"], p["pvid"], json.dumps(p["untagged"]),
                  json.dumps(p["tagged"]), p["trunk"], json.dumps(p["members"]), lldp(p), mac_count(p), p["poe_admin"],
                  p["poe_status"], p["poe_power"]) for p in data["ports"]],
            )
            await conn.executemany("INSERT INTO vlans(switch_id, vid, name) VALUES (?,?,?)", [(switch_id, v, n) for v, n in data["vlans"].items()])
            await conn.commit()
        try:
            await monitor.poll_succeeded(row, old, data, incomplete, now)
        except Exception:  # noqa: BLE001
            log.exception("Ereignisse %s", host)
        if record:
            import history  # late: history → topology → changes → poller
            try:
                await history.record([switch_id])
            except Exception:  # noqa: BLE001
                log.exception("Verlauf %s", host)
        return {"ok": True, "ports": len(data["ports"]), "macs": len(data["macs"])}


def merge_lldp(fresh: list[list[str]], kept: list[list[str]], failed: Container[str]) -> list[list[str]]:
    """The LLDP entries of a port ([sysName, PortDesc or PortId, PortId], _build) after a poll whose LLDP walks may have failed:
    fresh are the ones read now, kept the ones the last poll stored (empty unless an LLDP walk failed), failed the names of the
    failed walks (the dict `failed` of poll_switch). The fresh entries, then every kept one not among them, as before Phase 5; but a
    fresh entry is left out when a kept one other than it covers it: the same sysName, and each field equal, except a field of a
    failed walk that came out missing (field 1 equal to field 2 once lldpPortDesc failed, as _build falls back to the PortId; field
    2 empty once lldpPortId failed). Then the kept entry is the same neighbour at the same port, and it makes every claim the
    shortened one makes (topology._lldp_claims reads the name and fields 1 and 2): display only, the uplink protection keeps all it
    had. A field a walk that broke off did read counts (snmp.Rows.broken_off: its rows before the break are real), so a neighbour
    that moved to another port stays listed with both, as before. Without a failed lldpPortDesc or lldpPortId walk only an equal
    entry covers, and that one does not count. A kept entry from before R40 (two fields) covers only through its first two."""
    desc_failed, id_failed = "lldpPortDesc" in failed, "lldpPortId" in failed

    def covers(k: list[str], e: list[str]) -> bool:
        return (k != e and k[:1] == e[:1] and (k[1:2] == e[1:2] or (desc_failed and e[1] == e[2]))
                and (k[2:3] == e[2:3] or (id_failed and not e[2])))

    return [e for e in fresh if not any(covers(k, e) for k in kept)] + [k for k in kept if k not in fresh]


def partial_note(failed: dict[str, Exception], kept: dict[str, bool], vlan_rows_skipped: int) -> str | None:
    """last_error of a poll that went through with gaps ("Teilweise gelesen: ..."), None without any: the failed walks the driver uses
    (in walk order, with the first one's error, at most 300 characters of it, as a failed poll stores), then for each value the poll
    kept of the last one (kept: KEPT_NOTES key -> whether the last poll had any) that it was kept, or, with nothing to keep, what is
    missing, then the VLAN rows _build skipped."""
    parts = []
    if failed:
        parts.append(f"{', '.join(failed)} fehlgeschlagen ({str(next(iter(failed.values())))[:300]})")
    parts += [KEPT_NOTES[what][0 if had else 1] for what, had in kept.items()]
    if vlan_rows_skipped:
        parts.append(f"{vlan_rows_skipped} VLAN-Zeilen ohne gültige VLAN-ID (1–4094) übersprungen")
    return "Teilweise gelesen: " + "; ".join(parts) if parts else None


def _build(W: dict, driver_name: str = "procurve") -> dict:
    """Die Anzeige-Daten aus den Walks W (Schluessel wie O, dazu die von poe_walks des Treibers und LLDP_LOC; ein fehlender ist leer).
    Welche Interfaces Ports und Trunks sind, entscheidet select_ports nach dem Treiber; ifType wird nur gelesen, wenn er danach waehlt. PoE je
    Port (poe_admin, poe_status, poe_power in mW) nur, wo poe_ports ihm einen Eintrag sicher zuordnet, nachsichtig: sonst None. LLDP je
    Port als [sysName, PortDesc oder PortId, PortId]: bei ProCurve am Port mit dem ifIndex der lokalen LLDP-Portnummer, sonst an jedem
    Port, den sie meinen kann (lldp_ports).

    ifAlias and vlanName come from a walk with -Ox (TEXT_AS_HEX) and are decoded by _display_text. A number the display cannot use
    costs only its own value, never the poll: sysUpTime counts only as ASCII digits (at most 10, a TimeTicks), ifHighSpeed only as
    ASCII digits up to 9 (else 0), a bridge port index only as ASCII digits up to 10 (else it is no bridge port), an FDB row only with
    six ASCII numbers 0..255 as its MAC (else it is skipped). The VLAN table (name, egress, untagged) counts only rows whose index
    is a VLAN ID 1..4094 (is_vlan_index); the indexes of the others are counted in "vlan_rows_skipped". More than MAX_PORTS ports
    (select_ports) are a snmp.SnmpError: no real switch has them, and every port is tested against every VLAN."""
    sysName = (W["sysName"][0][1] if W["sysName"] else "")
    sysDescr = (W["sysDescr"][0][1] if W["sysDescr"] else "")
    model, fw = parse_descr(sysDescr)
    ticks = _ascii_number(W["sysUpTime"][0][1], 10) if W["sysUpTime"] else None
    uptime = ticks // 100 if ticks is not None else None
    base = snmp.fmt_mac(snmp.hex_to_bytes(W["baseMac"][0][1])) if W["baseMac"] else ""

    ifname = _tbl(W["ifName"], O["ifName"])
    alias = {k: _display_text(v) for k, v in _tbl(W["ifAlias"], O["ifAlias"]).items()}
    speed = _tbl(W["ifHighSpeed"], O["ifHighSpeed"])
    oper = _tbl(W["ifOper"], O["ifOper"])
    admin = _tbl(W["ifAdmin"], O["ifAdmin"])
    bp2if = _tbl(W["bp2if"], O["bp2if"])
    if2bp = {v: k for k, v in bp2if.items() if _ascii_number(k, 10) is not None}    # "3.0" is no bridge port
    vlan_tables = {k: _tbl(W[k], O[k]) for k in ("vlanName", "vlanEgress", "vlanUntagged")}
    vlan_rows_skipped = len({vid for table in vlan_tables.values() for vid in table if not is_vlan_index(vid)})
    vname = {k: _display_text(v) for k, v in vlan_tables["vlanName"].items() if is_vlan_index(k)}
    # PortList bytes per VLAN, at most snmp.MAX_PORTLIST_BYTES each (ValueError beyond); membership below is a bit test, no set per VLAN
    egress = {k: snmp.portlist_bytes(v) for k, v in vlan_tables["vlanEgress"].items() if is_vlan_index(k)}
    untag = {k: snmp.portlist_bytes(v) for k, v in vlan_tables["vlanUntagged"].items() if is_vlan_index(k)}
    pvid = _tbl(W["pvid"], O["pvid"])

    # LLDP-Nachbarn: [sysName, PortDesc (sonst PortId), PortId] (R40: PortId ab jetzt immer dabei, die Stelle 1 wie seit jeher), je
    # lokaler Portnummer (lldpRemLocalPortNum, der mittlere Teil des Index); zu welchem Port sie gehoert, steht unten nach select_ports
    entries: list[tuple[str, list[str]]] = []
    l_desc = _tbl(W["lldpPortDesc"], O["lldpPortDesc"])
    l_id = _tbl(W["lldpPortId"], O["lldpPortId"])
    for k, v in _tbl(W["lldpSys"], O["lldpSys"]).items():
        parts = k.split(".")
        if len(parts) < 3 or not v.strip():
            continue
        pid = l_id.get(k, "")
        pd = l_desc.get(k, "") or pid
        entries.append((parts[1], [v.strip(), pd.strip(), pid.strip()]))

    fid2vlan = {}
    for k, v in _tbl(W["fid"], O["fid"]).items():
        fid2vlan[v] = k.split(".")[-1]
    fdb_by_bp: dict[str, list[tuple[str, str]]] = {}
    for k, bp in _tbl(W["fdb"], O["fdb"]).items():
        parts = k.split(".")
        mac = _fdb_mac(parts[1:]) if len(parts) == 7 else None
        if mac is None:
            continue
        fdb_by_bp.setdefault(bp, []).append((mac, fid2vlan.get(parts[0], parts[0])))

    iftype = _tbl(W["ifType"], O["ifType"]) if by_iftype(driver_name) else {}
    port_ifis, member_of, members = select_ports(ifname, iftype, _tbl(W["ifStack"], O["ifStack"]), driver_name)
    check_port_count(port_ifis)
    lldp: dict[str, list[list[str]]] = {}    # ifIndex -> LLDP-Eintraege
    if by_iftype(driver_name):
        loc = {k: _tbl(W.get(k, []), base) for k, base in LLDP_LOC.items()}
        for num, entry in entries:
            for ifi in lldp_ports(num, port_ifis, ifname, bp2if, loc):
                lldp.setdefault(ifi, []).append(entry)
    else:    # ProCurve: die lokale Portnummer ist der ifIndex, wie seit jeher
        for num, entry in entries:
            lldp.setdefault(num, []).append(entry)
    # Trunk: bei ProCurve jedes Trk-Interface (auch ohne Mitglieder), sonst jeder LAG-Port (select_ports fuehrt ihn in members)
    trunks = trunk_ports(ifname, port_ifis, members, driver_name)
    driver = drivers.driver_for({"driver": driver_name})
    poe, _ = poe_ports(driver, {k: _tbl(W.get(k, []), base) for k, base in poe_walks(driver, power=True).items()}, ifname, port_ifis,
                       members)
    ports, macs = [], []
    for ifi in port_ifis:
        name = ifname[ifi]
        is_trk = ifi in trunks
        trk = member_of.get(ifi)
        eff = if2bp.get(trk) if trk else if2bp.get(ifi)
        b = int(eff) if eff else 0    # 0: no bridge port (PortList bits start at bridge port 1)
        un = sorted([v for v in vname if b > 0 and snmp.portlist_has_bit(untag.get(v, b""), b)], key=int)
        tg = sorted([v for v in vname if b > 0 and snmp.portlist_has_bit(egress.get(v, b""), b)
                     and not snmp.portlist_has_bit(untag.get(v, b""), b)], key=int)
        fdb = fdb_by_bp.get(eff, []) if eff else []
        if not trk:  # MACs nur einmal ablegen (am Trunk bzw. am Einzelport)
            macs += [(name, m, v) for m, v in fdb]
        pe = poe.get(ifi, {})
        ports.append({
            "if": int(ifi), "name": name, "alias": alias.get(ifi, ""),
            "oper": 1 if oper.get(ifi) == "1" else 0, "admin": 1 if admin.get(ifi) == "1" else 0,
            "speed": _ascii_number(speed.get(ifi, ""), 9) or 0, "pvid": pvid.get(eff, "") if eff else "",
            "untagged": un, "tagged": tg,
            "trunk": ifname.get(trk, "") if trk else (name if is_trk else ""),
            "members": [ifname.get(m, m) for m in members.get(ifi, [])] if is_trk else [],
            "lldp": lldp.get(ifi, []), "mac_count": len(fdb),
            "poe_admin": pe.get("admin"), "poe_status": pe.get("status"), "poe_power": pe.get("power"),
        })
    return {"sysName": sysName, "sysDescr": sysDescr, "model": model, "firmware": fw, "uptime": uptime, "baseMac": base,
            "vlans": {k: vname[k] for k in sorted(vname, key=int)}, "ports": ports, "macs": macs, "vlan_rows_skipped": vlan_rows_skipped}


async def poll_all():
    """One round: every enabled switch, four at a time, then the sightings of every good poll recorded at once (history.record, one
    build_map for the round: the uplink rule needs the links of all switches), wrapped like each poll."""
    async with db() as conn:
        async with conn.execute("SELECT id FROM switches WHERE enabled = 1") as cur:
            ids = [r["id"] for r in await cur.fetchall()]
    sem = asyncio.Semaphore(4)
    good: list[int] = []

    async def one(i):
        async with sem:
            try:
                if (await poll_switch(i, record=False))["ok"]:
                    good.append(i)
            except Exception:  # noqa: BLE001
                log.exception("Abfrage Switch %s", i)

    await asyncio.gather(*(one(i) for i in ids))
    import history  # late: history → topology → changes → poller
    try:
        await history.record(good)
    except Exception:  # noqa: BLE001
        log.exception("Verlauf der Abfragerunde (%d %s)", len(good), "Switch" if len(good) == 1 else "Switches")
