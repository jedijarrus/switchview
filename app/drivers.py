"""Treiber-Registry: was ein Switch-Typ kann und wie man ihn per SNMP anspricht.

Reine Daten, ohne I/O und ohne Umgebung. Jeder Switch hat genau einen Treiber (switches.driver). Die Pfadwahl (SSH-CLI oder SNMP)
und die SNMP-Schreib-Engine fragen nur hier nach, was erlaubt ist und welche OIDs gelten.

caps (Faehigkeiten):
  cli         SSH-CLI-Pfad (gestuft, mit Backup); nur ProCurve
  snmp_vlan   VLAN-Zugehoerigkeit (untagged / tagged / PVID) per SNMP lesen und schreiben
  snmp_admin  Port auf / ab (ifAdminStatus)
  snmp_name   Portname (ifAlias)
  snmp_poe    PoE ein / aus und Status; ob ein Port PoE hat, zeigt erst der Poll
  nac         802.1X / MAC-Auth / RADIUS; nur ueber die CLI, also nur ProCurve
  backup      Config-Backup und Diff; nur ueber die CLI, also nur ProCurve
vlan_strategy (wie ein Access-Port sein VLAN bekommt):
  qbridge     Q-BRIDGE-MIB: dot1qPvid plus die Egress- und Untagged-PortLists des VLANs
  cisco_vmps  Access-Ports ueber vmVlan (CISCO-VLAN-MEMBERSHIP-MIB); Trunk-Mitglieder weiter ueber dot1q
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Driver:
    """Profil eines Switch-Typs. Wird nie veraendert; oids (ein dict) macht ihn nicht hashbar, als Schluessel dient name."""
    name: str
    caps: frozenset[str]
    vlan_strategy: str
    oids: dict[str, str]
    notes: str


# Standard-Profil: Basis-OIDs ohne Instanz-Index (der Aufrufer haengt ".<index>" an), ohne fuehrenden Punkt wie in poller.O.
#   Schluessel  Objekt                        Typ                       Instanz-Index
#   pvid        dot1qPvid                     Unsigned32                .<Bridge-Port> (dot1dBasePort, NICHT der ifIndex)
#   egress      dot1qVlanStaticEgressPorts    PortList                  .<VLAN-ID> (Static-, nicht die Current-Tabelle)
#   untagged    dot1qVlanStaticUntaggedPorts  PortList                  .<VLAN-ID>
#   ifadmin     ifAdminStatus                 1 = up, 2 = down          .<ifIndex>
#   ifalias     ifAlias                       DisplayString (max. 64)   .<ifIndex>
#   poe_admin   pethPsePortAdminEnable        TruthValue (1 an, 2 aus)  .<Gruppe>.<Port> (pethPsePortGroupIndex.pethPsePortIndex)
#   poe_status  pethPsePortDetectionStatus    nur lesen                 .<Gruppe>.<Port>
# poe_*: pethPsePortEntry ist ...105.1.1.1 und die Spalte folgt direkt (3 bzw. 6). Die Schreibweise ...105.1.1.1.1.3 aus der Spec hat
# ein ".1" zu viel: ...105.1.1.1.1 ist die Indexspalte pethPsePortGroupIndex (not-accessible), dorthin laesst sich nichts schreiben.
_STANDARD_OIDS = {
    "pvid": "1.3.6.1.2.1.17.7.1.4.5.1.1",
    "egress": "1.3.6.1.2.1.17.7.1.4.3.1.2",
    "untagged": "1.3.6.1.2.1.17.7.1.4.3.1.4",
    "ifadmin": "1.3.6.1.2.1.2.2.1.7",
    "ifalias": "1.3.6.1.2.1.31.1.1.1.18",
    "poe_admin": "1.3.6.1.2.1.105.1.1.1.3",
    "poe_status": "1.3.6.1.2.1.105.1.1.1.6",
}
# Nur fuer vlan_strategy "cisco_vmps": vmVlan (CISCO-VLAN-MEMBERSHIP-MIB), INTEGER 0..4095, schreibbar, .<ifIndex>
_VMVLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"

_SNMP_CAPS = frozenset({"snmp_vlan", "snmp_admin", "snmp_name", "snmp_poe"})
_CLI_CAPS = frozenset({"cli", "nac", "backup"})

_UNGEPRUEFT = (
    "Standard-Profil (Q-BRIDGE, IF-MIB, POWER-ETHERNET-MIB); SET-Unterstuetzung und herstellerspezifische Abweichungen "
    "(Index-Offsets, PoE-MIB-Variante) sind noch nicht gegen ein Geraet bestaetigt."
)

# Jede Zeile bekommt ihr eigenes oids-dict (dict(...)), damit sich Treiber nie ein veraenderbares Profil teilen.
DRIVERS: dict[str, Driver] = {d.name: d for d in (
    Driver(
        "procurve", _SNMP_CAPS | _CLI_CAPS, "qbridge", dict(_STANDARD_OIDS),
        "HPE ProCurve / AOS-S. Standardweg ist die SSH-CLI (gestuft, Backup, NAC), SNMP nur als Fallback. Die PVID darf nicht in der "
        "Tagged-Liste stehen; ein SNMP-Set loest implizit write-mem aus (kein Staging).",
    ),
    Driver("aruba_cx", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Aruba AOS-CX. " + _UNGEPRUEFT),
    Driver(
        "cisco", _SNMP_CAPS, "cisco_vmps", {**_STANDARD_OIDS, "vmvlan": _VMVLAN},
        "Cisco IOS (klassisch). Access-VLAN ueber vmVlan statt ueber Q-BRIDGE-Untagged; Trunk-Mitglieder weiter ueber dot1q.",
    ),
    Driver(
        "cisco_sb", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS),
        "Cisco Small Business (SG/CBS), kein klassisches IOS. Angenommen: Q-BRIDGE statt vmVlan; nicht gegen ein Geraet bestaetigt.",
    ),
    Driver("comware", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "HPE/H3C Comware. " + _UNGEPRUEFT),
    Driver("juniper", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Juniper Junos (EX/QFX). " + _UNGEPRUEFT),
    Driver("arista", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Arista EOS. " + _UNGEPRUEFT),
    Driver("dell", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Dell Networking. " + _UNGEPRUEFT),
    Driver("netgear", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Netgear Smart/Managed Switches. " + _UNGEPRUEFT),
    Driver("mikrotik", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "MikroTik RouterOS. " + _UNGEPRUEFT),
    Driver(
        "generic", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS),
        "Reine Standard-MIBs (Q-BRIDGE, IF-MIB, POWER-ETHERNET-MIB) ohne Herstellerannahmen; Fallback fuer unbekannte Treibernamen.",
    ),
)}


def driver_for(row) -> Driver:
    """Der Treiber einer switches-Zeile (sqlite3.Row oder dict).

    Leer (NULL / '', Altzeilen von vor der Spalte) heisst procurve, also weiter der SSH-Weg wie bisher. Ein unbekannter Name heisst
    generic (nur Standard-MIBs, kein CLI). Fehlt die Spalte "driver" in der Zeile ganz, ist das ein Fehler der Abfrage: es gibt
    KeyError / IndexError statt eines stillen procurve.
    """
    return DRIVERS.get(row["driver"] or "procurve", DRIVERS["generic"])


def can(driver: Driver, op: str) -> bool:
    """Hat der Treiber die Faehigkeit op? Ein unbekannter Name ist False (im Zweifel gesperrt), nie ein Fehler."""
    return op in driver.caps
