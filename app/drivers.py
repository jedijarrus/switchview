"""Treiber-Registry: was ein Switch-Typ kann und wie man ihn per SNMP anspricht.

Reine Daten, ohne I/O und ohne Umgebung. Jeder Switch hat genau einen Treiber (switches.driver). Die Pfadwahl (SSH-CLI oder SNMP)
und die SNMP-Schreib-Engine fragen nur hier nach, was erlaubt ist und welche OIDs gelten.

caps (Faehigkeiten):
  cli         SSH-CLI-Pfad (gestuft, mit Backup); nur ProCurve
  snmp_vlan   VLAN-Zugehoerigkeit (untagged / tagged / PVID) per SNMP lesen und schreiben
  snmp_admin  Port auf / ab (ifAdminStatus)
  snmp_name   Portname (ifAlias)
  snmp_poe    PoE ein / aus (pethPsePortAdminEnable) und Status; ob ein Port PoE hat, zeigt erst der Read, und nur ein Port, dem
              poller.poe_ports einen PoE-Eintrag sicher zuordnet, hat welches (poe_index). Immer per SNMP, auch bei ProCurve (R30).
              Nur ProCurve und Cisco (R35): nur fuer sie ist belegt, welcher PoE-Eintrag zu welchem Port gehoert
  snmp_autosave  der Switch speichert jeden SNMP-Set selbst dauerhaft (implizites write memory); nur ProCurve. Ohne sie steht eine
              SNMP-Aenderung nur in der laufenden Konfiguration, bis jemand am Switch speichert (R26)
  nac         802.1X / MAC-Auth / RADIUS; nur ueber die CLI, also nur ProCurve
  backup      Config-Backup und Diff; nur ueber die CLI, also nur ProCurve
vlan_strategy (wie ein Access-Port sein VLAN bekommt):
  qbridge     Q-BRIDGE-MIB: dot1qPvid plus die Egress- und Untagged-PortLists des VLANs
  cisco_vmps  Access-Ports ueber vmVlan (CISCO-VLAN-MEMBERSHIP-MIB); Trunk-Mitglieder weiter ueber dot1q
poe_index (wie ein PoE-Eintrag, Index <pethPsePortGroupIndex>.<pethPsePortIndex>, zu seinem Port findet; RFC 3621 legt das nicht fest,
poller.poe_ports wendet es an; was nicht sicher passt, gehoert zu keinem Port):
  none          kein Eintrag gehoert zu einem Port (Vorgabe: ein Treiber ohne belegte Zuordnung schaltet nie PoE)
  ifindex       Gruppe 1 und pethPsePortIndex = ifIndex eines physischen Ports; nur ProCurve / AOS-S (R35: HP nimmt den ifIndex als
                PoE-Port-Index). Zeigt ein Eintrag der Gruppe 1 auf keinen physischen Port, gilt das fuer den Switch nicht, und kein
                Eintrag wird zugeordnet. Bei einem anderen Hersteller koennte ein versetzter Index trotzdem stets auf irgendeinen
                physischen Port zeigen: falsch zugeordnet, und das Pruefen faende es nicht (es liest mit derselben Zuordnung zurueck)
  cisco_entity  CISCO-POWER-ETHERNET-EXT-MIB cpeExtPsePortEntPhyIndex (entPhysicalIndex des PoE-Ports) und ENTITY-MIB
                entAliasMappingIdentifier (entPhysicalIndex -> ifIndex.N); klassisches IOS zaehlt PoE-Eintraege nach Portnummer im
                Stack-Mitglied, seine ifIndexe beginnen bei 10101
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
    poe_index: str = "none"


# Standard-Profil: Basis-OIDs ohne Instanz-Index (der Aufrufer haengt ".<index>" an), ohne fuehrenden Punkt wie in poller.O.
#   Schluessel  Objekt                        Typ                       Instanz-Index
#   pvid        dot1qPvid                     Unsigned32                .<Bridge-Port> (dot1dBasePort, NICHT der ifIndex)
#   egress      dot1qVlanStaticEgressPorts    PortList                  .<VLAN-ID> (Static-, nicht die Current-Tabelle)
#   untagged    dot1qVlanStaticUntaggedPorts  PortList                  .<VLAN-ID>
#   ifadmin     ifAdminStatus                 1 = up, 2 = down          .<ifIndex>
#   ifalias     ifAlias                       DisplayString (max. 64)   .<ifIndex>
#   poe_admin   pethPsePortAdminEnable        TruthValue (1 an, 2 aus)  .<Gruppe>.<Port> (pethPsePortGroupIndex.pethPsePortIndex)
#   poe_status  pethPsePortDetectionStatus    nur lesen                 .<Gruppe>.<Port>
# poe_*: pethPsePortEntry ist ...105.1.1.1 und die Spalte folgt direkt (3 bzw. 6, R4). Nicht ...105.1.1.1.1.3: ...105.1.1.1.1 ist die
# Indexspalte pethPsePortGroupIndex (not-accessible), dorthin laesst sich nichts schreiben.
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
# PoE ueber RFC 3621 hinaus, nur wo ein Hersteller-MIB es festlegt (nur lesen). Beide Leistungs-Tabellen erweitern pethPsePortEntry
# (AUGMENTS), haben also seinen Index .<Gruppe>.<Port>:
#   poe_power   Leistung am Port in mW, nur fuer die Anzeige (best effort)
#     ProCurve  hpicfPoePethPsePortPower (HP-ICF-POE-MIB, "Power supplied at this port", Integer32 in mW): hpicfCommon
#               1.3.6.1.4.1.11.2.14.11.1 (HP-ICF-OID) .9 hpicfPOE .1 hpicfPoe .1 hpicfPoePethPsePortTable .1 Eintrag .3
#     Cisco     cpeExtPsePortPwrConsumption (CISCO-POWER-ETHERNET-EXT-MIB, Unsigned32 "milliwatts"): ciscoMgmt.402 .1 cpeExtMIBObjects
#               .2 cpeExtPsePortTable .1 Eintrag .9 (laut Ciscos eigenem MIB; ein MIB-Browser eines Dritten nennt .8, das ist falsch)
#   poe_entphy  cpeExtPsePortEntPhyIndex (dieselbe Tabelle, Spalte .11): entPhysicalIndex des PoE-Ports, 0 = keiner (nur cisco_entity)
#   ent_alias   entAliasMappingIdentifier (ENTITY-MIB, RFC 6933) .<entPhysicalIndex>.<logischer Index oder 0>: RowPointer auf die
#               ifTable-Zeile des Ports (ifIndex.N) (nur cisco_entity)
_HP_POE_POWER = "1.3.6.1.4.1.11.2.14.11.1.9.1.1.1.3"
_CISCO_POE_POWER = "1.3.6.1.4.1.9.9.402.1.2.1.9"
_CISCO_POE_ENTPHY = "1.3.6.1.4.1.9.9.402.1.2.1.11"
_ENT_ALIAS = "1.3.6.1.2.1.47.1.3.2.1.2"

_SNMP_CAPS = frozenset({"snmp_vlan", "snmp_admin", "snmp_name"})
# PoE nur, wo die Zuordnung PoE-Eintrag -> Port belegt ist (R35): ProCurve (poe_index ifindex) und Cisco (cisco_entity). Bei MikroTik
# ist nicht einmal belegt, dass es PoE ueber POWER-ETHERNET-MIB zeigt (R31), fuer alle anderen fehlt eine belegte Zuordnung.
_POE = frozenset({"snmp_poe"})
_CLI_CAPS = frozenset({"cli", "nac", "backup"})
# Wie dauerhaft ein SNMP-Set ist, haengt am Geraet (R26): ProCurve / AOS-S speichert ihn selbst, fuer alle anderen ist das nicht
# bestaetigt, sie bekommen die Faehigkeit nicht.
_AUTOSAVE = frozenset({"snmp_autosave"})

# Die notes sind Text fuer das Switch-Formular: deutsch mit echten Umlauten, ohne interne Verweise (Rnn).
_UNGEPRUEFT = (
    "Standard-Profil (Q-BRIDGE, IF-MIB, POWER-ETHERNET-MIB); SET-Unterstützung und herstellerspezifische Abweichungen "
    "(Index-Offsets) sind noch nicht gegen ein Gerät bestätigt. Kein PoE: welcher PoE-Eintrag zu welchem Port gehört, ist "
    "für diesen Hersteller nicht belegt."
)

# Jede Zeile bekommt ihr eigenes oids-dict (dict(...)), damit sich Treiber nie ein veraenderbares Profil teilen.
DRIVERS: dict[str, Driver] = {d.name: d for d in (
    Driver(
        "procurve", _SNMP_CAPS | _POE | _CLI_CAPS | _AUTOSAVE, "qbridge", {**_STANDARD_OIDS, "poe_power": _HP_POE_POWER},
        "HPE ProCurve / AOS-S. Standardweg ist die SSH-CLI (gestuft, Backup, NAC), SNMP nur als Fallback; PoE immer per SNMP. Die "
        "PVID darf nicht in der Tagged-Liste stehen; ein SNMP-Set löst implizit write-mem aus (kein Staging). PoE-Index = ifIndex, "
        "Gruppe 1: ein weiteres Stack-Mitglied (Gruppe 2 ...) hat kein PoE.",
        poe_index="ifindex",
    ),
    Driver("aruba_cx", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Aruba AOS-CX. " + _UNGEPRUEFT),
    Driver(
        "cisco", _SNMP_CAPS | _POE, "cisco_vmps",
        {**_STANDARD_OIDS, "vmvlan": _VMVLAN, "poe_power": _CISCO_POE_POWER, "poe_entphy": _CISCO_POE_ENTPHY, "ent_alias": _ENT_ALIAS},
        "Cisco IOS (klassisch). Access-VLAN über vmVlan statt über Q-BRIDGE-Untagged; Trunk-Mitglieder weiter über dot1q. PoE-Port "
        "über cpeExtPsePortEntPhyIndex und ENTITY-MIB (entAliasMappingIdentifier).",
        poe_index="cisco_entity",
    ),
    Driver(
        "cisco_sb", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS),
        "Cisco Small Business (SG/CBS), kein klassisches IOS. Angenommen: Q-BRIDGE statt vmVlan; nicht gegen ein Gerät bestätigt. "
        "Kein PoE: seine PoE-MIB (CISCOSB-POE-MIB) und die Zuordnung zum Port sind nicht belegt.",
    ),
    Driver("comware", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "HPE/H3C Comware. " + _UNGEPRUEFT),
    Driver("juniper", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Juniper Junos (EX/QFX). " + _UNGEPRUEFT),
    Driver("arista", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Arista EOS. " + _UNGEPRUEFT),
    Driver("dell", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Dell Networking. " + _UNGEPRUEFT),
    Driver("netgear", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS), "Netgear Smart/Managed Switches. " + _UNGEPRUEFT),
    # R31: dass RouterOS PoE ueber POWER-ETHERNET-MIB zeigt, ist nicht belegt; ohne snmp_poe weder PoE-Walk noch PoE-SET
    Driver(
        "mikrotik", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS),
        "MikroTik RouterOS. Standard-Profil (Q-BRIDGE, IF-MIB); SET-Unterstützung und herstellerspezifische Abweichungen sind noch nicht "
        "gegen ein Gerät bestätigt. Kein PoE: dass RouterOS es über POWER-ETHERNET-MIB zeigt, ist nicht belegt.",
    ),
    Driver(
        "generic", _SNMP_CAPS, "qbridge", dict(_STANDARD_OIDS),
        "Reine Standard-MIBs (Q-BRIDGE, IF-MIB) ohne Herstellerannahmen; Fallback für unbekannte Treibernamen. Kein PoE: "
        "POWER-ETHERNET-MIB sagt nicht, welcher PoE-Eintrag zu welchem Port gehört.",
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
