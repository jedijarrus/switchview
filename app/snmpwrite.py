"""SNMP-Schreibweg. Hier: den Switch live lesen (read_cfg); Operationen rendern, anwenden und zuruecklesen folgen.

read_cfg ist das SNMP-Gegenstueck zu `show running-config` + cfgparse.parse_config auf dem SSH-Weg. Es liest den Switch gezielt und
live, im Change-Lock des Aufrufers und nie aus dem Poll-Cache, und baut daraus dasselbe cfg-dict, mit dem changes.plan_ports und
changes.verify_ports schon arbeiten. Dazu kommt `raw`: die gelesenen PortList-Bytes und die Index-Tabellen, mit denen der Schreibweg
einzelne Bits aendert und zuruecklesen kann. Aus genau diesem Read stammt auch `before`, die Quelle fuer ein Revert.

Die Port-Logik spiegelt poller._build: dieselben Ports unter denselben Namen (ifName), dieselbe Trunk-Erkennung (ifStack unter TrkN)
und dieselbe VLAN-Zugehoerigkeit ueber den EFFEKTIVEN Bridge-Port (ein Trunk-Mitglied zaehlt mit dem Bridge-Port seines Trunks). So
sehen Oberflaeche, Inventar (main.build_map) und Schreibweg denselben Switch; tests/test_snmpwrite_read.py legt beides auf dieselben
Walk-Zeilen. Wer poller._build aendert, muss build_cfg mitziehen (oder bewusst abweichen). Abweichungen gibt es nur hier: ein Port,
den cfg nicht eindeutig beschreiben kann (in mehreren VLANs ungetaggt, oder eine PVID, die nicht sein ungetaggtes VLAN ist), steht
ohne u in raw["unmanaged"]; und bei vlan_strategy cisco_vmps ist ein Port mit vmVlan-Zeile ein Access-Port, dessen VLAN aus vmVlan
kommt, dem Objekt, das der Schreibweg dort setzt (so liest das Pruefen zurueck, was geschrieben wurde).

Zwei Index-Raeume, nie vermischen:
  Bridge-Port (dot1dBasePort)  dot1qPvid und die Bits der PortLists (Egress / Untagged)
  ifIndex                      ifAdminStatus, ifAlias, vmVlan (und ifName, der Portname)
raw haelt beide getrennt: port2bp / bp2port fuer die Q-BRIDGE-Seite, ifindex fuer die IF-MIB-Seite.
"""
import asyncio

import cfgparse
import poller
import snmp

# Die Walks von read_cfg: Schluessel aus poller.O, die beiden PortLists als Hex wie im Poller (poller.HEX). Fuer pvid, egress, untagged,
# ifadmin und ifalias hat jeder Treiber dieselben OIDs wie poller.O (tests/test_drivers.py), gelesen wird also, was geschrieben wird.
WALKS = ("ifName", "ifAlias", "ifAdmin", "bp2if", "vlanName", "vlanEgress", "vlanUntagged", "pvid", "ifStack")


def _vids(vids) -> str:
    """VLAN-IDs fuer eine Meldung, numerisch sortiert (ohne int(): auch eine kaputte ID darf die Meldung nicht sprengen)."""
    return ", ".join(sorted(vids, key=lambda v: (len(v), v)))


def build_cfg(W: dict, *, vmvlan_base: str | None = None) -> tuple[dict, dict]:
    """(cfg, raw) aus den Walk-Zeilen W: Schluessel wie in WALKS -> [(oid, wert), ...], so wie poller.poll_switch sie sammelt, dazu
    bei vlan_strategy cisco_vmps "vmVlan" (dann ist vmvlan_base die OID, unter der diese Zeilen gewalkt wurden; wie bei jedem
    anderen Walk zaehlen nur Zeilen darunter). Weitere Schluessel stoeren nicht. Rein, ohne I/O.

    cfg hat genau die Schluessel von cfgparse.parse_config. Vom Switch gelesen sind vlans ({vid: Name}, nach Nummer), trunks
    ({TrkN: [Mitglieder]}) und ports. Jeder Port hat die Felder von cfgparse._empty_port plus "poe": u ist das VLAN, in dessen
    Untagged-Liste das Bit des Ports steht (sonst None), t sind die uebrigen VLANs mit Egress-Bit (nach Nummer), name ist ifAlias,
    en ist ifAdminStatus == 1 (up). Ein Port mit vmVlan-Zeile ist ein Access-Port: u ist der vmVlan-Wert (0 = kein VLAN = None),
    t ist leer, die Q-BRIDGE-Sicht auf u / t zaehlt fuer ihn nicht. Alles andere liest SNMP hier nicht und steht auf dem Wert einer
    leeren Konfiguration: hostname "" (read_cfg traegt sys_name ein), primary_vlan "1", mgmt_vlan None, auth_active / eap_radius /
    login_radius False, addr_format None, voice_vlans [], radius {}; pro Port x / m False, cl / al / xuv / muv None (802.1X /
    MAC-Auth nur ueber die CLI) und poe None.

    raw: egress / untagged {vid: Bytes der PortList, wie gelesen}; pvid {Port: vid} ueber den effektiven Bridge-Port; admin
    {Port: int}; alias {Port: str}, nur wo der Switch eine Zeile liefert; poe {}; port2bp {Port: effektiver Bridge-Port};
    bp2port {Bridge-Port: Port, dem er gehoert}; ifindex {Port: ifIndex}; unmanaged {Port: Grund}, Ports, die der Schreibweg nicht
    anfassen darf; vmvlan {Port: vmVlan wie gelesen}, nur Ports mit vmVlan-Zeile. Ein Port ohne Bridge-Port fehlt in port2bp und pvid.

    Nur der Port faellt heraus (raw["unmanaged"], kein u; t und raw bleiben, wie gelesen), wenn er in mehr als einem VLAN ungetaggt
    ist (Hybrid-/General-Port; das gilt auch mit vmVlan-Zeile), oder wenn er ohne vmVlan-Zeile genau ein ungetaggtes VLAN hat, sein
    Bridge-Port aber eine andere PVID (ungetaggt Ankommendes landete in einem anderen VLAN, als cfg sagt). Fuer den ganzen Switch
    geschlossen aus (snmp.SnmpError statt eines cfg, das ihn falsch beschreibt), wenn
      - Name, Egress- und Untagged-Liste nicht fuer dieselben VLANs vorliegen (Spalten derselben Tabellenzeile),
      - ein Port kein lesbares ifAdminStatus hat (er gaelte sonst als aus, und ein Revert wuerde ihn abschalten),
      - ein Portname doppelt vorkommt (ein Schreibzugriff auf diesen Port waere nicht eindeutig),
      - die vmVlan-Zeile eines Ports keine Zahl ist oder ein vmVlan-Index kein ifIndex (falsche Basis-OID),
      - ein Index oder Wert sonst nicht lesbar ist (z. B. ein Bridge-Port "3.0"; hier wird jeder ValueError / KeyError zu SnmpError).
    """
    rows = {k: W[k] for k in WALKS}
    if "vmVlan" in W and not vmvlan_base:
        raise TypeError("build_cfg: vmVlan-Zeilen ohne vmvlan_base (die OID, unter der sie gewalkt wurden)")
    try:
        return _synth(rows, poller._tbl(W["vmVlan"], vmvlan_base) if "vmVlan" in W else {})
    except (ValueError, KeyError) as e:
        raise snmp.SnmpError(f"Unerwartete SNMP-Daten (Index oder Wert nicht lesbar): {e}") from e


def _synth(rows: dict, vmvlan: dict[str, str]) -> tuple[dict, dict]:
    """Der Kern von build_cfg: rows = die Walks aus WALKS, vmvlan = {ifIndex: vmVlan} (leer ohne vmVlan-Walk)."""
    tbl = {k: poller._tbl(rows[k], poller.O[k]) for k in WALKS}
    ifname, alias, admin, pvid, vname = tbl["ifName"], tbl["ifAlias"], tbl["ifAdmin"], tbl["pvid"], tbl["vlanName"]
    eg_hex, un_hex, bp2if = tbl["vlanEgress"], tbl["vlanUntagged"], tbl["bp2if"]
    if not set(vname) == set(eg_hex) == set(un_hex):
        odd = (set(vname) | set(eg_hex) | set(un_hex)) - (set(vname) & set(eg_hex) & set(un_hex))
        raise snmp.SnmpError(f"VLAN-Tabelle unvollständig gelesen: Name, Egress- und Untagged-Liste passen nicht zusammen (VLAN {_vids(odd)})")
    bad = [k for k in vmvlan if not k.isdigit()]
    if bad:
        raise snmp.SnmpError(f"vmVlan: Index {bad[0]} ist kein ifIndex (zeigt die OID des Treibers nicht auf die Spalte vmVlan?)")
    if2bp = {v: k for k, v in bp2if.items()}
    egress = {k: snmp.bitmap_ports(v) for k, v in eg_hex.items()}
    untag = {k: snmp.bitmap_ports(v) for k, v in un_hex.items()}

    member_of: dict[str, str] = {}
    members: dict[str, list[str]] = {}
    for k in tbl["ifStack"]:
        hi, _, lo = k.partition(".")
        if hi != "0" and lo != "0" and ifname.get(hi, "").startswith("Trk"):
            member_of[lo] = hi
            members.setdefault(hi, []).append(lo)

    raw: dict = {"egress": {k: snmp.hex_to_bytes(v) for k, v in eg_hex.items()},
                 "untagged": {k: snmp.hex_to_bytes(v) for k, v in un_hex.items()},
                 "pvid": {}, "admin": {}, "alias": {}, "poe": {}, "port2bp": {}, "bp2port": {}, "ifindex": {}, "unmanaged": {},
                 "vmvlan": {}}
    ports: dict[str, dict] = {}
    kept: dict[str, str] = {}  # ifIndex -> Portname
    for ifi in sorted(ifname, key=lambda x: int(x) if x.isdigit() else 10**9):
        # Filter, Trunk-Mitglied und effektiver Bridge-Port genau wie poller._build
        if not ifi.isdigit() or int(ifi) >= 1000:
            continue
        name = ifname[ifi]
        up = name.upper()
        if "VLAN" in up or up.startswith("LO") or "LOOPBACK" in up:
            continue
        if name in ports:
            raise snmp.SnmpError(f"Portname {name} kommt doppelt vor (ifIndex {raw['ifindex'][name]} und {ifi}), Ports sind nicht eindeutig")
        if not admin.get(ifi, "").isdigit():
            raise snmp.SnmpError(f"Port {name}: ifAdminStatus fehlt oder ist unlesbar ({admin.get(ifi)!r})")
        trk = member_of.get(ifi)
        eff = if2bp.get(trk) if trk else if2bp.get(ifi)
        b = int(eff) if eff else None
        un = sorted([v for v in vname if b and b in untag.get(v, set())], key=int)
        tg = sorted([v for v in vname if b and b in egress.get(v, set()) and b not in untag.get(v, set())], key=int)
        u = un[0] if un else None
        vm = vmvlan.get(ifi)
        if vm is not None:  # cisco_vmps-Access-Port: vmVlan ist sein VLAN, getaggte VLANs hat er nicht
            if not vm.isdigit():
                raise snmp.SnmpError(f"Port {name}: vmVlan unlesbar ({vm!r})")
            raw["vmvlan"][name] = vm
            u, tg = (str(int(vm)) if int(vm) else None), []
        if len(un) > 1:
            raw["unmanaged"][name] = f"ungetaggt in mehreren VLANs ({', '.join(un)}): Hybrid-/General-Port, per SNMP nicht verwaltbar"
            u = None
        elif vm is None and u is not None and eff in pvid and pvid[eff] != u:
            raw["unmanaged"][name] = f"PVID {pvid[eff]} weicht vom ungetaggten VLAN {u} ab – erst am Switch bereinigen"
            u = None
        st = cfgparse._empty_port()
        st.update(u=u, t=tg, name=alias.get(ifi, ""), en=admin[ifi] == "1", poe=None)
        ports[name] = st
        kept[ifi] = name
        raw["ifindex"][name] = int(ifi)
        raw["admin"][name] = int(admin[ifi])
        if ifi in alias:
            raw["alias"][name] = alias[ifi]
        if eff:
            raw["port2bp"][name] = int(eff)
            if eff in pvid:
                raw["pvid"][name] = pvid[eff]
    raw["bp2port"] = {int(bp): kept[ifi] for bp, ifi in bp2if.items() if ifi in kept}

    cfg = {
        "hostname": "",  # kein Walk: read_cfg setzt sys_name aus der Switch-Zeile
        "primary_vlan": "1", "mgmt_vlan": None, "auth_active": False, "eap_radius": False, "login_radius": False, "addr_format": None,
        "trunks": {ifname[hi]: [ifname.get(m, m) for m in mem] for hi, mem in members.items()},
        "vlans": {k: vname[k] for k in sorted(vname, key=int)},
        "voice_vlans": [], "radius": {},
        "ports": ports,
    }
    return cfg, raw


async def read_cfg(row, driver) -> tuple[dict, dict]:
    """Den Switch `row` (switches-Zeile) jetzt per SNMP lesen: (cfg, raw) wie build_cfg, mit cfg["hostname"] = sys_name der Zeile.

    Liest mit der LESE-Identitaet (poller.creds_of(row)), alle Walks parallel und strikt (snmp.walk(strict=True)): ein Walk, der
    mittendrin abbricht, oder eine fremde Zeile in einer PortList ist ein Fehler, keine kuerzere oder falsche Tabelle. Bei
    driver.vlan_strategy "cisco_vmps" kommt driver.oids["vmvlan"] als weiterer Walk dazu (W["vmVlan"], siehe build_cfg). Schreibt
    nicht in die DB und nimmt keinen Lock, weder den Poll-Lock noch den Change-Lock: den haelt der Aufrufer (asyncio.Lock ist nicht
    reentrant).

    Faellt geschlossen aus, strenger als der Poller (der einen fehlgeschlagenen Walk ueberspringt): scheitert auch nur ein Walk, kommt
    genau dessen Exception heraus (meist snmp.SnmpError), nie ein cfg aus Teildaten. Ausgewertet wird erst, wenn alle Walks fertig sind,
    damit nach dem Ruecksprung keine Abfrage mehr am Switch laeuft. Zeilen, die den Switch nicht sicher beschreiben: siehe build_cfg.
    """
    host, cred, hostname = row["host"], poller.creds_of(row), row["sys_name"] or ""
    vm_base = driver.oids["vmvlan"] if driver.vlan_strategy == "cisco_vmps" else None
    walks = {k: (poller.O[k], k in poller.HEX) for k in WALKS}  # Schluessel -> (OID, als Hex)
    if vm_base:
        walks["vmVlan"] = (vm_base, False)
    results = await asyncio.gather(*(snmp.walk(host, cred, oid, hex_values=hx, strict=True) for oid, hx in walks.values()),
                                   return_exceptions=True)
    for r in results:
        if isinstance(r, BaseException):
            raise r
    cfg, raw = build_cfg(dict(zip(walks, results)), vmvlan_base=vm_base)
    cfg["hostname"] = hostname
    return cfg, raw
