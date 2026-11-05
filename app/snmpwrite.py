"""SNMP-Schreibweg: den Switch live lesen (read_cfg), die Aenderung in snmpset-Varbinds uebersetzen (render_ops) und sie schreiben
(apply_ops). Den Ablauf darum herum (Lock, Abgleich mit der Vorschau, Zuruecklesen und Pruefen) fuehrt changes.run_change.

read_cfg ist das SNMP-Gegenstueck zu `show running-config` + cfgparse.parse_config auf dem SSH-Weg. Es liest den Switch gezielt und
live, im Change-Lock des Aufrufers und nie aus dem Poll-Cache, und baut daraus dasselbe cfg-dict, mit dem changes.plan_ports und
changes.verify_ports schon arbeiten. Dazu kommt `raw`: die gelesenen PortList-Bytes und die Index-Tabellen, mit denen der Schreibweg
einzelne Bits aendert und zuruecklesen kann. Aus genau diesem Read stammt auch `before`, die Quelle fuer ein Revert.

Die Port-Logik spiegelt poller._build. Welche Interfaces Ports sind und welche Trunks sie bilden, entscheidet fuer beide dieselbe
Funktion, poller.select_ports (ProCurve nach Name und ifIndex mit Trunks unter TrkN, jeder andere Treiber nach ifType mit LAGs);
dazu kommt dieselbe VLAN-Zugehoerigkeit ueber den EFFEKTIVEN Bridge-Port (ein Trunk-Mitglied zaehlt mit dem Bridge-Port seines
Trunks). So sehen Oberflaeche, Inventar (main.build_map) und Schreibweg denselben Switch; tests/test_snmpwrite_read.py und
tests/test_port_discovery.py legen beides auf dieselben Walk-Zeilen. Wer poller._build aendert, muss build_cfg mitziehen (oder
bewusst abweichen). Abweichungen gibt es nur hier: ein Port, den cfg nicht eindeutig beschreiben kann (in mehreren VLANs ungetaggt,
oder eine PVID, die nicht sein ungetaggtes VLAN ist), steht ohne u in raw["unmanaged"]; und bei vlan_strategy cisco_vmps ist ein
Port mit vmVlan-Zeile ein Access-Port, dessen VLAN aus vmVlan kommt, dem Objekt, das der Schreibweg dort setzt (so liest das Pruefen
zurueck, was geschrieben wurde).

Drei Index-Raeume, nie vermischen:
  Bridge-Port (dot1dBasePort)  dot1qPvid und die Bits der PortLists (Egress / Untagged)
  ifIndex                      ifAdminStatus, ifAlias, vmVlan (und ifName, der Portname)
  PoE-Eintrag <Gruppe>.<Port>  pethPsePortAdminEnable (POWER-ETHERNET-MIB); zu welchem Port er gehoert, entscheidet allein
                               poller.poe_ports (sicher oder gar nicht, wie fuer die Anzeige)
raw haelt sie getrennt: port2bp / bp2port fuer die Q-BRIDGE-Seite, ifindex fuer die IF-MIB-Seite, poe fuer die PoE-Eintraege.

render_ops macht aus dem Ziel pro Port (desired aus changes.plan_ports) die Varbinds fuer EIN snmpset, gerechnet auf den Bytes genau
dieses Reads: jede PortList wird gelesen, nur die Bits der geaenderten Ports kippen, und sie geht ganz zurueck. Ein Revert ist kein
eigener Weg: plan_ports mit desired = before gegen einen frischen Read, gerendert wie jede andere Aenderung. Was an einem Port nicht
geschrieben werden darf, steht genau einmal in snmp_block_reason: render_ops lehnt damit ab, plan_ports zeigt denselben Grund als
gesperrten Port.
"""
import asyncio
import re
import unicodedata

import cfgparse
import drivers
import poller
import snmp

# Die Walks von read_cfg: Schluessel aus poller.O, die beiden PortLists als Hex wie im Poller (poller.HEX). Fuer pvid, egress, untagged,
# ifadmin und ifalias hat jeder Treiber dieselben OIDs wie poller.O (tests/test_drivers.py), gelesen wird also, was geschrieben wird.
# Dazu "ifType" fuer jeden Treiber, dessen Ports select_ports danach waehlt (poller.by_iftype: alle ausser procurve), und die PoE-Walks
# des Treibers (poller.poe_walks, OIDs aus driver.oids, ohne die Leistung: die braucht nur die Anzeige).
WALKS = ("ifName", "ifAlias", "ifAdmin", "bp2if", "vlanName", "vlanEgress", "vlanUntagged", "pvid", "ifStack")
# Freitext, den read_cfg als Hex walkt (R18). Ohne MIBs gibt net-snmp einen OCTET STRING mit einem Byte, das es nicht fuer druckbar
# haelt (etwa jedes Byte eines Umlauts in UTF-8), als nacktes Hex aus, alle 16 Bytes umbrochen; ein strikter Text-Walk lehnt das ab
# (snmp._parse), und ein einziger Portname mit Umlaut sperrte den ganzen Switch. Mit -Ox ist jeder Wert Hex (strikt nach den Hex-Regeln),
# build_cfg(text_hex=True) macht wieder Text daraus. Der Anzeige-Poller liest beide weiter als Text.
TEXT_AS_HEX = ("ifAlias", "vlanName")
# ifTypes, die poller.select_ports zum Port machen kann (physisch, LAG, und 53 / 54 mit LAG-Namen)
_PORT_IFTYPES = poller.PHYS_IFTYPES | {poller.LAG_IFTYPE} | poller.NAMED_LAG_IFTYPES


def _hex_text(column: str, index: str, value: str) -> str:
    """Ein Freitext-Wert aus einem Hex-Walk ("42 C3 BC 72 6F", auch ueber Zeilen; "" ist leer) als Text: UTF-8, sonst latin-1 (jedes
    Byte ein Zeichen, das scheitert nie). ValueError, wenn der Wert nicht aus ganzen Hex-Bytes besteht."""
    try:
        data = bytes.fromhex(value)
    except ValueError as e:
        raise ValueError(f"{column}.{index} ist kein Hex-Text: {value[:40]!r}") from e
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _vids(vids) -> str:
    """VLAN-IDs fuer eine Meldung, numerisch sortiert (ohne int(): auch eine kaputte ID darf die Meldung nicht sprengen)."""
    return ", ".join(sorted(vids, key=lambda v: (len(v), v)))


def build_cfg(W: dict, driver_name: str = "procurve", *, vmvlan_base: str | None = None, text_hex: bool = False) -> tuple[dict, dict]:
    """(cfg, raw) aus den Walk-Zeilen W: Schluessel wie in WALKS -> [(oid, wert), ...], so wie poller.poll_switch sie sammelt, dazu
    "ifType", wenn driver_name die Ports danach waehlt (poller.by_iftype; fehlt er dann, ist das ein KeyError des Aufrufers), bei
    vlan_strategy cisco_vmps "vmVlan" (dann ist vmvlan_base die OID, unter der diese Zeilen gewalkt wurden; wie bei jedem anderen
    Walk zaehlen nur Zeilen darunter) und die PoE-Walks des Treibers (poller.poe_walks; ein fehlender ist leer). Der Treiber ist der
    namens driver_name (drivers.driver_for). Weitere Schluessel stoeren nicht. Rein, ohne I/O. Welche Interfaces Ports und Trunks
    sind, entscheidet poller.select_ports fuer driver_name, genau wie in der Anzeige, welcher PoE-Eintrag zu welchem Port gehoert
    poller.poe_ports, ebenso. text_hex (nur read_cfg): die Spalten aus TEXT_AS_HEX kommen als Hex und werden zu Text (UTF-8, sonst
    latin-1); ohne text_hex (Zeilen im Format des Pollers) bleiben sie, wie sie sind.

    cfg hat genau die Schluessel von cfgparse.parse_config. Vom Switch gelesen sind vlans ({vid: Name}, nach Nummer), trunks
    ({Trunk: [Mitglieder]}; Trunk ist der ifName, TrkN bei ProCurve, sonst der des LAG, etwa Po1, ae0, auch ein LAG ohne Mitglieder)
    und ports. Jeder Port hat die Felder von cfgparse._empty_port plus "poe": u ist das VLAN, in dessen
    Untagged-Liste das Bit des Ports steht (sonst None), t sind die uebrigen VLANs mit Egress-Bit (nach Nummer), name ist ifAlias,
    en ist ifAdminStatus == 1 (up), poe ist pethPsePortAdminEnable == 1 (an) des Eintrags, den poller.poe_ports ihm sicher zuordnet,
    None ohne einen (kein PoE, oder nicht sicher zuzuordnen). Ein Port mit vmVlan-Zeile ist ein Access-Port: u ist der vmVlan-Wert
    (0 = kein VLAN = None), t ist leer, die Q-BRIDGE-Sicht auf u / t zaehlt fuer ihn nicht. Alles andere liest SNMP hier nicht und steht
    auf dem Wert einer leeren Konfiguration: hostname "" (read_cfg traegt sys_name ein), primary_vlan "1", mgmt_vlan None, auth_active /
    eap_radius / login_radius False, addr_format None, voice_vlans [], radius {}; pro Port x / m False, cl / al / xuv / muv None (802.1X /
    MAC-Auth nur ueber die CLI).

    raw: egress / untagged {vid: Bytes der PortList, wie gelesen}; pvid {Port: vid} ueber den effektiven Bridge-Port; admin
    {Port: int}; alias {Port: str}, nur wo der Switch eine Zeile liefert; poe {Port: {"group", "index", "admin", "status"}} (der
    PoE-Eintrag <group>.<index>, admin 1 an / 2 aus, status pethPsePortDetectionStatus), nur Ports mit sicher zugeordnetem Eintrag;
    poe_unmapped [PoE-Indexe "<Gruppe>.<Port>" ohne Port]; port2bp {Port: effektiver Bridge-Port}; bp2port {Bridge-Port: Port, dem er
    gehoert}; ifindex {Port: ifIndex}; unmanaged {Port: Grund}, Ports, die der Schreibweg nicht anfassen darf; vmvlan {Port: vmVlan wie
    gelesen}, nur Ports mit vmVlan-Zeile. Ein Port ohne Bridge-Port fehlt in port2bp und pvid.

    Nur der Port faellt heraus (raw["unmanaged"], kein u; t und raw bleiben, wie gelesen), wenn er in mehr als einem VLAN ungetaggt
    ist (Hybrid-/General-Port; das gilt auch mit vmVlan-Zeile), oder wenn er ohne vmVlan-Zeile genau ein ungetaggtes VLAN hat, sein
    Bridge-Port aber eine andere PVID (ungetaggt Ankommendes landete in einem anderen VLAN, als cfg sagt). Fuer den ganzen Switch
    geschlossen aus (snmp.SnmpError statt eines cfg, das ihn falsch beschreibt), wenn
      - Name, Egress- und Untagged-Liste nicht fuer dieselben VLANs vorliegen (Spalten derselben Tabellenzeile),
      - driver_name die Ports nach ifType waehlt und ein Interface mit numerischem ifIndex in ifName keine ifType-Zeile hat, oder
        eines mit einem ifType, der ein Port sein kann (6, 117, 161, 53, 54), keine ifName-Zeile (ifXEntry ergaenzt ifEntry, ein
        Agent liefert also beide; fehlt eine doch, etwa weil ein Walk vorzeitig endete, fiele das Interface still heraus, und waere
        es ein LAG, stuenden seine Mitglieder ungeschuetzt als gewoehnliche Ports da),
      - ein Port kein lesbares ifAdminStatus hat (er gaelte sonst als aus, und ein Revert wuerde ihn abschalten),
      - ein Portname doppelt vorkommt (ein Schreibzugriff auf diesen Port waere nicht eindeutig),
      - die vmVlan-Zeile eines Ports keine Zahl ist oder ein vmVlan-Index kein ifIndex (falsche Basis-OID),
      - die PoE-Tabelle da ist, aber nicht sicher lesbar (poller.poe_ports mit strict: Admin- und Status-Spalte mit verschiedenen
        Eintraegen, ein Index, der nicht <Gruppe>.<Port> ist, ein Wert, der keiner ist, bei cisco_entity dasselbe fuer die Tabellen der
        Zuordnung). Gar keine PoE-Zeile ist kein Fehler: dann hat kein Port PoE,
      - ein Index oder Wert sonst nicht lesbar ist (z. B. ein Bridge-Port "3.0" oder mit text_hex ein Freitext, der kein Hex ist; hier
        wird jeder ValueError zu SnmpError. Ein KeyError bleibt einer: jeder Zugriff auf Switch-Daten ist abgesichert, er kann nur ein
        Fehler im Code sein).
    """
    rows = {k: W[k] for k in ((*WALKS, "ifType") if poller.by_iftype(driver_name) else WALKS)}
    if "vmVlan" in W and not vmvlan_base:
        raise TypeError("build_cfg: vmVlan-Zeilen ohne vmvlan_base (die OID, unter der sie gewalkt wurden)")
    driver = drivers.driver_for({"driver": driver_name})
    poe = {k: poller._tbl(W.get(k, []), base) for k, base in poller.poe_walks(driver).items()}
    try:
        return _synth(rows, poller._tbl(W["vmVlan"], vmvlan_base) if "vmVlan" in W else {}, driver_name, text_hex, driver, poe)
    except ValueError as e:
        raise snmp.SnmpError(f"Unerwartete SNMP-Daten (Index oder Wert nicht lesbar): {e}") from e


def _synth(rows: dict, vmvlan: dict[str, str], driver_name: str, text_hex: bool, driver: drivers.Driver,
           poe_tables: dict[str, dict[str, str]]) -> tuple[dict, dict]:
    """Der Kern von build_cfg: rows = die Walks aus WALKS (plus ifType, wenn driver_name nach ihm waehlt), vmvlan = {ifIndex: vmVlan}
    (leer ohne vmVlan-Walk), text_hex wie bei build_cfg, driver der Treiber namens driver_name, poe_tables seine PoE-Tabellen
    (_tbl-Tabellen der Walks aus poller.poe_walks)."""
    tbl = {k: poller._tbl(v, poller.O[k]) for k, v in rows.items()}
    if text_hex:
        for k in TEXT_AS_HEX:
            tbl[k] = {i: _hex_text(k, i, v) for i, v in tbl[k].items()}
    ifname, alias, admin, pvid, vname = tbl["ifName"], tbl["ifAlias"], tbl["ifAdmin"], tbl["pvid"], tbl["vlanName"]
    eg_hex, un_hex, bp2if = tbl["vlanEgress"], tbl["vlanUntagged"], tbl["bp2if"]
    if not set(vname) == set(eg_hex) == set(un_hex):
        odd = (set(vname) | set(eg_hex) | set(un_hex)) - (set(vname) & set(eg_hex) & set(un_hex))
        raise snmp.SnmpError(f"VLAN-Tabelle unvollständig gelesen: Name, Egress- und Untagged-Liste passen nicht zusammen (VLAN {_vids(odd)})")
    if poller.by_iftype(driver_name):
        missing = sorted((i for i in ifname if i.isdigit() and i not in tbl["ifType"]), key=lambda v: (len(v), v))
        if missing:
            listed = ", ".join(f"{ifname[i]} (ifIndex {i})" for i in missing[:5]) + (", ..." if len(missing) > 5 else "")
            raise snmp.SnmpError(f"Interface-Tabelle unvollständig gelesen: ifType fehlt für {listed}")
        iftype = tbl["ifType"]
        nameless = sorted((i for i, t in iftype.items() if i.isdigit() and t in _PORT_IFTYPES and i not in ifname),
                          key=lambda v: (len(v), v))
        if nameless:
            listed = ", ".join(f"ifIndex {i} (ifType {iftype[i]})" for i in nameless[:5]) + (", ..." if len(nameless) > 5 else "")
            raise snmp.SnmpError(f"Interface-Tabelle unvollständig gelesen: ifName fehlt für {listed}")
    bad = [k for k in vmvlan if not k.isdigit()]
    if bad:
        raise snmp.SnmpError(f"vmVlan: Index {bad[0]} ist kein ifIndex (zeigt die OID des Treibers nicht auf die Spalte vmVlan?)")
    if2bp = {v: k for k, v in bp2if.items()}
    egress = {k: snmp.bitmap_ports(v) for k, v in eg_hex.items()}
    untag = {k: snmp.bitmap_ports(v) for k, v in un_hex.items()}
    port_ifis, member_of, members = poller.select_ports(ifname, tbl.get("ifType", {}), tbl["ifStack"], driver_name)
    trunks = poller.trunk_ports(ifname, port_ifis, members, driver_name)
    poe, unmapped = poller.poe_ports(driver, poe_tables, [ifi for ifi in port_ifis if ifi not in trunks], strict=True)

    raw: dict = {"egress": {k: snmp.hex_to_bytes(v) for k, v in eg_hex.items()},
                 "untagged": {k: snmp.hex_to_bytes(v) for k, v in un_hex.items()},
                 "pvid": {}, "admin": {}, "alias": {}, "poe": {}, "poe_unmapped": unmapped, "port2bp": {}, "bp2port": {}, "ifindex": {},
                 "unmanaged": {}, "vmvlan": {}}
    ports: dict[str, dict] = {}
    kept: dict[str, str] = {}  # ifIndex -> Portname
    for ifi in port_ifis:
        # Ports, Trunk-Mitglied und effektiver Bridge-Port genau wie poller._build
        name = ifname[ifi]
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
            raw["unmanaged"][name] = (f"PVID {pvid[eff]} weicht vom ungetaggten VLAN {u} ab (Fehlkonfiguration oder dynamisch per "
                                      f"802.1X/RADIUS zugewiesen) – per SNMP nicht verwaltbar")
            u = None
        pe = poe.get(ifi)
        st = cfgparse._empty_port()
        st.update(u=u, t=tg, name=alias.get(ifi, ""), en=admin[ifi] == "1", poe=pe["admin"] == 1 if pe else None)
        ports[name] = st
        kept[ifi] = name
        raw["ifindex"][name] = int(ifi)
        raw["admin"][name] = int(admin[ifi])
        if ifi in alias:
            raw["alias"][name] = alias[ifi]
        if pe:
            raw["poe"][name] = {"group": pe["group"], "index": pe["index"], "admin": pe["admin"], "status": pe["status"]}
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
    mittendrin abbricht, oder eine fremde Zeile hinter einem Wert ist ein Fehler, keine kuerzere oder falsche Tabelle. Waehlt der
    Treiber seine Ports nach ifType (poller.by_iftype, alle ausser procurve), kommt ifType als weiterer Walk dazu; ProCurve braucht
    ihn nicht. Bei driver.vlan_strategy "cisco_vmps" kommt driver.oids["vmvlan"] dazu (W["vmVlan"], siehe build_cfg), bei einem
    Treiber mit snmp_poe seine PoE-Walks (poller.poe_walks, ohne die Leistung), auch fuer eine Aenderung, die PoE nicht beruehrt: cfg
    beschreibt immer den ganzen Port. Den Freitext (TEXT_AS_HEX: ifAlias, vlanName) walkt read_cfg als Hex, damit Umlaute lesbar sind;
    build_cfg bekommt driver.name und text_hex=True. Schreibt nicht in die DB und nimmt keinen Lock, weder den Poll-Lock noch den
    Change-Lock: den haelt der Aufrufer (asyncio.Lock ist nicht reentrant).

    Faellt geschlossen aus, strenger als der Poller (der einen fehlgeschlagenen Walk ueberspringt): scheitert auch nur ein Walk, kommt
    genau dessen Exception heraus (meist snmp.SnmpError), nie ein cfg aus Teildaten. Ausgewertet wird erst, wenn alle Walks fertig sind,
    damit nach dem Ruecksprung keine Abfrage mehr am Switch laeuft. Zeilen, die den Switch nicht sicher beschreiben: siehe build_cfg.
    """
    host, cred, hostname = row["host"], poller.creds_of(row), row["sys_name"] or ""
    vm_base = driver.oids["vmvlan"] if driver.vlan_strategy == "cisco_vmps" else None
    walks = {k: (poller.O[k], k in poller.HEX or k in TEXT_AS_HEX) for k in WALKS}  # Schluessel -> (OID, als Hex)
    if poller.by_iftype(driver.name):
        walks["ifType"] = (poller.O["ifType"], False)
    if vm_base:
        walks["vmVlan"] = (vm_base, False)
    walks |= {k: (base, False) for k, base in poller.poe_walks(driver).items()}
    results = await asyncio.gather(*(snmp.walk(host, cred, oid, hex_values=hx, strict=True) for oid, hx in walks.values()),
                                   return_exceptions=True)
    for r in results:
        if isinstance(r, BaseException):
            raise r
    cfg, raw = build_cfg(dict(zip(walks, results)), driver.name, vmvlan_base=vm_base, text_hex=True)
    cfg["hostname"] = hostname
    return cfg, raw


# ── Operationen rendern ──────────────────────────────────────────────────────────────────────────────────────────────────────────
# Felder, die render_ops schreibt, und die Faehigkeit des Treibers, die jedes braucht (drivers.can). Jedes andere Feld lehnt es ab:
# 802.1X / MAC-Anmeldung (x, m, cl, al, xuv, muv) gehen nur ueber die CLI. pvid (R21) ist die PVID ausdruecklich, fuer einen Revert,
# der sie wiederherstellt; cfg kennt sie nicht, sie steht nur in raw["pvid"]. poe (an / aus) geht bei jedem Treiber nur hier (R30).
FIELD_CAPS = {"u": "snmp_vlan", "pvid": "snmp_vlan", "t": "snmp_vlan", "en": "snmp_admin", "name": "snmp_name", "poe": "snmp_poe"}
_CAP_LABEL = {"snmp_vlan": "VLANs", "snmp_admin": "An/Aus", "snmp_name": "Portnamen", "snmp_poe": "PoE"}
POE_DELIVERING = 3    # pethPsePortDetectionStatus deliveringPower(3): der Port versorgt gerade ein Geraet (changes.plan_ports warnt)
ALIAS_MAX = 64  # ifAlias ist DisplayString SIZE (0..64): hoechstens 64 Bytes, geschrieben werden die UTF-8-Bytes des Namens
_RUNS = re.compile(r"[0-9]+|[^0-9]+")
_VLAN_ID = re.compile(r"[1-9][0-9]{0,3}")  # eine VLAN-ID, wie ein Walk sie zeigt: Dezimal ohne fuehrende Null (1..4094 prueft int)


def port_order(name: str) -> tuple:
    """Sortierschluessel (sorted(..., key=port_order)) fuer die natuerliche Reihenfolge von Portnamen jedes Herstellers: Ziffernfolgen
    zaehlen als Zahl, also 2 vor 10 (ProCurve 1, 2, 10, A1, A10, Trk1, Trk2; sonst etwa Gi1/0/2 vor Gi1/0/10, Po1, ge-0/0/1, ae0).
    Wirft nie: eine Ziffernfolge vergleicht ohne int() (das scheitert an mehr als 4300 Ziffern) ueber Laenge und Text ohne fuehrende
    Nullen, jedes Stueck ist (0, Laenge, Ziffern) oder (1, 0, Text), Zahl und Text treffen also nie aufeinander; bei gleichem
    Schluessel (01 und 1) entscheidet der Name selbst. Auch main nutzt ihn (Zusammenfassung einer Aenderung)."""
    key = []
    for s in _RUNS.findall(name):
        digits = s.lstrip("0") if s[0] in "0123456789" else None
        key.append((0, len(digits), digits) if digits is not None else (1, 0, s))
    return key, name


def _quote(text: str) -> str:
    """Text fuer eine shown-Zeile: in Anfuehrungszeichen, " und \\ mit Backslash, jedes nicht druckbare Zeichen (Steuerzeichen,
    Zeilentrenner, ...) als \\uXXXX, damit jede Aenderung genau eine lesbare Zeile bleibt, auch mit einem alten Namen vom Switch."""
    out = []
    for c in text:
        if c in '"\\':
            out.append("\\" + c)
        elif c.isprintable():
            out.append(c)
        else:
            out.append(f"\\u{ord(c):04x}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08x}")
    return '"' + "".join(out) + '"'


def _vlan(vid: str | None) -> str:
    return "–" if vid is None else vid


def _onoff(en: bool) -> str:
    return "an" if en else "aus"


def is_vlan_id(value) -> bool:
    """Ist value eine VLAN-ID 1..4094 als Text, wie ein Walk sie zeigt (Dezimal ohne fuehrende Null, nur ASCII-Ziffern)? So muss eine
    ausdrueckliche pvid aussehen (R21); changes.plan_ports nimmt eine PVID aus raw auch nur so in before auf."""
    return isinstance(value, str) and bool(_VLAN_ID.fullmatch(value)) and int(value) <= 4094


def _touched(st: dict, u: str | None, t: list[str]) -> set[str]:
    """Die VLANs, in denen sich ein Bit des Ports aendern kann, wenn er von st (u / t laut cfg) zu u / t geht: altes und neues ungetaggtes
    VLAN (nur wenn u sich aendert) und jedes VLAN, das getaggt dazukommt oder wegfaellt."""
    return ({st["u"], u} - {None} if u != st["u"] else set()) | (set(st["t"]) ^ set(t))


def snmp_block_reason(driver: drivers.Driver, cfg: dict, raw: dict, port: str, fields: dict) -> str | None:
    """Warum render_ops Port `port` mit `fields` ({Feld: Zielwert} wie in desired) nicht schreiben darf: ein deutscher Grund ohne
    "Port X: " davor, oder None, wenn nichts dagegen spricht (auch bei leeren fields). Die eine Quelle der Regeln pro Port: render_ops
    wirft ValueError("Port X: <Grund>"), changes.plan_ports traegt {"port": X, "reason": <Grund>} in blocked ein und plant die anderen
    Ports weiter. Gerechnet auf cfg / raw desselben Reads (read_cfg); die Reihenfolge der Pruefungen ist der Vorrang der Gruende.

    Abgelehnt wird
      - ein Port, den es nicht gibt, und ein anderes Feld als u / pvid / t / en / name / poe (802.1X / MAC-Anmeldung gehen nur ueber die
        CLI);
      - ein Port in raw["unmanaged"]; ein Trunk-Mitglied (der Trunk selbst geht: er ist ein Bridge-Port); ein Port ohne Bridge-Port oder
        ifIndex (nur Anzeige, auch kein Abschalten) oder dessen Bridge-Port laut raw["bp2port"] nicht ihm gehoert; ein Feld, dessen
        Faehigkeit der Treiber nicht hat (FIELD_CAPS, drivers.can);
      - ein Wert, der keiner ist: u keine VLAN-ID als Text, t keine Liste verschiedener, pvid keine VLAN-ID 1..4094 (is_vlan_id), en
        nicht wahr oder falsch, ein Name mit Steuerzeichen, ohne UTF-8-Form oder mit mehr als 64 Bytes in UTF-8;
      - wenn sich VLANs aendern (u, t oder eine pvid): bei cisco_vmps (R20) jede pvid und alles ausser dem Access-VLAN eines Ports mit
        vmVlan-Zeile, auch keins (vmVlan 0); bei qbridge ein Port, den der Read per vmVlan beschreibt; ein VLAN, das es auf dem Switch
        nicht gibt, auch als pvid (R23); u zugleich in t; ein Port ohne jedes VLAN; eine pvid neben einem anderen ungetaggten VLAN (der
        Port waere danach nicht verwaltbar, R12); jede andere vlan_strategy;
      - PoE (poe, nicht wahr oder falsch: abgelehnt) an einem Port ohne PoE-Eintrag in raw["poe"]: ein Trunk (PoE hat nur ein einzelner
        Port), ein Port ohne PoE, und einer, dessen Eintrag poller.poe_ports nicht sicher zuordnen konnte (raw["poe_unmapped"] nennt die
        Eintraege ohne Port). Ein SET auf einen geratenen Eintrag schaltete womoeglich ein anderes Geraet ab.
    Was nur mehrere Ports zusammen betrifft (zwei Ports einer Aenderung auf einem ifIndex oder PoE-Eintrag), prueft render_ops selbst."""
    p, d = port, fields
    if not d:
        return None
    if p not in cfg["ports"]:
        return "gibt es auf diesem Switch nicht"
    odd = sorted(str(k) for k in d if k not in FIELD_CAPS)
    if odd:
        return f"per SNMP nicht änderbar: {', '.join(odd)}"
    if p in raw["unmanaged"]:
        return raw["unmanaged"][p]
    member_of = {m: trunk for trunk, members in cfg["trunks"].items() for m in members}
    if p in member_of:  # ein Mitglied hat keinen eigenen Bridge-Port, seine VLANs sind die des Trunks
        return f"gehört zu {member_of[p]}, bitte {member_of[p]} wählen"
    if p not in raw["port2bp"] or p not in raw["ifindex"]:
        # etwa ein Management-Port ausserhalb der Bridge: nur Anzeige, auch kein Abschalten (es koennte SwitchViews eigener Zugang sein)
        return "kein Bridge-Port (etwa ein Management-Port), per SNMP nur zur Anzeige"
    bp = raw["port2bp"][p]
    if raw["bp2port"].get(bp) != p:
        # build_cfg sorgt dafuer, dass der effektive Bridge-Port eines Ports, der kein Mitglied ist, ihm selbst gehoert. Stimmt das
        # nicht, waere es ein Fehler in raw: lieber nichts schreiben als die Bits eines fremden Ports kippen.
        owner = raw["bp2port"].get(bp)
        return f"Bridge-Port {bp} gehört laut bp2port zu {f'Port {owner}' if owner else 'keinem Port'}"
    for k, cap in FIELD_CAPS.items():
        if k in d and not drivers.can(driver, cap):
            return f"Treiber {driver.name} kann {_CAP_LABEL[cap]} nicht per SNMP schreiben"
    st = cfg["ports"][p]
    u, t, pvid = d.get("u", st["u"]), d.get("t", st["t"]), d.get("pvid")
    if u is not None and not isinstance(u, str):
        return f"u ist keine VLAN-ID ({u!r})"
    if not isinstance(t, (list, tuple)) or not all(isinstance(v, str) for v in t) or len(set(t)) != len(t):
        return f"t ist keine Liste verschiedener VLAN-IDs ({t!r})"
    if "pvid" in d and not is_vlan_id(pvid):
        return f"pvid ist keine VLAN-ID 1–4094 ({pvid!r})"
    if u != st["u"] or set(t) != set(st["t"]) or pvid is not None:
        reason = _vlan_refusal(driver, cfg, raw, p, st, u, list(t), pvid)
        if reason:
            return reason
    if "en" in d and not isinstance(d["en"], bool):
        return f"en ist nicht wahr oder falsch ({d['en']!r})"
    if "name" in d:
        reason = _name_refusal(d["name"])
        if reason:
            return reason
    if "poe" in d:
        return _poe_refusal(cfg, raw, p, d["poe"])
    return None


def _poe_refusal(cfg: dict, raw: dict, p: str, on) -> str | None:
    """Warum Port p sein PoE nicht auf `on` (an True, aus False) bekommt; sonst None."""
    if not isinstance(on, bool):
        return f"poe ist nicht wahr oder falsch ({on!r})"
    if p in raw["poe"]:
        return None
    if p in cfg["trunks"]:
        return "PoE nur an einzelnen Ports: nicht am Trunk und noch nicht an Trunk-Mitgliedern"
    if raw["poe_unmapped"]:
        return ("hat kein PoE, oder sein PoE-Eintrag lässt sich nicht sicher zuordnen "
                f"(Einträge ohne Port: {poller.poe_listing(raw['poe_unmapped'])})")
    return "hat kein PoE" if raw["poe"] else "hat kein PoE (der Switch meldet keine PoE-Ports)"


def _name_refusal(name) -> str | None:
    """Warum `name` nicht als ifAlias geschrieben werden kann oder soll (sonst None). Ein fuehrendes "-" ist erlaubt: der Name geht als
    Hex (Typ x) zu snmpset, getopt sieht ihn nie (R22)."""
    if not isinstance(name, str):
        return f"Name ist kein Text ({name!r})"
    if any(unicodedata.category(c) == "Cc" for c in name):  # NUL, Zeilenumbruch, Steuerzeichen: gehoeren in keinen Portnamen
        return "Name enthält Steuerzeichen"
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError:  # etwa ein einzelnes Surrogat aus einem JSON-Escape
        return "Name enthält Zeichen, die sich nicht als UTF-8 schreiben lassen"
    if size > ALIAS_MAX:
        return f"Name zu lang ({size} Bytes in UTF-8, ifAlias erlaubt höchstens {ALIAS_MAX})"
    return None


def _vlan_refusal(driver, cfg: dict, raw: dict, p: str, st: dict, u: str | None, t: list[str], pvid: str | None) -> str | None:
    """Warum Port p (Zustand st laut cfg) nicht das ungetaggte VLAN u, die getaggten t und, wenn pvid nicht None ist, ausdruecklich diese
    PVID bekommen darf (mindestens eins davon ist neu; die Werte sind schon als VLAN-IDs geprueft); sonst None."""
    u_changed, t_changed = u != st["u"], set(t) != set(st["t"])
    if driver.vlan_strategy == "cisco_vmps":
        # R20: nur das Access-VLAN eines Access-Ports (einer mit vmVlan-Zeile), ueber vmVlan; Trunk-VLANs fuehrt IOS in CISCO-VTP-MIB
        if pvid is not None:
            return "PVID per SNMP nur über Q-BRIDGE, nicht bei Cisco (vmVlan)"
        if p not in raw["vmvlan"]:
            return "Trunk-VLANs auf Cisco per SNMP noch nicht unterstützt (CISCO-VTP-MIB)"
        if t_changed:
            return "Access-Port (vmVlan), getaggte VLANs gibt es dort nicht"
        if u is None:  # vmVlan 0 (kein VLAN) laesst die MIB fuer einen statischen Port nicht zu
            return "Access-Port (vmVlan) ohne VLAN lässt sich per SNMP nicht setzen"
        if u not in cfg["vlans"]:
            return f"VLAN {u} gibt es auf diesem Switch nicht"
        return None
    if driver.vlan_strategy != "qbridge":
        return f"VLAN-Strategie {driver.vlan_strategy!r} des Treibers {driver.name} ist unbekannt"
    if p in raw["vmvlan"]:  # dieser Read beschreibt den Port per vmVlan, Q-BRIDGE ginge vom falschen VLAN aus
        return f"als Access-Port per vmVlan gelesen, Treiber {driver.name} schreibt aber Q-BRIDGE"
    for v in sorted(_touched(st, u, t), key=lambda v: (len(v), v)):
        if v not in raw["egress"] or v not in raw["untagged"]:
            return f"VLAN {v} gibt es auf diesem Switch nicht"
    if u_changed or t_changed:
        if u is not None and u in t:  # ProCurve: die PVID (sie folgt u) darf nicht in der Tagged-Liste stehen
            return f"VLAN {u} kann nicht ungetaggt und getaggt zugleich sein"
        if u is None and not t:
            return "wäre in keinem VLAN mehr"
    if pvid is not None and u is not None and pvid != u:
        # Mit einem ungetaggten VLAN muss die PVID es sein: sonst liest build_cfg den Port als nicht verwaltbar (R12), das Pruefen
        # faende u nicht wieder, und keine Aenderung, auch kein Revert, kaeme mehr an ihn heran.
        return f"PVID {pvid} wiche vom ungetaggten VLAN {u} ab, der Port wäre danach per SNMP nicht verwaltbar"
    if pvid is not None and pvid not in cfg["vlans"]:
        # R23: ohne diese Pruefung ginge eine PVID ohne ungetaggtes VLAN an jeder VLAN-Pruefung vorbei; ein Revert auf eine PVID, deren
        # VLAN es nicht mehr gibt, bekommt diesen Grund statt eines SET, das das Pruefen nur unklar faende. Zuletzt geprueft: jeder
        # Grund von vor R23 bleibt, wie er war.
        return f"PVID {pvid}: das VLAN gibt es auf diesem Switch nicht"
    return None


def _vlan_ops(driver, raw: dict, p: str, st: dict, u: str | None, t: list[str], pvid: str | None,
              portlists: dict[str, dict[str, bytes]], values: dict[str, dict[int, tuple[str, str]]]) -> list[str]:
    """Port p bekommt das ungetaggte VLAN u, die getaggten t und, wenn pvid nicht None ist, ausdruecklich diese PVID (mindestens eins
    davon ist neu, snmp_block_reason hat nichts dagegen): traegt die noetigen Bits in portlists ein, PVID / vmVlan in values, und
    liefert die shown-Zeilen dazu."""
    u_changed, t_changed = u != st["u"], set(t) != set(st["t"])
    if driver.vlan_strategy == "cisco_vmps":  # nur das Access-VLAN, ueber vmVlan (R20)
        values["vmvlan"][raw["ifindex"][p]] = ("i", u)
        return [f"Port {p}: Access-VLAN {_vlan(st['u'])} → {u}"]
    # Jedes VLAN, das die Aenderung beruehrt, bekommt fuer den Bridge-Port den Zielzustand: Egress = ungetaggt oder getaggt,
    # Untagged = ungetaggt. Alle anderen VLANs stehen schon so (cfg ist aus genau diesen Bits gelesen).
    bp = raw["port2bp"][p]
    for v in _touched(st, u, t):
        for kind, member in (("egress", v == u or v in t), ("untagged", v == u)):
            have = portlists[kind].get(v, raw[kind][v])
            if snmp.portlist_has_bit(have, bp) != member:
                portlists[kind][v] = snmp.portlist_set_bit(have, bp) if member else snmp.portlist_clear_bit(have, bp)
    # dot1qPvid: die ausdrueckliche PVID, wenn es eine gibt, sonst das neue ungetaggte VLAN (R21). u -> None ohne pvid (ein Port, der
    # nur getaggte VLANs behaelt) schreibt keine PVID.
    old_pvid = raw["pvid"].get(p)
    if (u_changed and u is not None) or (pvid is not None and pvid != old_pvid):
        values["pvid"][bp] = ("u", pvid if pvid is not None else u)
    lines = [f"Port {p}: VLAN ungetaggt {_vlan(st['u'])} → {_vlan(u)}"] if u_changed else []
    if pvid is not None and pvid != old_pvid:
        lines.append(f"Port {p}: PVID {_vlan(old_pvid)} → {pvid}")
    return lines + ([f"Port {p}: VLAN getaggt {_vids(st['t']) or '–'} → {_vids(t) or '–'}"] if t_changed else [])


def render_ops(driver: drivers.Driver, cfg: dict, raw: dict, desired: dict) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Die Aenderung `desired` ({Port: {Feld: Zielwert}} mit u, pvid, t, en, name, poe, wie changes.plan_ports sie plant) als Varbinds
    fuer EIN snmpset, gerechnet auf cfg / raw desselben Reads (read_cfg). Ergebnis (ops, shown):
      ops    [(OID, Typ, Wert)] fuer snmp.set_vars. dot1qPvid "u" (VlanIndex = Unsigned32), PortList "x" (snmp.portlist_to_hex),
             ifAdminStatus "i" ("1" an, "2" aus), ifAlias "x" (die UTF-8-Bytes des Namens als Hex: dasselbe OCTET STRING wie mit
             "s", aber snmpset liest den Wert nie als Option, R22), vmVlan "i", pethPsePortAdminEnable "i" ("1" an, "2" aus).
      shown  je Port und geaendertem Feld eine Zeile mit vorher und nachher: "Port 6: VLAN ungetaggt 1 → 20", "Port 3: PVID 99 → 1",
             "Port 1: VLAN getaggt 30 → 30, 99", "Port 2: an → aus", 'Port 2: Name "" → "Drucker"', "Port 5: PoE an → aus" ("–"
             heisst keins); Ports in natuerlicher Reihenfolge, Felder in der Reihenfolge u, pvid, t, en, name, poe. Daraus entsteht der
             Token (changes.cmd_token).
             PortList-Bytes stehen nie darin: aendert sich nach der Vorschau ein anderer Port derselben PortList, bleibt der Token (R6),
             und die ops kommen beim Ausfuehren ohnehin aus einem frischen Read; aendert sich der Port selbst, aendert sich seine Zeile.

    Q-BRIDGE (vlan_strategy "qbridge"), auf dem effektiven Bridge-Port (raw["port2bp"]): in jedem VLAN, das die Aenderung beruehrt,
    steht das Bit danach so, wie u / t es sagen. Das neue ungetaggte VLAN kommt in Egress und Untagged; das alte verliert das
    Untagged-Bit und das Egress-Bit nur, wenn es nicht getaggt bleibt; getaggt hinzu / weg aendert nur Egress. Alle Bits einer
    PortList gehen in EINE Kopie der gelesenen Bytes und EIN Varbind (eins je Port liesse im PDU den letzten gewinnen), und nur, wenn
    sie sich aendert; jedes andere Bit und die Laenge bleiben (nur ein Bit hinter dem Ende verlaengert die Liste bis dorthin).
    dot1qPvid (R21): eine ausdrueckliche pvid (VLAN-ID 1..4094 als Text, ein VLAN des Switches, R23, nur Q-BRIDGE) geht vor, sonst das
    neue ungetaggte VLAN; bei u -> None ohne pvid wird keine PVID geschrieben. Hat der Port danach ein ungetaggtes VLAN, muss eine
    ausdrueckliche pvid es sein (sonst waere er per SNMP nicht verwaltbar, R12). Eine pvid, die schon gilt, schreibt nichts (ausser
    zusammen mit u). cisco_vmps (R20): VLANs nur als Access-VLAN eines Ports mit vmVlan-Zeile, ueber vmVlan.<ifIndex>, keine pvid. An/Aus
    und Name bei jedem Treiber ueber IF-MIB: ifAdminStatus / ifAlias .<ifIndex>. PoE (R30, jeder Treiber mit snmp_poe):
    pethPsePortAdminEnable.<Gruppe>.<Port> des Eintrags, den raw["poe"] dem Port zuordnet (poller.poe_ports), nie ifIndex oder
    Bridge-Port.

    Feste Reihenfolge der Varbinds (das SET-PDU wirkt laut RFC 3416 als Ganzes): Egress, Untagged (je nach VLAN-ID), dot1qPvid (nach
    Bridge-Port), vmVlan, ifAdminStatus, ifAlias (je nach ifIndex), pethPsePortAdminEnable (nach Gruppe, dann Port). Ein Feld mit schon
    dem Zielwert, ein Port ohne Felder: nichts.

    ValueError mit deutschem Grund ("Port X: <Grund>") und ohne Teilergebnis, sobald snmp_block_reason einen Port ablehnt (dort stehen
    die Regeln; changes.plan_ports sperrt solche Ports schon beim Planen und rendert nur die anderen), die Felder eines Ports kein dict
    sind oder zwei Ports der Aenderung denselben ifIndex oder denselben PoE-Eintrag haetten. cfg, raw und desired bleiben unveraendert.
    """
    portlists: dict[str, dict[str, bytes]] = {"egress": {}, "untagged": {}}  # VLAN -> PortList mit allen Bits dieses Plans
    values: dict[str, dict[int, tuple[str, str]]] = {"pvid": {}, "vmvlan": {}, "ifadmin": {}, "ifalias": {}}  # Index -> (Typ, Wert)
    owner: dict[int, str] = {}  # ifIndex -> Port; zwei Ports auf einem ifIndex ueberschrieben einander (Bridge-Ports: bp2port)
    poe: dict[tuple[int, int], str] = {}  # PoE-Eintrag (Gruppe, Port) -> "1" an / "2" aus
    poe_owner: dict[tuple[int, int], str] = {}  # PoE-Eintrag -> Port; zwei Ports auf einem schalteten dasselbe Geraet
    shown: list[str] = []
    for p in sorted(desired, key=port_order):
        d = desired[p]
        if not isinstance(d, dict):
            raise ValueError(f"Port {p}: keine Felder ({d!r})")
        if not d:
            continue
        reason = snmp_block_reason(driver, cfg, raw, p, d)
        if reason:
            raise ValueError(f"Port {p}: {reason}")
        st, ifi = cfg["ports"][p], raw["ifindex"][p]
        if owner.setdefault(ifi, p) != p:
            raise ValueError(f"Port {p}: ifIndex {ifi} gehört auch zu Port {owner[ifi]}")
        u, t, pvid = d.get("u", st["u"]), list(d.get("t", st["t"])), d.get("pvid")
        if u != st["u"] or set(t) != set(st["t"]) or pvid is not None:
            shown += _vlan_ops(driver, raw, p, st, u, t, pvid, portlists, values)
        if "en" in d and d["en"] != st["en"]:
            values["ifadmin"][ifi] = ("i", "1" if d["en"] else "2")
            shown.append(f"Port {p}: {_onoff(st['en'])} → {_onoff(d['en'])}")
        if "name" in d and d["name"] != st["name"]:
            values["ifalias"][ifi] = ("x", d["name"].encode("utf-8").hex().upper())
            shown.append(f"Port {p}: Name {_quote(st['name'])} → {_quote(d['name'])}")
        if "poe" in d and d["poe"] != st["poe"]:
            entry = (raw["poe"][p]["group"], raw["poe"][p]["index"])
            if poe_owner.setdefault(entry, p) != p:
                raise ValueError(f"Port {p}: PoE-Eintrag {entry[0]}.{entry[1]} gehört auch zu Port {poe_owner[entry]}")
            poe[entry] = "1" if d["poe"] else "2"
            shown.append(f"Port {p}: PoE {_onoff(st['poe'])} → {_onoff(d['poe'])}")
    ops = [(f"{driver.oids[kind]}.{vid}", "x", snmp.portlist_to_hex(data))
           for kind in ("egress", "untagged") for vid, data in sorted(portlists[kind].items(), key=lambda kv: int(kv[0]))
           if data != raw[kind][vid]]
    ops += [(f"{driver.oids[kind]}.{index}", typ, value)
            for kind in ("pvid", "vmvlan", "ifadmin", "ifalias") for index, (typ, value) in sorted(values[kind].items())]
    ops += [(f"{driver.oids['poe_admin']}.{group}.{index}", "i", value) for (group, index), value in sorted(poe.items())]
    return ops, shown


# ── Anwenden ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def apply_ops(row, driver: drivers.Driver, ops: list[tuple[str, str, str]]) -> str:
    """Die Varbinds `ops` (aus render_ops, fuer diesen Switch gerechnet) mit EINEM snmpset an den Switch `row` (switches-Zeile)
    schreiben, mit der SCHREIB-Identitaet poller.creds_of(row, write=True); liefert die Ausgabe von snmpset. Ohne ops geht nichts
    hinaus (""). driver ist der Treiber, fuer den render_ops gerechnet hat; jeder Treiber schreibt heute gleich, mit einem snmpset.

    snmp.SnmpError, wenn es keine Schreib-Identitaet gibt (Grund aus write_identity; dann ist nichts gesendet) oder snmpset scheitert.
    Ein gescheitertes SET heisst NICHT "nicht geschrieben": nach einem Timeout ist offen, ob der Switch die Werte schon uebernommen hat
    (das PDU wirkt als Ganzes, die Antwort kann trotzdem verloren gehen). Darum wiederholt apply_ops nie, und der Aufrufer
    (changes.run_change) liest immer zurueck und prueft."""
    if not ops:
        return ""
    return await snmp.set_vars(row["host"], poller.creds_of(row, write=True), list(ops))
