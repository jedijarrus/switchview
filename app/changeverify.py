"""Checking a change after it was sent: verify_ports against the running-config read back over SSH, verify_snmp against the SNMP
read-back. Split from changes.py (Phase 3, Task 11), the code as it was; changes re-exports every name."""
import cfgparse
import snmp
import snmpwrite


def verify_ports(cfg_after: dict, desired: dict) -> list[str]:
    bad = []
    for p, d in desired.items():
        st = cfgparse.port_state(cfg_after, p)
        for k, v in d.items():
            # Limits/Gast-VLAN bleiben nach 'no aaa port-access ...' in der Konfiguration stehen, wirken dann aber nicht
            if (k in ("cl", "xuv") and not st["x"]) or (k in ("al", "muv") and not st["m"]):
                continue
            have = sorted(st[k], key=int) if k == "t" else st.get(k)    # ohne PoE-Zustand (poe fehlt / None) passt kein PoE-Ziel
            want = sorted(v, key=int) if k == "t" else v
            if have != want:
                bad.append(f"Port {p}: {k} ist {have!r}, erwartet {want!r}")
    return bad


def verify_snmp(driver, cfg: dict, cfg_after: dict, raw_after: dict, desired: dict, *, raw: dict) -> list[str]:
    """Das Pruefen nach einem SNMP-SET, das Gegenstueck zu verify_ports: was im Read-back (cfg_after, raw_after aus snmpwrite.read_cfg)
    nicht so ist, wie die Aenderung desired es aus cfg / raw (dem Read, gegen den sie geplant und gerendert ist) machen will, je eine
    Zeile, Ports in natuerlicher Reihenfolge; leer heisst ok.
      - Ein geschriebener Port, den der Read-back nicht mehr kennt (fehlt in raw_after["ifindex"]), weicht ab: cfg haelt fuer ihn nur
        Platzhalter (port_state fuellte Vorgaben ein), an denen ein Ziel wie "Name leer" sonst unbemerkt vorbeikaeme. Ebenso einer, den
        er als nicht verwaltbar fuehrt (raw_after["unmanaged"]), wenn sich ein VLAN-Feld aendert (R41): sein u ist nur ein Platzhalter
        (None), an dem "kein ungetaggtes VLAN" vorbeikaeme. en, name und poe lesen u nie, sie werden einzeln geprueft wie unten.
      - Ebenso einer, der im Read-back ein anderes Interface ist als in raw (M4): ein anderer ifIndex, oder bei Q-BRIDGE fuer eine
        VLAN-Aenderung (die ueber den Bridge-Port geht, PortList-Bits und dot1qPvid) ein anderer Bridge-Port. Dann wurden Interfaces
        zwischen Lesen und Zuruecklesen umnummeriert, das SET kann ein anderes Interface getroffen haben, und was der Read-back unter
        dem Namen zeigt, sagt nichts darueber. Den Bridge-Port eines Ports, dessen SET ihn nicht nutzt (vmVlan, An/Aus, Name, PoE),
        prueft es nicht: ein Cisco-Access-Port ist im Default-Kontext oft gar keiner (R45).
      - Aendert sich u oder t, zaehlt die GANZE VLAN-Zugehoerigkeit (R32): u und t, wie cfg sie zeigt, mit desired darueber. Ein
        VLAN-Wechsel sind mehrere Varbinds (Egress und Untagged des alten und des neuen VLANs, die PVID); kaeme einer nicht an, stuende
        der Port sonst etwa noch getaggt im alten VLAN. Wechselt u zu einem VLAN und zeigt der Read-back es (sonst meldet verify_ports
        schon u), muss bei Q-BRIDGE dazu dessen Egress-Bit gesetzt sein: ungetaggt ohne Egress zeigt cfg nicht (u kommt aus der
        Untagged-Liste), der Port gaebe das VLAN aber nicht aus.
      - en, name und poe wie verify_ports, wenn desired sie hat. poe ist das pethPsePortAdminEnable des Eintrags, den der Read-back dem
        Port zuordnet (poller.poe_ports); ordnet er keinen mehr zu (poe None), weicht das ab. Und es muss DER Eintrag sein, auf den das
        SET ging (raw["poe"], Gruppe und Port): ordnet der Read-back dem Port einen anderen zu, etwa weil sich PoE-Hardware zwischen Read
        und SET geaendert hat, sagt dessen Zustand nichts ueber das SET, und ein anderes Geraet koennte geschaltet sein.
      - Die PVID (R21) bei Q-BRIDGE (vlan_strategy "qbridge") fuer einen Port ohne vmVlan-Zeile, gelesen aus raw_after["pvid"]:
        erwartet ist eine ausdrueckliche pvid aus desired, sonst das neue ungetaggte VLAN, wenn u zu einem VLAN wechselt (genau das
        schreibt render_ops). Sonst (u -> None, nur t / en / name) schreibt render_ops keine PVID, und keine wird erwartet. Bei
        cisco_vmps nie: vmVlan ist dort das VLAN des Access-Ports (u); Egress-Bits und dot1qPvid schreibt dieser Weg nicht."""
    bad = []
    for p in sorted(desired, key=snmpwrite.port_order):
        d = desired[p]
        if p not in raw_after["ifindex"]:
            bad.append(f"Port {p}: beim Zurücklesen nicht gefunden")
            continue
        via_bp = driver.vlan_strategy == "qbridge" and bool(snmpwrite.VLAN_FIELDS & set(d))    # ging das SET ueber den Bridge-Port?
        if raw_after["ifindex"][p] != raw["ifindex"].get(p) or (via_bp and raw_after["port2bp"].get(p) != raw["port2bp"].get(p)):
            bad.append(f"Port {p}: Interface-Nummer hat sich geändert")
            continue
        if p in raw_after["unmanaged"] and snmpwrite.VLAN_FIELDS & set(d):    # R41: nur die VLAN-Felder lesen den Platzhalter u
            bad.append(f"Port {p}: nach der Änderung {raw_after['unmanaged'][p]}")
            continue
        want = {k: v for k, v in d.items() if k != "pvid"}
        if {"u", "t"} & set(d):
            st = cfgparse.port_state(cfg, p)
            want = {"u": st["u"], "t": st["t"]} | want
        bad += verify_ports(cfg_after, {p: want})
        if "poe" in d:
            bad += _poe_entry_moved(p, raw, raw_after)
        if driver.vlan_strategy != "qbridge" or p in raw_after["vmvlan"]:
            continue
        u = d.get("u")
        if u is not None and cfgparse.port_state(cfg_after, p)["u"] == u:  # ungetaggt im neuen VLAN, wie gewollt: auch mit Egress-Bit?
            bp, egress = raw_after["port2bp"].get(p), raw_after["egress"].get(u)
            if bp and egress is not None and not snmp.portlist_has_bit(egress, bp):
                bad.append(f"Port {p}: VLAN {u} ungetaggt, aber ohne Egress-Bit")
        pvid = d["pvid"] if "pvid" in d else d.get("u")
        if pvid is not None and raw_after["pvid"].get(p) != pvid:
            bad.append(f"Port {p}: pvid ist {raw_after['pvid'].get(p)!r}, erwartet {pvid!r}")
    return bad


def _poe_entry_moved(p: str, raw: dict, raw_after: dict) -> list[str]:
    """verify_snmp: zeigt der Read-back Port p einem anderen PoE-Eintrag zugeordnet als dem, auf den das SET ging (raw["poe"][p])?
    Ohne Eintrag im Read-back meldet verify_ports schon poe None."""
    planned, now = raw["poe"].get(p), raw_after["poe"].get(p)
    if planned is None:  # render_ops lehnt PoE ohne Eintrag ab: kann nicht vorkommen, zaehlt aber nie als ok
        return [f"Port {p}: PoE ohne geplanten Eintrag"]
    if now is not None and (now["group"], now["index"]) != (planned["group"], planned["index"]):
        return [f"Port {p}: PoE-Eintrag ist jetzt {now['group']}.{now['index']}, geschrieben wurde {planned['group']}.{planned['index']}"]
    return []
