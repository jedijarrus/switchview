# SwitchView – CLI-Referenz ProCurve / ArubaOS-Switch

Stand: 03.11.2026 · Geltungsbereich: ProCurve / ArubaOS-Switch, Firmware-Zweige J.15, YA/WB 15.x und 16.x · Zugriff: netmiko `hp_procurve` (SSH) + SNMP

**Belegkennzeichnung**

| Kürzel | Bedeutung |
|---|---|
| **[D x]** | offizielle HPE/Aruba-Doku, Branch/Version x (Links in Abschnitt 5) |
| **[C]** | Quellcode netmiko / paramiko (Stand develop/main, 11/2026) |
| **[F]** | Forum/Community (HPE Community, ssh-audit-Wiki) |
| **[U]** | unbestätigt / Erfahrungswert / abgeleitet – vor Rollout am Gerät prüfen |

Verwendete Doku-Stände: J.15.09-Guides (2520G, 08/2012) + Release Notes J.15.09.0028 (09/2016); YA/YB.15.17 (ATMG, MCG, ASG); WB.15.11 (ATMG, ASG; für WB.15.12 nur Release Notes gefunden); Basic Operation Guide 15.x (2015/03, gilt laut Titelblatt auch für 2520G/2530/2920); AOS-S Basic Operation Guide 16.10; AOS-S 16.11 YA/YB HTML-Guides (ATMG, ASG, MCG). **Für WB.16.06 wurde kein eigener Guide geprüft** – 16.10/16.11-Doku wird übertragen; versionsabhängige 16.x-Features sind dort mit [U] markiert.

---

## 1. Kurzfazit / Empfehlungen für das Tool

1. **paramiko auf 4.x pinnen: `pip install "netmiko[par4]"` (= `paramiko>=4.0,<5.0`).** paramiko 5.0.0 (09.05.2026) hat SHA-1-KEX (`diffie-hellman-group1-sha1`, `group14-sha1`, `group-exchange-sha1`) und RSA-Signaturen mit SHA-1 (`ssh-rsa`) entfernt [C]. Der 2520G (J.15) bietet nur diese [U] → **mit paramiko 5 keine Verbindung**. netmiko 4.8.0 verlangt nur `paramiko>=3.5.1`, ein nacktes `pip install netmiko` zieht also 5.1.0 [C]. paramiko 4.0 kann alles, was J.15 anbietet, ohne `disabled_algorithms`-Anpassung [C]. Für YA/WB 15.x ist das KEX-Angebot nicht dokumentiert, vermutlich ebenfalls nur SHA-1 [U].
2. **Untagged-Wechsel = nur „neues VLAN setzen“.** `vlan <neu> untagged <ports>` entfernt die alte untagged-Mitgliedschaft automatisch. Tagged-Mitgliedschaften bleiben erhalten [D alle: max. 1 untagged VLAN/Port; F: HPE-Engineer bestätigt Auto-Entfernung]. Die Umkehrung (`no vlan <alt> untagged <p>`) schlägt fehl, wenn der Port danach in keinem VLAN wäre [F]. Das Tool baut deshalb nie „entfernen, dann hinzufügen“.
3. **Ports mit aktiver 802.1X-/MAC-Auth-Session:** statische VLAN-Änderungen greifen erst nach Session-Ende [D 16.11]. Ein RADIUS-VLAN überschreibt das statische untagged VLAN temporär. Es steht nicht in der running-config, `show vlan <vid>` listet es unter „Overridden Port VLAN configuration“ [D J.15].
4. **Trunks:** VLANs nur auf `TrkX` setzen, nie auf Member-Ports [D]. Wird ein Trunk angelegt, landet er im DEFAULT_VLAN (alte VLANs weg); beim Entfernen aus dem Trunk landet der Port im DEFAULT_VLAN [D J.15, 16.11]. 802.1X/MAC-Auth geht nicht auf Trunk-/LACP-Ports [D].
5. **2520G/J.15 ist eingeschränkt:** 802.1X client-limit nur 1–2, MAC-Auth addr-limit 1–2 [D J.15]. Es gibt kein `session interactive-mode` [D BOG 15.x] und keine `interface <p> tagged|untagged vlan`-Syntax (nicht in der J.15-Doku). `ip ssh` hat dort weder `version` noch `kex` [D J.15]. HPE empfiehlt `terminal width` ≤ 150 [D RN J.15.09]. **CoA/`dyn-authorization` ist in J.15.09 dagegen dokumentiert** [D J.15].
6. **Ablauf pro Änderung:** Snapshot (`show running-config`), Befehle senden, Read-back (`show vlan ports <p> detail` o. ä.), erst dann `write memory` als eigener, expliziter Schritt. Pro Switch serialisieren: max. 1 Konsole + 5 SSH/Telnet-Sessions [D J.15]. Immer sauber ausloggen.
7. **Schutzliste im Tool:** Uplink-/Management-Port (der Port, über den die Switch-IP erreichbar ist), Trunk-Member, Primary-VLAN, Management-VLAN und Ports mit LLDP-Nachbar vom Typ Switch/Bridge sind gesperrt oder brauchen eine Extra-Bestätigung [U, Empfehlung].
8. **Fähigkeiten beim ersten Kontakt ermitteln**, statt sie nach Modell anzunehmen: `show version`/SNMP `sysDescr` (Branch), `show radius` (Spalte „Dynamic Authorization UDP Port“ = CoA vorhanden), `show vlans` (Primary/Management VLAN). Unklare Syntax per `?`-Hilfe nur manuell prüfen, nie im Tool.

---

## 2. Übersicht: Vorgang → Befehl je Branch

Sofern nicht anders vermerkt, ist die Syntax in allen drei Spalten gleich.

| Vorgang | J.15 (2520G) | YA/WB 15.x | YA.16.11 / WB.16.06 | Beleg |
|---|---|---|---|---|
| Paging aus | `no page` | `no page` | `no page` | [C] netmiko; `page` = Toggle [D BOG 15.x/16.10] |
| Zeilenbreite | `terminal width <n>` (HPE: ≤150) | dto. | dto. | [D RN J.15, BOG 15.x] |
| Config-Modus rein/raus | `configure` bzw. `configure terminal` / `end` | dto. | dto. | [D J.15 MCG, BOG 16.10] |
| Running-Config | `show running-config` | + `show running-config interface <p>` / `vlan <ids>` / `structured` | dto. + `status` | [D BOG 15.x, 16.11]; J.15-Varianten [U] |
| VLAN-Liste | `show vlans` | dto. | dto. | [D] |
| VLAN-Detail | `show vlans <vid>` | dto. | dto. | [D] |
| VLANs eines Ports | `show vlan ports <p> [detail]` | dto. | dto. | [D J.15, 16.11] |
| Port-Status | `show interfaces brief`, `show interfaces <p>`, `show interfaces config` | dto. | dto. | [D] |
| Portnamen | `show name [<p>]` | dto. | dto. | [D] |
| LLDP-Nachbarn | `show lldp info remote-device [<p>]` | dto. | dto. | [D J.15, 16.11] |
| 802.1X-Status | `show port-access authenticator [<p>] [config\|statistics\|session-counters\|vlan\|clients [detailed]]` | dto. | dto. + `show port-access clients [<p>] [detailed]` | [D J.15, 16.11] |
| MAC-Auth-Status | `show port-access [<p>] mac-based [clients\|config [detail]]` | dto. | `show port-access mac-based <p> config detailed` | [D J.15, 16.11] |
| Port-Access gesamt | `show port-access config` | dto. | dto. | [D J.15, 16.11] |
| Trunks | `show trunks [<p>]`, `show lacp` | dto. | dto. | [D] |
| System/Version | `show system [information]`, `show version` | dto. | dto. | [D] |
| Untagged setzen | `vlan <vid> untagged <ports>` | dto. oder `interface <ports> untagged vlan <vid>` | dto. | [D J.15, YA.15.17, WB.15.11, 16.11] |
| Tagged hinzufügen | `vlan <vid> tagged <ports>` | dto. oder `interface <ports> tagged vlan <vid-list>` | dto. | [D] |
| Tagged entfernen | `no vlan <vid> tagged <ports>` | dto. oder `no interface <ports> tagged vlan <vid-list>` | dto. | [D] |
| VLAN anlegen/benennen | `vlan <vid> name "<text>"` | dto. | dto. | [D] |
| Port an/aus | `interface <ports> enable\|disable` | dto. | dto. | [D] |
| Portname setzen | `interface <ports> name <text>` | dto. | dto. | [D] |
| Portname löschen | `no interface <ports> name` | dto. | dto. | [D J.15, 16.11] |
| 802.1X-Methode | `aaa authentication port-access eap-radius` | dto. | dto. | [D] |
| 802.1X Port an/aus | `[no] aaa port-access authenticator <ports>` | dto. | dto. | [D] |
| 802.1X global an/aus | `[no] aaa port-access authenticator active` | dto. | dto. | [D] |
| 802.1X client-limit | `… authenticator <ports> client-limit <1-2>` | YA.15.17: 1–2 (Doku), WB.15.11: 1–32 | 1–32 | [D] |
| MAC-Auth Port an/aus | `[no] aaa port-access mac-based <ports>` | dto. | dto. | [D] |
| MAC-Format | `aaa port-access mac-based addr-format <fmt>` | dto. | dto. | [D] |
| Reihenfolge 802.1X/MAC | – (parallel, 802.1X hat Vorrang) | – | `aaa port-access <ports> auth-order …` / `auth-priority …` | [D 16.11]; ab welcher 16.x [U] |
| RADIUS-Server | `radius-server host <ip> key <key>` | dto. | dto. | [D] |
| CoA pro Server | `radius-server host <ip> dyn-authorization` | dto. (WB.15.11 + `time-window`) | dto. | [D J.15, YA.15.17, WB.15.11, 16.11] |
| CoA-Port | `radius-server dyn-autz-port <1024-49151>` (Default 3799) | dto. | dto. | [D] |
| Voice-VLAN | `vlan <vid> voice` | dto. | dto. | [D] |
| Speichern | `write memory` | dto. | dto. | [D] |
| Änderungsstand | – | `show config status` [U für 15.x] | `show running-config status` | [D BOG 16.10, 16.11] |

---

## 3. Details je Vorgang

### 3.1 Session-Vorbereitung

**Login-Ablauf** (SSH, alle Branches):
1. SSH-Auth (User/Passwort).
2. Banner mit „Copyright …“ und **„Press any key to continue“** [D BOG 15.x/16.10]. Der Prompt kann vor dem Banner erscheinen [C, Kommentar im netmiko-Treiber].
3. Prompt `name>` (Operator) oder `name#` (Manager). Bei `>` folgt `enable` mit Manager-Credentials.
4. `no page` (Paging aus, gilt pro Session).

| Thema | Details | Beleg |
|---|---|---|
| Paging | `page` **toggelt** (zweimal senden = wieder an). Immer explizit `no page`. Alternative: `terminal length <x>`. | [D BOG], [C] |
| Pager-Prompt | `-- MORE --, next page: Space, next line: Enter, quit: Control-C` | [D BOG 16.10] |
| Prompts | `switch#`, `switch(config)#`, `switch(vlan-10)#`, `switch(eth-5)#`, `switch(eth-1-4)#`, Stack: `switch-Stack(config)#` | [D BOG 16.10] |
| Config-Modus | `configure` und `configure terminal` funktionieren beide, `end` führt zurück in den Manager-Exec. | [D J.15 MCG, BOG 16.10] |
| Terminal-Breite | netmiko sendet `terminal width 511`. Laut J.15.09-Release-Notes besser ≤ 150. | [C], [D RN J.15.09] |
| Session-Limit | 1 Konsole + bis zu 5 SSH/Telnet-Sessions | [D J.15 ASG] |

**Rückfragen (y/n), die Automatisierung blockieren** (netmiko wartet bis zum Timeout):

| Auslöser | Prompt | Beleg |
|---|---|---|
| `no vlan <vid>`, wenn Ports nur in diesem VLAN sind | `The following ports will be moved to the default VLAN: … Do you want to continue? [y/n]` | [D J.15, 16.11] |
| `logout` mit ungespeicherten Änderungen | `Do you want to save current configuration [y/n]?` (netmiko antwortet `n`), dann `Do you want to log out [y/n]?` (netmiko antwortet `y`) | [C], [D BOG] |
| `reload`, `boot system …` | `Device will be rebooted, do you want to continue [y/n]?` + Speicherfrage | [D BOG] |
| `max-vlans` u. ä. | Reboot-Hinweis/Rückfrage | [D J.15 ATMG] |
| `no password all` | `Password protection for all will be deleted, continue [y/n]?` | [D BOG 16.10] |
| `menu`, `setup`, `snmpv3 enable`, `password manager` (ohne `plaintext`) | interaktiver Dialog | [D BOG], [F netmiko #1976] |

`session interactive-mode disable` beantwortet y/n-Fragen automatisch mit „yes“, Speicherfragen mit „no“. **Auf 2520/2520G nicht unterstützt** [D BOG 15.x]. Der Modus gilt nur pro Session. Empfehlung: nicht nutzen und Prompt-Befehle gar nicht automatisieren (Abschnitt 3.13).

### 3.2 Konfiguration lesen

**VLAN-Block in der running-config** (Format ab 15.x belegt, J.15-Beispiele gleich) [D J.15 MCG, WB.15.11 ASG, BOG 15.x]:

```
trunk 1,2 trk1
vlan 1
   name "DEFAULT_VLAN"
   untagged 3-24
   ip address dhcp-bootp
   tagged A4-A6
   no untagged trk1
   exit
vlan 20
   name "VLAN20"
   untagged C10-C14
   tagged trk1
   no ip address
   exit
```

- `no untagged <ports>` steht **nur unter VLAN 1**. Es heißt: Port ist nicht im DEFAULT_VLAN [F; in allen Doku-Beispielen nur dort].
- Ein Port kann tagged in VLAN 1 und gleichzeitig untagged in einem anderen VLAN sein (Beispiel `tagged A4-A6` unter vlan 1) [D WB.15.11].
- Port-Listen: Komma-getrennte Bereiche, Trunks als `Trk1`/`trk1`, Modulports `A1-A4`, gemischt `A1,A7-A10,Trk1` [D]. Die Reihenfolge der Zeilen im Block variiert (`ip address` vor oder nach `untagged`/`tagged`), also schlüsselbasiert parsen.
- Pro Interface (15.x/16.x): `show running-config interface 2-3` zeigt abgeleitete Zeilen `untagged vlan 1`, `tagged vlan …`, `name "…"`, `disable` [D BOG 15.x, 16.11]. Diese Ausgabe ist **nicht** zurückspielbar [D BOG 15.x].
- Die running-config enthält nur Statisches. Dynamische Zuweisungen (RADIUS-VLAN, Auth-/Unauth-VLAN, GVRP) erscheinen nicht.

**Weitere Ausgaben:**

| Befehl | Hinweise für den Parser | Beleg |
|---|---|---|
| `show vlans` | Kopf mit `Maximum VLANs to support`, `Primary VLAN`, `Management VLAN`. **Spalten je Branch verschieden** (J.15 teils ohne `Jumbo`, 16.x mit `\|`-Trenner) → nach Header parsen. Der Name ist in der Tabelle auf 20 Zeichen begrenzt. | [D J.15, 16.11] |
| `show vlans <vid>` | Liste `Port / Mode (Untagged/Tagged/Auto) / Unknown VLAN / Status`, dazu Abschnitt **„Overridden Port VLAN configuration“** für Ports, die gerade durch Auth-VLANs überschrieben sind | [D J.15 ASG] |
| `show vlan ports <p> detail` | ein Block pro Port, Spalte `Mode` = Untagged/Tagged | [D J.15, 16.11] |
| `show interfaces brief` | `Port, Type, Intrusion Alert, Enabled, Status, Mode, MDI, Flow, Bcast Limit` | [D] |
| `show lldp info remote-device` | Tabelle `LocalPort \| ChassisId PortId PortDescr SysName`. Mit Port: Detail inkl. `System Capabilities`, bei LLDP-MED `Media Policy Vlan id`. Mehrere Einträge pro Port = Hub oder Mehrfachgerät. | [D J.15, 16.11] |
| `show port-access authenticator vlan` | `Access Control`, `Unauth VLAN ID`, `Auth VLAN ID` je Port | [D J.15] |
| `show port-access clients <p> detailed` (16.x) | u. a. `Untagged VLAN`, `Tagged VLANs`, `Auth Order` | [D 16.11] |
| `show trunks` | `Port \| Name Type \| Group Type` (nur statische Trunks/LACP) | [D] |
| `show system` | `Software revision : J.15.XX`, `Base MAC Addr` | [D J.15 MCG] |

Lesen per SNMP (Q-BRIDGE-MIB PVID/Egress/Untagged) ist robuster als CLI-Parsing. Ob die SNMP-Sicht Auth-Overrides zeigt oder die statische Konfiguration, ist hier nicht geprüft [U].

### 3.3 Ungetaggtes (Access-)VLAN ändern

```
configure
vlan 30 untagged 5-8,12
end
show vlan ports 5-8,12 detail
```

| Aspekt | Verhalten | Beleg |
|---|---|---|
| Grundregel | Ein Port ist untagged in **max. einem** port-basierten VLAN und Mitglied in **mind. einem** VLAN. | [D J.15, YA.15.17, 16.11] |
| Alte untagged-Mitgliedschaft | wird **automatisch entfernt**. Unter VLAN 1 erscheint dann `no untagged <p>`. Tagged-Mitgliedschaften bleiben. | [F HPE Community, HPE-Engineer „Arimo“]; Regel [D] |
| Zurück nach VLAN 1 | `vlan 1 untagged <p>`, nicht `no vlan 30 untagged <p>` | [F] |
| `no vlan <vid> untagged <p>` | scheitert, wenn der Port danach verwaist wäre (Fehlermeldung, keine Änderung). Ist der Port woanders tagged, wird er „tagged-only“ (keine PVID, untagged Frames werden verworfen). | [F]; Drop-Verhalten [D J.15 ATMG] |
| Zielt `untagged` auf ein nicht existierendes VLAN | `vlan <vid> …` legt laut Doku ein fehlendes VLAN an. Ob das auch mit `untagged`/`tagged`-Option gilt, ist nicht explizit belegt. `interface … untagged vlan <vid>` meldet bei fehlendem VLAN einen Fehler. | [D 16.11/J.15 für `vlan <vid>`], [D YA.15.17 für `interface`-Variante], Rest [U] → **Tool prüft VLAN-Existenz vorher** |
| VLAN 1 / DEFAULT_VLAN | kann umbenannt, aber nicht gelöscht werden. Die VID bleibt 1. Ports, die nicht explizit entfernt wurden, bleiben drin. | [D] |
| Primary VLAN | Default = VLAN 1. DHCP/Bootp-Werte des Switches (IP, GW, TimeP) kommen aus dem Primary VLAN. Ein Nicht-Default-Primary-VLAN lässt sich nicht löschen. | [D 16.11, J.15] |
| Management VLAN | `management-vlan <vid>`: Zugriff nur aus diesem VLAN. Wer eine Telnet-/SSH-Session über einen ausgeschlossenen Port hat, verliert den Zugang beim Logout. Routing in andere VLANs ist gesperrt. | [D 16.11] |
| Uplink-Falle | Den untagged-Wechsel auf dem Port, über den die Switch-IP erreichbar ist, verliert das Tool sofort. Port sperren. | [U, Empfehlung] |
| Auth-Ports | Läuft eine Session, greift die Änderung erst nach Session-Ende. | [D 16.11 ASG] |
| Trunks | nur `vlan <vid> untagged Trk1`. Member-Ports einzeln geht nicht. | [D 16.11 MCG, J.15] |
| Port-Liste | `1-5,7`, `Trk1`, Module `A1-A2`, Stack (2920) `1/1-1/24` | [D]; Stack-Format [U] |

### 3.4 Getaggte VLANs hinzufügen/entfernen

```
vlan 40 tagged 49-50,Trk1
no vlan 40 tagged 49-50
interface 49-50 tagged vlan 40,41,50-55        ; nur 15.x/16.x
no interface 49-50 tagged vlan 50-55           ; nur 15.x/16.x
```

- `no vlan <vid> tagged <p>` setzt den Port auf „No“, bei aktivem GVRP auf „Auto“ [D 16.11].
- Für dynamische GVRP-VLANs gibt es nur die Meldung `VLAN already exists with no change` [D 16.11, YA.15.17].
- `interface <ports> tagged|untagged|forbid vlan <vid-list>` bearbeitet bis zu 256 VLANs auf einmal. Fehlt ein VLAN, kommt ein Fehler [D YA.15.17, WB.15.11]. Für J.15 nicht dokumentiert, also im Tool nur `vlan <vid> tagged …` verwenden.
- Trunks: nur `TrkX`. Bei dynamischen LACP-Trunks (`DynX`) ist ein VLAN außer DEFAULT_VLAN nur mit GVRP möglich [D 16.11 MCG].
- Entfernt das Tool das letzte VLAN eines Ports (tagged, ohne untagged), gilt dieselbe Verwaist-Sperre wie in 3.3 [F].

### 3.5 VLAN anlegen/benennen

```
vlan 30 name "Clients"
```

| Regel | Wert | Beleg |
|---|---|---|
| VID | 1–4094. Anzahl begrenzt durch `max-vlans` (J.15: 1–256, Änderung braucht `write memory` + Reboot). | [D J.15 ATMG] |
| Default-Name | `VLANn` (z. B. `VLAN30`) | [D] |
| Verbotene Zeichen | `@ # $ ^ & * ( )`, Leerzeichen nur mit Quotes `"…"`/`'…'` | [D J.15, 16.11] |
| Länge | Menü-Interface: **max. 12 Zeichen, keine Leerzeichen** [D J.15 ATMG]. CLI-Maximum nicht dokumentiert. Forum: 4208vl/L.11 lehnt > 12 ab [F]. Q-BRIDGE-MIB `dot1qVlanStaticName` erlaubt 0..32 [U]. |
| Löschen | `no vlan <vid>` → Rückfrage, Ports werden ins DEFAULT_VLAN verschoben | [D] |

Empfehlung: `^[A-Za-z0-9_-]{1,12}$`, immer in `"…"` senden.

### 3.6 Port an/aus, Portbeschreibung

```
interface 5 disable
interface 5 enable
interface 5-8 name Platz-107
no interface 5-8 name
; Kontextmodus:
interface 5
   name Platz-107
   disable
   exit
```

| Regel | Wert | Beleg |
|---|---|---|
| enable/disable | ohne `no`-Form. Default `enable`. Gilt pro Port, auch für Trunk-Member. | [D 16.11 MCG, J.15] |
| Name-Länge | bis **64** zusammenhängende alphanumerische Zeichen | [D J.15, 16.11] |
| Leerzeichen | **nicht erlaubt**, führen zu `Invalid input` (Leerzeichen beendet den Namen) | [D J.15, 16.11] |
| Erlaubte Sonderzeichen | in Doku-Beispielen `_ @ . : -` | [D J.15: `Bill_Smith@10.25.101.73`, `Draft-Server:Trunk`] |
| Anzeige | running-config: `name "Platz-107"` (mit Quotes) | [D BOG 15.x] |
| Trunks | Name pro Member-Port, nicht pro TrkX | [D] |
| Speichern | ohne `write memory` nach Reboot weg | [D] |

Quoted Namen mit Leerzeichen funktionieren auf neueren Firmwares wohl, sind aber laut Doku unzulässig [U].

### 3.7 802.1X (Port-based / Client-based)

**Einschalten** [D J.15, YA.15.17, WB.15.11, 16.11]:
```
radius-server host 10.0.0.10 key <secret>
aaa authentication port-access eap-radius
aaa port-access authenticator 1-20
aaa port-access authenticator 1-20 client-limit 2      ; client-based statt port-based
aaa port-access authenticator 1-20 unauth-vid 99       ; Gast-VLAN, muss existieren
aaa port-access authenticator 1-20 auth-vid 30         ; optional
aaa port-access authenticator active                   ; global, wirkt erst damit
```

**Ausschalten:** `no aaa port-access authenticator 1-20` (pro Port), global `no aaa port-access authenticator active` (alle Ports!).

| Parameter (`aaa port-access authenticator <p> …`) | J.15 (Doku) | 16.11 | Beleg |
|---|---|---|---|
| `control authorized\|auto\|unauthorized` | Default `auto` | dto. | [D] |
| `client-limit` | **1–2** | 1–32 (YA.15.17-Doku: 1–2 [U, vermutlich Doku-Übernahme]; WB.15.11: 1–32) | [D] |
| `no … client-limit` | zurück auf port-based. Neue Session ersetzt die alte. | dto. | [D] |
| `logoff-period` | 1–999999999, Default 300 s | – | [D J.15] |
| `quiet-period` / `tx-period` | 0–65535 / Default 60 s bzw. 30 s | – | [D J.15] |
| `supplicant-timeout` / `server-timeout` | 1–300, Default 30 s | – | [D J.15] |
| `max-requests` / `reauth-period` | 1–10 (Default 2) / 0–9999999 (0 = aus) | – | [D J.15] |
| `unauth-vid` / `auth-vid` | statisches VLAN, muss vorher existieren | dto. | [D] |

Syntax-Hinweis J.15: Die Syntaxzeile schreibt `aaa port-access authenticator client-limit <port-list> <1-2>`, das Beispiel `aaa port-access authenticator 10-12 client-limit 2`. Das Tool nutzt die Beispielform (identisch mit 16.x) [D J.15].

**Wie RADIUS-VLANs wirken** [D J.15, 16.11]:
- Rangfolge: RADIUS-VLAN → `auth-vid` → statisches untagged VLAN → sonst gesperrt.
- Das RADIUS-VLAN muss **statisch** existieren. Ist es nicht vorhanden oder nur dynamisch (GVRP), schlägt die Auth fehl. Ausnahme: `aaa port-access gvrp-vlans` [D 16.11].
- Der Port wird temporär untagged Mitglied des RADIUS-VLANs und verliert solange das statische untagged VLAN. Laut 802.1X-Regeln bleiben tagged Mitgliedschaften (z. B. Voice) nutzbar. Für MAC/Web-Auth heißt es dagegen „drops all other VLAN memberships“ [D 16.11, widersprüchlich → mit Telefon+PC testen, U].
- Mehrere Clients auf einem Port: alle im **selben** untagged VLAN. Der erste Client bestimmt es, abweichende werden blockiert.
- Anzeige: `show vlan <vid>` (Overridden-Abschnitt), `show port-access authenticator vlan`, 16.x `show port-access clients <p> detailed`. Nicht in `show running-config`.
- Konflikte: 802.1X und LACP schließen sich aus (`Error configuring port X: LACP and 802.1X cannot be run together`). Ports in einem LACP-Trunk erst aus dem Trunk nehmen. Mit RADIUS-VLAN auf Trunk-Port: Auth geht durch, Port wird aber blockiert [D J.15, 16.11].

### 3.8 MAC-Authentifizierung (MAB)

```
aaa port-access mac-based addr-format multi-colon        ; global
aaa port-access mac-based 1-20
aaa port-access mac-based 1-20 addr-limit 2
aaa port-access mac-based 1-20 unauth-vid 99
no aaa port-access mac-based 1-20
```

| Aspekt | Wert | Beleg |
|---|---|---|
| `addr-format` | `no-delimiter` (Default, `aabbccddeeff`), `single-dash`, `multi-dash`, `multi-colon`. J.15 zusätzlich `*-uppercase`-Varianten. | [D J.15, 16.11] |
| `addr-limit` | J.15: **1–2**, YA.15.17: 1–32, WB.15.11: 1–256, 16.11: bis 32 Sessions/Port | [D] |
| `logoff-period` | 60–9999999, Default 300 s | [D 16.11, J.15] |
| `unauth-vid` | 0 = keine VLAN-Änderung (Default). Ohne unauth-vid bleibt der Port bei Fehlschlag in seiner Original-VLAN-Konfiguration. | [D 16.11] |
| Kombination mit 802.1X | J.15: 802.1X + Web + MAC gleichzeitig auf einem Port (max. 2 Clients). Exklusiv dazu: Port-Security, MAC lockdown, MAC lockout. | [D J.15 ASG] |
| Vorrang | MAC lockout > MAC lockdown/Port-Security > 802.1X/Web/MAC. Ältere Releases: alle Methoden parallel, 802.1X vor MAC vor Web. | [D J.15, 16.11] |
| Reihenfolge steuern | nur 16.x: `aaa port-access <p> auth-order authenticator mac-based [local-mac]`, `… auth-priority …`. Eine Änderung **de-authentifiziert alle Clients** des Ports. Ab welcher 16.x-Version das geht (WB.16.06?) ist offen. | [D 16.11], Version [U] |
| Falle | Ist MAC-Auth primär, lösen EAP-Pakete von Supplicants keine MAC-Auth aus. HPE rät: 802.1X primär, Vorrang über `auth-priority`. | [D 16.11] |
| Voice | MAC-Auth im Voice-VLAN wird nicht empfohlen | [D 16.11] |
| unauth-vid bei 802.1X + MAC | Laufen beide auf einem Port, darf **nur MAC (oder Web)** ein `unauth-vid` haben. `aaa port-access mac-based <p>` wird sonst abgelehnt: „Configuration change denied … Only Web or MAC-authenticator can have unauthenticated VLAN enabled if 802.1X authenticator is enabled“. | [U] |
| addr-limit 1 | ist Standard und erscheint **nicht** in der running-config. Erst ab 2 steht die Zeile drin. | [U] |
| Reste nach `no aaa port-access …` | `client-limit`, `addr-limit` und `unauth-vid` bleiben als Zeilen stehen, wirken aber erst wieder beim Einschalten | [U] |
| LACP | wird auf MAC-/Web-Auth-Ports automatisch deaktiviert | [D J.15] |

### 3.9 RADIUS-Server und CoA

```
radius-server host 10.0.0.10 key <secret>
radius-server host 10.0.0.10 dyn-authorization
radius-server dyn-autz-port 3799
radius-server timeout 5
radius-server retransmit 3
radius-server dead-time 5
show radius
show radius dyn-authorization
show radius host 10.0.0.10 dyn-authorization
```

| Aspekt | J.15 | YA.15.17 | WB.15.11 | 16.11 | Beleg |
|---|---|---|---|---|---|
| Server | max. 3 | max. 3 | max. 3 | max. 3 Server / 15 Adressen, FQDN/IPv6 | [D] |
| `dyn-authorization` | **ja** | ja | ja | ja (Default: aus) | [D] |
| `dyn-autz-port` | 1024–49151, Default 3799 | dto. | dto. | dto. | [D] |
| `time-window` | nicht dokumentiert | nicht dokumentiert | `[time-window <0-65535>]`, **Default 300 s** | Spalte „Time Window“ in `show radius` | [D WB.15.11, 16.11] |
| `timeout` | 1–15, **Default 3 s** | – | 1–15 | 1–15, **Default 5 s** | [D] |
| `retransmit` | 1–5, Default 3 | – | – | 1–5, Default 3 | [D] |

- **CoA-Falle `time-window`:** Ist der Wert ≠ 0, müssen CoA/Disconnect-Requests das Attribut `Event-Timestamp` enthalten, sonst werden sie **verworfen** [D WB.15.11]. Für PacketFence/ClearPass prüfen oder `time-window 0` setzen [U].
- Der CoA-Client muss als `radius-server host` mit `dyn-authorization` eingetragen sein. Zähler stehen in `show radius dyn-authorization` [D 16.11].
- Seit 16.x erzwingt CoA mit `Session-Timeout` eine Re-Auth [D 16.11].
- **`show radius` zeigt den Server-Key im Klartext** (Doku-Beispiele) [D]. Ausgabe im Tool-Log maskieren.
- `~` im Key nur auf neueren Firmwares, nicht rückwärtskompatibel [D 16.11].
- Key in Config-Dateien: per TFTP/Xmodem nur mit `include-credentials` [D WB.15.11].

### 3.10 Voice-VLAN, LLDP-MED

```
vlan 50 voice
vlan 50 tagged 1-20
lldp config 1-20 medTlvEnable network_policy     ; Default bereits an
```

- Nur statische, port-basierte VLANs. Alle Ports im Voice-VLAN tagged, damit QoS-Prioritäten erhalten bleiben. Der PC hinter dem Telefon hängt tagged/untagged im Daten-VLAN [D 16.11, J.15].
- LLDP-MED ist per Default an. `network_policy` (Voice-VLAN) wird nur auf Ports angekündigt, die Mitglied eines Voice-VLANs sind. Bei mehreren gewinnt die niedrigste VID [D 16.11 MCG]. J.15 hat LLDP-MED und `medTlvenable` [D J.15 MCG].
- J.15.09.0003+: CDPv2-Antwort mit Voice-VLAN für Cisco-Telefone [D RN J.15.09.0028].
- Anzeige: Spalte `Voice` in `show vlans`, Telefon-Policy in `show lldp info remote-device <p>` (`Media Policy Vlan id`, `Tagged`) [D].

### 3.11 Speichern

- `write memory` (`write mem`) kopiert running- nach startup-config. Laut Doku ohne Rückfrage [D J.15, 16.11]. Konfigänderungen wirken sofort im Running-Config, ohne Speichern sind sie nach Reboot weg [D BOG].
- Vergleich: `show config` = startup, `show running-config`/`write terminal` = running [D]. `show running-config status` (16.11) / `show config status` (BOG 16.10) zeigen, ob beide abweichen [D]. Für J.15 nicht belegt [U].
- Dauer: nicht dokumentiert, meist wenige Sekunden [U]. netmiko `save_config()` ruft `enable()` und dann `write memory` mit `read_timeout=100` (Prompt-Erkennung) [C]. Timeout-Berichte bei Aruba betrafen `aruba_os` (Controller/CX), Workaround `send_command_timing` [F netmiko #3510].
- Management-VLAN: Läuft ein anderer Wert als im startup-config, gilt der running-Wert bis `write memory` oder Reboot [D 16.11].
- „Notfall-Rollback“ = Reboot ohne Speichern. Das Tool macht das **nicht** automatisch.

### 3.12 Besonderheiten J.15 (2520G) gegenüber YA/WB

| Thema | J.15.09 | YA/WB 15.x / 16.x | Beleg |
|---|---|---|---|
| SSH-Konfig | `ip ssh [cipher …] [mac …] [port] [timeout] [filetransfer]`. **Kein** `version`, `kex`, `host-key-algorithm`. | 16.11: zusätzlich `ip ssh kex …` und ab 16.11.0015 `ip ssh host-key-algorithm …` | [D J.15], [F ssh-audit] |
| SSH-MACs | nur `hmac-md5`, `hmac-sha1`, `-96`-Varianten | 16.11: zusätzlich `hmac-sha2-256` | [D J.15], [F] |
| Host-Key | RSA (Doku-Beispiel 1024 bit, max. 2048 für 2520) oder DSA (1024) | RSA bis 3072 | [D J.15], [F] |
| SSH-Fix | „SSH session disconnects when the SSH key re-exchange takes place“ in J.15.09 behoben | – | [D RN J.15.09.0028] |
| 802.1X / MAC / Web Clients | 1–2 pro Port | 32 (16.11), WB.15.11 bis 256 (MAC/Web) | [D] |
| auth-order/priority | nein | 16.x | [D] |
| `interface <p> tagged vlan <list>` | nicht dokumentiert | ja (YA.15.17, WB.15.11) | [D] |
| `show running-config interface/vlan/structured` | nicht in J.15-MCG (BOG 15.x gilt formal für alle) | ja | [D BOG 15.x], J.15 [U] |
| `session interactive-mode` | **nein** | ja | [D BOG 15.x] |
| `terminal width` | ≤ 150 empfohlen | – | [D RN] |
| RADIUS-Timeout-Default | 3 s | 5 s (16.11) | [D] |
| `time-window` (CoA) | nicht dokumentiert | WB.15.11 ja | [D] |
| max-vlans | 1–256 | höher (16.11: bis 2048 statisch+dynamisch) | [D] |
| Letzte Enhancements | J.15.09.0012. J.15.09.0028 = 09/2016, nur Fixes. | – | [D RN] |
| CoA, Voice-VLAN, LLDP-MED, auth/unauth-vid, addr-format | vorhanden | vorhanden | [D] |

### 3.13 Validierungsregeln für das Tool

**Eingaben** (alles Whitelist, nie Freitext in Befehle):

| Feld | Regel | Begründung |
|---|---|---|
| VLAN-ID | int 1–4094, **muss in `show vlans`/SNMP existieren**; nicht Primary-/Management-VLAN, ohne Extra-Freigabe | [D], verhindert Tippfehler-VLANs |
| VLAN-Name | `^[A-Za-z0-9_-]{1,12}$`, immer `"…"` | [D Zeichenverbot, Menülimit 12] |
| Portname | `^[A-Za-z0-9._-]{1,64}$` (optional `:` `@`, laut Doku-Beispielen ok). Leerzeichen in UI zu `_` | [D 64 Zeichen, keine Leerzeichen] |
| Port-ID | nur aus Inventar (SNMP `ifName`/`show interfaces brief`), z. B. `^(\d{1,2}/)?([A-F]?\d{1,2}\|Trk\d{1,3})$` | [U] Format je Modell |
| Port-Liste | vom Tool generiert, Bereiche komprimiert (`1-5,7,Trk1`). Bereiche nie über Modul-/Stack-Grenzen. Trunk-Member-Ports **ablehnen**, stattdessen TrkX. | [D Trunk-Regel] |
| Länge Befehlszeile | CLI-Limit nicht dokumentiert. Zeile ≤ 120 Zeichen halten (J.15: Breite ≤ 150), sonst auf mehrere Befehle verteilen. | [U] |
| RADIUS-Key | nicht über das Tool editierbar (Template durch Admin). Wenn doch: `^[A-Za-z0-9!%+,./=_-]{16,32}$`, kein `~` (J.15), keine Quotes/Leerzeichen. | [D Tilde], Länge [U] |
| Steuerzeichen | in allen Feldern verbieten: `\r \n \t ? " ' \ ;` und Nicht-ASCII. `?` löst sofort die CLI-Hilfe aus, `Tab` die Vervollständigung. | [D BOG: `?` listet Befehle] |

**Nie automatisieren** (nur manuell an der CLI):
- `write erase`, `erase startup-config`, `reload`, `boot …`, `copy … startup-config`, `crypto key zeroize`, `crypto key generate`
- `no vlan <vid>` (y/n-Rückfrage, Ports wandern ins DEFAULT_VLAN), `max-vlans`, `primary-vlan`, `management-vlan`
- `trunk …` / `no trunk …` / `lacp` (VLAN-Reset auf DEFAULT_VLAN, Loop-Gefahr laut Doku)
- `[no] aaa port-access authenticator active`, `[no] aaa authentication port-access …`, `no radius-server host …` (wirken switchweit, Lockout-Gefahr), `aaa authentication ssh/telnet …`
- `password …`, `no password all`, `ip ssh …`, `ip address`/`ip default-gateway`, `spanning-tree …`, `snmpv3 enable`, `setup`, `menu`, `kill`
- `interface <Uplink/Mgmt-Port> disable` sowie VLAN-Änderungen am Uplink/Mgmt-Port und an Ports mit LLDP-Nachbar „bridge“
- `aaa port-access <p> auth-order|auth-priority` (de-authentifiziert alle Clients) nur mit Hinweis

**Ablaufregeln:** eine Session pro Switch (Lock). Vorher und nachher `show running-config` speichern und diffen. Read-back prüfen, erst dann `write memory`. Bei Fehler im Read-back die Inverse-Befehle anzeigen, nicht automatisch ausführen.

---

## 4. netmiko `hp_procurve` / paramiko

### 4.1 Treiberverhalten

`netmiko/hp/hp_procurve.py`, netmiko 4.8.0 [C]:

| Methode | Verhalten |
|---|---|
| `__init__` | `conn_timeout` Default **20 s**. Ist `disabled_algorithms` nicht gesetzt, kommt `{"pubkeys": ["rsa-sha2-256","rsa-sha2-512"]}` dazu (nur Pubkey-Auth). **Eigenes `disabled_algorithms` ersetzt den Default, ohne zu mergen.** |
| `session_preparation` | `ansi_escape_codes=True`. Liest bis `.*opyright` (1,3 s), dann bis `any key to continue\|[>#]` (3 s) und sendet bei Bedarf `RETURN`. `set_base_prompt` (zweiter Versuch bei ≥ 25 Zeichen). Dann **`enable()`**, `terminal width 511`, `no page`. |
| `enable` | sendet `enable`, erkennt `username\|login\|user name`, `password`, `[>#]` (je 15 s). Username = Login-User, Passwort = `secret`. Schlägt es fehl: `ValueError` „pass the 'secret' argument“. |
| `check_config_mode` | `")#"` im Prompt |
| `config_mode` / `exit_config_mode` | geerbt: `configure terminal` / `end` |
| `send_config_set` | betritt den Config-Modus, wartet pro Befehl auf das Echo (cmd_verify) und dann auf Prompt oder `#` (`read_timeout` Default 15 s), verlässt mit `end`. `error_pattern=` wirft `ConfigInvalidException`. |
| `save_config` | `enable()` + `write memory` mit `read_timeout=100` |
| `cleanup` | `end`, `logout`, beantwortet „Do you want to save the current…“ mit **n** und „Do you want to log out“ mit **y** (max. 10 Runden à 1,5 s) |
| ANSI | entfernt u. a. `ESC[24;1H`, `ESC[?25h`, `ESC E`, `ESC[2K`, `ESC[1;24r`, `ESC[?7l` |
| `aruba_osswitch`, `aruba_procurve` | dieselbe Klasse `HPProcurveSSH` |

### 4.2 Bekannte Probleme

| Problem | Ursache / Workaround | Beleg |
|---|---|---|
| `Failed to enter enable mode` | SSH-User (RADIUS) ≠ Manager-User. `enable()` nimmt den Login-Usernamen, in `session_preparation` nicht übersteuerbar. Workaround: gleiche Credentials oder Subklasse mit `enable(default_username="manager")`. | [F netmiko #3238, offen] |
| Login scheitert bei `password configuration-control` | Passwortkomplexität erzeugt zusätzliche Dialoge | [F netmiko #2941] |
| Interaktive Befehle hängen | y/n-Prompts in `send_config_set`. Solche Befehle nicht automatisieren oder einzeln mit `send_command_timing`/`expect_string`. | [F #1976], [C] |
| Echo-Verify scheitert | lange Befehlszeilen werden umgebrochen (kleine `terminal width`, J.15 ≤ 150). Befehle kurz halten, Port-Listen komprimieren. | [U] |
| EOFError jeder 2. Verbindung (2810) | ungeklärt, Versionsfrage paramiko/cryptography | [F #3490] |

### 4.3 Empfohlene Parameter

[U, abgeleitet aus Code + Doku]
```python
dev = dict(
    device_type="hp_procurve",
    host=ip, username=user, password=pw, secret=pw_manager,
    conn_timeout=20, auth_timeout=20, banner_timeout=20,
    fast_cli=False,          # True (Default) setzt global_delay_factor=0.1
    global_delay_factor=1,   # J.15: ggf. 2
    session_log=None,        # wenn aktiv: netmiko maskiert password/secret, aber nicht "show radius"
)
# pro Aufruf:
conn.send_command("show running-config", read_timeout=60)
conn.send_config_set(cmds, read_timeout=30,
    error_pattern=r"(Invalid input|Incomplete input|Ambiguous input|Module not present|not found|cannot|Error)")
conn.save_config()           # intern read_timeout=100
```
Belegte Fehlertexte: `Invalid input: <input>`, `Incomplete input`, `Module not present for port or invalid port: <p>`, `Command cannot operate over a logical port` [D J.15/YA.15.17/BOG]. Die übrigen Muster [U].

### 4.4 SSH-Algorithmen (paramiko)

| Library | KEX group1-sha1 / group14-sha1 | Hostkey `ssh-rsa` (SHA-1) | aes*-ctr/cbc | hmac-sha1/md5 | J.15 verbindbar? |
|---|---|---|---|---|---|
| paramiko 3.5.x / **4.0.x** | ja (in `_preferred_kex`) | ja | ja | ja | **ja, ohne Anpassung** [C] |
| paramiko **5.0.0+** (05/2026) | **entfernt** | **entfernt** | ja | ja | **nein** [C] |

- paramiko 4.0.0 hat **DSA entfernt** [C]. Der Switch-Hostkey muss also RSA sein (`crypto key generate ssh rsa`) [D J.15].
- paramiko 5.0 verlangt bei `diffie-hellman-group-exchange-sha256` mindestens 2048-bit-Moduli [C].
- Eine `disabled_algorithms`-Anpassung ist für J.15 unter paramiko 4 nicht nötig. Sie kann nur **einschränken**, aber nichts wieder aktivieren, was eine Version entfernt hat [C].
- YA.16.11: `ip ssh kex` (ecdh-sha2-nistp*, group14-sha1 …), MAC `hmac-sha2-256` und ab 16.11.0015 `host-key-algorithm`. Ob ein rsa-sha2-Hostkey ohne Update geht, ist offen. Damit läuft 16.11 vermutlich auch mit paramiko 5 [F ssh-audit, U]. WB.16.06 / YA.15.17 / WB.15.x: unbekannt [U].
- Prüfen ohne Gerätezugriff auf Konfig: `nmap -p22 --script ssh2-enum-algos <ip>` oder `ssh-audit <ip>`. OpenSSH-Client für Tests mit Altgeräten: `-oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa` [F precedence.co.uk].

---

## 5. Quellen

**HPE/Aruba (offiziell)**
- J.15.09 Access Security Guide (2520G): https://support.hpe.com/hpesc/public/docDisplay?docId=c03486703
- J.15.09 Advanced Traffic Management Guide (2520G): https://support.hpe.com/hpesc/public/docDisplay?docId=c03486726
- J.15.09 Management and Configuration Guide (2520G): https://support.hpe.com/hpesc/public/docDisplay?docId=c03486743
- Release Notes J.15.09.0028: https://support.hpe.com/hpesc/public/docDisplay?docId=c05272737
- YA/YB.15.17 ATMG: https://support.hpe.com/hpesc/public/docDisplay?docId=c04723368 · MCG: https://support.hpe.com/hpesc/public/docDisplay?docId=c04723387 · ASG: https://support.hpe.com/hpesc/public/docDisplay?docId=c04723426
- WB.15.11 ATMG: https://support.hpe.com/hpesc/public/docDisplay?docId=c03673784 · ASG: https://support.hpe.com/hpesc/public/docDisplay?docId=c03674552 · Release Notes WB.15.12.0016: https://support.hpe.com/hpesc/public/docDisplay?docId=c04680170
- HP Switch Software Basic Operation Guide 15.x (2015/03, alle Familien): https://support.hpe.com/hpesc/public/docDisplay?docId=c04656670
- Aruba Basic Operation Guide AOS-S 16.10: https://arubanetworking.hpe.com/techdocs/AOS-Switch/16.10/Aruba%20Basic%20Operation%20Guide%20for%20AOS-S%20Switch%2016.10.pdf
- AOS-S 16.11 YA/YB HTML-Guides (Basis `https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/<GUIDE>/YAYB/content/common%20files/`):
  - ATMG: `cnf-cha-sta-vla-per-por-set-cli.htm` (tagged/untagged), `cre-new-sta-vla-por-bas-pro-bas-cli.htm` (vlan/name/voice), `vla-res.htm`, `vla-ope-not.htm`, `the-pri-vla.htm`, `ope-not-man-vla.htm`, `del-sta-vla-cli.htm`, `vie-vla-mem-one-mor-por-cli.htm`, `ope-rul-voi-vla.htm`
  - ASG: `cnf-802-aut-met.htm`, `ena-sel-por-as-aut-ena-def-por-bas-aut.htm`, `spe-use-bas-aut-ret-por-bas-aut.htm.htm`, `cnf-802-ope-vla-mod.htm`, `ope-rul-aut-unaut-cli-vla.htm`, `how-rad-aut-aff-vla-ope.htm`, `ord-pri-asi-vla.htm`, `ena-mac-aut.htm`, `cnf-mac-add-fmt.htm`, `spe-vla-use-whe-aut-fai.htm`, `aut-ord-pri.htm`, `cnf-aut-ord-pre-fal_1.htm`, `cnf-swi-acc-rad-ser44.htm`, `cnf-swi-glo-rad-par.htm`, `add-rad-att.htm`, `ip-ssh.htm`, `ena-802-aut-sel-por.htm`
  - MCG: `cnf-ope-rul-fri-por-nam.htm`, `cnf-fri-por-nam-cli.htm`, `ena-dis-por-cnf-por-mod-cli.htm`, `vie-por-sta-cnf-cli.htm`, `sho-run-con31.htm`, `vie-adv-cur-nei-mib.htm`, `vie-sta-tru-typ-all-por.htm`, `ena-dis-med.htm`, `../kb/ope-por-tru.htm`
  - Hinweis: Die Seiten liefern für Nicht-Browser-Clients (curl) HTTP 403.
- 2920-Doku 16.10 (HTML): https://www.arubanetworks.com/techdocs/AOS-S/16.10/ATMG/WB/content/home_wb.htm

**Quellcode**
- netmiko hp_procurve: https://github.com/ktbyers/netmiko/blob/develop/netmiko/hp/hp_procurve.py
- netmiko base/cisco_base_connection: https://github.com/ktbyers/netmiko/blob/develop/netmiko/base_connection.py · https://github.com/ktbyers/netmiko/blob/develop/netmiko/cisco_base_connection.py
- netmiko pyproject (Extra `par4`): https://github.com/ktbyers/netmiko/blob/develop/pyproject.toml
- paramiko Changelog (5.0.0: SHA-1-KEX und ssh-rsa entfernt, 4.0.0: DSA entfernt): https://github.com/paramiko/paramiko/blob/main/sites/www/changelog.rst
- paramiko 4.0.0 transport.py (Algorithmenlisten): https://github.com/paramiko/paramiko/blob/4.0.0/paramiko/transport.py

**Community / Foren**
- HPE Community „Unable to Untag“ (Auto-Entfernung, Verwaist-Sperre, HPE-Engineer): https://community.hpe.com/t5/switches-hubs-and-modems/unable-to-untag/m-p/5916647
- HPE Community „Vlan questions“ (`no untagged` in VLAN 1): https://community.hpe.com/t5/Switches-Hubs-and-Modems/Vlan-questions/m-p/4251935
- HPE Community „Procurve 2910 removing port from a VLAN“: https://community.hpe.com/t5/hpe-aruba-networking-provision/procurve-2910-24g-removing-port-from-a-vlan/m-p/5948901
- HPE Community „4208vl VLAN Name too long“ (12 Zeichen): https://community.hpe.com/t5/switches-hubs-and-modems/procurve-4208vl-vlan-name-too-long/td-p/4426753
- netmiko Issues: #3238 https://github.com/ktbyers/netmiko/issues/3238 · #3510 https://github.com/ktbyers/netmiko/issues/3510 · #2941 https://github.com/ktbyers/netmiko/issues/2941 · #1976 https://github.com/ktbyers/netmiko/issues/1976 · #3490 https://github.com/ktbyers/netmiko/issues/3490
- ssh-audit Hardening AOS-S 16.11: https://github.com/jtesta/ssh-audit/wiki/ArubaOS-Switch-(AOS-S)-16.11
- Alte HP-SSH-Algorithmen (Client-Workaround): https://www.precedence.co.uk/wiki/Support-KB-NetworkMan/HP-ssh
