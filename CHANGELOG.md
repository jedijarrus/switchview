# Änderungen

Jeder ausgerollte Stand von SwitchView hat eine Nummer und steht hier mit Datum, der neueste oben. Die Nummer steht in
`app/version.py` und nach der Anmeldung oben neben „SwitchView“. Der Commit einer Version trägt den Git-Tag `v<Nummer>`.

- Neue Funktion: die mittlere Zahl steigt, die letzte geht auf 0.
- Korrektur: die letzte Zahl steigt.

## 0.5.0 – 2026-11-10

Der erste nummerierte Stand. Er enthält alles, was bis hierhin gebaut wurde:

- Lesen per SNMP (v2c und v3) für elf Treiber: Ports, VLANs, Trunks, LLDP-Nachbarn, MAC-Adressen und PoE; dazu Topologie mit
  Uplink-Erkennung, VLAN-Matrix und Suche
- Port-Änderungen per SSH (ProCurve) und per SNMP (alle Treiber), jede mit Vorschau, Prüfung nach dem Senden und Rückgängig;
  Uplinks und Trunks sind geschützt
- Nächtliche Sicherung der Konfiguration mit Diff, Geheimnisse maskiert
- Anmeldung über Microsoft Entra oder das Notfallkonto, vier Rollen, Zonen, Vier-Augen-Freigabe und API-Token
- Sammeländerungen über mehrere Switches, in der Oberfläche und per REST-API, auf Wunsch mit Bestätigung und mit
  Vier-Augen-Freigabe
- Verlauf, Protokoll und Benachrichtigungen
- PacketFence: Anmeldungen je Port, Geräte in vier Reitern mit Freigabe, für unbekannte Geräte ein Vorschlag für Gerätetyp und
  Rolle; „Vorbereiten“ richtet RADIUS und den SNMPv3-Benutzer am Switch ein
- Die Versionsnummer selbst: im Kopf der Seite, in `GET /api/auth/me` und in dieser Datei
