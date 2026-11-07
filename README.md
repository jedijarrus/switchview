# SwitchView

Web portal for access switches: HP/Aruba **ProCurve / ArubaOS-Switch** with the full feature set over SSH, switches of other vendors
over SNMP, with optional **PacketFence** NAC integration.
See every port, VLAN and device at a glance, change ports safely, and manage which devices may enter the network without a certificate.

The user interface is in German. It loads nothing from other hosts, fonts included (with Entra SSO only Microsoft's sign-in), the
browser's Back and Forward walk its views, and dialogs, the port panel and the search work with the keyboard.

## Features

**Read (SNMP v2c/v3, every driver)**
- Switch overview: ports, link/speed, untagged and tagged VLANs, trunks / LAGs, LLDP neighbours, learned MAC addresses, PoE state and power (ProCurve, Cisco)
- Topology with automatic uplink detection (LLDP, base-MAC matching) and VLAN consistency check per link; switches are told apart by
  id, so two switches with the same name each keep their own links and uplinks (links to a switch view read `#sw=<id>`)
- VLAN × switch matrix, global search (device, IP, MAC, port description) with arrow keys, Enter and Escape
- Navigation: every view change is an entry in the browser history, so Back and Forward walk the views; the address of a view is
  its bookmark (`#sw=<id>`, `#vlans`, …; old `#switch=<name>` bookmarks still resolve). Back closes an open dialog, a running
  change goes on at the server and stays in the change list. Dialogs and the port panel keep the keyboard focus, Escape closes the
  top one, and the focus goes back to where it came from
- Device names from the OPNsense ARP table (API) plus reverse DNS
- Port descriptions and VLAN names with non-ASCII characters (umlauts) are shown as text, not as hex
- A poll that misses a walk still counts: the switch view says "Abfrage unvollständig" and names the gap; when the MAC table, LLDP
  or the base MAC cannot be read, the values of the last poll are kept (they carry the uplink protection) and merged with what was read
- A stored credential that can no longer be decrypted, a missing read community (the poll then asks with `public`) or an SNMPv3
  level lowered because a passphrase is missing or cannot be decrypted is shown as a warning at the switch, in the connection test
  and in the log; polling goes on as before

**Configuration backups (SSH, ProCurve only)**
- Nightly `show running-config`, stored only when changed, with diff view; a change of a masked secret alone counts as a change too
  (a keyed HMAC of the unmasked text, derived from `SECRET_KEY`, tells it), and its diff says that only masked secrets changed
- Secrets (RADIUS keys, SNMP communities, password hashes) are masked before storage

**Port changes over SSH (ProCurve)**
- Port states: **Off**, **On** (switched on, 802.1X/MAC authentication left as it is), **Protected** (fixed VLAN), **Known devices** (MAC authentication), **RADIUS** (802.1X with MAC authentication fallback)
- Untagged/tagged VLANs, description, devices per port, VLAN for unknown devices
- Every change shows the exact CLI commands as a preview. At execution time the running config is read again and the plan must still match the preview. After sending, the config is read back and verified; only then `write memory` is issued
- Uplinks and trunks are protected (expert mode required), 802.1X/MAC auth is never applied to uplinks or trunks. A port also counts as
  an uplink when it learns the base MAC of another managed switch or when its LLDP neighbour is a managed switch, on every driver
- Trunk members can be renamed and switched on/off (on an uplink trunk in expert mode only); VLANs, authentication and PoE only on the trunk
- Per-switch lock (one change at a time per switch), audit log, one-click revert, "save anyway" for unclear results; revert and
  "save anyway" are offered only for a change that may have sent something to the switch. A disabled switch takes no change (409)
- "Prepare switch" adds the RADIUS prerequisites additively: RADIUS host, CoA (`dyn-authorization`, `time-window 0`), `eap-radius`, `authenticator active` and a park VLAN (3999).
  With a RADIUS server set in the settings, a port change that needs RADIUS requires exactly that server on the switch

**Port changes over SNMP (every driver)**
- Untagged/tagged VLANs (Q-BRIDGE-MIB; on classic Cisco IOS the access VLAN via `vmVlan`), port on/off (`ifAdminStatus`), description (`ifAlias`) and PoE on/off (POWER-ETHERNET-MIB, where the driver can map PoE entries to ports)
- The same guided loop as over SSH: the preview shows every field before → after, at execution time the switch is read live again and the plan must still match the preview, the change goes out as ONE SNMP SET, then it is read back and verified (a mismatch ends as "unclear"); revert restores the state read before the change
- Uplink and trunk protection, the VLAN checks and the per-switch lock apply exactly as over SSH
- When SNMP writes: for every driver without the SSH CLI it is the only way to change a port. On ProCurve it is the fallback when SSH is not available (no SSH account stored, or the pre-flight read of the running config fails; the preview says so), and PoE always goes over SNMP
- Persistence: a ProCurve saves every SNMP SET by itself, and with it its whole running config (the preview warns when that would also save an SSH change that was left unsaved on purpose). Other drivers keep the change in the running config until someone saves it on the switch. There is no staged `write memory` and no backup on this path
- Off by default: SNMP writes happen only on switches with `snmp_write` on ("SNMP darf schreiben" in the switch form). Read-only credentials never become write credentials silently, and the community `public` never writes
- Write credentials: a separate SNMPv3 write user with **authPriv** (authentication and encryption) is recommended. A v2c write community travels in clear text, so anyone who can see the traffic can write to the switch; the UI warns loudly. Without separate write credentials the read identity writes (it then needs write access on the device), and the switch form shows which identity writes

**Drivers**

Each switch has a driver. `procurve` is the full product; every other driver is SNMP only.

| Driver | Device | SSH CLI (changes, 802.1X/RADIUS, backup) | SNMP writes | PoE | Saves SNMP changes itself |
|---|---|---|---|---|---|
| `procurve` | HPE ProCurve / AOS-S | yes | VLANs, on/off, description (fallback) | yes | yes |
| `cisco` | Cisco IOS (classic) | – | access VLAN (`vmVlan`), on/off, description | yes | – |
| `aruba_cx` | Aruba AOS-CX | – | VLANs, on/off, description | – | – |
| `cisco_sb` | Cisco Small Business (SG/CBS) | – | VLANs, on/off, description | – | – |
| `comware` | HPE/H3C Comware | – | VLANs, on/off, description | – | – |
| `juniper` | Juniper Junos (EX/QFX) | – | VLANs, on/off, description | – | – |
| `arista` | Arista EOS | – | VLANs, on/off, description | – | – |
| `dell` | Dell Networking | – | VLANs, on/off, description | – | – |
| `netgear` | Netgear smart/managed switches | – | VLANs, on/off, description | – | – |
| `mikrotik` | MikroTik RouterOS | – | VLANs, on/off, description | – | – |
| `generic` | standard MIBs only (also used for unknown driver names) | – | VLANs, on/off, description | – | – |

The drivers other than `procurve` and `cisco` use the standard profile (Q-BRIDGE-MIB, IF-MIB); their SET support is not yet confirmed
against a device. PoE is offered only where the mapping of a PoE entry to its port is documented (ProCurve, Cisco).

What stays SSH-only, so ProCurve only: 802.1X / MAC authentication / RADIUS (the port states RADIUS, Known devices and Protected,
devices per port, the VLAN for unknown devices, "Prepare switch"), configuration backup and diff, and the staged change with
`write memory` after verification.

Known limitations and required device checks (German): [docs/snmp-multivendor.md](docs/snmp-multivendor.md)

Logic and robustness notes (German): [docs/logik-phase3.md](docs/logik-phase3.md) (what was built, where the moved code lives now,
known limits, checks before production use, what to do on an update, decisions)

UX notes and upgrade steps (German): [docs/ux-phase5.md](docs/ux-phase5.md) (what was built, known limits, checks before production
use, what to do on an update, what is left for Phase 4, decisions)

Roles and approvals notes (German): [docs/rollen-phase4a.md](docs/rollen-phase4a.md) (what was built, the rights per route, known
limits, checks before production use, what to do on an update, decisions).

**Device database (PacketFence)**
- Approve devices without a certificate (printers, phones, …) by MAC
- Approved devices become registered PacketFence nodes with owner `switchview` and a role; access is re-evaluated (CoA) immediately.
  A failed CoA shows as a hint at the device (the device switches at its next login); a delete that PacketFence does not confirm
  keeps the device
- Optional expiry date, nightly expiry job, list of unknown devices on access ports

**Login**
- Microsoft Entra ID (MSAL popup, ID token verified via JWKS, optional app roles/groups) or a local emergency account. With neither
  `ENTRA_ALLOWED_ROLES` nor `ENTRA_ALLOWED_GROUPS` set, every user of the tenant may sign in; the start logs a warning
- Sessions are stored hashed (SHA-256 of the session token), so a copy of the database holds no usable session cookie; sessions
  from before this change are rehashed at start, nobody is logged out; expired sessions are removed at start and every hour
- Log out everywhere: Settings → "Sitzungen" ends every session of your account on every device, the current one included

## Quick start

```bash
cp .env.example .env
# set SECRET_KEY (openssl rand -hex 32) and ADMIN_PASSWORD or the ENTRA_* values
docker compose up -d --build
```

SwitchView listens on port 8080 (see `docker-compose.yml`). Data (SQLite) lives in `./data`.
Run it behind a TLS-terminating reverse proxy in production and set `FORWARDED_ALLOW_IPS` and `COOKIE_SECURE` as described under
[Security](#security).

Run it with a **single uvicorn worker** (the `Dockerfile` default; do not add `--workers`): the scheduler (`jobs.scheduler`), the login throttle (`main._LOGIN`), the cache of Microsoft's signing keys with its 30-second cooldown, per-switch SSH/poll locks and running changes (`api_changes._tasks`) live in process memory.

Then add switches in the UI (management IP, driver, SNMP credentials, for ProCurve an optional SSH manager account, optional SNMP write access). All credentials are stored encrypted with a key derived from `SECRET_KEY` and are never shown again. A credential that can no longer be decrypted (for example after a change of `SECRET_KEY`) is reported in the switch view, the connection test and the settings instead of falling back silently: SSH, "Prepare switch", PacketFence and OPNsense stop with a message rather than send an empty secret, and polling goes on as described under Read. Enter it anew.

## Security

Security notes and upgrade steps (German): [docs/sicherheit-phase2.md](docs/sicherheit-phase2.md) (what was built, known limits,
checks before production use, what to do on an update, decisions).

The settings that matter, in `.env` unless noted:

| Setting | Default | What it does |
|---|---|---|
| `FORWARDED_ALLOW_IPS` | unset (`127.0.0.1`, nobody else inside the container) | addresses or networks allowed to set `X-Forwarded-For` / `X-Forwarded-Proto` |
| `COOKIE_SECURE` | `auto` | `auto` or `always`: when the session and device cookies carry the `Secure` flag |
| `SECRET_KEY` | none (required) | key of the stored credentials; under 16 characters stops the start, a weak one gets a warning |
| `SESSION_HOURS` | `12` | lifetime of a session |
| "TLS-Zertifikat prüfen" (Settings, PacketFence and OPNsense) | on for a new installation | certificate check of the PacketFence and OPNsense APIs |
| "SSH-Hostschlüssel vergessen" (switch form) | – | drops a switch's pinned SSH host key, so the next SSH session pins the key it is offered |
| "Alle meine Sitzungen beenden" (Settings → "Sitzungen") | – | ends every session of your account on every device |

**Reverse proxy.** Set `FORWARDED_ALLOW_IPS` to the proxy's address as the container sees it (comma-separated addresses or networks,
e.g. `172.18.0.1`, or `172.18.0.0/16` for a proxy in another container of the compose network): only that sender may set
`X-Forwarded-For` and `X-Forwarded-Proto`. To find the address, open SwitchView through the proxy and look at the uvicorn access log
(`docker compose logs switchview`): before the variable is set, every request shows the proxy as its client (for a proxy on the
Docker host usually the gateway of the compose network). Without the variable uvicorn trusts proxy headers only from 127.0.0.1, which
inside the container is nobody else: SwitchView works the same, but the log shows the proxy's address for every client.
`docker-compose.yml` publishes port 8080 on every address of the host; if only the proxy should reach SwitchView, bind it to
`127.0.0.1` or close it in the firewall. SwitchView compresses answers of 4 KiB and more with gzip; a proxy passes that on.

**Cookies.** `COOKIE_SECURE` decides when the session and device cookies carry the `Secure` flag. `auto` (the default) sets it when
the request came over HTTPS, by its own scheme or by `X-Forwarded-Proto: https`; either signal can only add the flag, a forged
`X-Forwarded-Proto: http` never removes it. If SwitchView is reachable over HTTPS only, set `COOKIE_SECURE=always`. Any other value
stops the start. HSTS belongs on the TLS-terminating proxy. Sessions are stored as the SHA-256 of their token.

**Emergency login.** The emergency login (`ADMIN_USER` / `ADMIN_PASSWORD`) is throttled: after 10 failed attempts within 60 seconds
from browsers without a device cookie, it refuses such browsers (HTTP 429) until those failures are older than 60 seconds. A browser
in which the emergency login succeeded once keeps a device cookie and with it a quota of its own, so an attack does not lock it out.
Entra SSO is never throttled; an access token is refused where an id_token is expected. The fetch of Microsoft's signing keys
(JWKS) waits at most 5 seconds; after a fetch that could not reach Microsoft, SSO logins are refused for 30 seconds without a new
fetch (the emergency login still works), and the login page asks to try again in half a minute. A refused token is one warning line
in the log, without a traceback.

**Request size.** Every request over 64 KiB is refused with HTTP 413 before its body is read.

**Content Security Policy.** Every answer (except the plain-text 500 of an unhandled exception) carries a strict
Content-Security-Policy (only SwitchView itself; with SSO also connect-src https://login.microsoftonline.com for the MSAL popup). A
reverse proxy should not set its own CSP for SwitchView: both would apply. The policy allows no inline script and no `<style>`
element, only inline style attributes, so a proxy that injects scripts or styles into the pages (some WAF or portal features) is
blocked. It applies from the first start of the new image, without a report-only phase; the emergency login works under it.

**SECRET_KEY.** A `SECRET_KEY` under 16 characters stops the start; one under 32 characters or with fewer than 8 different
characters gets a warning in the log at every start. Changing the key later means entering every stored credential anew.

**Credentials follow their destination.** When a save changes the address of a switch, of PacketFence, of OPNsense or of the
RADIUS server, every stored secret of that destination that the same save does not enter anew is deleted, and the answer and the UI
say which. A changed address never inherits a stored secret.

**SNMP credentials** never go on a command line, where any local process could read them (`ps`, `/proc/<pid>/cmdline`): for each
SNMP call SwitchView writes the community or the v3 passphrases into a short-lived `snmp.conf` (mode 0600, in a private directory
under `/dev/shm`, or in the temporary directory when `/dev/shm` is not writable, removed when the call ends) and points net-snmp at it
with `SNMPCONFPATH`. An SNMP credential with a line break or a NUL character is refused when the switch is saved. A v2c community
still travels in clear text on the network; prefer SNMPv3 with authPriv.

**SSH host keys** are pinned on first use: the first SSH session to a switch (connection test, backup, configuration read or
change) stores the host key the switch offers, and from then on SwitchView refuses any other key before it logs in, so the password
never reaches a device that only pretends to be the switch. The switch form shows the pinned key's fingerprints (SHA256 and MD5);
compare them once with the switch (`show crypto host-public-key fingerprint`). The pinned key stays when the switch's address
changes. If a key changes as expected (replacement, new firmware), every SSH access to that switch fails with "passt nicht zum
gemerkten" until you choose "SSH-Hostschlüssel vergessen" in the switch form; the next SSH session then pins the key it is offered.
A refused key falls back to SNMP only when SNMP writes to that switch with an SNMPv3 authPriv identity: a port change then goes
over SNMP, and its preview starts with "SSH nicht verfügbar (… passt nicht zum gemerkten … Möglicher Angriff …)". With any other
write identity (a v2c community, SNMPv3 without privacy) the preview is refused with 502 and the host key message ("Kein Ausweichen
auf SNMP …"): a v2c community, or the SETs of SNMPv3 without privacy, would go readable to whoever answers at that address. Either
way, check the fingerprint on the switch before you confirm anything or forget the key. The message is shown whole wherever it
appears (connection test, backup, change, "Anmeldungen anzeigen"), the remedy at its end included.

**TLS.** "TLS-Zertifikat prüfen" (PacketFence, OPNsense) is on for a new installation; an existing one keeps its stored setting.
`http://` addresses stay allowed. The settings warn while a check is off or an address uses `http://`: anyone on the network could
then read the password or API key. The check uses the certifi bundle; for an own CA, set `SSL_CERT_FILE` to a bundle that holds the
usual CAs plus your own (the variable also applies to the Microsoft key fetch of the Entra login). The file must be inside the
container, where only `./data` is mounted (as `/data`): put the bundle at e.g. `./data/ca-bundle.pem`, set
`SSL_CERT_FILE=/data/ca-bundle.pem` in `.env` and run `docker compose up -d`. A wrong path makes every checked PacketFence/OPNsense
call and the Entra login fail (the emergency login still works), so afterwards log in once over SSO and press "PacketFence testen"
and "Namen jetzt aktualisieren" in the settings.

**Masking.** Secrets are masked in stored backups, in the backup and diff views, in CLI previews and in the error, steps and output
of every change, also of changes stored before the update (masked when they are served; the rows in the database stay as they were),
and in the log line of a change that ends with an exception; SwitchView never runs `show radius`, `show tech` or `show tacacs`,
nor an abbreviation of them such as `sh rad` or `sho tech`.
Switch output is parsed within fixed limits (SNMP output per call and 32 MiB per poll, values per walk, 4096 ports per switch, VLAN IDs
1–4094, port ranges and configuration size), off the event loop, so a hostile switch cannot exhaust the single worker's memory with one
answer nor stall the UI; a cancelled SNMP call ends its net-snmp process.

## Requirements

- Network access from SwitchView to the switches: UDP 161 (SNMP), TCP 22 (SSH, ProCurve)
- For changes on ProCurve: an SSH account with manager rights on the switch (SNMP write access as an optional fallback)
- For changes on any other driver: SNMP write access (`snmp_write` on, plus write credentials, or a read identity that may write)
- Browsers of the admins: Chrome/Edge 102, Firefox 112 or Safari 15.5 or later (`inert` and `style-src-attr`); older ones show
  the UI without its inline styles (VLAN colours, bars) and let screen readers read the page behind a dialog
- **paramiko 4.x** is pinned via `netmiko[par4]`. paramiko 5 removed the SHA-1 key exchange and `ssh-rsa` host keys, which older ProCurve firmware (e.g. J.15 on the 2520G) still requires. The switch host key must be RSA (paramiko 4 has no DSA).

## PacketFence integration

SwitchView talks to the PacketFence API v1 (`https://<packetfence>:9999`). Settings → "RADIUS und PacketFence".

Recommended PacketFence setup:

| Item | Setting |
|---|---|
| Roles | one per VLAN, named `vlan_<VID>`, functional description; role→VLAN mapping on the switch group |
| Park role | `vlan_3999` → VLAN 3999 (no IP, no routing, not on uplinks) |
| VLAN filter | MAC authentication (`Ethernet-NoEAP`) whose node owner ≠ `switchview` → role `vlan_3999`. Prevents certificate devices' MACs from being reused via MAC authentication |
| Switch type | `HP::AOS_Switch_v16_X`, deauth method RADIUS. The generic `HP::Switch` / `HP::Procurve_2600` types try SNMP v1 for wired MAC-auth deauth |
| Switch side | `radius-server host <pf> dyn-authorization` **and** `time-window 0`. PacketFence sends CoA without `Event-Timestamp`; with the default window (300 s) the switch silently drops it |

Unknown devices are accepted into the park role (not rejected), so PacketFence keeps a session it can change via CoA once the device is approved. `unauth-vid 3999` on the switch remains as a fallback.

## ProCurve notes

Collected in [docs/procurve-cli-referenz.md](docs/procurve-cli-referenz.md) (German), including:
- Untagged VLAN changes only via `vlan <new> untagged <ports>` (the old membership is removed automatically)
- VLAN changes only on `TrkX`, never on trunk members; no 802.1X/MAC auth on trunks
- With 802.1X **and** MAC auth on one port, only MAC auth may have an `unauth-vid`
- `addr-limit 1` is the default and does not appear in the running config
- `show radius` prints the RADIUS key in clear text

## Status

Tested with ProCurve / ArubaOS-Switch firmware 15.x and 16.x.
SNMP writes are tested against a simulated agent only; check the device checks in [docs/snmp-multivendor.md](docs/snmp-multivendor.md)
before you enable `snmp_write` on a production switch.

## Stack

FastAPI, aiosqlite, APScheduler, net-snmp CLI tools, netmiko, cryptography (Fernet), PyJWT, vanilla JS frontend.

Fonts: Geist and Geist Mono by Vercel, SIL Open Font License 1.1, served by SwitchView from app/static/fonts/ (license in
app/static/fonts/OFL.txt).
