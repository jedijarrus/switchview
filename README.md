# SwitchView

Web portal for access switches: HP/Aruba **ProCurve / ArubaOS-Switch** with the full feature set over SSH, switches of other vendors
over SNMP, with optional **PacketFence** NAC integration.
See every port, VLAN and device at a glance, change ports safely, and manage which devices may enter the network without a certificate.

The user interface is in German.

## Features

**Read (SNMP v2c/v3, every driver)**
- Switch overview: ports, link/speed, untagged and tagged VLANs, trunks / LAGs, LLDP neighbours, learned MAC addresses, PoE state and power (ProCurve, Cisco)
- Topology with automatic uplink detection (LLDP, base-MAC matching) and VLAN consistency check per link
- VLAN × switch matrix, global search (device, IP, MAC, port description)
- Device names from the OPNsense ARP table (API) plus reverse DNS

**Configuration backups (SSH, ProCurve only)**
- Nightly `show running-config`, stored only when changed, with diff view
- Secrets (RADIUS keys, SNMP communities, password hashes) are masked before storage

**Port changes over SSH (ProCurve)**
- Port states: **Off**, **On** (switched on, 802.1X/MAC authentication left as it is), **Protected** (fixed VLAN), **Known devices** (MAC authentication), **RADIUS** (802.1X with MAC authentication fallback)
- Untagged/tagged VLANs, description, devices per port, VLAN for unknown devices
- Every change shows the exact CLI commands as a preview. At execution time the running config is read again and the plan must still match the preview. After sending, the config is read back and verified; only then `write memory` is issued
- Uplinks and trunks are protected (expert mode required), 802.1X/MAC auth is never applied to uplinks or trunks
- Per-switch lock, audit log, one-click revert, "save anyway" for unclear results
- "Prepare switch" adds the RADIUS prerequisites additively: RADIUS host, CoA (`dyn-authorization`, `time-window 0`), `eap-radius`, `authenticator active` and a park VLAN (3999)

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

**Device database (PacketFence)**
- Approve devices without a certificate (printers, phones, …) by MAC
- Approved devices become registered PacketFence nodes with owner `switchview` and a role; access is re-evaluated (CoA) immediately
- Optional expiry date, nightly expiry job, list of unknown devices on access ports

**Login**
- Microsoft Entra ID (MSAL popup, ID token verified via JWKS, optional app roles/groups) or a local emergency account

## Quick start

```bash
cp .env.example .env
# set SECRET_KEY (openssl rand -hex 32) and ADMIN_PASSWORD or the ENTRA_* values
docker compose up -d --build
```

SwitchView listens on port 8080 (see `docker-compose.yml`). Data (SQLite) lives in `./data`.
Run it behind a TLS-terminating reverse proxy in production, and set `FORWARDED_ALLOW_IPS` in `.env` to the proxy's address as the
container sees it (comma-separated addresses or networks, e.g. `172.18.0.1`, or `172.18.0.0/16` for a proxy in another container
of the compose network): only that sender may set `X-Forwarded-For` and `X-Forwarded-Proto`. To find the address, open SwitchView
through the proxy and look at the uvicorn access log (`docker compose logs switchview`): before the variable is set, every request
shows the proxy as its client (for a proxy on the Docker host usually the gateway of the compose network). Without the variable
uvicorn trusts proxy headers only from 127.0.0.1, which inside the container is nobody else: SwitchView works the same, but the log
shows the proxy's address for every client.

The emergency login (`ADMIN_USER` / `ADMIN_PASSWORD`) is throttled: after 10 failed attempts within 60 seconds from browsers
without a device cookie, it refuses such browsers (HTTP 429) until those failures are older than 60 seconds. A browser in which the
emergency login succeeded once keeps a device cookie and with it a quota of its own, so an attack does not lock it out. Entra SSO is
never throttled.

Run it with a **single uvicorn worker** (the `Dockerfile` default; do not add `--workers`): the scheduler, the login throttle (`main._LOGIN`), per-switch SSH/poll locks and running changes live in process memory.

Then add switches in the UI (management IP, driver, SNMP credentials, for ProCurve an optional SSH manager account, optional SNMP write access). All credentials are stored encrypted with a key derived from `SECRET_KEY` and are never shown again.

## Requirements

- Network access from SwitchView to the switches: UDP 161 (SNMP), TCP 22 (SSH, ProCurve)
- For changes on ProCurve: an SSH account with manager rights on the switch (SNMP write access as an optional fallback)
- For changes on any other driver: SNMP write access (`snmp_write` on, plus write credentials, or a read identity that may write)
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
