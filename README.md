# SwitchView

Web portal for HP/Aruba **ProCurve / ArubaOS-Switch** access switches, with optional **PacketFence** NAC integration.
See every port, VLAN and device at a glance, change ports safely, and manage which devices may enter the network without a certificate.

The user interface is in German.

## Features

**Read (SNMP v2c/v3)**
- Switch overview: ports, link/speed, untagged and tagged VLANs, trunks, LLDP neighbours, learned MAC addresses
- Topology with automatic uplink detection (LLDP, base-MAC matching) and VLAN consistency check per link
- VLAN × switch matrix, global search (device, IP, MAC, port description)
- Device names from the OPNsense ARP table (API) plus reverse DNS

**Configuration backups (SSH)**
- Nightly `show running-config`, stored only when changed, with diff view
- Secrets (RADIUS keys, SNMP communities, password hashes) are masked before storage

**Port changes (SSH)**
- Port states: **Off**, **Protected** (fixed VLAN), **Known devices** (MAC authentication), **RADIUS** (802.1X with MAC authentication fallback)
- Untagged/tagged VLANs, description, devices per port, VLAN for unknown devices
- Every change shows the exact CLI commands as a preview. At execution time the running config is read again and the plan must still match the preview. After sending, the config is read back and verified; only then `write memory` is issued
- Uplinks and trunks are protected (expert mode required), 802.1X/MAC auth is never applied to uplinks or trunks
- Per-switch lock, audit log, one-click revert, "save anyway" for unclear results
- "Prepare switch" adds the RADIUS prerequisites additively: RADIUS host, CoA (`dyn-authorization`, `time-window 0`), `eap-radius`, `authenticator active` and a park VLAN (3999)

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
Run it behind a TLS-terminating reverse proxy in production (`X-Forwarded-Proto` is honoured).
Run it with a **single uvicorn worker** (the `Dockerfile` default; do not add `--workers`): the scheduler, login rate limit, per-switch SSH/poll locks and running changes live in process memory.

Then add switches in the UI (management IP, SNMP credentials, optional SSH manager account). All credentials are stored encrypted with a key derived from `SECRET_KEY` and are never shown again.

## Requirements

- Network access from SwitchView to the switches: UDP 161 (SNMP), TCP 22 (SSH)
- For changes: an SSH account with manager rights on each switch
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

## Stack

FastAPI, aiosqlite, APScheduler, net-snmp CLI tools, netmiko, cryptography (Fernet), PyJWT, vanilla JS frontend.
