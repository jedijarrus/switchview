"""Geraetenamen zu MAC-Adressen: ARP-Tabelle der OPNsense (API) plus Reverse-DNS."""
import asyncio
import logging
import socket
from datetime import datetime, timezone

import httpx

from crypto import decrypt, unreadable
from db import db, load_settings

log = logging.getLogger("switchview.names")

OUI = {
    "00:50:56": "VMware-VM", "00:0c:29": "VMware-VM", "00:15:5d": "Hyper-V-VM", "52:54:00": "KVM-VM",
    "08:00:27": "VirtualBox-VM", "00:16:3e": "Xen-VM", "b8:27:eb": "Raspberry Pi", "00:15:65": "Yealink",
}


def vendor_of(mac: str) -> str:
    return OUI.get(mac[:8].lower(), "")


async def _ptr(ip: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        name = (await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 2))[0]
        return name.split(".")[0]
    except Exception:  # noqa: BLE001
        return ""


async def opnsense_arp() -> list:
    """The ARP table of the OPNsense, [] without an address or without key and secret: the answer itself when it is a list, else the
    list under "rows". RuntimeError when key or secret is stored but does not decrypt, or when the answer is neither: refresh_names
    reports it, instead of a silent empty table. Its entries are as OPNsense sent them, refresh_names checks each."""
    # target and secret in one SELECT (db.load_settings): a concurrent settings PUT never pairs one with the other's old value (F2)
    s = await load_settings(["opnsense_url", "opnsense_key", "opnsense_secret", "opnsense_verify_tls"])
    url = (s["opnsense_url"] or "").rstrip("/")
    if not url:
        return []
    if unreadable(s["opnsense_key"]) or unreadable(s["opnsense_secret"]):
        raise RuntimeError("OPNsense-API-Key oder -Secret lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – in den Einstellungen neu "
                           "eingeben")
    key, secret = decrypt(s["opnsense_key"]), decrypt(s["opnsense_secret"])
    if not (key and secret):
        return []
    verify = (s["opnsense_verify_tls"] or "1") == "1"    # on without a stored value (E32), a stored one stays
    async with httpx.AsyncClient(verify=verify, timeout=20) as c:
        r = await c.get(f"{url}/api/diagnostics/interface/getArp", auth=(key, secret))
        r.raise_for_status()
        data = r.json()
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        return data["rows"]
    raise RuntimeError("OPNsense-Antwort unerwartet: keine Liste von ARP-Einträgen")


def _odd(entry) -> bool:
    """Whether an ARP entry has a shape refresh_names cannot read: no object, a mac or ip that is set but no text, a hostname or
    manufacturer that is set but no text. A missing or null mac or ip is no odd shape: the filter of refresh_names drops such an
    entry in silence, as it drops a MAC that is not 17 characters long."""
    if not isinstance(entry, dict):
        return True
    return any(entry.get(k) is not None and not isinstance(entry[k], str) for k in ("mac", "ip", "hostname", "manufacturer"))


async def refresh_names() -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        arp = await opnsense_arp()
    except Exception as e:  # noqa: BLE001
        log.warning("OPNsense-ARP fehlgeschlagen: %s", e)
        return {"ok": False, "error": str(e)}
    readable = [e for e in arp if not _odd(e)]
    skipped = len(arp) - len(readable)
    if skipped:    # an OPNsense that changed its answer shows here, and the readable entries still count
        log.warning("OPNsense-ARP: %d von %d Einträgen übersprungen (unerwartete Form)", skipped, len(arp))
    rows = []
    sem = asyncio.Semaphore(20)

    async def one(entry):
        mac = (entry.get("mac") or "").lower()
        ip = entry.get("ip") or ""
        if len(mac) != 17 or not ip:
            return
        name = (entry.get("hostname") or "").split(".")[0]
        if not name:
            async with sem:
                name = await _ptr(ip)
        rows.append((mac, ip, name, entry.get("manufacturer") or vendor_of(mac), "arp", now))

    await asyncio.gather(*(one(e) for e in readable))
    async with db() as conn:
        await conn.executemany(
            "INSERT INTO names(mac, ip, name, vendor, source, last_seen) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, name=CASE WHEN excluded.name <> '' THEN excluded.name ELSE names.name END, "
            "vendor=excluded.vendor, source=excluded.source, last_seen=excluded.last_seen",
            rows,
        )
        await conn.commit()
    return {"ok": True, "entries": len(rows), "skipped": skipped}
