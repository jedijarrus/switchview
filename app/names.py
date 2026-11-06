"""Geraetenamen zu MAC-Adressen: ARP-Tabelle der OPNsense (API) plus Reverse-DNS."""
import asyncio
import logging
import socket
from datetime import datetime, timezone

import httpx

from crypto import decrypt
from db import db, get_setting

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


async def opnsense_arp() -> list[dict]:
    url = (await get_setting("opnsense_url") or "").rstrip("/")
    key = decrypt(await get_setting("opnsense_key"))
    secret = decrypt(await get_setting("opnsense_secret"))
    if not (url and key and secret):
        return []
    verify = (await get_setting("opnsense_verify_tls", "1")) == "1"    # on without a stored value (E32), a stored one stays
    async with httpx.AsyncClient(verify=verify, timeout=20) as c:
        r = await c.get(f"{url}/api/diagnostics/interface/getArp", auth=(key, secret))
        r.raise_for_status()
        data = r.json()
    return data if isinstance(data, list) else data.get("rows", [])


async def refresh_names() -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        arp = await opnsense_arp()
    except Exception as e:  # noqa: BLE001
        log.warning("OPNsense-ARP fehlgeschlagen: %s", e)
        return {"ok": False, "error": str(e)}
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

    await asyncio.gather(*(one(e) for e in arp))
    async with db() as conn:
        await conn.executemany(
            "INSERT INTO names(mac, ip, name, vendor, source, last_seen) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, name=CASE WHEN excluded.name <> '' THEN excluded.name ELSE names.name END, "
            "vendor=excluded.vendor, source=excluded.source, last_seen=excluded.last_seen",
            rows,
        )
        await conn.commit()
    return {"ok": True, "entries": len(rows)}
