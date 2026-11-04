"""PacketFence-API (v1): bekannte Geraete als registrierte Nodes mit Rolle pflegen.

Ein freigegebenes Geraet ist in PacketFence 'reg' mit seiner Rolle (node category). An Ports im Status
'known' oder 'radius' fragt der Switch per MAC-Anmeldung, PacketFence antwortet mit dem VLAN der Rolle.
Gesperrte oder geloeschte Geraete werden 'unreg' gesetzt, nicht geloescht (Verlauf bleibt in PacketFence).
"""
import logging
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone

import httpx

from crypto import decrypt
from db import db, get_setting

log = logging.getLogger("switchview.pf")
# Besitzer (pid) aller in SwitchView freigegebenen Geraete. Ein VLAN-Filter in PacketFence
# laesst MAC-Anmeldung (Ethernet-NoEAP) nur fuer Nodes dieses Besitzers zu.
OWNER = "switchview"


async def config() -> dict:
    return {"url": (await get_setting("pf_url", "") or "").rstrip("/"), "user": await get_setting("pf_user", "") or "",
            "password": decrypt(await get_setting("pf_pass")) or "", "verify": (await get_setting("pf_verify_tls", "0")) == "1"}


async def configured() -> bool:
    c = await config()
    return bool(c["url"] and c["user"] and c["password"])


@asynccontextmanager
async def session():
    c = await config()
    if not (c["url"] and c["user"] and c["password"]):
        raise RuntimeError("PacketFence-API ist nicht eingerichtet")
    async with httpx.AsyncClient(base_url=c["url"] + "/api/v1", verify=c["verify"], timeout=15) as cl:
        r = await cl.post("/login", json={"username": c["user"], "password": c["password"]})
        if r.status_code != 200 or "token" not in r.json():
            raise RuntimeError(f"Anmeldung an PacketFence fehlgeschlagen (HTTP {r.status_code})")
        cl.headers["Authorization"] = r.json()["token"]
        yield cl


async def roles(cl=None) -> list[dict]:
    async def go(c):
        r = await c.get("/node_categories", params={"limit": 1000})
        r.raise_for_status()
        return [{"id": str(i.get("category_id")), "name": i.get("name"), "notes": i.get("notes") or ""} for i in r.json().get("items", [])]
    if cl:
        return await go(cl)
    async with session() as c:
        return await go(c)


async def test() -> dict:
    try:
        async with session() as c:
            rl = await roles(c)
        return {"ok": True, "detail": f"{len(rl)} Rollen: " + ", ".join(r["name"] for r in rl[:12])}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}


async def ensure_owner(cl) -> None:
    r = await cl.get(f"/user/{OWNER}")
    if r.status_code == 404:
        r = await cl.post("/users", json={"pid": OWNER, "firstname": "SwitchView",
                                          "notes": "Besitzer der in SwitchView freigegebenen Geräte"})
        if r.status_code not in (200, 201):
            raise RuntimeError(f"Benutzer {OWNER} in PacketFence nicht anlegbar: HTTP {r.status_code} {r.text[:150]}")


def _expired(dev) -> bool:
    return bool(dev["valid_until"]) and dev["valid_until"] < date.today().isoformat()


async def _sync_one(cl, role_ids: dict, dev) -> None:
    mac = dev["mac"]
    allowed = bool(dev["allowed"]) and not _expired(dev)
    r = await cl.get(f"/node/{mac}")
    exists = r.status_code == 200
    if r.status_code not in (200, 404):
        raise RuntimeError(f"Node lesen: HTTP {r.status_code}")
    if allowed:
        role = dev["role"] or "default"
        if role not in role_ids:
            raise RuntimeError(f"Rolle „{role}“ gibt es in PacketFence nicht")
        body = {"status": "reg", "category_id": role_ids[role], "pid": OWNER,
                "unregdate": (dev["valid_until"] + " 23:59:59") if dev["valid_until"] else "0000-00-00 00:00:00",
                "notes": f"SwitchView: {dev['name']} ({dev['kind']})"[:255]}
        r = await (cl.patch(f"/node/{mac}", json=body) if exists else cl.post("/nodes", json={"mac": mac, **body}))
    elif exists:
        r = await cl.patch(f"/node/{mac}", json={"status": "unreg", "pid": "default"})
    else:
        return
    if r.status_code not in (200, 201, 204):
        raise RuntimeError(f"Node schreiben: HTTP {r.status_code} {r.text[:150]}")
    await cl.post(f"/node/{mac}/reevaluate_access", json={})  # CoA, damit ein angestecktes Geraet sofort umschaltet


async def _save_state(mac: str, state: str, err: str | None):
    async with db() as conn:
        await conn.execute("UPDATE devices SET pf_state = ?, pf_error = ?, pf_synced_at = ? WHERE mac = ?",
                           (state, err, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), mac))
        await conn.commit()


async def sync(macs: list[str] | None = None) -> dict:
    """Uebertraegt Geraete nach PacketFence. Ohne macs: alle."""
    async with db() as conn:
        q = "SELECT * FROM devices" + (f" WHERE mac IN ({','.join('?' * len(macs))})" if macs else "")
        async with conn.execute(q, macs or []) as cur:
            devs = await cur.fetchall()
    if not await configured():
        for d in devs:
            await _save_state(d["mac"], "aus", None)
        return {"ok": False, "error": "PacketFence-API ist nicht eingerichtet", "done": 0}
    done, failed = 0, 0
    try:
        async with session() as cl:
            await ensure_owner(cl)
            role_ids = {r["name"]: r["id"] for r in await roles(cl)}
            for d in devs:
                try:
                    await _sync_one(cl, role_ids, d)
                    await _save_state(d["mac"], "ok", None)
                    done += 1
                except Exception as e:  # noqa: BLE001
                    await _save_state(d["mac"], "fehler", str(e)[:250])
                    failed += 1
    except Exception as e:  # noqa: BLE001
        log.warning("PacketFence-Abgleich: %s", e)
        for d in devs:
            await _save_state(d["mac"], "fehler", str(e)[:250])
        return {"ok": False, "error": str(e)[:250], "done": 0}
    return {"ok": failed == 0, "done": done, "failed": failed}


async def unregister(mac: str) -> None:
    if not await configured():
        return
    async with session() as cl:
        r = await cl.get(f"/node/{mac}")
        if r.status_code == 200:
            await cl.patch(f"/node/{mac}", json={"status": "unreg", "pid": "default"})
            await cl.post(f"/node/{mac}/reevaluate_access", json={})


async def expire_and_sync():
    """Naechtlich: abgelaufene Freigaben zuruecknehmen, dann alles abgleichen."""
    async with db() as conn:
        await conn.execute("UPDATE devices SET allowed = 0, updated_at = datetime('now') WHERE allowed = 1 AND valid_until IS NOT NULL "
                           "AND valid_until < date('now')")
        await conn.commit()
    await sync()
