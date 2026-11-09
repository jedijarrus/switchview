"""PacketFence-API (v1): bekannte Geraete als registrierte Nodes mit Rolle pflegen.

Ein freigegebenes Geraet ist in PacketFence 'reg' mit seiner Rolle (node category). An Ports im Status
'known' oder 'radius' fragt der Switch per MAC-Anmeldung, PacketFence antwortet mit dem VLAN der Rolle.
Gesperrte oder geloeschte Geraete werden 'unreg' gesetzt, nicht geloescht (Verlauf bleibt in PacketFence).
"""
import logging
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone

import httpx

from crypto import decrypt, unreadable
from db import db, load_settings

log = logging.getLogger("switchview.pf")
# Besitzer (pid) aller in SwitchView freigegebenen Geraete. Ein VLAN-Filter in PacketFence
# laesst MAC-Anmeldung (Ethernet-NoEAP) nur fuer Nodes dieses Besitzers zu.
OWNER = "switchview"


async def config() -> dict:
    """The stored PacketFence access: url, user, password ("" when not set or not decryptable), password_unreadable when a stored one
    does not decrypt, verify. TLS verification without a stored value is on (E32: a new installation), a stored one stays."""
    # target and secret in one SELECT (db.load_settings): a concurrent settings PUT never pairs one with the other's old value (F2)
    s = await load_settings(["pf_url", "pf_user", "pf_pass", "pf_verify_tls"])
    return {"url": (s["pf_url"] or "").rstrip("/"), "user": s["pf_user"] or "", "password": decrypt(s["pf_pass"]) or "",
            "password_unreadable": unreadable(s["pf_pass"]), "verify": (s["pf_verify_tls"] or "1") == "1"}


def _set_up(c: dict) -> bool:
    """Whether the access c (config) is set up: a password that does not decrypt counts, so whoever needs PacketFence gets session's
    reason instead of passing over it in silence."""
    return bool(c["url"] and c["user"] and (c["password"] or c["password_unreadable"]))


async def configured() -> bool:
    return _set_up(await config())


@asynccontextmanager
async def session():
    c = await config()
    if not _set_up(c):
        raise RuntimeError("PacketFence-API ist nicht eingerichtet")
    if c["password_unreadable"]:
        raise RuntimeError("PacketFence-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – in den Einstellungen neu eingeben")
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


async def _reevaluate(cl, mac: str) -> int | None:
    """Asks PacketFence to re-evaluate the node's access (CoA), so a device that is plugged in switches over at once; None when it
    answers 2xx, else its status code."""
    r = await cl.post(f"/node/{mac}/reevaluate_access", json={})
    return None if 200 <= r.status_code < 300 else r.status_code


async def _sync_one(cl, role_ids: dict, dev) -> str | None:
    """Writes the device dev to its node (registered with its role, or unregistered) and re-evaluates it. RuntimeError for a role
    PacketFence does not have, or when it does not confirm reading or writing the node. A failed re-evaluation is no error, the node
    stands as written: the hint it returns then says that the device switches over at its next login only (None without one)."""
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
        return None
    if r.status_code not in (200, 201, 204):
        raise RuntimeError(f"Node schreiben: HTTP {r.status_code} {r.text[:150]}")
    code = await _reevaluate(cl, mac)
    if code is not None:
        return f"Freigabe übertragen, aber Neubewertung (CoA) fehlgeschlagen: HTTP {code} – das Gerät schaltet erst bei der nächsten Anmeldung um"
    return None


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
                    hint = await _sync_one(cl, role_ids, d)
                    await _save_state(d["mac"], "ok", hint)    # transferred; a hint (failed CoA) stands at the device
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


async def unregister(mac: str) -> str | None:
    """Takes the release of a device that is being deleted back in PacketFence: its node unregistered and re-evaluated. Nothing to do
    without PacketFence set up or for a node PacketFence does not know (404). RuntimeError when PacketFence does not confirm reading or
    unregistering the node: the caller keeps the device, which would otherwise stay registered in PacketFence without a trace in
    SwitchView. A failed re-evaluation is only a warning, returned (None without one): the node is unregistered."""
    if not await configured():
        return None
    async with session() as cl:
        r = await cl.get(f"/node/{mac}")
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise RuntimeError(f"Node lesen: HTTP {r.status_code}")
        r = await cl.patch(f"/node/{mac}", json={"status": "unreg", "pid": "default"})
        if r.status_code not in (200, 201, 204):
            raise RuntimeError(f"Node zurücknehmen: HTTP {r.status_code} {r.text[:150]}")
        code = await _reevaluate(cl, mac)
    return None if code is None else f"In PacketFence zurückgenommen, aber Neubewertung (CoA) fehlgeschlagen: HTTP {code}"


# The LAN sessions of the locationlog: by 802.1X and by MAC (MAC authentication bypass)
WIRED = ("Ethernet-EAP", "Ethernet-NoEAP")
SESSION_FIELDS = ["mac", "connection_type", "dot1x_username", "role", "vlan", "switch", "switch_ip", "switch_mac", "port", "ifDesc", "start_time"]
PARK_ROLE = "vlan_3999"                 # the role of the park VLAN (where a PacketFence VLAN filter puts a MAC login)
OPEN = "0000-00-00 00:00:00"            # the end_time of a session that still runs


def _wired() -> dict:
    return {"op": "or", "values": [{"field": "connection_type", "op": "equals", "value": w} for w in WIRED]}


async def _search(cl, query: dict, fields: list[str], *, sort: list[str] | None = None, limit: int = 1000, pages: int = 20) -> list[dict]:
    """The locationlog entries of query (POST /locationlogs/search), page by page: at most pages pages of limit entries.
    RuntimeError when PacketFence does not answer the search."""
    out: list[dict] = []
    cursor = 0
    for _ in range(pages):
        body = {"query": query, "fields": fields, "limit": limit, "cursor": cursor} | ({"sort": sort} if sort else {})
        r = await cl.post("/locationlogs/search", json=body)
        if r.status_code != 200:
            raise RuntimeError(f"PacketFence-Verlauf nicht lesbar (HTTP {r.status_code})")
        data = r.json()
        items = [i for i in (data.get("items") or []) if isinstance(i, dict)]
        out += items
        nxt = data.get("nextCursor")
        if not items or not nxt:
            break
        cursor = nxt
    return out


async def open_sessions() -> list[dict]:
    """The LAN sessions PacketFence holds open now (its locationlog entries without an end, end_time OPEN): by 802.1X and by MAC,
    each with SESSION_FIELDS. RuntimeError without PacketFence set up or when it does not answer the search."""
    query = {"op": "and", "values": [_wired(), {"field": "end_time", "op": "equals", "value": OPEN}]}
    async with session() as cl:
        return await _search(cl, query, SESSION_FIELDS)


async def expire_and_sync():
    """Naechtlich: abgelaufene Freigaben zuruecknehmen, dann alles abgleichen."""
    async with db() as conn:
        await conn.execute("UPDATE devices SET allowed = 0, updated_at = datetime('now') WHERE allowed = 1 AND valid_until IS NOT NULL "
                           "AND valid_until < date('now')")
        await conn.commit()
    await sync()
