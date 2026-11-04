"""SSH/CLI-Zugriff auf ProCurve/ArubaOS-Switches ueber netmiko.

Lesen (Test, Sicherung) und die Verbindung fuer Aenderungen (changes.py).
Pro Switch laeuft immer nur eine SSH-Aktion (lock), der Switch erlaubt max. 5 Sessions.
"""
import asyncio
import hashlib
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone

from netmiko import ConnectHandler

import cfgparse
from crypto import decrypt
from db import db

log = logging.getLogger("switchview.ssh")

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1bE|\x1b[=>]")


_locks: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)


def lock(switch_id: int) -> asyncio.Lock:
    return _locks[switch_id]


def clean(text: str) -> str:
    text = ANSI.sub("", text).replace("\r", "")
    return "\n".join(line.rstrip() for line in text.splitlines()).strip() + "\n"


def _device(row) -> dict:
    return {
        "device_type": "hp_procurve",
        "host": row["host"],
        "username": row["ssh_user"] or "",
        "password": decrypt(row["ssh_pass"]) or "",
        "conn_timeout": 15,
        "auth_timeout": 20,
        "banner_timeout": 20,
        "timeout": 60,
        "fast_cli": False,
    }


def connect(row):
    return ConnectHandler(**_device(row))


def disconnect(conn):
    try:
        conn.disconnect()
    except Exception:  # noqa: BLE001
        log.warning("Abmelden vom Switch fehlgeschlagen", exc_info=True)


def _run_show(row, commands: list[str]) -> dict[str, str]:
    out = {}
    with ConnectHandler(**_device(row)) as conn:
        for cmd in commands:
            out[cmd] = clean(conn.send_command(cmd, read_timeout=90))
    return out


async def test_ssh(row) -> dict:
    if not row["ssh_user"] or not row["ssh_pass"]:
        return {"ok": False, "error": "Kein SSH-Zugang hinterlegt"}
    try:
        res = await run_shows(row, ["show version"])
        first = next((l for l in res["show version"].splitlines() if l.strip()), "")
        return {"ok": True, "detail": first[:120]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}


async def store_backup(switch_id: int, content: str, trigger: str) -> bool:
    """Speichert die Konfiguration maskiert; gleiche Fassung wie zuletzt wird nicht doppelt abgelegt."""
    content = cfgparse.mask_secrets(content)
    sha = hashlib.sha256(content.encode()).hexdigest()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    async with db() as conn:
        async with conn.execute("SELECT sha FROM config_backups WHERE switch_id = ? ORDER BY id DESC LIMIT 1", (switch_id,)) as cur:
            last = await cur.fetchone()
        if last and last["sha"] == sha:
            return False
        await conn.execute("INSERT INTO config_backups(switch_id, taken_at, sha, content, trigger) VALUES (?,?,?,?,?)",
                           (switch_id, now, sha, content, trigger))
        await conn.commit()
    return True


async def backup_config(switch_id: int, trigger: str = "nightly") -> dict:
    async with db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (switch_id,)) as cur:
            row = await cur.fetchone()
    if not row:
        return {"ok": False, "error": "Switch nicht gefunden"}
    if not row["ssh_user"] or not row["ssh_pass"]:
        return {"ok": False, "error": "Kein SSH-Zugang hinterlegt"}
    try:
        async with lock(switch_id):
            res = await asyncio.to_thread(_run_show, row, ["show running-config"])
    except Exception as e:  # noqa: BLE001
        log.warning("Sicherung %s fehlgeschlagen: %s", row["host"], e)
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}
    content = res["show running-config"]
    if "hostname" not in content and "vlan" not in content:
        return {"ok": False, "error": "Antwort sieht nicht nach einer Konfiguration aus"}
    import changes  # spaete Bindung, vermeidet Zyklus
    await changes.store_cfg(switch_id, content)
    changed = await store_backup(switch_id, content, trigger)
    return {"ok": True, "changed": changed}


async def run_shows(row, commands: list[str]) -> dict[str, str]:
    async with lock(row["id"]):
        return await asyncio.to_thread(_run_show, row, commands)


async def backup_all():
    async with db() as conn:
        async with conn.execute("SELECT id FROM switches WHERE enabled = 1 AND ssh_user IS NOT NULL AND ssh_pass IS NOT NULL") as cur:
            ids = [r["id"] for r in await cur.fetchall()]
    for i in ids:
        await backup_config(i, "nightly")
