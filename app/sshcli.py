"""SSH/CLI-Zugriff auf ProCurve/ArubaOS-Switches ueber netmiko.

Lesen (Test, Sicherung) und die Verbindung fuer Aenderungen (changes.py).
Pro Switch laeuft immer nur eine SSH-Aktion (lock), der Switch erlaubt max. 5 Sessions.
Nur fuer einen Treiber mit SSH-CLI (drivers, Faehigkeit cli): netmiko spricht den Switch als hp_procurve mit ProCurve-Befehlen an, und
die Antwort verstehen nur der ProCurve-Parser und das Maskieren in cfgparse. Fuer jeden anderen Treiber geht keine Sitzung auf (R39),
auch mit gespeichertem SSH-Zugang (er bleibt gespeichert, wird aber nie benutzt): _device ist die eine Stelle davor.
"""
import asyncio
import hashlib
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone

from netmiko import ConnectHandler

import cfgparse
import drivers
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


class NoCliError(RuntimeError):
    """Fuer diesen Switch geht keine SSH-Sitzung auf: sein Treiber hat keine SSH-CLI (cli_refusal)."""


# Was der Verbindungstest fuer SSH meldet, wenn der Treiber keine CLI hat: kein Fehler, dieser Switch braucht kein SSH
SSH_UNUSED = "nicht verwendet (Treiber ohne CLI)"


def cli_refusal(row) -> str | None:
    """Warum fuer den Switch row (switches-Zeile) keine SSH-Sitzung aufgeht, sonst None: sein Treiber (drivers.driver_for) hat keine
    SSH-CLI."""
    driver = drivers.driver_for(row)
    return None if drivers.can(driver, "cli") else f"Treiber {driver.name} hat keine SSH-CLI"


def _device(row) -> dict:
    """Die netmiko-Parameter fuer den Switch row. Alles, was ConnectHandler erreicht (connect, _run_show), geht hier durch: ohne CLI im
    Treiber NoCliError statt einer Sitzung."""
    reason = cli_refusal(row)
    if reason:
        raise NoCliError(reason)
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
    if cli_refusal(row):    # kein Fehlschlag: SSH ist fuer diesen Switch kein Weg (gleich, ob ein Zugang gespeichert ist)
        return {"ok": None, "unused": True, "detail": SSH_UNUSED}
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
    reason = cli_refusal(row)    # vor allem anderen: keine Sitzung, keine Sicherung, kein switch_cfg aus einer Fehldeutung
    if reason:
        return {"ok": False, "error": reason}
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
    """Die naechtliche Sicherung: jeder aktive Switch mit SSH-Zugang, dessen Treiber sichern kann (Faehigkeit backup). Die anderen
    uebergeht sie still, ohne Sitzung und ohne Meldung, auch mit gespeichertem SSH-Zugang (R39)."""
    async with db() as conn:
        async with conn.execute("SELECT id, driver FROM switches WHERE enabled = 1 AND ssh_user IS NOT NULL AND ssh_pass IS NOT NULL") as cur:
            ids = [r["id"] for r in await cur.fetchall() if drivers.can(drivers.driver_for(r), "backup")]
    for i in ids:
        await backup_config(i, "nightly")
