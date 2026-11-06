"""SSH/CLI-Zugriff auf ProCurve/ArubaOS-Switches ueber netmiko.

Lesen (Test, Sicherung) und die Verbindung fuer Aenderungen (changes.py).
Pro Switch laeuft immer nur eine SSH-Aktion (lock), der Switch erlaubt max. 5 Sessions.
Nur fuer einen Treiber mit SSH-CLI (drivers, Faehigkeit cli): netmiko spricht den Switch als hp_procurve mit ProCurve-Befehlen an, und
die Antwort verstehen nur der ProCurve-Parser und das Maskieren in cfgparse. Fuer jeden anderen Treiber geht keine Sitzung auf (R39),
auch mit gespeichertem SSH-Zugang (er bleibt gespeichert, wird aber nie benutzt): _device ist die eine Stelle davor.
Every session goes through _open, which pins the switch's SSH host key at the first contact and refuses any other key afterwards,
before the login (trust on first use, E30).
"""
import asyncio
import base64
import binascii
import hashlib
import logging
import os
import re
import tempfile
from collections import defaultdict
from datetime import datetime, timezone

from netmiko import ConnectHandler, NetmikoTimeoutException

import cfgparse
import drivers
from crypto import decrypt, keyed_digest, unreadable
from db import db, execute_sync, query_sync

log = logging.getLogger("switchview.ssh")

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1bE|\x1b[=>]")
# show commands that print secrets in clear text even with encrypt-credentials: SwitchView never runs them (E27)
SECRET_SHOWS = re.compile(r"^\s*show\s+(radius|tech|tacacs)\b", re.I)


_locks: dict[int, asyncio.Lock] = defaultdict(asyncio.Lock)


def lock(switch_id: int) -> asyncio.Lock:
    return _locks[switch_id]


def clean(text: str) -> str:
    text = ANSI.sub("", text).replace("\r", "")
    return "\n".join(line.rstrip() for line in text.splitlines()).strip() + "\n"


class NoCliError(RuntimeError):
    """Fuer diesen Switch geht keine SSH-Sitzung auf: sein Treiber hat keine SSH-CLI (cli_refusal)."""


class CredentialError(RuntimeError):
    """The stored SSH password of the switch does not decrypt (SECRET_KEY changed?): no session (_device), since an empty password in
    its place is never the one stored, and SSH writes configuration."""


# Was der Verbindungstest fuer SSH meldet, wenn der Treiber keine CLI hat: kein Fehler, dieser Switch braucht kein SSH
SSH_UNUSED = "nicht verwendet (Treiber ohne CLI)"


def cli_refusal(row) -> str | None:
    """Warum fuer den Switch row (switches-Zeile) keine SSH-Sitzung aufgeht, sonst None: sein Treiber (drivers.driver_for) hat keine
    SSH-CLI."""
    driver = drivers.driver_for(row)
    return None if drivers.can(driver, "cli") else f"Treiber {driver.name} hat keine SSH-CLI"


def fingerprints(key: str | None) -> dict | None:
    """The fingerprints of the SSH public key line key ("<type> <base64>", as host_key_of writes it) the way OpenSSH writes them, both
    over the key bytes: "SHA256:" plus base64 without "=" padding, and MD5 as colon-separated hex pairs (what older ProCurve firmware
    shows). None without a key or for one whose base64 does not decode."""
    parts = (key or "").split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return None
    md5 = hashlib.md5(blob, usedforsecurity=False).hexdigest()
    return {"sha256": "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="),
            "md5": ":".join(md5[i:i + 2] for i in range(0, len(md5), 2))}


class HostKeyMismatch(RuntimeError):
    """The switch offered another SSH host key than the pinned one (pinned: the key line stored for it), so no session: paramiko
    compares the key after the key exchange and before the login, nothing is sent, not even the password. Without pinned (None) the
    key of a first contact could not be pinned, because the switch entry changed during the login (another address, or deleted)."""

    def __init__(self, host: str, pinned: str | None):
        if pinned:
            fp = fingerprints(pinned)
            sha = fp["sha256"] if fp else "unlesbar"
            text = (f"SSH-Hostschlüssel von {host} passt nicht zum gemerkten ({sha}). Möglicher Angriff oder neuer Schlüssel am "
                    "Switch – nichts gesendet. Ist der neue Schlüssel erwartet (Tausch, Firmware): Switch → Zugang bearbeiten → "
                    "„SSH-Hostschlüssel vergessen“.")
        else:
            text = (f"SSH-Hostschlüssel von {host} ließ sich nicht merken: der Switch-Eintrag hat sich inzwischen geändert (Adresse oder "
                    "gelöscht) – Sitzung beendet, kein Befehl gesendet. Bitte erneut versuchen.")
        super().__init__(text)


def host_key_of(conn) -> str:
    """The SSH host key the switch offered in the open netmiko session conn, as "<type> <base64>" (a known_hosts line without the
    host)."""
    k = conn.remote_conn_pre.get_transport().get_remote_server_key()
    return f"{k.get_name()} {k.get_base64()}"


def _device(row, known_hosts: str | None = None) -> dict:
    """Die netmiko-Parameter fuer den Switch row. Alles, was ConnectHandler erreicht (connect, _run_show), geht hier durch: ohne CLI im
    Treiber NoCliError statt einer Sitzung. With known_hosts (a file holding the pinned key, _open) paramiko accepts that key only
    (RejectPolicy, ssh_strict); without it a first contact takes the key it is offered (AutoAddPolicy), and _open pins it. The
    system's known_hosts is never read: only the key SwitchView pinned counts. A stored SSH password that does not decrypt is a
    CredentialError, never an empty password."""
    reason = cli_refusal(row)
    if reason:
        raise NoCliError(reason)
    if unreadable(row["ssh_pass"]):
        raise CredentialError("SSH-Kennwort lässt sich nicht entschlüsseln (SECRET_KEY geändert?) – bitte im Switch-Formular neu eingeben, "
                              "nichts gesendet")
    keys = ({"ssh_strict": True, "system_host_keys": False, "alt_host_keys": True, "alt_key_file": known_hosts} if known_hosts
            else {"ssh_strict": False, "system_host_keys": False, "alt_host_keys": False})
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
        **keys,
    }


# How paramiko's refusals of a host key reach SwitchView, inside netmiko's NetmikoTimeoutException: BadHostKeyException ("Host key
# for server '…' does not match: …") and RejectPolicy ("Server '…' not found in known_hosts"). Only the message tells them from a
# timeout; should that text ever change, the session is refused all the same, with netmiko's English message (E31).
_KEY_REFUSALS = ("does not match", "not found in known_hosts")


def _open(row):
    """The netmiko session to the switch row, its SSH host key pinned (trust on first use, E30). Synchronous: it runs in a worker
    thread, under the switch's lock (connect in run_change, _run_show). Whether a key is pinned decides the database now, never row:
    a caller may have read row before the lock, before another contact pinned the key. With a pinned key paramiko gets it as the
    only known host key and refuses any other before the login (HostKeyMismatch). Without one the first contact takes the key it is
    offered and pins it, but only while the entry still has row's host and no key; is a different key stored afterwards, or none
    (the entry changed meanwhile), the session is closed and refused. A driver without CLI fails first (NoCliError), before anything
    else; a switch that is gone gets no session."""
    reason = cli_refusal(row)
    if reason:
        raise NoCliError(reason)
    found = query_sync("SELECT ssh_host_key FROM switches WHERE id = ?", (row["id"],))
    if not found:
        raise RuntimeError("Switch nicht gefunden")
    pinned = found[0][0]
    if pinned:
        with tempfile.TemporaryDirectory(prefix="switchview-ssh-") as tmp:
            known_hosts = os.path.join(tmp, "known_hosts")
            with open(known_hosts, "w", encoding="utf-8") as f:
                f.write(f"{row['host']} {pinned}\n")
            try:
                return ConnectHandler(**_device(row, known_hosts))
            except NetmikoTimeoutException as e:
                if any(t in str(e) for t in _KEY_REFUSALS):
                    raise HostKeyMismatch(row["host"], pinned) from e
                raise
    conn = ConnectHandler(**_device(row))
    try:
        key = host_key_of(conn)
        execute_sync("UPDATE switches SET ssh_host_key = ?, ssh_host_key_at = ? WHERE id = ? AND host = ? AND ssh_host_key IS NULL",
                     (key, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), row["id"], row["host"]))
        found = query_sync("SELECT ssh_host_key FROM switches WHERE id = ? AND host = ?", (row["id"], row["host"]))
    except BaseException:
        disconnect(conn)
        raise
    stored = found[0][0] if found else None
    if stored != key:
        disconnect(conn)
        raise HostKeyMismatch(row["host"], stored)
    return conn


def connect(row):
    return _open(row)


def disconnect(conn):
    try:
        conn.disconnect()
    except Exception:  # noqa: BLE001
        log.warning("Abmelden vom Switch fehlgeschlagen", exc_info=True)


def _run_show(row, commands: list[str]) -> dict[str, str]:
    """Each command's answer, cleaned. ValueError for a command that prints secrets (SECRET_SHOWS), before a session opens."""
    for cmd in commands:
        if SECRET_SHOWS.match(cmd):
            raise ValueError(f"„{cmd}“ gibt Geheimnisse im Klartext aus und wird nie ausgeführt")
    out = {}
    with _open(row) as conn:
        for cmd in commands:
            out[cmd] = clean(conn.send_command(cmd, read_timeout=90))
    return out


def _error(e: Exception) -> str:
    """An error as the connection test and the backup report it: its type and text, the text cut to 200 characters, except for a
    HostKeyMismatch (SwitchView's own text, bounded by the 64-character host), whose end says what to do."""
    return f"{type(e).__name__}: {e if isinstance(e, HostKeyMismatch) else str(e)[:200]}"


async def test_ssh(row) -> dict:
    if cli_refusal(row):    # kein Fehlschlag: SSH ist fuer diesen Switch kein Weg (gleich, ob ein Zugang gespeichert ist)
        return {"ok": None, "unused": True, "detail": SSH_UNUSED}
    if not row["ssh_user"] or not row["ssh_pass"]:
        return {"ok": False, "error": "Kein SSH-Zugang hinterlegt"}
    try:
        res = await run_shows(row, ["show version"])
        first = next((line for line in res["show version"].splitlines() if line.strip()), "")
        return {"ok": True, "detail": first[:120]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": _error(e)}


def backup_sha(content: str) -> str:
    """The sha of the backup of the running-config content: the SHA-256 (hex) of its masked text, as config_backups.sha stores it."""
    return hashlib.sha256(cfgparse.mask_secrets(content).encode()).hexdigest()


async def store_backup(switch_id: int, content: str, trigger: str) -> bool:
    """Stores the running-config content masked, with its sha (backup_sha) and the mark of the unmasked text (raw_mac,
    crypto.keyed_digest), and says whether it made a new row. No new row when the last row has the same sha and the same raw_mac:
    then nothing changed. With the same sha and another raw_mac only secrets changed, which makes a new row, except when reading for
    a preview (trigger "lesen", up to every 600 s): that compares the masked text only, since a firmware that salts its encrypted
    secrets anew on every read would otherwise store a backup per preview. A last row from before raw_mac (NULL) with the same sha
    gets this mark filled in, without a new row: the first backup after the update adds none."""
    sha, mark = backup_sha(content), keyed_digest("backup", content)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    async with db() as conn:
        async with conn.execute("SELECT id, sha, raw_mac FROM config_backups WHERE switch_id = ? ORDER BY id DESC LIMIT 1",
                                (switch_id,)) as cur:
            last = await cur.fetchone()
        if last and last["sha"] == sha:
            if last["raw_mac"] is None:
                await conn.execute("UPDATE config_backups SET raw_mac = ? WHERE id = ?", (mark, last["id"]))
                await conn.commit()
                return False
            if last["raw_mac"] == mark or trigger == "lesen":
                return False
        await conn.execute("INSERT INTO config_backups(switch_id, taken_at, sha, content, trigger, raw_mac) VALUES (?,?,?,?,?,?)",
                           (switch_id, now, sha, cfgparse.mask_secrets(content), trigger, mark))
        await conn.commit()
    return True


async def backup_config(switch_id: int, trigger: str = "nightly") -> dict:
    """Read the running-config of the switch, store it (masked, store_backup) and its parse (changes.store_cfg, the cache of
    changes.fresh_cfg). A configuration that does not parse is still kept as a backup: it is the evidence, all the more for a switch
    that sends something odd (E24); the answer is then ok False with the parse error."""
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
        return {"ok": False, "error": _error(e)}
    content = res["show running-config"]
    if "hostname" not in content and "vlan" not in content:
        return {"ok": False, "error": "Antwort sieht nicht nach einer Konfiguration aus"}
    import changes  # spaete Bindung, vermeidet Zyklus
    changed = await store_backup(switch_id, content, trigger)
    try:
        await changes.store_cfg(switch_id, content)
    except Exception as e:  # noqa: BLE001
        error = f"Konfiguration gesichert, aber nicht auswertbar: {type(e).__name__}: {cfgparse.mask_secrets(str(e))[:200]}"
        log.warning("%s: %s", row["host"], error)
        return {"ok": False, "error": error}
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
    for i in ids:    # one switch at a time; whatever goes wrong with one never stops the others (F5)
        try:
            await backup_config(i, "nightly")
        except Exception:  # noqa: BLE001
            log.exception("Nächtliche Sicherung von Switch %s fehlgeschlagen", i)
