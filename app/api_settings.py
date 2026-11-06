"""The settings API: OPNsense, RADIUS and PacketFence settings with their secrets bound to their destinations, the name refresh and the
audit log. Split from main.py (Phase 3, Task 11), the code as it was."""
import ipaddress
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import auth
import changes
import names as names_mod
from api_switches import same_destination
from crypto import encrypt, unreadable
from db import audit, db, load_settings, read_settings, write_settings
from jobs import _schedule

router = APIRouter()


# ── Einstellungen ─────────────────────────────────────────────────────────────
class SettingsIn(BaseModel):
    poll_minutes: int = Field(default=15, ge=5, le=1440)
    opnsense_url: str = Field(default="", max_length=200)
    opnsense_key: str | None = Field(default=None, max_length=200)
    opnsense_secret: str | None = Field(default=None, max_length=200)
    opnsense_verify_tls: bool = True    # E32: on for a new installation; a stored value stays what it is
    radius_server: str = Field(default="", max_length=45)
    radius_key: str | None = Field(default=None, max_length=64)
    pf_url: str = Field(default="", max_length=200)
    pf_user: str = Field(default="", max_length=100)
    pf_pass: str | None = Field(default=None, max_length=200)
    pf_verify_tls: bool = True


# The secrets of the settings by the destination each one is sent to (F2): a PUT that changes a destination deletes each of its stored
# secrets that it does not carry anew. The order is that of "cleared" in the answer.
DESTINATION_SECRETS: dict[str, tuple[str, ...]] = {"opnsense_url": ("opnsense_key", "opnsense_secret"), "radius_server": ("radius_key",),
                                                   "pf_url": ("pf_pass",)}


# The secrets of the settings in the order "unreadable" lists them (sorted)
SETTINGS_SECRETS = ("opnsense_key", "opnsense_secret", "pf_pass", "radius_key")


@router.get("/api/settings")
async def get_settings(user=Depends(auth.current_user)):
    """The settings without a secret: of each secret only *_set, and in "unreadable" those stored that do not decrypt (SECRET_KEY
    changed?), so the view asks for them anew. One SELECT (db.load_settings)."""
    s = await load_settings(["poll_minutes", "opnsense_url", "opnsense_verify_tls", "radius_server", "pf_url", "pf_user", "pf_verify_tls",
                             *SETTINGS_SECRETS])
    return {"poll_minutes": int(s["poll_minutes"] or 15),
            "opnsense_url": s["opnsense_url"] or "",
            "opnsense_key_set": bool(s["opnsense_key"]),
            "opnsense_secret_set": bool(s["opnsense_secret"]),
            "opnsense_verify_tls": (s["opnsense_verify_tls"] or "1") == "1",
            "radius_server": s["radius_server"] or "",
            "radius_key_set": bool(s["radius_key"]),
            "pf_url": s["pf_url"] or "",
            "pf_user": s["pf_user"] or "",
            "pf_pass_set": bool(s["pf_pass"]),
            "pf_verify_tls": (s["pf_verify_tls"] or "1") == "1",
            "unreadable": sorted(k for k in SETTINGS_SECRETS if unreadable(s[k]))}


@router.put("/api/settings")
async def put_settings(body: SettingsIn, user=Depends(auth.current_user)):
    """A secret changes only when the PUT carries a value for it ("" deletes it), except that it is bound to its destination (F2,
    DESTINATION_SECRETS): a new destination (same_destination) deletes each of its stored secrets the PUT does not carry anew;
    "cleared" names them. One write transaction as in update_switch. The RADIUS server is stored canonical and without a zone id
    (§6 (a)): it lands in a CLI line on every switch prepared for RADIUS. The audit names each destination whose stored text changes
    ("old → new") and what the change deleted."""
    if body.opnsense_url and not re.fullmatch(r"https?://[A-Za-z0-9.\-:]+(/[\w\-./]*)?", body.opnsense_url):
        raise HTTPException(422, "OPNsense-Adresse ungültig")
    if body.pf_url and not re.fullmatch(r"https?://[A-Za-z0-9.\-:]+(/[\w\-./]*)?", body.pf_url):
        raise HTTPException(422, "PacketFence-Adresse ungültig")
    radius_server = body.radius_server
    if radius_server:
        try:
            ip = ipaddress.ip_address(radius_server)
        except ValueError:
            raise HTTPException(422, "RADIUS-Server muss eine IP-Adresse sein")
        if getattr(ip, "scope_id", None) is not None:
            raise HTTPException(422, "RADIUS-Server muss eine IP-Adresse ohne Zonen-Angabe sein")
        radius_server = str(ip)
    if body.radius_key and not changes.RADIUS_KEY_RE.fullmatch(body.radius_key):
        raise HTTPException(422, "Shared Secret: 8–64 Zeichen, ohne Leerzeichen, Anführungszeichen, Backslash, ? und ~ (die versteht die Switch-CLI nicht)")
    new = {"poll_minutes": str(body.poll_minutes), "opnsense_url": body.opnsense_url.rstrip("/"),
           "opnsense_verify_tls": "1" if body.opnsense_verify_tls else "0", "radius_server": radius_server,
           "pf_url": body.pf_url.rstrip("/"), "pf_user": body.pf_user, "pf_verify_tls": "1" if body.pf_verify_tls else "0"}
    secrets = [k for keys in DESTINATION_SECRETS.values() for k in keys]
    for k in secrets:
        v = getattr(body, k)
        if v is not None:
            new[k] = encrypt(v) if v else None
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        old = await read_settings(conn, [*DESTINATION_SECRETS, *secrets])
        changed, cleared = [], []
        for dest, keys in DESTINATION_SECRETS.items():
            if (old[dest] or "") != new[dest]:
                changed.append(f"{dest}: {old[dest] or '–'} → {new[dest] or '–'}")
            if not same_destination(old[dest], new[dest]):
                for k in keys:
                    if old[k] and getattr(body, k) is None:
                        new[k] = None
                        cleared.append(k)
        await write_settings(conn, new)
        await conn.commit()
    await _schedule()
    await audit(user["username"], "settings_update", "", ", ".join(changed + ([f"gelöscht: {', '.join(cleared)}"] if cleared else [])))
    return {"ok": True, "cleared": cleared}


@router.post("/api/names/refresh")
async def names_refresh(user=Depends(auth.current_user)):
    return await names_mod.refresh_names()


@router.get("/api/audit")
async def audit_log(user=Depends(auth.current_user)):
    async with db() as conn:
        async with conn.execute("SELECT ts, username, action, target, detail FROM audit ORDER BY id DESC LIMIT 200") as cur:
            return [dict(r) for r in await cur.fetchall()]
