"""SNMP-Lesezugriff ueber net-snmp (snmpbulkwalk/snmpget), nur lesend.

Ausgabe immer numerisch (-On), ohne Typ (-Oq), Enums als Zahl (-Oe),
Timeticks als Zahl (-Ot). Bitmaps (VLAN-Portlisten, MACs) mit -Ox als Hex.
"""
import asyncio
import os
import re

AUTH_PROTOS = {"SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "MD5"}
PRIV_PROTOS = {"AES", "AES-192", "AES-256", "DES"}


class SnmpError(Exception):
    pass


def _auth_args(cred: dict) -> list[str]:
    if cred.get("snmp_version") == "3":
        user = cred.get("snmp_user") or ""
        args = ["-v3", "-u", user]
        ap, apass = cred.get("snmp_auth_proto"), cred.get("snmp_auth_pass")
        pp, ppass = cred.get("snmp_priv_proto"), cred.get("snmp_priv_pass")
        if ap and apass and pp and ppass:
            args += ["-l", "authPriv", "-a", ap, "-A", apass, "-x", pp, "-X", ppass]
        elif ap and apass:
            args += ["-l", "authNoPriv", "-a", ap, "-A", apass]
        else:
            args += ["-l", "noAuthNoPriv"]
        return args
    return ["-v2c", "-c", cred.get("snmp_community") or "public"]


async def _run(cmd: list[str], timeout: float) -> str:
    env = dict(os.environ, MIBS="")
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise SnmpError("Zeitüberschreitung bei der SNMP-Abfrage")
    text = out.decode("utf-8", "replace")
    if proc.returncode != 0 and not text.strip():
        msg = err.decode("utf-8", "replace").strip().splitlines()
        msg = [m for m in msg if "Cannot find module" not in m and "MIB search path" not in m]
        raise SnmpError(msg[-1] if msg else f"snmp Exit-Code {proc.returncode}")
    return text


def _parse(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        if line.startswith("."):
            oid, _, val = line.partition(" ")
            rows.append((oid.lstrip("."), val.strip()))
        elif rows and line.strip():
            # Fortsetzung eines mehrzeiligen Strings
            oid, val = rows[-1]
            rows[-1] = (oid, val + "\n" + line)
    out = []
    for oid, val in rows:
        if "No Such Object" in val or "No Such Instance" in val or "No more variables" in val:
            continue
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        out.append((oid, val))
    return out


async def walk(host: str, cred: dict, oid: str, hex_values: bool = False, timeout: float = 60) -> list[tuple[str, str]]:
    cmd = ["snmpbulkwalk", *_auth_args(cred), "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", "-Cr25"]
    if hex_values:
        cmd.append("-Ox")
    cmd += [host, oid]
    return _parse(await _run(cmd, timeout))


async def get(host: str, cred: dict, oids: list[str], timeout: float = 15) -> dict[str, str]:
    cmd = ["snmpget", *_auth_args(cred), "-On", "-Oq", "-Oe", "-Ot", "-t", "3", "-r", "1", host, *oids]
    return dict(_parse(await _run(cmd, timeout)))


def hex_to_bytes(val: str) -> bytes:
    h = re.sub(r"[^0-9A-Fa-f]", "", val)
    if len(h) % 2:
        h = h[:-1]
    try:
        return bytes.fromhex(h)
    except ValueError:
        return b""


def bitmap_ports(val: str) -> set[int]:
    """Q-BRIDGE PortList: Bit 1 (MSB des ersten Bytes) = Bridge-Port 1."""
    b = hex_to_bytes(val)
    return {i * 8 + j + 1 for i, byte in enumerate(b) for j in range(8) if byte & (0x80 >> j)}


def fmt_mac(raw: bytes) -> str:
    return ":".join(f"{x:02x}" for x in raw[:6])
