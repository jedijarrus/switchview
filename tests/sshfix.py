"""Shared SSH fakes of the suite; no network, no switch.

- HOST_KEY, ServerKey, Session, Sessions: netmiko's side of a ProCurve, for tests that replace sshcli.ConnectHandler with a Sessions
  recorder. It records the host of every session it is asked to open; each session answers every show command with one
  running-config, and its switch offers HOST_KEY, which the first session pins (sshcli._open).
- RUNNING, FakeSSH, SshEnv, make_ssh_env: one ProCurve behind a fake sshcli.connect, for tests of a change from its creation to its
  end (the ssh_env fixture of tests/conftest.py). procurve: the switches columns of that ProCurve.

Unlike tests/switchfix.py this module imports app code, so tests/conftest.py imports it inside its fixture (ssh_env), like netfix; a
test file takes that fixture without importing it (an imported fixture trips ruff F401/F811).
"""
import asyncio
import types
from collections import defaultdict

import changes
import config
import crypto
import db
import dbfix
import sshcli
from cfgparse import parse_config

# The SSH host key every switch of these fakes offers, as an OpenSSH line; the first session pins it (sshcli._open)
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINnHpT9l6rpHqB25Ts4S4dT4wkOfhzh0ZbNcJVpVdfiZ"


class ServerKey:
    """The key paramiko's transport reports (Transport.get_remote_server_key), as far as sshcli.host_key_of reads it."""

    def get_name(self):
        return HOST_KEY.split()[0]

    def get_base64(self):
        return HOST_KEY.split()[1]


class Session:
    """A netmiko connection to a ProCurve: every show command answers with running; its switch offers HOST_KEY."""

    remote_conn_pre = types.SimpleNamespace(get_transport=lambda: types.SimpleNamespace(get_remote_server_key=ServerKey))

    def __init__(self, running: str):
        self.running = running

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def send_command(self, cmd, read_timeout=None):
        return self.running

    def disconnect(self):
        pass


class Sessions:
    """sshcli.ConnectHandler: records the host of every session it is asked to open and hands out a Session answering with running.
    repolls: the re-polls run_change scheduled, when repoll stands in for changes._repoll."""

    def __init__(self, running: str):
        self.running = running
        self.hosts: list[str] = []
        self.repolls: list[int] = []

    def __call__(self, **device):
        self.hosts.append(device["host"])
        return Session(self.running)

    def repoll(self, sid: int):
        self.repolls.append(sid)    # recorded on the call; the task it becomes has nothing to do (no SNMP poll in these tests)
        return asyncio.sleep(0)


# ── One ProCurve behind a fake sshcli.connect (ssh_env) ───────────────────────────────────────────────────────────────────────────
RUNNING = 'hostname "SW-EK-01"\nvlan 1\n   name "DEFAULT_VLAN"\n   untagged 1-24\n   exit\n'    # no radius-server: prepare sends the key


def procurve(**cols) -> dict:
    """The switches columns of SshEnv's ProCurve (SSH access manager / ssh-s3cret, the password encrypted anew on each call, SNMP v2c),
    updated by cols."""
    return {"name": "SW-EK-01", "host": "203.0.113.21", "driver": "procurve", "snmp_version": "2c", "ssh_user": "manager",
            "ssh_pass": crypto.encrypt("ssh-s3cret")} | cols


class FakeSSH:
    """A netmiko session to a ProCurve: show commands answer with env.running, send_config_set raises env.on_send if set."""

    def __init__(self, env):
        self.env = env

    def send_command(self, cmd, read_timeout=None):
        return self.env.running

    def send_config_set(self, commands, **kwargs):
        self.env.sent.append(list(commands))
        if self.env.on_send is not None:
            raise self.env.on_send
        return ""

    def save_config(self):
        pass

    def disconnect(self):
        pass


class SshEnv:
    """One ProCurve with SSH access manager / ssh-s3cret (sid) and what the fakes around it record."""

    def __init__(self, sid: int):
        self.sid = sid
        self.running = RUNNING
        self.on_send: BaseException | None = None
        self.on_connect: BaseException | None = None
        self.sent: list[list[str]] = []
        self.repolls: list[int] = []

    def connect(self, row):
        if self.on_connect is not None:
            raise self.on_connect
        return FakeSSH(self)

    def repoll(self, sid: int):
        self.repolls.append(sid)
        return asyncio.sleep(0)

    async def run_prepare(self, **settings) -> int:
        """Store the settings (radius_key encrypted, as PUT /api/settings does), create the RADIUS preparation as /prepare previews it
        on RUNNING, run it to its end; the change id."""
        for k, v in settings.items():
            await db.set_setting(k, crypto.encrypt(v) if k == "radius_key" else v)
        plan = changes.plan_prepare(parse_config(RUNNING), {"server": settings.get("radius_server", ""),
                                                            "key": settings.get("radius_key", "")})
        cid = await changes.create_change(self.sid, "tester", "prepare", "RADIUS vorbereiten", {}, plan | {"mechanism": "ssh"})
        await changes.run_change(cid)
        return cid

    def change(self, cid: int) -> dict:
        conn = dbfix.connect()
        try:
            return dict(conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)).fetchone())
        finally:
            conn.close()


def make_ssh_env(tmp_path, monkeypatch) -> SshEnv:
    """A fresh database under tmp_path (the app's own init_db) with the ProCurve of procurve(); sshcli.connect answered by its SshEnv;
    fresh switch locks and R27 marks; re-polls recorded, never run."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    asyncio.run(db.init_db())
    env = SshEnv(dbfix.insert_switch(**procurve()))
    monkeypatch.setattr(sshcli, "connect", env.connect)
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    monkeypatch.setattr(changes, "_cfg_stale", set())
    monkeypatch.setattr(changes, "_repoll", env.repoll)
    return env
