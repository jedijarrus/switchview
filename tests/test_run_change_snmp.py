"""Task 11: changes.run_change over SNMP, the place where SNMP SETs reach a live switch, and what goes with it: create_change
persisting the mechanism, snmpwrite.apply_ops, persistence per driver (R26), the fresh_cfg cache invalidation (R27) and the host
guard in snmp.py.

The safety loop is the one of the SSH path, step for step, inside the same per-switch lock (sshcli.lock): read the switch live
(snmpwrite.read_cfg) -> plan again against that read (plan_ports, mechanism "snmp") -> blocked, or shown different from the preview:
aborted, nothing written -> store `before` from this read (with the PVID, R21) -> ONE SET (snmpwrite.apply_ops, with the write
identity) -> read back -> verify -> ok, otherwise unclear. On top of verify_ports the SNMP verify checks the PVID (R21) and counts a
written port that the read-back no longer has, or now finds unmanaged, as a mismatch (cfg only holds placeholders for those). A SET
that errors is an UNKNOWN outcome (the switch may have taken it): the read-back decides. A failure before anything was sent is
"failed", after that "unclear". Persistence (R26): saved=1 only for a driver with the cap snmp_autosave (ProCurve), otherwise ok +
saved=0 + a warning step. Never SSH, never a config backup, no switch_cfg write: there is no running-config.

A mechanism NULL (a row from before the column) or "ssh" runs the SSH path as before; any other one aborts without touching the switch.

No network and no switch: behind SNMP sits the simulated agent of tests/switchfix.py (snmp.walk answers from its rows, snmp.set_vars
goes through switchfix.store, which refuses what a switch would refuse); the SSH side is a fake netmiko connection, and on the SNMP
path every SSH entry point is a trap. Previews are planned by main._make_plan, as /plan and /apply plan them, against a fresh database
(the environment of tests/conftest.py, db.init_db with the migration); changes.inventory (the poll) lists the fixture switch's ports.
Expected messages, shown lines and varbinds are written out by hand.
"""
import asyncio
import json
from collections import defaultdict
from datetime import datetime, timezone

import pytest
from netmiko.exceptions import NetmikoTimeoutException

import cfgparse
import changes
import config
import crypto
import db
import drivers
import main
import snmp
import snmpwrite
import sshcli
from drivers import Driver
from switchfix import (CATALYST_VMVLAN, HOST, IF_ADMIN, IF_ALIAS, IFTYPE_SAMPLE, POE_ADMIN, PVID, VLAN_EGRESS, VLAN_UNTAGGED, VMVLAN,
                       W_CATALYST, W_CATALYST_POE, W_SAMPLE, WALK_BASES, agent, edit_walks, store)

USER = "tester"
FW = "WB.16.99.0001"
READ, RW = "read-s3cret", "rw-s3cret"
NO_V3 = {"snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None, "snmp_priv_proto": None, "snmp_priv_pass": None}
READ_CRED = {"snmp_version": "2c", "snmp_community": READ, **NO_V3}    # poller.creds_of(row): what read_cfg walks with
RW_CRED = {"snmp_version": "2c", "snmp_community": RW, **NO_V3}        # poller.creds_of(row, write=True): what the SET goes out with
PAD = "00" * 7                                                         # the seven zero bytes behind the first one of a PortList

# Messages, written out by hand.
TIMEOUT = "Zeitüberschreitung bei der SNMP-Abfrage"                    # snmp._run's timeout
SSH_DOWN = "NetmikoTimeoutException: TCP connection to device failed."
DRIFT = "Der Switch hat sich seit der Vorschau geändert. Bitte Vorschau neu laden."
AUTOSAVED = "Gespeichert (der Switch speichert SNMP-Änderungen selbst)"
UNSAVED = "Änderung ist aktiv, aber NICHT dauerhaft gespeichert – am Switch speichern (z. B. write memory / copy running-config startup-config)"
MISMATCH = "Prüfung nach der Änderung passt nicht: "
# Behind every step that ends a run unclear: what the switch may already have taken is in effect, and saved or not (R26).
SAVED_NOTE = "Was der Switch davon übernommen hat, wirkt schon und ist gespeichert (er speichert SNMP-Änderungen selbst)."
UNSAVED_NOTE = "Was der Switch davon übernommen hat, wirkt schon, ist aber nicht dauerhaft gespeichert."
CANCELLED = "Abgebrochen (Prozess beendet)"
NOTHING = "Nichts zu ändern"
WRITE_DISABLED = "SNMP-Schreiben ist für diesen Switch nicht aktiviert"
NO_WRITE_CREDS = "Keine SNMP-Schreib-Zugangsdaten hinterlegt"
R12_PORT2 = ("PVID 1 weicht vom ungetaggten VLAN 99 ab (Fehlkonfiguration oder dynamisch per 802.1X/RADIUS zugewiesen) – per SNMP nicht "
             "verwaltbar")
HYBRID_1_20 = "ungetaggt in mehreren VLANs (1, 20): Hybrid-/General-Port, per SNMP nicht verwaltbar"


def setting(n: int) -> str:
    return f"Setze {n} {'Wert' if n == 1 else 'Werte'} per SNMP (ein SET)"


READ_STEPS = [(f"Lese {HOST} per SNMP", "info"), ("Zustand vorher gelesen", "info")]

# What the SNMP read sees per driver (walk rows as the simulated agent holds them):
#   procurve  the sample ProCurve (switchfix.W_SAMPLE): ports 1-6, Trk1 = 4 + 5. Port 1 = bridge port 3, untagged 20 + tagged 30,
#             "Platz-107"; port 2 = bp 1, untagged 99, PVID 99; port 3 = bp 2, tagged 20 + 30, no untagged VLAN, PVID 1.
#             First bytes of its 8-byte PortLists: egress 1: 0A, 20: 62, 30: 62, 99: 82; untagged 1: 0A, 20: 20, 30: 00, 99: 80.
#   cisco     the Catalyst with vmVlan rows: Gi1/0/2 (ifIndex 10102) an access port in VLAN 1 (vmVlan), Q-BRIDGE PVID 1.
#   generic   the Catalyst over Q-BRIDGE: Gi1/0/2 (bridge port 2) untagged 1 + tagged 20, PVID 1.
VIEWS = {"procurve": agent(W_SAMPLE), "cisco": agent({**W_CATALYST, "vmVlan": CATALYST_VMVLAN}), "generic": agent(W_CATALYST)}
SAMPLE_BY_IFTYPE = agent({**W_SAMPLE, "ifType": IFTYPE_SAMPLE})    # the sample switch for a driver that selects its ports by ifType
# read_cfg: nine walks, + ifType when by ifType, + vmVlan on cisco; no PoE walk, none of these changes touches PoE (R34)
WALKS_PER_READ = {"procurve": 9, "cisco": 11, "generic": 10}
BY_OID = {base: key for key, base in WALK_BASES.items()}

PC_PROBE = {"ports": ["2"], "change": {"untagged": "20"}}
GI_PROBE = {"ports": ["Gi1/0/2"], "change": {"untagged": "10"}}

PROCURVE, GENERIC = drivers.DRIVERS["procurve"], drivers.DRIVERS["generic"]
# R26: the cap snmp_autosave, nothing else, decides. A CLI driver without it, and an SNMP-only driver with it.
CLI_UNSAVED = Driver("cli_unsaved", PROCURVE.caps - {"snmp_autosave"}, "qbridge", dict(PROCURVE.oids), "")
AUTOSAVE_ONLY = Driver("autosave_only", GENERIC.caps | {"snmp_autosave"}, "qbridge", dict(GENERIC.oids), "")

# The ProCurve's running-config as the SSH path reads it: the very switch W_SAMPLE describes over SNMP (port 2 untagged 99, ...).
# SSH_AFTER is the same switch after "vlan 20 untagged 2".
SSH_CONFIG = """\
Running configuration:

; J9729A Configuration Editor; Created on release #WB.16.99.0001
hostname "SW-EK-01"
trunk 4-5 Trk1 LACP
vlan 1
   name "DEFAULT_VLAN"
   untagged 6,Trk1
   no untagged 1-3
   exit
vlan 20
   name "Clients"
   untagged 1
   tagged 3,Trk1
   exit
vlan 30
   name "Voice"
   tagged 1,3,Trk1
   exit
vlan 99
   name "Guest"
   untagged 2
   tagged Trk1
   exit
interface 1
   name "Platz-107"
   exit
interface 6
   disable
   name "unused"
   exit
"""
SSH_AFTER = SSH_CONFIG.replace("   untagged 1\n   tagged 3,Trk1", "   untagged 1-2\n   tagged 3,Trk1").replace("   untagged 2\n", "")

# The originals of what the SSH fakes wrap, taken before any test patches them.
REAL = {"disconnect": sshcli.disconnect, "store_backup": sshcli.store_backup, "store_cfg": changes.store_cfg}


def pl(first: str) -> str:
    """A PortList row as the agent holds it (8 bytes, spaced hex): the first byte given, the other seven 00."""
    return first + " 00" * 7


def read(W: dict, driver_name: str) -> tuple[dict, dict]:
    """The switch as read_cfg would read it from rows W, without the walks."""
    return snmpwrite.build_cfg(W, driver_name, vmvlan_base=VMVLAN if "vmVlan" in W else None, text_hex=True)


def inv_of(cfg: dict) -> dict:
    """changes.inventory() of the switch read as cfg, as far as plan_ports looks at it: every port, tr = the trunk of a member or the
    trunk's own name, no LLDP neighbour, no link, no uplinks."""
    member_of = {m: t for t, members in cfg["trunks"].items() for m in members}
    return {"ports": {n: {"n": n, "tr": n if n in cfg["trunks"] else member_of.get(n, ""), "l": [], "o": False} for n in cfg["ports"]},
            "uplinks": set()}


class Agent:
    """The switch behind SNMP: snmp.walk answers from its rows W (switchfix.agent format), snmp.set_vars goes through switchfix.store.
    Records every walk (OID, cred), every SET (host, cred, varbinds) and whether the switch's change lock was held at each of them.
    A walk of anything its rows do not have fails the test, a PoE walk too (these changes do not touch PoE, R34). Knobs: set_mode
    "apply" (default), "ignore" (answers, takes nothing), "lost" (takes it, the answer never comes: SnmpError), "timeout" (takes
    nothing, no answer); drop: OIDs, or base OIDs, whose varbinds it silently ignores (a partly applied SET);
    after_set: W -> W, what else changes on the switch right after the SET; read_error / readback_error: what every walk raises
    before / after the first SET; on_set: a coroutine function awaited as the SET arrives; set_raises: what the SET raises then,
    before taking anything."""

    def __init__(self, W: dict, sid: int):
        self.W, self.sid = W, sid
        self.walks: list[tuple[str, dict]] = []
        self.sets: list[tuple[str, dict, list]] = []
        self.locked: list[bool] = []
        self.set_mode, self.drop, self.after_set = "apply", set(), None
        self.read_error: BaseException | None = None
        self.readback_error: BaseException | None = None
        self.on_set = None
        self.set_raises: BaseException | None = None

    async def walk(self, host, cred, oid, hex_values=False, timeout=60, strict=False):
        assert (host, strict) == (HOST, True), (host, strict)
        self.walks.append((oid, cred))
        self.locked.append(sshcli.lock(self.sid).locked())
        error = self.readback_error if self.sets else self.read_error
        if error:
            raise error
        assert BY_OID[oid] in self.W, f"walk of {BY_OID[oid]}, which this switch does not answer"
        return list(self.W[BY_OID[oid]])

    async def set_vars(self, host, cred, varbinds, timeout=20):
        self.sets.append((host, cred, list(varbinds)))
        self.locked.append(sshcli.lock(self.sid).locked())
        if self.on_set:
            await self.on_set()
        if self.set_raises:
            raise self.set_raises
        if self.set_mode in ("apply", "lost"):
            self.W = store(self.W, [vb for vb in varbinds if vb[0] not in self.drop and vb[0].rpartition(".")[0] not in self.drop])
            if self.after_set:
                self.W = self.after_set(self.W)
        if self.set_mode in ("lost", "timeout"):
            raise snmp.SnmpError(TIMEOUT)
        return "".join(f".{oid} = {typ}: {value}\n" for oid, typ, value in varbinds)


class FakeSSH:
    """The netmiko connection to the ProCurve of SSH_CONFIG: show running-config answers with env.ssh_config, a config set turns it
    into SSH_AFTER; every call lands in env.ssh. env.ssh_fails == "read": the first command fails (the session dropped)."""

    def __init__(self, env):
        self.env = env

    def send_command(self, cmd, read_timeout=None):
        self.env.ssh.append(("send_command", cmd))
        if self.env.ssh_fails == "read":
            raise OSError("Socket is closed")
        return self.env.ssh_config

    def send_config_set(self, cmds, **kwargs):
        self.env.ssh.append(("send_config_set", list(cmds)))
        self.env.ssh_config = SSH_AFTER
        return "SW-EK-01(config)# vlan 20 untagged 2"

    def save_config(self):
        self.env.ssh.append(("save_config",))

    def disconnect(self):
        self.env.ssh.append(("disconnect",))


class Env:
    """One test's world: a fresh database, the switch behind SNMP (agent, set by switch()), the poll (inv), every SSH-side call (ssh)
    and every re-poll run_change schedules (repolls)."""

    def __init__(self, monkeypatch):
        self.mp = monkeypatch
        self.agent: Agent | None = None
        self.inv: dict | None = None
        self.ssh: list[tuple] = []
        self.repolls: list[int] = []
        self.ssh_fails: str | None = None       # with allow_ssh: "connect" or "read" fails, backup_config reports a failure
        self.ssh_config = SSH_CONFIG

    async def switch(self, driver: str, W: dict | None = None, *, ssh: bool = False, snmp_write: bool = True) -> int:
        """A switches row (read community READ, RW community RW, SSH access if ssh), and the agent behind it holding W (default: the
        driver's view)."""
        cols = {"name": "SW-EK-01", "host": HOST, "driver": driver, "snmp_write": int(snmp_write), "snmp_version": "2c",
                "snmp_community": crypto.encrypt(READ), "snmp_rw_community": crypto.encrypt(RW), "sys_name": "SW-EK-01", "firmware": FW}
        if ssh:
            cols |= {"ssh_user": "manager", "ssh_pass": crypto.encrypt("ssh-s3cret")}
        async with db.db() as conn:
            cur = await conn.execute(f"INSERT INTO switches ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                                     tuple(cols.values()))
            await conn.commit()
            sid = cur.lastrowid
        W = W if W is not None else VIEWS[driver]
        self.agent = Agent(W, sid)
        self.inv = inv_of(read(W, driver)[0])
        return sid

    def allow_ssh(self):
        """Replace the SSH traps by fakes: connect gives a FakeSSH (or fails, ssh_fails == "connect"), backups and switch_cfg writes
        are the real ones, recorded; backup_config (the read of fresh_cfg) stores ssh_config, or reports SSH_DOWN when ssh_fails."""
        env = self

        def connect(row):
            env.ssh.append(("connect", row["id"]))
            if env.ssh_fails == "connect":
                raise NetmikoTimeoutException("TCP connection to device failed.")
            return FakeSSH(env)

        async def store_backup(sid, content, trigger):
            env.ssh.append(("store_backup", trigger))
            return await REAL["store_backup"](sid, content, trigger)

        async def store_cfg(sid, content):
            env.ssh.append(("store_cfg", sid))
            return await REAL["store_cfg"](sid, content)

        async def backup_config(sid, trigger="nightly"):
            env.ssh.append(("backup_config", sid))
            if env.ssh_fails:
                return {"ok": False, "error": SSH_DOWN}
            await changes.store_cfg(sid, env.ssh_config)
            return {"ok": True, "changed": False}

        for mod, name, fake in ((sshcli, "connect", connect), (sshcli, "disconnect", REAL["disconnect"]),
                                (sshcli, "store_backup", store_backup), (changes, "store_cfg", store_cfg),
                                (sshcli, "backup_config", backup_config)):
            self.mp.setattr(mod, name, fake)


@pytest.fixture
async def env(tmp_path, monkeypatch) -> Env:
    """A fresh database under tmp_path (db.init_db: schema + migration); snmp.walk / snmp.set_vars answered by the test's agent;
    changes.inventory = the agent's ports; re-polls recorded, never run; fresh change locks and R27 marks; every SSH entry point a
    trap that records and raises."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    await db.init_db()
    e = Env(monkeypatch)

    async def walk(*args, **kwargs):
        assert e.agent, "SNMP walk without a switch behind it"
        return await e.agent.walk(*args, **kwargs)

    async def set_vars(*args, **kwargs):
        assert e.agent, "SNMP SET without a switch behind it"
        return await e.agent.set_vars(*args, **kwargs)

    async def inventory(sid):
        return e.inv

    def repoll(sid):
        e.repolls.append(sid)     # recorded on the call; the task it becomes has nothing left to do

        async def nothing():
            return None
        return nothing()

    def trap(name: str, is_async: bool):
        def sync(*args, **kwargs):
            e.ssh.append((name,))
            raise AssertionError(f"{name} on the SNMP path")

        async def coro(*args, **kwargs):
            sync()
        return coro if is_async else sync

    monkeypatch.setattr(snmp, "walk", walk)
    monkeypatch.setattr(snmp, "set_vars", set_vars)
    monkeypatch.setattr(changes, "inventory", inventory)
    monkeypatch.setattr(changes, "_repoll", repoll)
    monkeypatch.setattr(changes, "_cfg_stale", set())
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    for mod, name, is_async in ((sshcli, "connect", False), (sshcli, "disconnect", False), (sshcli, "run_shows", True),
                                (sshcli, "backup_config", True), (sshcli, "store_backup", True), (changes, "store_cfg", True)):
        monkeypatch.setattr(mod, name, trap(name, is_async))
    return e


async def sql(query: str, args: tuple = ()) -> list[tuple]:
    async with db.db() as conn:
        async with conn.execute(query, args) as cur:
            rows = [tuple(r) for r in await cur.fetchall()]
        await conn.commit()
    return rows


async def switch_row(sid: int):
    async with db.db() as conn:
        async with conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)) as cur:
            return await cur.fetchone()


async def change(cid: int) -> dict:
    """The changes row, its JSON columns decoded."""
    async with db.db() as conn:
        async with conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)) as cur:
            ch = dict(await cur.fetchone())
    for k in ("request", "ports", "desired", "before", "commands", "steps"):
        ch[k] = json.loads(ch[k]) if ch[k] else ch[k]
    return ch


def steps(ch: dict) -> list[tuple[str, str]]:
    return [(text, level) for _, text, level in ch["steps"]]


async def apply(sid: int, payload: dict) -> tuple[int, dict]:
    """What POST /apply does once the preview's token matches: plan with main._make_plan (preview and apply plan the same way) and
    create the change from it. The run is up to the test."""
    plan, req, kind, summary = await main._make_plan(await switch_row(sid), main.PlanIn(**payload))
    assert plan["blocked"] == [] and plan["shown"], plan
    revert_of = payload["of"] if payload.get("mode") == "revert" else None
    return await changes.create_change(sid, USER, kind, summary, req, plan, revert_of=revert_of), plan


async def run(env: Env, cid: int) -> dict:
    """run_change(cid) to its end; the changes row afterwards."""
    await changes.run_change(cid)
    await asyncio.sleep(0)
    return await change(cid)


async def audit_rows() -> list[tuple]:
    return await sql("SELECT action, target, detail FROM audit ORDER BY id")


async def ssh_change(env: Env, sid: int, mechanism: str | None = "ssh") -> int:
    """An SSH change as /apply creates one ("vlan 20 untagged 2", planned against SSH_CONFIG); mechanism None or another value is
    written into the row afterwards (None: a row from before the column)."""
    req = {"ports": ["2"], "set": {"untagged": "20"}, "expert": False}
    plan = changes.plan_ports(FW, env.inv, cfgparse.parse_config(SSH_CONFIG), req)
    assert (plan["shown"], plan["mechanism"]) == (["vlan 20 untagged 2"], "ssh")
    cid = await changes.create_change(sid, USER, "ports", "Port 2: VLAN 20", req, plan)
    if mechanism != "ssh":
        await sql("UPDATE changes SET mechanism = ? WHERE id = ?", (mechanism, cid))
    return cid


async def put_cfg(sid: int):
    """A young switch_cfg entry (the cache of fresh_cfg) with SSH_CONFIG, as a preview over SSH leaves it."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    await sql("INSERT INTO switch_cfg(switch_id, taken_at, parsed) VALUES (?,?,?)", (sid, now, json.dumps(cfgparse.parse_config(SSH_CONFIG))))


# ── create_change: the mechanism of the preview ───────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("mechanism", ["snmp", "ssh", None])
async def test_create_change_persists_the_mechanism(env, mechanism):
    """plan["mechanism"] goes into changes.mechanism; a plan without one leaves NULL (= ssh). Every other column as before."""
    sid = await env.switch("procurve")
    plan = {"desired": {"2": {"u": "20"}}, "before": {"2": {"u": "99"}}, "shown": ["vlan 20 untagged 2"], "blocked": [], "expert": True}
    if mechanism:
        plan["mechanism"] = mechanism
    cid = await changes.create_change(sid, USER, "ports", "Port 2: VLAN 20", {"ports": ["2"]}, plan, revert_of=4)
    ch = await change(cid)
    assert {k: ch[k] for k in ("switch_id", "username", "kind", "summary", "request", "ports", "desired", "before", "commands", "status",
                               "saved", "steps", "expert", "revert_of", "mechanism")} == {
        "switch_id": sid, "username": USER, "kind": "ports", "summary": "Port 2: VLAN 20", "request": {"ports": ["2"]}, "ports": ["2"],
        "desired": {"2": {"u": "20"}}, "before": {"2": {"u": "99"}}, "commands": ["vlan 20 untagged 2"], "status": "queued", "saved": 0,
        "steps": [], "expert": 1, "revert_of": 4, "mechanism": mechanism}


# ── The SNMP safety loop: ok ──────────────────────────────────────────────────────────────────────────────────────────────────────
# driver -> (request, shown, varbinds of the SET, saved)
OK_CASES = {
    "procurve": (PC_PROBE, ["Port 2: VLAN ungetaggt 99 → 20"], 5, 1),       # Egress + Untagged of 20 and 99, PVID
    "cisco": (GI_PROBE, ["Port Gi1/0/2: Access-VLAN 1 → 10"], 1, 0),       # vmVlan only (R20)
    "generic": (GI_PROBE, ["Port Gi1/0/2: VLAN ungetaggt 1 → 10"], 5, 0),
}


@pytest.mark.parametrize("driver", list(OK_CASES))
async def test_snmp_change_ok(env, driver):
    """Live read and read-back with the READ identity, ONE SET with the write identity carrying exactly the planned varbinds, all inside
    the switch's change lock; verify passes -> ok. ProCurve (snmp_autosave) saved=1; cisco / generic saved=0 plus the R26 warning. The
    cisco access port is verified through vmVlan; its Q-BRIDGE PVID (still 1) does not count."""
    payload, shown, n, saved = OK_CASES[driver]
    sid = await env.switch(driver)
    cid, plan = await apply(sid, payload)
    assert (plan["mechanism"], plan["shown"], len(plan["ops"])) == ("snmp", shown, n)
    env.agent.walks.clear()
    ch = await run(env, cid)
    assert (ch["status"], ch["saved"], ch["error"], ch["mechanism"]) == ("ok", saved, None, "snmp")
    assert steps(ch) == [*READ_STEPS, (setting(n), "info"), ("Zustand nachher gelesen", "info"), ("Prüfung ok", "info"),
                         (AUTOSAVED, "ok") if saved else (UNSAVED, "warn")]
    assert env.agent.sets == [(HOST, RW_CRED, plan["ops"])]
    assert [cred for _, cred in env.agent.walks] == [READ_CRED] * (2 * WALKS_PER_READ[driver])    # read before, read back
    assert env.agent.locked and all(env.agent.locked)
    port, vlan = payload["ports"][0], payload["change"]["untagged"]
    cfg, raw = read(env.agent.W, driver)
    assert cfg["ports"][port]["u"] == vlan
    assert ch["before"] == plan["before"] and ch["output"] == "".join(f".{o} = {t}: {v}\n" for o, t, v in plan["ops"])
    assert await audit_rows() == [("change_ok", str(sid), f"#{cid} {ch['summary']}, mechanism: snmp")]
    assert env.repolls == [sid]
    assert env.ssh == []


@pytest.mark.parametrize("drv, W, payload, saved", [
    (CLI_UNSAVED, SAMPLE_BY_IFTYPE, PC_PROBE, 0),         # has cli (like ProCurve), lacks snmp_autosave
    (AUTOSAVE_ONLY, VIEWS["generic"], GI_PROBE, 1),       # no cli, has snmp_autosave
])
async def test_snmp_saved_follows_the_autosave_cap(env, drv, W, payload, saved):
    """R26: saved=1 exactly for a driver with snmp_autosave; neither cli nor the driver's name decides."""
    env.mp.setitem(drivers.DRIVERS, drv.name, drv)
    sid = await env.switch(drv.name, W)
    cid, _ = await apply(sid, payload)
    ch = await run(env, cid)
    assert (ch["status"], ch["saved"], steps(ch)[-1]) == ("ok", saved, (AUTOSAVED, "ok") if saved else (UNSAVED, "warn"))
    assert env.ssh == []


async def test_snmp_change_waits_for_the_switch_lock(env):
    """The same lock as the SSH path, so changes on one switch run one after the other: while another action holds sshcli.lock(sid),
    the SNMP change only says that it waits, and reads and writes nothing."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.walks.clear()
    lock = sshcli.lock(sid)
    await lock.acquire()
    task = asyncio.create_task(changes.run_change(cid))
    try:
        for _ in range(300):
            if (await change(cid))["steps"]:
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        ch = await change(cid)
        assert (ch["status"], steps(ch)) == ("queued", [("Warte auf laufende Aktion an diesem Switch", "info")])
        assert env.agent.walks == [] and env.agent.sets == []
    finally:
        lock.release()
    await task
    assert (await change(cid))["status"] == "ok"


# ── Verify: a read-back that does not show the change ─────────────────────────────────────────────────────────────────────────────
async def test_snmp_verify_mismatch_unclear(env):
    """The switch answers the SET but takes nothing: the read-back still shows port 2 in VLAN 99 with PVID 99 -> unclear, with what
    differs. saved stays 0 (but on an autosaving switch anything it did take is saved: the step says so)."""
    sid = await env.switch("procurve")
    cid, plan = await apply(sid, PC_PROBE)
    env.agent.set_mode = "ignore"
    ch = await run(env, cid)
    error = MISMATCH + "Port 2: u ist '99', erwartet '20'; Port 2: pvid ist '99', erwartet '20'"
    assert (ch["status"], ch["saved"], ch["error"]) == ("unclear", 0, error)
    assert steps(ch) == [*READ_STEPS, (setting(5), "info"), ("Zustand nachher gelesen", "info"), (f"{error}. {SAVED_NOTE}", "error")]
    assert len(env.agent.sets) == 1 and ch["before"] == plan["before"]
    assert await audit_rows() == [("change_unclear", str(sid), f"#{cid} Port 2: VLAN 20, mechanism: snmp")]
    assert env.repolls == [sid] and env.ssh == []


async def test_snmp_verify_mismatch_on_a_driver_without_autosave(env):
    sid = await env.switch("generic")
    cid, _ = await apply(sid, GI_PROBE)
    env.agent.set_mode = "ignore"
    ch = await run(env, cid)
    error = MISMATCH + "Port Gi1/0/2: u ist '1', erwartet '10'; Port Gi1/0/2: pvid ist '1', erwartet '10'"
    assert (ch["status"], ch["saved"], ch["error"], steps(ch)[-1]) == ("unclear", 0, error, (f"{error}. {UNSAVED_NOTE}", "error"))


async def forward_port3(env: Env) -> tuple[int, int]:
    """The forward change the revert tests take back, over SNMP on the sample ProCurve: port 3 (bridge port 2, tagged 20 + 30, no
    untagged VLAN, PVID 1) gets untagged 99. Its `before` keeps the PVID (R21). Returns (switch id, change id)."""
    sid = await env.switch("procurve")
    cid, plan = await apply(sid, {"ports": ["3"], "change": {"untagged": "99"}})
    assert (plan["shown"], plan["before"]) == (["Port 3: VLAN ungetaggt – → 99"], {"3": {"u": None, "pvid": "1"}})
    ch = await run(env, cid)
    assert (ch["status"], ch["before"]) == ("ok", {"3": {"u": None, "pvid": "1"}})
    assert env.agent.sets == [(HOST, RW_CRED, [(f"{VLAN_EGRESS}.99", "x", "C2" + PAD), (f"{VLAN_UNTAGGED}.99", "x", "C0" + PAD),
                                               (f"{PVID}.2", "u", "99")])]
    assert read(env.agent.W, "procurve")[1]["pvid"]["3"] == "99"
    env.agent.sets.clear()
    return sid, cid


async def test_revert_of_an_snmp_change_runs_snmp_and_restores_the_pvid(env):
    """R21 end to end: the revert is planned over SNMP (the original's mechanism) with desired = before, so it writes the PVID 1 back
    explicitly (u -> None alone would leave PVID 99, the VLAN the port just left); the run verifies it and the switch is byte for
    byte what it was before the forward change."""
    sid, cid = await forward_port3(env)
    rid, plan = await apply(sid, {"mode": "revert", "of": cid})
    assert (plan["mechanism"], plan["shown"], plan["desired"]) == ("snmp", ["Port 3: VLAN ungetaggt 99 → –", "Port 3: PVID 99 → 1"],
                                                                   {"3": {"u": None, "pvid": "1"}})
    ch = await run(env, rid)
    assert (ch["status"], ch["saved"], ch["error"], ch["mechanism"], ch["revert_of"]) == ("ok", 1, None, "snmp", cid)
    assert env.agent.sets == [(HOST, RW_CRED, [(f"{VLAN_EGRESS}.99", "x", "82" + PAD), (f"{VLAN_UNTAGGED}.99", "x", "80" + PAD),
                                               (f"{PVID}.2", "u", "1")])]
    assert ch["before"] == {"3": {"u": "99", "pvid": "99"}}       # the revert can itself be taken back
    assert env.agent.W == VIEWS["procurve"]
    assert env.ssh == []


async def test_snmp_before_comes_from_the_live_read(env):
    """`before` is taken from the read in the run, not from the preview (as on the SSH path): port 3's PVID changed from 1 to 30
    after the preview. shown does not carry the PVID of a u change, so the token still matches and the change runs; its `before` keeps
    PVID 30, the value a revert has to restore."""
    sid = await env.switch("procurve")
    cid, plan = await apply(sid, {"ports": ["3"], "change": {"untagged": "99"}})
    assert plan["before"] == {"3": {"u": None, "pvid": "1"}}
    env.agent.W = edit_walks(env.agent.W, pvid={"2": "30"})
    ch = await run(env, cid)
    assert (ch["status"], ch["before"]) == ("ok", {"3": {"u": None, "pvid": "30"}})


async def test_snmp_explicit_pvid_mismatch_unclear(env):
    """The revert's PortLists arrive, its PVID does not: port 3 has no untagged VLAN any more (so it is not unmanaged), but PVID 99
    instead of 1 -> unclear. Only the PVID check sees this."""
    sid, cid = await forward_port3(env)
    rid, _ = await apply(sid, {"mode": "revert", "of": cid})
    env.agent.drop = {PVID}
    ch = await run(env, rid)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 3: pvid ist '99', erwartet '1'")


async def test_snmp_implicit_pvid_checked_when_u_changes(env):
    """u changes to a VLAN: the expected PVID is that VLAN. Bridge port 2 has no PVID row and the agent drops the PVID varbind, so the
    read-back finds port 3 untagged in 99 (not unmanaged: R12 needs a PVID row) without a PVID -> unclear."""
    sid = await env.switch("procurve", edit_walks(VIEWS["procurve"], pvid={"2": None}))
    cid, plan = await apply(sid, {"ports": ["3"], "change": {"untagged": "99"}})
    assert plan["before"] == {"3": {"u": None}}                   # no PVID to capture
    env.agent.drop = {PVID}
    ch = await run(env, cid)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 3: pvid ist None, erwartet '99'")


async def test_snmp_written_port_unmanaged_afterwards_unclear(env):
    """Right after the revert's SET port 3 turns up untagged in VLAN 1 and 20 (a hybrid port, unmanaged). Its u None in cfg is only a
    placeholder, which matches the revert's u None, and the PVID is 1 as wanted: the unmanaged port alone is the mismatch."""
    sid, cid = await forward_port3(env)
    rid, _ = await apply(sid, {"mode": "revert", "of": cid})
    env.agent.after_set = lambda W: edit_walks(W, vlanEgress={"1": pl("4A")}, vlanUntagged={"1": pl("4A"), "20": pl("60")})
    ch = await run(env, rid)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + f"Port 3: nach der Änderung {HYBRID_1_20}")


async def test_snmp_written_port_missing_afterwards_unclear(env):
    """Port 1's name is cleared, and right after the SET the switch no longer lists port 1 (its ifName row is gone). cfgparse.port_state
    would fill in the defaults, name "" among them, which is the target: the missing port alone is the mismatch."""
    sid = await env.switch("procurve")
    cid, plan = await apply(sid, {"ports": ["1"], "change": {"name": ""}})
    assert (plan["shown"], plan["ops"]) == (['Port 1: Name "Platz-107" → ""'], [(f"{IF_ALIAS}.1", "x", "")])
    env.agent.after_set = lambda W: edit_walks(W, ifName={"1": None})
    ch = await run(env, cid)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 1: beim Zurücklesen nicht gefunden")


def move_bridge_port(W: dict, old: int, new: int) -> dict:
    """W with bridge port `old` renumbered to `new`: its bp2if and PVID rows and its bit in every PortList move along (8-byte lists)."""
    def moved(value: str) -> str:
        bits = bytearray(bytes.fromhex(value.replace(" ", "")))
        if bits[(old - 1) // 8] & (0x80 >> (old - 1) % 8):
            bits[(old - 1) // 8] &= 0xFF ^ (0x80 >> (old - 1) % 8)
            bits[(new - 1) // 8] |= 0x80 >> (new - 1) % 8
        return " ".join(f"{b:02X}" for b in bits)
    bp2if, pvid = dict(edit_walks(W)["bp2if"]), dict(W["pvid"])
    return edit_walks(W, bp2if={str(old): None, str(new): bp2if[f"{WALK_BASES['bp2if']}.{old}"]},
                      pvid={str(old): None, str(new): pvid[f"{PVID}.{old}"]},
                      vlanEgress={v.rpartition(".")[2]: moved(x) for v, x in W["vlanEgress"]},
                      vlanUntagged={v.rpartition(".")[2]: moved(x) for v, x in W["vlanUntagged"]})


async def test_snmp_verify_finds_a_port_on_another_ifindex_unclear(env):
    """M4: right after the SET the switch renumbers its interfaces (a module swap, say): port 2 now sits on ifIndex 7. The read-back
    finds it by name, switched off as wanted, but the SET went to ifAdminStatus.2, which may now be another interface: unclear."""
    sid = await env.switch("procurve")
    cid, plan = await apply(sid, {"ports": ["2"], "change": {"status": "off"}})
    assert plan["ops"] == [("1.3.6.1.2.1.2.2.1.7.2", "i", "2")]
    env.agent.after_set = lambda W: edit_walks(W, ifName={"2": None, "7": "2"}, ifAlias={"2": None, "7": ""}, ifAdmin={"2": None, "7": "2"},
                                               bp2if={"1": "7"}, ifStack={"0.2": None, "2.0": None, "0.7": "1", "7.0": "1"})
    ch = await run(env, cid)
    assert read(env.agent.W, "procurve")[0]["ports"]["2"]["en"] is False
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 2: Interface-Nummer hat sich geändert")


async def test_snmp_verify_finds_a_port_on_another_bridge_port_unclear(env):
    """M4: port 2 moves 99 -> 20 through its bridge port 1, and right after the SET the switch renumbers that bridge port to 8, bits and
    PVID included. The read-back shows port 2 untagged in 20 with PVID 20 and its Egress bit, all as wanted, but the bits were written
    for bridge port 1: unclear."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.after_set = lambda W: move_bridge_port(W, 1, 8)
    ch = await run(env, cid)
    cfg, raw = read(env.agent.W, "procurve")
    assert (cfg["ports"]["2"]["u"], raw["pvid"]["2"], raw["port2bp"]["2"]) == ("20", "20", 8)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 2: Interface-Nummer hat sich geändert")


# R32: a VLAN move is several varbinds (Egress and Untagged of the old and the new VLAN, the PVID); the verify checks the port's whole
# VLAN membership, not only the field the request named. Port 2 (bridge port 1) moves 99 -> 20; its varbinds: Egress 20 (E2), Egress 99
# (02), Untagged 20 (A0), Untagged 99 (00), PVID 20.
@pytest.mark.parametrize("dropped, bad", [
    pytest.param({VLAN_EGRESS}, "Port 2: t ist ['99'], erwartet []; Port 2: VLAN 20 ungetaggt, aber ohne Egress-Bit", id="both-egress"),
    pytest.param({f"{VLAN_EGRESS}.99"}, "Port 2: t ist ['99'], erwartet []", id="old-egress"),
    pytest.param({f"{VLAN_EGRESS}.20"}, "Port 2: VLAN 20 ungetaggt, aber ohne Egress-Bit", id="new-egress"),
])
async def test_snmp_verify_checks_the_whole_vlan_membership(env, dropped, bad):
    """The switch takes the move only in part. Old Egress bit left: port 2 reads as untagged 20 AND tagged 99 - right u, right PVID,
    but t must stay []. New Egress bit missing: cfg cannot show it (u comes from the Untagged list), yet the port would not send VLAN 20
    out; the read-back's Egress list must have it. Each is unclear, never ok."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.drop = dropped
    ch = await run(env, cid)
    assert (ch["status"], ch["saved"], ch["error"]) == ("unclear", 0, MISMATCH + bad)


async def test_snmp_revert_to_no_untagged_vlan_verifies_t(env):
    """The revert takes port 3 back to no untagged VLAN (u None): its tagged VLANs 20 and 30 are part of what must be true afterwards.
    The Egress bit of 99 stays (dropped), so port 3 would keep 99 as a tagged VLAN -> unclear."""
    sid, cid = await forward_port3(env)
    rid, _ = await apply(sid, {"mode": "revert", "of": cid})
    env.agent.drop = {f"{VLAN_EGRESS}.99"}
    ch = await run(env, rid)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 3: t ist ['20', '30', '99'], erwartet ['20', '30']")


async def test_snmp_tagged_change_verifies_u_too(env):
    """Only t changes (port 1: tagged 30 -> 30, 99), but right after the SET port 1 is no longer in VLAN 20 at all: its t is what was
    asked for, its u (20 before, untouched by the change) is gone -> unclear."""
    sid = await env.switch("procurve")
    cid, plan = await apply(sid, {"ports": ["1"], "change": {"tagged_add": ["99"]}})
    assert (plan["shown"], plan["ops"]) == (["Port 1: VLAN getaggt 30 → 30, 99"], [(f"{VLAN_EGRESS}.99", "x", "A2" + PAD)])
    env.agent.after_set = lambda W: edit_walks(W, vlanEgress={"20": pl("42")}, vlanUntagged={"20": pl("00")})
    ch = await run(env, cid)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 1: u ist None, erwartet '20'")


# ── Drift since the preview: aborted, nothing written ─────────────────────────────────────────────────────────────────────────────
async def test_snmp_preview_drift_aborted(env):
    """Between preview and run someone moved port 2 from VLAN 99 to VLAN 1: the fresh plan's line reads "1 → 20", not the previewed
    "99 → 20" -> aborted, no SET, `before` stays the preview's, no re-poll."""
    sid = await env.switch("procurve")
    cid, plan = await apply(sid, PC_PROBE)
    env.agent.W = edit_walks(env.agent.W, vlanEgress={"1": pl("8A"), "99": pl("02")}, vlanUntagged={"1": pl("8A"), "99": pl("00")},
                             pvid={"1": "1"})
    ch = await run(env, cid)
    assert (ch["status"], ch["error"], ch["saved"]) == ("aborted", DRIFT, 0)
    assert steps(ch) == [*READ_STEPS, (DRIFT, "error")]
    assert env.agent.sets == [] and ch["before"] == plan["before"]
    assert await audit_rows() == [("change_aborted", str(sid), f"#{cid} Port 2: VLAN 20, mechanism: snmp")]
    assert env.repolls == [] and env.ssh == []


async def test_snmp_drift_into_a_blocked_port_aborted(env):
    """Since the preview port 2's PVID became 1 next to its untagged VLAN 99 (R12): the fresh plan blocks it -> aborted with the reason,
    no SET."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.W = edit_walks(env.agent.W, pvid={"1": "1"})
    ch = await run(env, cid)
    assert (ch["status"], ch["error"]) == ("aborted", f"2: {R12_PORT2}")
    assert steps(ch) == [*READ_STEPS, (f"Abgebrochen: 2: {R12_PORT2}", "error")]
    assert env.agent.sets == [] and env.repolls == []


# ── SNMP errors around the SET ────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_snmp_set_error_then_readback_ok(env):
    """The switch takes the SET but its answer is lost (timeout): outcome unknown, not "failed". The read-back shows the change -> ok."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.set_mode = "lost"
    ch = await run(env, cid)
    assert (ch["status"], ch["saved"], ch["error"], ch["output"]) == ("ok", 1, None, TIMEOUT)
    assert steps(ch) == [*READ_STEPS, (setting(5), "info"),
                         (f"SET nicht bestätigt ({TIMEOUT}): ob der Switch die Werte übernommen hat, zeigt das Zurücklesen", "error"),
                         ("Zustand nachher gelesen", "info"), ("Prüfung ok", "info"), (AUTOSAVED, "ok")]
    assert len(env.agent.sets) == 1                                # never sent twice


async def test_snmp_set_error_then_readback_bad(env):
    """No answer and nothing taken: the read-back shows the old state -> unclear (the outcome was unknown until the read-back)."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.set_mode = "timeout"
    ch = await run(env, cid)
    assert (ch["status"], ch["error"]) == ("unclear", MISMATCH + "Port 2: u ist '99', erwartet '20'; Port 2: pvid ist '99', erwartet '20'")
    assert len(env.agent.sets) == 1 and env.repolls == [sid]


@pytest.mark.parametrize("error, text", [
    (snmp.SnmpError(TIMEOUT), TIMEOUT),
    (FileNotFoundError(2, "No such file or directory", "snmpbulkwalk"), "[Errno 2] No such file or directory: 'snmpbulkwalk'"),
])
async def test_snmp_preread_failure_failed(env, error, text):
    """The live read before anything is written fails: "failed" with the reason, no SET, `before` stays the preview's."""
    sid = await env.switch("procurve")
    cid, plan = await apply(sid, PC_PROBE)
    env.agent.read_error = error
    ch = await run(env, cid)
    assert (ch["status"], ch["error"], ch["saved"]) == ("failed", f"Zustand per SNMP nicht lesbar: {text}", 0)
    assert steps(ch) == [(f"Lese {HOST} per SNMP", "info"), (f"Zustand per SNMP nicht lesbar: {text}", "error")]
    assert env.agent.sets == [] and ch["before"] == plan["before"]
    assert env.repolls == [sid] and env.ssh == []                 # re-polled after "failed", as on the SSH path


async def test_snmp_readback_failure_unclear(env):
    """The SET went out, the read-back fails: whatever the switch took is unknown -> unclear."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.readback_error = snmp.SnmpError(TIMEOUT)
    ch = await run(env, cid)
    error = f"Zurücklesen per SNMP fehlgeschlagen: {TIMEOUT}"
    assert (ch["status"], ch["error"], ch["saved"]) == ("unclear", error, 0)
    assert steps(ch) == [*READ_STEPS, (setting(5), "info"), (f"{error}. {SAVED_NOTE}", "error")]
    assert len(env.agent.sets) == 1 and ch["before"] == {"2": {"u": "99", "pvid": "99"}}


async def test_snmp_without_write_identity_fails_before_reading(env):
    """SNMP writing was switched off after the preview: "failed" with the reason of poller.creds_of(row, write=True), before any read,
    never a SET with the read identity."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    await sql("UPDATE switches SET snmp_write = 0 WHERE id = ?", (sid,))
    env.agent.walks.clear()
    ch = await run(env, cid)
    assert (ch["status"], ch["error"], steps(ch)) == ("failed", WRITE_DISABLED, [(WRITE_DISABLED, "error")])
    assert env.agent.walks == [] and env.agent.sets == []


async def test_snmp_without_write_identity_does_not_wait_for_the_lock(env):
    """A change that could not write anyway fails at once, without queueing behind another action on the switch."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    await sql("UPDATE switches SET snmp_write = 0 WHERE id = ?", (sid,))
    lock = sshcli.lock(sid)
    await lock.acquire()
    try:
        ch = await asyncio.wait_for(run(env, cid), timeout=2)
    finally:
        lock.release()
    assert (ch["status"], ch["error"], steps(ch)) == ("failed", WRITE_DISABLED, [(WRITE_DISABLED, "error")])


@pytest.mark.parametrize("driver, payload, note", [("procurve", PC_PROBE, SAVED_NOTE), ("generic", GI_PROBE, UNSAVED_NOTE)])
async def test_snmp_unexpected_error_after_the_set_is_unclear(env, monkeypatch, driver, payload, note):
    """Any other exception once the SET is out (here: in the verify) is unclear, never failed: the switch may have taken it. Its step
    says so, and whether that is saved (R26)."""
    sid = await env.switch(driver)
    cid, _ = await apply(sid, payload)

    def broken(*args, **kwargs):
        raise KeyError("pvid")
    monkeypatch.setattr(changes, "verify_snmp", broken)
    ch = await run(env, cid)
    assert (ch["status"], ch["error"], steps(ch)[-1]) == ("unclear", "KeyError: 'pvid'", (f"KeyError: 'pvid'. {note}", "error"))
    assert len(env.agent.sets) == 1


async def test_snmp_error_raised_by_the_set_itself_is_unclear(env):
    """Not an SnmpError but any exception out of the SET: the varbinds may be on the switch already, so unclear (the run counts as
    "sent" before the SET is handed over, not after it returns)."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.set_raises = RuntimeError("Fehler im Agenten")
    ch = await run(env, cid)
    error = "RuntimeError: Fehler im Agenten"
    assert (ch["status"], ch["error"], steps(ch)[-1]) == ("unclear", error, (f"{error}. {SAVED_NOTE}", "error"))
    assert len(env.agent.sets) == 1


async def test_snmp_before_is_stored_before_the_set(env):
    """By the time the SET reaches the switch, the change row already holds the `before` of the live read (here PVID 30, drifted since
    the preview's 1): a run that dies during the SET can still be taken back to the true state."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, {"ports": ["3"], "change": {"untagged": "99"}})
    env.agent.W = edit_walks(env.agent.W, pvid={"2": "30"})
    seen = []

    async def look():
        seen.append((await change(cid))["before"])
    env.agent.on_set = look
    assert (await run(env, cid))["status"] == "ok"
    assert seen == [{"3": {"u": None, "pvid": "30"}}]


@pytest.mark.parametrize("when, status", [("first read", "failed"), ("set", "unclear"), ("verify", "unclear")])
async def test_snmp_cancelled_run_ends_by_whether_the_set_was_out(env, monkeypatch, when, status):
    """Cancelled (say the app shuts down) during the first read: failed, nothing was sent. Cancelled during the SET or after it (here in
    the verify): unclear, never failed. Either way the change does not stay "running", and says why it ended."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    if when == "first read":
        env.agent.read_error = asyncio.CancelledError()
    elif when == "set":
        env.agent.set_raises = asyncio.CancelledError()
    else:
        def cancelled(*args, **kwargs):
            raise asyncio.CancelledError()
        monkeypatch.setattr(changes, "verify_snmp", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await changes.run_change(cid)
    ch = await change(cid)
    assert (ch["status"], ch["error"], len(env.agent.sets)) == (status, CANCELLED, 0 if when == "first read" else 1)
    assert steps(ch)[-1] == ((CANCELLED, "error") if status == "failed" else (f"{CANCELLED}. {SAVED_NOTE}", "error"))
    assert ch["finished_at"] is not None


# ── R33: the write identity once more after the wait for the lock ─────────────────────────────────────────────────────────────────
async def hold_the_lock_while(env: Env, sid: int, cid: int, meanwhile) -> dict:
    """Run change cid while another action holds the switch's lock; once the run waits for it, await meanwhile() (an edit of the
    switch, say), then release the lock and let the run finish. The changes row afterwards."""
    lock = sshcli.lock(sid)
    await lock.acquire()
    task = asyncio.create_task(changes.run_change(cid))
    try:
        for _ in range(300):
            if (await change(cid))["steps"]:
                break
            await asyncio.sleep(0.01)
        assert steps(await change(cid)) == [("Warte auf laufende Aktion an diesem Switch", "info")]
        await meanwhile()
    finally:
        lock.release()
    await task
    await asyncio.sleep(0)
    return await change(cid)


@pytest.mark.parametrize("edit, reason", [
    ("UPDATE switches SET snmp_write = 0 WHERE id = ?", WRITE_DISABLED),
    ("UPDATE switches SET snmp_rw_community = NULL, snmp_community = NULL WHERE id = ?", NO_WRITE_CREDS),
])
async def test_snmp_write_identity_checked_again_after_waiting_for_the_lock(env, edit, reason):
    """SNMP writing was switched off, or the write credentials removed, while the change waited for the lock: failed with the reason,
    nothing read, no SET."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.walks.clear()

    async def meanwhile():
        await sql(edit, (sid,))
    ch = await hold_the_lock_while(env, sid, cid, meanwhile)
    assert (ch["status"], ch["error"]) == ("failed", reason)
    assert steps(ch) == [("Warte auf laufende Aktion an diesem Switch", "info"), (reason, "error")]
    assert env.agent.walks == [] and env.agent.sets == []


async def test_snmp_run_uses_the_switch_row_as_it_is_after_the_wait(env):
    """The RW community was changed while the change waited: the SET goes out with the new one."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)

    async def meanwhile():
        await sql("UPDATE switches SET snmp_rw_community = ? WHERE id = ?", (crypto.encrypt("rw-neu"), sid))
    ch = await hold_the_lock_while(env, sid, cid, meanwhile)
    assert ch["status"] == "ok"
    assert [cred for _, cred, _ in env.agent.sets] == [{**RW_CRED, "snmp_community": "rw-neu"}]


# ── Nothing to write: aborted, never ok without a verify ──────────────────────────────────────────────────────────────────────────
async def test_snmp_plan_without_ops_aborts(env, monkeypatch):
    """The live plan matches the preview but has no varbinds (here a renderer that loses them): aborted, nothing written, never ok,
    "Gespeichert" or the R26 warning without a read-back and a verify."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    real = snmpwrite.render_ops

    def no_ops(*args, **kwargs):
        return [], real(*args, **kwargs)[1]
    monkeypatch.setattr(snmpwrite, "render_ops", no_ops)
    ch = await run(env, cid)
    assert (ch["status"], ch["error"], ch["saved"]) == ("aborted", NOTHING, 0)
    assert steps(ch) == [*READ_STEPS, (NOTHING, "error")]
    assert env.agent.sets == [] and env.repolls == []


async def test_snmp_change_already_in_place_aborts(env):
    """A change whose target already is the switch's state (an empty preview, as only a direct create_change can store one): aborted."""
    sid = await env.switch("procurve")
    plan = {"desired": {}, "before": {}, "shown": [], "blocked": [], "expert": False, "mechanism": "snmp"}
    cid = await changes.create_change(sid, USER, "ports", "Port 2: VLAN 99", {"ports": ["2"], "set": {"untagged": "99"}}, plan)
    ch = await run(env, cid)
    assert (ch["status"], ch["error"]) == ("aborted", NOTHING)
    assert env.agent.sets == []


# ── R41: unmanaged ports take en / name ───────────────────────────────────────────────────────────────────────────────────────────────
# The sample ProCurve with an unmanaged port: R12 port 2 (bridge port 1, untagged 99) with PVID 1; R9 port 3 (bridge port 2) untagged in
# VLAN 1 and 20 (a hybrid port).
R12_VIEW = edit_walks(VIEWS["procurve"], pvid={"1": "1"})
R9_VIEW = edit_walks(VIEWS["procurve"], vlanEgress={"1": pl("4A")}, vlanUntagged={"1": pl("4A"), "20": pl("60")})


@pytest.mark.parametrize("W, port, reason", [(R12_VIEW, "2", R12_PORT2), (R9_VIEW, "3", HYBRID_1_20)], ids=["R12", "R9"])
async def test_unmanaged_port_off_on_and_name_round_trip(env, W, port, reason):
    """R41 end to end (ProCurve without SSH, so over SNMP): an unmanaged port is switched off, on again ("on", R43) and named; each
    change is written, verified ok although the port reads as unmanaged before and after (that counts only for a VLAN change), and
    the revert of the name restores the name alone. u / t changes stay refused with the unmanaged reason."""
    sid = await env.switch("procurve", W)
    for change, shown in (({"status": "off"}, "an → aus"), ({"status": "on"}, "aus → an"), ({"name": "Telefon"}, 'Name "" → "Telefon"')):
        cid, plan = await apply(sid, {"ports": [port], "change": change})
        assert (plan["shown"], plan["blocked"]) == ([f"Port {port}: {shown}"], [])
        ch = await run(env, cid)
        assert (ch["status"], ch["saved"], ch["error"]) == ("ok", 1, None), ch["steps"]
    assert read(env.agent.W, "procurve")[1]["unmanaged"] == {port: reason}
    rid, plan = await apply(sid, {"mode": "revert", "of": cid})
    assert (plan["desired"], plan["before"]) == ({port: {"name": ""}}, {port: {"name": "Telefon"}})
    assert (await run(env, rid))["status"] == "ok"
    assert env.agent.W == W
    for change in ({"untagged": "20"}, {"tagged_add": ["99"]}):
        plan, _, _, _ = await main._make_plan(await switch_row(sid), main.PlanIn(ports=[port], change=main.PortChange(**change)))
        assert plan["blocked"] == [{"port": port, "reason": reason}]
    assert env.ssh == []


# ── R42: a ProCurve SNMP SET saves the whole running config, earlier unsaved SSH changes included ───────────────────────────────────
ALSO_SAVED = "der Switch speichert bei jedem SNMP-SET die gesamte laufende Konfiguration"


def unsaved_warning(refs: str, many: bool = False) -> str:
    return (f"Achtung: {'Änderungen' if many else 'Änderung'} {refs} {'sind' if many else 'ist'} absichtlich nicht gespeichert. Ein SNMP-SET "
            f"lässt den Switch die gesamte laufende Konfiguration speichern – {refs} {'wären' if many else 'wäre'} danach dauerhaft. "
            f"Vorher {refs} zurücknehmen oder bewusst speichern.")


async def old_change(sid: int, *, status: str = "unclear", mechanism: str | None = "ssh", saved: int = 0, kind: str = "ports",
                     reverted_by: int | None = None) -> int:
    """A finished change of the switch as an earlier run left it (mechanism NULL: a row from before the column)."""
    async with db.db() as conn:
        cur = await conn.execute(
            "INSERT INTO changes(switch_id, username, kind, summary, request, ports, desired, before, commands, status, saved, steps, expert, "
            "mechanism, reverted_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, USER, kind, "Port 6: VLAN 20", "{}", "[]", "{}", "{}", "[]", status, saved, json.dumps([["2026-11-01 10:00:00", "Gesendet",
             "info"]]), 0, mechanism, reverted_by))
        await conn.commit()
        return cur.lastrowid


async def test_snmp_preview_warns_of_the_unsaved_ssh_changes_it_would_save(env):
    """R42: the preview of an SNMP change on a driver with snmp_autosave names, loudly and first, every change of the switch that ran
    over SSH (or before the mechanism column) and was left unsaved on purpose: saved 0, not reverted, status ok / unclear / failed. Not
    a block: the SNMP way is used exactly when SSH is down, and the SSH change can then be neither reverted nor saved."""
    sid = await env.switch("procurve")
    listed = [await old_change(sid), await old_change(sid, status="failed", mechanism=None), await old_change(sid, status="ok"),
              await old_change(sid, kind="prepare", status="failed")]
    for kw in ({"saved": 1}, {"reverted_by": 99}, {"status": "aborted"}, {"status": "queued"}, {"status": "running"},
               {"mechanism": "snmp"}, {"kind": "save", "status": "failed"}):
        await old_change(sid, **kw)
    await sql("INSERT INTO switches(name, host, driver) VALUES ('SW-EK-02', '203.0.113.22', 'procurve')")
    [(other,)] = await sql("SELECT id FROM switches WHERE host = '203.0.113.22'")
    await old_change(other)                 # another switch's unsaved change says nothing about this one
    _, plan = await apply(sid, PC_PROBE)
    refs = "#{}, #{}, #{} und #{}".format(*listed)
    assert (plan["mechanism"], plan["blocked"], plan["warnings"]) == ("snmp", [], [unsaved_warning(refs, many=True)])
    await sql("UPDATE changes SET saved = 1 WHERE id IN (?, ?, ?)", tuple(listed[1:]))
    _, plan = await apply(sid, PC_PROBE)
    assert plan["warnings"] == [unsaved_warning(f"#{listed[0]}")]


async def test_snmp_revert_preview_warns_too_and_the_fallback_warning_stays_first(env):
    """The SNMP revert is an SNMP SET as well; and on the SSH fallback the SSH warning stays in front."""
    sid, cid = await forward_port3(env)
    old = await old_change(sid)
    _, plan = await apply(sid, {"mode": "revert", "of": cid})
    assert plan["warnings"] == [unsaved_warning(f"#{old}")]
    await sql("UPDATE switches SET ssh_user = 'manager', ssh_pass = ? WHERE id = ?", (crypto.encrypt("ssh-s3cret"), sid))
    env.allow_ssh()
    env.ssh_fails = "connect"
    _, plan = await apply(sid, PC_PROBE)
    assert plan["warnings"] == [f"SSH nicht verfügbar ({SSH_DOWN}), die Änderung geht per SNMP", unsaved_warning(f"#{old}")]


@pytest.mark.parametrize("drv, W, payload", [(GENERIC, VIEWS["generic"], GI_PROBE), (CLI_UNSAVED, SAMPLE_BY_IFTYPE, PC_PROBE)],
                         ids=["generic", "cli-without-autosave"])
async def test_no_warning_and_no_marking_without_autosave(env, drv, W, payload):
    """A driver without snmp_autosave keeps a SET in the running config only: it saves nothing, earlier unsaved changes stay unsaved."""
    env.mp.setitem(drivers.DRIVERS, drv.name, drv)
    sid = await env.switch(drv.name, W)
    old = await old_change(sid)
    cid, plan = await apply(sid, payload)
    assert plan["warnings"] == []
    assert (await run(env, cid))["status"] == "ok"
    assert (await change(old))["saved"] == 0 and len((await change(old))["steps"]) == 1
    assert not any(ALSO_SAVED in text for text, _ in steps(await change(cid)))


async def test_a_successful_snmp_set_marks_the_unsaved_ssh_changes_saved(env):
    """R42: once apply_ops returned without error on an autosaving switch, the switch has saved its whole running config: exactly the
    listed changes get saved = 1 and a step that says why, and the SNMP change a step naming them. Every other change stays as it was."""
    sid = await env.switch("procurve")
    first, second = await old_change(sid), await old_change(sid, status="failed", mechanism=None)
    keep = [await old_change(sid, saved=1), await old_change(sid, reverted_by=99), await old_change(sid, status="aborted")]
    before = {i: await change(i) for i in keep}
    cid, _ = await apply(sid, PC_PROBE)
    ch = await run(env, cid)
    assert (ch["status"], ch["saved"]) == ("ok", 1)
    for i in (first, second):
        old = await change(i)
        assert old["saved"] == 1 and steps(old) == [("Gesendet", "info"),
                                                    (f"Mitgespeichert durch SNMP-Änderung #{cid}: {ALSO_SAVED}.", "warn")]
        assert old["status"] == ("unclear" if i == first else "failed")
    assert steps(ch) == [*READ_STEPS, (setting(5), "info"), (f"Mitgespeichert: Änderung #{first} und #{second} ({ALSO_SAVED})", "warn"),
                         ("Zustand nachher gelesen", "info"), ("Prüfung ok", "info"), (AUTOSAVED, "ok")]
    assert {i: await change(i) for i in keep} == before


async def test_an_unclear_verify_after_a_set_without_error_marks_them_all_the_same(env):
    """The SET came back without error, so the switch saved: the marks do not wait for the verify (here: the switch took nothing)."""
    sid = await env.switch("procurve")
    old = await old_change(sid)
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.set_mode = "ignore"
    assert (await run(env, cid))["status"] == "unclear"
    assert (await change(old))["saved"] == 1


@pytest.mark.parametrize("mode, status", [("lost", "ok"), ("timeout", "unclear")])
async def test_an_erroring_snmp_set_marks_nothing(env, mode, status):
    """A SET that errored marks nothing (R42), whatever the read-back finds afterwards: the switch took it but the answer was lost
    ("lost": the change itself verifies ok), or it took nothing ("timeout")."""
    sid = await env.switch("procurve")
    old = await old_change(sid)
    cid, _ = await apply(sid, PC_PROBE)
    env.agent.set_mode = mode
    ch = await run(env, cid)
    assert ch["status"] == status
    assert (await change(old))["saved"] == 0 and len((await change(old))["steps"]) == 1
    assert not any(ALSO_SAVED in text for text, _ in steps(ch))


# ── R43: status "on" ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_procurve_without_ssh_switches_a_port_off_and_on_again_over_snmp(env):
    """R43: on a ProCurve without SSH a port switched off over SNMP comes back on with "on" (before it, only "Protected" re-enabled a
    port, and that is CLI-only on a NAC driver). The change is en alone, 802.1X / MAC auth untouched; afterwards the switch is what it
    was."""
    sid = await env.switch("procurve")
    for status, ops, shown in (("off", "2", "Port 2: an → aus"), ("on", "1", "Port 2: aus → an")):
        cid, plan = await apply(sid, {"ports": ["2"], "change": {"status": status}})
        assert (plan["desired"], plan["ops"], plan["shown"]) == ({"2": {"en": status == "on"}}, [(f"{IF_ADMIN}.2", "i", ops)], [shown])
        ch = await run(env, cid)
        assert (ch["status"], ch["saved"], ch["summary"], ch["desired"]) == ("ok", 1, f"Port 2: {'An' if status == 'on' else 'Aus'}",
                                                                             {"2": {"en": status == "on"}})
    assert env.agent.W == VIEWS["procurve"]
    assert env.ssh == []


# ── M1: Cisco access ports outside VLAN 1 (BRIDGE-MIB per VLAN context) ──────────────────────────────────────────────────────────────
# Classic IOS serves BRIDGE-MIB per VLAN (community@vlan, v3 context vlan-N): in the default context dot1dBasePortIfIndex lists only the
# VLAN-1 ports. The Catalyst with PoE so: Gi1/0/1 (ifIndex 10101) an access port in VLAN 20 (vmVlan) and so no bridge port, "Drucker",
# PoE entry 1.1 on; Gi1/0/2 (10102) an access port in VLAN 1, bridge port 2; Po1 = Gi1/0/3 + Gi1/0/4 (bridge port 56).
CISCO_CONTEXT = agent(edit_walks({**W_CATALYST_POE, "vmVlan": CATALYST_VMVLAN}, bp2if={"1": None}, vmVlan={"10101": "20"}))
NO_BRIDGE_PORT = "kein Bridge-Port (etwa ein Management-Port), per SNMP nur zur Anzeige"


async def test_cisco_access_port_without_a_bridge_port_is_written_and_verified(env):
    """R45: on cisco_vmps a port with a vmVlan row is a switchport even without a bridge port in the default context: its access VLAN
    (vmVlan), on / off (ifAdminStatus), name (ifAlias) and PoE are planned, written in ONE SET by ifIndex / PoE entry and verified."""
    sid = await env.switch("cisco", CISCO_CONTEXT)
    payload = {"ports": ["Gi1/0/1"], "change": {"untagged": "10", "status": "off", "name": "Drucker-2", "poe": False}}
    cid, plan = await apply(sid, payload)
    assert plan["shown"] == ["Port Gi1/0/1: Access-VLAN 20 → 10", "Port Gi1/0/1: an → aus", 'Port Gi1/0/1: Name "Drucker" → "Drucker-2"',
                             "Port Gi1/0/1: PoE an → aus"]
    assert plan["ops"] == [(f"{VMVLAN}.10101", "i", "10"), (f"{IF_ADMIN}.10101", "i", "2"), (f"{IF_ALIAS}.10101", "x", "447275636B65722D32"),
                           (f"{POE_ADMIN}.1.1", "i", "2")]
    ch = await run(env, cid)
    assert (ch["status"], ch["saved"], ch["error"], steps(ch)[-1]) == ("ok", 0, None, (UNSAVED, "warn"))
    st = read(env.agent.W, "cisco")[0]["ports"]["Gi1/0/1"]
    assert (st["u"], st["en"], st["name"], st["poe"]) == ("10", False, "Drucker-2", False)
    assert env.ssh == []


async def test_cisco_access_port_that_leaves_the_default_context_verifies(env):
    """Gi1/0/2 moves from VLAN 1 to 20 through vmVlan; right after the SET the default context no longer lists it as a bridge port (it
    is no VLAN-1 port any more). The SET used no bridge port, so the read-back without one is no mismatch: ok."""
    sid = await env.switch("cisco", CISCO_CONTEXT)
    cid, plan = await apply(sid, {"ports": ["Gi1/0/2"], "change": {"untagged": "20"}})
    assert plan["ops"] == [(f"{VMVLAN}.10102", "i", "20")]
    env.agent.after_set = lambda W: edit_walks(W, bp2if={"2": None})
    ch = await run(env, cid)
    assert "Gi1/0/2" not in read(env.agent.W, "cisco")[1]["port2bp"]
    assert (ch["status"], ch["error"]) == ("ok", None)


@pytest.mark.parametrize("port, change", [
    ("Gi1/0/2", {"status": "off"}),                  # no vmVlan row (a trunk port) and no bridge port: display only, as before
    ("Gi1/0/2", {"name": "x"}),
    ("Gi1/0/2", {"untagged": "20"}),
    ("Gi1/0/1", {"tagged_add": ["10"]}),             # a Q-BRIDGE field still needs a bridge port
])
async def test_cisco_port_without_a_bridge_port_stays_refused_otherwise(env, port, change):
    """Gi1/0/2 here: up, no vmVlan row, no bridge port."""
    sid = await env.switch("cisco", edit_walks(CISCO_CONTEXT, bp2if={"2": None}, vmVlan={"10102": None}, ifAdmin={"10102": "1"}))
    plan, _, _, _ = await main._make_plan(await switch_row(sid), main.PlanIn(ports=[port], change=main.PortChange(**change)))
    assert (plan["blocked"], plan["ops"]) == ([{"port": port, "reason": NO_BRIDGE_PORT}], [])


# ── Never SSH on the SNMP path ────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("outcome", ["ok", "unclear", "aborted", "failed", "readback"])
async def test_snmp_never_calls_ssh(env, outcome):
    """Whatever the SNMP run ends with: no SSH connect (so no send_config_set / save_config), no config backup, no switch_cfg write -
    every one of them is a trap here - and the database holds neither a backup nor a switch_cfg row afterwards."""
    sid = await env.switch("procurve")
    cid, _ = await apply(sid, PC_PROBE)
    if outcome == "unclear":
        env.agent.set_mode = "ignore"
    elif outcome == "aborted":
        env.agent.W = edit_walks(env.agent.W, pvid={"1": "1"})
    elif outcome == "failed":
        env.agent.read_error = snmp.SnmpError(TIMEOUT)
    elif outcome == "readback":
        env.agent.readback_error = snmp.SnmpError(TIMEOUT)
    ch = await run(env, cid)
    assert ch["status"] == {"readback": "unclear"}.get(outcome, outcome)
    assert env.ssh == []
    assert await sql("SELECT count(*) FROM config_backups") == [(0,)] and await sql("SELECT count(*) FROM switch_cfg") == [(0,)]


# ── Which path a change runs ──────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("mechanism", [None, "ssh"])
async def test_null_or_ssh_mechanism_runs_ssh(env, mechanism):
    """NULL (a row from before the column) and "ssh" run the SSH path exactly as before: connect, read, send, read back, verify,
    write memory, backups before / after and switch_cfg, the audit line of before. No SNMP I/O."""
    sid = await env.switch("procurve", ssh=True)
    env.allow_ssh()
    cid = await ssh_change(env, sid, mechanism)
    env.agent.walks.clear()
    ch = await run(env, cid)
    assert (ch["status"], ch["saved"], ch["error"], ch["mechanism"]) == ("ok", 1, None, mechanism)
    assert steps(ch) == [(f"Verbinde mit {HOST}", "info"), ("Konfiguration vorher gelesen", "info"), ("Sende 1 Befehle", "info"),
                         ("Konfiguration nachher gelesen", "info"), ("Prüfung ok", "info"), ("Speichere (write memory)", "info"),
                         ("Gespeichert", "ok")]
    assert env.ssh == [("connect", sid), ("send_command", "show running-config"), ("send_config_set", ["vlan 20 untagged 2"]),
                       ("send_command", "show running-config"), ("save_config",), ("disconnect",), ("store_backup", f"vor #{cid}"),
                       ("store_backup", f"nach #{cid}"), ("store_cfg", sid)]
    assert ch["before"] == {"2": {"u": "99"}}
    assert await audit_rows() == [("change_ok", str(sid), f"#{cid} Port 2: VLAN 20")]
    assert env.agent.walks == [] and env.agent.sets == [] and env.repolls == [sid]


@pytest.mark.parametrize("mechanism, kind, error", [
    ("telnet", "ports", "Unbekannter Schreibweg 'telnet': nichts ausgeführt"),
    ("snmp", "save", "Per SNMP gibt es nur Port-Änderungen: nichts ausgeführt"),
])
async def test_unknown_mechanism_or_kind_aborts_without_touching_the_switch(env, mechanism, kind, error):
    """Fail closed: a mechanism this code does not know is never taken for SSH, and over SNMP there are only port changes (save and
    RADIUS prepare are SSH-only, main refuses them earlier)."""
    sid = await env.switch("procurve", ssh=True)
    plan = {"desired": {"2": {"u": "20"}}, "before": {}, "shown": ["x"], "blocked": [], "mechanism": mechanism}
    cid = await changes.create_change(sid, USER, kind, "Etwas", {"ports": ["2"]}, plan)
    env.agent.walks.clear()
    ch = await run(env, cid)
    assert (ch["status"], ch["error"], steps(ch)) == ("aborted", error, [(error, "error")])
    assert env.ssh == [] and env.agent.walks == [] and env.agent.sets == [] and env.repolls == []
    assert await audit_rows() == [("change_aborted", str(sid), f"#{cid} Etwas, mechanism: {mechanism}")]


# ── R27: an SSH failure makes the cached configuration stale ──────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("fails", ["connect", "read"])
async def test_r27_ssh_failure_in_run_change_invalidates_the_cached_config(env, fails):
    """fresh_cfg serves a young switch_cfg entry without connecting. Once run_change could not reach the switch over SSH (connect, or
    the first read), the next fresh_cfg reads for real (so the preview notices SSH is gone and can fall back to SNMP); a successful
    read makes the entry valid again."""
    sid = await env.switch("procurve", ssh=True)
    env.allow_ssh()
    await changes.store_cfg(sid, SSH_CONFIG)
    env.ssh.clear()
    assert await changes.fresh_cfg(sid) == cfgparse.parse_config(SSH_CONFIG) and env.ssh == []     # from the cache
    cid = await ssh_change(env, sid)
    env.ssh_fails = fails
    ch = await run(env, cid)
    assert ch["status"] == "failed"
    env.ssh.clear()
    with pytest.raises(RuntimeError, match=SSH_DOWN):
        await changes.fresh_cfg(sid)                    # a real read, which fails as well: the preview falls back to SNMP
    assert env.ssh == [("backup_config", sid)]
    env.ssh_fails, env.ssh = None, []
    assert await changes.fresh_cfg(sid) == cfgparse.parse_config(SSH_CONFIG)
    assert env.ssh == [("backup_config", sid), ("store_cfg", sid)]
    env.ssh.clear()
    await changes.fresh_cfg(sid)
    assert env.ssh == []                                # valid again: served from the cache


async def test_r27_a_failed_ssh_read_in_fresh_cfg_invalidates(env):
    """fresh_cfg's own read fails (a caller wanted it fresher than the entry): a later call with the default age must not serve the
    young entry either, SSH just failed."""
    sid = await env.switch("procurve", ssh=True)
    env.allow_ssh()
    await changes.store_cfg(sid, SSH_CONFIG)
    env.ssh_fails = "connect"
    with pytest.raises(RuntimeError, match=SSH_DOWN):
        await changes.fresh_cfg(sid, max_age_s=0)
    env.ssh.clear()
    with pytest.raises(RuntimeError, match=SSH_DOWN):
        await changes.fresh_cfg(sid)
    assert env.ssh == [("backup_config", sid)]


@pytest.mark.parametrize("outcome, stale", [("ok", True), ("unclear", True), ("aborted", False)])
async def test_snmp_set_invalidates_the_cached_ssh_config(env, outcome, stale):
    """Once an SNMP SET went out, the cached running-config no longer describes the switch: the next SSH preview reads it for real. An
    SNMP run that wrote nothing (aborted) leaves the entry alone."""
    sid = await env.switch("procurve")
    await put_cfg(sid)
    cid, _ = await apply(sid, PC_PROBE)
    if outcome == "unclear":
        env.agent.set_mode = "ignore"
    elif outcome == "aborted":
        env.agent.W = edit_walks(env.agent.W, pvid={"1": "1"})
    assert (await run(env, cid))["status"] == outcome
    env.allow_ssh()
    env.ssh_fails = "connect"
    if stale:
        with pytest.raises(RuntimeError, match=SSH_DOWN):
            await changes.fresh_cfg(sid)
        assert env.ssh == [("backup_config", sid)]
    else:
        assert await changes.fresh_cfg(sid) == cfgparse.parse_config(SSH_CONFIG) and env.ssh == []


@pytest.mark.parametrize("outcome, aged", [("ok", True), ("unclear", True), ("aborted", False)])
async def test_snmp_set_ages_the_cached_ssh_config_past_a_restart(env, outcome, aged):
    """M3: the R27 mark lives in the process only. Once an SNMP SET went out, switch_cfg.taken_at is also aged past fresh_cfg's window
    (parsed stays: the map shows NAC state and RADIUS readiness from it), so after a restart, which loses the mark, the next SSH preview
    still reads for real instead of serving the entry from before the SET. A run that wrote nothing leaves the entry young."""
    sid = await env.switch("procurve")
    await put_cfg(sid)
    [(young,)] = await sql("SELECT taken_at FROM switch_cfg WHERE switch_id = ?", (sid,))
    cid, _ = await apply(sid, PC_PROBE)
    if outcome == "unclear":
        env.agent.set_mode = "ignore"
    elif outcome == "aborted":
        env.agent.W = edit_walks(env.agent.W, pvid={"1": "1"})
    assert (await run(env, cid))["status"] == outcome
    changes._cfg_stale.clear()                          # a restart: the in-process mark is gone
    [(taken_at, parsed)] = await sql("SELECT taken_at, parsed FROM switch_cfg WHERE switch_id = ?", (sid,))
    assert json.loads(parsed) == cfgparse.parse_config(SSH_CONFIG)
    age = datetime.now(timezone.utc) - datetime.strptime(taken_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert (age.total_seconds() > 600) is aged and (taken_at == young) is not aged
    env.allow_ssh()
    env.ssh_fails = "connect"
    if aged:
        with pytest.raises(RuntimeError, match=SSH_DOWN):
            await changes.fresh_cfg(sid)
        assert env.ssh == [("backup_config", sid)]
    else:
        assert await changes.fresh_cfg(sid) == cfgparse.parse_config(SSH_CONFIG) and env.ssh == []


# ── snmpwrite.apply_ops ───────────────────────────────────────────────────────────────────────────────────────────────────────────
def write_row(**cols) -> dict:
    """A switches row as far as apply_ops / poller.creds_of look at it: read community READ, RW community RW, SNMP writing on."""
    return {"id": 7, "host": HOST, "driver": "procurve", "snmp_write": 1, "snmp_version": "2c", "snmp_community": crypto.encrypt(READ),
            "snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None, "snmp_priv_proto": None, "snmp_priv_pass": None,
            "snmp_rw_community": crypto.encrypt(RW), "snmp_rw_user": None, "snmp_rw_auth_proto": None, "snmp_rw_auth_pass": None,
            "snmp_rw_priv_proto": None, "snmp_rw_priv_pass": None} | cols


@pytest.fixture
def set_calls(monkeypatch) -> list:
    calls = []

    async def set_vars(host, cred, varbinds, timeout=20):
        calls.append((host, cred, varbinds))
        return "snmpset output"
    monkeypatch.setattr(snmp, "set_vars", set_vars)
    return calls


async def test_apply_ops_writes_with_the_write_identity_in_one_set(set_calls):
    ops = [(f"{VLAN_EGRESS}.20", "x", "E2" + PAD), (f"{PVID}.1", "u", "20")]
    assert await snmpwrite.apply_ops(write_row(), PROCURVE, ops) == "snmpset output"
    assert set_calls == [(HOST, RW_CRED, ops)]


async def test_apply_ops_without_ops_sends_nothing(set_calls):
    assert await snmpwrite.apply_ops(write_row(), PROCURVE, []) == ""
    assert set_calls == []


@pytest.mark.parametrize("cols, reason", [
    ({"snmp_write": 0}, WRITE_DISABLED),
    ({"snmp_rw_community": None, "snmp_community": None}, "Keine SNMP-Schreib-Zugangsdaten hinterlegt"),
])
async def test_apply_ops_without_a_write_identity_refuses(set_calls, cols, reason):
    """Never a SET with the read identity behind write_identity's back: its SnmpError, nothing sent."""
    with pytest.raises(snmp.SnmpError, match=reason):
        await snmpwrite.apply_ops(write_row(**cols), PROCURVE, [(f"{PVID}.1", "u", "20")])
    assert set_calls == []


# ── verify_snmp ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def readback(ports: dict, *, pvid=None, unmanaged=None, vmvlan=None, port2bp=None, egress=None) -> tuple[dict, dict]:
    """A hand-made read-back: cfg with these ports (fields over cfgparse's defaults), raw with an ifIndex for each of them."""
    cfg = {"ports": {p: {**cfgparse._empty_port(), **st} for p, st in ports.items()}}
    raw = {"ifindex": {p: i for i, p in enumerate(ports, 1)}, "pvid": pvid or {}, "unmanaged": unmanaged or {}, "vmvlan": vmvlan or {},
           "port2bp": port2bp or {}, "egress": egress or {}}
    return cfg, raw


CISCO = drivers.DRIVERS["cisco"]


# drv, pre (the read the plan was made from: port -> u / t), desired, ports of the read-back, more of the read-back's raw, mismatches
@pytest.mark.parametrize("drv, pre, desired, ports, extra, bad", [
    pytest.param(GENERIC, {"2": {"u": "99"}}, {"2": {"u": "20"}}, {"2": {"u": "20"}}, {"pvid": {"2": "20"}}, [], id="u-and-implicit-pvid"),
    pytest.param(GENERIC, {"2": {"u": "99"}}, {"2": {"u": "20"}}, {"2": {"u": "20"}}, {"pvid": {"2": "99"}},
                 ["Port 2: pvid ist '99', erwartet '20'"], id="implicit-pvid-differs"),
    pytest.param(GENERIC, {"2": {"u": "99"}}, {"2": {"u": "20"}}, {"2": {"u": "20"}}, {}, ["Port 2: pvid ist None, erwartet '20'"],
                 id="no-pvid-row"),
    pytest.param(GENERIC, {"3": {"u": "99", "t": ["20"]}}, {"3": {"u": None, "pvid": "1"}}, {"3": {"t": ["20"]}}, {"pvid": {"3": "1"}}, [],
                 id="explicit-pvid"),
    pytest.param(GENERIC, {"3": {"u": "99", "t": ["20"]}}, {"3": {"u": None, "pvid": "1"}}, {"3": {"t": ["20"]}}, {"pvid": {"3": "99"}},
                 ["Port 3: pvid ist '99', erwartet '1'"], id="explicit-pvid-differs"),
    pytest.param(GENERIC, {"3": {"t": ["20"]}}, {"3": {"pvid": "1"}}, {"3": {}}, {"pvid": {"3": "5"}}, ["Port 3: pvid ist '5', erwartet '1'"],
                 id="pvid-only-checks-no-vlans"),
    pytest.param(GENERIC, {"3": {"u": "99", "t": ["20"]}}, {"3": {"u": None}}, {"3": {"t": ["20"]}}, {"pvid": {"3": "99"}}, [],
                 id="u-to-none-expects-no-pvid"),
    pytest.param(GENERIC, {"3": {"t": ["30"]}}, {"3": {"t": ["20"], "en": False}}, {"3": {"t": ["20"], "en": False}}, {"pvid": {"3": "7"}},
                 [], id="no-u-change-expects-no-pvid"),
    # R32: the whole VLAN membership of a port whose u or t changes
    pytest.param(GENERIC, {"2": {"u": "99"}}, {"2": {"u": "20"}}, {"2": {"u": "20", "t": ["99"]}}, {"pvid": {"2": "20"}},
                 ["Port 2: t ist ['99'], erwartet []"], id="u-change-checks-t"),
    pytest.param(GENERIC, {"1": {"u": "20", "t": ["30"]}}, {"1": {"t": ["30", "99"]}}, {"1": {"t": ["30", "99"]}}, {"pvid": {"1": "20"}},
                 ["Port 1: u ist None, erwartet '20'"], id="t-change-checks-u"),
    # ... but the PVID still follows what was written: a t change writes none, so a port without a PVID row is fine
    pytest.param(GENERIC, {"1": {"u": "20", "t": ["30"]}}, {"1": {"t": ["30", "99"]}}, {"1": {"u": "20", "t": ["30", "99"]}}, {}, [],
                 id="t-change-expects-no-pvid"),
    pytest.param(GENERIC, {"2": {"u": "99"}}, {"2": {"u": "20"}}, {"2": {"u": "20"}},
                 {"pvid": {"2": "20"}, "port2bp": {"2": 1}, "egress": {"20": bytes([0x00, 0x00])}},
                 ["Port 2: VLAN 20 ungetaggt, aber ohne Egress-Bit"], id="new-u-without-egress-bit"),
    pytest.param(GENERIC, {"2": {"u": "99"}}, {"2": {"u": "20"}}, {"2": {"u": "20"}},
                 {"pvid": {"2": "20"}, "port2bp": {"2": 1}, "egress": {"20": bytes([0x80, 0x00])}}, [], id="new-u-with-egress-bit"),
    pytest.param(GENERIC, {"1": {"u": "20"}}, {"1": {"t": ["30"]}}, {"1": {"u": "20", "t": ["30"]}},
                 {"pvid": {"1": "20"}, "port2bp": {"1": 3}, "egress": {"20": bytes([0x00])}}, [], id="unchanged-u-egress-not-written"),
    pytest.param(CISCO, {"Gi1/0/2": {"u": "1"}}, {"Gi1/0/2": {"u": "10"}}, {"Gi1/0/2": {"u": "10"}},
                 {"pvid": {"Gi1/0/2": "1"}, "port2bp": {"Gi1/0/2": 2}, "egress": {"10": bytes([0x00])}}, [], id="cisco-skips-q-bridge"),
    pytest.param(GENERIC, {"2": {"u": "1"}}, {"2": {"u": "20"}}, {"2": {"u": "20"}},
                 {"pvid": {"2": "1"}, "vmvlan": {"2": "20"}, "port2bp": {"2": 1}, "egress": {"20": bytes([0x00])}}, [],
                 id="vmvlan-row-skips-q-bridge"),
    pytest.param(GENERIC, {}, {"2": {"en": False, "name": "x"}}, {"2": {}}, {},
                 ["Port 2: en ist True, erwartet False", "Port 2: name ist '', erwartet 'x'"], id="fields"),
    pytest.param(GENERIC, {}, {"9": {"name": ""}}, {"2": {}}, {}, ["Port 9: beim Zurücklesen nicht gefunden"], id="missing"),
    pytest.param(GENERIC, {"3": {"u": "99"}}, {"3": {"u": None, "pvid": "1"}}, {"3": {}}, {"pvid": {"3": "1"}, "unmanaged": {"3": "Grund"}},
                 ["Port 3: nach der Änderung Grund"], id="unmanaged"),
    pytest.param(GENERIC, {"3": {"t": ["20"]}}, {"3": {"t": ["20", "30"]}}, {"3": {"t": ["20", "30"]}}, {"unmanaged": {"3": "Grund"}},
                 ["Port 3: nach der Änderung Grund"], id="unmanaged-after-a-t-change"),
    pytest.param(GENERIC, {"3": {"t": ["20"]}}, {"3": {"pvid": "20"}}, {"3": {"t": ["20"]}}, {"pvid": {"3": "20"}, "unmanaged": {"3": "Grund"}},
                 ["Port 3: nach der Änderung Grund"], id="unmanaged-after-a-pvid-change"),
    # R41: en / name / poe never read the VLAN slot, they are checked field by field; an unmanaged port is no mismatch for them
    pytest.param(GENERIC, {}, {"3": {"en": False, "name": "x"}}, {"3": {"en": False, "name": "x"}}, {"unmanaged": {"3": "Grund"}}, [],
                 id="unmanaged-after-en-and-name"),
    pytest.param(GENERIC, {}, {"3": {"en": False}}, {"3": {}}, {"unmanaged": {"3": "Grund"}}, ["Port 3: en ist True, erwartet False"],
                 id="unmanaged-en-still-verified"),
    pytest.param(GENERIC, {}, {"Gi1/0/10": {"name": ""}, "Gi1/0/2": {"name": ""}}, {}, {},
                 ["Port Gi1/0/2: beim Zurücklesen nicht gefunden", "Port Gi1/0/10: beim Zurücklesen nicht gefunden"], id="natural-order"),
])
def test_verify_snmp(drv, pre, desired, ports, extra, bad):
    """The read the change was planned from (cfg, raw) has the same interfaces (ifIndex, bridge port) as the read-back."""
    cfg_after, raw_after = readback(ports, **extra)
    cfg = readback(pre)[0]
    raw = {"ifindex": dict(raw_after["ifindex"]), "port2bp": dict(raw_after["port2bp"]), "poe": {}}
    assert changes.verify_snmp(drv, cfg, cfg_after, raw_after, desired, raw=raw) == bad


RENUMBERED = "Interface-Nummer hat sich geändert"


# M4: drv, desired, ifIndex and bridge port of the port before (the read the SET was rendered from) and after (the read-back), mismatches
@pytest.mark.parametrize("drv, desired, before, after, bad", [
    pytest.param(GENERIC, {"2": {"en": False}}, (2, 1), (7, 1), [f"Port 2: {RENUMBERED}"], id="ifindex"),
    pytest.param(GENERIC, {"2": {"name": "x"}}, (2, None), (7, None), [f"Port 2: {RENUMBERED}"], id="ifindex-without-bridge-port"),
    pytest.param(GENERIC, {"2": {"u": "20"}}, (2, 1), (2, 9), [f"Port 2: {RENUMBERED}"], id="bridge-port-of-a-vlan-write"),
    pytest.param(GENERIC, {"2": {"t": ["30"]}}, (2, 1), (2, None), [f"Port 2: {RENUMBERED}"], id="bridge-port-gone-after-a-vlan-write"),
    pytest.param(GENERIC, {"2": {"pvid": "20"}}, (2, 1), (2, 9), [f"Port 2: {RENUMBERED}"], id="bridge-port-of-a-pvid-write"),
    # the SET did not go through the bridge port: its number is no identity of what was written
    pytest.param(GENERIC, {"2": {"en": False, "name": "x"}}, (2, 1), (2, 9), [], id="bridge-port-not-used-by-en-and-name"),
    pytest.param(CISCO, {"Gi1/0/2": {"u": "20"}}, (10102, 2), (10102, None), [], id="cisco-vmvlan-uses-no-bridge-port"),
    pytest.param(GENERIC, {"2": {"u": "20"}}, (2, 1), (2, 1), [], id="unchanged"),
])
def test_verify_snmp_checks_the_identity_of_each_written_port(drv, desired, before, after, bad):
    """A written port must be the same interface in the read-back as in the read the SET was rendered from: the same ifIndex, and for a
    write through its bridge port (Q-BRIDGE VLAN bits and PVID) the same bridge port. Otherwise interfaces were renumbered between read
    and read-back (a module swap, say), and the SET may have hit another interface while the read-back finds the port by its name:
    unclear, and nothing else is judged for that port (it would be judged on another interface)."""
    (port, want), = desired.items()
    st = {"u": want.get("u"), "t": want.get("t", []), "name": want.get("name", ""), "en": want.get("en", True)}
    cfg_after = {"ports": {port: {**cfgparse._empty_port(), **st}}}
    raw_after = {"ifindex": {port: after[0]}, "port2bp": {port: after[1]} if after[1] else {}, "pvid": {port: want.get("pvid", want.get("u"))},
                 "unmanaged": {}, "vmvlan": {port: want["u"]} if drv is CISCO else {}, "egress": {}}
    raw = {"ifindex": {port: before[0]}, "port2bp": {port: before[1]} if before[1] else {}, "poe": {}}
    cfg = {"ports": {port: {**cfgparse._empty_port(), "u": "1"}}}
    assert changes.verify_snmp(drv, cfg, cfg_after, raw_after, desired, raw=raw) == bad


# ── The host guard in snmp.py ─────────────────────────────────────────────────────────────────────────────────────────────────────
CRED = {"snmp_version": "2c", "snmp_community": RW}
IF_ADMIN_1 = "1.3.6.1.2.1.2.2.1.7.1"
CALLS = {"walk": lambda host: snmp.walk(host, CRED, "1.3.6.1.2.1.2.2.1.7"), "get": lambda host: snmp.get(host, CRED, [IF_ADMIN_1]),
         "set_vars": lambda host: snmp.set_vars(host, CRED, [(IF_ADMIN_1, "i", "2")])}


@pytest.fixture
def argvs(monkeypatch) -> list:
    """snmp._run replaced by a recorder: the argv net-snmp would get."""
    seen = []

    async def fake_run(cmd, timeout, strict=False):
        seen.append(cmd)
        return ""
    monkeypatch.setattr(snmp, "_run", fake_run)
    return seen


@pytest.mark.parametrize("call", list(CALLS))
@pytest.mark.parametrize("host", ["-x", "--help", "-Ox"])
async def test_snmp_refuses_a_host_with_a_leading_dash(argvs, call, host):
    """A host from a row stored before the host regex would reach net-snmp as an option: refused, net-snmp never starts."""
    with pytest.raises(snmp.SnmpError, match="darf nicht mit '-' beginnen"):
        await CALLS[call](host)
    assert argvs == []


@pytest.mark.parametrize("call", list(CALLS))
@pytest.mark.parametrize("host", [HOST, "sw-ek-01.example.org", "fe80::1"])
async def test_snmp_passes_an_ordinary_host(argvs, call, host):
    await CALLS[call](host)
    assert len(argvs) == 1 and host in argvs[0]
