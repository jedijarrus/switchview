"""Task 10: which write mechanism main._make_plan picks for a port change (SSH-CLI or SNMP), what it refuses before planning, and the
API around it (POST /plan, POST /apply, GET /api/drivers).

The routing rule (spec §5 / Q5: fixed at plan time, never switched mid-apply):
  * revert / save run over the mechanism of the ORIGINAL change (changes.mechanism, NULL = "ssh" from before the column), never over
    another one: an SNMP change's `before` carries a PVID the SSH planner does not know (it would KeyError, a 500; a `before` with such
    fields is refused over SSH as well). Not possible over that mechanism right now -> 409 with the reason. Saving an SNMP change ->
    409 (R26): a driver with snmp_autosave (ProCurve) stores every SNMP set itself, any other one cannot save over SNMP.
  * a mechanism the client echoes on /apply (what its preview used) is used if it is still possible, else 409 "Die Vorschau ist
    veraltet" - never a silent switch between preview and apply. /plan ignores an echo (R28): the preview always chooses itself.
  * otherwise: a driver with the `cli` cap and stored SSH credentials goes over SSH, and reading its configuration (changes.fresh_cfg)
    is the pre-flight. If that read fails, SNMP takes over only if the request can go over SNMP (a warning says so), else today's 502
    plus the reason SNMP cannot; a read refused for the switch's host key (changes.HostKeyRefused) hands over only to a write identity
    with SNMPv3 authPriv, else 502. Without `cli` or without SSH credentials: SNMP if possible, else 409 / 422 with the reason.
  * "possible over SNMP": nothing CLI-only in the request (802.1X / MAC auth: status known / radius, limit, guest VLAN, "Protected" on a
    NAC-capable driver, RADIUS prepare -> 409, before any read), the driver has every cap the request needs (needed_ops) and
    poller.creds_of(row, write=True) finds a write identity (else its reason, 422).
  * port names: SSH keeps the strict PORT_RE (it guards CLI interpolation); SNMP accepts the names of other vendors (no leading "-") and
    requires each port to exist in the live read.

The app runs in-process (FastAPI TestClient without `with`: no lifespan, no scheduler) against a fresh database per test. No network:
changes.fresh_cfg (the SSH read), snmpwrite.read_cfg (the SNMP read) and changes.inventory (the poll) are fakes over fixture switches,
and changes.plan_ports, create_change and run_change are spied on (run_change never runs: nothing is applied in this file).
Expected messages and shown lines are written out by hand.
"""
import asyncio
import hashlib
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import cfgparse
import changes
import config
import crypto
import db
import drivers
import main
import poller
import snmp
import snmpwrite
import sshcli
from drivers import Driver
from switchfix import CATALYST_VMVLAN, POE_WALKS, VMVLAN, W_CATALYST, W_POE, W_SAMPLE, agent, edit_walks

USER = {"username": "tester", "name": "Tester", "method": "local"}

# Messages, written out by hand (poller's write-identity reasons included).
WRITE_DISABLED = "SNMP-Schreiben ist für diesen Switch nicht aktiviert"
NO_WRITE_CREDS = "Keine SNMP-Schreib-Zugangsdaten hinterlegt"
PUBLIC = "Community 'public' wird nicht zum Schreiben verwendet – bitte eine eigene Schreib-Community hinterlegen"
OLD_SSH = "Für Änderungen braucht der Switch einen SSH-Zugang (Zugang bearbeiten)"     # the message of before Task 10
SSH_NEEDED = f"{OLD_SSH}. Per SNMP geht es auch nicht: "
NO_SSH_ACCESS = "für diesen Switch ist kein SSH-Zugang hinterlegt (Zugang bearbeiten)"
STALE = "Die Vorschau ist veraltet, bitte neu laden"
SSH_DOWN = "NetmikoTimeoutException: TCP connection to device failed."
SNMP_DOWN = "Zeitüberschreitung bei der SNMP-Abfrage"
NOT_READABLE = f"Konfiguration des Switches nicht lesbar: {SSH_DOWN}"
FALLBACK = f"SSH nicht verfügbar ({SSH_DOWN}), die Änderung geht per SNMP"
RADIUS_CLI = "Zustand „RADIUS“ geht nur mit SSH/ProCurve, nicht per SNMP"
# Saving an SNMP change (R26): a driver with snmp_autosave (ProCurve) stores every SNMP set by itself, any other one cannot save over SNMP.
AUTOSAVED = "SNMP-Änderungen werden automatisch gespeichert"
NOT_SAVABLE = "Per SNMP nicht speicherbar – bitte am Switch speichern (z. B. write memory / copy running-config startup-config)"

# The ProCurve's running-config as the SSH read sees it: the very switch tests/switchfix.py's W_SAMPLE describes over SNMP (ports 1-6,
# Trk1 = 4 + 5; port 1 untagged 20 + tagged 30 "Platz-107", port 2 untagged 99, port 3 tagged 20 + 30, port 6 untagged 1 and disabled),
# so one request means the same on both paths.
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
# What the SNMP read sees per driver: (walk rows as the simulated agent holds them, port selection for snmpwrite.build_cfg).
#   procurve  W_SAMPLE (as above): port 2 = bridge port 1, untagged 99, PVID 99
#   cisco     the Catalyst with vmVlan rows: Gi1/0/1 access VLAN 10, Gi1/0/2 access VLAN 1 (down), Po1 = Gi1/0/3 + Gi1/0/4
#   others    the Catalyst over Q-BRIDGE: Gi1/0/1 untagged 10 (PVID 10), Gi1/0/2 untagged 1 + tagged 20 (PVID 1, down), Po1 a LAG
VIEWS = {"procurve": (agent(W_SAMPLE), "procurve"), "cisco": (agent({**W_CATALYST, "vmVlan": CATALYST_VMVLAN}), "cisco")}
QBRIDGE_VIEW = (agent(W_CATALYST), "generic")

PC_PROBE = {"ports": ["2"], "change": {"untagged": "20"}}
GI_PROBE = {"ports": ["Gi1/0/2"], "change": {"untagged": "10"}}
PROBES = {"procurve": PC_PROBE, "cisco": GI_PROBE, "generic": GI_PROBE}
SHOWN = {("procurve", "ssh"): ["vlan 20 untagged 2"], ("procurve", "snmp"): ["Port 2: VLAN ungetaggt 99 → 20"],
         ("cisco", "snmp"): ["Port Gi1/0/2: Access-VLAN 1 → 10"], ("generic", "snmp"): ["Port Gi1/0/2: VLAN ungetaggt 1 → 10"]}

SSH = {"ssh_user": "manager", "ssh_pass": "ssh-s3cret"}
RW = {"snmp_rw_community": "rw-s3cret"}
NO_CREDS = {}                                   # neither a RW identity nor a read community to fall back to
PUBLIC_RW = {"snmp_rw_community": "public"}     # R25

PROCURVE, GENERIC = drivers.DRIVERS["procurve"], drivers.DRIVERS["generic"]
# Drivers that lack a cap, registered for single tests: an SNMP driver without ifAlias writes, a CLI driver without SNMP VLAN writes,
# and one without any SNMP cap.
NONAME = Driver("noname", GENERIC.caps - {"snmp_name"}, "qbridge", dict(GENERIC.oids), "")
NOVLAN = Driver("novlan", GENERIC.caps - {"snmp_vlan"}, "qbridge", dict(GENERIC.oids), "")
CLI_NOVLAN = Driver("cli_novlan", PROCURVE.caps - {"snmp_vlan"}, "qbridge", dict(PROCURVE.oids), "")
BARE = Driver("bare", frozenset(), "qbridge", dict(GENERIC.oids), "")


def token(shown: list[str]) -> str:
    """changes.cmd_token, written out: the first 16 hex digits of the SHA-256 of the shown lines."""
    return hashlib.sha256("\n".join(shown).encode()).hexdigest()[:16]


def inv_of(cfg: dict) -> dict:
    """changes.inventory() of the switch read as cfg, as far as plan_ports looks at it: every port and trunk member, tr = the trunk of
    a member or the trunk's own name, no LLDP neighbour, no link, no uplinks."""
    member_of = {m: t for t, members in cfg["trunks"].items() for m in members}
    names = dict.fromkeys([*cfg["ports"], *member_of])
    return {"ports": {n: {"n": n, "tr": n if n in cfg["trunks"] else member_of.get(n, ""), "l": [], "o": False} for n in names},
            "uplinks": set()}


class FakeSwitch:
    """The switch behind both mechanisms. ssh_up / snmp_error decide whether a read works; calls records, in order, every SSH read
    ("ssh", switch id), SNMP read ("snmp", driver name, change lock held?) and plan_ports run ("plan", mechanism); poe_reads the
    with_poe of every SNMP read (R34: without it, like read_cfg, no PoE rows); created and ran what /apply handed to create_change and
    run_change."""

    def __init__(self):
        self.ssh_up = True
        self.ssh_exc: Exception = RuntimeError(SSH_DOWN)    # what the SSH read raises while ssh_up is False
        self.snmp_error: Exception | None = None
        self.views = dict(VIEWS)
        self.calls: list[tuple] = []
        self.poe_reads: list[bool] = []
        self.created: list[dict] = []
        self.ran: list[int] = []
        self.cfg: dict | None = None    # what the last read returned: the inventory is built from it

    async def fresh_cfg(self, sid: int, max_age_s: int = 600) -> dict:
        self.calls.append(("ssh", sid))
        if not self.ssh_up:
            raise self.ssh_exc
        self.cfg = cfgparse.parse_config(SSH_CONFIG)
        return self.cfg

    async def read_cfg(self, row, driver, *, with_poe: bool = False) -> tuple[dict, dict]:
        self.calls.append(("snmp", driver.name, sshcli.lock(row["id"]).locked()))
        self.poe_reads.append(with_poe)
        if self.snmp_error:
            raise self.snmp_error
        W, selection = self.views.get(driver.name, QBRIDGE_VIEW)
        W = {k: rows for k, rows in W.items() if with_poe or k not in POE_WALKS}
        cfg, raw = snmpwrite.build_cfg(W, selection, vmvlan_base=VMVLAN if "vmVlan" in W else None, text_hex=True)
        cfg["hostname"] = row["sys_name"] or ""
        self.cfg = cfg
        return cfg, raw

    async def inventory(self, sid: int) -> dict:
        return inv_of(self.cfg)

    def kinds(self) -> list[str]:
        return [c[0] for c in self.calls]


def _never(*args, **kwargs):
    raise AssertionError("the scheduler must not start in a test (no background polling, no network)")


@pytest.fixture
def fake(monkeypatch) -> FakeSwitch:
    sw = FakeSwitch()
    real_plan, real_create = changes.plan_ports, changes.create_change

    def plan_spy(*args, **kwargs):
        sw.calls.append(("plan", kwargs.get("mechanism", "ssh")))
        return real_plan(*args, **kwargs)

    async def create_spy(sid, user, kind, summary, req, plan, revert_of=None):
        sw.created.append(plan)
        return await real_create(sid, user, kind, summary, req, plan, revert_of=revert_of)

    def run_fake(cid):
        sw.ran.append(cid)          # recorded on the call itself: the task it would become never has to run

        async def nothing():
            return None
        return nothing()

    monkeypatch.setattr(changes, "fresh_cfg", sw.fresh_cfg)
    monkeypatch.setattr(snmpwrite, "read_cfg", sw.read_cfg)
    monkeypatch.setattr(changes, "inventory", sw.inventory)
    monkeypatch.setattr(changes, "plan_ports", plan_spy)
    monkeypatch.setattr(changes, "create_change", create_spy)
    monkeypatch.setattr(changes, "run_change", run_fake)
    return sw


@pytest.fixture
def api(tmp_path, monkeypatch, fake):
    """A TestClient on main.app against a fresh database under tmp_path (the app's own init_db), signed in as USER."""
    monkeypatch.setattr(db, "settings", config.Settings(data_dir=str(tmp_path)))
    monkeypatch.setattr(main.scheduler, "start", _never)
    main.app.dependency_overrides[auth.current_user] = lambda: USER
    asyncio.run(db.init_db())
    try:
        yield TestClient(main.app, headers={"X-Requested-With": "SwitchView"})
    finally:
        main.app.dependency_overrides.pop(auth.current_user, None)


def switch(api, driver: str = "procurve", *, ssh: bool = True, snmp_write: bool = True, creds: dict = RW, **fields) -> int:
    body = {"name": "SW-EK-01", "host": "203.0.113.21", "driver": driver, "snmp_write": snmp_write, **(SSH if ssh else {}), **creds,
            **fields}
    r = api.post("/api/switches", json=body)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def plan(api, sid: int, payload: dict, **extra):
    return api.post(f"/api/switches/{sid}/plan", json={**payload, **extra})


def preview(api, sid: int, payload: dict, **extra) -> dict:
    r = plan(api, sid, payload, **extra)
    assert r.status_code == 200, r.text
    return r.json()


def apply(api, sid: int, payload: dict, tok: str, **extra):
    return api.post(f"/api/switches/{sid}/apply", json={**payload, "token": tok, **extra})


def refused(r, status: int, detail: str):
    assert (r.status_code, r.json().get("detail")) == (status, detail), r.text


def add_change(tmp_path, sid: int, *, before: dict, mechanism: str | None, status: str = "ok", kind: str = "ports", saved: int = 0,
               summary: str = "Port 2: VLAN 99", sent: int | None = None) -> int:
    """A changes row as a finished change leaves it (mechanism NULL, sent NULL: a row from before the column)."""
    conn = sqlite3.connect(tmp_path / "switchview.db")
    try:
        cur = conn.execute(
            "INSERT INTO changes(switch_id, username, kind, summary, request, ports, desired, before, commands, status, saved, steps, "
            "expert, mechanism, sent) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, "tester", kind, summary, "{}", json.dumps(sorted(before)), "{}", json.dumps(before), "[]", status, saved, "[]", 0,
             mechanism, sent))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def reverted_by_of(tmp_path, cid: int) -> int | None:
    conn = sqlite3.connect(tmp_path / "switchview.db")
    try:
        return conn.execute("SELECT reverted_by FROM changes WHERE id = ?", (cid,)).fetchone()[0]
    finally:
        conn.close()


# ── The named cases ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_cisco_routes_snmp(api, fake):
    """A driver without the cli cap goes over SNMP, even with SSH credentials stored: SSH is never touched. The SNMP read runs in the
    switch's change lock, like the SSH read of the configuration."""
    sid = switch(api, "cisco", ssh=True)
    r = plan(api, sid, GI_PROBE)
    assert r.status_code == 200, r.text
    assert r.json() == {"kind": "ports", "summary": "Port Gi1/0/2: VLAN 10", "mechanism": "snmp",
                        "commands": ["Port Gi1/0/2: Access-VLAN 1 → 10"], "warnings": [], "blocked": [],
                        "before": {"Gi1/0/2": {"u": "1"}}, "desired": {"Gi1/0/2": {"u": "10"}},
                        "token": token(["Port Gi1/0/2: Access-VLAN 1 → 10"])}
    assert fake.calls == [("snmp", "cisco", True), ("plan", "snmp")]


def test_procurve_prefers_ssh(api, fake):
    """ProCurve with SSH credentials goes over SSH even though SNMP writing is set up: the plan of before, plus the mechanism."""
    sid = switch(api, "procurve", ssh=True, snmp_write=True)
    r = plan(api, sid, PC_PROBE)
    assert r.status_code == 200, r.text
    assert r.json() == {"kind": "ports", "summary": "Port 2: VLAN 20", "mechanism": "ssh", "commands": ["vlan 20 untagged 2"],
                        "warnings": [], "blocked": [], "before": {"2": {"u": "99"}}, "desired": {"2": {"u": "20"}},
                        "token": token(["vlan 20 untagged 2"])}
    assert fake.calls == [("ssh", sid), ("plan", "ssh")]


def test_procurve_snmp_fallback_when_ssh_fails(api, fake):
    """The SSH read is the pre-flight: when it fails and SNMP is possible, the change is planned over SNMP, and a warning says why."""
    sid = switch(api, "procurve", ssh=True, snmp_write=True)
    fake.ssh_up = False
    r = plan(api, sid, PC_PROBE)
    assert r.status_code == 200, r.text
    got = r.json()
    assert (got["mechanism"], got["commands"], got["warnings"], got["blocked"]) == ("snmp", ["Port 2: VLAN ungetaggt 99 → 20"],
                                                                                    [FALLBACK], [])
    assert (got["desired"], got["before"]) == ({"2": {"u": "20"}}, {"2": {"u": "99", "pvid": "99"}})    # R21: the PVID goes along
    assert fake.calls == [("ssh", sid), ("snmp", "procurve", True), ("plan", "snmp")]


def test_procurve_snmp_when_no_ssh_creds(api, fake):
    sid = switch(api, "procurve", ssh=False, snmp_write=True)
    got = preview(api, sid, PC_PROBE)
    assert (got["mechanism"], got["commands"], got["warnings"]) == ("snmp", ["Port 2: VLAN ungetaggt 99 → 20"], [])
    assert fake.calls == [("snmp", "procurve", True), ("plan", "snmp")]


def test_snmp_write_disabled_refused(api, fake):
    """snmp_write off: refused at plan time with that reason, even with a RW community stored; nothing is read, nothing planned."""
    refused(plan(api, switch(api, "cisco", snmp_write=False), GI_PROBE), 422, WRITE_DISABLED)
    refused(plan(api, switch(api, "procurve", ssh=False, snmp_write=False, host="203.0.113.22"), PC_PROBE), 422, SSH_NEEDED + WRITE_DISABLED)
    assert fake.calls == []


@pytest.mark.parametrize("creds, reason", [(NO_CREDS, NO_WRITE_CREDS), (PUBLIC_RW, PUBLIC), ({"snmp_community": "public"}, PUBLIC)],
                         ids=["none", "rw-public", "read-public"])
def test_snmp_no_rw_cred_refused(api, fake, creds, reason):
    """snmp_write on but no identity that may write (poller.creds_of(row, write=True)): refused with its reason, never a SET with the
    read community or "public"."""
    refused(plan(api, switch(api, "cisco", creds=creds), GI_PROBE), 422, reason)
    assert fake.calls == []


def test_mixed_cli_op_on_snmp_blocked(api, fake):
    """RADIUS plus a VLAN on an SNMP-only switch: the whole change is refused, the VLAN part is never planned alone."""
    sid = switch(api, "cisco")
    refused(plan(api, sid, {"ports": ["Gi1/0/2"], "change": {"status": "radius", "untagged": "10"}}), 409, RADIUS_CLI)
    assert fake.calls == []      # no read, no plan built


# ── The routing table ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
# (id, driver, SSH credentials, SSH read works, snmp_write, write identity) -> mechanism, or (status, detail)
ROUTES = [
    ("procurve: ssh", "procurve", True, True, True, RW, "ssh"),
    ("procurve: ssh, snmp off", "procurve", True, True, False, NO_CREDS, "ssh"),
    ("procurve: ssh down -> snmp", "procurve", True, False, True, RW, "snmp"),
    ("procurve: ssh down, snmp off", "procurve", True, False, False, RW, (502, f"{NOT_READABLE} (per SNMP geht es auch nicht: {WRITE_DISABLED})")),
    ("procurve: ssh down, no write identity", "procurve", True, False, True, NO_CREDS,
     (502, f"{NOT_READABLE} (per SNMP geht es auch nicht: {NO_WRITE_CREDS})")),
    ("procurve: ssh down, public", "procurve", True, False, True, PUBLIC_RW, (502, f"{NOT_READABLE} (per SNMP geht es auch nicht: {PUBLIC})")),
    ("procurve: no ssh creds -> snmp", "procurve", False, True, True, RW, "snmp"),
    ("procurve: no ssh creds, snmp off", "procurve", False, True, False, RW, (422, SSH_NEEDED + WRITE_DISABLED)),
    ("procurve: no ssh creds, no write identity", "procurve", False, True, True, NO_CREDS, (422, SSH_NEEDED + NO_WRITE_CREDS)),
    ("procurve: no ssh creds, public", "procurve", False, True, True, PUBLIC_RW, (422, SSH_NEEDED + PUBLIC)),
    ("cisco: snmp, ssh creds ignored", "cisco", True, True, True, RW, "snmp"),
    ("cisco: snmp", "cisco", False, True, True, RW, "snmp"),
    ("cisco: snmp off", "cisco", True, True, False, RW, (422, WRITE_DISABLED)),
    ("cisco: no write identity", "cisco", False, True, True, NO_CREDS, (422, NO_WRITE_CREDS)),
    ("cisco: public", "cisco", False, True, True, PUBLIC_RW, (422, PUBLIC)),
    ("generic: snmp", "generic", False, True, True, RW, "snmp"),
    ("generic: snmp, ssh creds ignored", "generic", True, False, True, RW, "snmp"),
    ("generic: snmp off", "generic", True, True, False, RW, (422, WRITE_DISABLED)),
    ("generic: no write identity", "generic", True, True, True, NO_CREDS, (422, NO_WRITE_CREDS)),
]


@pytest.mark.parametrize("driver, ssh, ssh_up, snmp_write, creds, want", [r[1:] for r in ROUTES], ids=[r[0] for r in ROUTES])
def test_routing_table(api, fake, driver, ssh, ssh_up, snmp_write, creds, want):
    sid = switch(api, driver, ssh=ssh, snmp_write=snmp_write, creds=creds)
    fake.ssh_up = ssh_up
    r = plan(api, sid, PROBES[driver])
    tried_ssh = [("ssh", sid)] if driver == "procurve" and ssh else []    # only a cli driver with SSH credentials reads over SSH
    if isinstance(want, tuple):
        refused(r, *want)
        assert fake.calls == tried_ssh          # refused before any SNMP read and before planning
        return
    assert r.status_code == 200, r.text
    got = r.json()
    assert (got["mechanism"], got["commands"], got["blocked"]) == (want, SHOWN[(driver, want)], [])
    assert got["warnings"] == ([FALLBACK] if tried_ssh and want == "snmp" else [])
    if want == "ssh":
        assert fake.calls == [("ssh", sid), ("plan", "ssh")]
    else:
        assert fake.calls == tried_ssh + [("snmp", driver, True), ("plan", "snmp")]


# ── Driver caps (needed_ops) ──────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("change, ops", [
    ({}, set()),
    ({"untagged": "20"}, {"snmp_vlan"}), ({"tagged_add": ["20"]}, {"snmp_vlan"}), ({"tagged_remove": ["30"]}, {"snmp_vlan"}),
    ({"status": "off"}, {"snmp_admin"}), ({"status": "protected"}, {"snmp_admin"}), ({"status": "on"}, {"snmp_admin"}),
    ({"name": "Drucker"}, {"snmp_name"}), ({"name": ""}, {"snmp_name"}),
    ({"untagged": "20", "tagged_add": ["30"], "status": "off", "name": "x"}, {"snmp_vlan", "snmp_admin", "snmp_name"}),
])
def test_needed_ops(change, ops):
    assert main.needed_ops(main.PlanIn(ports=["2"], change=change)) == ops


@pytest.mark.parametrize("change, want", [
    ({"untagged": "10"}, (200, ["Port Gi1/0/2: VLAN ungetaggt 1 → 10"])),
    ({"name": "Drucker"}, (422, "Treiber noname kann Portnamen nicht per SNMP schreiben")),
    ({"name": "Drucker", "untagged": "10"}, (422, "Treiber noname kann Portnamen nicht per SNMP schreiben")),
])
def test_snmp_driver_without_a_needed_cap_refused(api, fake, monkeypatch, change, want):
    monkeypatch.setitem(drivers.DRIVERS, "noname", NONAME)
    r = plan(api, switch(api, "noname"), {"ports": ["Gi1/0/2"], "change": change})
    if want[0] == 422:
        refused(r, *want)
        assert fake.calls == []
    else:
        assert (r.status_code, r.json()["mechanism"], r.json()["commands"]) == (200, "snmp", want[1])


def test_missing_caps_are_all_named(api, fake, monkeypatch):
    monkeypatch.setitem(drivers.DRIVERS, "bare", BARE)
    refused(plan(api, switch(api, "bare"), {"ports": ["Gi1/0/2"], "change": {"status": "off", "name": "x", "untagged": "10"}}), 422,
            "Treiber bare kann An/Aus, Portnamen und VLANs nicht per SNMP schreiben")


def test_cli_driver_falls_back_only_for_what_snmp_can(api, fake, monkeypatch):
    """A cli driver whose SNMP side lacks VLAN writes: over SSH anything goes; with SSH down a VLAN change has no SNMP fallback (502
    with the reason) while a name change does; without SSH credentials a VLAN change is refused with both reasons."""
    monkeypatch.setitem(drivers.DRIVERS, "cli_novlan", CLI_NOVLAN)
    fake.views["cli_novlan"] = VIEWS["procurve"]
    sid = switch(api, "cli_novlan")
    assert preview(api, sid, PC_PROBE)["mechanism"] == "ssh"
    fake.ssh_up = False
    refused(plan(api, sid, PC_PROBE), 502, f"{NOT_READABLE} (per SNMP geht es auch nicht: Treiber cli_novlan kann VLANs nicht per SNMP schreiben)")
    got = preview(api, sid, {"ports": ["2"], "change": {"name": "Drucker"}})
    assert (got["mechanism"], got["commands"], got["warnings"]) == ("snmp", ['Port 2: Name "" → "Drucker"'], [FALLBACK])
    refused(plan(api, switch(api, "cli_novlan", ssh=False, host="203.0.113.22"), PC_PROBE), 422,
            SSH_NEEDED + "Treiber cli_novlan kann VLANs nicht per SNMP schreiben")


# ── Refused over SNMP before planning (CLI-only) ──────────────────────────────────────────────────────────────────────────────────
CLI_ONLY = [
    ("known", {"ports": ["Gi1/0/2"], "change": {"status": "known"}}, "Zustand „Bekannte Geräte“ geht nur mit SSH/ProCurve, nicht per SNMP"),
    ("radius", {"ports": ["Gi1/0/2"], "change": {"status": "radius"}}, RADIUS_CLI),
    ("limit", {"ports": ["Gi1/0/2"], "change": {"limit": 2}}, "Geräte pro Port geht nur mit SSH/ProCurve, nicht per SNMP"),
    ("guest", {"ports": ["Gi1/0/2"], "change": {"guest": "20"}}, "Gast-VLAN geht nur mit SSH/ProCurve, nicht per SNMP"),
    ("no guest", {"ports": ["Gi1/0/2"], "change": {"guest": ""}}, "Gast-VLAN geht nur mit SSH/ProCurve, nicht per SNMP"),
    ("several", {"ports": ["Gi1/0/2"], "change": {"status": "known", "limit": 2, "guest": "20", "untagged": "10"}},
     "Zustand „Bekannte Geräte“, Geräte pro Port und Gast-VLAN gehen nur mit SSH/ProCurve, nicht per SNMP"),
    ("prepare", {"mode": "prepare"}, "RADIUS vorbereiten geht nur mit SSH/ProCurve, nicht per SNMP"),
]


@pytest.mark.parametrize("payload, detail", [c[1:] for c in CLI_ONLY], ids=[c[0] for c in CLI_ONLY])
def test_cli_only_request_refused_over_snmp(api, fake, payload, detail):
    """Over SNMP these would plan NOTHING (802.1X / MAC auth is neither readable nor writable there): 409 before any read."""
    refused(plan(api, switch(api, "cisco"), payload), 409, detail)
    assert fake.calls == []


def test_cli_only_wins_over_missing_write_identity(api, fake):
    """No configuration of SNMP writing would make RADIUS possible on cisco: that is the reason given, not the missing identity."""
    refused(plan(api, switch(api, "cisco", snmp_write=False), {"ports": ["Gi1/0/2"], "change": {"status": "radius"}}), 409, RADIUS_CLI)


def test_protected_refused_over_snmp_on_a_nac_driver_only(api, fake):
    """"Protected" means 802.1X / MAC auth off: on a NAC-capable driver (ProCurve) SNMP can neither read nor switch that, it would only
    enable the port and claim "Protected". On a driver without NAC it is just "port on"; "off" is fine everywhere."""
    pc = switch(api, "procurve", ssh=False)
    refused(plan(api, pc, {"ports": ["2"], "change": {"status": "protected"}}), 409, SSH_NEEDED + (
        "Zustand „Protected“ (802.1X/MAC-Anmeldung ist per SNMP weder lesbar noch abschaltbar) geht nur mit SSH/ProCurve, nicht per SNMP"))
    assert fake.calls == []
    got = preview(api, pc, {"ports": ["2"], "change": {"status": "off"}})
    assert (got["mechanism"], got["commands"]) == ("snmp", ["Port 2: an → aus"])
    got = preview(api, switch(api, "cisco", host="203.0.113.22"), {"ports": ["Gi1/0/2"], "change": {"status": "protected"}})
    assert (got["mechanism"], got["commands"], got["blocked"]) == ("snmp", ["Port Gi1/0/2: aus → an"], [])


def test_status_on_is_nac_neutral_on_every_driver_and_way(api, fake):
    """R43: "on" ("An", 802.1X / MAC auth as they are) needs only snmp_admin: a ProCurve without SSH switches its port 6 back on over
    SNMP (where "Protected" is refused, see above), a driver without NAC too, and over SSH it is the plain enable line."""
    got = preview(api, switch(api, "procurve", ssh=False), {"ports": ["6"], "change": {"status": "on"}})
    assert (got["mechanism"], got["commands"], got["desired"], got["summary"]) == ("snmp", ["Port 6: aus → an"], {"6": {"en": True}},
                                                                                   "Port 6: An")
    got = preview(api, switch(api, "cisco", host="203.0.113.22"), {"ports": ["Gi1/0/2"], "change": {"status": "on"}})
    assert (got["mechanism"], got["commands"], got["blocked"]) == ("snmp", ["Port Gi1/0/2: aus → an"], [])
    got = preview(api, switch(api, "procurve", host="203.0.113.23"), {"ports": ["6"], "change": {"status": "on"}})
    assert (got["mechanism"], got["commands"], got["desired"]) == ("ssh", ["interface 6 enable"], {"6": {"en": True}})


@pytest.mark.parametrize("status", ["an", "ON", "enable", ""])
def test_an_unknown_status_is_422(api, fake, status):
    refused_422 = plan(api, switch(api, "procurve", ssh=False), {"ports": ["6"], "change": {"status": status}})
    assert refused_422.status_code == 422 and fake.calls == []


def test_cli_only_request_without_ssh_creds_names_the_missing_access(api, fake):
    refused(plan(api, switch(api, "procurve", ssh=False), {"ports": ["2"], "change": {"status": "radius"}}), 409, SSH_NEEDED + RADIUS_CLI)
    refused(plan(api, switch(api, "procurve", ssh=False, host="203.0.113.22"), {"mode": "prepare"}), 409,
            SSH_NEEDED + "RADIUS vorbereiten geht nur mit SSH/ProCurve, nicht per SNMP")
    assert fake.calls == []


def test_cli_only_request_has_no_snmp_fallback(api, fake):
    """SSH down: a request SNMP cannot carry keeps today's 502, plus why SNMP cannot take over; nothing is read over SNMP."""
    sid = switch(api, "procurve")
    fake.ssh_up = False
    refused(plan(api, sid, {"ports": ["2"], "change": {"status": "radius"}}), 502, f"{NOT_READABLE} (per SNMP geht es auch nicht: {RADIUS_CLI})")
    refused(plan(api, sid, {"mode": "prepare"}), 502,
            f"{NOT_READABLE} (per SNMP geht es auch nicht: RADIUS vorbereiten geht nur mit SSH/ProCurve, nicht per SNMP)")
    assert fake.kinds() == ["ssh", "ssh"]


def test_cli_only_request_still_goes_over_ssh(api, fake):
    """Over SSH nothing of this is refused: the RADIUS change is planned as before (here blocked only because the switch is not
    prepared for RADIUS), prepare as well."""
    sid = switch(api, "procurve")
    got = preview(api, sid, {"ports": ["2"], "change": {"status": "radius", "limit": 2, "guest": "99"}})
    assert got["mechanism"] == "ssh" and got["commands"][0] == "aaa port-access authenticator 2"
    assert [b["port"] for b in got["blocked"]] == ["*"]
    got = preview(api, sid, {"mode": "prepare"})
    assert (got["kind"], got["mechanism"], got["summary"]) == ("prepare", "ssh", "RADIUS vorbereiten")
    assert fake.kinds() == ["ssh", "plan", "ssh"]


# ── The SNMP read ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("error, text", [(snmp.SnmpError(SNMP_DOWN), SNMP_DOWN),
                                         (FileNotFoundError(2, "No such file or directory"), "[Errno 2] No such file or directory")],
                         ids=["snmp-error", "no-net-snmp"])
def test_snmp_read_failure_is_502(api, fake, error, text):
    fake.snmp_error = error
    refused(plan(api, switch(api, "cisco"), GI_PROBE), 502, f"Konfiguration des Switches per SNMP nicht lesbar: {text}")
    assert fake.kinds() == ["snmp"]          # nothing planned from a failed read


def test_fallback_with_snmp_down_too_is_502_naming_both_errors(api, fake):
    sid = switch(api, "procurve")
    fake.ssh_up, fake.snmp_error = False, snmp.SnmpError(SNMP_DOWN)
    refused(plan(api, sid, PC_PROBE), 502, f"{NOT_READABLE} (per SNMP auch nicht: {SNMP_DOWN})")
    assert fake.kinds() == ["ssh", "snmp"]


def test_an_ssh_failure_without_a_message_never_falls_back_silently(api, fake):
    """L19: an SSH read that fails with an empty message (asyncio's TimeoutError has none) is still a failure. SNMP takes over WITH the
    warning, which then names the error's type; and where SNMP cannot take over, both 502 messages name it as well."""
    sid = switch(api, "procurve")
    fake.ssh_up, fake.ssh_exc = False, asyncio.TimeoutError()
    got = preview(api, sid, PC_PROBE)
    assert (got["mechanism"], got["warnings"]) == ("snmp", ["SSH nicht verfügbar (TimeoutError), die Änderung geht per SNMP"])
    fake.snmp_error = snmp.SnmpError(SNMP_DOWN)
    refused(plan(api, sid, PC_PROBE), 502, f"Konfiguration des Switches nicht lesbar: TimeoutError (per SNMP auch nicht: {SNMP_DOWN})")
    sid = switch(api, "procurve", snmp_write=False, host="203.0.113.22")
    refused(plan(api, sid, PC_PROBE), 502, f"Konfiguration des Switches nicht lesbar: TimeoutError (per SNMP geht es auch nicht: {WRITE_DISABLED})")


# ── A refused SSH host key (Phase 2 F-b) ──────────────────────────────────────────────────────────────────────────────────────────
# The SSH read failed because the switch offered another host key than the pinned one (changes.HostKeyRefused): whoever answers at the
# address may be an attacker, so SNMP takes over only when it writes with SNMPv3 authPriv; a v2c community or v3 without privacy would
# go to that address in the clear. A request SNMP cannot take anyway keeps today's 502.
MISMATCH = ("SSH-Hostschlüssel von 203.0.113.21 passt nicht zum gemerkten (SHA256:3f9mUu0QpZ0bXgq3l2yq1b1n2kQe0m7GJmS4ckT8b0E). "
            "Möglicher Angriff oder neuer Schlüssel am Switch – nichts gesendet. Ist der neue Schlüssel erwartet (Tausch, Firmware): "
            "Switch → Zugang bearbeiten → „SSH-Hostschlüssel vergessen“.")
V3_AUTHPRIV_RW = {"snmp_rw_user": "rw", "snmp_rw_auth_proto": "SHA", "snmp_rw_auth_pass": "authpass1", "snmp_rw_priv_proto": "AES",
                  "snmp_rw_priv_pass": "privpass1"}
V3_AUTHNOPRIV_RW = {"snmp_rw_user": "rw", "snmp_rw_auth_proto": "SHA", "snmp_rw_auth_pass": "authpass1"}
V2C_READ = {"snmp_community": "ro-s3cret"}
V3_AUTHPRIV_READ = {"snmp_version": "3", "snmp_user": "ro", "snmp_auth_proto": "SHA", "snmp_auth_pass": "authpass1",
                    "snmp_priv_proto": "AES", "snmp_priv_pass": "privpass1"}
NO_FALLBACK = ("Kein Ausweichen auf SNMP: der Schlüssel kann von einem Angreifer stammen, und SNMP schriebe hier nicht mit SNMPv3 "
               "authPriv.")


def test_a_refused_host_key_does_not_fall_back_to_a_v2c_write(api, fake):
    sid = switch(api, "procurve", ssh=True, snmp_write=True)
    fake.ssh_up, fake.ssh_exc = False, changes.HostKeyRefused(f"HostKeyMismatch: {MISMATCH}")
    r = plan(api, sid, PC_PROBE)
    assert r.status_code == 502 and r.json()["detail"].endswith("Kein Ausweichen auf SNMP: der Schlüssel kann von einem Angreifer stammen, "
                                                                "und SNMP schriebe hier nicht mit SNMPv3 authPriv.")


def test_a_refused_host_key_still_falls_back_with_authpriv(api, fake):
    sid = switch(api, "procurve", ssh=True, snmp_write=True, creds=V3_AUTHPRIV_RW)
    fake.ssh_up, fake.ssh_exc = False, changes.HostKeyRefused(f"HostKeyMismatch: {MISMATCH}")
    p = preview(api, sid, PC_PROBE)
    assert p["mechanism"] == "snmp" and p["warnings"][0].startswith("SSH nicht verfügbar (HostKeyMismatch: ")


def test_the_refusal_names_the_whole_host_key_message_and_reads_nothing_over_snmp(api, fake):
    """The 502 carries the host key message with its remedy, then why there is no fallback (one period between them); nothing is read
    or planned over SNMP."""
    sid = switch(api, "procurve", ssh=True, snmp_write=True)
    fake.ssh_up, fake.ssh_exc = False, changes.HostKeyRefused(f"HostKeyMismatch: {MISMATCH}")
    refused(plan(api, sid, PC_PROBE), 502, f"Konfiguration des Switches nicht lesbar: HostKeyMismatch: {MISMATCH} {NO_FALLBACK}")
    assert fake.kinds() == ["ssh"]


@pytest.mark.parametrize("creds, falls_back", [(RW, False), (V3_AUTHNOPRIV_RW, False), (V2C_READ, False), (V3_AUTHPRIV_READ, True),
                                               (V3_AUTHPRIV_RW, True)],
                         ids=["v2c-rw", "v3-authnopriv-rw", "v2c-read", "v3-authpriv-read", "v3-authpriv-rw"])
def test_only_a_v3_authpriv_write_identity_takes_over_after_a_refused_host_key(api, fake, creds, falls_back):
    """Whichever identity writes (poller.write_identity: the RW one, else the read one) decides, by its level alone."""
    sid = switch(api, "procurve", ssh=True, snmp_write=True, creds=creds)
    fake.ssh_up, fake.ssh_exc = False, changes.HostKeyRefused(f"HostKeyMismatch: {MISMATCH}")
    r = plan(api, sid, PC_PROBE)
    if falls_back:
        assert r.status_code == 200 and r.json()["warnings"] == [f"SSH nicht verfügbar (HostKeyMismatch: {MISMATCH}), die Änderung geht per SNMP"]
        assert fake.kinds() == ["ssh", "snmp", "plan"]
    else:
        refused(r, 502, f"Konfiguration des Switches nicht lesbar: HostKeyMismatch: {MISMATCH} {NO_FALLBACK}")


def test_a_refused_host_key_where_snmp_cannot_write_keeps_todays_502(api, fake):
    """SNMP could not take the request anyway (writing off, or a CLI-only request): the 502 of before, which names why SNMP cannot."""
    sid = switch(api, "procurve", ssh=True, snmp_write=False)
    fake.ssh_up, fake.ssh_exc = False, changes.HostKeyRefused(f"HostKeyMismatch: {MISMATCH}")
    refused(plan(api, sid, PC_PROBE), 502,
            f"Konfiguration des Switches nicht lesbar: HostKeyMismatch: {MISMATCH} (per SNMP geht es auch nicht: {WRITE_DISABLED})")
    sid = switch(api, "procurve", ssh=True, snmp_write=True, creds=V3_AUTHPRIV_RW, host="203.0.113.22")
    refused(plan(api, sid, {"ports": ["2"], "change": {"status": "radius"}}), 502,
            f"Konfiguration des Switches nicht lesbar: HostKeyMismatch: {MISMATCH} (per SNMP geht es auch nicht: {RADIUS_CLI})")


def test_another_ssh_failure_still_falls_back_to_a_v2c_write(api, fake):
    """Only a refused host key changes the rule: an SSH read that fails otherwise (a RuntimeError, as from fresh_cfg) still hands over to
    the v2c write identity, with the warning (Spec Q5)."""
    sid = switch(api, "procurve", ssh=True, snmp_write=True)
    fake.ssh_up, fake.ssh_exc = False, RuntimeError(f"HostKeyMismatch: {MISMATCH}")    # the same text, but no refusal of the key
    p = preview(api, sid, PC_PROBE)
    assert (p["mechanism"], p["warnings"]) == ("snmp", [f"SSH nicht verfügbar (HostKeyMismatch: {MISMATCH}), die Änderung geht per SNMP"])


@pytest.mark.parametrize("cols, want", [
    ({"snmp_write": 0, **V3_AUTHPRIV_RW}, False),               # no write identity at all (snmp.SnmpError): False, never raises
    ({"snmp_write": 1, "snmp_rw_community": None}, False),      # nor without credentials
    ({"snmp_write": 1, **V3_AUTHNOPRIV_RW}, False),
    ({"snmp_write": 1, **V3_AUTHPRIV_RW}, True),
    ({"snmp_write": 1, "snmp_rw_user": None, **V3_AUTHPRIV_READ}, True),
], ids=["write-off", "no-creds", "authnopriv", "authpriv-rw", "authpriv-read"])
def test_write_authpriv(cols, want):
    secret = ("snmp_rw_auth_pass", "snmp_rw_priv_pass", "snmp_auth_pass", "snmp_priv_pass", "snmp_rw_community", "snmp_community")
    row = {"snmp_version": "2c", "snmp_community": None, "snmp_user": None, "snmp_auth_proto": None, "snmp_auth_pass": None,
           "snmp_priv_proto": None, "snmp_priv_pass": None, "snmp_rw_community": None, "snmp_rw_user": None, "snmp_rw_auth_proto": None,
           "snmp_rw_auth_pass": None, "snmp_rw_priv_proto": None, "snmp_rw_priv_pass": None, **cols}
    row = {k: crypto.encrypt(v) if k in secret and v else v for k, v in row.items()}
    assert poller.write_authpriv(row) is want


# ── Port names per mechanism ──────────────────────────────────────────────────────────────────────────────────────────────────────
# The Catalyst over Q-BRIDGE with two ports renamed the way other vendors name them: Gi1/0/2 -> ge-0/0/1, Po1 -> Port-channel1.
RENAMED = (edit_walks(QBRIDGE_VIEW[0], ifName={"10102": "ge-0/0/1", "5001": "Port-channel1"}), "generic")


@pytest.mark.parametrize("payload, shown, summary", [
    ({"ports": ["Gi1/0/1"], "change": {"untagged": "20"}}, "Port Gi1/0/1: VLAN ungetaggt 10 → 20", "Port Gi1/0/1: VLAN 20"),
    ({"ports": ["ge-0/0/1"], "change": {"untagged": "10"}}, "Port ge-0/0/1: VLAN ungetaggt 1 → 10", "Port ge-0/0/1: VLAN 10"),
    ({"ports": ["Port-channel1"], "change": {"tagged_remove": ["20"]}, "expert": True}, "Port Port-channel1: VLAN getaggt 10, 20 → 10",
     "Port Port-channel1: getaggt −20"),
], ids=["Gi1/0/1", "ge-0/0/1", "Port-channel1"])
def test_snmp_accepts_vendor_port_names_present_in_the_read(api, fake, payload, shown, summary):
    fake.views["generic"] = RENAMED
    got = preview(api, switch(api, "generic"), payload)
    assert (got["mechanism"], got["commands"], got["blocked"], got["summary"]) == ("snmp", [shown], [], summary)


@pytest.mark.parametrize("port", ["ge-0/0/1", "Port-channel1", "1.5", "-x", "A1:2"])
def test_ssh_keeps_the_strict_port_re(api, fake, port):
    sid = switch(api, "procurve")
    refused(plan(api, sid, {"ports": [port], "change": {"untagged": "20"}}), 422, f"Port ungültig: {port}")
    assert fake.kinds() == ["ssh"]           # validated after the SSH read, as before; never planned


@pytest.mark.parametrize("port", ["-x", "-", "", "a b", "Gi1/0/1;id", "Gi1/0/1\n", "Ä1", "x" * 65, "/1", ".1"])
def test_snmp_refuses_a_bad_port_name_before_reading(api, fake, port):
    refused(plan(api, switch(api, "generic"), {"ports": ["Gi1/0/1", port], "change": {"untagged": "20"}}), 422, f"Port ungültig: {port}")
    assert fake.calls == []


def test_snmp_refuses_a_port_missing_from_the_live_read(api, fake):
    sid = switch(api, "generic")
    refused(plan(api, sid, {"ports": ["Gi9/0/9", "Gi1/0/1", "Po7", "x" * 64], "change": {"untagged": "20"}}), 422,
            f"Port gibt es auf diesem Switch nicht: Gi9/0/9, Po7, {'x' * 64}")
    assert fake.kinds() == ["snmp"]          # read, then refused: nothing planned


def test_snmp_keeps_the_vlan_id_check(api, fake):
    refused(plan(api, switch(api, "generic"), {"ports": ["Gi1/0/1"], "change": {"tagged_add": ["20", "x1"]}}), 422, "VLAN ungültig: x1")
    assert fake.calls == []


def test_tagged_add_and_remove_of_one_vlan_is_422(api, fake):
    """Baseline L7: before the fix "remove" won silently. The first VLAN by number is named."""
    sid = switch(api, "procurve", ssh=True)
    r = plan(api, sid, {"ports": ["2"], "change": {"tagged_add": ["30"], "tagged_remove": ["30"]}})
    assert (r.status_code, r.json()["detail"]) == (422, "VLAN 30 steht in „getaggt hinzufügen“ und „getaggt entfernen“")
    sid = switch(api, "generic", host="203.0.113.22")    # over SNMP: the same check, before the read
    r = plan(api, sid, {"ports": ["Gi1/0/1"], "change": {"tagged_add": ["30", "20", "100"], "tagged_remove": ["100", "20"]}})
    assert (r.status_code, r.json()["detail"]) == (422, "VLAN 20 steht in „getaggt hinzufügen“ und „getaggt entfernen“")
    assert fake.kinds() == ["ssh"]    # the SSH read of the first request; nothing planned, nothing read over SNMP


# SSH_CONFIG has no RADIUS setup at all; with a RADIUS server in the settings the missing host line names it
NOT_READY_FOR = "Switch ist nicht für RADIUS vorbereitet: RADIUS-Server 203.0.113.99, 802.1X-Methode eap-radius, 802.1X global aktiv"


def test_an_ssh_preview_and_revert_need_the_configured_radius_server(api, fake, tmp_path):
    """Review §3: main._make_plan and main._plan_revert hand the RADIUS server of the settings to plan_ports (radius_server)."""
    asyncio.run(db.set_setting("radius_server", "203.0.113.99"))
    sid = switch(api, "procurve")
    got = preview(api, sid, {"ports": ["2"], "change": {"status": "radius"}})
    assert (got["mechanism"], got["blocked"]) == ("ssh", [{"port": "*", "reason": NOT_READY_FOR}])
    cid = add_change(tmp_path, sid, before={"2": {"x": True, "m": True, "cl": 1, "al": 1}}, mechanism="ssh")
    got = preview(api, sid, {"mode": "revert", "of": cid})
    assert (got["mechanism"], got["blocked"]) == ("ssh", [{"port": "*", "reason": NOT_READY_FOR}])


def test_snmp_trunk_member_is_blocked_not_refused(api, fake):
    """A trunk member exists in the read, so it passes the port check; plan_ports blocks it with the usual reason."""
    got = preview(api, switch(api, "generic"), {"ports": ["Gi1/0/3"], "change": {"untagged": "10"}})
    assert (got["mechanism"], got["commands"], got["blocked"]) == ("snmp", [], [{"port": "Gi1/0/3", "reason": "gehört zu Po1, bitte Po1 wählen"}])


# ── Echo: /apply never switches the mechanism of its preview ──────────────────────────────────────────────────────────────────────
def test_apply_with_echoed_snmp_stays_snmp_when_ssh_is_back(api, fake):
    sid = switch(api, "procurve")
    fake.ssh_up = False
    p = preview(api, sid, PC_PROBE)
    assert (p["mechanism"], p["commands"]) == ("snmp", ["Port 2: VLAN ungetaggt 99 → 20"])
    fake.ssh_up, fake.calls = True, []
    r = apply(api, sid, PC_PROBE, p["token"], mechanism="snmp")
    assert r.status_code == 200, r.text
    assert fake.kinds() == ["snmp", "plan"]                   # SSH is not even tried
    assert [(c["mechanism"], c["shown"]) for c in fake.created] == [("snmp", ["Port 2: VLAN ungetaggt 99 → 20"])]
    assert fake.ran == [r.json()["id"]]


def test_apply_with_echoed_ssh_refused_when_ssh_is_down(api, fake):
    sid = switch(api, "procurve")
    p = preview(api, sid, PC_PROBE)
    assert p["mechanism"] == "ssh"
    fake.ssh_up, fake.calls = False, []
    refused(apply(api, sid, PC_PROBE, p["token"], mechanism="ssh"), 409, f"{STALE} (Konfiguration per SSH nicht lesbar: {SSH_DOWN})")
    assert fake.kinds() == ["ssh"] and fake.created == [] and fake.ran == []    # no SNMP fallback behind the client's back


def test_apply_without_echo_cannot_switch_silently(api, fake):
    """A client that does not echo (today's frontend): the preview went over SNMP, SSH is back, so apply plans over SSH; its CLI lines
    never match the previewed SNMP lines, the token check refuses."""
    sid = switch(api, "procurve")
    fake.ssh_up = False
    p = preview(api, sid, PC_PROBE)
    fake.ssh_up = True
    refused(apply(api, sid, PC_PROBE, p["token"]), 409, STALE)
    assert fake.created == []


def test_apply_with_echoed_snmp_refused_when_snmp_writing_was_switched_off(api, fake):
    sid = switch(api, "cisco")
    p = preview(api, sid, GI_PROBE)
    assert api.put(f"/api/switches/{sid}", json={"name": "SW-EK-01", "host": "203.0.113.21", "snmp_write": False}).status_code == 200
    fake.calls = []
    refused(apply(api, sid, GI_PROBE, p["token"], mechanism="snmp"), 409, f"{STALE} ({WRITE_DISABLED})")
    assert fake.calls == [] and fake.created == []


@pytest.mark.parametrize("driver, ssh, reason", [("cisco", True, "Treiber cisco hat keine SSH-CLI"), ("procurve", False, NO_SSH_ACCESS)])
def test_echoed_ssh_refused_where_there_is_no_ssh(api, fake, driver, ssh, reason):
    refused(apply(api, switch(api, driver, ssh=ssh), PROBES[driver], "0" * 16, mechanism="ssh"), 409, f"{STALE} ({reason})")
    assert fake.calls == [] and fake.created == []


def test_echoed_snmp_still_refuses_cli_only_requests(api, fake):
    refused(apply(api, switch(api, "procurve"), {"ports": ["2"], "change": {"status": "radius"}}, "0" * 16, mechanism="snmp"), 409,
            RADIUS_CLI)
    assert fake.calls == [] and fake.created == []


def test_echoed_snmp_refused_for_a_cap_the_driver_lacks(api, fake, monkeypatch):
    """The capability check of an echoed "snmp" (needed_ops): a driver without ifAlias writes cannot apply a name over SNMP."""
    monkeypatch.setitem(drivers.DRIVERS, "noname", NONAME)
    refused(apply(api, switch(api, "noname"), {"ports": ["Gi1/0/2"], "change": {"name": "x"}}, "0" * 16, mechanism="snmp"), 409,
            f"{STALE} (Treiber noname kann Portnamen nicht per SNMP schreiben)")
    assert fake.calls == [] and fake.created == []


@pytest.mark.parametrize("route", ["plan", "apply"])
def test_mechanism_must_be_ssh_or_snmp(api, fake, route):
    r = api.post(f"/api/switches/{switch(api, 'procurve')}/{route}", json={**PC_PROBE, "mechanism": "telnet", "token": "0" * 16})
    assert r.status_code == 422 and r.json()["detail"][0]["loc"] == ["body", "mechanism"]
    assert fake.calls == []


# ── R28: the preview always chooses the mechanism itself ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("echo", ["ssh", "snmp"])
def test_plan_ignores_an_echoed_mechanism(api, fake, echo):
    """A client cannot ask /plan for a mechanism: a ProCurve whose SSH works previews over SSH, a cisco over SNMP, a ProCurve whose SSH
    read fails falls back to SNMP as usual - whatever the request says."""
    pc = switch(api, "procurve")
    got = preview(api, pc, PC_PROBE, mechanism=echo)
    assert (got["mechanism"], got["commands"]) == ("ssh", ["vlan 20 untagged 2"])
    got = preview(api, switch(api, "cisco", host="203.0.113.22"), GI_PROBE, mechanism=echo)
    assert (got["mechanism"], got["commands"]) == ("snmp", ["Port Gi1/0/2: Access-VLAN 1 → 10"])
    fake.ssh_up = False
    got = preview(api, pc, PC_PROBE, mechanism=echo)
    assert (got["mechanism"], got["warnings"]) == ("snmp", [FALLBACK])
    assert fake.calls == [("ssh", pc), ("plan", "ssh"), ("snmp", "cisco", True), ("plan", "snmp"), ("ssh", pc), ("snmp", "procurve", True),
                          ("plan", "snmp")]


def test_apply_pins_an_echo_that_differs_from_the_server_choice(api, fake):
    """R28 leaves /apply as it was: an echoed "snmp" on a ProCurve whose SSH works is planned over SNMP (SSH not even tried). Its lines
    are not those of the SSH preview, so that token is stale; only a token of exactly these SNMP lines passes. Not possible over SNMP
    -> 409 with the reason, still without trying SSH."""
    sid = switch(api, "procurve")
    p = preview(api, sid, PC_PROBE)
    assert p["mechanism"] == "ssh"
    fake.calls = []
    refused(apply(api, sid, PC_PROBE, p["token"], mechanism="snmp"), 409, STALE)
    assert fake.kinds() == ["snmp", "plan"] and fake.created == []
    r = apply(api, sid, PC_PROBE, token(SHOWN[("procurve", "snmp")]), mechanism="snmp")
    assert r.status_code == 200, r.text
    assert [(c["mechanism"], c["shown"]) for c in fake.created] == [("snmp", SHOWN[("procurve", "snmp")])]
    fake.calls = []
    off = switch(api, "procurve", snmp_write=False, host="203.0.113.22")
    refused(apply(api, off, PC_PROBE, p["token"], mechanism="snmp"), 409, f"{STALE} ({WRITE_DISABLED})")
    assert fake.calls == []


def test_apply_over_ssh_is_unchanged(api, fake, tmp_path):
    sid = switch(api, "procurve")
    p = preview(api, sid, PC_PROBE)
    r = apply(api, sid, PC_PROBE, p["token"], mechanism="ssh")
    assert r.status_code == 200, r.text
    cid = r.json()["id"]
    assert [(c["mechanism"], c["commands"], c["shown"]) for c in fake.created] == [("ssh", ["vlan 20 untagged 2"], ["vlan 20 untagged 2"])]
    assert fake.ran == [cid]
    conn = sqlite3.connect(tmp_path / "switchview.db")
    try:
        row = conn.execute("SELECT kind, summary, ports, desired, before, commands, status FROM changes WHERE id = ?", (cid,)).fetchone()
    finally:
        conn.close()
    assert row == ("ports", "Port 2: VLAN 20", '["2"]', '{"2": {"u": "20"}}', '{"2": {"u": "99"}}', '["vlan 20 untagged 2"]', "queued")


def test_apply_still_refuses_a_blocked_plan(api, fake):
    sid = switch(api, "generic")
    p = preview(api, sid, {"ports": ["Gi1/0/3"], "change": {"untagged": "10"}})
    refused(apply(api, sid, {"ports": ["Gi1/0/3"], "change": {"untagged": "10"}}, p["token"], mechanism="snmp"), 409,
            "Nicht ausführbar: Gi1/0/3: gehört zu Po1, bitte Po1 wählen")
    assert fake.created == []


# ── Revert and save: the mechanism of the original change ─────────────────────────────────────────────────────────────────────────
def test_revert_of_an_snmp_change_goes_over_snmp(api, fake, tmp_path):
    """Its `before` carries the PVID (R21): planned over SNMP it restores it; over SSH the same `before` would be a KeyError (500). SSH
    works here, and still is not used."""
    sid = switch(api, "procurve")
    cid = add_change(tmp_path, sid, before={"2": {"u": "20", "pvid": "20"}}, mechanism="snmp")
    r = plan(api, sid, {"mode": "revert", "of": cid})
    assert r.status_code == 200, r.text
    got = r.json()
    assert (got["kind"], got["summary"], got["mechanism"]) == ("ports", f"Rückgängig #{cid}: Port 2: VLAN 99", "snmp")
    assert got["commands"] == ["Port 2: VLAN ungetaggt 99 → 20", "Port 2: PVID 99 → 20"]
    assert (got["desired"], got["blocked"]) == ({"2": {"u": "20", "pvid": "20"}}, [])
    assert fake.calls == [("snmp", "procurve", True), ("plan", "snmp")]


def test_revert_of_an_snmp_change_refused_when_snmp_is_not_possible(api, fake, tmp_path):
    sid = switch(api, "procurve", snmp_write=False)
    cid = add_change(tmp_path, sid, before={"2": {"u": "20", "pvid": "20"}}, mechanism="snmp")
    refused(plan(api, sid, {"mode": "revert", "of": cid}), 409, f"Änderung #{cid} lief per SNMP und lässt sich nur per SNMP zurücknehmen: {WRITE_DISABLED}")
    assert fake.calls == []                  # never over SSH instead


def test_revert_of_a_change_without_mechanism_goes_over_ssh(api, fake, tmp_path):
    """NULL: a change from before the column, made over SSH. SNMP would be possible here, and is not used."""
    sid = switch(api, "procurve")
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism=None)
    got = preview(api, sid, {"mode": "revert", "of": cid})
    assert (got["kind"], got["mechanism"], got["commands"], got["summary"]) == ("ports", "ssh", ["vlan 20 untagged 2"],
                                                                                f"Rückgängig #{cid}: Port 2: VLAN 99")
    assert fake.calls == [("ssh", sid), ("plan", "ssh")]


def test_ssh_revert_has_no_snmp_fallback(api, fake, tmp_path):
    sid = switch(api, "procurve")
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism="ssh")
    fake.ssh_up = False
    refused(plan(api, sid, {"mode": "revert", "of": cid}), 502, NOT_READABLE)
    assert fake.kinds() == ["ssh"]


@pytest.mark.parametrize("mode, verb", [("revert", "zurücknehmen"), ("save", "speichern")])
@pytest.mark.parametrize("driver, ssh", [("cisco", True), ("procurve", False)])
def test_ssh_revert_or_save_refused_without_ssh(api, fake, tmp_path, driver, ssh, mode, verb):
    """The switch was switched to another driver, or its SSH access removed, after the change: no revert / save over SNMP instead.
    Without SSH access the message of before comes first."""
    sid = switch(api, driver, ssh=ssh)
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism=None, status="unclear")
    done = f"Änderung #{cid} lief per SSH und lässt sich nur per SSH {verb}"
    refused(plan(api, sid, {"mode": mode, "of": cid}), 409, f"{done}: Treiber cisco hat keine SSH-CLI" if driver == "cisco" else f"{OLD_SSH}. {done}")
    assert fake.calls == []


def test_ssh_revert_of_a_before_with_fields_ssh_does_not_know_refused(api, fake, tmp_path):
    """Defence in depth: a NULL-mechanism change whose `before` came from SNMP (pvid, R21) is refused with the reason, not a 500."""
    sid = switch(api, "procurve")
    cid = add_change(tmp_path, sid, before={"2": {"u": "20", "pvid": "20"}, "3": {"poe": True, "name": "x"}}, mechanism=None)
    refused(plan(api, sid, {"mode": "revert", "of": cid}), 409,
            f"Änderung #{cid} lässt sich per SSH nicht zurücknehmen: ihr Vorher-Stand enthält Felder, die der SSH-Weg nicht kennt (poe, pvid)")
    assert fake.calls == []                  # no read, no plan


def test_snmp_revert_blocks_a_port_whose_field_the_driver_cannot_write(api, fake, tmp_path, monkeypatch):
    """Fail closed per port: the driver lost snmp_vlan since the change, so reverting its VLAN is blocked with the reason (and /apply
    refuses), the read and the plan still run."""
    monkeypatch.setitem(drivers.DRIVERS, "novlan", NOVLAN)
    sid = switch(api, "novlan")
    cid = add_change(tmp_path, sid, before={"Gi1/0/1": {"u": "20", "pvid": "20"}}, mechanism="snmp")
    got = preview(api, sid, {"mode": "revert", "of": cid})
    reason = "Treiber novlan kann VLANs nicht per SNMP schreiben"
    assert (got["mechanism"], got["commands"], got["blocked"]) == ("snmp", [], [{"port": "Gi1/0/1", "reason": reason}])
    assert fake.calls == [("snmp", "novlan", True), ("plan", "snmp")]
    refused(apply(api, sid, {"mode": "revert", "of": cid}, got["token"]), 409, f"Nicht ausführbar: Gi1/0/1: {reason}")
    assert fake.created == []


@pytest.mark.parametrize("mode", ["revert", "save"])
def test_revert_or_save_of_a_change_with_an_unknown_mechanism_refused(api, fake, tmp_path, mode):
    """Fail closed: a mechanism this code does not know is never taken for SSH."""
    sid = switch(api, "procurve")
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism="telnet", status="unclear")
    refused(plan(api, sid, {"mode": mode, "of": cid}), 409, f"Änderung #{cid} hat einen unbekannten Schreibweg (telnet)")
    assert fake.calls == []


def test_revert_apply_refuses_an_echo_of_another_mechanism(api, fake, tmp_path):
    """/apply: the echo must be the change's own mechanism. /plan ignores an echo (R28) and previews over the change's mechanism."""
    sid = switch(api, "procurve")
    cid = add_change(tmp_path, sid, before={"2": {"u": "20", "pvid": "20"}}, mechanism="snmp")
    p = preview(api, sid, {"mode": "revert", "of": cid, "mechanism": "ssh"})
    assert p["mechanism"] == "snmp"
    fake.calls = []
    refused(apply(api, sid, {"mode": "revert", "of": cid}, p["token"], mechanism="ssh"), 409, STALE)
    assert fake.calls == [] and fake.created == []


@pytest.mark.parametrize("status", ["unclear", "failed", "ok"])
@pytest.mark.parametrize("driver, detail", [("procurve", AUTOSAVED), ("cisco", NOT_SAVABLE), ("generic", NOT_SAVABLE)])
def test_save_of_an_snmp_change_refused_per_driver(api, fake, tmp_path, driver, detail, status):
    """R26: a driver with snmp_autosave stored the SNMP change by itself; any other one cannot save over SNMP, the switch has to. Said
    whatever the change's status (an SNMP change that ended ok is not saved on such a switch). Nothing is read, nothing planned."""
    sid = switch(api, driver)
    cid = add_change(tmp_path, sid, before={"2": {"u": "20", "pvid": "20"}}, mechanism="snmp", status=status)
    refused(plan(api, sid, {"mode": "save", "of": cid}), 409, detail)
    assert fake.calls == []


def test_save_of_an_ssh_change_is_unchanged(api, fake, tmp_path):
    sid = switch(api, "procurve")
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism=None, status="unclear")
    got = preview(api, sid, {"mode": "save", "of": cid})
    assert got == {"kind": "save", "summary": f"Speichern nach #{cid}", "mechanism": "ssh", "commands": [],
                   "warnings": ["Speichert den aktuellen Stand des Switches dauerhaft (write memory)."], "blocked": [], "before": {},
                   "desired": {}, "token": token([])}
    assert fake.calls == [("ssh", sid)]      # the SSH read stays the pre-flight of a save
    refused(plan(api, sid, {"mode": "save", "of": add_change(tmp_path, sid, before={}, mechanism=None, status="ok")}), 409,
            "Diese Änderung muss nicht gespeichert werden")


@pytest.mark.parametrize("mode", ["revert", "save"])
def test_revert_or_save_of_a_missing_change_is_404(api, fake, mode):
    refused(plan(api, switch(api, "procurve"), {"mode": mode, "of": 4711}), 404, "Änderung nicht gefunden")
    assert fake.calls == []


def test_revert_of_an_unrevertable_change_is_409(api, fake, tmp_path):
    sid = switch(api, "procurve")
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism=None, status="aborted")
    refused(plan(api, sid, {"mode": "revert", "of": cid}), 409, "Diese Änderung lässt sich nicht zurücknehmen")


# ── Revert and save only of a change that sent something (changes.sent; NULL, a row from before the column, counts as sent) ──────
def test_revert_of_a_failed_change_that_sent_nothing_is_refused(api, fake, tmp_path):
    sid = switch(api, "procurve", ssh=True)
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism="ssh", status="failed", sent=0)
    refused(plan(api, sid, {"mode": "revert", "of": cid}), 409, f"Änderung #{cid} hat nichts an den Switch gesendet – es gibt nichts zurückzunehmen")
    assert fake.calls == []                  # nothing read, nothing planned


def test_save_of_a_failed_change_that_sent_nothing_is_refused(api, fake, tmp_path):
    sid = switch(api, "procurve", ssh=True)
    cid = add_change(tmp_path, sid, before={}, mechanism="ssh", status="failed", sent=0)
    refused(plan(api, sid, {"mode": "save", "of": cid}), 409, "Diese Änderung muss nicht gespeichert werden")
    assert fake.calls == []


@pytest.mark.parametrize("sent", [1, None], ids=["sent", "from-before-the-column"])
def test_revert_and_save_of_a_failed_change_that_sent_stay(api, fake, tmp_path, sent):
    sid = switch(api, "procurve", ssh=True)
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism="ssh", status="failed", sent=sent)
    assert preview(api, sid, {"mode": "revert", "of": cid})["commands"] == ["vlan 20 untagged 2"]
    assert preview(api, sid, {"mode": "save", "of": cid})["kind"] == "save"


def test_apply_of_a_revert_leaves_the_original_unreverted(api, fake, tmp_path):   # only the end of the revert sets reverted_by
    sid = switch(api, "procurve", ssh=True)
    cid = add_change(tmp_path, sid, before={"2": {"u": "20"}}, mechanism="ssh")     # port 2 is in 99 in SSH_CONFIG: "vlan 20 untagged 2"
    r = preview(api, sid, {"mode": "revert", "of": cid})
    assert apply(api, sid, {"mode": "revert", "of": cid}, r["token"]).status_code == 200
    assert reverted_by_of(tmp_path, cid) is None                                 # run_change is a fake here: the revert never ran


# ── Summary, drivers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ports, change, want", [
    (["A3", "A1", "A2", "Trk1"], {"untagged": "20"}, "Port A1-A3,Trk1: VLAN 20"),             # ProCurve: compressed, as before
    (["2"], {"status": "off"}, "Port 2: Aus"),
    (["Gi1/0/10", "Gi1/0/2", "Po1", "Gi1/0/2"], {"untagged": "20"}, "Port Gi1/0/2, Gi1/0/10, Po1: VLAN 20"),
    (["ge-0/0/1", "1"], {"name": "Drucker"}, "Port 1, ge-0/0/1: Name Drucker"),
    (["1/1/10", "1/1/2"], {"tagged_add": ["30"]}, "Port 1/1/2, 1/1/10: getaggt +30"),
])
def test_summary(ports, change, want):
    """Port names of other vendors, which cfgparse.compress_ports cannot read (it raises), come naturally sorted and comma-separated."""
    assert main._summary(main.PlanIn(ports=ports, change=change)) == want


def test_drivers_list(api):
    r = api.get("/api/drivers")
    assert r.status_code == 200, r.text
    got = r.json()
    assert [d["name"] for d in got] == list(drivers.DRIVERS)
    for d in got:
        assert set(d) == {"name", "caps", "notes"}
        assert d["caps"] == sorted(drivers.DRIVERS[d["name"]].caps) and d["notes"] == drivers.DRIVERS[d["name"]].notes and d["notes"]
    by_name = {d["name"]: d["caps"] for d in got}
    assert by_name["procurve"] == ["backup", "cli", "nac", "snmp_admin", "snmp_autosave", "snmp_name", "snmp_poe", "snmp_vlan"]
    assert by_name["cisco"] == ["snmp_admin", "snmp_name", "snmp_poe", "snmp_vlan"]
    for name in set(by_name) - {"procurve", "cisco"}:    # R31 (mikrotik), R35 (everyone else): no PoE
        assert by_name[name] == ["snmp_admin", "snmp_name", "snmp_vlan"], name


def test_drivers_list_needs_a_session(api):
    main.app.dependency_overrides.pop(auth.current_user)
    assert api.get("/api/drivers").status_code == 401


# ── PoE (Task 12, R30): over SNMP for every driver, ProCurve with working SSH included ──────────────────────────────────────────────
POE_OFF = {"ports": ["1"], "change": {"poe": False}}


def test_poe_preview_and_apply_go_snmp_on_a_procurve_with_ssh(api, fake):
    """/plan of a PoE change on a ProCurve whose SSH works: SNMP, without any SSH read; /apply with the echoed mechanism and the token
    creates the change with mechanism snmp (tests/test_poe.py runs such changes)."""
    fake.views["procurve"] = (agent(W_POE), "procurve")
    sid = switch(api, "procurve", ssh=True)
    got = preview(api, sid, POE_OFF)
    assert got == {"kind": "ports", "summary": "Port 1: PoE aus", "mechanism": "snmp", "commands": ["Port 1: PoE an → aus"],
                   "warnings": ["Port 1: versorgt gerade ein Gerät mit Strom (PoE), es verliert die Stromversorgung"], "blocked": [],
                   "before": {"1": {"poe": True}}, "desired": {"1": {"poe": False}}, "token": token(["Port 1: PoE an → aus"])}
    assert fake.calls == [("snmp", "procurve", True), ("plan", "snmp")]
    r = apply(api, sid, POE_OFF, got["token"], mechanism="snmp")
    assert r.status_code == 200, r.text
    assert (fake.created[-1]["mechanism"], fake.created[-1]["ops"]) == ("snmp", [("1.3.6.1.2.1.105.1.1.1.3.1.1", "i", "2")])
    assert ("ssh", sid) not in fake.calls
    assert fake.poe_reads == [True, True]    # R34: preview and apply read PoE for a PoE change


def test_snmp_reads_without_poe_for_a_change_without_poe(api, fake):
    """R34: a VLAN change over SNMP (no SSH credentials) on the same PoE switch reads without the PoE tables."""
    fake.views["procurve"] = (agent(W_POE), "procurve")
    got = preview(api, switch(api, "procurve", ssh=False), {"ports": ["2"], "change": {"untagged": "20"}})
    assert (got["mechanism"], got["commands"], fake.poe_reads) == ("snmp", ["Port 2: VLAN ungetaggt 99 → 20"], [False])


@pytest.mark.parametrize("driver, kw, detail", [
    ("procurve", {"snmp_write": False}, f"PoE erfordert SNMP-Schreibzugriff ({WRITE_DISABLED})"),
    ("procurve", {"ssh": False, "creds": NO_CREDS}, f"PoE erfordert SNMP-Schreibzugriff ({NO_WRITE_CREDS})"),
    ("mikrotik", {}, "PoE erfordert SNMP-Schreibzugriff (Treiber mikrotik kann PoE nicht per SNMP schreiben)"),
    ("generic", {}, "PoE erfordert SNMP-Schreibzugriff (Treiber generic kann PoE nicht per SNMP schreiben)"),      # R35
    ("arista", {}, "PoE erfordert SNMP-Schreibzugriff (Treiber arista kann PoE nicht per SNMP schreiben)"),        # R35
], ids=["procurve-snmp-off", "procurve-no-identity", "mikrotik", "generic", "arista"])
def test_poe_without_an_snmp_way_is_422(api, fake, driver, kw, detail):
    refused(plan(api, switch(api, driver, **kw), POE_OFF), 422, detail)
    assert fake.calls == []          # neither an SSH nor an SNMP read


@pytest.mark.parametrize("value", [0, 1, "false", "off"])
def test_poe_must_be_a_json_boolean(api, fake, value):
    r = plan(api, switch(api, "procurve"), {"ports": ["1"], "change": {"poe": value}})
    assert r.status_code == 422 and r.json()["detail"][0]["loc"] == ["body", "change", "poe"], r.text
    assert fake.calls == []


def test_the_api_serves_the_follow_up_actions_of_each_change(api, fake, tmp_path):
    """GET /api/changes and GET /api/changes/{id} carry can_revert and can_save (changes.actions_of, main._change_out): the UI offers
    "Rückgängig" and "Trotzdem speichern" by these flags alone."""
    sid = switch(api, "procurve", ssh=True)
    before = {"2": {"u": "20"}}
    want = {add_change(tmp_path, sid, before=before, mechanism="ssh", status="failed", sent=1): [True, True],
            add_change(tmp_path, sid, before=before, mechanism="ssh", status="failed", sent=0): [False, False],
            add_change(tmp_path, sid, before=before, mechanism="snmp", status="unclear", sent=1): [True, False],
            add_change(tmp_path, sid, before=before, mechanism=None, status="ok", saved=1): [True, False]}
    listed = {c["id"]: [c["can_revert"], c["can_save"]] for c in api.get("/api/changes").json()}
    single = {cid: [api.get(f"/api/changes/{cid}").json()[k] for k in ("can_revert", "can_save")] for cid in want}
    assert listed == single == want
    assert {type(v) for flags in listed.values() for v in flags} == {bool}
