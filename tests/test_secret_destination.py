"""F2: a stored secret is bound to the destination it was entered for. A PUT that gives a switch a new host, or the settings a new
OPNsense address, RADIUS server or PacketFence address, deletes every stored secret of that destination it does not carry anew and
names it in "cleared", so none of them ever reaches the new destination. A different spelling of the same destination (case, a
trailing "/", another way to write the same IP) is no new destination. Both PUTs read and write in one write transaction, so
concurrent PUTs audit a consistent chain. Also here: the read identity's protocols in the audit (R48) and the RADIUS server's zone
id (§6 (a)), refused when saved and again when a switch is prepared.

The app runs in-process: FastAPI's TestClient (created without `with`, so no lifespan and no scheduler) and, for the concurrency
test, an httpx.AsyncClient on the same app, both signed in through the user override and sending the CSRF header. Each test gets
its own database under tmp_path. Nothing leaves the process: PacketFence's and OPNsense's HTTP clients, netmiko's ConnectHandler and
snmp.get are recorders. The F2 tests show that nothing reached them; the positive control shows that the HTTP, SNMP and SSH recorders
do see what goes out (the SSH recorder counts the attempt; its session offers no host key, so sshcli._open gives up right after it).
"""
import asyncio
import sqlite3
from collections import defaultdict
from contextlib import closing

import httpx
import pytest

import apifix
import changes
import crypto
import db
import main
import names as names_mod
import pf
import snmp
import sshcli
from cfgparse import parse_config
from loginfix import CSRF

ALL_SECRETS = {"snmp_community": "ro-s3cret", "snmp_auth_pass": "ro-auth-s3cret", "snmp_priv_pass": "ro-priv-s3cret",
               "ssh_pass": "ssh-s3cret", "snmp_rw_community": "rw-s3cret", "snmp_rw_auth_pass": "rw-auth-s3cret",
               "snmp_rw_priv_pass": "rw-priv-s3cret"}


@pytest.fixture
def api(tmp_path, monkeypatch):
    """A TestClient on main.app signed in as apifix.USER, against a fresh database under tmp_path set up by the app's own init_db."""
    apifix.fresh_db(tmp_path, monkeypatch)
    with apifix.signed_in(monkeypatch) as client:
        yield client


@pytest.fixture
async def api_async(api):
    """An httpx.AsyncClient on main.app in the test's own event loop, so that requests really run concurrently; through api the same
    database and the same user override."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test", headers=CSRF) as client:
        yield client


class Outbound(apifix.Remote):
    """PacketFence and OPNsense behind one recorder: the OPNsense (a URL with /api/diagnostics/) answers an empty ARP table,
    PacketFence a login with a token and a list with no items."""

    def reply(self, method: str, url: str):
        return [] if "/api/diagnostics/" in url else {"token": "t", "items": []}


@pytest.fixture
def outbound(monkeypatch) -> list[str]:
    """Every URL PacketFence's and OPNsense's code sends a request to, base_url included. Patched in the two modules only: the httpx
    of api_async stays real."""
    remote = Outbound()
    monkeypatch.setattr(pf, "httpx", apifix.fake_httpx(remote))
    monkeypatch.setattr(names_mod, "httpx", apifix.fake_httpx(remote))
    return remote.urls


class _Session:
    """A netmiko connection that answers every show command with a version line."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def send_command(self, cmd, read_timeout=None):
        return "Image stamp: /ws/swbuildm/test\n"

    def disconnect(self):
        pass


class Sessions:
    """sshcli.ConnectHandler: records the host of every session it is asked to open."""

    def __init__(self):
        self.hosts: list[str] = []

    def __call__(self, **device):
        self.hosts.append(device["host"])
        return _Session()


@pytest.fixture
def sessions(monkeypatch) -> Sessions:
    recorder = Sessions()
    monkeypatch.setattr(sshcli, "ConnectHandler", recorder)
    monkeypatch.setattr(sshcli, "_locks", defaultdict(asyncio.Lock))
    return recorder


@pytest.fixture
def snmp_creds(monkeypatch) -> list[dict]:
    """Every cred snmp.get is called with; it answers each OID with "SW"."""
    creds: list[dict] = []

    async def get(host, cred, oids, **kwargs):
        creds.append(cred)
        return {oid: "SW" for oid in oids}

    monkeypatch.setattr(snmp, "get", get)
    return creds


def stored(tmp_path, sid: int) -> sqlite3.Row:
    """The switches row as it sits in the database."""
    with closing(sqlite3.connect(tmp_path / "switchview.db")) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM switches WHERE id = ?", (sid,)).fetchone()


def audits(tmp_path) -> list[tuple]:
    with closing(sqlite3.connect(tmp_path / "switchview.db")) as conn:
        return conn.execute("SELECT action, target, detail FROM audit ORDER BY id").fetchall()


def last_audit_detail() -> str:
    """The detail of the newest audit row in the database the app uses now."""
    with closing(sqlite3.connect(db.settings.db_path)) as conn:
        return conn.execute("SELECT detail FROM audit ORDER BY id DESC LIMIT 1").fetchone()[0]


def body(**fields) -> dict:
    return {"name": "SW-VK-02", "host": "203.0.113.42", "zone": "VK", **fields}


def create(api, **fields) -> int:
    r = api.post("/api/switches", json=body(**fields))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def settings_body(**fields) -> dict:
    """A complete SettingsIn body as the settings view sends it (sv-settings.js, any of its three cards): every field, each secret None (= keep)."""
    return {"poll_minutes": 15, "opnsense_url": "", "opnsense_key": None, "opnsense_secret": None, "opnsense_verify_tls": False,
            "radius_server": "", "radius_key": None, "pf_url": "", "pf_user": "", "pf_pass": None, "pf_verify_tls": False, **fields}


def put_settings(api, **fields) -> dict:
    r = api.put("/api/settings", json=settings_body(**fields))
    assert r.status_code == 200, r.text
    return r.json()


# ── Settings: OPNsense, RADIUS, PacketFence ───────────────────────────────────────────────────────────────────────────────────────
def test_new_pf_url_without_password_deletes_it_and_nothing_reaches_the_new_url(api, outbound):   # F2, the audit's input
    put_settings(api, pf_url="https://pf.example:9999", pf_user="svc", pf_pass="pf-s3cret")
    r = api.put("/api/settings", json=settings_body(pf_url="http://attacker.example/", pf_user="svc"))      # pf_pass None = "keep"
    assert r.json() == {"ok": True, "cleared": ["pf_pass"]} and api.get("/api/settings").json()["pf_pass_set"] is False
    assert api.post("/api/pf/test").json()["ok"] is False and outbound == []


def test_new_opnsense_url_deletes_key_and_secret(api, outbound):
    put_settings(api, opnsense_url="https://fw.example", opnsense_key="k-s3cret", opnsense_secret="s-s3cret")
    r = api.put("/api/settings", json=settings_body(opnsense_url="http://attacker.example"))
    assert r.json() == {"ok": True, "cleared": ["opnsense_key", "opnsense_secret"]}
    api.post("/api/names/refresh")
    assert outbound == []


def test_new_radius_server_deletes_the_shared_secret(api):
    put_settings(api, radius_server="203.0.113.10", radius_key="S3cretKey1")
    assert api.put("/api/settings", json=settings_body(radius_server="198.51.100.210")).json()["cleared"] == ["radius_key"]


def test_settings_audit_names_each_new_destination_and_what_it_cleared(api, tmp_path):
    put_settings(api, opnsense_url="https://fw.example", opnsense_key="k-s3cret", radius_server="203.0.113.10", radius_key="S3cretKey1",
                 pf_url="https://pf.example:9999", pf_user="svc", pf_pass="pf-s3cret")
    put_settings(api, opnsense_url="https://fw.example", radius_server="198.51.100.210", pf_url="https://pf2.example", pf_user="svc",
                 pf_pass="pf-n3w")
    assert last_audit_detail() == ("radius_server: 203.0.113.10 → 198.51.100.210, pf_url: https://pf.example:9999 → https://pf2.example, "
                                   "gelöscht: radius_key")
    put_settings(api, opnsense_url="https://fw.example", radius_server="198.51.100.210", pf_url="https://pf2.example", pf_user="svc")
    assert last_audit_detail() == ""
    rows = audits(tmp_path)
    assert [a for a, _, _ in rows] == ["settings_update"] * 3
    assert not any(s in str(rows) for s in ("s3cret", "S3cretKey1", "n3w"))


# ── Switches: the host ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_new_switch_host_deletes_every_stored_secret(api, tmp_path, sessions, snmp_creds):   # incl. snmp_rw_*
    sid = create(api, host="203.0.113.21", ssh_user="manager", **ALL_SECRETS)
    r = api.put(f"/api/switches/{sid}", json=body(host="198.51.100.201", ssh_user="manager"))
    assert r.json() == {"ok": True, "cleared": list(main.SECRET_FIELDS)}
    assert all(stored(tmp_path, sid)[k] is None for k in main.SECRET_FIELDS)
    api.post(f"/api/switches/{sid}/test")
    assert sessions.hosts == [] and not any("s3cret" in str(c) for c in snmp_creds)


def test_a_resubmitted_secret_moves_with_the_host(api, tmp_path):            # Review Focus 3
    sid = create(api, host="203.0.113.21", **ALL_SECRETS)
    r = api.put(f"/api/switches/{sid}", json=body(host="198.51.100.201", ssh_pass="neu-ssh"))
    assert r.json()["cleared"] == [k for k in main.SECRET_FIELDS if k != "ssh_pass"]
    assert crypto.decrypt(stored(tmp_path, sid)["ssh_pass"]) == "neu-ssh"


@pytest.mark.parametrize("old, new", [("SW-01.Example.org", "sw-01.example.org"), ("fe80::21", "FE80:0:0:0:0:0:0:21")])
def test_same_host_in_another_spelling_keeps_everything(api, old, new):
    sid = create(api, host=old, **ALL_SECRETS)
    assert api.put(f"/api/switches/{sid}", json=body(host=new)).json() == {"ok": True, "cleared": []}


def test_the_audit_names_the_new_host_first_and_each_cleared_secret(api, tmp_path):
    sid = create(api, host="203.0.113.21", ssh_user="manager", ssh_pass="ssh-s3cret", snmp_community="ro-s3cret")
    api.put(f"/api/switches/{sid}", json=body(host="198.51.100.201", ssh_user="manager", ssh_pass="neu-ssh"))
    assert audits(tmp_path)[-1] == ("switch_update", "198.51.100.201", "host: 203.0.113.21 → 198.51.100.201, snmp_community, ssh_pass")
    api.put(f"/api/switches/{sid}", json=body(host="198.51.100.201", ssh_user="manager"))
    assert audits(tmp_path)[-1] == ("switch_update", "198.51.100.201", "")


def test_an_unchanged_destination_keeps_its_secrets_and_still_gets_them(api, outbound, snmp_creds, sessions):
    """The positive control of the tests above: with every destination as it was nothing is cleared, and the recorders see what goes
    out, so an empty recorder above means that nothing went out."""
    dests = {"opnsense_url": "https://fw.example", "pf_url": "https://pf.example:9999", "pf_user": "svc"}
    put_settings(api, **dests, opnsense_key="k-s3cret", opnsense_secret="s-s3cret", pf_pass="pf-s3cret")
    assert put_settings(api, **dests) == {"ok": True, "cleared": []}
    assert api.post("/api/pf/test").json()["ok"] is True
    assert api.post("/api/names/refresh").json()["ok"] is True
    assert outbound == ["https://pf.example:9999/api/v1/login", "https://pf.example:9999/api/v1/node_categories",
                        "https://fw.example/api/diagnostics/interface/getArp"]
    sid = create(api, host="203.0.113.21", ssh_user="manager", **ALL_SECRETS)
    assert api.put(f"/api/switches/{sid}", json=body(host="203.0.113.21", ssh_user="manager")).json() == {"ok": True, "cleared": []}
    api.post(f"/api/switches/{sid}/test")
    assert [c["snmp_community"] for c in snmp_creds] == ["ro-s3cret"]
    assert sessions.hosts == ["203.0.113.21"]


@pytest.mark.parametrize("old, new, same", [
    ("203.0.113.21", "203.0.113.21", True), ("fe80::21", "FE80:0:0:0:0:0:0:21", True), ("SW-01.Example.org", "sw-01.example.org", True),
    ("https://pf.example:9999", "https://PF.example:9999/", True), ("", None, True), (None, None, True),
    ("203.0.113.21", "203.0.113.22", False), ("fe80::1%eth0", "fe80::1", False), ("https://pf.example:9999", "https://pf.example:9998", False),
    ("http://pf.example", "https://pf.example", False), ("", "https://pf.example", False), ("https://pf.example", "", False),
])
def test_same_destination(old, new, same):
    assert main.same_destination(old, new) is same


# ── Concurrent PUTs ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_concurrent_puts_audit_a_consistent_chain(api, api_async, tmp_path):   # Phase 1 leftover: the audit race
    sid = create(api, snmp_write=True, snmp_rw_user="x")
    await asyncio.gather(*(api_async.put(f"/api/switches/{sid}", json=body(snmp_write=True, snmp_rw_user=u)) for u in "ab"))
    details = {d for action, _, d in audits(tmp_path) if action == "switch_update"}
    assert details in ({"snmp_rw_user: x → a", "snmp_rw_user: a → b"}, {"snmp_rw_user: x → b", "snmp_rw_user: b → a"})


# ── R48: the read identity's protocols ────────────────────────────────────────────────────────────────────────────────────────────
def test_read_identity_protocols_are_audited(api):                            # R48
    sid = create(api, snmp_version="3", snmp_user="mon", snmp_auth_proto="SHA")
    api.put(f"/api/switches/{sid}", json=body(snmp_version="3", snmp_user="mon", snmp_auth_proto="SHA-256"))
    assert "snmp_auth_proto: SHA → SHA-256" in last_audit_detail()


# ── §6 (a): the RADIUS server's zone id ───────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("server", ["fe80::1%\nradius-server host 6.6.6.6 key x", "fe80::1%eth0"])
def test_radius_server_with_a_scope_id_is_refused(api, server):              # §6 (a), the audit's input
    assert api.put("/api/settings", json=settings_body(radius_server=server)).status_code == 422


def test_radius_server_is_stored_canonical(api):
    put_settings(api, radius_server="FE80::1")
    assert api.get("/api/settings").json()["radius_server"] == "fe80::1"


def test_plan_prepare_refuses_a_stored_scope_id(sample_running_config):
    plan = changes.plan_prepare(parse_config(sample_running_config), {"server": "fe80::1%eth0", "key": "S3cretKey1"})
    assert plan["commands"] == [] and plan["blocked"]
