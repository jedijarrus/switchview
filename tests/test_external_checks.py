"""Phase 3, other systems and inputs: what PacketFence and OPNsense answer is checked, device data is validated, sessions are pruned.

- PacketFence (Review §5): a failed re-evaluation (CoA) after a node write is a hint at the device (pf_state "ok", the hint in
  pf_error), not an error: the release stands in PacketFence, only the switch-over waits for the device's next login. Deleting a
  device needs PacketFence to confirm reading and unregistering its node; otherwise the device stays (502). A failed CoA after a
  confirmed unregister still deletes and answers with a warning.
- OPNsense (Review §4): an ARP answer that is no list of entries is an error; an entry of an odd shape is skipped and counted, it never
  stops the refresh. What the old filter dropped in silence (a MAC that is not 17 characters, no IP) still goes without a count.
- Devices (Review §4, Baseline L9): "valid until" must be a calendar date (null and "" stay "no expiry date"); a PUT whose body names
  another MAC than its path is a 422.
- Sessions (Review §5): expired sessions are deleted hourly by the scheduler and once at the start, not only at a login.

No network: pf's and names' HTTP clients are fakes (apifix.fake_httpx) that answer per (method, path), the reverse DNS lookup of names is
replaced, the scheduler never starts. Each test gets its own database under tmp_path, set up by the app's own init_db. Expected
messages are written out by hand.
"""
import asyncio
import logging
import secrets
from datetime import datetime, timezone

import pytest

import apifix
import approvals
import auth
import crypto
import db
import dbfix
import main
import names
import pf

MAC = "aa:bb:cc:dd:ee:ff"
# What the fake PacketFence answers besides its status: a login token and the one role "default"; every other request an empty object
PF_ANSWERS = {("POST", "/login"): {"token": "t"}, ("GET", "/node_categories"): {"items": [{"category_id": 1, "name": "default"}]}}


@pytest.fixture
def database(tmp_path, monkeypatch):
    """A fresh database under tmp_path, set up by the app's own init_db."""
    apifix.fresh_db(tmp_path, monkeypatch)


@pytest.fixture
def api(database, monkeypatch):
    """A TestClient on main.app (no lifespan, scheduler booby-trapped) on database, signed in as apifix.USER."""
    with apifix.signed_in(monkeypatch) as client:
        yield client


class PacketFence(apifix.Remote):
    """The fake PacketFence: answers with PF_ANSWERS, else an empty object."""

    def reply(self, method: str, path: str):
        return PF_ANSWERS.get((method, path), {})


class OPNsense(apifix.Remote):
    """The fake OPNsense: answers every request with answer (the ARP table, an empty list unless set)."""

    def __init__(self):
        super().__init__()
        self.answer = []

    def reply(self, method: str, path: str):
        return self.answer


@pytest.fixture
def pfenv(database, monkeypatch) -> PacketFence:
    """PacketFence set up (address, user, encrypted password) and the released device MAC with role "default"; pf.httpx replaced by
    apifix.fake_httpx on a PacketFence."""
    for k, v in {"pf_url": "https://pf.example", "pf_user": "svc", "pf_pass": crypto.encrypt("pf-s3cret")}.items():
        asyncio.run(db.set_setting(k, v))
    dbfix.query("INSERT INTO devices(mac, name, kind, role, allowed) VALUES (?, 'Drucker', 'drucker', 'default', 1)", (MAC,))
    remote = PacketFence()
    monkeypatch.setattr(pf, "httpx", apifix.fake_httpx(remote))
    return remote


@pytest.fixture
def arp(database, monkeypatch) -> OPNsense:
    """OPNsense set up (address, encrypted key and secret); names.httpx replaced by apifix.fake_httpx on an OPNsense, and the reverse
    DNS lookup by one that finds no name (no network)."""
    for k, v in {"opnsense_url": "https://fw.example", "opnsense_key": crypto.encrypt("k"), "opnsense_secret": crypto.encrypt("s")}.items():
        asyncio.run(db.set_setting(k, v))
    remote = OPNsense()
    monkeypatch.setattr(names, "httpx", apifix.fake_httpx(remote))

    async def no_name(ip):
        return ""

    monkeypatch.setattr(names, "_ptr", no_name)
    return remote


def device_row() -> dict | None:
    conn = dbfix.connect()
    try:
        row = conn.execute("SELECT * FROM devices WHERE mac = ?", (MAC,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def device(**fields) -> dict:
    """The body of POST/PUT /api/devices as the device form sends it."""
    return {"mac": MAC, "name": "Drucker", "kind": "drucker", "location": "", "owner": "", "notes": "", "role": "default",
            "allowed": True, "valid_until": None} | fields


def insert_session(expires: str) -> None:
    dbfix.query("INSERT INTO sessions(token, username, display_name, method, created_at, expires_at) VALUES (?,?,?,?,?,?)",
                (db.token_hash(secrets.token_urlsafe(32)), "admin", "admin", "local", datetime.now(timezone.utc).isoformat(), expires))


def count_sessions() -> int:
    return dbfix.query("SELECT count(*) FROM sessions")[0][0]


# ── PacketFence: the re-evaluation (CoA) and the unregister are checked ───────────────────────────────────────────────────────────
async def test_a_failed_coa_is_a_hint_on_the_device(pfenv):
    pfenv.status[("POST", "/node/aa:bb:cc:dd:ee:ff/reevaluate_access")] = 500
    assert (await pf.sync(["aa:bb:cc:dd:ee:ff"]))["ok"] is True
    assert device_row()["pf_state"] == "ok"
    assert device_row()["pf_error"].startswith("Freigabe übertragen, aber Neubewertung (CoA) fehlgeschlagen: HTTP 500")


async def test_the_whole_coa_hint(pfenv):
    pfenv.status[("POST", "/node/aa:bb:cc:dd:ee:ff/reevaluate_access")] = 403
    await pf.sync(["aa:bb:cc:dd:ee:ff"])
    assert device_row()["pf_error"] == ("Freigabe übertragen, aber Neubewertung (CoA) fehlgeschlagen: HTTP 403 – das Gerät schaltet erst "
                                        "bei der nächsten Anmeldung um")


async def test_a_good_coa_leaves_no_hint(pfenv):
    """Positive control: the CoA goes out after the node write, and a 2xx answer clears an older hint."""
    dbfix.query("UPDATE devices SET pf_state = 'ok', pf_error = 'alter Hinweis'")
    pfenv.status[("POST", "/node/aa:bb:cc:dd:ee:ff/reevaluate_access")] = 204
    assert await pf.sync(["aa:bb:cc:dd:ee:ff"]) == {"ok": True, "done": 1, "failed": 0}
    assert (device_row()["pf_state"], device_row()["pf_error"]) == ("ok", None)
    assert pfenv.calls[-2:] == [("PATCH", "/node/aa:bb:cc:dd:ee:ff"), ("POST", "/node/aa:bb:cc:dd:ee:ff/reevaluate_access")]


async def test_a_failed_node_write_is_still_an_error(pfenv):
    pfenv.status[("PATCH", "/node/aa:bb:cc:dd:ee:ff")] = 500
    assert (await pf.sync(["aa:bb:cc:dd:ee:ff"]))["ok"] is False
    assert device_row()["pf_state"] == "fehler" and device_row()["pf_error"].startswith("Node schreiben: HTTP 500")
    assert ("POST", "/node/aa:bb:cc:dd:ee:ff/reevaluate_access") not in pfenv.calls


@pytest.mark.parametrize("key, code", [(("GET", "/node/aa:bb:cc:dd:ee:ff"), 500), (("PATCH", "/node/aa:bb:cc:dd:ee:ff"), 403)])
def test_an_unconfirmed_unregister_keeps_the_device(api, pfenv, key, code):
    pfenv.status[key] = code
    assert api.delete("/api/devices/aa:bb:cc:dd:ee:ff").status_code == 502 and device_row() is not None


@pytest.mark.parametrize("key, code, error", [(("GET", "/node/aa:bb:cc:dd:ee:ff"), 500, "Node lesen: HTTP 500"),
                                              (("PATCH", "/node/aa:bb:cc:dd:ee:ff"), 403, "Node zurücknehmen: HTTP 403 answer 403")])
async def test_unregister_names_what_packetfence_did_not_confirm(pfenv, key, code, error):
    pfenv.status[key] = code
    with pytest.raises(RuntimeError) as e:
        await pf.unregister(MAC)
    assert str(e.value) == error


def test_a_failed_coa_after_unregister_still_deletes_and_warns(api, pfenv):
    pfenv.status[("POST", "/node/aa:bb:cc:dd:ee:ff/reevaluate_access")] = 500
    r = api.delete("/api/devices/aa:bb:cc:dd:ee:ff").json()
    assert r["ok"] is True
    assert r["warning"] == "In PacketFence zurückgenommen, aber Neubewertung (CoA) fehlgeschlagen: HTTP 500" and device_row() is None


@pytest.mark.parametrize("node_status, calls", [(200, [("PATCH", "/node/aa:bb:cc:dd:ee:ff"), ("POST", "/node/aa:bb:cc:dd:ee:ff/reevaluate_access")]),
                                                (404, [])])
def test_a_confirmed_unregister_deletes_without_a_warning(api, pfenv, node_status, calls):
    """Positive control: the node unregistered and re-evaluated, or one PacketFence does not know (404): deleted, no warning."""
    pfenv.status[("GET", "/node/aa:bb:cc:dd:ee:ff")] = node_status
    assert api.delete("/api/devices/aa:bb:cc:dd:ee:ff").json() == {"ok": True, "warning": None} and device_row() is None
    assert pfenv.calls[pfenv.calls.index(("GET", "/node/aa:bb:cc:dd:ee:ff")) + 1:] == calls


def test_a_delete_without_packetfence_has_no_warning(api):
    dbfix.query("INSERT INTO devices(mac, name) VALUES (?, 'Drucker')", (MAC,))
    assert api.delete("/api/devices/aa:bb:cc:dd:ee:ff").json() == {"ok": True, "warning": None}


# ── OPNsense: an odd answer is an error, an odd entry is skipped ──────────────────────────────────────────────────────────────────
async def test_odd_arp_entries_are_skipped_not_fatal(arp):
    arp.answer = [{"mac": "AA:BB:CC:DD:EE:01", "ip": "10.0.0.5", "hostname": "pc"}, "garbage", {"mac": 7, "ip": "10.0.0.6"}]
    assert await names.refresh_names() == {"ok": True, "entries": 1, "skipped": 2}
    assert dbfix.query("SELECT mac, ip, name FROM names") == [("aa:bb:cc:dd:ee:01", "10.0.0.5", "pc")]


async def test_an_arp_answer_without_a_list_is_an_error(arp):
    arp.answer = {"rows": "nope"}
    assert await names.refresh_names() == {"ok": False, "error": "OPNsense-Antwort unerwartet: keine Liste von ARP-Einträgen"}


@pytest.mark.parametrize("answer", [{"total": 0}, "rows", 7, None])
async def test_any_answer_that_is_no_list_is_an_error(arp, answer):
    arp.answer = answer
    assert (await names.refresh_names())["error"] == "OPNsense-Antwort unerwartet: keine Liste von ARP-Einträgen"


async def test_the_rows_of_an_arp_answer_are_its_entries(arp):
    arp.answer = {"rows": [{"mac": "AA:BB:CC:DD:EE:01", "ip": "10.0.0.5", "hostname": "pc.example.lan", "manufacturer": "ACME"}]}
    assert await names.refresh_names() == {"ok": True, "entries": 1, "skipped": 0}
    assert dbfix.query("SELECT mac, ip, name, vendor FROM names") == [("aa:bb:cc:dd:ee:01", "10.0.0.5", "pc", "ACME")]


@pytest.mark.parametrize("entry", [["AA:BB:CC:DD:EE:01", "10.0.0.5"], {"mac": "AA:BB:CC:DD:EE:01", "ip": 10},
                                   {"mac": "AA:BB:CC:DD:EE:01", "ip": "10.0.0.5", "hostname": 5},
                                   {"mac": "AA:BB:CC:DD:EE:01", "ip": "10.0.0.5", "manufacturer": ["ACME"]}])
async def test_each_odd_shape_is_skipped(arp, entry, caplog):
    arp.answer = [entry]
    with caplog.at_level(logging.WARNING, logger="switchview.names"):
        assert await names.refresh_names() == {"ok": True, "entries": 0, "skipped": 1}
    assert [r.getMessage() for r in caplog.records] == ["OPNsense-ARP: 1 von 1 Einträgen übersprungen (unerwartete Form)"]


async def test_what_the_old_filter_dropped_is_not_counted(arp, caplog):
    """A MAC that is not 17 characters, no IP (missing, null or empty): dropped in silence as before; missing or null names are fine."""
    arp.answer = [{"mac": "aa:bb", "ip": "10.0.0.1"}, {"mac": "AA:BB:CC:DD:EE:02", "ip": ""}, {"mac": "AA:BB:CC:DD:EE:03"},
                  {"mac": None, "ip": "10.0.0.4"}, {"mac": "AA:BB:CC:DD:EE:05", "ip": None},
                  {"mac": "AA:BB:CC:DD:EE:06", "ip": "10.0.0.6", "hostname": None, "manufacturer": None}]
    with caplog.at_level(logging.WARNING, logger="switchview.names"):
        assert await names.refresh_names() == {"ok": True, "entries": 1, "skipped": 0}
    assert caplog.records == []


# ── Devices: a real date, the MAC of the path ─────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("value", ["2026-13-45", "0000-00-00", "2026-02-30"])
def test_valid_until_must_be_a_date(api, value):
    assert api.post("/api/devices", json=device(valid_until=value)).status_code == 422


def test_an_impossible_date_is_named(api):
    r = api.post("/api/devices", json=device(valid_until="2026-02-30"))
    assert (r.status_code, r.json()["detail"]) == (422, "Gültig bis: kein gültiges Datum (JJJJ-MM-TT)") and device_row() is None


@pytest.mark.parametrize("value, stored", [(None, None), ("", None), ("2028-02-29", "2028-02-29")])
def test_no_date_or_a_real_one_is_kept(api, value, stored):
    assert api.post("/api/devices", json=device(valid_until=value)).status_code == 200
    assert device_row()["valid_until"] == stored
    assert api.put("/api/devices/aa:bb:cc:dd:ee:ff", json=device(valid_until=value)).status_code == 200


def test_a_put_with_another_mac_in_the_body_is_422(api):
    r = api.put("/api/devices/aa:bb:cc:dd:ee:ff", json=device(mac="aa:bb:cc:dd:ee:00"))
    assert (r.status_code, r.json()["detail"]) == (422, "MAC-Adresse im Formular passt nicht zum Gerät")


def test_a_put_with_the_same_mac_in_another_spelling_is_fine(api):
    assert api.post("/api/devices", json=device(allowed=False)).status_code == 200
    r = api.put("/api/devices/aa:bb:cc:dd:ee:ff", json=device(mac="AA-BB-CC-DD-EE-FF", name="Drucker 2"))
    assert r.status_code == 200 and device_row()["name"] == "Drucker 2"


# ── Sessions: pruned hourly and at the start ──────────────────────────────────────────────────────────────────────────────────────
async def test_expired_sessions_are_pruned_without_a_login(api):
    insert_session(expires="2000-01-01T00:00:00+00:00")
    insert_session(expires="2999-01-01T00:00:00+00:00")
    assert await auth.prune_sessions() == 1 and count_sessions() == 1


def test_the_scheduler_prunes_sessions_hourly(api, monkeypatch):
    jobs = {}
    monkeypatch.setattr(main.scheduler, "add_job", lambda func, trigger, **kw: jobs.__setitem__(kw["id"], (func, trigger, kw)))
    asyncio.run(main._schedule())
    assert jobs["sessions"][0] is auth.prune_sessions and jobs["sessions"][1] == "interval" and jobs["sessions"][2]["minutes"] == 60


def test_the_scheduler_expires_requests(api, monkeypatch):
    """Phase 4a, Task 6: open four-eyes requests past their time are marked expired every 10 minutes (and before every read of one)."""
    jobs = {}
    monkeypatch.setattr(main.scheduler, "add_job", lambda func, trigger, **kw: jobs.__setitem__(kw["id"], (func, trigger, kw)))
    asyncio.run(main._schedule())
    assert jobs["approvals"][0] is approvals.expire_due and jobs["approvals"][1] == "interval" and jobs["approvals"][2]["minutes"] == 10


async def test_the_start_prunes_sessions(database, monkeypatch):
    """lifespan prunes once, right after init_db; the scheduler's start and stop are no-ops here (no job ever runs)."""
    for name in ("add_job", "start", "shutdown"):
        monkeypatch.setattr(main.scheduler, name, lambda *args, **kwargs: None)
    insert_session(expires="2000-01-01T00:00:00+00:00")
    insert_session(expires="2999-01-01T00:00:00+00:00")
    async with main.lifespan(main.app):
        assert count_sessions() == 1
