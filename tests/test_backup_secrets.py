"""Phase 3, backups (Review §5): a change of secrets alone gets a backup of its own, and "Speichern" names the state it saved.

A backup is stored masked (sshcli.store_backup), so its sha (the SHA-256 of the masked text) is blind to a changed secret: before
Phase 3 a new RADIUS key or SNMP passphrase never made a new backup. Now each row also carries raw_mac, an HMAC of the unmasked
text under a key derived from SECRET_KEY (crypto.keyed_digest): it tells a changed secret apart without being an oracle for one, as
a plain hash next to the masked text would be for anyone holding a copy of the database. Reading for a preview (trigger "lesen", up
to every 600 s) compares the masked text only, so firmware that salts its encrypted secrets anew on every read never makes a backup
per preview. A row from before Phase 3 (raw_mac NULL) gets its mark from the first backup of the same masked text, without a new row.
The diff of two rows whose masked texts are equal says that only masked secrets changed. The audit of a save change names the
state it saved: the start of the sha of the backup "vor #id" (or of the equal one before it).

No network, no switch: store_backup is called directly, run_change talks to the fake ProCurve of ssh_env. Each test gets its own
database under tmp_path, set up by the app's own init_db.
"""
import asyncio
import hashlib
import hmac

import pytest

import apifix
import cfgparse
import changes
import config
import crypto
import main
import sshcli
import sshfix
from dbfix import connect, insert_switch, query

CONFIG_A = ('hostname "SW-EK-01"\nradius-server host 10.0.0.1 key "alt-Schluessel1"\nvlan 1\n   name "DEFAULT_VLAN"\n   untagged 1-24\n'
            "   exit\n")
CONFIG_B = CONFIG_A.replace("alt-Schluessel1", "neu-Schluessel2")    # the same configuration with another RADIUS key


@pytest.fixture
def world(tmp_path, monkeypatch) -> int:
    """A fresh database under tmp_path with the ProCurve of sshfix.procurve; its id."""
    apifix.fresh_db(tmp_path, monkeypatch)
    return insert_switch(**sshfix.procurve())


@pytest.fixture
def api(world, monkeypatch):
    """A TestClient on main.app (no lifespan, scheduler booby-trapped) on world's database, signed in as apifix.USER."""
    with apifix.signed_in(monkeypatch) as client:
        yield client


def backups() -> dict[int, int]:
    """The number of config_backups rows per switch_id."""
    return {sid: n for sid, n in query("SELECT switch_id, count(*) FROM config_backups GROUP BY switch_id")}


def old_row(sid: int, content: str, raw_mac: str | None) -> int:
    """A config_backups row as Phase 2 stored it: content as given (masked by the caller), its sha, raw_mac as given; its id."""
    conn = connect()
    try:
        cur = conn.execute("INSERT INTO config_backups(switch_id, taken_at, sha, content, trigger, raw_mac) VALUES (?, datetime('now'), ?, ?, ?, ?)",
                           (sid, hashlib.sha256(content.encode()).hexdigest(), content, "nightly", raw_mac))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def mark_of_last(sid: int) -> str | None:
    return query("SELECT raw_mac FROM config_backups WHERE switch_id = ? ORDER BY id DESC LIMIT 1", (sid,))[0][0]


def last_audit_detail() -> str:
    return query("SELECT detail FROM audit ORDER BY id DESC LIMIT 1")[0][0]


async def save_change(env) -> int:
    """A "Speichern" change on env's switch as main creates it (nothing to send), run to its end; its id."""
    cid = await changes.create_change(env.sid, "tester", "save", "Speichern", {},
                                      {"shown": [], "desired": {}, "before": {}, "mechanism": "ssh"})
    await changes.run_change(cid)
    return cid


# ── A change of secrets alone ─────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_a_secret_only_change_gets_a_new_backup(world):
    sid = world
    assert await sshcli.store_backup(sid, CONFIG_A, "nightly") is True and await sshcli.store_backup(sid, CONFIG_B, "nightly") is True
    assert await sshcli.store_backup(sid, CONFIG_B, "nightly") is False and backups() == {sid: 2}


async def test_each_row_is_masked_and_carries_the_mark_of_its_text(world):
    sid = world
    await sshcli.store_backup(sid, CONFIG_B, "manual")
    (content, sha, mark), = query("SELECT content, sha, raw_mac FROM config_backups")
    assert "Schluessel" not in content and sha == hashlib.sha256(content.encode()).hexdigest()
    assert mark == crypto.keyed_digest("backup", CONFIG_B) != crypto.keyed_digest("backup", CONFIG_A)


async def test_reading_for_a_preview_never_stores_a_secret_only_change(world):
    sid = world
    await sshcli.store_backup(sid, CONFIG_A, "nightly")
    assert await sshcli.store_backup(sid, CONFIG_B, "lesen") is False


async def test_a_secret_change_a_preview_saw_first_is_kept_by_the_next_backup(world):
    """The preview leaves the last row's mark as it is, so the next nightly backup still sees the change."""
    sid = world
    await sshcli.store_backup(sid, CONFIG_A, "nightly")
    await sshcli.store_backup(sid, CONFIG_B, "lesen")
    assert mark_of_last(sid) == crypto.keyed_digest("backup", CONFIG_A)
    assert await sshcli.store_backup(sid, CONFIG_B, "nightly") is True and backups() == {sid: 2}


async def test_a_preview_still_stores_a_change_of_the_masked_text(world):
    sid = world
    await sshcli.store_backup(sid, CONFIG_A, "nightly")
    assert await sshcli.store_backup(sid, CONFIG_A.replace("SW-EK-01", "SW-EK-02"), "lesen") is True and backups() == {sid: 2}


@pytest.mark.parametrize("trigger", ["vor #7", "nach #7", "manual"])
async def test_the_other_triggers_see_a_secret_only_change(world, trigger):
    sid = world
    await sshcli.store_backup(sid, CONFIG_A, "nightly")
    assert await sshcli.store_backup(sid, CONFIG_B, trigger) is True


async def test_an_old_backup_gets_its_mark_without_a_new_row(world):           # Review Focus 1
    sid = world
    old_row(sid, cfgparse.mask_secrets(CONFIG_A), raw_mac=None)
    assert await sshcli.store_backup(sid, CONFIG_A, "nightly") is False and backups() == {sid: 1}
    assert mark_of_last(sid) == crypto.keyed_digest("backup", CONFIG_A)


async def test_after_its_mark_an_old_backup_sees_the_next_secret_change(world):
    sid = world
    old_row(sid, cfgparse.mask_secrets(CONFIG_A), raw_mac=None)
    await sshcli.store_backup(sid, CONFIG_A, "lesen")                          # a preview read marks it as well
    assert backups() == {sid: 1} and mark_of_last(sid) == crypto.keyed_digest("backup", CONFIG_A)
    assert await sshcli.store_backup(sid, CONFIG_B, "nightly") is True and backups() == {sid: 2}


def test_the_mark_is_keyed():
    assert crypto.keyed_digest("backup", "x") != hashlib.sha256(b"x").hexdigest()
    assert crypto.keyed_digest("backup", "x") != crypto.keyed_digest("other", "x")


def test_the_mark_is_the_hmac_the_interface_names():
    key = hashlib.sha256(b"switchview:backup:" + config.settings.secret_key.encode()).digest()
    assert crypto.keyed_digest("backup", "Schlüssel \ud800") == hmac.new(key, "Schlüssel \ud800".encode("utf-8", "surrogatepass"),
                                                                        hashlib.sha256).hexdigest()


# ── The diff of a secret-only change ──────────────────────────────────────────────────────────────────────────────────────────────
def test_the_diff_of_a_secret_only_change_says_so(api, world):
    asyncio.run(sshcli.store_backup(world, CONFIG_A, "nightly"))
    asyncio.run(sshcli.store_backup(world, CONFIG_B, "nightly"))
    b = query("SELECT max(id) FROM config_backups")[0][0]
    assert api.get(f"/api/backups/{b}/diff").text == main.SECRET_ONLY_DIFF


def test_the_diff_of_another_change_is_still_a_diff(api, world):
    asyncio.run(sshcli.store_backup(world, CONFIG_A, "nightly"))
    asyncio.run(sshcli.store_backup(world, CONFIG_B.replace("SW-EK-01", "SW-EK-02"), "nightly"))
    b = query("SELECT max(id) FROM config_backups")[0][0]
    diff = api.get(f"/api/backups/{b}/diff").text
    assert '-hostname "SW-EK-01"' in diff and '+hostname "SW-EK-02"' in diff and "Schluessel" not in diff


# ── The audit of "Speichern" names the state it saved ─────────────────────────────────────────────────────────────────────────────
async def test_save_audits_the_state_it_saved(ssh_env):
    cid = await save_change(ssh_env)
    pre = sshcli.clean(sshfix.RUNNING)
    assert last_audit_detail() == f"#{cid} Speichern, Stand {hashlib.sha256(cfgparse.mask_secrets(pre).encode()).hexdigest()[:12]}"


async def test_the_audited_state_is_the_start_of_the_backup_sha(ssh_env):
    """With a secret in the running-config: the state is that of the masked backup "vor #id", never a hash of the unmasked text."""
    ssh_env.running = CONFIG_A
    cid = await save_change(ssh_env)
    (sha,), = query("SELECT sha FROM config_backups WHERE trigger = ?", (f"vor #{cid}",))
    stand = last_audit_detail().rpartition("Stand ")[2]
    assert len(stand) == 12 and sha.startswith(stand) and not hashlib.sha256(sshcli.clean(CONFIG_A).encode()).hexdigest().startswith(stand)


async def test_a_save_without_a_read_names_no_state(ssh_env):
    ssh_env.on_connect = OSError("keine Verbindung")
    cid = await save_change(ssh_env)
    assert last_audit_detail() == f"#{cid} Speichern"


async def test_other_changes_name_no_state(ssh_env):
    cid = await ssh_env.run_prepare(radius_server="10.0.0.1", radius_key="S3cretKey1")
    assert last_audit_detail() == f"#{cid} RADIUS vorbereiten"


def test_backup_sha_takes_a_lone_surrogate_and_keeps_every_valid_sha():
    text = "hostname \"SW-ä\"\nvlan 20\n"
    assert sshcli.backup_sha(text) == hashlib.sha256(cfgparse.mask_secrets(text).encode()).hexdigest()
    assert len(sshcli.backup_sha("hostname x\ud800\n")) == 64
