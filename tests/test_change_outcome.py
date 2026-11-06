"""Phase 3 Task 5: what a change did to its switch, recorded in changes.sent, and what that allows afterwards.

  * changes.sent: NULL for a row from before the column (unknown), 0 while nothing has gone out, 1 from the moment the switch may have
    taken something (right before send_config_set / write memory over SSH, right before the SET over SNMP). An exception after that
    point ends the change "unclear", not "failed", like the SNMP way: the commands can be in effect (netmiko's ReadTimeout from
    send_config_set, say); its last step says what that leaves open (changes.SSH_KEPT). A cancelled run ends the same way, with
    changes.CANCELLED. Only a revert that ends ok marks the change it took back (reverted_by).
  * changes.actions_of(ch): the two follow-up actions the UI offers, decided in one place. "Rückgängig" (can_revert) for a port change
    that ended ok / unclear / failed, is not reverted and may have sent something; "Trotzdem speichern" (can_save) for an SSH change
    (NULL = SSH) that ended unclear / failed, is not saved and may have sent something. A row from before the column counts as sent.
  * changes.mark_interrupted(): at start, a change left queued or running by the last process ends "aborted" when it never sent
    anything, otherwise "unclear" as before.

No network, no switch: run_change talks to the fake ProCurve of ssh_env (tests/sshfix.py), each test gets its own database under
tmp_path, set up by the app's own init_db.
"""
import asyncio
import json
import threading

import pytest
from netmiko.exceptions import ConfigInvalidException, ReadTimeout

import changes
import main
import sshcli
import sshfix
from cfgparse import parse_config
from dbfix import connect, query
from sshfix import SshEnv

# The ProCurve of sshfix.RUNNING once it took "interface 2 disable"
OFF = sshfix.RUNNING + "interface 2\n   disable\n   exit\n"
CANCELLED = "Abgebrochen (Prozess beendet)"
KEPT = "Was der Switch davon übernommen hat, wirkt schon, ist aber nicht dauerhaft gespeichert."


async def run_ports(env: SshEnv, req: dict, revert_of: int | None = None) -> int:
    """The port change req of env's ProCurve, planned on its running-config (env.running, sshfix.RUNNING unless the test changed it;
    the inventory lists exactly the ports of req, no uplinks), created (as the revert of change revert_of, if given) and run to its
    end by run_change; its id."""
    port_inv = {"ports": {p: {"tr": "", "l": [], "o": False} for p in req.get("ports") or req["desired"]}, "uplinks": set()}

    async def inventory(sid):
        return port_inv

    plan = changes.plan_ports("", port_inv, parse_config(env.running), req)
    assert plan["blocked"] == [] and plan["commands"], plan
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(changes, "inventory", inventory)
        cid = await changes.create_change(env.sid, "tester", "ports", "Port-Änderung", req, plan, revert_of=revert_of)
        await changes.run_change(cid)
    return cid


async def run_revert(env: SshEnv, of: int) -> int:
    """The revert of change `of` as /apply creates it (desired = its before, planned on the switch's running-config now), run to its
    end by run_change; its id."""
    return await run_ports(env, {"desired": json.loads(env.change(of)["before"]), "expert": False}, revert_of=of)


def switch_runs(monkeypatch, *texts: str):
    """FakeSSH.send_config_set: the switch takes the lines of its i-th call and runs texts[i] from then on; env.on_send, if set, is
    raised after that (the answer lost, or a line refused)."""
    left, real = list(texts), sshfix.FakeSSH.send_config_set

    def send(self, commands, **kwargs):
        self.env.running = left.pop(0)
        return real(self, commands, **kwargs)

    monkeypatch.setattr(sshfix.FakeSSH, "send_config_set", send)


async def until(cond):
    """Wait in steps of 10 ms, at most 5 s, for cond() to hold."""
    for _ in range(500):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not reached in 5 s")


def queued_change(env: SshEnv, sent: int | None) -> int:
    """A port change of env's switch left queued by a process that ended, with sent as given; its id."""
    conn = connect()
    try:
        cur = conn.execute("INSERT INTO changes(switch_id, username, kind, summary, commands, status, steps, sent) "
                           "VALUES (?, 'tester', 'ports', 'Port 2: Aus', '[]', 'queued', '[]', ?)", (env.sid, sent))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


async def test_an_exception_while_sending_is_unclear_not_failed(ssh_env):      # flow fix, the same cause as SNMP's `sent`
    ssh_env.on_send = ReadTimeout("Pattern not detected")
    row = ssh_env.change(await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}}))
    assert (row["status"], row["sent"]) == ("unclear", 1)


async def test_a_change_that_fails_before_sending_records_that(ssh_env):
    ssh_env.on_connect = RuntimeError("down")
    row = ssh_env.change(await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}}))
    assert (row["status"], row["sent"]) == ("failed", 0) and changes.actions_of(row) == {"can_revert": False, "can_save": False}


async def test_a_rejected_command_stays_failed_but_counts_as_sent(ssh_env):
    """ConfigInvalidException: the switch refused one line, the ones before it can be in effect; "failed" as before, with sent = 1, so
    revert and save stay on offer."""
    ssh_env.on_send = ConfigInvalidException("Invalid input: disable")
    row = ssh_env.change(await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}}))
    assert (row["status"], row["sent"]) == ("failed", 1) and changes.actions_of(row) == {"can_revert": True, "can_save": True}


async def test_a_change_that_ends_ok_has_sent(ssh_env, monkeypatch):
    """The switch takes the line (its read-back shows port 2 disabled): ok and saved, sent = 1; revert on offer, save not needed."""
    switch_runs(monkeypatch, OFF)
    row = ssh_env.change(await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}}))
    assert (row["status"], row["saved"], row["sent"], ssh_env.sent) == ("ok", 1, 1, [["interface 2 disable"]])
    assert changes.actions_of(row) == {"can_revert": True, "can_save": False}


async def test_an_exception_in_write_memory_is_unclear(ssh_env, monkeypatch):
    """A save sends no line, but write memory itself may have gone through when it raises: unclear, sent = 1."""
    def save_fails(self):
        raise ReadTimeout("Pattern not detected: write memory")

    monkeypatch.setattr(sshfix.FakeSSH, "save_config", save_fails)
    cid = await changes.create_change(ssh_env.sid, "tester", "save", "Speichern", {}, {"shown": [], "desired": {}, "before": {},
                                                                                         "mechanism": "ssh"})
    await changes.run_change(cid)
    row = ssh_env.change(cid)
    assert (row["status"], row["saved"], row["sent"], ssh_env.sent) == ("unclear", 0, 1, [])


@pytest.mark.parametrize("case, error, note", [
    ("send", "ReadTimeout: Pattern not detected", KEPT),
    ("read-back-differs", "Prüfung nach der Änderung passt nicht: ", KEPT),
    ("write-memory", "ReadTimeout: Pattern not detected: write memory", "Ob der Switch gespeichert hat (write memory), ist offen.")],
    ids=["send", "read-back-differs", "write-memory"])
async def test_an_unclear_ssh_change_says_what_is_open(ssh_env, monkeypatch, case, error, note):
    """Its last error step is its error plus what that leaves open (the progress dialog shows that step, as over SNMP): what the switch
    took of the lines is in effect but not saved (an exception while they went out, or a read-back that does not match), or, when
    write memory itself raised after the check, whether the switch saved."""
    def save_fails(self):
        raise ReadTimeout("Pattern not detected: write memory")

    switch_runs(monkeypatch, sshfix.RUNNING if case == "read-back-differs" else OFF)
    if case == "send":
        ssh_env.on_send = ReadTimeout("Pattern not detected")
    if case == "write-memory":
        monkeypatch.setattr(sshfix.FakeSSH, "save_config", save_fails)
    row = ssh_env.change(await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}}))
    assert (row["status"], row["sent"], row["saved"]) == ("unclear", 1, 0) and row["error"].startswith(error)
    assert json.loads(row["steps"])[-1][1:] == [f"{row['error']}. {note}", "error"]


@pytest.mark.parametrize("when", ["waiting-for-the-lock", "sending"])
async def test_a_cancelled_ssh_change_ends_by_whether_it_sent(ssh_env, monkeypatch, when):
    """The app shuts down (asyncio cancels the task). While the change waits for the switch's lock: failed, nothing went out. While
    send_config_set runs: the line may be out, so unclear, as over SNMP. Either way it ends with the reason, never "failed" without an
    error, and never stays running."""
    started, release = threading.Event(), threading.Event()

    def send_blocks(self, commands, **kwargs):
        self.env.sent.append(list(commands))
        started.set()
        release.wait(5)
        return ""

    monkeypatch.setattr(sshfix.FakeSSH, "send_config_set", send_blocks)
    lock = sshcli.lock(ssh_env.sid)
    if when == "waiting-for-the-lock":
        await lock.acquire()
    task = asyncio.create_task(run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}}))
    try:
        if when == "sending":
            await until(started.is_set)
        else:
            await until(lambda: "Warte auf laufende Aktion" in json.dumps(query("SELECT steps FROM changes")))
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        if when == "waiting-for-the-lock":
            lock.release()
    [(cid,)] = query("SELECT id FROM changes")
    row, sent = ssh_env.change(cid), when == "sending"
    assert (row["status"], row["error"], row["sent"], row["finished_at"] is not None) == ("unclear" if sent else "failed", CANCELLED,
                                                                                         int(sent), True)
    assert json.loads(row["steps"])[-1][1:] == [f"{CANCELLED}. {KEPT}" if sent else CANCELLED, "error"]
    assert ssh_env.sent == ([["interface 2 disable"]] if sent else [])


@pytest.mark.parametrize("after, on_send, status", [
    (sshfix.RUNNING, None, "ok"),
    (sshfix.RUNNING, ReadTimeout("Pattern not detected"), "unclear"),
    (OFF, ConfigInvalidException("Invalid input: enable"), "failed"),
    (OFF, None, "unclear")], ids=["ok", "answer-lost", "refused", "read-back-differs"])
async def test_only_an_ssh_revert_that_ends_ok_marks_the_change_reverted(ssh_env, monkeypatch, after, on_send, status):
    """Review §2 over SSH (run_change's end, _mark_reverted): the revert of port 2 "off" sends "interface 2 enable"; only when it ends
    ok does the change it takes back get reverted_by, and then no longer offers "Rückgängig". An unclear or failed revert leaves it
    revertable: another revert plans against a fresh read."""
    switch_runs(monkeypatch, OFF, after)
    cid = await run_ports(ssh_env, {"ports": ["2"], "set": {"status": "off"}})
    assert ssh_env.change(cid)["status"] == "ok"
    ssh_env.on_send = on_send
    rid = await run_revert(ssh_env, cid)
    assert (ssh_env.change(rid)["status"], ssh_env.change(rid)["revert_of"], ssh_env.sent[-1]) == (status, cid, ["interface 2 enable"])
    original = ssh_env.change(cid)
    assert (original["reverted_by"], changes.actions_of(original)["can_revert"]) == ((rid, False) if status == "ok" else (None, True))


@pytest.mark.parametrize("ch, flags", [
    (dict(kind="ports", status="ok", sent=1, mechanism="ssh", saved=1, reverted_by=None), (True, False)),
    (dict(kind="ports", status="failed", sent=1, mechanism="ssh", saved=0, reverted_by=None), (True, True)),
    (dict(kind="ports", status="failed", sent=0, mechanism="ssh", saved=0, reverted_by=None), (False, False)),
    (dict(kind="ports", status="unclear", sent=1, mechanism="snmp", saved=0, reverted_by=None), (True, False)),
    (dict(kind="ports", status="unclear", sent=1, mechanism="ssh", saved=0, reverted_by=7), (False, True)),
    (dict(kind="prepare", status="unclear", sent=1, mechanism="ssh", saved=0, reverted_by=None), (False, True)),
    (dict(kind="ports", status="aborted", sent=0, mechanism="ssh", saved=0, reverted_by=None), (False, False))])
def test_actions_follow_status_sent_and_way(ch, flags):
    assert tuple(changes.actions_of(ch).values()) == flags and list(changes.actions_of(ch)) == ["can_revert", "can_save"]


async def test_a_restart_aborts_what_never_went_out(ssh_env):
    a, b = queued_change(ssh_env, sent=0), queued_change(ssh_env, sent=1)
    assert await changes.mark_interrupted() == 2
    assert [ssh_env.change(i)["status"] for i in (a, b)] == ["aborted", "unclear"]


async def test_a_restart_says_why_and_keeps_rows_from_before_the_column_unclear(ssh_env):
    """The error names the restart (and, when nothing went out, that); a row from before the column (sent NULL) is unclear as before;
    a finished change is not touched."""
    a, b, old = queued_change(ssh_env, sent=0), queued_change(ssh_env, sent=1), queued_change(ssh_env, sent=None)
    done = queued_change(ssh_env, sent=0)
    conn = connect()
    try:
        conn.execute("UPDATE changes SET status = 'failed', error = 'down' WHERE id = ?", (done,))
        conn.execute("UPDATE changes SET status = 'running' WHERE id = ?", (b,))
        conn.commit()
    finally:
        conn.close()
    assert await changes.mark_interrupted() == 3
    rows = {i: ssh_env.change(i) for i in (a, b, old, done)}
    assert [(rows[i]["status"], rows[i]["error"], rows[i]["finished_at"] is not None) for i in (a, b, old)] == [
        ("aborted", "Abgebrochen durch Neustart von SwitchView, nichts gesendet", True),
        ("unclear", "Abgebrochen durch Neustart von SwitchView", True),
        ("unclear", "Abgebrochen durch Neustart von SwitchView", True)]
    assert (rows[done]["status"], rows[done]["error"]) == ("failed", "down")
    assert await changes.mark_interrupted() == 0


async def test_the_start_marks_interrupted_changes(ssh_env, monkeypatch):
    """lifespan runs mark_interrupted once, after init_db; the scheduler's start and stop are no-ops here (no job ever runs)."""
    for name in ("add_job", "start", "shutdown"):
        monkeypatch.setattr(main.scheduler, name, lambda *args, **kwargs: None)
    a, b = queued_change(ssh_env, sent=0), queued_change(ssh_env, sent=None)
    async with main.lifespan(main.app):
        assert [ssh_env.change(i)["status"] for i in (a, b)] == ["aborted", "unclear"]


def test_rows_from_before_the_sent_column_keep_revert_and_save():               # Review Focus 1
    old = {"kind": "ports", "status": "failed", "sent": None, "mechanism": None, "saved": 0, "reverted_by": None}
    assert changes.actions_of(old) == {"can_revert": True, "can_save": True}
