"""Phase 3 Task 5: what a change did to its switch, recorded in changes.sent, and what that allows afterwards.

  * changes.sent: NULL for a row from before the column (unknown), 0 while nothing has gone out, 1 from the moment the switch may have
    taken something (right before send_config_set / write memory over SSH, right before the SET over SNMP). An exception after that
    point ends the change "unclear", not "failed", like the SNMP way: the commands can be in effect (netmiko's ReadTimeout from
    send_config_set, say).
  * changes.actions_of(ch): the two follow-up actions the UI offers, decided in one place. "Rückgängig" (can_revert) for a port change
    that ended ok / unclear / failed, is not reverted and may have sent something; "Trotzdem speichern" (can_save) for an SSH change
    (NULL = SSH) that ended unclear / failed, is not saved and may have sent something. A row from before the column counts as sent.
  * changes.mark_interrupted(): at start, a change left queued or running by the last process ends "aborted" when it never sent
    anything, otherwise "unclear" as before.

No network, no switch: run_change talks to the fake ProCurve of ssh_env (tests/sshfix.py), each test gets its own database under
tmp_path, set up by the app's own init_db.
"""
import pytest
from netmiko.exceptions import ConfigInvalidException, ReadTimeout

import changes
import main
import sshfix
from cfgparse import parse_config
from dbfix import connect
from sshfix import SshEnv


async def run_ports(env: SshEnv, req: dict) -> int:
    """The port change req of env's ProCurve, planned on sshfix.RUNNING (the inventory lists exactly the ports of req, no uplinks),
    created and run to its end by run_change; its id."""
    port_inv = {"ports": {p: {"tr": "", "l": [], "o": False} for p in req["ports"]}, "uplinks": set()}

    async def inventory(sid):
        return port_inv

    plan = changes.plan_ports("", port_inv, parse_config(sshfix.RUNNING), req)
    assert plan["blocked"] == [] and plan["commands"], plan
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(changes, "inventory", inventory)
        cid = await changes.create_change(env.sid, "tester", "ports", "Port-Änderung", req, plan)
        await changes.run_change(cid)
    return cid


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
    real = sshfix.FakeSSH.send_config_set

    def send_and_take(self, commands, **kwargs):
        out = real(self, commands, **kwargs)
        self.env.running = sshfix.RUNNING + "interface 2\n   disable\n   exit\n"
        return out

    monkeypatch.setattr(sshfix.FakeSSH, "send_config_set", send_and_take)
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
