"""A change with confirmation (Phase 4c, Task 4): "Bestätigen" of a change that run_change left waiting (changes.PENDING), and its
route; and (Task 5) the watch over the waiting changes - their deadline, the reachability of their switch, the automatic revert.

The waiting change is the change's own row: "Bestätigen" takes it from pending over running to ok (saved) or unclear, one change with
one history in its steps. Who may confirm it: who started it or approved it, else anyone with Freigeben, always in their zones (an
API token too: a script with a health check of its own may confirm). Of two confirms at once exactly one wins, and one after the
deadline is too late: one UPDATE takes the row from pending to running only before confirm_until (its own second is the watch's).
Over SSH the confirm reads the running-config afresh in the switch's lock and saves (write memory) only when verify_ports still
finds the change there - minutes pass between the check and the save, and write memory saves everything that runs then; that save
is the one place outside changes.run_change that writes to a switch. Over SNMP it ends ok and unsaved, as every SNMP change of a
driver without snmp_autosave (the only driver that waits): SwitchView never saves over SNMP.

The watch (watch, a job of the one scheduler every CHECK_S seconds, its first run at the start; jobs._schedule) reads the waiting
changes from the database: a change past its deadline (confirm_until) is due at once, any other one is due when its switch did not
answer UNREACHABLE_AFTER checks in a row (reachable: sysUpTime over SNMP with the read identity; the misses are counted in the
process, _misses - a restart loses at most a miss, never a deadline); a disabled switch is not asked, only its deadline acts. A due
change is taken back as a normal revert (auto_revert): _make_plan of the revert for its preview token, then start_change as
AUTO_USER without a role, without a check of rights or four eyes; planning, the fresh read in the lock, the check and the save are
those of the guided loop. The revert goes in only if its INSERT is what ends the waiting (_claim_of): a confirm or a revert by hand
that ended it while the watch planned wins, and nothing of the watch is stored. A revert that cannot start - a disabled switch, a
refusal, any other error - ends the waiting unclear with a clear text, an audit and an alert, and is not tried again (_give_up).

Everything of api_changes and changes goes through the module (api_changes.spawn, changes._step, ...), never imported by name."""
import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException

import alerts
import api_changes
import auth
import cfgparse
import changes
import poller
import roles
import snmp
import sshcli
from db import AUDIT_TOKEN, audit, db

log = logging.getLogger("switchview.confirm")

router = APIRouter()

NOT_FOUND = "Änderung nicht gefunden"
NOT_PENDING = "Änderung #{cid} wartet nicht auf Bestätigung"
TOO_LATE = "Zu spät: die Frist von Änderung #{cid} ist abgelaufen, SwitchView nimmt sie zurück"
WHO = "Bestätigen kann, wer die Änderung gestartet oder freigegeben hat, oder jemand mit der Rolle „Freigeben“"
CONFIRMED_STEP = "Bestätigt von {user}"
DRIFT = "Nicht gespeichert: der Switch passt nicht mehr zur geprüften Änderung: "
# A change row with the zone and the state of its switch (confirm_change checks both)
_JOINED = ("SELECT c.*, s.zone AS switch_zone, s.enabled AS switch_enabled FROM changes c JOIN switches s ON s.id = c.switch_id "
           "WHERE c.id = ?")


def may_confirm(user: dict, ch) -> bool:
    """Whether user (auth.current_user) may confirm change ch: who started it (changes.username) or approved it (approved_by), the
    case aside, else anyone with Freigeben. The zone is the caller's check (confirm_change)."""
    name = user["username"].casefold()
    return (name in ((ch["username"] or "").casefold(), (ch["approved_by"] or "").casefold())
            or roles.at_least(user["role"], roles.FREIGEBEN))


async def _change(cid: int):
    async with db() as conn:
        async with conn.execute("SELECT * FROM changes WHERE id = ?", (cid,)) as cur:
            return await cur.fetchone()


async def confirm_change(cid: int, user: dict) -> dict:
    """The "Bestätigen" of change cid by user, checked in this order: the change is there (404 NOT_FOUND), its switch is in user's zones
    (403 roles.zone_denial), user may confirm it (403 WHO), it waits for its confirmation (409 NOT_PENDING), its switch is enabled (409
    api_changes.DISABLED, as in every mode of /plan and /apply; the change keeps waiting). Then one UPDATE takes it from pending to
    running, only before its deadline (confirm_until > now: the deadline's own second is the watch's, due at confirm_until <= now, so
    no confirm wins a change the watch takes back): if it changes nothing, 409 TOO_LATE while it still waits (the watch takes it
    back), else NOT_PENDING (another confirm or its revert came first). Audits change_confirm (user, the switch, "#<cid> <summary>");
    over SNMP the change ends here (_confirm_snmp), over SSH the save runs as a tracked task (_confirm_ssh). {"ok": True, "id": cid};
    Task 7 calls it for each change of a bulk change."""
    async with db() as conn:
        async with conn.execute(_JOINED, (cid,)) as cur:
            ch = await cur.fetchone()
        if ch is None:
            raise HTTPException(404, NOT_FOUND)
        if not roles.zone_allows(user, ch["switch_zone"]):
            raise HTTPException(403, roles.zone_denial(ch["switch_zone"], user["zones"]))
        if not may_confirm(user, ch):
            raise HTTPException(403, WHO)
        if ch["status"] != changes.PENDING:
            raise HTTPException(409, NOT_PENDING.format(cid=cid))
        if not ch["switch_enabled"]:
            raise HTTPException(409, api_changes.DISABLED)
        taken = await conn.execute("UPDATE changes SET status = 'running', confirmed_by = ? WHERE id = ? AND status = 'pending' "
                                   "AND confirm_until > ?", (user["username"], cid, changes._now()))
        await conn.commit()
        if taken.rowcount != 1:
            async with conn.execute("SELECT status FROM changes WHERE id = ?", (cid,)) as cur:
                now = await cur.fetchone()
            raise HTTPException(409, (TOO_LATE if now is not None and now["status"] == changes.PENDING else NOT_PENDING).format(cid=cid))
    await audit(user["username"], "change_confirm", str(ch["switch_id"]), f"#{cid} {ch['summary']}", role=user["role"])
    if (ch["mechanism"] or "ssh") == "snmp":
        await _confirm_snmp(cid, user["username"])
    else:
        api_changes.spawn(_confirm_ssh(cid, user["username"]))
    return {"ok": True, "id": cid}


async def _confirm_snmp(cid: int, by: str) -> None:
    """The end of confirmed change cid over SNMP: nothing read, nothing sent, nothing saved (a driver that waits has no snmp_autosave,
    and SwitchView never saves over SNMP): the steps CONFIRMED_STEP and changes.SNMP_UNSAVED (warn), ok with saved 0, the audit
    change_ok of its starter as changes._close writes it, and the alerts. Its row is read after confirm_change's UPDATE, with every
    step written until then."""
    ch = await _change(cid)
    now = changes._now()
    steps = json.loads(ch["steps"] or "[]") + [[now, CONFIRMED_STEP.format(user=by), "info"], [now, changes.SNMP_UNSAVED, "warn"]]
    await changes._upd(cid, status="ok", saved=0, finished_at=now, steps=json.dumps(steps))
    await audit(ch["username"], "change_ok", str(ch["switch_id"]), f"#{cid} {ch['summary']}, mechanism: {ch['mechanism']}", role=ch["role"])
    await changes._logged(cid, "Benachrichtigung", alerts.change_ended(ch, cid, "ok", None))


async def _confirm_ssh(cid: int, by: str) -> None:
    """The save of confirmed change cid over SSH, in the switch's lock (a tracked task, api_changes.spawn): the step CONFIRMED_STEP,
    then the switch row of now - gone or disabled meanwhile (changes.DISABLED_RUN) or without an SSH CLI (sshcli.cli_refusal): unclear
    "Nicht gespeichert: <reason>", no session. Else the running-config read afresh: if verify_ports no longer finds the change there,
    unclear with DRIFT and the first eight differences, nothing saved; else write memory, ok with saved 1. Any exception is unclear
    (changes._error_text, masked as in run_change; after write memory went out its step says the save is open, changes.SSH_KEPT). At
    the end the read as the backup "bestätigt #<cid>" and the cached read (changes.store_cfg), the audit change_<status> of the
    starter and the alerts, each on its own (changes._logged), and last the row (status, error, saved, finished_at): whoever waits for
    the change to leave running finds everything of its end; no re-poll (write memory changes no port)."""
    ch = await _change(cid)
    if ch is None:    # deleted with its switch meanwhile
        return
    sid = ch["switch_id"]
    steps = json.loads(ch["steps"] or "[]")
    rs = await changes.radius_settings()
    secrets = changes._secrets_of(await changes._switch_row(sid), rs)

    def mask(text: str) -> str:
        return cfgparse.mask_secrets(text, secrets)

    async def step(text: str, level: str = "info"):
        await changes._step(cid, steps, mask(text), level)

    status, error, saved, post, saving = None, None, 0, None, False
    try:
        await step(CONFIRMED_STEP.format(user=by))
        async with sshcli.lock(sid):
            row = await changes._switch_row(sid)
            reason = changes.DISABLED_RUN if row is None or not row["enabled"] else sshcli.cli_refusal(row)
            if reason:
                status, error = "unclear", f"Nicht gespeichert: {reason}"
                await step(error, "error")
                return
            secrets.extend(changes._secrets_of(row, rs))
            conn = await asyncio.to_thread(sshcli.connect, row)
            try:
                post = sshcli.clean(await asyncio.to_thread(conn.send_command, "show running-config", read_timeout=90))
                bad = changes.verify_ports(cfgparse.parse_config(post), json.loads(ch["desired"] or "{}"))
                if bad:
                    status, error = "unclear", DRIFT + "; ".join(bad[:8])
                    await step(error, "error")
                    return
                await step("Speichere (write memory)")
                saving = True
                await asyncio.to_thread(conn.save_config)
                saved, status = 1, "ok"
                await step("Gespeichert", "ok")
            finally:
                await asyncio.to_thread(sshcli.disconnect, conn)
    except Exception as e:  # noqa: BLE001
        status, error = "unclear", changes._error_text(e, mask)
        changes._log_masked(cid, e, mask)
        await step(f"{error}. {changes.SSH_KEPT['save']}" if saving else error, "error")
    finally:
        if status is None:    # cancelled (the app shut down): the change is in effect, its save is open or never ran
            status, error = "unclear", changes.CANCELLED
            await changes._logged(cid, "Abbruch vermerken", step(f"{error}. {changes.SSH_KEPT['save']}" if saving else error, "error"))
        if post:
            await changes._logged(cid, "Sicherung bestätigt", sshcli.store_backup(sid, post, f"bestätigt #{cid}"))
            if not await changes._logged(cid, "Konfiguration auswerten", changes.store_cfg(sid, post)):
                changes.invalidate_cfg(sid)
        await changes._logged(cid, "Protokoll", audit(ch["username"], "change_" + status, str(sid), f"#{cid} {ch['summary']}", role=ch["role"]))
        await changes._logged(cid, "Benachrichtigung", alerts.change_ended(ch, cid, status, error and mask(error)))
        await changes._upd(cid, status=status, error=error and mask(error), saved=saved, finished_at=changes._now())


@router.post("/api/changes/{cid}/confirm")
async def confirm_route(cid: int, user=Depends(auth.require(roles.AENDERN))):
    """The "Bestätigen" of a change that waits for its confirmation: confirm_change."""
    return await confirm_change(cid, user)


# ── The watch over the waiting changes (Task 5) ─────────────────────────────────────────────────────────────────────────────────
CHECK_S = 15              # the watch runs every CHECK_S seconds (jobs._schedule), its first run at the start
UNREACHABLE_AFTER = 2     # misses in a row (about 30 s) after which a waiting change is taken back before its deadline
REACH_TIMEOUT_S = 8       # how long reachable waits for the switch's answer
PARALLEL = 5              # at most that many switches are asked at once
AUTO_USER = "SwitchView"  # the user of an automatic revert (no role: it is no person's request)
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
TIMED_OUT = "Frist abgelaufen ({until} UTC)"
NO_ANSWER = "Switch antwortet nicht"
REVERTING_STEP = "{why}: SwitchView nimmt die Änderung zurück"
UNREACHABLE = ("Nicht bestätigt und nicht zurückgenommen: Switch nicht erreichbar – ungespeichert; ein Neustart des Switches lädt die "
               "gespeicherte Konfiguration")
NOT_TAKEN_BACK = "Nicht bestätigt und nicht zurückgenommen – ungespeichert; ein Neustart des Switches lädt die gespeicherte Konfiguration"
NOTHING_BACK = "Nicht bestätigt: am Switch ist nichts mehr zurückzunehmen"
# The misses in a row of each waiting change (its id): in the process like the locks (single worker, main.py); a restart starts at 0
_misses: dict[int, int] = {}
# A change row with the name of its switch (auto_revert, _give_up and their alerts)
_NAMED = "SELECT c.*, s.name AS switch_name FROM changes c JOIN switches s ON s.id = c.switch_id WHERE c.id = ?"


async def reachable(row) -> bool:
    """Whether switch row answers: sysUpTime over SNMP with its read identity (poller.creds_of) within REACH_TIMEOUT_S. Any exception
    (the identity included) and an empty answer are False. Every switch is polled over SNMP anyway; an SSH login every 15 s would hold
    one of its at most five sessions and write a login into its log."""
    try:
        return bool(await snmp.get(row["host"], poller.creds_of(row), [SYS_UPTIME], timeout=REACH_TIMEOUT_S))
    except Exception:  # noqa: BLE001 - whatever fails, the switch did not answer
        return False


async def watch() -> int:
    """The job: every waiting change (status pending) whose deadline has passed is due with TIMED_OUT (its time HH:MM), without a
    check; every other one at an enabled switch is checked by reachable with its switch row, at most PARALLEL at once: an answer
    clears its misses, a miss counts up, and at UNREACHABLE_AFTER it is due with NO_ANSWER. A disabled switch is not asked (the poller
    does not poll it either): only its deadline acts, and auto_revert gives up there. The misses of changes that no longer wait, or
    whose switch is disabled, go. Then auto_revert of each due change in turn, each on its own (an exception is logged, the next one
    runs). First of all the context's API token goes (db.AUDIT_TOKEN): APScheduler runs a job in the context of whoever woke it, and
    no entry of the watch names a token. How many reverts it started."""
    AUDIT_TOKEN.set(None)
    now = changes._now()
    async with db() as conn:
        async with conn.execute("SELECT c.id AS cid, c.confirm_until, s.* FROM changes c JOIN switches s ON s.id = c.switch_id "
                                "WHERE c.status = 'pending' ORDER BY c.id") as cur:
            waiting = await cur.fetchall()
    for cid in set(_misses) - {w["cid"] for w in waiting if w["enabled"]}:
        del _misses[cid]
    # (a waiting change without a deadline - no code writes one - is due as well: nothing waits without an end)
    due = [(w["cid"], TIMED_OUT.format(until=w["confirm_until"][11:16] if w["confirm_until"] else "–")) for w in waiting
           if not w["confirm_until"] or w["confirm_until"] <= now]
    gate = asyncio.Semaphore(PARALLEL)

    async def check(w):
        async with gate:
            answered = await reachable(w)
        _misses[w["cid"]] = 0 if answered else _misses.get(w["cid"], 0) + 1
        if _misses[w["cid"]] >= UNREACHABLE_AFTER:
            due.append((w["cid"], NO_ANSWER))

    await asyncio.gather(*(check(w) for w in waiting if w["enabled"] and w["confirm_until"] and w["confirm_until"] > now))
    started = 0
    for cid, why in due:
        try:
            if await auto_revert(cid, why) is not None:
                started += 1
        except Exception:  # noqa: BLE001 - one change that cannot be handled costs the others nothing
            log.exception("Rücknahme von Änderung %s", cid)
    return started


async def _named(cid: int):
    async with db() as conn:
        async with conn.execute(_NAMED, (cid,)) as cur:
            return await cur.fetchone()


async def _add_step(cid: int, text: str, level: str, end: dict | None = None) -> bool:
    """The step text (level) at the end of the steps of change cid, only while it waits (one write transaction: no step of another
    writer is lost, and none lands in the run of a confirm that came first); with end ({column: value}) the same UPDATE ends the
    waiting. Whether the change still waited."""
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute("SELECT steps FROM changes WHERE id = ? AND status = 'pending'", (cid,)) as cur:
            got = await cur.fetchone()
        if got is None:
            return False    # closing the connection ends the transaction
        cols = {"steps": json.dumps(json.loads(got["steps"] or "[]") + [[changes._now(), text, level]])} | (end or {})
        await conn.execute(f"UPDATE changes SET {', '.join(f'{k} = ?' for k in cols)} WHERE id = ? AND status = 'pending'",
                           (*cols.values(), cid))
        await conn.commit()
        return True


class _NotWaiting(Exception):
    """The claim of auto_revert's revert (_claim_of): the change no longer waited when the revert went in - a confirm or a revert by
    hand ended its waiting after the watch's step; the INSERT is rolled back."""


def _claim_of(cid: int):
    """The claim (api_changes.start_change, changes.create_change: after the INSERT of revert rid and _leave_pending, in their
    transaction) of the automatic revert of change cid: it goes in only if it is what ended the waiting - cid is now unclear with
    changes.REVERT_STARTED of rid. Else _NotWaiting, and nothing is stored: a change confirmed while the watch planned (over SNMP the
    confirm ends it ok inside its request, and can_revert allows an ok change) or taken back by hand meanwhile is left alone."""
    async def claim(conn, rid: int) -> None:
        async with conn.execute("SELECT status, error FROM changes WHERE id = ?", (cid,)) as cur:
            got = await cur.fetchone()
        if got is None or (got["status"], got["error"]) != ("unclear", changes.REVERT_STARTED.format(rid=rid)):
            raise _NotWaiting(cid)
    return claim


async def _mask_of(sid: int):
    """The mask of every stored text of a change at switch sid: its secrets and the RADIUS key (changes._secrets_of)."""
    secrets = changes._secrets_of(await changes._switch_row(sid), await changes.radius_settings())
    return lambda text: cfgparse.mask_secrets(text, secrets)


async def _tell(ch, title: str, text: str) -> None:
    """The alert confirm_revert about change ch (a _NAMED row), its title and text; one key per change."""
    await alerts.emit("confirm_revert", title, text, switch_id=ch["switch_id"], switch_name=ch["switch_name"], key=f"confirm:{ch['id']}",
                      facts={"Switch": ch["switch_name"]})


async def auto_revert(cid: int, why: str) -> int | None:
    """Takes back waiting change cid because of why (TIMED_OUT or NO_ANSWER) as a normal revert; the number of the revert, or None.
    Nothing when cid no longer waits; else first the step REVERTING_STEP, only while it waits (a confirm that won the race: None).
    A disabled switch (changes.DISABLED_RUN would end the revert's run) is neither read nor written: the waiting ends with
    NOT_TAKEN_BACK and api_changes.DISABLED. Else the cached SSH read of its switch is dropped (changes.invalidate_cfg): run_change
    stored its read-back moments ago, and a switch that stopped answering must show in this plan, not only in the revert's run. Then
    the revert's plan (api_changes._make_plan of PlanIn(mode="revert", of=cid)): nothing to send and nothing blocked ends the waiting
    with NOTHING_BACK, without an alert; else start_change with the plan's preview token and write way as AUTO_USER without a role (a
    blocked port is its 409 "Nicht ausführbar: …", as checked_plan says it) and the claim _claim_of(cid): a confirm or a revert by
    hand that ended the waiting while the watch planned rolls the revert back (None, nothing told), so a confirmed change is never
    taken back. Then the alert confirm_revert „… wird zurückgenommen“. Any HTTPException ends the waiting (_give_up, only while it
    still waits): UNREACHABLE for a switch that cannot be read (502), else NOT_TAKEN_BACK, each with the reason; so does any other
    exception (a database error, a bug), with its type and text (changes._error_text) and logged masked (changes._log_masked) - else
    the change, still waiting, were due again at every run, with one more step each and PENDING_BUSY on its switch without end. It is
    not tried again - a retry would hold the switch's lock without end, and the change is unsaved anyway."""
    ch = await _named(cid)
    if ch is None or ch["status"] != changes.PENDING:
        return None
    if not await _add_step(cid, REVERTING_STEP.format(why=why), "warn"):
        return None
    sid = ch["switch_id"]
    body = api_changes.PlanIn(mode="revert", of=cid)
    try:
        row = await changes._switch_row(sid)
        if row is None or not row["enabled"]:
            await _give_up(ch, f"{NOT_TAKEN_BACK} ({api_changes.DISABLED})")
            return None
        changes.invalidate_cfg(sid)
        plan, *_ = await api_changes._make_plan(row, body)
        if not plan["shown"] and not plan["blocked"]:
            await _give_up(ch, NOTHING_BACK, alert=False)
            return None
        rid = await api_changes.start_change(row, body.model_copy(update={"token": changes.cmd_token(plan["shown"]),
                                                                          "mechanism": plan["mechanism"]}),
                                             {"username": AUTO_USER, "role": None}, claim=_claim_of(cid))
    except _NotWaiting:
        return None
    except HTTPException as e:    # _give_up does nothing to a change that no longer waits (a confirm or a revert came first)
        await _give_up(ch, f"{UNREACHABLE if e.status_code == 502 else NOT_TAKEN_BACK} ({e.detail})")
        return None
    except Exception as e:  # noqa: BLE001 - whatever it is, the waiting ends once, here
        mask = await _mask_of(sid)
        changes._log_masked(cid, e, mask)
        await _give_up(ch, f"{NOT_TAKEN_BACK} ({changes._error_text(e, mask)})")
        return None
    await _tell(ch, f"Änderung #{cid} an {ch['switch_name']} wird zurückgenommen",
                f"{ch['summary']} (von {ch['username']}): {why}. Rücknahme #{rid}.")
    return rid


async def _give_up(ch, error: str, alert: bool = True) -> None:
    """The waiting of change ch (a _NAMED row) ends without a revert: unclear with error (masked with the secrets of its switch, as
    every stored text of a change) as its error and its last step, finished now, only while it still waits. Then the audit
    change_unclear of its starter (with their role) and, with alert, the alert confirm_revert „… nicht zurückgenommen“."""
    cid = ch["id"]
    error = (await _mask_of(ch["switch_id"]))(error)
    if not await _add_step(cid, error, "error" if alert else "warn",
                           {"status": "unclear", "error": error, "finished_at": changes._now()}):
        return
    await changes._logged(cid, "Protokoll", audit(ch["username"], "change_unclear", str(ch["switch_id"]), f"#{cid} {ch['summary']}",
                                                  role=ch["role"]))
    if alert:
        await _tell(ch, f"Änderung #{cid} an {ch['switch_name']} nicht zurückgenommen", f"{ch['summary']} (von {ch['username']}): {error}")
