"""Bulk changes (Phase 4c): the same port change on many ports of many switches, each switch through the guided loop of a single
change. Task 6: the selection per switch and the combined preview. A request names the change once and per switch its ports, as a
list or as the filter "every access port untagged in VLAN N by the last poll" (resolve); each switch gets a section planned by the
per-switch planner (api_changes._make_plan) with its own preview token, at most PARALLEL at once. A switch outside the user's
zones, with a blocked port, with nothing to do or that cannot be planned is skipped with its reason; the uplink, trunk and LAG
protection is the planner's, per switch, as today. The preview starts nothing: what runs later (Task 7) are the port lists it
showed, never the filter again.

Task 7: the run. POST /api/bulk takes the ready sections of a preview and the skipped ones (api_bulk.BulkIn): its limits (validate),
the rights of every switch (rights), then every switch planned once more against its preview token (precheck) - one that does not
match starts nothing at all. create stores the bulk change and its switches, schedule adds its run as a date job of the one
scheduler. The run (run) starts the switches one after another, each as a normal change through api_changes.start_change (which
plans again, and changes.run_change a third time in the switch's lock), and waits for its end in the database (_settled). The first
failure stops the rest unless on_error is "continue"; a cancel (cancel) acts between two switches, never inside a change. With
confirm_minutes each switch waits for its confirmation and the run goes on, the deadlines of the waiting ones grow with it
(_extend_deadlines), and confirm_all confirms them in one go. The end is audited (bulk_<status>) and a bulk change with failures
raises the alert bulk_problem; a restart ends every bulk change that was queued or running as interrupted (mark_interrupted) and
continues none. Everything of api_changes, changes and confirm goes through the module, never imported by name."""
import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

import alerts
import api_changes
import approvals
import changes
import confirm
import roles
import snmpwrite
from db import AUDIT_TOKEN, audit, db

log = logging.getLogger("switchview.bulk")

MAX_SWITCHES = 20
MAX_PORTS_PER_SWITCH = 200          # the limit of PlanIn.ports
MAX_PORTS = 1000
PARALLEL = 5                        # switches planned at once: each costs a fresh read and a build_map
TOO_MANY_SWITCHES = "Höchstens 20 Switches je Sammeländerung"
TOO_MANY_PORTS = "Höchstens 1000 Ports je Sammeländerung"
TWICE = "Switch #{sid} steht doppelt in der Sammeländerung"
ONE_OF = "Für Switch #{sid} entweder Ports oder „ungetaggt in VLAN“ angeben, nicht beides"
NO_PORTS = "Für Switch #{sid} sind keine Ports gewählt"
NO_MATCH = "Kein Zugangsport ungetaggt in VLAN {vlan} (laut letztem Poll)"
OVER_200 = "Mehr als 200 Ports an einem Switch – bitte die Auswahl teilen"
MOVED = "Port {port} ist nicht mehr ungetaggt in VLAN {vlan} (jetzt {now}) – Switch neu abfragen und die Vorschau neu laden"
NOTHING = "Es gibt nichts zu ändern"
SELECTED = "Zugangsports ungetaggt in VLAN {vlan} laut Poll vom {when}"


def _doubled(ids) -> int | None:
    """The first switch id that comes a second time in ids, else None."""
    seen: set[int] = set()
    for sid in ids:
        if sid in seen:
            return sid
        seen.add(sid)
    return None


def _check(targets) -> None:
    """The limits of a request, in this order, each a 422: more than MAX_SWITCHES switches, a switch twice (the first), a switch with
    a port list and the filter, one with neither, more than MAX_PORTS ports in the lists."""
    if len(targets) > MAX_SWITCHES:
        raise HTTPException(422, TOO_MANY_SWITCHES)
    sid = _doubled(t.switch_id for t in targets)
    if sid is not None:
        raise HTTPException(422, TWICE.format(sid=sid))
    for t in targets:
        if t.ports and t.untagged_in is not None:
            raise HTTPException(422, ONE_OF.format(sid=t.switch_id))
    for t in targets:
        if not t.ports and t.untagged_in is None:
            raise HTTPException(422, NO_PORTS.format(sid=t.switch_id))
    if sum(len(t.ports) for t in targets) > MAX_PORTS:
        raise HTTPException(422, TOO_MANY_PORTS)


def _polled_at(row) -> str:
    """The time of the poll the inventory comes from, as the switches table holds it, in UTC: the last good poll (last_ok_at; a row
    from before Phase 4b has only last_poll, which counts when that poll was good) - a failed poll keeps the ports of the good one."""
    at = row["last_ok_at"] or (row["last_poll"] if row["last_poll_ok"] else None)
    return f"{at} UTC" if at else "–"


async def resolve(row, target) -> tuple[list[str], str]:
    """The ports of target at switch row and how they were chosen: a list as it is (and ""); for the filter (untagged_in) every
    access port the last poll (api_changes._inventory) has untagged in that VLAN, in natural order (snmpwrite.port_order), and
    SELECTED. An access port is no trunk (no Trk… name, no port another one names as its trunk, none with members), no trunk member
    (tr) and no uplink (inventory "uplinks")."""
    if target.untagged_in is None:
        return list(target.ports), ""
    vlan = target.untagged_in
    inv = await api_changes._inventory(row["id"])
    trunks = {p.get("tr") for p in inv["ports"].values()} - {"", None}
    ports = [n for n, p in inv["ports"].items()
             if vlan in (p.get("u") or []) and not n.startswith("Trk") and n not in trunks and not p.get("tr") and not p.get("mb")
             and n not in inv["uplinks"]]
    return sorted(ports, key=snmpwrite.port_order), SELECTED.format(vlan=vlan, when=_polled_at(row))


def _verdict(target, change, plan: dict) -> tuple[str, str]:
    """(status, reason) of a planned section: for the filter and a change of the untagged VLAN, a port the fresh read (plan["before"])
    has no longer untagged in the filter's VLAN blocks the switch (MOVED, the first); a blocked port blocks it ("Port <p>: <reason>",
    "; " between, "*" without "Port "), as /apply runs no plan with a block; no command is nothing to do; else ready."""
    if target.untagged_in is not None and change.untagged is not None:
        for p, d in plan["desired"].items():
            now = plan["before"].get(p, {}).get("u")
            if "u" in d and now != target.untagged_in:
                return "blocked", MOVED.format(port=p, vlan=target.untagged_in, now=now or "–")
    if plan["blocked"]:
        return "blocked", "; ".join(b["reason"] if b["port"] == "*" else f"Port {b['port']}: {b['reason']}" for b in plan["blocked"])
    if not plan["shown"]:
        return "nothing", NOTHING
    return "ready", ""


async def section(user: dict, target, change, expert: bool, four_eyes: bool) -> dict:
    """The section of target's switch in the preview: switch_id, switch (its name), zone, ports, selection (resolve), status and
    reason, preview (the /plan answer: api_changes.preview_answer plus confirm, None without a plan). In the order of /plan: the
    switch (api_changes._enabled_row: gone or disabled is "error"), the rights (api_changes._mode_rights: a 403, another zone or the
    expert mode, is "denied"), the ports (resolve: none in the VLAN is "nothing", more than MAX_PORTS_PER_SWITCH "error"), the plan
    (api_changes._make_plan: any HTTPException is "error" with its text), then _verdict: "blocked", "nothing" or "ready"."""
    out = {"switch_id": target.switch_id, "switch": f"#{target.switch_id}", "zone": "", "ports": list(target.ports), "selection": "",
           "status": "", "reason": "", "preview": None}
    try:
        row = await api_changes._enabled_row(target.switch_id)
        out |= {"switch": row["name"], "zone": row["zone"]}
        try:
            await api_changes._mode_rights(user, row, api_changes.PlanIn(mode="ports", change=change, expert=expert), four_eyes)
        except HTTPException as e:
            if e.status_code != 403:
                raise
            return out | {"status": "denied", "reason": e.detail}
        ports, selection = await resolve(row, target)
        out |= {"ports": ports, "selection": selection}
        if not ports:
            return out | {"status": "nothing", "reason": NO_MATCH.format(vlan=target.untagged_in)}
        if len(ports) > MAX_PORTS_PER_SWITCH:
            return out | {"status": "error", "reason": OVER_200}
        body = api_changes.PlanIn(mode="ports", ports=ports, change=change, expert=expert)
        plan, _, kind, text = await api_changes._make_plan(row, body)
    except HTTPException as e:
        return out | {"status": "error", "reason": e.detail}
    status, reason = _verdict(target, change, plan)
    answer = api_changes.preview_answer(row, plan, kind, text) | {"confirm": api_changes.confirm_info(row, plan, body)}
    return out | {"status": status, "reason": reason, "preview": answer}


def token_of(pairs: list[tuple[int, str]]) -> str:
    """The token of a bulk preview: changes.cmd_token over "<switch id>:<preview token>" of each ready switch, by switch id."""
    return changes.cmd_token([f"{sid}:{token}" for sid, token in sorted(pairs, key=lambda p: p[0])])


def summary(change, switches: int, ports: int) -> str:
    """"VLAN 30 · 3 Ports an 2 Switches" (singular "1 Port an 1 Switch"): the parts of the change (api_changes._change_parts) and
    how many ports at how many switches."""
    what = ", ".join(api_changes._change_parts(change)) or "–"
    return f"{what} · {ports} {'Port' if ports == 1 else 'Ports'} an {switches} {'Switch' if switches == 1 else 'Switches'}"


def _confirm(ready: list[dict]) -> dict:
    """Whether the bulk can run with confirmation, as confirm_info says it for one switch: possible when there is a ready section and
    every ready one can, else why not (the first reason; None without a ready section)."""
    whys = [s["preview"]["confirm"]["why"] for s in ready if not s["preview"]["confirm"]["possible"]]
    return {"possible": bool(ready) and not whys, "why": whys[0] if whys else None, "default_minutes": api_changes.CONFIRM_DEFAULT,
            "max_minutes": api_changes.CONFIRM_MAX}


async def preview(user: dict, body) -> dict:
    """The preview of the bulk request body (api_bulk.BulkPlanIn) for user: the limits first (_check, 422), then a section per switch
    in the order of the request, at most PARALLEL planned at once, then MAX_PORTS once more over the ports of the ready sections (the
    filter resolves only now; 422). sections, summary (of the ready ones), token (token_of the ready ones), approval (with the
    four-eyes principle on every bulk needs one), ready and skipped (counts), ports (of the ready ones), confirm (_confirm)."""
    _check(body.targets)
    four_eyes = (await approvals.policy())["four_eyes"]
    gate = asyncio.Semaphore(PARALLEL)

    async def planned(target) -> dict:
        async with gate:
            return await section(user, target, body.change, body.expert, four_eyes)

    sections = await asyncio.gather(*(planned(t) for t in body.targets))
    ready = [s for s in sections if s["status"] == "ready"]
    ports = sum(len(s["ports"]) for s in ready)
    if ports > MAX_PORTS:
        raise HTTPException(422, TOO_MANY_PORTS)
    return {"sections": sections, "summary": summary(body.change, len(ready), ports),
            "token": token_of([(s["switch_id"], s["preview"]["token"]) for s in ready]), "approval": four_eyes, "ready": len(ready),
            "skipped": len(sections) - len(ready), "ports": ports, "confirm": _confirm(ready)}


# ── Task 7: start, run, cancel, read ───────────────────────────────────────────────────────────────────────────────────────────────
POLL_S = 1.0                        # how often the run asks the database whether the change of a switch has ended
# A bulk change (bulks.status) is queued, running, done, failed, cancelled or interrupted, a switch in it (bulk_items.status)
# waiting, running, done, failed, skipped or not_started. The counts of an answer, in this order: those of a switch, and pending,
# the switches whose change waits for its confirmation
COUNTED = ("done", "failed", "skipped", "not_started", "waiting", "running", changes.PENDING)
OUTDATED = "Die Vorschau ist veraltet – bitte neu laden: {list}"
APPROVAL_NEEDED = "Sammeländerungen brauchen eine Freigabe (Vier-Augen-Prinzip): bitte „Freigabe anfordern“"
NOT_FOUND = "Sammeländerung nicht gefunden"
CANCEL_WHO = "Abbrechen kann, wer die Sammeländerung gestartet hat, oder jemand mit der Rolle „Freigeben“"
NOT_RUNNING = "Sammeländerung #{bid} läuft nicht mehr"
GONE = "Switch gelöscht"
NOT_STARTED = "nicht gestartet: {why}"
WHY_CANCELLED = "abgebrochen"
WHY_STOPPED = "nach einem Fehler gestoppt"
WHY_RESTART = "SwitchView neu gestartet"
# The detail of a switch whose change ended in one of these states: "Änderung #<cid> <ENDED>"
ENDED = {"unclear": "unklar", "failed": "fehlgeschlagen", "aborted": "abgebrochen"}
UNCONFIRMED = "Änderung #{cid} nicht bestätigt, zurückgenommen"
# The detail of the switch at which the run itself failed (an exception that is no refusal of start_change); the log has the rest
CRASHED = "Unerwarteter Fehler im Lauf – Einzelheiten im Log von SwitchView"


def plan_in(item, change, expert: bool, confirm_minutes: int | None) -> api_changes.PlanIn:
    """The body of /apply for one switch of a bulk change: the ports, the preview token and the write way of item (a mapping with
    "ports", "token" and "mechanism": a BulkItemIn's model_dump, or a bulk_items row read back), the change, the expert mode and the
    minutes of the confirmation (None: without)."""
    return api_changes.PlanIn(mode="ports", ports=item["ports"], change=change, expert=expert, token=item["token"],
                              mechanism=item["mechanism"], confirm_minutes=confirm_minutes)


def validate(body) -> None:
    """The limits of a bulk change body (api_bulk.BulkIn) over its items and its skipped switches together, in this order, each a 422
    as the preview says it (_check): more than MAX_SWITCHES switches (TOO_MANY_SWITCHES), a switch twice (TWICE, the first that comes
    a second time), more than MAX_PORTS ports (TOO_MANY_PORTS). POST /api/bulk and a four-eyes request of a bulk change (Task 8) call
    it first: the body is the UI's preview, or a forged one."""
    ids = [i.switch_id for i in body.items] + [s.switch_id for s in body.skipped]
    if len(ids) > MAX_SWITCHES:
        raise HTTPException(422, TOO_MANY_SWITCHES)
    sid = _doubled(ids)
    if sid is not None:
        raise HTTPException(422, TWICE.format(sid=sid))
    if sum(len(i.ports) for i in body.items) > MAX_PORTS:
        raise HTTPException(422, TOO_MANY_PORTS)


async def rights(user: dict, body, four_eyes: bool) -> None:
    """The rights of user at every switch of body's items, in their order, as /apply checks them: the switch
    (api_changes._enabled_row: 404 gone, 409 api_changes.DISABLED), then the zone and the mode (api_changes._mode_rights: 403 for
    another zone or the expert mode below Freigeben without four eyes). The first error goes through; a skipped switch runs nothing."""
    probe = api_changes.PlanIn(mode="ports", change=body.change, expert=body.expert)
    for item in body.items:
        row = await api_changes._enabled_row(item.switch_id)
        await api_changes._mode_rights(user, row, probe, four_eyes)


async def precheck(body) -> list[dict]:
    """Every switch of body's items planned against its preview token as /apply plans it (api_changes.checked_plan, on the write way of
    its preview) and, with confirm_minutes, asked whether it can run with confirmation (api_changes.confirm_refusal), at most
    PARALLEL at once. Every HTTPException of a switch - outdated, blocked, unreadable, disabled, gone, nothing to change, no
    confirmation possible - means it does not match, with its text; if one does not match, api_changes.PreviewOutdated (409) with
    OUTDATED naming each that does not ("<name>: <reason>", "; " between, "#<id>" for a switch that is gone), and nothing starts.
    Else per switch {"switch_id", "switch", "ports", "preview"} in the order of the items, preview as api_changes.preview_answer."""
    gate = asyncio.Semaphore(PARALLEL)

    async def checked(item) -> dict | tuple[str, str]:
        name = f"#{item.switch_id}"
        async with gate:
            try:
                row = await api_changes._enabled_row(item.switch_id)
                name = row["name"]
                one = plan_in(item.model_dump(), body.change, body.expert, body.confirm_minutes)
                plan, _, kind, summary_ = await api_changes.checked_plan(row, one)
                if body.confirm_minutes is not None:
                    refusal = api_changes.confirm_refusal(row, plan, one)
                    if refusal:
                        raise HTTPException(409, refusal)
            except HTTPException as e:
                return name, str(e.detail)
        return {"switch_id": item.switch_id, "switch": name, "ports": list(item.ports),
                "preview": api_changes.preview_answer(row, plan, kind, summary_)}

    results = await asyncio.gather(*(checked(i) for i in body.items))
    misfits = [r for r in results if isinstance(r, tuple)]
    if misfits:
        raise api_changes.PreviewOutdated(OUTDATED.format(list="; ".join(f"{name}: {why}" for name, why in misfits)))
    return results


def summary_of(body) -> str:
    """The summary of a bulk change body (api_bulk.BulkIn): summary over its change, its items and their ports."""
    return summary(body.change, len(body.items), sum(len(i.ports) for i in body.items))


async def create(body, maker: dict, *, api_token: str | None = None, approved_by: str | None = None, claim=None) -> int:
    """Stores bulk change body in one write transaction (BEGIN IMMEDIATE): its bulks row "queued" (maker's username and role, the
    label of the API token it was started with, auth.token_label, and who approved it, each None without), then its switches in this
    order, each with the name of now (a switch that is no longer there: no switch_id, "#<id>"): every item "waiting" with its ports,
    preview token and write way, every skipped one "skipped" with its reason. claim, if given, is `async (conn, bid) -> None` and runs
    on the same connection before the commit (Task 8: the approval that starts it); its exception goes through, nothing stored. The
    id of the bulk change."""
    ids = [i.switch_id for i in body.items] + [s.switch_id for s in body.skipped]
    rows = ([(i.switch_id, json.dumps(i.ports), i.mechanism, i.token, "waiting", "") for i in body.items]
            + [(s.switch_id, "[]", None, None, "skipped", s.reason) for s in body.skipped])
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute(f"SELECT id, name FROM switches WHERE id IN ({', '.join('?' * len(ids))})", ids) as cur:
            names = {r["id"]: r["name"] for r in await cur.fetchall()}
        cur = await conn.execute(
            "INSERT INTO bulks(created_at, username, role, api_token, approved_by, summary, change, expert, on_error, confirm_minutes, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued')",
            (changes._now(), maker["username"], maker["role"], api_token, approved_by, summary_of(body), json.dumps(body.change.model_dump()),
             int(body.expert), body.on_error, body.confirm_minutes))
        bid = cur.lastrowid
        await conn.executemany(
            "INSERT INTO bulk_items(bulk_id, pos, switch_id, switch_name, ports, mechanism, token, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(bid, pos, sid if sid in names else None, names.get(sid, f"#{sid}"), ports, mechanism, token, status, detail)
             for pos, (sid, ports, mechanism, token, status, detail) in enumerate(rows)])
        if claim is not None:
            await claim(conn, bid)    # its exception: closing the connection rolls everything back
        await conn.commit()
    return bid


def schedule(bid: int) -> None:
    """The run of bulk change bid as a date job of the one scheduler (jobs.scheduler, imported here: jobs imports half the app), now,
    id "bulk-<bid>"; misfire_grace_time None: a run that starts late still runs."""
    from jobs import scheduler
    scheduler.add_job(run, "date", args=[bid], id=f"bulk-{bid}", replace_existing=True, misfire_grace_time=None)


async def _logged(bid: int, what: str, aw) -> bool:
    """await aw; False when it raised, logged with the bulk change and what: the end of a run goes on (as changes._logged)."""
    try:
        await aw
        return True
    except Exception:  # noqa: BLE001
        log.exception("Sammeländerung %s: %s fehlgeschlagen", bid, what)
        return False


async def _set_item(bid: int, pos: int, **f) -> None:
    sets = ", ".join(f"{k} = ?" for k in f)
    async with db() as conn:
        await conn.execute(f"UPDATE bulk_items SET {sets} WHERE bulk_id = ? AND pos = ?", (*f.values(), bid, pos))
        await conn.commit()


async def _stop(bid: int, why: str, crashed: bool = False) -> None:
    """Every switch of bulk change bid that still waits is not started (NOT_STARTED with why); with crashed, the one that is running
    when the run failed ends failed with CRASHED first."""
    async with db() as conn:
        if crashed:
            await conn.execute("UPDATE bulk_items SET status = 'failed', detail = ? WHERE bulk_id = ? AND status = 'running'", (CRASHED, bid))
        await conn.execute("UPDATE bulk_items SET status = 'not_started', detail = ? WHERE bulk_id = ? AND status = 'waiting'",
                           (NOT_STARTED.format(why=why), bid))
        await conn.commit()


async def _settled(cid: int) -> str | None:
    """The status of change cid once it is neither queued nor running, asked every POLL_S seconds; None when it is gone (deleted
    with its switch). The database is the one source: a change a restart ended counts as well."""
    while True:
        async with db() as conn:
            async with conn.execute("SELECT status FROM changes WHERE id = ?", (cid,)) as cur:
                r = await cur.fetchone()
        if r is None or r["status"] not in ("queued", "running"):
            return None if r is None else r["status"]
        await asyncio.sleep(POLL_S)


async def _extend_deadlines(bid: int, minutes: int) -> None:
    """The deadline (confirm_until) of every change of bulk change bid that waits for its confirmation now + minutes (UTC), only while
    it waits: called after each switch whose change waits, so at the end every one of them has the deadline of the last (T7-e). A
    seam for the tests: the run calls it through the module."""
    until = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
    async with db() as conn:
        await conn.execute("UPDATE changes SET confirm_until = ? WHERE bulk_id = ? AND status = 'pending'", (until, bid))
        await conn.commit()


async def _unconfirmed(bid: int) -> bool:
    """Whether a change of bulk change bid ended unconfirmed: the change of a done switch (it waited for its confirmation at its run)
    with confirm_minutes and without confirmed_by that is neither waiting nor queued, running or ok (ok without a confirm is
    changes.CONFIRM_SKIPPED: the switch saved it itself). Each such switch keeps done and gets the detail UNCONFIRMED (again at each
    look, the same text); a switch that failed at its own run keeps its detail."""
    async with db() as conn:
        async with conn.execute(
                "SELECT i.pos, c.id FROM bulk_items i JOIN changes c ON c.id = i.change_id WHERE i.bulk_id = ? AND i.status = 'done' "
                "AND c.confirm_minutes IS NOT NULL AND c.confirmed_by IS NULL AND c.status NOT IN ('pending', 'queued', 'running', 'ok')",
                (bid,)) as cur:
            ended = await cur.fetchall()
        for r in ended:
            await conn.execute("UPDATE bulk_items SET detail = ? WHERE bulk_id = ? AND pos = ?", (UNCONFIRMED.format(cid=r["id"]), bid, r["pos"]))
        await conn.commit()
    return bool(ended)


async def _run_switch(b, item, change) -> bool:
    """One switch of bulk change b (its bulks row): running, then the switch row of now - gone: failed GONE; disabled: failed
    api_changes.DISABLED, as /apply refuses it - then api_changes.start_change of plan_in under the starter of b (username, role),
    with b's approver and b's id; a refusal (HTTPException: busy, changed since the check, ...) is failed with its text, masked with
    the switch's secrets (confirm._mask_of). The change's id into the row, then its end (_settled): ok or waiting (pending) is done -
    waiting with confirm_minutes extends the deadlines (_extend_deadlines) -, anything else failed "Änderung #<cid> <ENDED>" (GONE when
    the change went with its switch). True when the switch is done."""
    bid, pos = b["id"], item["pos"]
    await _set_item(bid, pos, status="running")
    row = await changes._switch_row(item["switch_id"]) if item["switch_id"] is not None else None
    if row is None:
        await _set_item(bid, pos, status="failed", detail=GONE)
        return False
    if not row["enabled"]:
        await _set_item(bid, pos, status="failed", detail=api_changes.DISABLED)
        return False
    body = plan_in({"ports": json.loads(item["ports"]), "token": item["token"], "mechanism": item["mechanism"]}, change, bool(b["expert"]),
                   b["confirm_minutes"])
    try:
        cid = await api_changes.start_change(row, body, {"username": b["username"], "role": b["role"]}, approved_by=b["approved_by"],
                                             bulk_id=bid)
    except HTTPException as e:
        await _set_item(bid, pos, status="failed", detail=(await confirm._mask_of(row["id"]))(str(e.detail)))
        return False
    await _set_item(bid, pos, change_id=cid)
    status = await _settled(cid)
    if status in ("ok", changes.PENDING):
        await _set_item(bid, pos, status="done")
        if status == changes.PENDING and b["confirm_minutes"]:
            await _extend_deadlines(bid, b["confirm_minutes"])
        return True
    await _set_item(bid, pos, status="failed", detail=GONE if status is None else f"Änderung #{cid} {ENDED.get(status, status)}")
    return False


async def _run_switches(b) -> str:
    """The switches of bulk change b that wait, in their order; before each: a cancel asked for ends the run "cancelled" with the rest
    not started (WHY_CANCELLED); a change of the bulk that ended unconfirmed meanwhile counts as a failure (_unconfirmed); after a
    failure with on_error "stop" the rest is not started (WHY_STOPPED) and the run ends "failed". After the last switch one more
    look for an unconfirmed end. "failed" when a switch failed or a change ended unconfirmed, else "done". Any other exception ends
    the run "failed": logged, the switch at hand failed with CRASHED, the rest not started (never a bulk change left running)."""
    bid = b["id"]
    change = api_changes.PortChange.model_validate(json.loads(b["change"]))
    failed = False
    try:
        async with db() as conn:
            async with conn.execute("SELECT * FROM bulk_items WHERE bulk_id = ? AND status = 'waiting' ORDER BY pos", (bid,)) as cur:
                items = await cur.fetchall()
        for item in items:
            async with db() as conn:
                async with conn.execute("SELECT cancel_requested FROM bulks WHERE id = ?", (bid,)) as cur:
                    cancelled = (await cur.fetchone())["cancel_requested"]
            if cancelled:
                await _stop(bid, WHY_CANCELLED)
                return "cancelled"
            failed |= await _unconfirmed(bid)
            if failed and b["on_error"] == "stop":
                await _stop(bid, WHY_STOPPED)
                return "failed"
            failed |= not await _run_switch(b, item, change)
        failed |= await _unconfirmed(bid)
    except Exception:  # noqa: BLE001
        log.exception("Sammeländerung %s: Lauf abgebrochen", bid)
        await _logged(bid, "Abbruch", _stop(bid, WHY_STOPPED, crashed=True))
        return "failed"
    return "failed" if failed else "done"


def _tally(counts: dict) -> str:
    """"2 erledigt, 1 fehlgeschlagen, 0 nicht gestartet" of the counts of a bulk change (German participles have one form for one and
    many, so the text holds for every number)."""
    return f"{counts['done']} erledigt, {counts['failed']} fehlgeschlagen, {counts['not_started']} nicht gestartet"


async def _counts(conn, bids: list[int]) -> dict[int, dict[str, int]]:
    """Per bulk change of bids its switches per state (COUNTED: each state of a switch, and pending, the switches whose change waits
    for its confirmation now)."""
    out = {bid: dict.fromkeys(COUNTED, 0) for bid in bids}
    async with conn.execute(f"SELECT i.bulk_id, i.status, c.status AS change_status FROM bulk_items i LEFT JOIN changes c ON c.id = i.change_id "
                            f"WHERE i.bulk_id IN ({', '.join('?' * len(bids))})", bids) as cur:
        for r in await cur.fetchall():
            counts = out[r["bulk_id"]]
            counts[r["status"]] = counts.get(r["status"], 0) + 1
            counts[changes.PENDING] += r["change_status"] == changes.PENDING
    return out


async def _told(b, end: str, title: str) -> None:
    """The end of bulk change b (its bulks row) in the audit, bulk_<end> of its starter ("#<bid> <summary>: <_tally>", with the API
    token it was started with: AUDIT_TOKEN for this entry only), and, with title, the alert bulk_problem (the link to the view bulk)."""
    bid = b["id"]
    async with db() as conn:
        text = _tally((await _counts(conn, [bid]))[bid])
    via = AUDIT_TOKEN.set((b["username"], b["api_token"]) if b["api_token"] else None)
    try:
        await _logged(bid, "Protokoll", audit(b["username"], f"bulk_{end}", "", f"#{bid} {b['summary']}: {text}", role=b["role"]))
    finally:
        AUDIT_TOKEN.reset(via)
    if title:
        await alerts.emit("bulk_problem", title, f"{b['summary']} (von {b['username']}): {text}", key=f"bulk:{bid}", facts={"_view": "bulk"})


async def run(bid: int) -> str:
    """The run of bulk change bid (the job of schedule): queued becomes running in one UPDATE (otherwise nothing happens and its
    status is the answer: a second run of the same bulk change starts nothing; "" for one that is not there). The run writes its
    audit entries, and those of the changes it starts, in the context of the API token the bulk change was started with (AUDIT_TOKEN
    from bulks.api_token, None without): a job runs in the context of whoever woke the scheduler. Then _run_switches, then the end:
    status and finished_at, the audit bulk_<end> and, for "failed", the alert bulk_problem "Sammeländerung #<bid> mit Fehlern beendet"
    (a cancelled one does not alert: a person wanted it), each on its own (_logged). Its end status."""
    async with db() as conn:
        taken = await conn.execute("UPDATE bulks SET status = 'running' WHERE id = ? AND status = 'queued'", (bid,))
        await conn.commit()
        async with conn.execute("SELECT * FROM bulks WHERE id = ?", (bid,)) as cur:
            b = await cur.fetchone()
    if b is None:
        return ""
    if taken.rowcount != 1:
        return b["status"]
    via = AUDIT_TOKEN.set((b["username"], b["api_token"]) if b["api_token"] else None)
    try:
        end = await _run_switches(b)
        await _logged(bid, "Ende", _ended(bid, end))
        await _logged(bid, "Meldung", _told(b, end, f"Sammeländerung #{bid} mit Fehlern beendet" if end == "failed" else ""))
    finally:
        AUDIT_TOKEN.reset(via)    # the changes it spawned copied the context already
    return end


async def _ended(bid: int, end: str) -> None:
    async with db() as conn:
        await conn.execute("UPDATE bulks SET status = ?, finished_at = ? WHERE id = ?", (end, changes._now(), bid))
        await conn.commit()


async def cancel(bid: int, user: dict) -> None:
    """The cancel of bulk change bid by user, in this order: it is there (404 NOT_FOUND), user started it (the case aside) or has
    Freigeben (403 CANCEL_WHO), it is queued or running (409 NOT_RUNNING). It sets cancel_requested; the run stops before its next
    switch, never inside a change (a change cut short would leave part of it at the switch, Spec §5). Audits bulk_cancel ("#<bid>")."""
    async with db() as conn:
        async with conn.execute("SELECT username FROM bulks WHERE id = ?", (bid,)) as cur:
            b = await cur.fetchone()
        if b is None:
            raise HTTPException(404, NOT_FOUND)
        if b["username"].casefold() != user["username"].casefold() and not roles.at_least(user["role"], roles.FREIGEBEN):
            raise HTTPException(403, CANCEL_WHO)
        asked = await conn.execute("UPDATE bulks SET cancel_requested = 1 WHERE id = ? AND status IN ('queued', 'running')", (bid,))
        await conn.commit()
    if asked.rowcount != 1:
        raise HTTPException(409, NOT_RUNNING.format(bid=bid))
    await audit(user["username"], "bulk_cancel", "", f"#{bid}", role=user["role"])


async def confirm_all(bid: int, user: dict) -> dict:
    """"Alle bestätigen": every change of bulk change bid that waits for its confirmation, in the order of its id, through
    confirm.confirm_change with its rules (zone, who may, the deadline, ...) for user; 404 NOT_FOUND for a bulk change that is not
    there. {"confirmed": [<id>, ...], "refused": [{"id", "detail"}, ...]}."""
    async with db() as conn:
        async with conn.execute("SELECT 1 FROM bulks WHERE id = ?", (bid,)) as cur:
            if await cur.fetchone() is None:
                raise HTTPException(404, NOT_FOUND)
        async with conn.execute("SELECT id FROM changes WHERE bulk_id = ? AND status = 'pending' ORDER BY id", (bid,)) as cur:
            ids = [r["id"] for r in await cur.fetchall()]
    confirmed, refused = [], []
    for cid in ids:
        try:
            await confirm.confirm_change(cid, user)
            confirmed.append(cid)
        except HTTPException as e:
            refused.append({"id": cid, "detail": e.detail})
    return {"confirmed": confirmed, "refused": refused}


def _change_of(r) -> dict | None:
    """The change of a switch of a bulk change as GET /api/bulk/{blk} names it, of now; None before it started (or once it went with
    its switch)."""
    if r["c_id"] is None:
        return None
    return {"id": r["c_id"], "status": r["c_status"], "error": r["c_error"], "saved": r["c_saved"], "confirm_until": r["c_until"],
            "confirmed_by": r["c_by"], "reverted_by": r["c_rev"]}


async def get(bid: int) -> dict | None:
    """Bulk change bid as GET /api/bulk/{blk} answers it (None: not there): its row (change as the PortChange it ran, expert and
    cancel_requested as booleans; not the API token), items - per switch in its order pos, switch_id (None once deleted), switch (the
    name of now, else the stored one), zone (of now, "" once deleted), ports, status, detail and change (_change_of) - and counts."""
    async with db() as conn:
        async with conn.execute("SELECT * FROM bulks WHERE id = ?", (bid,)) as cur:
            b = await cur.fetchone()
        if b is None:
            return None
        async with conn.execute(
                "SELECT i.pos, i.switch_id, COALESCE(s.name, i.switch_name) AS switch, COALESCE(s.zone, '') AS zone, i.ports, i.status, "
                "i.detail, c.id AS c_id, c.status AS c_status, c.error AS c_error, c.saved AS c_saved, c.confirm_until AS c_until, "
                "c.confirmed_by AS c_by, c.reverted_by AS c_rev FROM bulk_items i LEFT JOIN switches s ON s.id = i.switch_id "
                "LEFT JOIN changes c ON c.id = i.change_id WHERE i.bulk_id = ? ORDER BY i.pos", (bid,)) as cur:
            items = await cur.fetchall()
        counts = (await _counts(conn, [bid]))[bid]
    return {"id": b["id"], "created_at": b["created_at"], "username": b["username"], "role": b["role"], "approved_by": b["approved_by"],
            "summary": b["summary"], "change": json.loads(b["change"]), "expert": bool(b["expert"]), "on_error": b["on_error"],
            "confirm_minutes": b["confirm_minutes"], "status": b["status"], "cancel_requested": bool(b["cancel_requested"]),
            "finished_at": b["finished_at"],
            "items": [{"pos": r["pos"], "switch_id": r["switch_id"], "switch": r["switch"], "zone": r["zone"], "ports": json.loads(r["ports"]),
                       "status": r["status"], "detail": r["detail"], "change": _change_of(r)} for r in items],
            "counts": counts}


async def listing(limit: int = 50) -> list[dict]:
    """The last limit bulk changes (1-100), newest first, each with id, created_at, username, summary, status and counts."""
    async with db() as conn:
        async with conn.execute("SELECT id, created_at, username, summary, status FROM bulks ORDER BY id DESC LIMIT ?",
                                (max(1, min(limit, 100)),)) as cur:
            rows = await cur.fetchall()
        counts = await _counts(conn, [r["id"] for r in rows])
    return [dict(r) | {"counts": counts[r["id"]]} for r in rows]


async def mark_interrupted() -> int:
    """At start (main.lifespan, right after changes.mark_interrupted): every bulk change the last process left queued or running ends
    interrupted, in one write transaction - its running switch failed with WHY_RESTART (its change, if it started one, changes ended
    already), every waiting one not started (WHY_RESTART) - and none is continued (T7-f). After the commit each gets the audit
    bulk_interrupted of its starter and the alert bulk_problem "Sammeländerung #<bid> durch Neustart abgebrochen"; changes waiting for
    their confirmation keep their deadlines (the watch, confirm.watch). Returns how many."""
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute("SELECT * FROM bulks WHERE status IN ('queued', 'running') ORDER BY id") as cur:
            ended = await cur.fetchall()
        for b in ended:
            await conn.execute("UPDATE bulk_items SET status = 'failed', detail = ? WHERE bulk_id = ? AND status = 'running'", (WHY_RESTART, b["id"]))
            await conn.execute("UPDATE bulk_items SET status = 'not_started', detail = ? WHERE bulk_id = ? AND status = 'waiting'",
                               (NOT_STARTED.format(why=WHY_RESTART), b["id"]))
            await conn.execute("UPDATE bulks SET status = 'interrupted', finished_at = ? WHERE id = ?", (changes._now(), b["id"]))
        await conn.commit()
    for b in ended:
        await _logged(b["id"], "Meldung", _told(b, "interrupted", f"Sammeländerung #{b['id']} durch Neustart abgebrochen"))
    return len(ended)
