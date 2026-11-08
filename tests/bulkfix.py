"""The shared world of the bulk tests (Phase 4c, Tasks 6-8; Ruling 1 of the plan): a fresh database with three switches, a fake
per-switch planner and a fake poll inventory, so a bulk preview runs without a switch and without the network.

make_world(tmp_path, monkeypatch, zones) builds it and keeps it in WORLD; fake_plan is the fake api_changes._make_plan of that
world (a module function, so a test can wrap it: `return await fake_plan(row, body)`). Each bulk test module defines a thin
fixture world that calls make_world and imports `from bulkfix import fake_plan, make_world`. Task 7 adds the run: fake_run_change,
the fake changes.run_change of the world, a recorded bulk.schedule (World.scheduled) and bulk.POLL_S 0, so a test runs a bulk with
`asyncio.run(bulk.run(bid))`; and items_of and start, the body of POST /api/bulk as the UI builds it from a preview, and the start
itself (Task 8 imports items_of).

Like tests/apifix.py this module imports app code, so a test module imports it at the top, after conftest.py has set the
environment.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import api_changes
import apifix
import bulk
import changes
import db
import dbfix

# The world make_world created last: fake_plan and the fake inventory read it
WORLD = None
# The inventory of a switch the world has none for: no port at all (a switch without a poll)
NO_PORTS = {"ports": {}, "uplinks": set()}
# The poll columns of every switch of the world: one good poll, at 09:00 UTC
POLLED = {"last_poll": "2026-11-08 09:00:00", "last_poll_ok": 1, "last_ok_at": "2026-11-08 09:00:00"}


class World:
    """Switches A, B and C (ids a, b, c) in zones; plans: per switch name what fake_plan plans for it (an exception it raises, a dict
    it lays over its default plan); inv: per switch id the poll inventory (changes.inventory), NO_PORTS without an entry; extra(name)
    adds another switch in zone EK, extra_ids are their ids in order. For the run (Task 7): ends, per switch name the status
    fake_run_change ends its change with ("ok" without an entry); order, the switch ids in the order their changes ran; after_start,
    per switch id a function fake_run_change calls (in a thread) right before it writes the end; scheduled, the bulk ids bulk.schedule
    was given."""

    def __init__(self, zones: tuple[str, str, str]):
        self.a, self.b, self.c = (dbfix.insert_switch(name=name, host=f"10.0.0.{i + 1}", zone=zone, **POLLED)
                                  for i, (name, zone) in enumerate(zip("ABC", zones)))
        self.plans: dict[str, dict | BaseException] = {}
        self.inv: dict[int, dict] = {}
        self.extra_ids: list[int] = []
        self.ends: dict[str, str] = {}
        self.order: list[int] = []
        self.after_start: dict[int, object] = {}
        self.scheduled: list[int] = []

    def extra(self, name: str) -> int:
        sid = dbfix.insert_switch(name=name, host=f"10.0.1.{len(self.extra_ids) + 1}", zone="EK", **POLLED)
        self.extra_ids.append(sid)
        return sid


async def fake_plan(row, body):
    """api_changes._make_plan of WORLD: for the switch of row WORLD.plans[<its name>] - an exception is raised, a dict is laid over the
    default plan, which sets VLAN 30 untagged on body.ports (shown "vlan 30 untagged <ports>", nothing blocked, over SSH, each port
    from VLAN 20)."""
    over = WORLD.plans.get(row["name"], {})
    if isinstance(over, BaseException):
        raise over
    shown = [f"vlan 30 untagged {','.join(body.ports)}"]
    plan = {"shown": shown, "blocked": [], "mechanism": "ssh", "warnings": [], "expert": body.expert,
            "desired": {p: {"u": "30"} for p in body.ports}, "before": {p: {"u": "20"} for p in body.ports}} | over
    plan.setdefault("commands", plan["shown"])
    return plan, {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}, "ports", api_changes._summary(body)


async def _inventory(sid: int) -> dict:
    return WORLD.inv.get(sid, NO_PORTS)


async def fake_run_change(cid: int) -> None:
    """changes.run_change of WORLD: notes the switch of change cid in WORLD.order, calls WORLD.after_start[<switch id>], if there is
    one, then ends the change with WORLD.ends[<its switch's name>] ("ok" without an entry), sent 1 and finished_at now - "pending" also
    with confirm_until now + 5 minutes, as run_change leaves a change waiting for its confirmation. Nothing is read, sent or audited.
    after_start (a function with dbfix.query, sqlite3 in the calling thread) runs in a thread before the end: the run sees its writes
    once it sees the end (bulk._settled), and the event loop stays free meanwhile - called in the loop, it blocked the commit of a
    write the run had open (bulk._set_item of change_id) until "database is locked"."""
    async with db.db() as conn:
        async with conn.execute("SELECT c.switch_id, s.name FROM changes c JOIN switches s ON s.id = c.switch_id WHERE c.id = ?",
                                (cid,)) as cur:
            sid, name = await cur.fetchone()
    WORLD.order.append(sid)
    if sid in WORLD.after_start:
        await asyncio.to_thread(WORLD.after_start[sid])
    async with db.db() as conn:
        end = WORLD.ends.get(name, "ok")
        now = datetime.now(timezone.utc)
        until = (now + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S") if end == changes.PENDING else None
        await conn.execute("UPDATE changes SET status = ?, sent = 1, finished_at = ?, confirm_until = ? WHERE id = ?",
                           (end, now.strftime("%Y-%m-%d %H:%M:%S"), until, cid))
        await conn.commit()


def items_of(preview: dict, **over) -> dict:
    """The body of POST /api/bulk as the UI builds it from a preview: the ready sections with their ports, preview token and write way,
    the skipped ones with their reason."""
    ready = [s for s in preview["sections"] if s["status"] == "ready"]
    return {"items": [{"switch_id": s["switch_id"], "ports": s["ports"], "token": s["preview"]["token"], "mechanism": s["preview"]["mechanism"]}
                      for s in ready],
            "skipped": [{"switch_id": s["switch_id"], "reason": s["reason"]} for s in preview["sections"] if s["status"] != "ready"],
            "change": {"untagged": "30"}} | over


def start(client, world, who="anna", planner=None, **over):
    """The preview of planner (who, unless given: a test that forges a body plans as someone else), then POST /api/bulk as who."""
    preview = client.post("/api/bulk/plan", json={"targets": [{"switch_id": s, "ports": ["1", "2"]} for s in (world.a, world.b, world.c)],
                                                  "change": {"untagged": "30"}}, headers={"X-Test-User": planner or who}).json()
    return client.post("/api/bulk", json=items_of(preview, **over), headers={"X-Test-User": who})


def make_world(tmp_path, monkeypatch, zones: tuple[str, str, str] = ("EK", "EK", "VK")) -> World:
    """A fresh database (apifix.fresh_db) with A, B and C in zones, polled as POLLED says; api_changes._make_plan is
    fake_plan, changes.inventory reads world.inv, changes.run_change is fake_run_change, bulk.schedule notes the bulk in
    world.scheduled (nothing is scheduled), and the run asks for the end of a change without a pause (bulk.POLL_S 0). The world, also
    in WORLD."""
    global WORLD
    apifix.fresh_db(tmp_path, monkeypatch)
    WORLD = World(zones)
    monkeypatch.setattr(api_changes, "_make_plan", fake_plan)
    monkeypatch.setattr(changes, "inventory", _inventory)
    monkeypatch.setattr(changes, "run_change", fake_run_change)
    monkeypatch.setattr(bulk, "schedule", WORLD.scheduled.append)
    monkeypatch.setattr(bulk, "POLL_S", 0)
    return WORLD
