"""The shared world of the bulk tests (Phase 4c, Tasks 6-8; Ruling 1 of the plan): a fresh database with three switches, a fake
per-switch planner and a fake poll inventory, so a bulk preview runs without a switch and without the network.

make_world(tmp_path, monkeypatch, zones) builds it and keeps it in WORLD; fake_plan is the fake api_changes._make_plan of that
world (a module function, so a test can wrap it: `return await fake_plan(row, body)`). Each bulk test module defines a thin
fixture world that calls make_world and imports `from bulkfix import fake_plan, make_world`; Tasks 7 and 8 add what their tests
need here (the fake run, items_of, start).

Like tests/apifix.py this module imports app code, so a test module imports it at the top, after conftest.py has set the
environment.
"""
import api_changes
import apifix
import changes
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
    adds another switch in zone EK, extra_ids are their ids in order."""

    def __init__(self, zones: tuple[str, str, str]):
        self.a, self.b, self.c = (dbfix.insert_switch(name=name, host=f"10.0.0.{i + 1}", zone=zone, **POLLED)
                                  for i, (name, zone) in enumerate(zip("ABC", zones)))
        self.plans: dict[str, dict | BaseException] = {}
        self.inv: dict[int, dict] = {}
        self.extra_ids: list[int] = []

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


def make_world(tmp_path, monkeypatch, zones: tuple[str, str, str] = ("EK", "EK", "VK")) -> World:
    """A fresh database (apifix.fresh_db) with A, B and C in zones, polled as POLLED says; api_changes._make_plan is
    fake_plan, changes.inventory reads world.inv. The world, also in WORLD."""
    global WORLD
    apifix.fresh_db(tmp_path, monkeypatch)
    WORLD = World(zones)
    monkeypatch.setattr(api_changes, "_make_plan", fake_plan)
    monkeypatch.setattr(changes, "inventory", _inventory)
    return WORLD
