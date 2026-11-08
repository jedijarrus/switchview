"""Bulk changes (Phase 4c): the same port change on many ports of many switches, each switch through the guided loop of a single
change. Task 6: the selection per switch and the combined preview. A request names the change once and per switch its ports, as a
list or as the filter "every access port untagged in VLAN N by the last poll" (resolve); each switch gets a section planned by the
per-switch planner (api_changes._make_plan) with its own preview token, at most PARALLEL at once. A switch outside the user's
zones, with a blocked port, with nothing to do or that cannot be planned is skipped with its reason; the uplink, trunk and LAG
protection is the planner's, per switch, as today. The preview starts nothing: what runs later (Task 7) are the port lists it
showed, never the filter again."""
import asyncio

from fastapi import HTTPException

import api_changes
import approvals
import changes
import snmpwrite

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
