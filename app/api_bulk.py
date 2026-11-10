"""The routes of bulk changes (Phase 4c): Task 6 the combined preview, POST /api/bulk/plan (Ändern); Task 7 the start (POST
/api/bulk, Ändern), the list and one bulk change (GET /api/bulk, GET /api/bulk/{blk}, Lesen, not limited by zone like every read),
the cancel and "Alle bestätigen" (POST /api/bulk/{blk}/cancel and /confirm, Ändern); Task 8 four eyes: the kind bulk_change of the
approvals (registered here at import, approvals.register), with what a request stores (request_parts), the reviewer's fresh preview
and the approver's run. The rules are in bulk."""
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import api_changes
import approvals
import auth
import bulk
import roles
from db import audit

router = APIRouter()


class BulkTarget(BaseModel):
    """One switch of a bulk request and its ports: a list (at most 200, the limit of PlanIn), or untagged_in, the filter "every
    access port untagged in this VLAN by the last poll" (bulk.resolve); exactly one of both (bulk.preview checks it)."""
    switch_id: int
    ports: list[str] = Field(default_factory=list, max_length=200)
    untagged_in: str | None = Field(default=None, pattern=r"^\d{1,4}$")


class BulkPlanIn(BaseModel):
    """The preview of a bulk change: its switches (bulk.MAX_SWITCHES of them, which bulk.preview says in German; 100 is only the
    bound of the body), the change once, as the form of a switch offers it, and the expert mode."""
    targets: list[BulkTarget] = Field(min_length=1, max_length=100)
    change: api_changes.PortChange
    expert: bool = False


@router.post("/api/bulk/plan")
async def plan_bulk(body: BulkPlanIn, user=Depends(auth.require(roles.AENDERN))):
    """Per switch the preview of /plan with its own preview token, or why the switch is skipped; the combined token, whether the bulk
    needs an approval and whether it can run with confirmation (bulk.preview). Starts nothing."""
    return await bulk.preview(user, body)


class BulkItemIn(BaseModel):
    """A ready switch of a bulk change as its preview showed it (a section of POST /api/bulk/plan): the ports it resolved (the run takes
    these, never the filter again, T6-a), its preview token and its write way."""
    switch_id: int
    ports: list[str] = Field(min_length=1, max_length=200)
    token: str = Field(max_length=32)
    mechanism: str = Field(pattern=r"^(ssh|snmp)$")


class BulkSkip(BaseModel):
    """A switch the preview skipped, with its reason: it stands in the summary, nothing runs there."""
    switch_id: int
    reason: str = Field(default="", max_length=300)


class BulkIn(BaseModel):
    """The start of a bulk change from its preview: the ready switches (bulk.MAX_SWITCHES with the skipped ones, which bulk.validate
    says in German; 100 is only the bound of the body), the skipped ones, the change and the expert mode of the preview, on_error
    (stop: the first failure stops the rest; continue: the rest runs) and confirm_minutes (each switch waits that long for its
    confirmation, as /apply takes it; None: without)."""
    items: list[BulkItemIn] = Field(min_length=1, max_length=100)
    skipped: list[BulkSkip] = Field(default_factory=list, max_length=100)
    change: api_changes.PortChange
    expert: bool = False
    on_error: str = Field(default="stop", pattern=r"^(stop|continue)$")
    confirm_minutes: int | None = Field(default=None, ge=1, le=api_changes.CONFIRM_MAX, strict=True)


@router.post("/api/bulk")
async def start_bulk(body: BulkIn, user=Depends(auth.require(roles.AENDERN))):
    """Starts a bulk change, checked in this order (the rights before "needs an approval", as /apply): the limits (bulk.validate,
    422), the zone and the mode at every switch (bulk.rights, 403; a switch gone 404, disabled 409), the four-eyes principle (409
    bulk.APPROVAL_NEEDED where approvals.needs_approval says so: requested instead, POST /api/approvals of the kind bulk_change),
    every switch against its preview token (bulk.precheck, 409 bulk.OUTDATED naming each that does not match; nothing starts). Then
    bulk.create (with the label of the API token of the request), the audit bulk_start ("#<bid> <summary>") and its run as a job
    (bulk.schedule). {"id": <bid>}."""
    bulk.validate(body)
    four_eyes = (await approvals.policy())["four_eyes"]
    await bulk.rights(user, body, four_eyes)
    if approvals.needs_approval(approvals.BULK_CHANGE, {}, four_eyes):
        raise HTTPException(409, bulk.APPROVAL_NEEDED)
    await bulk.precheck(body)
    label = auth.token_label(user["api_token"]) if user["api_token"] else None
    bid = await bulk.create(body, user, api_token=label)
    await audit(user["username"], "bulk_start", "", f"#{bid} {bulk.summary_of(body)}", role=user["role"])
    bulk.schedule(bid)
    return {"id": bid}


@router.get("/api/bulk")
async def list_bulks(limit: int = Query(default=50, ge=1, le=100), user=Depends(auth.require(roles.LESEN))):
    """The last limit bulk changes, newest first, with their counts (bulk.listing)."""
    return await bulk.listing(limit)


@router.get("/api/bulk/{blk}")
async def get_bulk(blk: int, user=Depends(auth.require(roles.LESEN))):
    """One bulk change with each switch, its state and its change of now (bulk.get); 404 bulk.NOT_FOUND."""
    found = await bulk.get(blk)
    if found is None:
        raise HTTPException(404, bulk.NOT_FOUND)
    return found


@router.post("/api/bulk/{blk}/cancel")
async def cancel_bulk(blk: int, user=Depends(auth.require(roles.AENDERN))):
    """Asks the run of a waiting or running bulk change to stop before its next switch (bulk.cancel). {"ok": True, "id": <blk>}."""
    await bulk.cancel(blk, user)
    return {"ok": True, "id": blk}


@router.post("/api/bulk/{blk}/confirm")
async def confirm_bulk(blk: int, user=Depends(auth.require(roles.AENDERN))):
    """"Alle bestätigen": every change of the bulk change that waits for its confirmation, each with the rules of
    POST /api/changes/{cid}/confirm (bulk.confirm_all)."""
    return await bulk.confirm_all(blk, user)


# ── Task 8: four eyes, the kind bulk_change ────────────────────────────────────────────────────────────────────────────────────────
# Why a switch whose commands are those of the request does not match in the reviewer's preview: the planner chose another write way
OTHER_WAY = "Der Schreibweg von jetzt ist ein anderer als der der Vorschau der Anfrage"
# The keys of a switch's preview (api_changes.preview_answer) a request stores and a reviewer sees, beside switch_id, switch and ports
SECTION_KEYS = ("mechanism", "commands", "warnings", "token")


async def request_parts(body: BulkIn) -> tuple[str, dict, dict]:
    """What a four-eyes request of bulk change body stores (POST /api/approvals of the kind bulk_change), after every switch matched
    its preview token (bulk.precheck: its 409 bulk.OUTDATED goes through, nothing is stored): the summary (bulk.summary_of), the
    payload - body as it was sent, BulkIn(**payload) restores it - and the preview its requester saw: summary, token (bulk.token_of
    the switches), sections - per ready switch switch_id, switch, ports and SECTION_KEYS - and skipped, the skipped switches with
    their name of now ("#<id>" for one that is gone) and their reason."""
    checked = await bulk.precheck(body)
    sections = [{"switch_id": c["switch_id"], "switch": c["switch"], "ports": c["ports"]} | {k: c["preview"][k] for k in SECTION_KEYS}
                for c in checked]
    names = await bulk.names_of([s.switch_id for s in body.skipped]) if body.skipped else {}
    summary = bulk.summary_of(body)
    preview = {"summary": summary, "token": bulk.token_of([(s["switch_id"], s["token"]) for s in sections]), "sections": sections,
               "skipped": [{"switch_id": s.switch_id, "switch": names.get(s.switch_id, f"#{s.switch_id}"), "reason": s.reason}
                           for s in body.skipped]}
    return summary, body.model_dump(mode="json"), preview


async def _preview_bulk(a: dict, user: dict) -> dict:
    """The reviewer's preview of bulk request a: every switch of the request planned now with its ports (bulk.section, the planner of
    the preview, at most bulk.PARALLEL at once; a switch that is gone, disabled, unreadable or blocked now is a section with that
    status and reason, never an error of the whole). Per switch switch_id, switch, ports, status, reason, SECTION_KEYS of now (None
    and [] without a plan) and matches: ready, the commands those of the requester's preview (the same token) and on its write way
    (else OTHER_WAY). kind, the request's summary, sections, token (bulk.token_of the ready ones: the request's when all match) and
    matches (every switch does). Only then can it be approved; the binding check is the run's (bulk.precheck)."""
    body = BulkIn(**a["payload"])
    four_eyes = (await approvals.policy())["four_eyes"]
    gate = asyncio.Semaphore(bulk.PARALLEL)

    async def planned(item: BulkItemIn) -> dict:
        async with gate:
            s = await bulk.section(user, BulkTarget(switch_id=item.switch_id, ports=item.ports), body.change, body.expert, four_eyes)
        p = s["preview"] or {"mechanism": None, "commands": [], "warnings": [], "token": None}
        ready = s["status"] == "ready"
        other_way = ready and p["token"] == item.token and p["mechanism"] != item.mechanism
        return ({"switch_id": s["switch_id"], "switch": s["switch"], "ports": s["ports"], "status": s["status"],
                 "reason": OTHER_WAY if other_way else s["reason"]} | {k: p[k] for k in SECTION_KEYS}
                | {"matches": ready and p["token"] == item.token and not other_way})

    sections = await asyncio.gather(*(planned(i) for i in body.items))
    return {"kind": approvals.BULK_CHANGE, "summary": a["summary"], "sections": sections,
            "token": bulk.token_of([(s["switch_id"], s["token"]) for s in sections if s["status"] == "ready"]),
            "matches": all(s["matches"] for s in sections)}


async def _run_bulk(a: dict, approver: dict, comment: str) -> int:
    """Starts the bulk change of request a, approved by approver with comment: first every switch against its preview token
    (bulk.precheck; its api_changes.PreviewOutdated makes the request stale in api_approvals, and nothing starts), then bulk.create -
    the bulk change is the requester's (their name and their role when they asked), without an API token (a request keeps none, and
    approving never goes by token), approved_by names the approver, and the request is claimed in the transaction that creates the
    bulk change (approvals.claim, column bulk_id: of two approvals at once one starts it) -, then its run as a job (bulk.schedule).
    The bulk change's id."""
    body = BulkIn(**a["payload"])
    await bulk.precheck(body)
    bid = await bulk.create(body, {"username": a["requested_by"], "role": a["requester_role"]}, approved_by=approver["username"],
                            claim=lambda conn, bid: approvals.claim(conn, a["id"], approver, comment, bid, column="bulk_id"))
    bulk.schedule(bid)
    return bid


approvals.register(approvals.Kind(approvals.BULK_CHANGE, "Sammeländerung", preview=_preview_bulk, run=_run_bulk, started="Sammeländerung"))
