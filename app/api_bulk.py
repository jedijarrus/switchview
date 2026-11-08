"""The routes of bulk changes (Phase 4c): Task 6 the combined preview, POST /api/bulk/plan (Ändern); Task 7 the start (POST
/api/bulk, Ändern), the list and one bulk change (GET /api/bulk, GET /api/bulk/{blk}, Lesen, not limited by zone like every read),
the cancel and "Alle bestätigen" (POST /api/bulk/{blk}/cancel and /confirm, Ändern). The rules are in bulk."""
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
    bulk.APPROVAL_NEEDED: requested instead, Task 8), every switch against its preview token (bulk.precheck, 409 bulk.OUTDATED
    naming each that does not match; nothing starts). Then bulk.create (with the label of the API token of the request), the audit
    bulk_start ("#<bid> <summary>") and its run as a job (bulk.schedule). {"id": <bid>}."""
    bulk.validate(body)
    four_eyes = (await approvals.policy())["four_eyes"]
    await bulk.rights(user, body, four_eyes)
    if four_eyes:
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
