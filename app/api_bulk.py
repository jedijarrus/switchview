"""The routes of bulk changes (Phase 4c): Task 6 the combined preview, POST /api/bulk/plan (Ändern); the rules are in bulk."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

import api_changes
import auth
import bulk
import roles

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
