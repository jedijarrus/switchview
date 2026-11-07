"""The four-eyes routes (Phase 4a, Tasks 6 and 7): request a change that needs an approval (POST /api/approvals), list and read the
requests, withdraw one's own, reject someone else's (Task 6); review someone else's against a fresh plan and approve it, which starts
the change through the change loop of /apply (api_changes.start_change, Task 7). The kind port_change (an expert-mode port change)
is registered here at import (approvals.register). The mechanism itself is app/approvals.py.

Everything of api_changes goes through the module (api_changes.X), never imported by name: the tests replace api_changes._make_plan,
and a request is planned and checked by exactly the code of /plan and /apply."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import api_changes
import approvals
import auth
import roles
from db import audit

router = APIRouter()

NO_APPROVAL_NEEDED = "Diese Änderung braucht keine Freigabe – sie lässt sich direkt ausführen"
ONLY_OWN = "Zurückziehen kann nur, wer die Freigabe angefordert hat"
OWN_REJECT = "Die eigene Anfrage bitte zurückziehen, nicht ablehnen"
NOT_FOUND = "Anfrage nicht gefunden"
SELF = "Die eigene Anfrage kann niemand selbst freigeben – auch nicht mit der Rolle „Admin“"
EMERGENCY = "Der Notfall-Login gibt keine Anfrage frei: er ist kein persönliches Konto"
REVIEW_AGAIN = "Diese Vorschau ist nicht die der Anfrage – bitte die Anfrage neu prüfen"
STALE_REQUEST = "Der Switch hat sich seit der Anfrage geändert: die Anfrage ist veraltet und muss neu gestellt werden"
DECIDED = "Anfrage #{aid} ist schon entschieden"


class ApprovalIn(BaseModel):
    kind: str = Field(pattern=r"^port_change$")
    switch_id: int
    plan: api_changes.PlanIn


class CommentIn(BaseModel):
    comment: str = Field(default="", max_length=500)


class ApproveIn(BaseModel):
    token: str = Field(max_length=32)       # the token of the preview the approver saw (POST …/preview), the request's own
    comment: str = Field(default="", max_length=500)


def not_open(a: dict) -> HTTPException:
    """The 409 for a request that is no longer open, naming its status."""
    return HTTPException(409, f"Anfrage #{a['id']} ist {approvals.STATUS_LABEL[a['status']]}")


def _target(a: dict) -> str:
    """The audit target of a request: its switch's id ("" for a kind without a switch)."""
    return "" if a["switch_id"] is None else str(a["switch_id"])


async def _found(aid: int) -> dict:
    """Request aid (approvals.get, so expired ones are marked first), 404 NOT_FOUND without one."""
    a = await approvals.get(aid)
    if a is None:
        raise HTTPException(404, NOT_FOUND)
    return a


async def _announce(event: str, aid: int) -> None:
    """Tells the listeners event about request aid as it stands now; a request gone with its switch meanwhile is told to no one."""
    a = await approvals.get(aid)
    if a is not None:
        await approvals.emit(event, a)


def _port_change_body(a: dict, **extra) -> api_changes.PlanIn:
    """The change request a asks for, as its requester sent it (its payload), on the write way of its preview (mechanism): planned
    exactly so or refused, never silently over the other way."""
    return api_changes.PlanIn(**a["payload"], mechanism=a["preview"]["mechanism"], **extra)


async def _preview_port_change(a: dict, user: dict) -> dict:
    """The reviewer's preview of request a: planned now, by the code of /plan (api_changes._make_plan; its errors go through) on the
    write way of the requester's preview, answered as /plan answers, plus matches: nothing is blocked and the commands are those of
    the requester's preview (the same token). Only then can it be approved."""
    row = await api_changes._enabled_row(a["switch_id"])
    plan, _, kind, summary = await api_changes._make_plan(row, _port_change_body(a))
    answer = api_changes.preview_answer(row, plan, kind, summary)
    return answer | {"matches": not plan["blocked"] and answer["token"] == a["preview"]["token"]}


async def _run_port_change(a: dict, approver: dict, comment: str) -> int:
    """Starts the change of request a, approved by approver with comment, through api_changes.start_change (the code of /apply):
    the change is the requester's (their name and their role when they asked), approved_by names the approver, and the request is
    claimed in the transaction that creates the change (approvals.claim). The change's id."""
    row = await api_changes._enabled_row(a["switch_id"])
    return await api_changes.start_change(row, _port_change_body(a, token=a["preview"]["token"]),
                                          {"username": a["requested_by"], "role": a["requester_role"]}, approved_by=approver["username"],
                                          claim=lambda conn, cid: approvals.claim(conn, a["id"], approver, comment, cid))


approvals.register(approvals.Kind(approvals.PORT_CHANGE, "Port-Änderung im Expertenmodus", preview=_preview_port_change,
                                  run=_run_port_change))


@router.post("/api/approvals")
async def request_approval(body: ApprovalIn, user=Depends(auth.require(roles.AENDERN))):
    """A four-eyes request for the change body.plan at switch body.switch_id, checked in this order: the switch is there and enabled
    (api_changes._enabled_row); the change needs an approval (approvals.needs_approval, else 409 NO_APPROVAL_NEEDED: a prepare, a
    revert, a save and a change without expert mode go directly, as does everything with the four-eyes principle off); the rights of
    its mode and the zone (api_changes._mode_rights); the plan of now is the preview's (api_changes.checked_plan, the errors of
    /apply). Stores exactly the desired state the requester sent (without the empty defaults of PortChange: PlanIn(**payload) restores
    the request) and the preview they saw (api_changes.preview_answer); audits approval_requested and tells the listeners."""
    row = await api_changes._enabled_row(body.switch_id)
    four_eyes = (await approvals.policy())["four_eyes"]
    if not approvals.needs_approval(approvals.PORT_CHANGE, body.plan.model_dump(), four_eyes):
        raise HTTPException(409, NO_APPROVAL_NEEDED)
    await api_changes._mode_rights(user, row, body.plan, four_eyes)
    plan, _, kind, summary = await api_changes.checked_plan(row, body.plan)
    preview = api_changes.preview_answer(row, plan, kind, summary)
    payload = {"mode": body.plan.mode, "ports": body.plan.ports, "change": body.plan.change.model_dump(exclude_defaults=True),
               "expert": body.plan.expert}
    aid = await approvals.create(approvals.PORT_CHANGE, body.switch_id, summary, payload, preview, user)
    await audit(user["username"], "approval_requested", str(body.switch_id), f"#{aid} {summary}", role=user["role"])
    await _announce("requested", aid)
    return {"id": aid}


@router.get("/api/approvals")
async def list_approvals(status: str = Query(default="open", pattern=r"^(open|all)$"), limit: int = Query(default=100, ge=1, le=200),
                         user=Depends(auth.require(roles.LESEN))):
    """The open requests (status=all: every one), newest first, without payload and preview."""
    rows = await approvals.listing(None if status == "all" else approvals.OPEN, limit)
    return [approvals.public(a, user) for a in rows]


@router.get("/api/approvals/{aid}")
async def get_approval(aid: int, user=Depends(auth.require(roles.LESEN))):
    """One request with payload and preview."""
    return approvals.public(await _found(aid), user)


@router.post("/api/approvals/{aid}/withdraw")
async def withdraw_approval(aid: int, user=Depends(auth.require(roles.AENDERN))):
    """Only the requester withdraws (approvals.same_person, else 403 ONLY_OWN), and only an open request (409 not_open, also when
    another decision came first)."""
    a = await _found(aid)
    if not approvals.same_person(user, a):
        raise HTTPException(403, ONLY_OWN)
    if a["status"] != approvals.OPEN:
        raise not_open(a)
    if not await approvals.set_status(aid, approvals.WITHDRAWN, user):
        raise not_open(await _found(aid))
    await audit(user["username"], "approval_withdrawn", _target(a), f"#{aid} {a['summary']}", role=user["role"])
    await _announce("withdrawn", aid)
    return {"ok": True}


@router.post("/api/approvals/{aid}/reject")
async def reject_approval(aid: int, body: CommentIn, user=Depends(auth.require(roles.FREIGEBEN))):
    """Someone with Freigeben rejects an open request of someone else (403 OWN_REJECT for one's own: withdraw it), at a switch of
    their zones (403 roles.zone_denial, the switch's zone of now), with an optional comment (trimmed; audited after the summary)."""
    a = await _found(aid)
    if approvals.same_person(user, a):
        raise HTTPException(403, OWN_REJECT)
    if not roles.zone_allows(user, a["switch_zone"]):
        raise HTTPException(403, roles.zone_denial(a["switch_zone"], user["zones"]))
    if a["status"] != approvals.OPEN:
        raise not_open(a)
    comment = body.comment.strip()
    if not await approvals.set_status(aid, approvals.REJECTED, user, comment=comment):
        raise not_open(await _found(aid))
    await audit(user["username"], "approval_rejected", _target(a), f"#{aid} {a['summary']}" + (f": {comment}" if comment else ""),
                role=user["role"])
    await _announce("rejected", aid)
    return {"ok": True}


@router.post("/api/approvals/{aid}/preview")
async def preview_approval(aid: int, user=Depends(auth.require(roles.FREIGEBEN))):
    """The reviewer's fresh preview of an open request at a switch of their zones (403 roles.zone_denial, the switch's zone of now):
    the preview of its kind (for port_change planned now, with matches); the errors of planning go through (409 STALE, 502, …)."""
    a = await _found(aid)
    if a["status"] != approvals.OPEN:
        raise not_open(a)
    if not roles.zone_allows(user, a["switch_zone"]):
        raise HTTPException(403, roles.zone_denial(a["switch_zone"], user["zones"]))
    return await approvals.KINDS[a["kind"]].preview(a, user)


@router.post("/api/approvals/{aid}/approve")
async def approve_approval(aid: int, body: ApproveIn, user=Depends(auth.require(roles.FREIGEBEN))):
    """Someone with Freigeben approves an open request of someone else, which starts its change at once (the run of its kind:
    api_changes.start_change, the code of /apply). In this order: 404; not open (409 not_open); one's own (approvals.same_person,
    403 SELF, Admin too); the emergency login (403 EMERGENCY: a shared account, not a person); the switch disabled (409 DISABLED) or
    outside the approver's zones (403); body.token not the request's preview (409 REVIEW_AGAIN: the approver saw another preview).
    Then the run: a plan that is no longer the preview (api_changes.PreviewOutdated) sends nothing and makes the request stale (409
    STALE_REQUEST with the reason; audited and announced when this call made it so); a request decided meanwhile (the claim in the
    change's transaction, approvals.AlreadyDecided) is 409 DECIDED and leaves no change; every other refusal (busy, unreadable, a
    write way no longer possible) goes through and leaves it open. The comment is trimmed and stored with the approval."""
    a = await _found(aid)
    if a["status"] != approvals.OPEN:
        raise not_open(a)
    if approvals.same_person(user, a):
        raise HTTPException(403, SELF)
    if user["method"] == "local":
        raise HTTPException(403, EMERGENCY)
    row = await api_changes._enabled_row(a["switch_id"])
    if not roles.zone_allows(user, row["zone"]):
        raise HTTPException(403, roles.zone_denial(row["zone"], user["zones"]))
    if body.token != a["preview"]["token"]:
        raise HTTPException(409, REVIEW_AGAIN)
    comment = body.comment.strip()
    try:
        cid = await approvals.KINDS[a["kind"]].run(a, user, comment)
    except api_changes.PreviewOutdated as e:
        if await approvals.set_status(aid, approvals.STALE, user, reason=e.detail):
            await audit(user["username"], "approval_stale", _target(a), f"#{aid} {a['summary']}: {e.detail}", role=user["role"])
            await _announce("stale", aid)
        raise HTTPException(409, f"{STALE_REQUEST} ({e.detail})")
    except approvals.AlreadyDecided:
        raise HTTPException(409, DECIDED.format(aid=aid))    # the change's INSERT was rolled back with the claim
    await audit(user["username"], "approval_approved", _target(a), f"#{aid} {a['summary']} → Änderung #{cid}" + (f": {comment}" if comment else ""),
                role=user["role"])
    await audit(user["username"], "approval_run", _target(a), f"#{aid} → Änderung #{cid}", role=user["role"])
    await _announce("approved", aid)
    return {"id": cid, "approval": aid}
