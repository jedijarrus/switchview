"""The four-eyes routes (Phase 4a, Tasks 6 and 7): request a change that needs an approval (POST /api/approvals), list and read the
requests, withdraw one's own, reject someone else's (Task 6); review someone else's against a fresh plan and approve it, which starts
the change through the change loop of /apply (api_changes.start_change, Task 7). The kind port_change (an expert-mode port change)
is registered here at import (approvals.register). The mechanism itself is app/approvals.py.

Phase 4c, Task 8: the same routes carry the kind bulk_change (a bulk change, registered by api_bulk): a request with the body of
POST /api/bulk instead of a switch and a plan. It has no switch of its own; its zones are those of all its switches (_zones), and
whoever rejects, reviews or approves it needs every one of them. Its approval starts a bulk change (bulk.create, bulk.schedule).

Everything of api_changes goes through the module (api_changes.X), never imported by name: the tests replace api_changes._make_plan,
and a request is planned and checked by exactly the code of /plan and /apply."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

import api_bulk
import api_changes
import approvals
import auth
import bulk
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
# The reason a request stale for other commands stores, names and hands on (Phase 4b: alerts carry it): api_changes.STALE asks to
# reload the page, which fits a preview but not a request that has to be asked again
OTHER_COMMANDS = "Die Befehle von jetzt sind andere als die der Vorschau der Anfrage"
DECIDED = "Anfrage #{aid} ist schon entschieden"
APPROVE_VIA_TOKEN = ("Freigeben geht nur angemeldet in der Oberfläche, nicht mit einem API-Token: das Vier-Augen-Prinzip verlangt eine "
                     "Person")
MISSING = "Für eine Port-Änderung braucht die Anfrage switch_id und plan, für eine Sammeländerung bulk"


class ApprovalIn(BaseModel):
    """A four-eyes request: of the kind port_change with switch_id and plan (the body of /apply), of the kind bulk_change with bulk
    (the body of POST /api/bulk); request_approval refuses one without its parts (422 MISSING)."""
    kind: str = Field(pattern=r"^(port_change|bulk_change)$")
    switch_id: int | None = None
    plan: api_changes.PlanIn | None = None
    bulk: api_bulk.BulkIn | None = None


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


async def _zones(a: dict) -> list[str | None]:
    """The zones whoever decides request a must be allowed to change in, of now: the zone of its switch for a port change, those of
    all its switches for a bulk change (bulk.zones_of its payload)."""
    if a["kind"] == approvals.BULK_CHANGE:
        return await bulk.zones_of(a["payload"])
    return [a["switch_zone"]]


async def _zone_rights(user: dict, a: dict) -> None:
    """403 roles.zone_denial of the first zone of request a (_zones) that user may not change in."""
    for zone in await _zones(a):
        if not roles.zone_allows(user, zone):
            raise HTTPException(403, roles.zone_denial(zone, user["zones"]))


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
    """A four-eyes request, first of all with the parts of its kind (422 MISSING: switch_id and plan for a port change, bulk for a
    bulk change), then stored by _request_port_change or _request_bulk_change; audits approval_requested (the target: the switch of a
    port change, "" for a bulk change) and tells the listeners. {"id": <request>}."""
    if body.kind == approvals.BULK_CHANGE:
        if body.bulk is None:
            raise HTTPException(422, MISSING)
        target, (aid, summary) = "", await _request_bulk_change(body.bulk, user)
    else:
        if body.switch_id is None or body.plan is None:
            raise HTTPException(422, MISSING)
        target, (aid, summary) = str(body.switch_id), await _request_port_change(body.switch_id, body.plan, user)
    await audit(user["username"], "approval_requested", target, f"#{aid} {summary}", role=user["role"])
    await _announce("requested", aid)
    return {"id": aid}


async def _request_bulk_change(body: api_bulk.BulkIn, user: dict) -> tuple[int, str]:
    """Stores the request of user for bulk change body, checked in the order of POST /api/bulk: the limits (bulk.validate, 422); the
    zone and the mode at every switch (bulk.rights, 403; a switch gone 404, disabled 409); the bulk needs an approval
    (approvals.needs_approval: every bulk with the four-eyes principle on, else 409 NO_APPROVAL_NEEDED); every switch against its
    preview token (api_bulk.request_parts: 409 bulk.OUTDATED naming each that does not match). No switch of its own (switch_id NULL).
    The request's id and its summary."""
    bulk.validate(body)
    four_eyes = (await approvals.policy())["four_eyes"]
    await bulk.rights(user, body, four_eyes)
    if not approvals.needs_approval(approvals.BULK_CHANGE, {}, four_eyes):
        raise HTTPException(409, NO_APPROVAL_NEEDED)
    summary, payload, preview = await api_bulk.request_parts(body)
    return await approvals.create(approvals.BULK_CHANGE, None, summary, payload, preview, user), summary


async def _request_port_change(switch_id: int, body: api_changes.PlanIn, user: dict) -> tuple[int, str]:
    """Stores the request of user for the change body at switch switch_id, checked in this order: the switch is there and enabled
    (api_changes._enabled_row); the zone and the rights of its mode (api_changes._mode_rights, the 403 of /plan); the change needs an
    approval (approvals.needs_approval, else 409 NO_APPROVAL_NEEDED: a prepare, a revert, a save and a change without expert mode go
    directly, as does everything with the four-eyes principle off); the plan of now is the preview's (api_changes.checked_plan, the
    errors of /apply); with confirm_minutes, the change can run with confirmation (api_changes.confirm_refusal, 409 as in
    start_change: a request whose approval would have to fail is never stored). The rights come before the 409 since Phase 4c (4a
    R6-b): with the REST API the answer is a contract, and "sie lässt sich direkt ausführen" is true only for whoever has the rights.
    Stores exactly the desired state the requester sent (without the empty defaults of PortChange: PlanIn(**payload) restores the
    request, confirm_minutes too when it is set) and the preview they saw (api_changes.preview_answer). The request's id and its
    summary."""
    row = await api_changes._enabled_row(switch_id)
    four_eyes = (await approvals.policy())["four_eyes"]
    await api_changes._mode_rights(user, row, body, four_eyes)
    if not approvals.needs_approval(approvals.PORT_CHANGE, body.model_dump(), four_eyes):
        raise HTTPException(409, NO_APPROVAL_NEEDED)
    plan, _, kind, summary = await api_changes.checked_plan(row, body)
    if body.confirm_minutes is not None:
        refusal = api_changes.confirm_refusal(row, plan, body)
        if refusal:
            raise HTTPException(409, refusal)
    preview = api_changes.preview_answer(row, plan, kind, summary)
    payload = {"mode": body.mode, "ports": body.ports, "change": body.change.model_dump(exclude_defaults=True), "expert": body.expert}
    if body.confirm_minutes is not None:
        payload["confirm_minutes"] = body.confirm_minutes
    return await approvals.create(approvals.PORT_CHANGE, switch_id, summary, payload, preview, user), summary


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
    their zones (403 roles.zone_denial, the switch's zone of now; a bulk change: every zone of its switches, the first that is not
    theirs), with an optional comment (trimmed; audited after the summary)."""
    a = await _found(aid)
    if approvals.same_person(user, a):
        raise HTTPException(403, OWN_REJECT)
    await _zone_rights(user, a)
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
    """The reviewer's fresh preview of an open request at a switch of their zones (403 roles.zone_denial, the switch's zone of now;
    a bulk change: every zone of its switches): the preview of its kind - for port_change planned now, with matches; the errors of
    planning go through (409 STALE, 502, …); for bulk_change every switch planned now, each with its own matches, a switch that
    cannot be planned as a section with its reason (api_bulk._preview_bulk)."""
    a = await _found(aid)
    if a["status"] != approvals.OPEN:
        raise not_open(a)
    await _zone_rights(user, a)
    return await approvals.KINDS[a["kind"]].preview(a, user)


@router.post("/api/approvals/{aid}/approve")
async def approve_approval(aid: int, body: ApproveIn, user=Depends(auth.require(roles.FREIGEBEN))):
    """Someone with Freigeben approves an open request of someone else, which starts its change at once (the run of its kind:
    api_changes.start_change, the code of /apply; for a bulk change bulk.create and bulk.schedule, the code of POST /api/bulk). In
    this order: 404; not open (409 not_open); one's own (approvals.same_person, 403 SELF, Admin too); the emergency login (403
    EMERGENCY: a shared account, not a person); an API token (Phase 4c: 403 APPROVE_VIA_TOKEN, four eyes mean a person, and a leaked
    token must not replace one); the switch disabled (409 DISABLED; a bulk change has no switch of its own) or a zone of the request
    (_zones) outside the approver's (403); body.token not the request's preview (409 REVIEW_AGAIN: the approver saw another preview).
    Then the run: a plan that is no longer the preview (api_changes.PreviewOutdated) sends nothing and makes the request stale (409
    STALE_REQUEST with the reason; audited and announced when this call made it so) - the reason is OTHER_COMMANDS for other commands
    than the preview's (api_changes.STALE), else the refusal word for word ("Nicht ausführbar: …"); a request decided meanwhile
    (the claim in the change's transaction, approvals.AlreadyDecided) is 409 DECIDED and leaves no change; every other refusal (busy,
    unreadable, a write way no longer possible) goes through and leaves it open. A bulk change is checked whole before it starts
    (bulk.precheck): any switch that does not match its preview token now - changed, blocked, gone, disabled, unreadable or busy -
    makes the request stale with bulk.OUTDATED naming each, and nothing starts. The comment is trimmed and stored with the approval.
    The audit names what started by the noun of the kind (Kind.started: "… → Änderung #7", "… → Sammeländerung #3").
    {"id": <the change or the bulk change>, "approval": aid, "kind": <the request's kind>}."""
    a = await _found(aid)
    if a["status"] != approvals.OPEN:
        raise not_open(a)
    if approvals.same_person(user, a):
        raise HTTPException(403, SELF)
    if user["method"] == "local":
        raise HTTPException(403, EMERGENCY)
    if user["api_token"]:
        raise HTTPException(403, APPROVE_VIA_TOKEN)
    if a["switch_id"] is not None:
        await api_changes._enabled_row(a["switch_id"])
    await _zone_rights(user, a)
    if body.token != a["preview"]["token"]:
        raise HTTPException(409, REVIEW_AGAIN)
    comment = body.comment.strip()
    kind = approvals.KINDS[a["kind"]]
    try:
        ref = await kind.run(a, user, comment)
    except api_changes.PreviewOutdated as e:
        reason = OTHER_COMMANDS if e.detail == api_changes.STALE else e.detail
        if await approvals.set_status(aid, approvals.STALE, user, reason=reason):
            await audit(user["username"], "approval_stale", _target(a), f"#{aid} {a['summary']}: {reason}", role=user["role"])
            await _announce("stale", aid)
        raise HTTPException(409, f"{STALE_REQUEST} ({reason})")
    except approvals.AlreadyDecided:
        raise HTTPException(409, DECIDED.format(aid=aid))    # the change's INSERT was rolled back with the claim
    await audit(user["username"], "approval_approved", _target(a),
                f"#{aid} {a['summary']} → {kind.started} #{ref}" + (f": {comment}" if comment else ""), role=user["role"])
    await audit(user["username"], "approval_run", _target(a), f"#{aid} → {kind.started} #{ref}", role=user["role"])
    await _announce("approved", aid)
    return {"id": ref, "approval": aid, "kind": a["kind"]}
