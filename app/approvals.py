"""The four-eyes principle of SwitchView (Phase 4a, Task 6): a generic approval mechanism, without FastAPI (the routes are in
api_approvals). A request has a kind (KINDS, filled by register: each kind brings its own preview and its own run; Task 7 registers
port_change, 4c a bulk change), a payload (exactly the desired state its requester sent) and the preview they saw, stored in the table
approvals. needs_approval is the one predicate that says which request needs an approval, policy the setting (off by default). A
request is open until it is approved (claim, in the one write that also creates its change, Task 7), rejected, withdrawn, goes stale
(its plan is no longer the preview, Task 7) or expires (expire_due: every 10 minutes from the scheduler, and before every read of a
request). Every step is announced to the listeners (subscribe, emit), where 4b's alerting hangs on. KINDS and _listeners are
registries filled at import, the same in every process."""
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from db import audit, db, load_settings

log = logging.getLogger("switchview.approvals")

PORT_CHANGE = "port_change"
OPEN, APPROVED, REJECTED, WITHDRAWN, EXPIRED, STALE = "open", "approved", "rejected", "withdrawn", "expired", "stale"
STATUS_LABEL = {OPEN: "offen", APPROVED: "freigegeben", REJECTED: "abgelehnt", WITHDRAWN: "zurückgezogen", EXPIRED: "abgelaufen",
                STALE: "veraltet"}
DEFAULT_HOURS = 24
# The settings keys of the four-eyes principle (PUT /api/settings/approvals): "1" on, anything else off; the hours a request stays open
SETTINGS_KEYS = ("four_eyes", "approval_hours")
# The columns of a request in a listing: all but payload and preview (get reads those too)
LIST_COLUMNS = ("id", "kind", "switch_id", "summary", "status", "requested_by", "requester_name", "requester_subject", "requester_role",
                "requested_at", "expires_at", "decided_by", "decided_subject", "decided_at", "comment", "reason", "change_id")
# A request with the name and zone of its switch (LEFT JOIN: a kind without a switch has switch_id NULL)
_JOINED = "SELECT {}, s.name AS switch_name, s.zone AS switch_zone FROM approvals a LEFT JOIN switches s ON s.id = a.switch_id"


@dataclass(frozen=True)
class Kind:
    """A kind of request: its name (approvals.kind), its label for the UI, its preview for (request, user) and its run for (request,
    approver, comment), which starts what was approved and returns the id of the change."""
    name: str
    label: str
    preview: Callable[[dict, dict], Awaitable[dict]]
    run: Callable[[dict, dict, str], Awaitable[int]]


KINDS: dict[str, Kind] = {}
_listeners: list[Callable[[str, dict], Awaitable[None]]] = []


class AlreadyDecided(Exception):
    """The request is no longer open."""


def register(kind: Kind) -> None:
    """Makes kind known (KINDS); a second kind of the same name replaces the first."""
    KINDS[kind.name] = kind


def subscribe(listener: Callable[[str, dict], Awaitable[None]]) -> None:
    """listener(event, approval) hears every step of every request: requested, approved, rejected, withdrawn, expired, stale."""
    _listeners.append(listener)


async def emit(event: str, approval: dict) -> None:
    """Calls every listener with event and the request; a listener that fails is logged and costs the others nothing. Never raises."""
    for listener in list(_listeners):
        try:
            await listener(event, approval)
        except Exception:  # noqa: BLE001 -- a listener (4b alerting) must never break the step it hears about
            log.exception("Freigaben: ein Listener scheiterte an „%s“ (Anfrage #%s)", event, approval.get("id"))


def needs_approval(kind: str, request: dict, four_eyes: bool) -> bool:
    """Whether a request of kind needs an approval: in 4a only a port change (mode "ports") in expert mode, and only with the
    four-eyes principle on. A revert and a save never do: a revert must work in an outage without a second person, and it restores
    a state that ran before. 4c adds its bulk change here."""
    return four_eyes and kind == PORT_CHANGE and request.get("mode", "ports") == "ports" and bool(request.get("expert"))


def policy_of(s: dict) -> dict:
    """The four-eyes policy from the settings values of SETTINGS_KEYS: {"four_eyes": bool, "hours": int} (off and DEFAULT_HOURS
    without a value)."""
    return {"four_eyes": s.get("four_eyes") == "1", "hours": int(s.get("approval_hours") or DEFAULT_HOURS)}


async def policy() -> dict:
    """The four-eyes policy of now, in one read of the settings."""
    return policy_of(await load_settings(SETTINGS_KEYS))


async def create(kind: str, switch_id: int | None, summary: str, payload: dict, preview: dict, user: dict) -> int:
    """A new open request of user (as auth.current_user returns them); it expires policy()["hours"] from now. Its id."""
    hours = (await policy())["hours"]
    now = datetime.now(timezone.utc)
    async with db() as conn:
        cur = await conn.execute(
            "INSERT INTO approvals(kind, switch_id, summary, payload, preview, status, requested_by, requester_name, requester_subject, "
            "requester_role, requested_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (kind, switch_id, summary, json.dumps(payload), json.dumps(preview), OPEN, user["username"], user["name"], user["subject"],
             user["role"], now.isoformat(), (now + timedelta(hours=hours)).isoformat()))
        await conn.commit()
        return cur.lastrowid


async def _full(conn, aid: int) -> dict | None:
    """Request aid with payload and preview as dicts and its switch's name and zone; None if there is none."""
    async with conn.execute(_JOINED.format("a.*") + " WHERE a.id = ?", (aid,)) as cur:
        r = await cur.fetchone()
    if r is None:
        return None
    a = dict(r)
    a["payload"], a["preview"] = json.loads(a["payload"]), json.loads(a["preview"])
    return a


async def get(aid: int) -> dict | None:
    """Request aid as _full reads it, after expire_due; None if there is none (or its switch was deleted with it)."""
    await expire_due()
    async with db() as conn:
        return await _full(conn, aid)


async def listing(status: str | None, limit: int) -> list[dict]:
    """The requests of status (None: every status), newest first, at most limit, after expire_due; with the name and zone of their
    switch, without payload and preview."""
    await expire_due()
    q, args = _JOINED.format(", ".join(f"a.{c}" for c in LIST_COLUMNS)), []
    if status is not None:
        q += " WHERE a.status = ?"
        args.append(status)
    q += " ORDER BY a.id DESC LIMIT ?"
    args.append(limit)
    async with db() as conn:
        async with conn.execute(q, args) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def set_status(aid: int, status: str, user: dict | None, *, comment: str = "", reason: str = "") -> bool:
    """Decides request aid as status, by user (None: by no one), with comment and reason ("" stores none), and only while it is
    open: one UPDATE, so of two decisions at once one wins. Whether it changed the request."""
    async with db() as conn:
        cur = await conn.execute(
            "UPDATE approvals SET status = ?, decided_by = ?, decided_subject = ?, decided_at = ?, comment = ?, reason = ? "
            "WHERE id = ? AND status = ?",
            (status, user["username"] if user else None, user["subject"] if user else None, datetime.now(timezone.utc).isoformat(),
             comment or None, reason or None, aid, OPEN))
        await conn.commit()
    return cur.rowcount == 1


async def claim(conn, aid: int, approver: dict, comment: str, cid: int) -> None:
    """Marks request aid approved by approver (auth.current_user) for change cid, with comment ("" stores none), on conn and without a
    commit: changes.create_change runs it in the transaction of the change's INSERT, so the approval and the change are stored
    together or not at all. Only an open request that has not run out yet (its expires_at, whatever expire_due has marked so far);
    otherwise AlreadyDecided, and the transaction is rolled back by its caller."""
    now = datetime.now(timezone.utc).isoformat()
    cur = await conn.execute(
        "UPDATE approvals SET status = ?, decided_by = ?, decided_subject = ?, decided_at = ?, comment = ?, change_id = ? "
        "WHERE id = ? AND status = ? AND expires_at >= ?",
        (APPROVED, approver["username"], approver["subject"], now, comment or None, cid, aid, OPEN, now))
    if cur.rowcount != 1:
        raise AlreadyDecided()


async def expire_due() -> int:
    """Marks every open request whose expires_at has passed as expired (one UPDATE: of two runs at once each request goes to one),
    with one audit entry approval_expired each (no user, no role) and the event "expired". How many it marked."""
    now = datetime.now(timezone.utc).isoformat()
    async with db() as conn:
        async with conn.execute("UPDATE approvals SET status = ?, decided_at = ? WHERE status = ? AND expires_at < ? RETURNING id",
                                (EXPIRED, now, OPEN, now)) as cur:
            ids = sorted(r["id"] for r in await cur.fetchall())
        await conn.commit()
        expired = [a for a in [await _full(conn, aid) for aid in ids] if a is not None]
    for a in expired:
        await audit(None, "approval_expired", "" if a["switch_id"] is None else str(a["switch_id"]), f"#{a['id']} {a['summary']}", role=None)
        await emit("expired", a)
    return len(ids)


def same_person(user: dict, approval: dict) -> bool:
    """Whether user (auth.current_user) is the one who asked for approval: the same subject, or the same user name in any case."""
    return user["subject"] == approval["requester_subject"] or user["username"].casefold() == approval["requested_by"].casefold()


def public(approval: dict, user: dict) -> dict:
    """approval as the API serves it to user: without the subjects (they are for the server's comparisons), with own (user asked
    for it), the label of its kind (its name for a kind not registered) and of its status."""
    kind = KINDS.get(approval["kind"])
    return ({k: v for k, v in approval.items() if k not in ("requester_subject", "decided_subject")}
            | {"own": same_person(user, approval), "kind_label": kind.label if kind else approval["kind"],
               "status_label": STATUS_LABEL.get(approval["status"], approval["status"])})
