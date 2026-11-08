"""The API tokens (Phase 4c, Task 2): a person signed in over SSO creates their own (POST /api/tokens), lists them (GET /api/tokens)
and revokes them (DELETE /api/tokens/{tid}); an Admin lists every token (GET /api/settings/tokens) and revokes any. A token is
shown once, in the answer of its POST, and stored as db.token_hash. The tokens themselves - creating, listing, revoking, and
resolving a request with "Authorization: Bearer svt_..." into its user - are app/auth.py (current_user is the one place a token is
resolved).

Managing tokens works only signed in in the browser, never with an API token (_signed_in, 403 VIA_TOKEN): a leaked token must not
breed more tokens nor outlive its own revocation through a new one. The emergency login gets none (403 EMERGENCY): it is a shared
account, not a person, and an Admin token without a person would outlive every new ADMIN_PASSWORD.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import auth
import roles
from db import audit

router = APIRouter()

VIA_TOKEN = "API-Tokens verwaltet man angemeldet in der Oberfläche, nicht mit einem API-Token"
EMERGENCY = "Der Notfall-Login bekommt keine API-Tokens: er ist kein persönliches Konto"
NO_NAME = "Name fehlt"
ABOVE_ROLE = "Die Höchstrolle eines API-Tokens kann nicht über deiner Rolle „{role}“ liegen"
NAME_TAKEN = "Du hast schon ein API-Token mit diesem Namen"
TOO_MANY = "Höchstens 20 API-Tokens je Benutzer – erst eins widerrufen"
NOT_FOUND = "API-Token nicht gefunden"


class TokenIn(BaseModel):
    """A new API token: its name (unique per person, trimmed), the days it is good for (1-365, by default 90; none is good forever)
    and the role it is capped at (None: the role of its user, whatever that is at each request)."""
    name: str = Field(min_length=1, max_length=60)
    days: int = Field(default=auth.TOKEN_DEFAULT_DAYS, ge=1, le=auth.TOKEN_MAX_DAYS)
    max_role: str | None = Field(default=None, pattern=r"^(lesen|aendern|freigeben|admin)$")


def _signed_in(user: dict) -> None:
    """403 VIA_TOKEN for a request made with an API token: tokens are managed signed in in the browser only."""
    if user["api_token"]:
        raise HTTPException(403, VIA_TOKEN)


@router.post("/api/tokens")
async def create_token(body: TokenIn, request: Request, user=Depends(auth.require(roles.LESEN))):
    """A new API token of the signed-in person, any role: not with an API token (403 VIA_TOKEN), not the emergency login (403
    EMERGENCY); the name trimmed (blank: 422 NO_NAME); a maximum role at most the person's role (422 ABOVE_ROLE, a higher one would
    do nothing); at most auth.TOKENS_PER_USER per person and the name unused among them (409 TOO_MANY, NAME_TAKEN). The token copies
    the app roles of this session (auth.session_claims). Audits token_create (the id; name, expiry and maximum role, never the token)
    and answers {"id", "name", "token", "expires_at", "max_role"}: the only answer that ever holds the token."""
    _signed_in(user)
    if user["method"] == "local":
        raise HTTPException(403, EMERGENCY)
    name = body.name.strip()
    if not name:
        raise HTTPException(422, NO_NAME)
    if body.max_role is not None and not roles.at_least(user["role"], body.max_role):
        raise HTTPException(422, ABOVE_ROLE.format(role=roles.LABELS[user["role"]]))
    claims = await auth.session_claims(request)
    try:
        made = await auth.create_token(user, claims, name, body.days, body.max_role)
    except auth.TokenLimit:
        raise HTTPException(409, TOO_MANY) from None
    except auth.TokenNameTaken:
        raise HTTPException(409, NAME_TAKEN) from None
    capped = roles.LABELS[body.max_role] if body.max_role else "wie der Benutzer"
    await audit(user["username"], "token_create", f"#{made['id']}", f"„{name}“ bis {made['expires_at']} UTC, Höchstrolle {capped}",
                role=user["role"])
    return made


@router.get("/api/tokens")
async def list_my_tokens(user=Depends(auth.require(roles.LESEN))):
    """The signed-in person's API tokens (auth.list_tokens of their subject), newest first, without the tokens; not with a token."""
    _signed_in(user)
    return await auth.list_tokens(user["subject"])


@router.delete("/api/tokens/{tid}")
async def revoke_token(tid: int, user=Depends(auth.require(roles.LESEN))):
    """Revokes API token tid: one's own, as Admin any (404 NOT_FOUND for someone else's, as for a missing one); not with a token.
    Audits token_revoke (the id; its name and its user)."""
    _signed_in(user)
    gone = await auth.revoke_token(tid, user)
    if gone is None:
        raise HTTPException(404, NOT_FOUND)
    await audit(user["username"], "token_revoke", f"#{gone['id']}", f"„{gone['name']}“ von {gone['username']}", role=user["role"])
    return {"ok": True}


@router.get("/api/settings/tokens")
async def list_all_tokens(user=Depends(auth.require(roles.ADMIN))):
    """Every API token with its user (auth.list_tokens), newest first, without the tokens: Admin, not with a token."""
    _signed_in(user)
    return await auth.list_tokens(None)
