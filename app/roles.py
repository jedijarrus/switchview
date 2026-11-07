"""The roles of SwitchView (Phase 4a): Lesen ⊂ Ändern ⊂ Freigeben ⊂ Admin, each with the rights of the one before. Pure logic,
without FastAPI: which role a session has (from its method and the roles claim it stored at the login, against the mapping of now),
whether a role reaches a minimum, the zones a user may change in (Task 5) and the German text of a refusal."""
from config import Settings

LESEN, AENDERN, FREIGEBEN, ADMIN = "lesen", "aendern", "freigeben", "admin"
ORDER = (LESEN, AENDERN, FREIGEBEN, ADMIN)    # lowest first
LABELS = {LESEN: "Lesen", AENDERN: "Ändern", FREIGEBEN: "Freigeben", ADMIN: "Admin"}
SCOPED = (AENDERN, FREIGEBEN)    # the roles a zone scope can limit; Lesen changes nothing, Admin is never limited
NO_ZONE = "Ohne Zone"            # how a switch without a zone (zone "") is named


def at_least(role: str | None, minimum: str) -> bool:
    """Whether role has the rights of minimum. An unknown role or None has none."""
    return role in ORDER and ORDER.index(role) >= ORDER.index(minimum)


def role_of(method: str, claim_roles: list[str] | None, s: Settings) -> str:
    """The role of a session. The emergency login ("local") is Admin always. An SSO session ("entra") is Admin while
    ENTRA_ROLE_MAPPING is off (as before the roles); with it on, the highest role whose app role values (s.entra_role_values) meet
    claim_roles, and Lesen when none does: passing the login gate is enough to read. Any other method gets Lesen."""
    if method == "local":
        return ADMIN
    if method != "entra":
        return LESEN
    if not s.role_mapping_on:
        return ADMIN
    claim = claim_roles or []
    for role in reversed(ORDER):
        if any(value in claim for value in s.entra_role_values.get(role, [])):
            return role
    return LESEN


def denial(minimum: str, role: str | None, what: str = "Das") -> str:
    """The detail of a 403 for a role below minimum."""
    return f"Keine Berechtigung: {what} braucht die Rolle „{LABELS[minimum]}“ (deine Rolle: „{LABELS.get(role, role or '–')}“)"


def zones_of(role: str, claim_roles: list[str], scopes: list[tuple[str, str]]) -> list[str] | None:
    """The zones a user may change in, from their role, the app roles their session stored and the (principal, zone) entries of the
    list of now (zone_scopes): for Ändern and Freigeben whose app roles meet at least one entry, the sorted zones of every entry they
    meet; None (no limit) for everyone else: Admin and Lesen always, and whoever meets no entry, so an empty list limits no one."""
    if role not in SCOPED:
        return None
    zones = {zone for principal, zone in scopes if principal in claim_roles}
    return sorted(zones) if zones else None


def zone_label(zone: str | None) -> str:
    """A zone as the texts name it: the empty zone (or None) as „Ohne Zone“."""
    return zone or NO_ZONE


def zone_allows(user: dict, zone: str | None) -> bool:
    """Whether user (as auth.current_user returns it) may change a switch of zone: always without a limit (zones None)."""
    return user["zones"] is None or (zone or "") in user["zones"]


def zone_denial(zone: str | None, zones: list[str]) -> str:
    """The detail of a 403 for a switch of zone outside the zones a user may change in."""
    allowed = ", ".join(f"„{zone_label(z)}“" for z in zones)
    return f"Keine Berechtigung: Der Switch liegt in der Zone „{zone_label(zone)}“ – du darfst nur an Switches der Zonen {allowed} ändern"
