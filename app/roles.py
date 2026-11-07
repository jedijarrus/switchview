"""The roles of SwitchView (Phase 4a): Lesen ⊂ Ändern ⊂ Freigeben ⊂ Admin, each with the rights of the one before. Pure logic,
without FastAPI: which role a session has (from its method and the roles claim it stored at the login, against the mapping of now),
whether a role reaches a minimum, and the German text of a refusal."""
from config import Settings

LESEN, AENDERN, FREIGEBEN, ADMIN = "lesen", "aendern", "freigeben", "admin"
ORDER = (LESEN, AENDERN, FREIGEBEN, ADMIN)    # lowest first
LABELS = {LESEN: "Lesen", AENDERN: "Ändern", FREIGEBEN: "Freigeben", ADMIN: "Admin"}


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
