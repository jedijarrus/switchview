"""Bootstrap-Konfiguration aus der Umgebung (.env)."""
import os
from dataclasses import dataclass, field


def _list(name: str) -> list[str]:
    return [x.strip() for x in os.getenv(name, "").split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    secret_key: str = os.getenv("SECRET_KEY", "")
    data_dir: str = os.getenv("DATA_DIR", "/data")
    admin_user: str = os.getenv("ADMIN_USER", "")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "")
    entra_tenant_id: str = os.getenv("ENTRA_TENANT_ID", "")
    entra_client_id: str = os.getenv("ENTRA_CLIENT_ID", "")
    entra_allowed_roles: list[str] = field(default_factory=lambda: _list("ENTRA_ALLOWED_ROLES"))
    entra_allowed_groups: list[str] = field(default_factory=lambda: _list("ENTRA_ALLOWED_GROUPS"))
    session_hours: int = int(os.getenv("SESSION_HOURS", "12") or 12)
    # Secure flag of the session and device cookies (auth.cookie_secure): "auto" (when the request came over https) or "always".
    # Trimmed and in lower case; unset or empty means auto. main.check_startup_config refuses any other value.
    cookie_secure: str = field(default_factory=lambda: os.getenv("COOKIE_SECURE", "").strip().lower() or "auto")
    # Roles from the Entra app roles (Phase 4a, roles.role_of): "on" maps the roles claim of the id_token to the four roles, "off" (the
    # default, unset or empty) leaves every SSO user Admin as before. Trimmed and in lower case; main.check_startup_config refuses any
    # other value. The app role values of each role, comma-separated, a value in two lists counting for the higher role.
    entra_role_mapping: str = field(default_factory=lambda: os.getenv("ENTRA_ROLE_MAPPING", "").strip().lower() or "off")
    entra_role_values: dict[str, list[str]] = field(default_factory=lambda: {
        "lesen": _list("ENTRA_ROLE_LESEN") or ["SwitchView.Lesen"],
        "aendern": _list("ENTRA_ROLE_AENDERN") or ["SwitchView.Aendern"],
        "freigeben": _list("ENTRA_ROLE_FREIGEBEN") or ["SwitchView.Freigeben"],
        "admin": _list("ENTRA_ROLE_ADMIN") or ["SwitchView.Admin"],
    })
    # A session without a request for this many minutes ends (auth.current_user); 0 = never. main.check_startup_config refuses < 0.
    idle_minutes: int = field(default_factory=lambda: int(os.getenv("IDLE_MINUTES", "120") or 120))

    @property
    def role_mapping_on(self) -> bool:
        return self.entra_role_mapping == "on"

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "switchview.db")

    @property
    def sso_active(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id)

    @property
    def local_login_active(self) -> bool:
        return bool(self.admin_user and self.admin_password)


settings = Settings()
