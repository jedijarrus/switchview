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
