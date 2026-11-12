"""M6: the README describes the multivendor product, not a ProCurve/SSH-only one: every driver of the registry with what it can, SNMP
writes (the per-switch snmp_write switch, the RW credentials, PoE) and what stays SSH-only. A driver added to drivers.DRIVERS without
a README entry fails here. Phase 2: the README names the security settings. Phase 4a: the role settings and a paragraph on roles and
approvals. Phase 4b: the feature block on history, drift and alerts. Phase 4c: bulk changes, confirmation, API tokens, triage and the
REST flow."""
import pathlib

from drivers import DRIVERS

ROOT = pathlib.Path(__file__).parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_lists_every_driver():
    for name in DRIVERS:
        assert f"`{name}`" in README, name


def test_readme_describes_snmp_writes():
    for text in ("snmp_write", "authPriv", "clear text", "PoE", "write memory", "802.1X", "backup"):
        assert text in README, text
    assert "For changes: an SSH account with manager rights on each switch" not in README    # the ProCurve-only wording of before


def test_readme_describes_the_security_settings():
    for text in ("FORWARDED_ALLOW_IPS", "COOKIE_SECURE", "host key"):
        assert text in README, text


def test_ruff_is_pinned_and_no_file_is_exempt():
    """A new ruff release brings new rules and would break CI without a code change; every file is held to the full rule set."""
    assert "ruff==0.17.3" in (ROOT / "requirements-dev.txt").read_text() and "per-file-ignores" not in (ROOT / "ruff.toml").read_text()


def test_the_readme_names_the_role_settings():
    """Phase 4a, Task 3: the README names the role mapping, the role values and the idle logout."""
    for text in ("ENTRA_ROLE_MAPPING", "ENTRA_ROLE_AENDERN", "SwitchView.Freigeben", "IDLE_MINUTES"):
        assert text in README, text


def test_the_readme_describes_roles_and_approvals():
    """Phase 4a wrap-up: the security section has a paragraph on the roles and approvals - four roles, the matrix of the tests, zones,
    four eyes off by default (with them on, Ändern may request an expert-mode change too), the nonce, the idle logout - and the
    login list names zones and four eyes."""
    security = README.split("\n## Security\n", 1)[1].split("\n## ", 1)[0]
    login = README.split("\n**Login**\n", 1)[1].split("\n## ", 1)[0]
    assert "**Roles and approvals.**" in security
    for text in ("Lesen", "Admin", "tests/test_permissions.py", "zone", "four-eyes", "off by default", "nonce", "IDLE_MINUTES",
                 "Ändern may request an expert-mode change"):
        assert text in security.split("**Roles and approvals.**", 1)[1].split("\n\n", 1)[0], text
    for text in ("zone", "four-eyes"):
        assert text in login, text


def test_the_readme_describes_history_drift_and_alerts():
    """Phase 4b wrap-up: the feature list has a block on the history, the events, the security rules, the alerts, the watch list and
    the server-side audit log."""
    features = README.split("\n## Features\n", 1)[1].split("\n## ", 1)[0]
    assert "**History, drift and alerts**" in features
    block = features.split("**History, drift and alerts**", 1)[1].split("\n\n", 1)[0]
    for text in ("HISTORY_DAYS", "Verlauf", "outside SwitchView", "security rules", "SMTP", "Teams", "webhook", "watch list", "CSV",
                 "PUBLIC_URL", "off until"):
        assert text in block, text


def test_the_readme_shows_the_rest_flow():
    rest = README.split("\n## REST API\n", 1)[1].split("\n## ", 1)[0]
    for text in ("Authorization: Bearer", "/api/openapi.json", "/plan", "/apply", "preview token", "curl", "jq", "Settings → \"API-Tokens\"",
                 "shown once", "approving", "emergency login", "confirm_minutes", "/confirm", "/api/bulk/plan",
                 "/api/bulk"):
        assert text in rest, text


def test_the_readme_describes_bulk_changes_confirmation_tokens_and_triage():
    """Phase 4c wrap-up: the feature list has a block on bulk changes, changes with confirmation, API tokens and the triage, and the
    security section a paragraph on API tokens - the prefix, the hash, the header, shown once, revoking, the maximum role, the
    emergency login, that a token request never reads the cookie and that a proxy's own bearer value keeps the cookie path."""
    features = README.split("\n## Features\n", 1)[1].split("\n## ", 1)[0]
    assert "**Bulk changes, confirmation, REST API and triage**" in features
    block = " ".join(features.split("**Bulk changes, confirmation, REST API and triage**", 1)[1].split("\n\n", 1)[0].split())
    for text in ("up to 20 switches", "preview per switch", "first failure", "cancellable", "four-eyes", "Mit Bestätigung ausführen",
                 "takes it back", "API tokens", "/api/openapi.json", "Triage", "CSV", "Neu bewerten"):
        assert text in block, text
    security = README.split("\n## Security\n", 1)[1].split("\n## ", 1)[0]
    assert "**API tokens.**" in security
    paragraph = " ".join(security.split("**API tokens.**", 1)[1].split("\n\n", 1)[0].split())
    for text in ("svt_", "SHA-256", "Authorization: Bearer", "shown once", "revoke", "maximum role", "emergency login",
                 "never reads the cookie", "a proxy in front"):
        assert text in paragraph, text
