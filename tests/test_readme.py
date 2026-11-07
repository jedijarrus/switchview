"""M6: the README describes the multivendor product, not a ProCurve/SSH-only one: every driver of the registry with what it can, SNMP
writes (the per-switch snmp_write switch, the RW credentials, PoE), what stays SSH-only, and the pointer to the German list of known
limitations and device checks. A driver added to drivers.DRIVERS without a README entry fails here. Phase 2: the README names the
security settings and links the German security note, which has the sections the plan asks for. Phase 3: likewise the logic note,
with its module map and a row per decision of its plan. Phase 5: the README links the German UX note, which has the same sections.
Phase 4a: likewise the roles note, with its rights per route as tests/test_permissions.py pins them and a row per decision of
its plan."""
import pathlib
import re

import roles
from drivers import DRIVERS

ROOT = pathlib.Path(__file__).parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_lists_every_driver():
    for name in DRIVERS:
        assert f"`{name}`" in README, name


def test_readme_describes_snmp_writes():
    for text in ("snmp_write", "authPriv", "clear text", "PoE", "write memory", "802.1X", "backup",
                 "Known limitations and required device checks (German): [docs/snmp-multivendor.md](docs/snmp-multivendor.md)"):
        assert text in README, text
    assert "For changes: an SSH account with manager rights on each switch" not in README    # the ProCurve-only wording of before


def test_readme_describes_the_security_settings():
    for text in ("FORWARDED_ALLOW_IPS", "COOKIE_SECURE", "host key",
                 "Security notes and upgrade steps (German): [docs/sicherheit-phase2.md](docs/sicherheit-phase2.md)"):
        assert text in README, text


def test_the_security_note_has_its_sections_and_every_decision():
    """The note the README links to exists, with the sections of the Phase 2 plan (Task 9) and one table row per decision E1-E32."""
    note = (ROOT / "docs" / "sicherheit-phase2.md").read_text(encoding="utf-8")
    for heading in ("## Was gebaut wurde", "## Bekannte Grenzen", "## Prüfungen vor dem Produktiveinsatz", "## Was beim Update zu tun ist",
                    "## Später", "## Entscheidungen"):
        assert f"\n{heading}\n" in note, heading
    for n in range(1, 33):
        assert f"\n| E{n} |" in note, f"E{n}"
    assert "\n| E33 |" not in note


def test_the_logic_note_is_linked_and_has_its_sections():
    """Phase 3: the README links the German logic and robustness note, which has the sections the plan asks for (Task 1)."""
    assert "Logic and robustness notes (German): [docs/logik-phase3.md](docs/logik-phase3.md)" in README
    note = (ROOT / "docs" / "logik-phase3.md").read_text(encoding="utf-8")
    for heading in ("## Was gebaut wurde", "## Bekannte Grenzen", "## Prüfungen vor dem Produktiveinsatz", "## Was beim Update zu tun ist",
                    "## Später", "## Entscheidungen"):
        assert f"\n{heading}\n" in note, heading


def test_the_logic_note_has_its_module_map_and_a_row_per_decision_of_the_plan():
    """Phase 3 wrap-up: the note maps the moved code ("Wo liegt was") and has one table row per "Entscheidung:" of the plan, counted
    from the plan itself: A1.. for its exclusions, Tn-a.. for the decisions of task n."""
    note = (ROOT / "docs" / "logik-phase3.md").read_text(encoding="utf-8")
    plan = (ROOT / "docs" / "superpowers" / "plans" / "2026-11-06-phase3-logik.md").read_text(encoding="utf-8")
    assert "\n## Wo liegt was\n" in note
    counts, section = {}, None
    for line in plan.splitlines():
        task = re.match(r"### Task (\d+):", line)
        if task:
            section = f"T{task[1]}"
        elif line.startswith("## "):
            section = "A" if line == "## Ausschlüsse" else None
        elif line.startswith("- Entscheidung:") and section:
            counts[section] = counts.get(section, 0) + 1
    assert set(counts) == {"A"} | {f"T{n}" for n in range(1, 13)}, counts
    for section, n in counts.items():
        ids = [f"A{i}" for i in range(1, n + 1)] if section == "A" else [f"{section}-{chr(ord('a') + i)}" for i in range(n)]
        for rid in ids:
            assert f"\n| {rid} |" in note, rid


def test_the_ux_note_is_linked_and_has_its_sections():
    """Phase 5: the README links the German UX note, which has the sections of the earlier notes."""
    assert "UX notes and upgrade steps (German): [docs/ux-phase5.md](docs/ux-phase5.md)" in README
    note = (ROOT / "docs" / "ux-phase5.md").read_text(encoding="utf-8")
    for heading in ("## Was gebaut wurde", "## Bekannte Grenzen", "## Prüfungen vor dem Produktiveinsatz", "## Was beim Update zu tun ist",
                    "## Später", "## Entscheidungen"):
        assert f"\n{heading}\n" in note, heading


def test_the_ux_note_has_a_row_per_decision_of_the_plan():
    """Phase 5 wrap-up: one table row per "Entscheidung:" of the plan, counted from the plan itself: A1.. for its exclusions, Tn-a.. per task."""
    note = (ROOT / "docs" / "ux-phase5.md").read_text(encoding="utf-8")
    plan = (ROOT / "docs" / "superpowers" / "plans" / "2026-11-06-phase5-ux.md").read_text(encoding="utf-8")
    counts, section = {}, None
    for line in plan.splitlines():
        task = re.match(r"### Task (\d+):", line)
        if task:
            section = f"T{task[1]}"
        elif line.startswith("## "):
            section = "A" if line == "## Ausschlüsse" else None
        elif line.startswith("- Entscheidung:") and section:
            counts[section] = counts.get(section, 0) + 1
    assert set(counts) == {"A"} | {f"T{n}" for n in range(1, 12)}, counts
    for section, n in counts.items():
        for rid in ([f"A{i}" for i in range(1, n + 1)] if section == "A" else [f"{section}-{chr(ord('a') + i)}" for i in range(n)]):
            assert f"\n| {rid} |" in note, rid


def test_ruff_is_pinned_and_no_file_is_exempt():
    """A new ruff release brings new rules and would break CI without a code change; every file is held to the full rule set."""
    assert "ruff==0.17.3" in (ROOT / "requirements-dev.txt").read_text() and "per-file-ignores" not in (ROOT / "ruff.toml").read_text()


def test_the_roles_note_is_linked_and_has_its_sections():
    """Phase 4a: the README links the German roles note, which has the sections of the earlier notes and the rights per route."""
    assert "Roles and approvals notes (German): [docs/rollen-phase4a.md](docs/rollen-phase4a.md)" in README
    note = (ROOT / "docs" / "rollen-phase4a.md").read_text(encoding="utf-8")
    for heading in ("## Was gebaut wurde", "## Rechte je Route", "## Bekannte Grenzen", "## Prüfungen vor dem Produktiveinsatz",
                    "## Was beim Update zu tun ist", "## Später", "## Entscheidungen"):
        assert f"\n{heading}\n" in note, heading


def test_the_readme_names_the_role_settings():
    """Phase 4a, Task 3: the README names the role mapping, the role values and the idle logout."""
    for text in ("ENTRA_ROLE_MAPPING", "ENTRA_ROLE_AENDERN", "SwitchView.Freigeben", "IDLE_MINUTES"):
        assert text in README, text


def test_the_roles_note_has_a_row_per_decision_of_the_plan():
    """Phase 4a wrap-up: one table row per "Entscheidung:" of the plan, counted from the plan itself: A1.. for its exclusions, Tn-a.. per task."""
    note = (ROOT / "docs" / "rollen-phase4a.md").read_text(encoding="utf-8")
    plan = (ROOT / "docs" / "superpowers" / "plans" / "2026-11-07-phase4a-rollen.md").read_text(encoding="utf-8")
    counts, section = {}, None
    for line in plan.splitlines():
        task = re.match(r"### Task (\d+):", line)
        if task:
            section = f"T{task[1]}"
        elif line.startswith("## "):
            section = "A" if line == "## Ausschlüsse" else None
        elif line.startswith("- Entscheidung:") and section:
            counts[section] = counts.get(section, 0) + 1
    assert set(counts) == {"A"} | {f"T{n}" for n in range(1, 11)}, counts
    for section, n in counts.items():
        for rid in ([f"A{i}" for i in range(1, n + 1)] if section == "A" else [f"{section}-{chr(ord('a') + i)}" for i in range(n)]):
            assert f"\n| {rid} |" in note, rid


def test_the_roles_note_repeats_the_permission_matrix():
    """Phase 4a wrap-up: the note's table "Rechte je Route" has a row for every entry of MATRIX, the matrix the walk over the app's
    routes holds (tests/test_permissions.py), with the German name of its minimum role - the note cannot go stale silently."""
    from test_permissions import MATRIX
    note = (ROOT / "docs" / "rollen-phase4a.md").read_text(encoding="utf-8")
    label = {None: "öffentlich", **roles.LABELS}
    for (method, path), role in MATRIX.items():
        assert f"| {method} | `{path}` | {label[role]} |" in note, (method, path)


def test_the_readme_describes_roles_and_approvals():
    """Phase 4a wrap-up: the security section has a paragraph on the roles and approvals - four roles, the matrix in the note, zones,
    four eyes off by default, the nonce, the idle logout - and the login list names zones and four eyes."""
    security = README.split("\n## Security\n", 1)[1].split("\n## ", 1)[0]
    login = README.split("\n**Login**\n", 1)[1].split("\n## ", 1)[0]
    assert "**Roles and approvals.**" in security
    for text in ("Lesen", "Admin", "docs/rollen-phase4a.md", "zone", "four-eyes", "off by default", "nonce", "IDLE_MINUTES"):
        assert text in security.split("**Roles and approvals.**", 1)[1].split("\n\n", 1)[0], text
    for text in ("zone", "four-eyes"):
        assert text in login, text
