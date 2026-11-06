"""M6: the README describes the multivendor product, not a ProCurve/SSH-only one: every driver of the registry with what it can, SNMP
writes (the per-switch snmp_write switch, the RW credentials, PoE), what stays SSH-only, and the pointer to the German list of known
limitations and device checks. A driver added to drivers.DRIVERS without a README entry fails here. Phase 2: the README names the
security settings and links the German security note, which has the sections the plan asks for."""
import pathlib

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
