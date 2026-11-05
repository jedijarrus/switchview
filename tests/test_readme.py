"""M6: the README describes the multivendor product, not a ProCurve/SSH-only one: every driver of the registry with what it can, SNMP
writes (the per-switch snmp_write switch, the RW credentials, PoE), what stays SSH-only, and the pointer to the German list of known
limitations and device checks. A driver added to drivers.DRIVERS without a README entry fails here."""
import pathlib

from drivers import DRIVERS

README = (pathlib.Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")


def test_readme_lists_every_driver():
    for name in DRIVERS:
        assert f"`{name}`" in README, name


def test_readme_describes_snmp_writes():
    for text in ("snmp_write", "authPriv", "clear text", "PoE", "write memory", "802.1X", "backup",
                 "Known limitations and required device checks (German): [docs/snmp-multivendor.md](docs/snmp-multivendor.md)"):
        assert text in README, text
    assert "For changes: an SSH account with manager rights on each switch" not in README    # the ProCurve-only wording of before
