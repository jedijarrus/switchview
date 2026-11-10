"""The version of SwitchView: one number in app/version.py, handed to the page by GET /api/auth/me (so only to a signed-in user;
the header shows it, tests/test_frontend_dom.py). CHANGELOG.md names every version with its date, the newest first, and its first
entry is the number of version.py, so the two cannot drift apart."""
import re
from datetime import date
from pathlib import Path

from loginfix import GOOD
from version import VERSION

CHANGELOG = (Path(__file__).resolve().parent.parent / "CHANGELOG.md").read_text(encoding="utf-8")
ENTRIES = re.findall(r"^## (\d+\.\d+\.\d+) – (\d{4}-\d{2}-\d{2})$", CHANGELOG, flags=re.M)    # "## 0.5.0 – 2026-11-10"


def test_the_version_is_three_numbers():
    assert re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", VERSION)


def test_only_a_signed_in_user_learns_the_version(login_api):
    assert login_api.get("/api/auth/me").status_code == 401 and "version" not in login_api.get("/api/auth/config").json()
    login_api.post("/api/auth/local", json=GOOD)
    assert login_api.get("/api/auth/me").json()["version"] == VERSION


def test_the_changelog_starts_with_the_version():
    assert ENTRIES and ENTRIES[0][0] == VERSION


def test_the_changelog_names_every_version_once_with_its_date_the_newest_first():
    numbers = [tuple(int(n) for n in version.split(".")) for version, _ in ENTRIES]
    days = [date.fromisoformat(day) for _, day in ENTRIES]
    assert numbers == sorted(set(numbers), reverse=True) and days == sorted(days, reverse=True)
    assert len(ENTRIES) == len(re.findall(r"^## ", CHANGELOG, flags=re.M))    # every "## " heading is an entry of that form
