"""The version of SwitchView, named in this one place. GET /api/auth/me hands it to the page, which shows it next to the name in the
header (signed in only). CHANGELOG.md has an entry per version, the newest first, and its first entry is this number
(tests/test_version.py); the commit of a version carries the git tag v<number>. Every change raises the last number by one; the two
in front stay until a larger step is named as one (the last number then starts at 0 again)."""
VERSION = "0.5.1"
