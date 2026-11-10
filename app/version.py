"""The version of SwitchView, named in this one place. GET /api/auth/me hands it to the page, which shows it next to the name in the
header (signed in only). CHANGELOG.md has an entry per version, the newest first, and its first entry is this number
(tests/test_version.py); the commit of a version carries the git tag v<number>. A new function raises the middle number and sets
the last to 0, a fix raises the last."""
VERSION = "0.5.0"
