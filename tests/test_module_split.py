"""Task 11 of Phase 3 (Phase 1 "main.py, changes.py ... aufteilen"): main.py is split into routers (api_switches, api_settings,
api_changes, api_devices), the netmap (topology) and the scheduler (jobs); changes.py hands the RADIUS preparation to radiusprep and
the read-back checks to changeverify. A pure move: the route table is the one recorded before it (tests/data/routes.json), and every
name the suite or a module reaches as main.X or changes.X still resolves there (re-exported through __all__). Routes added since are
recorded there too: /static/fonts/{name} (Phase 5, Task 1).
"""
import json
from pathlib import Path

import changes
import main

ROOT = Path(__file__).resolve().parent.parent
ROUTES = ROOT / "tests" / "data" / "routes.json"
LINES_BEFORE_CHANGES = 1176    # app/changes.py before the move


def lines(path: str) -> int:
    return len((ROOT / path).read_text(encoding="utf-8").splitlines())


def test_the_route_table_is_unchanged():
    assert sorted([r.path, sorted(getattr(r, "methods", None) or [])] for r in main.app.routes) == json.loads(ROUTES.read_text())


def test_moved_names_still_resolve_through_main_and_changes():
    for name in ("build_map", "_links", "confirmed_endpoints", "switch_keys", "_make_plan", "_row", "_public", "_summary", "needed_ops",
                 "_snmp_unwritable", "_validate", "same_destination", "SECRET_FIELDS", "SECRET_INPUTS", "UNKNOWN_PER_PORT", "PortChange",
                 "PlanIn", "SwitchIn", "SettingsIn", "netmap", "unknown_devices"):
        assert hasattr(main, name), name
    for name in ("radius_settings", "_secrets_of", "readiness", "plan_prepare", "RADIUS_KEY_RE", "verify_ports", "verify_snmp"):
        assert hasattr(changes, name), name


def test_main_and_changes_shrank():
    assert lines("app/main.py") < 400 and lines("app/changes.py") < LINES_BEFORE_CHANGES
