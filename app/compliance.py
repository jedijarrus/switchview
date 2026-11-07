"""Security rules (Phase 4b, Task 5): built-in rules and custom ones, their findings per switch. Without FastAPI.

Sources, each checked where its data comes from:
  config   the built-in rules on the running-config (check_config), unmasked, right where SwitchView reads it: sshcli.store_backup
           (the nightly backup, "Jetzt sichern", the read for a preview, the reads before and after an SSH change) calls
           evaluate_config after its own connection is closed. Telnet and HTTP count as on unless the configuration switches them off
           (the ProCurve/AOS-S factory defaults), a community with "unrestricted" writes, a manager without password shows only
           with include-credentials (without it the configuration shows no password, not even a set one).
  custom   the Admin's text rules (A1: "keine Zeile enthält" / "eine Zeile enthält", without case) on the masked configuration, in
           the same call; and on the latest backup of every switch whose driver backs up when the rules are saved
           (reevaluate_custom), masked once more with today's patterns (a backup from before Phase 2 is masked with older ones, E26).
           On masked text a rule can never guess a secret: it sees what a backup shows. A must_not rule shows at most its first
           CUSTOM_LINES lines per switch.
  snmp     the rules on the SNMP access SwitchView itself uses (check_snmp), after every good poll (poller.poll_switch), for
           every driver.
The mask: a finding stores only its masked line (cfgparse.mask_secrets; a community name masked from its match, whatever the case
of the keywords), masks it again when it is served, and its detail names only the default communities "public" and "private",
never another value.

A finding is one row of the table findings, identified by (switch, rule, line) and, for a line that is there more than once, its
place among them: seen again it gets a new last_seen, line number and detail; one of the checked sources that is not found any
more gets resolved_at. The first check of a switch per source (switches.compliance_cfg_at, compliance_snmp_at NULL) is the
baseline: stored, listed and counted, never told; afterwards each check returns its new findings, which its caller hands to the
alerts (alerts.announce_findings in sshcli.store_backup and poller.poll_switch; reevaluate_custom stores a baseline and tells
nothing). A rule an Admin switches off (settings SETTINGS_KEY) still checks, but its findings are hidden from the list, the count
and the return - switched on again, they are there at once. Every caller wraps its call: a failure here is logged and never changes
a poll or a backup.
"""
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

import cfgparse
import drivers
import radiusprep
from crypto import decrypt
from db import db, get_setting


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    severity: str    # crit | warn
    source: str      # config | snmp | custom
    hint: str


RULES: dict[str, Rule] = {r.id: r for r in (
    Rule("telnet", "Telnet-Server an", "crit", "config", "Ab Werk an. Abschalten: no telnet-server (SSH bleibt)."),
    Rule("snmp_default_community", "SNMP-Community „public“ oder „private“", "crit", "config",
         "Die Standard-Communities kennt jeder. Eigene Community setzen oder SNMPv3 nutzen."),
    Rule("snmp_write_community", "SNMPv2c-Community mit Schreibrecht", "warn", "config",
         "unrestricted erlaubt Schreiben per SNMPv2c; die Community geht im Klartext übers Netz."),
    Rule("manager_password", "Manager ohne Kennwort", "crit", "config",
         "Die Konfiguration zeigt Kennwörter (include-credentials), aber keins für manager."),
    Rule("web_plaintext", "Web-Oberfläche per HTTP", "warn", "config", "Ab Werk an. Nur HTTPS: web-management ssl und no web-management plaintext."),
    Rule("radius_prereq", "RADIUS-Voraussetzungen fehlen", "warn", "config", "An Ports mit 802.1X oder MAC-Auth fehlt, was „Vorbereiten“ einrichtet."),
    Rule("snmp_read_default", "SwitchView liest mit „public“ oder „private“", "warn", "snmp", "Der Switch antwortet auf eine Standard-Community."),
    Rule("snmp_write_insecure", "SNMP-Schreiben ohne Schutz", "warn", "snmp", "Empfohlen: SNMPv3 mit authPriv für den Schreib-Zugang."),
)}
SETTINGS_KEY = "compliance_rules"    # {"off": [ids of RULES], "custom": [{"id", "name", "mode", "text"}]}, JSON
CUSTOM_SEVERITY = "warn"             # a custom rule is never critical: it is the Admin's own check, not a known weakness
# The most lines a must_not rule shows per switch: 50 rules on every line of a 3000-port configuration were 150 000 open findings, a
# check 10 s in its write transaction (twice the busy timeout of every other connection) and 30 MB per GET of the list
CUSTOM_LINES = 100
DEFAULTS = ("public", "private")     # the communities every SNMP agent knows
TIME = "%Y-%m-%d %H:%M:%S"
# What radius_prereq names as missing, by the keys of radiusprep.readiness, in this order
RADIUS_NAMES = {"host": "RADIUS-Server {server}", "coa": "CoA (dyn-authorization)", "tw": "time-window 0", "eap": "eap-radius",
                "active": "802.1X global aktiv", "park": f"Park-VLAN {radiusprep.PARK_VLAN}"}
# snmp-server community <name> [operator|manager] [restricted|unrestricted], the name quoted or not: the name, then the rest
_COMMUNITY = re.compile(r'snmp-server\s+community\s+(?:"([^"]*)"|(\S+))(.*)', re.I)


def _now() -> str:
    """Now in UTC as the tables store it (a seam like monitor._now)."""
    return datetime.now(timezone.utc).strftime(TIME)


# ── The pure checks ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
# A finding is (rule, line_no | None, line, detail): line_no 1-based, line the masked, trimmed line; none: None, "".

def check_config(raw: str, radius_server: str) -> list[tuple]:
    """The findings of the built-in config rules on the unmasked running-config raw, in the order of RULES (each rule's lines in
    order); keywords without case, lines trimmed. radius_server: the RADIUS server of the settings ("" = none, no radius_prereq)."""
    lines = [x.strip() for x in raw.splitlines()]

    def has(pattern: str) -> bool:
        return any(re.fullmatch(pattern, x, re.I) for x in lines)

    defaults, writing = [], []
    for n, x in enumerate(lines, 1):
        m = _COMMUNITY.fullmatch(x)
        if not m:
            continue
        name = (m[1] if m[1] is not None else m[2]).lower()
        # The name masked from the match itself: the pattern of cfgparse.mask_secrets reads "community" with case only
        start, end = (m.start(1) - 1, m.end(1) + 1) if m[1] is not None else m.span(2)
        masked = cfgparse.mask_secrets(x[:start] + '"***"' + x[end:])
        if name in DEFAULTS:
            defaults.append(("snmp_default_community", n, masked, f"Community „{name}“"))
        if re.search(r"\bunrestricted\b", m[3], re.I):
            writing.append(("snmp_write_community", n, masked, ""))
    out = []
    if not has(r"no\s+telnet-server"):
        out.append(("telnet", None, "", ""))
    out += defaults + writing
    if has(r"include-credentials") and not any(re.match(r"password\s+manager\b", x, re.I) for x in lines):
        out.append(("manager_password", None, "", ""))
    if not has(r"no\s+web-management(?:\s+plaintext)?"):
        out.append(("web_plaintext", None, "", "HTTPS ist zusätzlich an" if has(r"web-management\s+ssl") else ""))
    missing = _radius_missing(raw, radius_server)
    if missing:
        out.append(("radius_prereq", None, "", "Fehlt: " + ", ".join(missing)))
    return out


def _radius_missing(raw: str, server: str) -> list[str]:
    """What radiusprep.readiness misses for server on a configuration with a port under 802.1X or MAC-Auth, by RADIUS_NAMES; nothing
    without a server, without such a port or for a configuration parse_config refuses (too big, E23)."""
    if not server:
        return []
    try:
        cfg = cfgparse.parse_config(raw)
    except ValueError:
        return []
    if not any(p["x"] or p["m"] for p in cfg["ports"].values()):
        return []
    ready = radiusprep.readiness(cfg, server)
    return [name.format(server=server) for key, name in RADIUS_NAMES.items() if not ready[key]]


def check_snmp(row) -> list[tuple]:
    """The findings of the SNMP rules on the switch row (a switches row): snmp_read_default when SwitchView reads over v2c with a
    default community (trimmed, without case) or with none it can read (then it asks with "public", snmp._conf_lines);
    snmp_write_insecure when SETs would go out spoofable (api_switches.write_insecurity: v2c, or v3 without authentication)."""
    import api_switches  # late: a router module (FastAPI, and api_switches → sshcli → compliance); this module stays without it
    out = []
    if row["snmp_version"] != "3":
        stored = decrypt(row["snmp_community"])
        community = stored.strip().lower() if stored else "public"
        if community in DEFAULTS:
            out.append(("snmp_read_default", None, "", f"SwitchView liest per SNMPv2c mit der Community „{community}“"))
    weak = api_switches.write_insecurity(row)
    if weak == "v2c":
        out.append(("snmp_write_insecure", None, "", "per SNMPv2c: die Schreib-Community geht im Klartext übers Netz"))
    elif weak == "v3":
        out.append(("snmp_write_insecure", None, "", "per SNMPv3 ohne Authentifizierung"))
    return out


def check_custom(masked: str, rules: list[dict]) -> list[tuple]:
    """The findings of the custom rules ({"id", "name", "mode", "text"}) on the masked configuration masked, lines trimmed, text
    without case: must_not one per line that contains text, at most the first CUSTOM_LINES (the last of them names how many more
    there are), must one without a line when no line does."""
    lines = [x.strip() for x in masked.splitlines()]
    folded = [x.casefold() for x in lines]
    out = []
    for rule in rules:
        text = rule["text"]
        needle = text.casefold()
        hits = [n for n, x in enumerate(folded, 1) if needle in x]
        if rule["mode"] == "must_not":
            shown = hits[:CUSTOM_LINES]
            more = f" (und {len(hits) - len(shown)} weitere, nicht einzeln aufgeführt)" if len(hits) > len(shown) else ""
            out += [(rule["id"], n, lines[n - 1], f"Zeile enthält „{text}“" + (more if n == shown[-1] else "")) for n in shown]
        elif not hits:
            out.append((rule["id"], None, "", f"Keine Zeile enthält „{text}“"))
    return out


# ── The rules in force ───────────────────────────────────────────────────────────────────────────────────────────────────────────
async def load_rules() -> dict:
    """{"off": set of the built-in rules switched off, "custom": the custom rules}, from the settings (no value: none of either)."""
    raw = await get_setting(SETTINGS_KEY)
    data = json.loads(raw) if raw else {}
    return {"off": set(data.get("off", [])), "custom": list(data.get("custom", []))}


def _in_force(rules: dict) -> dict[str, Rule]:
    """The rules whose findings show: the built-in ones that are on, in the order of RULES, then the custom ones as Rule (label: the
    name)."""
    out = {rid: r for rid, r in RULES.items() if rid not in rules["off"]}
    out |= {c["id"]: Rule(c["id"], c["name"], CUSTOM_SEVERITY, "custom", "") for c in rules["custom"]}
    return out


def _served(r, rule: Rule) -> dict:
    """A findings row as open_findings serves it, its line masked once more."""
    return {"id": r["id"], "rule": rule.id, "label": rule.label, "severity": rule.severity, "line_no": r["line_no"],
            "line": cfgparse.mask_secrets(r["line"]), "detail": r["detail"], "first_seen": r["first_seen"]}


# ── Storing ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def _store(switch_id: int, found: dict[str, list[tuple]], column: str | None) -> list[int]:
    """Stores the findings of one check of switch_id - found: source -> its findings - in one write transaction: an open finding of
    the same (rule, line) gets last_seen, line_no and detail anew, a new one is inserted, an open one of these sources that was not
    found gets resolved_at; then column (compliance_cfg_at or compliance_snmp_at, None for none) is now. The same (rule, line) more
    than once - two communities mask alike, a custom rule finds "exit" at every block - is a finding each, the k-th found taking the
    k-th open one by id: so one more such line is new and one less resolves the last. Returns the ids of the new findings, none for
    the baseline (column NULL before, or None) or a switch that is gone. Writes in batches: a broad custom rule keeps up to
    CUSTOM_LINES findings at every check."""
    now, sources = _now(), list(found)
    async with db() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        async with conn.execute("SELECT compliance_cfg_at, compliance_snmp_at FROM switches WHERE id = ?", (switch_id,)) as cur:
            switch = await cur.fetchone()
        if switch is None:
            await conn.rollback()
            return []
        baseline = column is None or switch[column] is None
        async with conn.execute(f"SELECT id, rule, line FROM findings WHERE switch_id = ? AND resolved_at IS NULL AND source IN "
                                f"({', '.join('?' * len(sources))}) ORDER BY id", (switch_id, *sources)) as cur:
            stored = [(r["id"], (r["rule"], r["line"])) for r in await cur.fetchall()]
        open_ids: dict[tuple, list[int]] = {}
        for fid, key in stored:
            open_ids.setdefault(key, []).append(fid)
        seen: dict[tuple, int] = {}
        updates, inserts = [], []
        for source, items in found.items():
            for rule, line_no, line, detail in items:
                k = seen[(rule, line)] = seen.get((rule, line), 0) + 1
                ids = open_ids.get((rule, line), [])
                if k <= len(ids):
                    updates.append((now, line_no, detail, ids[k - 1]))
                else:
                    inserts.append((switch_id, rule, source, line_no, line, detail, now, now))
        kept = {fid for *_, fid in updates}
        await conn.executemany("UPDATE findings SET last_seen = ?, line_no = ?, detail = ? WHERE id = ?", updates)
        await conn.executemany("UPDATE findings SET resolved_at = ? WHERE id = ?", [(now, fid) for fid, _ in stored if fid not in kept])
        new = []
        if inserts:
            async with conn.execute("SELECT coalesce(max(id), 0) FROM findings") as cur:
                last = (await cur.fetchone())[0]
            await conn.executemany("INSERT INTO findings(switch_id, rule, source, line_no, line, detail, first_seen, last_seen) "
                                   "VALUES (?,?,?,?,?,?,?,?)", inserts)
            # AUTOINCREMENT gives each new row an id above every one before, and BEGIN IMMEDIATE lets no other writer in between
            async with conn.execute("SELECT id FROM findings WHERE id > ? ORDER BY id", (last,)) as cur:
                new = [r[0] for r in await cur.fetchall()]
        if column:
            await conn.execute(f"UPDATE switches SET {column} = ? WHERE id = ?", (now, switch_id))
        await conn.commit()
    return [] if baseline else new


async def _new_findings(ids: list[int], rules: dict) -> list[dict]:
    """The findings ids as open_findings reads them, without those of a rule not in force."""
    if not ids:
        return []
    force = _in_force(rules)
    async with db() as conn:
        async with conn.execute(f"SELECT id, rule, line_no, line, detail, first_seen FROM findings WHERE id IN ({', '.join('?' * len(ids))}) "
                                "ORDER BY id", ids) as cur:
            return [_served(r, force[r["rule"]]) for r in await cur.fetchall() if r["rule"] in force]


async def evaluate_config(switch_id: int, raw: str) -> list[dict]:
    """Checks the unmasked running-config raw of switch_id - the built-in config rules with the RADIUS server of the settings and the
    custom rules on its masked text - and stores the findings as the sources config and custom (_store, compliance_cfg_at). Returns
    the new findings as open_findings reads them: none at the baseline or of a rule switched off."""
    server = await get_setting("radius_server", "") or ""
    rules = await load_rules()
    found = {"config": check_config(raw, server), "custom": check_custom(cfgparse.mask_secrets(raw), rules["custom"])}
    return await _new_findings(await _store(switch_id, found, "compliance_cfg_at"), rules)


async def evaluate_snmp(row) -> list[dict]:
    """Checks the SNMP access of the switch row (check_snmp) and stores the findings as the source snmp (compliance_snmp_at); returns
    the new ones like evaluate_config."""
    rules = await load_rules()
    return await _new_findings(await _store(row["id"], {"snmp": check_snmp(row)}, "compliance_snmp_at"), rules)


async def reevaluate_custom() -> None:
    """The custom rules after they were saved: deletes the findings of the custom rules that are gone, then checks the latest backup
    of every switch whose driver backs up, masked once more (cfgparse.mask_secrets: today's patterns), and stores its findings as
    the source custom - as baseline, returning nothing."""
    rules = (await load_rules())["custom"]
    ids = [c["id"] for c in rules]
    async with db() as conn:
        await conn.execute(f"DELETE FROM findings WHERE source = 'custom' AND rule NOT IN ({', '.join('?' * len(ids))})", ids)
        await conn.commit()
        async with conn.execute("SELECT s.id, s.driver, b.content FROM switches s JOIN config_backups b ON b.id = "
                                "(SELECT max(id) FROM config_backups WHERE switch_id = s.id)") as cur:
            latest = [(r["id"], r["content"]) for r in await cur.fetchall() if drivers.can(drivers.driver_for(r), "backup")]
    for sid, content in latest:
        await _store(sid, {"custom": check_custom(cfgparse.mask_secrets(content), rules)}, None)


# ── Reading ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def open_findings(switch_id: int) -> list[dict]:
    """The open findings of switch_id of the rules in force, critical first, then by line (those without one first), then in the
    order of the rules: id, rule, label, severity, line_no, line (masked again), detail, first_seen."""
    force = _in_force(await load_rules())
    order = {rid: i for i, rid in enumerate(force)}
    async with db() as conn:
        async with conn.execute("SELECT id, rule, line_no, line, detail, first_seen FROM findings WHERE switch_id = ? AND resolved_at IS NULL",
                                (switch_id,)) as cur:
            rows = [r for r in await cur.fetchall() if r["rule"] in force]
    rows.sort(key=lambda r: (force[r["rule"]].severity != "crit", r["line_no"] is not None, r["line_no"] or 0, order[r["rule"]], r["id"]))
    return [_served(r, force[r["rule"]]) for r in rows]


async def summary() -> dict:
    """The open findings of the rules in force over all switches: {"total", "crit", "switches": [{"id", "name", "count", "crit"}]},
    only switches with findings, by name (without case)."""
    force = _in_force(await load_rules())
    crit = [rid for rid, r in force.items() if r.severity == "crit"]
    ids = list(force)
    async with db() as conn:
        async with conn.execute(f"SELECT s.id, s.name, count(*) AS count, sum(f.rule IN ({', '.join('?' * len(crit))})) AS crit "
                                f"FROM findings f JOIN switches s ON s.id = f.switch_id WHERE f.resolved_at IS NULL AND f.rule IN "
                                f"({', '.join('?' * len(ids))}) GROUP BY s.id ORDER BY s.name COLLATE NOCASE, s.id", (*crit, *ids)) as cur:
            switches = [{"id": r["id"], "name": r["name"], "count": r["count"], "crit": r["crit"]} for r in await cur.fetchall()]
    return {"total": sum(s["count"] for s in switches), "crit": sum(s["crit"] for s in switches), "switches": switches}


async def rules_view() -> dict:
    """Every rule with its state for GET /api/compliance/rules: the built-in ones first, in the order of RULES, then the custom ones
    (always on: a custom rule is removed, not switched off), only those with mode and text."""
    rules = await load_rules()
    out = [{"id": r.id, "label": r.label, "severity": r.severity, "source": r.source, "hint": r.hint, "on": r.id not in rules["off"],
            "custom": False} for r in RULES.values()]
    out += [{"id": c["id"], "label": c["name"], "severity": CUSTOM_SEVERITY, "source": "custom", "hint": "", "on": True, "custom": True,
             "mode": c["mode"], "text": c["text"]} for c in rules["custom"]]
    return {"rules": out}
