"""SQLite-Zugriff. Immer ueber db() verbinden (PRAGMAs pro Connection)."""
import contextvars
import hashlib
import os
import re
import sqlite3
from collections.abc import Iterable
from contextlib import asynccontextmanager, closing

import aiosqlite

from config import settings

# Urstand der Tabellen. Spaeter dazugekommene Spalten gehoeren NICHT hierher, sondern in ADDED_COLUMNS (siehe migrate()).
SCHEMA = """
CREATE TABLE IF NOT EXISTS switches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL UNIQUE,
    zone TEXT NOT NULL DEFAULT '',
    sort INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    snmp_version TEXT NOT NULL DEFAULT '2c',
    snmp_community TEXT,
    snmp_user TEXT,
    snmp_auth_proto TEXT,
    snmp_auth_pass TEXT,
    snmp_priv_proto TEXT,
    snmp_priv_pass TEXT,
    ssh_user TEXT,
    ssh_pass TEXT,
    sys_name TEXT,
    sys_descr TEXT,
    model TEXT,
    firmware TEXT,
    base_mac TEXT,
    uptime INTEGER,
    last_poll TEXT,
    last_poll_ok INTEGER,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ports (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    ifindex INTEGER NOT NULL,
    name TEXT NOT NULL,
    alias TEXT,
    oper INTEGER,
    admin INTEGER,
    speed INTEGER,
    pvid TEXT,
    untagged TEXT,
    tagged TEXT,
    trunk TEXT,
    members TEXT,
    lldp TEXT,
    mac_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (switch_id, ifindex)
);
CREATE TABLE IF NOT EXISTS vlans (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    vid TEXT NOT NULL,
    name TEXT,
    PRIMARY KEY (switch_id, vid)
);
CREATE TABLE IF NOT EXISTS macs (
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    port TEXT NOT NULL,
    mac TEXT NOT NULL,
    vlan TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (switch_id, mac, vlan)
);
CREATE INDEX IF NOT EXISTS idx_macs_port ON macs(switch_id, port);
CREATE TABLE IF NOT EXISTS names (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    name TEXT,
    vendor TEXT,
    source TEXT,
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS config_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    taken_at TEXT NOT NULL,
    sha TEXT NOT NULL,
    content TEXT NOT NULL,
    trigger TEXT NOT NULL DEFAULT 'nightly'
);
CREATE INDEX IF NOT EXISTS idx_backups_sw ON config_backups(switch_id, taken_at);
CREATE TABLE IF NOT EXISTS switch_cfg (
    switch_id INTEGER PRIMARY KEY REFERENCES switches(id) ON DELETE CASCADE,
    taken_at TEXT NOT NULL,
    parsed TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    username TEXT,
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    request TEXT,
    ports TEXT,
    desired TEXT,
    before TEXT,
    commands TEXT,
    status TEXT NOT NULL,
    saved INTEGER NOT NULL DEFAULT 0,
    expert INTEGER NOT NULL DEFAULT 0,
    steps TEXT,
    output TEXT,
    error TEXT,
    revert_of INTEGER,
    reverted_by INTEGER
);
CREATE INDEX IF NOT EXISTS idx_changes_sw ON changes(switch_id, id);
-- Phase 4c, Task 4: the one-change-per-switch check (changes.busy_reason) and the watch of the changes waiting for their
-- confirmation (Task 5) ask by status. Only a column of the original table: SCHEMA runs before migrate on an existing database.
CREATE INDEX IF NOT EXISTS idx_changes_status ON changes(status);
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'sonstiges',
    location TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    allowed INTEGER NOT NULL DEFAULT 0,
    valid_until TEXT,
    pf_state TEXT,
    pf_error TEXT,
    pf_synced_at TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT,
    method TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    username TEXT,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);
-- Phase 4a, Task 5: the zone scopes, kept by an Admin (PUT /api/zone-scopes). A user with Ändern or Freigeben whose Entra app roles
-- (sessions.claims) contain a principal here changes only switches whose zone is one of that principal's zones (roles.zones_of);
-- zone '' is the switches without a zone. Read on every request of such a user (auth.current_user). Empty: no one is limited.
CREATE TABLE IF NOT EXISTS zone_scopes (principal TEXT NOT NULL, zone TEXT NOT NULL, PRIMARY KEY (principal, zone));
-- Phase 4a, Task 6: the four-eyes requests (app/approvals.py). One row per request: its kind (approvals.KINDS), its switch (NULL for
-- a kind without one; deleting the switch deletes its requests), the exact desired state its requester sent (payload, JSON) and the
-- preview they saw (preview, JSON), its status (open, then approved, rejected, withdrawn, expired or stale), who asked (user name,
-- display name, subject, role) and when, when it expires (ISO-UTC), who decided and when, the rejection's comment, the reason of a
-- stale one and the change an approval started (Task 7).
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, switch_id INTEGER REFERENCES switches(id) ON DELETE CASCADE,
    summary TEXT NOT NULL, payload TEXT NOT NULL, preview TEXT NOT NULL, status TEXT NOT NULL,
    requested_by TEXT NOT NULL, requester_name TEXT, requester_subject TEXT NOT NULL, requester_role TEXT,
    requested_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    decided_by TEXT, decided_subject TEXT, decided_at TEXT, comment TEXT, reason TEXT, change_id INTEGER);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, id);
-- Phase 4b, Task 2: where each device was seen (app/history.py). Written only by history.record after a good poll (one round of
-- poll_all at once, a single poll for its switch). One row per place - a MAC at a switch, a port and a VLAN, with the IP and name
-- known for it - from the poll that first saw it there to the last one that did; a new row only when the place changes or another
-- IP turns up there, otherwise last_seen moves on. Trunks and confirmed uplinks are no place; suspect marks a possible uplink.
-- Purged after HISTORY_DAYS (history.purge). A deleted switch keeps its rows (ON DELETE SET NULL, its name in switch_name): where a
-- device was stays a question after a switch is replaced.
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL,
    switch_id INTEGER REFERENCES switches(id) ON DELETE SET NULL, switch_name TEXT NOT NULL DEFAULT '',
    port TEXT NOT NULL, vlan TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '',
    suspect INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sightings_mac ON sightings(mac, last_seen);
CREATE INDEX IF NOT EXISTS idx_sightings_ip ON sightings(ip, last_seen) WHERE ip <> '';
CREATE INDEX IF NOT EXISTS idx_sightings_port ON sightings(switch_id, port, last_seen);
CREATE INDEX IF NOT EXISTS idx_sightings_seen ON sightings(last_seen);
-- Phase 4b, Task 4: discrete events (app/monitor.py), one row each: a switch that stops answering (switch_down, after
-- monitor.UNREACHABLE_AFTER failed polls in a row) or answers again (switch_up), an LLDP neighbour that appears, changes or vanishes
-- at a port (lldp_new, lldp_changed, lldp_gone), a port changed outside SwitchView at a switch it does not back up (drift_port) and a
-- backup that differs from the one before without a SwitchView change between them (drift_config). ts is when it was seen (the
-- poll's time, the backup's), port '' for an event of the whole switch, text the German sentence, detail JSON (monitor.KINDS says
-- what each kind carries). Written by poller.poll_switch (through monitor.poll_succeeded / poll_failed) and sshcli.store_backup
-- (monitor.backup_outside); read by GET /api/events. Deleting the switch deletes its events; purged after HISTORY_DAYS by ts.
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, switch_id INTEGER REFERENCES switches(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, port TEXT NOT NULL DEFAULT '', text TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_events_sw ON events(switch_id, id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
-- Phase 4b, Task 5: the findings of the security rules (app/compliance.py), one row per switch, rule and line: rule an id of
-- compliance.RULES or of a custom rule, source config | custom | snmp (where it was checked), line_no 1-based (NULL for a finding
-- without a line), line the masked line ('' without one), detail the German detail (never a secret value), first_seen and last_seen
-- the first and the last check that found it, resolved_at the check that no longer did (NULL: open). Written by
-- compliance.evaluate_config (sshcli.store_backup), evaluate_snmp (poller.poll_switch) and reevaluate_custom (PUT
-- /api/compliance/rules); read by GET /api/switches/{sid}/findings and GET /api/compliance. Deleting the switch deletes its findings;
-- resolved ones are purged after HISTORY_DAYS by resolved_at.
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, switch_id INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE, rule TEXT NOT NULL,
    source TEXT NOT NULL, line_no INTEGER, line TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, resolved_at TEXT);
CREATE INDEX IF NOT EXISTS idx_findings_sw ON findings(switch_id, resolved_at);
-- Phase 4b, Task 6: the alert queue (app/alerts.py), one row per message and channel (mail | webhook): created_at when alerts.emit
-- wrote it, event a key of alerts.EVENTS (or cap, the summary past the hourly limit), dedup_key "<event>:<key>" (the same key within
-- alerts.DEDUP_MINUTES adds to repeats instead of a new row), the switch it is about (no foreign key: a message outlives its switch,
-- switch_name keeps the name), title (one line), text and facts (JSON) as they go out, status queued | sent | failed | suppressed
-- (past the hourly limit, never sent), attempts the failed attempts so far, next_at when a queued row is due, sent_at, error (the
-- masked text of the last failure). Written by alerts.emit, delivered by the scheduler job alerts.deliver_due; read by GET
-- /api/alerts/deliveries. Every row but a queued one is purged after HISTORY_DAYS by created_at.
CREATE TABLE IF NOT EXISTS alert_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, channel TEXT NOT NULL, event TEXT NOT NULL, dedup_key TEXT NOT NULL,
    switch_id INTEGER, switch_name TEXT NOT NULL DEFAULT '', title TEXT NOT NULL, text TEXT NOT NULL, facts TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_at TEXT, sent_at TEXT, error TEXT, repeats INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_outbox_due ON alert_outbox(status, next_at);
CREATE INDEX IF NOT EXISTS idx_outbox_key ON alert_outbox(channel, dedup_key, created_at);
CREATE INDEX IF NOT EXISTS idx_outbox_created ON alert_outbox(created_at);
-- A page of one status, newest first (GET /api/alerts/deliveries?status=...): without it, every row of that status is sorted per page
CREATE INDEX IF NOT EXISTS idx_outbox_status ON alert_outbox(status, id);
-- emit's count of the last hour of a channel (in its write transaction, on the poll path): idx_outbox_key serves only channel=? for
-- it, so without this one the count reads every retained row of the channel, the suppressed ones too
CREATE INDEX IF NOT EXISTS idx_outbox_hour ON alert_outbox(channel, created_at);
-- Phase 4b, Task 7: the MAC watch list (app/history.py), one row per watched MAC ("aa:bb:cc:dd:ee:ff", api_devices.norm_mac) with
-- the note of whoever added it, their user name and when (UTC). A recording (history.record) that sees one of them for the first
-- time, at another place or back after an absence tells it (alerts.announce_sightings, the event watch). Kept by Ändern
-- (POST /api/watch, DELETE /api/watch/{mac}), read by Lesen (GET /api/watch); no zone: a MAC belongs to no switch. Never purged.
CREATE TABLE IF NOT EXISTS watch_macs (mac TEXT PRIMARY KEY, note TEXT NOT NULL DEFAULT '', created_by TEXT, created_at TEXT NOT NULL);
-- Phase 4b, Task 8: the audit filtered by an action or a user (GET /api/audit, api_settings.audit_filter), a page in the order of the
-- id. The user's index carries the collation of its filter (username = ? COLLATE NOCASE): SQLite takes no BINARY index for that.
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action, id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(username COLLATE NOCASE, id);
-- Phase 4c, Task 2: the API tokens (app/api_tokens.py, resolved by auth.current_user), one row per token of a person signed in over
-- SSO: token_hash the db.token_hash of the token (the token itself is shown once, in the answer of POST /api/tokens, and stored
-- nowhere), name unique per subject, the user name, display name, login method and stable identity (subject) of whoever created it,
-- claims the app roles of the session it was created in (JSON {"roles": [...]}, from which current_user works out its role on every
-- request), max_role the role it is capped at (NULL: the role of its user), created_at, expires_at (1-365 days later, never NULL)
-- and last_used_at (written at most once a minute; NULL: never used), all UTC as "YYYY-MM-DD HH:MM:SS". Listed per subject (GET
-- /api/tokens), revoked by deleting the row; auth.prune_sessions deletes the expired ones hourly.
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL UNIQUE, name TEXT NOT NULL, username TEXT NOT NULL, display_name TEXT,
    method TEXT NOT NULL, subject TEXT NOT NULL, claims TEXT NOT NULL DEFAULT '{}', max_role TEXT, created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL, last_used_at TEXT);
CREATE INDEX IF NOT EXISTS idx_api_tokens_subject ON api_tokens(subject);
-- Phase 4c, Task 7: the bulk changes (app/bulk.py), one row per bulk change started by POST /api/bulk (bulk.create): created_at
-- (UTC), who started it (username, role, the API token they used as "<name> (#<id>)", NULL for a session; approved_by NULL without
-- a four-eyes approval), summary ("VLAN 30 · 3 Ports an 2 Switches"), change (the PortChange as JSON), expert, on_error (stop |
-- continue), confirm_minutes (NULL: without confirmation), status (queued, running, done, failed, cancelled, interrupted),
-- cancel_requested (1 once POST /api/bulk/{blk}/cancel asked; the run stops before its next switch) and finished_at. Written by
-- bulk.create, bulk.run, bulk.cancel and bulk.mark_interrupted (a restart); read by GET /api/bulk and GET /api/bulk/{blk}. Never
-- deleted: a bulk change outlives its switches.
CREATE TABLE IF NOT EXISTS bulks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, username TEXT NOT NULL, role TEXT, api_token TEXT, approved_by TEXT,
    summary TEXT NOT NULL, change TEXT NOT NULL, expert INTEGER NOT NULL DEFAULT 0, on_error TEXT NOT NULL, confirm_minutes INTEGER,
    status TEXT NOT NULL, cancel_requested INTEGER NOT NULL DEFAULT 0, finished_at TEXT);
CREATE INDEX IF NOT EXISTS idx_bulks_status ON bulks(status);
-- Phase 4c, Task 7: the switches of a bulk change in their order (pos): the switch (NULL once it is deleted; switch_name keeps its
-- name), its ports (JSON), the write way and the preview token of its preview (NULL for a skipped switch), status (waiting, running,
-- done, failed, skipped, not_started), the change it started (change_id, no foreign key: the change goes with its switch) and the
-- detail (why skipped, failed or not started; '' for a switch that ran). Written by bulk.create, bulk.run and
-- bulk.mark_interrupted; read with its bulk change.
CREATE TABLE IF NOT EXISTS bulk_items (
    bulk_id INTEGER NOT NULL REFERENCES bulks(id) ON DELETE CASCADE, pos INTEGER NOT NULL,
    switch_id INTEGER REFERENCES switches(id) ON DELETE SET NULL, switch_name TEXT NOT NULL DEFAULT '', ports TEXT NOT NULL,
    mechanism TEXT, token TEXT, status TEXT NOT NULL, change_id INTEGER, detail TEXT NOT NULL DEFAULT '', PRIMARY KEY (bulk_id, pos));
"""

# Spalten, die nach dem Urstand dazugekommen sind: (Tabelle, Spalte, Definition). migrate() ist die EINZIGE Stelle, die sie anlegt,
# damit eine frische und eine bestehende DB denselben Weg gehen und es keine zweite Quelle der Wahrheit gibt. Neue Spalten nur hier
# anhaengen. Alle Eintraege sind feste Literale und werden so ins SQL eingesetzt: nie Nutzereingaben hier hineinreichen.
ADDED_COLUMNS = (
    # Treiber und SNMP-Schreibfreigabe (Spec 2). Bestandszeilen bleiben ProCurve ohne SNMP-Write, das Verhalten aendert sich nicht.
    ("switches", "driver", "TEXT NOT NULL DEFAULT 'procurve'"),
    ("switches", "snmp_write", "INTEGER NOT NULL DEFAULT 0"),
    # Eigene Write-Identitaet fuer SNMP-SET, getrennt von den Read-Spalten snmp_*. Bestandszeilen haben NULL. Community und Passwoerter
    # liegen wie die Read-Spalten verschluesselt und stehen in main.SECRET_FIELDS (verschluesseln, nur *_set ausliefern, im Audit beim
    # Namen nennen). Ausgeliefert wird ohnehin nur, was in der Allowlist api_switches.PUBLIC_FIELDS steht; welche Identitaet schreibt,
    # entscheidet allein poller.write_identity.
    ("switches", "snmp_rw_community", "TEXT"),
    ("switches", "snmp_rw_user", "TEXT"),
    ("switches", "snmp_rw_auth_proto", "TEXT"),
    ("switches", "snmp_rw_auth_pass", "TEXT"),
    ("switches", "snmp_rw_priv_proto", "TEXT"),
    ("switches", "snmp_rw_priv_pass", "TEXT"),
    # PoE je Port. Bestandszeilen haben NULL.
    ("ports", "poe_admin", "INTEGER"),
    ("ports", "poe_status", "INTEGER"),
    ("ports", "poe_power", "INTEGER"),
    # Audit-Spur: ssh | snmp. Bestandszeilen haben NULL.
    ("changes", "mechanism", "TEXT"),
    # The switch's SSH host key, pinned at the first successful SSH contact ("<type> <base64>", sshcli.host_key_of), and when (UTC).
    # Existing rows have NULL: their next SSH contact pins the key (trust on first use, E30). No secret, but never served as is: GET
    # /api/switches serves its fingerprints only.
    ("switches", "ssh_host_key", "TEXT"),
    ("switches", "ssh_host_key_at", "TEXT"),
    # The mark of the unmasked running-config a backup was taken from: crypto.keyed_digest("backup", text), never a plain hash (that
    # would be an oracle for the masked secrets in a copy of the database). sshcli.store_backup compares it to tell a change of
    # secrets alone, which the masked sha cannot see. Existing rows have NULL: the next backup of the same masked text fills it in.
    ("config_backups", "raw_mac", "TEXT"),
    # Whether a change may have reached its switch: 0 while nothing has gone out (changes.create_change writes 0), 1 from the moment
    # the switch may have taken something (right before send_config_set / write memory over SSH, right before the SET over SNMP).
    # Existing rows have NULL: unknown, and counted as sent (changes.may_have_sent), so they keep revert and save as before.
    ("changes", "sent", "INTEGER"),
    # Whether the switch may have changed since its read of the running-config (switch_cfg): 1 once an SNMP SET or SSH lines may have
    # gone out (changes.mark_cfg_stale), 0 again with the next read (changes.store_cfg). taken_at stays the time of the read. fresh_cfg
    # reads anew for a stale entry, and the map takes a port's on / off from the poll then. Existing rows have 0.
    ("switch_cfg", "stale", "INTEGER NOT NULL DEFAULT 0"),
    # Phase 4a, written by auth.create_session at the login: the roles claim of the id_token as JSON ({"roles": [...]}, from which
    # auth.current_user works out the role on every request), the stable identity of the person (entra:<oid>, without an oid
    # entra:<sub>; local:<user name>) and the time of the last request (ISO-UTC like created_at, written at most once a minute, for
    # the idle logout). Sessions of before have NULL: no stored roles, the subject <method>:<user name>, and their first request
    # counts as activity.
    ("sessions", "claims", "TEXT"),
    ("sessions", "subject", "TEXT"),
    ("sessions", "last_seen", "TEXT"),
    # Phase 4a: the role of whoever made an audit entry (audit() requires it; NULL for a failed login, which has no session), the role
    # of whoever started a change (changes.create_change; its change_* entry names it, whenever the change ends) and who approved it
    # (Task 7; NULL until then and for every change without a four-eyes request). Rows of before have NULL.
    ("audit", "role", "TEXT"),
    ("changes", "role", "TEXT"),
    ("changes", "approved_by", "TEXT"),
    # Phase 4b, Task 4, written by poller.poll_switch: the failed polls in a row (+1 with each failed poll, 0 with a good one); since
    # when the switch counts as unreachable (set by monitor.poll_failed at the UNREACHABLE_AFTER-th failed poll in a row, NULL again
    # with the next good poll; NULL: reachable); the time of the last good poll (NULL: none since the update, monitor then takes
    # last_poll if that one was good); and the fields of the port configuration (monitor.DRIFT_FIELDS keys, a JSON list) the last
    # good poll could not read completely, which the next one does not compare (NULL: none known, a poll from before the update;
    # monitor then compares none of them when that poll left a note in last_error). Existing rows have 0 and NULL.
    ("switches", "poll_failures", "INTEGER NOT NULL DEFAULT 0"),
    ("switches", "down_since", "TEXT"),
    ("switches", "last_ok_at", "TEXT"),
    ("switches", "unread_fields", "TEXT"),
    # Phase 4b, Task 4, written by sshcli.store_backup (monitor.backup_outside): 1 when the backup differs from the one before it and
    # no SwitchView change that may have sent something ran between the two, 0 when one did. NULL: not compared - the first backup
    # of a switch, a backup from before the update, or one whose check failed.
    ("config_backups", "outside", "INTEGER"),
    # Phase 4b, Task 5, written by compliance (evaluate_config, evaluate_snmp): the time of the last check of the security rules per
    # source, the running-config and the SNMP access. NULL: never checked, so the next check is the baseline and tells nothing.
    # Existing rows have NULL.
    ("switches", "compliance_cfg_at", "TEXT"),
    ("switches", "compliance_snmp_at", "TEXT"),
    # Phase 4c, Task 2, written by audit(): the API token an entry was made with, "<name> (#<id>)" (auth.token_label), from the
    # context of its request (AUDIT_TOKEN). NULL for an entry of a session, of the scheduler, without a user, and for every row of
    # before.
    ("audit", "token", "TEXT"),
    # Phase 4c, Task 4: a change with confirmation. confirm_minutes the minutes it waits for "Bestätigen" (changes.create_change; NULL:
    # without confirmation, every row of before), confirm_until its deadline (UTC, "YYYY-MM-DD HH:MM:SS"), written when run_change
    # leaves it waiting (status pending), and confirmed_by who confirmed it (confirm.confirm_change). Existing rows have NULL.
    ("changes", "confirm_minutes", "INTEGER"),
    ("changes", "confirm_until", "TEXT"),
    ("changes", "confirmed_by", "TEXT"),
    # Phase 4c, Task 7: the bulk change a change belongs to (bulks.id, written by changes.create_change for each switch bulk.run
    # starts; NULL for every other change and every row of before). No foreign key: a bulk change is never deleted.
    ("changes", "bulk_id", "INTEGER"),
    # Phase 4c, Task 8: the bulk change an approval of the kind bulk_change started (bulks.id, written by approvals.claim in the
    # transaction that creates the bulk change; NULL for every other request and every row of before), as change_id for a port change.
    ("approvals", "bulk_id", "INTEGER"),
)


@asynccontextmanager
async def db():
    os.makedirs(settings.data_dir, exist_ok=True)
    conn = await aiosqlite.connect(settings.db_path)
    conn.row_factory = aiosqlite.Row
    try:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute("PRAGMA journal_mode = WAL")
        yield conn
    finally:
        await conn.close()


def execute_sync(sql: str, args: tuple = ()) -> int:
    """sql with args on a connection of its own (the stdlib sqlite3, for code in a worker thread, where db() cannot run), committed;
    the number of rows it changed."""
    with closing(sqlite3.connect(settings.db_path, timeout=5)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cur = conn.execute(sql, args)
        conn.commit()
        return cur.rowcount


def query_sync(sql: str, args: tuple = ()) -> list[tuple]:
    """The rows of sql with args, read like execute_sync writes (a connection of its own, for a worker thread), as tuples."""
    with closing(sqlite3.connect(settings.db_path, timeout=5)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        return conn.execute(sql, args).fetchall()


async def migrate(conn) -> None:
    """Legt fehlende Spalten aus ADDED_COLUMNS per ALTER TABLE ... ADD COLUMN an, je Spalte per PRAGMA table_info abgesichert.

    Idempotent: eine vorhandene Spalte bleibt unangetastet (kein Fehler, keine Werte zuruecksetzen), ein zweiter Lauf aendert nichts,
    und ein frueher abgebrochener Lauf wird beim naechsten Aufruf zu Ende gefuehrt. Laeuft nach executescript(SCHEMA) auf derselben
    Connection und committet nicht selbst (das macht init_db). Die Zeilen von table_info werden per Index gelesen, damit es mit und
    ohne row_factory geht. Gegen zwei gleichzeitig startende Prozesse ist die Pruefung nicht gesichert, dafuer gilt die
    Single-Worker-Invariante (siehe main.py)."""
    have: dict[str, set[str]] = {}
    for table, column, definition in ADDED_COLUMNS:
        if table not in have:
            async with conn.execute(f"PRAGMA table_info({table})") as cur:
                have[table] = {row[1] for row in await cur.fetchall()}    # Zeile: (cid, name, type, notnull, dflt_value, pk)
        if column not in have[table]:
            await conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            have[table].add(column)


# A session token as the sessions table keeps it since F4: token_hash, 64 lower-case hex digits. A raw token of before
# (secrets.token_urlsafe(32), 43 characters) never looks like this.
_HASHED_TOKEN = re.compile(r"[0-9a-f]{64}")


def token_hash(token: str) -> str:
    """What the sessions table stores in place of a session token: its SHA-256 as 64 hex digits (F4). A copy of the database then
    holds no value a browser could send as the cookie. The one definition: auth imports it (also for api_tokens.token_hash, Phase
    4c: no value a script could send as its API token either), hash_legacy_session_tokens uses it for the rows of before."""
    return hashlib.sha256(token.encode()).hexdigest()


async def hash_legacy_session_tokens(conn) -> int:
    """Replaces every raw session token of a release before F4 by its token_hash, so its browser stays signed in; returns how many it
    replaced. Idempotent: a stored hash is never hashed again, also after a rollback to an older image and a new update (the
    sessions of the older image are raw again). Does not commit (init_db does), works with and without row_factory."""
    async with conn.execute("SELECT token FROM sessions") as cur:
        raw = [row[0] for row in await cur.fetchall() if not _HASHED_TOKEN.fullmatch(row[0])]
    await conn.executemany("UPDATE sessions SET token = ? WHERE token = ?", [(token_hash(t), t) for t in raw])
    return len(raw)


async def init_db():
    async with db() as conn:
        await conn.executescript(SCHEMA)
        await migrate(conn)
        await hash_legacy_session_tokens(conn)
        await conn.commit()


async def get_setting(key: str, default: str | None = None) -> str | None:
    async with db() as conn:
        async with conn.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
    return row["value"] if row else default


async def set_setting(key: str, value: str | None):
    async with db() as conn:
        await conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        await conn.commit()


async def read_settings(conn, keys: Iterable[str]) -> dict[str, str | None]:
    """The value of each settings key in keys (None without a row), read on conn: inside the caller's transaction, if one is open."""
    keys = list(keys)
    if not keys:
        return {}
    async with conn.execute(f"SELECT key, value FROM settings WHERE key IN ({', '.join('?' * len(keys))})", keys) as cur:
        found = {row[0]: row[1] for row in await cur.fetchall()}
    return {k: found.get(k) for k in keys}


async def load_settings(keys: Iterable[str]) -> dict[str, str | None]:
    """The value of each settings key in keys (None without a row), on a connection of its own and in one SELECT (read_settings): one
    state of the table, so a reader that takes a destination and its secret from it never pairs one with the other's old value while a
    settings PUT commits (F2)."""
    async with db() as conn:
        return await read_settings(conn, keys)


async def write_settings(conn, items: dict[str, str | None]) -> None:
    """Stores each key → value of items on conn, without a commit: the caller commits (or not) its transaction as a whole."""
    await conn.executemany("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                           list(items.items()))


# The API token of the running request (Phase 4c, Task 2): (user name, label of the token, auth.token_label), set by
# auth.current_user on the bearer path, None (the default) for a session. audit() reads it, so every entry of a request made with a
# token names the token without a parameter at each call - the change_* entry of a change it started too, since asyncio copies the
# context into the tasks the request spawns. A job of the scheduler runs in the context of whoever woke the scheduler last
# (APScheduler wakes itself through call_soon_threadsafe / call_later, which copy the caller's context - a request with an API token
# that adds a job, for instance), so every job that writes entries with a user name sets the context itself (Task 5 confirm.watch,
# Task 7 bulk.run).
AUDIT_TOKEN: contextvars.ContextVar[tuple[str, str] | None] = contextvars.ContextVar("AUDIT_TOKEN", default=None)


async def audit(username: str | None, action: str, target: str = "", detail: str = "", *, role: str | None):
    """One audit entry. role is required as a keyword, so no call can forget it (tests/test_permissions.py checks every call): the
    role of the request (user["role"]), of the new session for a login, of whoever started a change for its change_* entry, None
    for a failed login. The entry names the API token of AUDIT_TOKEN (audit.token) when its user name is the context's, the case
    aside; an entry of anyone else, and one without a user (approval_expired), never names a token."""
    via = AUDIT_TOKEN.get()
    token = via[1] if via and username is not None and username.casefold() == via[0].casefold() else None
    async with db() as conn:
        await conn.execute(
            "INSERT INTO audit(username, action, target, detail, role, token) VALUES(?, ?, ?, ?, ?, ?)",
            (username, action, target, detail, role, token),
        )
        await conn.commit()
