"""The changes API: plan a port change, a RADIUS preparation, a revert or a save (choosing SSH or SNMP), apply it as a background task
of changes.run_change, and list the changes. Split from main.py (Phase 3, Task 11), the code as it was. With the four-eyes principle
on (Phase 4a, Task 6) an expert-mode change is not applied here but requested (api_approvals), from the same checked plan."""
import asyncio
import json
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import approvals
import auth
import cfgparse
import changes
import drivers
import poller
import roles
import snmp
import snmpwrite
import sshcli
from api_switches import _row, write_insecurity
from db import db

router = APIRouter()


# ── Aenderungen an Ports (Phase 2) ────────────────────────────────────────────
STATUS_LABEL = {"off": "Aus", "on": "An", "protected": "Protected", "known": "Bekannte Geräte", "radius": "RADIUS"}
# Portnamen auf dem SSH-Weg: ProCurve, streng, denn sie stehen in den CLI-Zeilen.
PORT_RE = re.compile(r"^[A-Za-z0-9/]{1,12}$")
# Portnamen auf dem SNMP-Weg: die jedes Herstellers (Gi1/0/1, ge-0/0/1, 1/1/1, Port-channel1, ...), ohne fuehrendes "-". SNMP setzt sie
# nie in einen Befehl ein (es schreibt auf ifIndex / Bridge-Port); der Port muss ausserdem im Live-Read stehen.
SNMP_PORT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$")
# Die Felder eines Ports, die der SSH-Weg plant (cfgparse.port_state). Ein before mit anderen (etwa pvid, R21, aus einer SNMP-Aenderung)
# nimmt er nicht zurueck.
SSH_FIELDS = frozenset(cfgparse.port_state({}, ""))
STALE = "Die Vorschau ist veraltet, bitte neu laden"
# A disabled switch gets no change in any mode (/plan and /apply): "Aktiv" means polled and backed up, the views do not show it
DISABLED = "Switch ist deaktiviert – Änderungen erst nach dem Aktivieren (Zugang bearbeiten)"
SSH_NEEDED = "Für Änderungen braucht der Switch einen SSH-Zugang (Zugang bearbeiten)"
NO_SSH = "für diesen Switch ist kein SSH-Zugang hinterlegt (Zugang bearbeiten)"
# /apply of a change that needs a four-eyes approval (approvals.needs_approval): it is requested instead (POST /api/approvals)
APPROVAL_NEEDED = "Diese Änderung braucht eine Freigabe (Vier-Augen-Prinzip): bitte „Freigabe anfordern“"
_tasks: set = set()


class PortChange(BaseModel):
    # "on" (R43): nur einschalten, 802.1X / MAC-Anmeldung unveraendert (changes.STATUS_ON); geht auf jedem Treiber, auch per SNMP
    status: str | None = Field(default=None, pattern=r"^(off|on|protected|known|radius)$")
    untagged: str | None = Field(default=None, pattern=r"^\d{1,4}$")
    tagged_add: list[str] = Field(default_factory=list, max_length=64)
    tagged_remove: list[str] = Field(default_factory=list, max_length=64)
    name: str | None = Field(default=None, max_length=64)
    limit: int | None = Field(default=None, ge=1, le=32)
    guest: str | None = Field(default=None, pattern=r"^\d{0,4}$")
    # PoE an (true) / aus (false), nur per SNMP (R30). strict: nur JSON true / false, kein "yes", 1 oder "off", das jemand anders meinen kann
    poe: bool | None = Field(default=None, strict=True)


class PlanIn(BaseModel):
    mode: str = Field(default="ports", pattern=r"^(ports|prepare|revert|save)$")
    ports: list[str] = Field(default_factory=list, max_length=200)
    change: PortChange = Field(default_factory=PortChange)
    expert: bool = False
    of: int | None = None
    token: str | None = Field(default=None, max_length=32)
    # Der Schreibweg der Vorschau (die Antwort von /plan nennt ihn), von /apply mitgeschickt: dann plant _make_plan genau so oder lehnt
    # ab, nie still ueber den anderen Weg. Ohne ihn waehlt _make_plan selbst; /plan beachtet ihn nie, die Vorschau waehlt immer (R28).
    mechanism: str | None = Field(default=None, pattern=r"^(ssh|snmp)$")


def _port_list(ports: list[str]) -> str:
    """Die Ports fuer eine Zusammenfassung: ProCurve-Namen zusammengefasst (1-3,7,Trk1); Namen anderer Hersteller (Gi1/0/1, ge-0/0/1,
    ...), an denen cfgparse.compress_ports scheitert, natuerlich sortiert und mit Komma."""
    try:
        return cfgparse.compress_ports(ports)
    except ValueError:
        return ", ".join(sorted(set(ports), key=snmpwrite.port_order))


def _listing(items: list[str]) -> str:
    """["a"] -> "a", ["a", "b", "c"] -> "a, b und c"."""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " und " + items[-1]


def _summary(body: PlanIn) -> str:
    c, parts = body.change, []
    if c.status:
        parts.append(STATUS_LABEL[c.status])
    if c.untagged:
        parts.append(f"VLAN {c.untagged}")
    if c.tagged_add:
        parts.append("getaggt +" + ",".join(c.tagged_add))
    if c.tagged_remove:
        parts.append("getaggt −" + ",".join(c.tagged_remove))
    if c.name is not None:
        parts.append(f"Name {c.name}" if c.name else "Name entfernt")
    if c.limit:
        parts.append(f"{c.limit} Geräte/Port")
    if c.guest is not None:
        parts.append(f"Gast-VLAN {c.guest}" if c.guest else "ohne Gast-VLAN")
    if c.poe is not None:
        parts.append("PoE an" if c.poe else "PoE aus")
    return f"Port {_port_list(body.ports)}: " + (", ".join(parts) or "–")


# ── Schreibweg waehlen: SSH-CLI oder SNMP ─────────────────────────────────────────────────────────────────────────────────────────────
# Fixiert beim Planen, vor dem ersten Schreibzugriff, nie mitten im Ausfuehren (Spec §5, Q5); plan["mechanism"] nennt ihn.
def needed_ops(body: PlanIn) -> set[str]:
    """Die SNMP-Faehigkeiten des Treibers (drivers.can), die die Anfrage per SNMP braucht: VLANs snmp_vlan, jeder Zustand snmp_admin
    ("Aus" schaltet den Port ab, jeder andere ein), ein Name snmp_name, PoE snmp_poe. Was per SNMP gar nicht geht (802.1X /
    MAC-Anmeldung, Limit, Gast-VLAN), prueft _cli_only."""
    c, ops = body.change, set()
    if c.untagged is not None or c.tagged_add or c.tagged_remove:
        ops.add("snmp_vlan")
    if c.status is not None:
        ops.add("snmp_admin")
    if c.name is not None:
        ops.add("snmp_name")
    if c.poe is not None:
        ops.add("snmp_poe")
    return ops


def _cli_only(body: PlanIn, driver: drivers.Driver) -> str | None:
    """Warum die Anfrage nur ueber die SSH-CLI geht (sonst None). 802.1X / MAC-Anmeldung kennt der SNMP-Weg nicht: read_cfg zeigt sie
    immer aus, render_ops schreibt sie nie; plan_ports plante davon per SNMP still nichts. Darum auch "Protected" nicht auf einem
    Treiber mit NAC: es heisst Anmeldung aus, per SNMP schaltete es nur den Port ein. Eine RADIUS-Vorbereitung ist reine CLI."""
    c, parts = body.change, []
    if body.mode == "prepare":
        parts.append("RADIUS vorbereiten")
    if c.status in ("known", "radius"):
        parts.append(f"Zustand „{STATUS_LABEL[c.status]}“")
    elif c.status == "protected" and drivers.can(driver, "nac"):
        parts.append("Zustand „Protected“ (802.1X/MAC-Anmeldung ist per SNMP weder lesbar noch abschaltbar)")
    if c.limit is not None:
        parts.append("Geräte pro Port")
    if c.guest is not None:
        parts.append("Gast-VLAN")
    if not parts:
        return None
    return f"{_listing(parts)} {'geht' if len(parts) == 1 else 'gehen'} nur mit SSH/ProCurve, nicht per SNMP"


def _snmp_unwritable(row, driver: drivers.Driver, ops: set[str]) -> str | None:
    """Warum der SNMP-Weg hier nicht schreiben kann (sonst None): dem Treiber fehlt eine der Faehigkeiten ops, oder es gibt keine
    Schreib-Identitaet; deren Grund (SNMP-Schreiben aus, keine Zugangsdaten, Community public, ...) kommt allein aus
    poller.creds_of(row, write=True)."""
    missing = sorted(op for op in ops if not drivers.can(driver, op))
    if missing:
        labels = [snmpwrite._CAP_LABEL.get(op, op) for op in missing]    # dieselben Namen wie in snmpwrite.snmp_block_reason
        return f"Treiber {driver.name} kann {_listing(labels)} nicht per SNMP schreiben"
    try:
        poller.creds_of(row, write=True)
    except snmp.SnmpError as e:
        return str(e)
    return None


def _snmp_refusal(row, driver: drivers.Driver, body: PlanIn) -> tuple[int, str] | None:
    """Warum die Anfrage nicht per SNMP gehen kann: (409, Grund), wenn sie etwas will, das nur die CLI kann; (422, Grund), wenn der
    SNMP-Weg nicht schreiben kann; sonst None."""
    reason = _cli_only(body, driver)
    if reason:
        return 409, reason
    reason = _snmp_unwritable(row, driver, needed_ops(body))
    return (422, reason) if reason else None


def _ssh_refusal(row, driver: drivers.Driver) -> str | None:
    """Warum der SSH-CLI-Weg fuer diesen Switch nicht geht (sonst None)."""
    if not drivers.can(driver, "cli"):
        return f"Treiber {driver.name} hat keine SSH-CLI"
    if not row["ssh_user"] or not row["ssh_pass"]:
        return NO_SSH
    return None


async def _choose_mechanism(row, driver: drivers.Driver, body: PlanIn) -> tuple[str, dict | None, str | None]:
    """Der Schreibweg einer neuen Aenderung (mode ports oder prepare): ("ssh", cfg aus der running-config, None) oder ("snmp", None,
    ssh_error), ssh_error der Fehler des SSH-Reads, fuer den SNMP einspringt (sonst None); sonst HTTPException.
      1. Ein mitgeschickter mechanism (nur von /apply, nach seiner Vorschau; /plan reicht keinen weiter, R28) gilt genau so, wenn er
         noch geht, sonst 409 STALE: nie still der andere Weg. Was nur die CLI kann, lehnt auch ein mitgeschicktes "snmp" mit seinem
         eigenen Grund ab.
      2. Treiber mit CLI und SSH-Zugang: SSH, das Lesen der Konfiguration (changes.fresh_cfg) ist der Pre-Flight. Scheitert es, geht die
         Aenderung per SNMP, wenn sie dort geht (mit Hinweis), sonst 502 wie bisher, mit dem Grund, warum SNMP nicht geht. If the read
         was refused for the switch's host key (changes.HostKeyRefused, Phase 2 F-b), SNMP takes over only with an SNMPv3 authPriv
         write identity (poller.write_authpriv), otherwise 502: whoever answers at the address may be an attacker, and a v2c community
         or v3 without privacy would go to it in the clear. A request SNMP cannot take anyway keeps the 502 of before.
      3. Sonst SNMP, wenn die Anfrage dort geht, sonst 409 / 422 mit dem Grund (_snmp_refusal), bei einem Treiber mit CLI (dann fehlt
         der SSH-Zugang) hinter der Meldung von bisher (SSH_NEEDED).
    PoE (R30) geht bei jedem Treiber nur per SNMP, auch bei ProCurve mit SSH: eine Port-Aenderung mit PoE geht als Ganzes per SNMP (u, t,
    an / aus und Name kann SNMP auch), ohne SSH-Read, wenn sie dort geht; sonst 422 "PoE erfordert SNMP-Schreibzugriff (Grund)", oder 409,
    wenn sie dazu etwas will, das nur die CLI kann. Ein mitgeschicktes "ssh" mit PoE: 409 STALE (diese Vorschau gab es nie)."""
    ssh_refusal = _ssh_refusal(row, driver)
    poe = body.mode == "ports" and body.change.poe is not None
    if body.mechanism == "ssh":
        if poe:
            raise HTTPException(409, f"{STALE} (PoE geht nur per SNMP)")
        if ssh_refusal:
            raise HTTPException(409, f"{STALE} ({ssh_refusal})")
        try:
            return "ssh", await changes.fresh_cfg(row["id"]), None
        except Exception as e:  # noqa: BLE001
            raise HTTPException(409, f"{STALE} (Konfiguration per SSH nicht lesbar: {e})")
    if body.mechanism == "snmp":
        reason = _cli_only(body, driver)
        if reason:
            raise HTTPException(409, reason)
        reason = _snmp_unwritable(row, driver, needed_ops(body))
        if reason:
            raise HTTPException(409, f"{STALE} ({reason})")
        return "snmp", None, None
    if poe:
        refusal = _snmp_refusal(row, driver, body)
        if refusal and refusal[0] == 409:
            raise HTTPException(409, f"{refusal[1]}. PoE geht nur per SNMP: bitte getrennt ändern")
        if refusal:
            raise HTTPException(422, f"PoE erfordert SNMP-Schreibzugriff ({refusal[1]})")
        return "snmp", None, None
    if not ssh_refusal:
        try:
            return "ssh", await changes.fresh_cfg(row["id"]), None
        except Exception as e:  # noqa: BLE001
            error = str(e) or type(e).__name__    # nie leer: ein leerer ssh_error hiesse sonst "kein SSH-Fehler", SNMP spraenge still ein
            refusal = _snmp_refusal(row, driver, body)
            if refusal:
                raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {error} (per SNMP geht es auch nicht: {refusal[1]})")
            if isinstance(e, changes.HostKeyRefused) and not poller.write_authpriv(row):
                # one period between the host key message (it ends with one) and the reason
                raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {error.removesuffix('.')}. Kein Ausweichen auf SNMP: "
                                         "der Schlüssel kann von einem Angreifer stammen, und SNMP schriebe hier nicht mit SNMPv3 authPriv.")
            return "snmp", None, error
    refusal = _snmp_refusal(row, driver, body)
    if refusal:
        status, reason = refusal
        if drivers.can(driver, "cli"):
            reason = f"{SSH_NEEDED}. Per SNMP geht es auch nicht: {reason}"
        raise HTTPException(status, reason)
    return "snmp", None, None


async def _read_snmp(row, driver: drivers.Driver, ssh_error: str | None = None, *, with_poe: bool = False) -> tuple[dict, dict]:
    """Der Live-Read per SNMP (snmpwrite.read_cfg) im Change-Lock des Switches, wie der SSH-Weg seine Konfiguration im selben Lock liest:
    nie mitten in eine laufende Aenderung hinein. with_poe (R34): auch die PoE-Tabellen, fuer eine Aenderung, die PoE beruehrt
    (changes.touches_poe der Anfrage, wie run_change es rechnet). read_cfg faellt geschlossen aus, das wird 502 mit dem Grund; springt
    SNMP fuer einen gescheiterten SSH-Read ein (ssh_error), nennt die Meldung beide Fehler."""
    try:
        async with sshcli.lock(row["id"]):
            return await snmpwrite.read_cfg(row, driver, with_poe=with_poe)
    except (snmp.SnmpError, OSError) as e:
        if ssh_error is not None:
            raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {ssh_error} (per SNMP auch nicht: {e})")
        raise HTTPException(502, f"Konfiguration des Switches per SNMP nicht lesbar: {e}")


def _check_request(body: PlanIn, port_re: re.Pattern):
    for p in body.ports:
        if not port_re.fullmatch(p):
            raise HTTPException(422, f"Port ungültig: {p}")
    for v in body.change.tagged_add + body.change.tagged_remove:
        if not re.fullmatch(r"\d{1,4}", v):
            raise HTTPException(422, f"VLAN ungültig: {v}")
    # Baseline L7: one VLAN in both lists was planned as "remove" without a word; the UI never sends both for one VLAN
    both = sorted(set(body.change.tagged_add) & set(body.change.tagged_remove), key=int)
    if both:
        raise HTTPException(422, f"VLAN {both[0]} steht in „getaggt hinzufügen“ und „getaggt entfernen“")


async def _inventory(sid: int) -> dict:
    """changes.inventory(sid); its LookupError (the switch is not in the map: disabled since the request began, or gone) is 409
    DISABLED, never a 500."""
    try:
        return await changes.inventory(sid)
    except LookupError:
        raise HTTPException(409, DISABLED)


async def _make_plan(row, body: PlanIn) -> tuple[dict, dict, str, str]:
    """-> (plan, request fuer run_change, kind, summary). plan["mechanism"] ist der Schreibweg, "ssh" oder "snmp"."""
    driver = drivers.driver_for(row)
    if body.mode in ("revert", "save"):
        return await _plan_of_change(row, driver, body)
    mech, cfg, ssh_error = await _choose_mechanism(row, driver, body)
    if mech == "snmp":
        return await _plan_snmp(row, driver, body, ssh_error)
    if body.mode == "prepare":
        plan = changes.plan_prepare(cfg, await changes.radius_settings())
        return plan | {"mechanism": "ssh"}, {}, "prepare", "RADIUS vorbereiten"
    _check_request(body, PORT_RE)
    req = {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}
    try:
        plan = changes.plan_ports(row["firmware"] or "", await _inventory(row["id"]), cfg, req,
                                  radius_server=(await changes.radius_settings())["server"])
    except ValueError as e:
        raise HTTPException(422, str(e))
    return plan, req, "ports", _summary(body)


async def _warn_unsaved(row, driver: drivers.Driver, plan: dict):
    """R42: ein SNMP-SET auf einem Treiber mit snmp_autosave laesst den Switch seine gesamte laufende Konfiguration speichern, auch jede
    per SSH absichtlich nicht gespeicherte Aenderung, die etwas gesendet hat (changes.unsaved_ssh_changes; R48: one that sent nothing
    is not named). Das sagt die Vorschau laut, vor den Hinweisen zu den Ports. Keine Sperre: per SNMP geht es gerade dann, wenn SSH weg
    ist und sich die SSH-Aenderung weder zuruecknehmen noch speichern laesst."""
    if not drivers.can(driver, "snmp_autosave"):
        return
    ids = await changes.unsaved_ssh_changes(row["id"])
    if not ids:
        return
    refs, one = changes.change_refs(ids), len(ids) == 1
    plan["warnings"] = [f"Achtung: {'Änderung' if one else 'Änderungen'} {refs} {'ist' if one else 'sind'} absichtlich nicht gespeichert. Ein "
                        f"SNMP-SET lässt den Switch die gesamte laufende Konfiguration speichern – {refs} {'wäre' if one else 'wären'} danach "
                        f"dauerhaft. Vorher {refs} zurücknehmen oder bewusst speichern.", *plan["warnings"]]


async def _plan_snmp(row, driver: drivers.Driver, body: PlanIn, ssh_error: str | None) -> tuple[dict, dict, str, str]:
    """Eine neue Port-Aenderung per SNMP (_choose_mechanism hat schon abgelehnt, was dort nicht geht): gegen einen Live-Read geplant,
    jeder Port muss in ihm stehen. ssh_error: SNMP springt fuer diesen gescheiterten SSH-Read ein, das sagt eine Warnung vorne."""
    _check_request(body, SNMP_PORT_RE)
    req = {"ports": body.ports, "set": body.change.model_dump(), "expert": body.expert}
    cfg, raw = await _read_snmp(row, driver, ssh_error, with_poe=changes.touches_poe(req))
    missing = [p for p in body.ports if p not in cfg["ports"]]
    if missing:
        raise HTTPException(422, f"Port gibt es auf diesem Switch nicht: {', '.join(missing)}")
    try:
        plan = changes.plan_ports(row["firmware"] or "", await _inventory(row["id"]), cfg, req, mechanism="snmp", driver=driver,
                                  raw=raw)
    except ValueError as e:
        raise HTTPException(422, str(e))
    await _warn_unsaved(row, driver, plan)
    if ssh_error is not None:    # nie still per SNMP (L19)
        plan["warnings"] = [f"SSH nicht verfügbar ({ssh_error}), die Änderung geht per SNMP", *plan["warnings"]]
    return plan, req, "ports", _summary(body)


async def _plan_of_change(row, driver: drivers.Driver, body: PlanIn) -> tuple[dict, dict, str, str]:
    """Rueckgaengig (revert) und Speichern (save) einer Aenderung, auf dem Weg der Aenderung selbst (changes.mechanism; NULL heisst ssh,
    eine Zeile von vor der Spalte) und nie auf einem anderen: before einer SNMP-Aenderung haelt etwa die PVID (R21), die der SSH-Weg
    nicht kennt. Ein unbekannter Weg, und ein mitgeschickter mechanism (/apply), der nicht dieser ist: 409."""
    async with db() as conn:
        async with conn.execute("SELECT * FROM changes WHERE id = ? AND switch_id = ?", (body.of, row["id"])) as cur:
            ch = await cur.fetchone()
    if not ch:
        raise HTTPException(404, "Änderung nicht gefunden")
    mech = ch["mechanism"] or "ssh"
    if mech not in ("ssh", "snmp"):  # im Zweifel gesperrt, nie still per SSH
        raise HTTPException(409, f"Änderung #{ch['id']} hat einen unbekannten Schreibweg ({mech})")
    if body.mechanism and body.mechanism != mech:
        raise HTTPException(409, STALE)
    if body.mode == "save":
        return await _plan_save(row, driver, ch, mech)
    return await _plan_revert(row, driver, ch, mech)


def _refuse_ssh_way(row, driver: drivers.Driver, ch, verb: str):
    """409, wenn sich die per SSH gemachte Aenderung ch jetzt nicht per SSH `verb` laesst: ohne SSH-Zugang mit der Meldung von bisher
    vorne (SSH_NEEDED), sonst mit dem Grund (der Treiber hat keine CLI)."""
    reason = _ssh_refusal(row, driver)
    done = f"Änderung #{ch['id']} lief per SSH und lässt sich nur per SSH {verb}"
    if reason == NO_SSH:
        raise HTTPException(409, f"{SSH_NEEDED}. {done}")
    if reason:
        raise HTTPException(409, f"{done}: {reason}")


async def _plan_save(row, driver: drivers.Driver, ch, mech: str) -> tuple[dict, dict, str, str]:
    """Speichern (write memory) nach einer Aenderung, die unklar oder fehlgeschlagen endete; nur per SSH, und es plant nie etwas. Eine
    SNMP-Aenderung speichert ein Treiber mit snmp_autosave selbst; bei jedem anderen geht Speichern per SNMP nicht, das bleibt dem
    Switch (R26). Beides vor der Pruefung des Status: eine SNMP-Aenderung, die ok endete, ist dort nicht unbedingt gespeichert. A
    change that sent nothing (changes.may_have_sent) has nothing to save either: the same 409. The rules of changes.actions_of."""
    if mech == "snmp":
        if drivers.can(driver, "snmp_autosave"):
            raise HTTPException(409, "SNMP-Änderungen werden automatisch gespeichert")
        raise HTTPException(409, "Per SNMP nicht speicherbar – bitte am Switch speichern (z. B. write memory / copy running-config startup-config)")
    if ch["status"] not in ("unclear", "failed") or ch["saved"] or not changes.may_have_sent(ch):    # sent nothing: nothing to save
        raise HTTPException(409, "Diese Änderung muss nicht gespeichert werden")
    _refuse_ssh_way(row, driver, ch, "speichern")
    try:
        await changes.fresh_cfg(row["id"])  # der Pre-Flight wie bisher
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {e}")
    plan = {"commands": [], "shown": [], "blocked": [], "mechanism": "ssh",
            "warnings": ["Speichert den aktuellen Stand des Switches dauerhaft (write memory)."]}
    return plan, {"of": ch["id"]}, "save", f"Speichern nach #{ch['id']}"


async def _plan_revert(row, driver: drivers.Driver, ch, mech: str) -> tuple[dict, dict, str, str]:
    """Rueckgaengig: plan_ports mit desired = before der Aenderung gegen einen frischen Read auf ihrem Weg mech. Geht der gerade nicht,
    409 mit dem Grund; per SSH auch, wenn before Felder hat, die der SSH-Weg nicht kennt (SSH_FIELDS; der Planer liefe sonst in einen
    KeyError). Was ein Treiber per SNMP nicht schreiben kann, sperrt plan_ports je Port (snmpwrite.snmp_block_reason). A change that
    sent nothing (changes.may_have_sent, e.g. failed before connecting) has nothing to take back: 409, before any read. The rules of
    changes.actions_of."""
    if ch["kind"] != "ports" or ch["reverted_by"] or ch["status"] in ("queued", "running", "aborted"):
        raise HTTPException(409, "Diese Änderung lässt sich nicht zurücknehmen")
    if not changes.may_have_sent(ch):    # e.g. failed before connecting: the switch is as it was
        raise HTTPException(409, f"Änderung #{ch['id']} hat nichts an den Switch gesendet – es gibt nichts zurückzunehmen")
    req = {"desired": json.loads(ch["before"] or "{}"), "expert": bool(ch["expert"])}
    if mech == "snmp":
        reason = _snmp_unwritable(row, driver, set())
        if reason:
            raise HTTPException(409, f"Änderung #{ch['id']} lief per SNMP und lässt sich nur per SNMP zurücknehmen: {reason}")
        cfg, raw = await _read_snmp(row, driver, with_poe=changes.touches_poe(req))    # R34: before mit poe liest PoE mit
        way = {"mechanism": "snmp", "driver": driver, "raw": raw}    # die Schluesselwoerter von plan_ports fuer diesen Weg
    else:
        _refuse_ssh_way(row, driver, ch, "zurücknehmen")
        odd = sorted({str(k) for d in req["desired"].values() for k in d} - SSH_FIELDS)
        if odd:
            raise HTTPException(409, f"Änderung #{ch['id']} lässt sich per SSH nicht zurücknehmen: ihr Vorher-Stand enthält Felder, die der "
                                     f"SSH-Weg nicht kennt ({', '.join(odd)})")
        try:
            cfg = await changes.fresh_cfg(row["id"])
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"Konfiguration des Switches nicht lesbar: {e}")
        way = {"radius_server": (await changes.radius_settings())["server"]}    # a NAC revert needs the configured server, like run_change
    try:
        plan = changes.plan_ports(row["firmware"] or "", await _inventory(row["id"]), cfg, req, **way)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if mech == "snmp":
        await _warn_unsaved(row, driver, plan)
    return plan, req, "ports", f"Rückgängig #{ch['id']}: {ch['summary']}"


async def _enabled_row(sid: int):
    """The switches row of sid for a change (_row), 409 DISABLED for a disabled switch: in every mode, before anything is read."""
    row = await _row(sid)
    if not row["enabled"]:
        raise HTTPException(409, DISABLED)
    return row


async def _mode_rights(user: dict, row, body: PlanIn, four_eyes: bool) -> None:
    """The rights of a /plan, /apply or approval request beyond the route's minimum (Ändern), right after _enabled_row. First the
    zone: a user with a zone scope changes only switches of their zones (roles.zone_allows, Task 5), in every mode. Then the mode:
    preparing RADIUS is Admin (it sends the RADIUS secret, Sicherheit Phase 2 T2-R1); the expert mode (uplinks, trunks) is Freigeben
    without the four-eyes principle (four_eyes, approvals.policy) and Ändern with it, since then it only gets as far as a request
    that a second person with Freigeben approves (/apply refuses it, APPROVAL_NEEDED); taking back a change made in expert mode,
    which goes over the same uplinks, is Freigeben either way. Saving and every other revert stay Ändern. A revert of a change that is
    not at this switch is left to _make_plan (404 as before)."""
    if not roles.zone_allows(user, row["zone"]):
        raise HTTPException(403, roles.zone_denial(row["zone"], user["zones"]))
    role = user["role"]
    if body.mode == "prepare" and not roles.at_least(role, roles.ADMIN):
        raise HTTPException(403, roles.denial(roles.ADMIN, role, "„RADIUS vorbereiten“"))
    if body.mode == "ports" and body.expert and not four_eyes and not roles.at_least(role, roles.FREIGEBEN):
        raise HTTPException(403, roles.denial(roles.FREIGEBEN, role, "Der Expertenmodus"))
    if body.mode == "revert" and not roles.at_least(role, roles.FREIGEBEN):
        async with db() as conn:
            async with conn.execute("SELECT expert FROM changes WHERE id = ? AND switch_id = ?", (body.of, row["id"])) as cur:
                ch = await cur.fetchone()
        if ch and ch["expert"]:
            raise HTTPException(403, roles.denial(roles.FREIGEBEN, role, "Eine Änderung im Expertenmodus zurückzunehmen"))


class PreviewOutdated(HTTPException):
    """409: the plan of now is not the one of the preview (a port is blocked now, or the commands differ from the token's)."""

    def __init__(self, detail: str):
        super().__init__(409, detail)


def preview_answer(row, plan: dict, kind: str, summary: str) -> dict:
    """The preview of plan as /plan answers it (and a four-eyes request stores it, POST /api/approvals): what goes out, the warnings
    and blocked ports, before and desired, the token of the commands, and what the preview says about the SNMP way, as the server sees
    it at plan time (Phase 5): whether the driver saves an SNMP change by itself (R26), and how a SET would go out spoofable ("v2c" /
    "v3", None when authenticated or not over SNMP)."""
    return {"kind": kind, "summary": summary, "mechanism": plan["mechanism"], "commands": plan["shown"], "warnings": plan.get("warnings", []),
            "blocked": plan["blocked"], "before": plan.get("before", {}), "desired": plan.get("desired", {}),
            "token": changes.cmd_token(plan["shown"]), "autosave": drivers.can(drivers.driver_for(row), "snmp_autosave"),
            "insecure_write": write_insecurity(row) if plan["mechanism"] == "snmp" else None}


async def checked_plan(row, body: PlanIn) -> tuple[dict, dict, str, str]:
    """_make_plan of body, held against the preview body.token stands for: a blocked port is PreviewOutdated „Nicht ausführbar: …“,
    other commands than the preview's PreviewOutdated(STALE), nothing to change (unless a save) 422. The checks of /apply, and of a
    four-eyes request (api_approvals) before it stores its preview."""
    plan, req, kind, summary = await _make_plan(row, body)
    if plan["blocked"]:
        raise PreviewOutdated("Nicht ausführbar: " + "; ".join(f"{b['port']}: {b['reason']}" for b in plan["blocked"]))
    if body.token != changes.cmd_token(plan["shown"]):
        raise PreviewOutdated(STALE)
    if not plan["shown"] and kind != "save":
        raise HTTPException(422, "Es gibt nichts zu ändern")
    return plan, req, kind, summary


@router.post("/api/switches/{sid}/plan")
async def plan_change(sid: int, body: PlanIn, user=Depends(auth.require(roles.AENDERN))):
    """The preview, and whether the change needs a four-eyes approval (approval: then it is requested, not applied)."""
    row = await _enabled_row(sid)
    four_eyes = (await approvals.policy())["four_eyes"]
    await _mode_rights(user, row, body, four_eyes)
    # Die Vorschau waehlt den Schreibweg immer selbst (R28): einen mitgeschickten mechanism beachtet nur /apply.
    plan, _, kind, summary = await _make_plan(row, body.model_copy(update={"mechanism": None}))
    return preview_answer(row, plan, kind, summary) | {"approval": approvals.needs_approval(approvals.PORT_CHANGE, body.model_dump(), four_eyes)}


@router.post("/api/switches/{sid}/apply")
async def apply_change(sid: int, body: PlanIn, user=Depends(auth.require(roles.AENDERN))):
    """A change that needs a four-eyes approval is refused first (409 APPROVAL_NEEDED), whoever sends it. The early check for a queued
    or running change spares the read and the plan; the binding one is changes.create_change's, in one transaction with the INSERT
    (two requests can both pass this one while they plan): either way 409 changes.BUSY."""
    row = await _enabled_row(sid)
    four_eyes = (await approvals.policy())["four_eyes"]
    await _mode_rights(user, row, body, four_eyes)
    if approvals.needs_approval(approvals.PORT_CHANGE, body.model_dump(), four_eyes):
        raise HTTPException(409, APPROVAL_NEEDED)
    async with db() as conn:
        async with conn.execute("SELECT id FROM changes WHERE switch_id = ? AND status IN ('queued', 'running')", (sid,)) as cur:
            if await cur.fetchone():
                raise HTTPException(409, changes.BUSY)
    plan, req, kind, summary = await checked_plan(row, body)
    # A revert marks the change it takes back (reverted_by) only when it ends ok (changes._mark_reverted), not here
    try:
        cid = await changes.create_change(sid, user["username"], kind, summary, req, plan,
                                          revert_of=body.of if body.mode == "revert" else None, role=user["role"])
    except changes.Busy:
        raise HTTPException(409, changes.BUSY)
    t = asyncio.create_task(changes.run_change(cid))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return {"id": cid}


def _change_out(r, secrets: list[str]) -> dict:
    """A changes row as the API serves it: error, output and the text of every step masked again (cfgparse.mask_secrets with
    secrets, changes._secrets_of of its switch). A row from before Phase 2 was stored unmasked; on one that run_change stored masked
    the masking changes nothing. The row in the database stays as it is (E26, as for backups). Plus can_revert and can_save
    (changes.actions_of): the UI offers "Rückgängig" and "Trotzdem speichern" by these flags alone."""
    d = dict(r) | changes.actions_of(r)
    for k in ("ports", "desired", "before", "commands", "steps"):
        d[k] = json.loads(d[k] or ("[]" if k in ("ports", "commands", "steps") else "{}"))
    d.pop("request", None)
    for k in ("error", "output"):
        if d[k]:
            d[k] = cfgparse.mask_secrets(d[k], secrets)
    d["steps"] = [[s[0], cfgparse.mask_secrets(s[1], secrets), *s[2:]] if isinstance(s, list) and len(s) > 1 and isinstance(s[1], str)
                  else s for s in d["steps"]]
    return d


async def _changes_out(conn, rows) -> list[dict]:
    """_change_out of each row, with the RADIUS key read once and the secrets of each switch once."""
    rs = await changes.radius_settings()
    secrets: dict[int, list[str]] = {}
    for r in rows:
        if r["switch_id"] not in secrets:
            async with conn.execute("SELECT * FROM switches WHERE id = ?", (r["switch_id"],)) as cur:
                secrets[r["switch_id"]] = changes._secrets_of(await cur.fetchone(), rs)
    return [_change_out(r, secrets[r["switch_id"]]) for r in rows]


@router.get("/api/changes")
async def list_changes(switch_id: int | None = None, limit: int = 100, user=Depends(auth.require(roles.LESEN))):
    q, args = "SELECT c.*, s.name AS switch_name FROM changes c JOIN switches s ON s.id = c.switch_id", []
    if switch_id:
        q += " WHERE c.switch_id = ?"
        args.append(switch_id)
    q += " ORDER BY c.id DESC LIMIT ?"
    args.append(max(1, min(limit, 500)))
    async with db() as conn:
        async with conn.execute(q, args) as cur:
            rows = await cur.fetchall()
        return await _changes_out(conn, rows)


@router.get("/api/changes/{cid}")
async def get_change(cid: int, user=Depends(auth.require(roles.LESEN))):
    async with db() as conn:
        async with conn.execute("SELECT c.*, s.name AS switch_name FROM changes c JOIN switches s ON s.id = c.switch_id WHERE c.id = ?", (cid,)) as cur:
            r = await cur.fetchone()
        if not r:
            raise HTTPException(404, "Änderung nicht gefunden")
        return (await _changes_out(conn, [r]))[0]
