"use strict";

  /* ── Änderung mit Bestätigung (Phase 4c): the choice "Mit Bestätigung ausführen" in the preview (confirmOptionHtml, read at the
     click by confirmMinutes: previewChange sends confirm_minutes with "Ausführen" and "Freigabe anfordern"), the banner of a change
     that waits for it (pendingHtml, in runProgress), and "Bestätigen" (confirmChange, offered by mayConfirm in the progress and in the
     change list of sv-switch.js). Only the preview knows the write way, so only it offers the choice; off by default. ── */
  // The minutes the preview offers; the server takes 1-30 (api_changes.CONFIRM_MAX) and names the one chosen first (default_minutes)
  const CONFIRM_CHOICES = [2, 5, 10, 15, 30];
  // The choice under the preview r (a /plan answer) of payload: only for a port change and only where r names confirm (a server from
  // before the update does not). Where it is possible a checkbox with the minutes (the select inside its label, which so names them),
  // else why not as a sentence. Over SNMP (r.mechanism) "Bestätigen" saves nothing (confirm._confirm_snmp), so the choice promises
  // the save only on another way
  const confirmOptionHtml = (r, payload) => {
    if (payload.mode !== "ports" || !r.confirm) return "";
    if (!r.confirm.possible) return `<p class="note" id="p-confirm-why">${esc(sentence(r.confirm.why || ""))}</p>`;
    const opts = CONFIRM_CHOICES.map(m => `<option value="${m}"${m === r.confirm.default_minutes ? " selected" : ""}>${m}</option>`).join("");
    const saves = r.mechanism === "snmp" ? "" : "erst speichern, wenn ich bestätige – ";
    return `<label class="check"><input type="checkbox" id="p-confirm"><span>Mit Bestätigung ausführen: ${saves}ohne Bestätigung nach `
      + `<select id="p-confirm-min" aria-label="Minuten bis zur automatischen Rücknahme">${opts}</select> Minuten automatisch zurücknehmen</span></label>`;
  };
  // The minutes of the preview's choice when it is ticked, else null (no choice shown: null too)
  const confirmMinutes = () => { const box = $("#p-confirm"); return box && box.checked ? Number($("#p-confirm-min").value) : null; };
  // Whether the user may confirm change c (GET /api/changes): it waits, the user has Ändern in the zone of its switch, and the rule of
  // confirm.may_confirm - who started it or approved it (the case aside), else anyone with Freigeben; the server checks it again
  const mayConfirm = c => {
    const me = ((ME && ME.username) || "").toLowerCase();
    return c.status === "pending" && roleOk("aendern") && inZone({ zone: c.switch_zone })
      && (roleOk("freigeben") || (!!me && [c.username, c.approved_by].some(n => !!n && n.toLowerCase() === me)));
  };
  // The banner of change c while it waits: its deadline (confirm_until, UTC) in local time and the minutes left
  // (SVLogic.minutesLeft), or that it ran out (the watch takes it back within 15 s)
  const pendingHtml = c => {
    const left = SVLogic.minutesLeft(c.confirm_until, Date.now());
    return `<div class="banner warn"><span><b>Geprüft und aktiv, aber nicht gespeichert.</b> Bestätigen bis ${esc(fmtTime(c.confirm_until))} `
      + `(${left ? `noch ${SVLogic.plural(left, "Minute", "Minuten")}` : "Frist abgelaufen"}), sonst nimmt SwitchView die Änderung zurück.</span></div>`;
  };
  // "Bestätigen" of change id (POST /api/changes/{id}/confirm): "Bestätigt", or the server's refusal as a message; whether it went
  // through. Over SSH the save runs on (running, then ok or unclear): whoever shows the change asks it on
  async function confirmChange(id) {
    try { await api("POST", `/api/changes/${id}/confirm`); toast("Bestätigt"); return true; } catch (e) { toast(e.message); return false; }
  }
