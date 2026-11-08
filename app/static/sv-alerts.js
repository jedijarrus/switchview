"use strict";

  /* ── Benachrichtigungen, Sicherheitsregeln, Beobachtungsliste (Phase 4b): the settings' cards "Benachrichtigungen" (Admin only:
     its routes are Admin, below it one sentence and no request) and "Sicherheitsregeln" (everyone reads them, an Admin switches the
     built-in ones off and keeps custom ones), and the devices' card "Beobachtungsliste" (Ändern keeps it). renderSettings and
     renderDevices draw the shells and call these. An answer without the fields a card expects draws it empty (the stubs of older
     tests answer every URL with {ok: true, …} or a list), a failed request shows the server's text in its card. ── */
  const ALERT_WAYS = { mail: "Mail", webhook: "Webhook" };
  // The error of a queued message an Admin's switch-off dropped (alerts.SWITCHED_OFF, alerts.drop_queued): no delivery that failed
  const ALERT_SWITCHED_OFF = "Kanal ausgeschaltet";
  const SMTP_SECURITY = [["starttls", "STARTTLS (Port 587)"], ["tls", "TLS (Port 465)"], ["none", "Ohne Verschlüsselung (Port 25, ohne Anmeldung)"]];
  const HOOK_FORMATS = [["teams", "Microsoft Teams (Workflow)"], ["json", "JSON"]];
  const RULE_MODES = [["must_not", "keine Zeile enthält"], ["must", "eine Zeile enthält"]];
  const SECRET_KEPT = "gesetzt – leer lassen = unverändert";
  const choices = (list, cur) => list.map(([v, l]) => `<option value="${esc(v)}"${v === cur ? " selected" : ""}>${esc(l)}</option>`).join("");

  // The card "Benachrichtigungen" of s (GET /api/settings/alerts): the channels mail (SMTP) and webhook, each with the events it
  // sends (s.events: key → text) and its test button, then "Letzte Meldungen" (#a-deliv, bindAlertCard fills it). The two secrets
  // follow the settings' rule: never shown, empty = unchanged, the note of one that does not decrypt beside its field (unreadNote)
  function alertCardHtml(s, admin) {
    const head = `<div class="card-h"><h2>Benachrichtigungen</h2></div>`;
    if (!admin) return head + `<div class="card-b" style="max-width:640px"><p class="note gate">Benachrichtigungen einrichten braucht die Rolle „Admin“.</p></div>`;
    if (!s || !s.events) return head + (s && s.error ? `<div class="empty">${esc(s.error)}</div>` : "");
    const lim = s.limits || {}, on = (id, key) => `<label class="check"><input id="${id}" type="checkbox"${s[key] ? " checked" : ""}>`;
    const boxes = (attr, picked) => `<fieldset class="evs"><legend>Ereignisse</legend>${Object.keys(s.events).map(k => `<label class="check"><input type="checkbox" `
      + `data-${attr}="${esc(k)}"${(picked || []).includes(k) ? " checked" : ""}> ${esc(s.events[k])}</label>`).join("")}</fieldset>`;
    const secret = (id, label, k, set, hint, max) => {
      const note = unreadNote(s, k, id + "-unread"), desc = [hint && id + "-hint", note && id + "-unread"].filter(Boolean).join(" ");
      return `<div class="field"><label for="${id}">${label}</label><input id="${id}" type="password" autocomplete="new-password" placeholder="${set ? SECRET_KEPT : ""}" `
        + `maxlength="${max}"${desc ? ` aria-describedby="${desc}"` : ""}>${hint ? `<span class="hint" id="${id}-hint">${esc(hint)}</span>` : ""}${note}</div>`;
    };
    const text = (id, label, v, extra = "") => `<label class="field"><span>${label}</span><input id="${id}" value="${esc(v)}"${extra} autocomplete="off"></label>`;
    return head + `<div class="card-b" style="display:grid;gap:16px;max-width:640px">
      <p class="note" style="margin:0">SwitchView meldet Ereignisse per Mail und per Webhook (Microsoft Teams oder JSON). Dieselbe Meldung geht innerhalb von ${esc(lim.dedup_minutes)} Minuten einmal hinaus, je Weg höchstens ${esc(lim.cap_per_hour)} in der Stunde.</p>
      <fieldset class="fs"><legend>Mail (SMTP)</legend>${on("a-mail-on", "mail_on")} Mail senden</label>
        <div class="grid2">${text("a-host", "Mailserver", s.smtp_host, ' maxlength="253"')}<label class="field"><span>Port</span><input id="a-port" type="number" min="1" max="65535" value="${esc(s.smtp_port)}"></label></div>
        <p class="note warn" id="a-host-note" style="margin:0" hidden>Neuer Mailserver: Das gespeicherte Kennwort gilt nur für den alten Mailserver. Was du hier nicht neu eingibst, löscht das Speichern.</p>
        <div class="grid2"><label class="field"><span>Verschlüsselung</span><select id="a-sec">${choices(SMTP_SECURITY, s.smtp_security)}</select></label></div>
        ${on("a-mtls", "smtp_verify_tls")} TLS-Zertifikat prüfen</label>
        <div class="grid2">${text("a-user", "Benutzer", s.smtp_user, ' maxlength="200"')}${secret("a-pass", "Kennwort", "smtp_pass", s.smtp_pass_set, "", 200)}</div>
        <div class="grid2">${text("a-from", "Absender", s.mail_from, ' maxlength="254"')}</div>
        <label class="field"><span>Empfänger (eine Adresse je Zeile)</span><textarea id="a-to" rows="3">${esc((s.mail_to || []).join("\n"))}</textarea></label>
        ${boxes("mev", s.mail_events)}<div><button class="btn small" type="button" id="a-mtest">Test-Mail senden</button></div></fieldset>
      <fieldset class="fs"><legend>Webhook</legend>${on("a-hook-on", "hook_on")} Webhook senden</label>
        ${secret("a-url", "Webhook-Adresse", "webhook_url", s.webhook_url_set, s.webhook_target ? `Ziel: ${s.webhook_target}` : "SwitchView zeigt die Adresse nach dem Speichern nie wieder, nur ihr Ziel.", 2000)}
        <div class="grid2"><label class="field"><span>Format</span><select id="a-fmt">${choices(HOOK_FORMATS, s.hook_format)}</select></label></div>
        ${on("a-htls", "hook_verify_tls")} TLS-Zertifikat prüfen</label>
        ${boxes("hev", s.hook_events)}<div><button class="btn small" type="button" id="a-htest">Test senden</button></div></fieldset>
      <p class="note" style="margin:0">Die Test-Knöpfe senden über den gespeicherten Stand: vorher speichern.${s.public_url ? "" : " Ohne PUBLIC_URL enthalten die Meldungen keinen Link zu SwitchView."}</p>
      <div><button class="btn primary" type="button" id="a-save">Benachrichtigungen speichern</button></div></div>
      <div class="card-h sub-h"><h3>Letzte Meldungen</h3><span class="sub">die letzten 20, nicht zugestellte zuerst</span></div><div id="a-deliv"><div class="empty">Lade …</div></div>`;
  }
  // The rows of "Letzte Meldungen" (GET /api/alerts/deliveries): the ones not delivered first, the rest as the server sends them
  // (newest first); the state as a pill, a retry waiting with its attempts so far, the error of one not delivered below it, and a
  // message that came again within the dedup window (repeats, sent once) after its title
  function deliveryRows(rows) {
    const state = r => r.status === "sent" ? `<span class="pill ok">zugestellt</span>`
      : r.status === "queued" ? `<span class="pill neutral">wartet</span>${r.attempts >= 1 ? ` · Versuch ${esc(r.attempts)}` : ""}`
      : r.status === "failed" ? `<span class="pill crit">nicht zugestellt</span>${r.error ? `<span class="cellnote">${esc(r.error)}</span>` : ""}`
      : r.status === "suppressed" ? `<span class="pill neutral">unterdrückt (Obergrenze)</span>` : esc(r.status);
    return [...rows.filter(r => r.status === "failed"), ...rows.filter(r => r.status !== "failed")].map(r => `<tr><td class="num time">${esc(fmtTime(r.created_at))}</td>`
      + `<td>${esc(ALERT_WAYS[r.channel] || r.channel)}</td><td>${esc(r.title)}${r.repeats > 0 ? ` · ${esc(r.repeats)}× wiederholt` : ""}</td><td>${state(r)}</td></tr>`).join("");
  }
  // The card's controls for an Admin: the note of a new mail server, the test buttons (POST /api/alerts/test: the stored channel,
  // the answer as a message), "Benachrichtigungen speichern" (PUT /api/settings/alerts with every field; a secret left empty is null
  // and stays; what the server's 422 would say in English is said here first), then "Letzte Meldungen"
  async function bindAlertCard(s) {
    if (!roleOk("admin") || !s || !s.events) return;
    // A new mail server deletes the stored password unless the same save enters it anew (Phase 2 E8, api_alerts.put_alert_settings)
    const sync = () => syncNote("a-host", "a-host-note", !!s.smtp_pass_set && destTxt($("#a-host").value) !== destTxt(s.smtp_host));
    $("#a-host").addEventListener("input", sync); sync();
    [["a-mtest", "mail"], ["a-htest", "webhook"]].forEach(([id, channel]) => $("#" + id).addEventListener("click", async e => {
      e.target.disabled = true;
      try { const r = await api("POST", "/api/alerts/test", { channel }); toast(r.ok ? "Test gesendet" : `Test fehlgeschlagen: ${r.error}`); } catch (err) { toast(err.message); }
      e.target.disabled = false;
    }));
    $("#a-save").addEventListener("click", async e => {
      const to = SVLogic.splitRecipients($("#a-to").value), port = Number($("#a-port").value.trim() || NaN), url = $("#a-url").value.trim();
      if (to.errors.length) { toast(to.errors[0]); return; }
      if (to.list.length > 20) { toast("Höchstens 20 Empfänger"); return; }
      if (!Number.isInteger(port) || port < 1 || port > 65535) { toast("Port: eine ganze Zahl von 1 bis 65535"); return; }
      const picked = (sel, key) => [...document.querySelectorAll(sel)].filter(b => b.checked).map(b => b.dataset[key]);
      e.target.disabled = true;
      try {
        const r = await api("PUT", "/api/settings/alerts", { mail_on: $("#a-mail-on").checked, smtp_host: $("#a-host").value.trim(), smtp_port: port,
          smtp_security: $("#a-sec").value, smtp_verify_tls: $("#a-mtls").checked, smtp_user: $("#a-user").value.trim(), smtp_pass: $("#a-pass").value || null,
          mail_from: $("#a-from").value.trim(), mail_to: to.list, mail_events: picked("[data-mev]", "mev"), hook_on: $("#a-hook-on").checked,
          webhook_url: url || null, hook_format: $("#a-fmt").value, hook_verify_tls: $("#a-htls").checked, hook_events: picked("[data-hev]", "hev") });
        toast(savedTxt(r.cleared) + (r.dropped ? `. ${SVLogic.plural(r.dropped, "wartende Meldung", "wartende Meldungen")} verworfen` : ""));
        // Read again: the *_set of a secret entered, the messages a channel switched off dropped
        const fresh = await api("GET", "/api/settings/alerts");
        $("#alert-card").innerHTML = alertCardHtml(fresh, true);
        const again = $("#a-save"); if (again) again.focus();
        await bindAlertCard(fresh);
      } catch (err) { toast(err.message); e.target.disabled = false; }
    });
    let d = null;
    try { d = await api("GET", "/api/alerts/deliveries"); } catch (e) { $("#a-deliv").innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    const rows = d && Array.isArray(d.rows) ? d.rows : [];
    $("#a-deliv").innerHTML = rows.length ? `<div class="tbl-wrap"><table><thead><tr><th>Zeit</th><th>Weg</th><th>Meldung</th><th>Stand</th></tr></thead><tbody>`
      + deliveryRows(rows) + `</tbody></table></div>` : `<div class="empty">Noch keine Meldungen.</div>`;
  }

  // A custom rule as a row of the rules card (c as GET /api/compliance/rules serves it, {} for a new one; data-crow: its id, "" for
  // a new one): name, mode and text, below Admin locked and without "Entfernen"
  function customRuleRow(c, admin) {
    const dis = admin ? "" : " disabled";
    return `<div class="crule" data-crow="${esc(c.id || "")}"><input data-cname name="r-name" aria-label="Name der Regel" placeholder="Name" maxlength="80" value="${esc(c.label || "")}"${dis}>`
      + `<select data-cmode name="r-mode" aria-label="Art der Regel"${dis}>${choices(RULE_MODES, c.mode || "must_not")}</select>`
      + `<input data-ctext name="r-text" aria-label="Text der Regel" placeholder="Text, z. B. vlan 666" maxlength="200" value="${esc(c.text || "")}"${dis}>`
      + (admin ? `<button class="btn small" type="button" data-cdel aria-label="${c.label ? `Entfernen: ${esc(c.label)}` : "Entfernen"}">Entfernen</button>` : "") + `</div>`;
  }
  // The card "Sicherheitsregeln" of r (GET /api/compliance/rules): each built-in rule as a box (checked: on; below Admin locked) with
  // its hint, then the custom rules (a text, no pattern: A1)
  function rulesCardHtml(r, admin) {
    const head = `<div class="card-h"><h2>Sicherheitsregeln</h2><span class="sub">geprüft an jeder gelesenen Konfiguration und am SNMP-Zugang jedes Switches</span></div>`;
    if (!r || !Array.isArray(r.rules)) return head + (r && r.error ? `<div class="empty">${esc(r.error)}</div>` : "");
    const dis = admin ? "" : " disabled", own = r.rules.filter(x => x.custom);
    return head + `<div class="card-b" style="display:grid;gap:12px;max-width:640px">${admin ? "" : `<p class="note gate">Regeln ändern braucht die Rolle „Admin“.</p>`}
      <div class="rules">${r.rules.filter(x => !x.custom).map(x => `<div class="rule"><label class="check"><input type="checkbox" data-rule="${esc(x.id)}"${x.on ? " checked" : ""}${dis} `
        + `aria-describedby="rh-${esc(x.id)}"> <b>${esc(x.label)}</b></label><span class="hint" id="rh-${esc(x.id)}">${esc(x.hint)}</span></div>`).join("")}</div>
      <fieldset class="fs"><legend>Eigene Regeln</legend><p class="note" style="margin:0">Eine eigene Regel sucht einen Text in jeder Zeile der Konfiguration, ohne Muster: „keine Zeile enthält“ meldet jede Zeile mit dem Text, „eine Zeile enthält“ meldet, wenn keine ihn hat.</p>
        <div id="r-custom">${own.length ? own.map(x => customRuleRow(x, admin)).join("") : `<p class="note" id="r-none" style="margin:0">Keine eigenen Regeln.</p>`}</div>
        ${admin ? `<div><button class="btn small" type="button" id="r-add">Regel hinzufügen</button></div>` : ""}</fieldset>
      ${admin ? `<div><button class="btn primary" type="button" id="r-save">Regeln speichern</button></div>` : ""}</div>`;
  }
  // An Admin's controls of the rules card: "Regel hinzufügen" appends an empty row, "Entfernen" takes its row away, "Regeln speichern"
  // sends the boxes switched off and the custom rows (PUT /api/compliance/rules; a row left empty is dropped, a half one named first)
  // and draws the card from the answer
  function bindRulesCard(r) {
    if (!roleOk("admin") || !r || !Array.isArray(r.rules)) return;
    const list = $("#r-custom");
    // A new row takes the focus in its name field
    $("#r-add").addEventListener("click", () => {
      const none = $("#r-none"); if (none) none.remove();
      list.insertAdjacentHTML("beforeend", customRuleRow({}, true));
      const row = list.lastElementChild; if (row) row.querySelector("[data-cname]").focus();
    });
    list.addEventListener("click", e => { const b = e.target.closest("[data-cdel]"); if (!b) return; b.closest("[data-crow]").remove(); $("#r-add").focus(); });
    $("#r-save").addEventListener("click", async e => {
      const off = [...document.querySelectorAll("[data-rule]")].filter(b => !b.checked).map(b => b.dataset.rule);
      const custom = [...document.querySelectorAll("#r-custom [data-crow]")].map(row => ({ id: row.dataset.crow || null, name: row.querySelector("[data-cname]").value.trim(),
        mode: row.querySelector("[data-cmode]").value, text: row.querySelector("[data-ctext]").value.trim() })).filter(c => c.name || c.text);
      const half = custom.find(c => !c.name || !c.text);
      if (half) { toast(half.name ? "Eigene Regel ohne Text" : "Eigene Regel ohne Namen"); return; }
      if (custom.length > 50) { toast("Höchstens 50 eigene Regeln"); return; }
      e.target.disabled = true;
      try {
        const saved = await api("PUT", "/api/compliance/rules", { off, custom });
        $("#rules-card").innerHTML = rulesCardHtml(saved, true); bindRulesCard(saved); toast("Gespeichert");
        const again = $("#r-save"); if (again) again.focus();
      } catch (err) { toast(err.message); e.target.disabled = false; }
    });
  }

  // A watched MAC as a row: its note, its latest sighting (switch and port, the time below), who added it and when
  const watchRow = (w, may) => `<tr><td class="mono">${esc(w.mac)}</td><td>${esc(w.note) || "–"}</td><td>${w.last ? `${esc(w.last.switch) || "–"} · Port ${esc(w.last.port)}`
    + `<span class="cellnote">${esc(fmtTime(w.last.last_seen))}</span>` : `<span class="muted">nicht gesehen</span>`}</td><td>${esc(w.created_by)}<span class="cellnote">${esc(fmtTime(w.created_at))}</span></td>`
    + (may ? `<td><button class="btn small" type="button" data-wdel="${esc(w.mac)}" aria-label="Entfernen: ${esc(w.mac)}">Entfernen</button></td>` : "") + `</tr>`;
  // The watch list (GET /api/watch, by MAC) into el, the body of the devices' card "Beobachtungsliste": with Ändern a MAC and a note
  // to watch (POST /api/watch, the server reads any usual spelling; the answer takes its place by MAC) and "Entfernen" per row
  // (DELETE /api/watch/{mac}, asked first); below it the sentence why not
  async function renderWatchInto(el) {
    if (!el) return;
    let got;
    try { got = await api("GET", "/api/watch"); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    let list = Array.isArray(got) ? got : [];
    const may = roleOk("aendern");
    el.innerHTML = (may ? `<form class="card-b toolrow" id="w-form"><input type="text" id="w-mac" placeholder="MAC-Adresse" aria-label="MAC-Adresse" maxlength="20" autocomplete="off">`
      + `<input type="text" id="w-note" placeholder="Notiz (optional)" aria-label="Notiz" maxlength="200" autocomplete="off"><button class="btn small primary" type="submit" id="w-add">Beobachten</button></form>`
      : `<p class="note gate" style="margin:12px 16px">Die Beobachtungsliste ändern braucht die Rolle „Ändern“.</p>`) + `<div id="w-rows"></div>`;
    const draw = () => {
      $("#w-rows").innerHTML = list.length ? `<div class="tbl-wrap"><table><thead><tr><th>MAC</th><th>Notiz</th><th>Zuletzt gesehen</th><th>Angelegt von</th>${may ? "<th></th>" : ""}</tr></thead>`
        + `<tbody>${list.map(w => watchRow(w, may)).join("")}</tbody></table></div>` : `<div class="empty">Keine MAC-Adresse beobachtet.</div>`;
    };
    draw();
    if (!may) return;
    $("#w-form").addEventListener("submit", async e => {
      e.preventDefault();
      $("#w-add").disabled = true;
      try {
        const w = await api("POST", "/api/watch", { mac: $("#w-mac").value.trim(), note: $("#w-note").value.trim() });
        list = [...list, w].sort((a, b) => (a.mac < b.mac ? -1 : a.mac > b.mac ? 1 : 0)); draw();
        $("#w-mac").value = ""; $("#w-note").value = ""; toast("Wird beobachtet");
      } catch (err) { toast(err.message); }
      $("#w-add").disabled = false; $("#w-mac").focus();
    });
    $("#w-rows").addEventListener("click", async e => {
      const b = e.target.closest("[data-wdel]"); if (!b) return;
      const mac = b.dataset.wdel;
      if (!(await confirmModal("Nicht mehr beobachten", `<b>${esc(mac)}</b> nicht mehr beobachten?`, "Entfernen", true))) return;
      try { await api("DELETE", `/api/watch/${encodeURIComponent(mac)}`); list = list.filter(w => w.mac !== mac); draw(); toast("Nicht mehr beobachtet"); }
      catch (err) { toast(err.message); }
      $("#w-mac").focus();
    });
  }
