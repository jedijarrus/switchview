"use strict";

  /* ── Sammeländerung (Phase 4c): the same port change at several switches. The view #bulk (reached from "Sammeländerung" in the
     switch view; no tab of its own) holds the form - the switches the user may change, per switch its ports as text or every access
     port untagged in a VLAN, the change as the port form offers it - and the last bulk changes. "Vorschau" plans every switch (POST
     /api/bulk/plan) and shows it ready or skipped with its reason; the ready ones run (POST /api/bulk) or, with the four-eyes
     principle on, are requested (POST /api/approvals of the kind bulk_change, reviewed in sv-approvals.js). The run stands in a
     dialog (openBulk). The server checks every step (api_bulk, bulk); the view offers what role and zone allow. ── */
  // The state of a switch in a bulk change (bulk_items.status) and of a bulk change (bulks.status): its text and its pill
  const BULK_ST = { waiting: ["wartet", "neutral"], running: ["läuft", "neutral"], done: ["erledigt", "ok"], failed: ["fehlgeschlagen", "crit"],
    skipped: ["übersprungen", "neutral"], not_started: ["nicht gestartet", "neutral"] };
  const BULK_RUN = { queued: ["wartet", "neutral"], running: ["läuft", "neutral"], done: ["fertig", "ok"], failed: ["mit Fehlern", "crit"],
    cancelled: ["abgebrochen", "neutral"], interrupted: ["durch Neustart abgebrochen", "warn"] };
  const bulkPill = ([text, cls]) => `<span class="pill ${cls}">${esc(text)}</span>`;
  // The form as it was read last (readBulkForm: at every change of a field and at "Vorschau"), so that it outlives a new render
  // and a visit to another view, like devText; null: empty (never filled, or its bulk change was started, requested or cancelled)
  let bulkForm = null;
  const bulkFormEmpty = () => ({ picked: [], ports: {}, mode: "ports", vlan: "", st: "", u: "", tadd: "", trem: "", name: "", nclear: false, poe: "",
    expert: false, cont: false });
  // "1 erledigt · 0 fehlgeschlagen · 2 nicht gestartet" of the counts of a bulk change (GET /api/bulk, bulk.COUNTED)
  const bulkCounts = c => `${c.done} erledigt · ${c.failed} fehlgeschlagen · ${c.not_started} nicht gestartet`;
  // The states of a port the form offers, in its order ("" leaves it as it is); the server's names (api_changes.PortChange)
  const BULK_STATES = [["", "unverändert"], ["off", "Aus"], ["on", "An"], ["protected", "Protected"], ["known", "Bekannte Geräte"], ["radius", "RADIUS"]];

  // The view: the form for Ändern (else the sentence of the role), then the last 50 bulk changes for every role
  async function renderBulk() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    const may = roleOk("aendern");
    let rows = [], failed = "";
    try { if (may) await loadMap(false); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    try { rows = await api("GET", "/api/bulk"); } catch (e) { failed = e.message; }
    const list = failed ? `<div class="empty">${esc(failed)}</div>` : !rows.length ? `<div class="empty">Noch keine Sammeländerungen.</div>`
      : `<div class="tbl-wrap"><table><thead><tr><th>#</th><th>Zeit</th><th>von</th><th>Änderung</th><th>Status</th><th></th></tr></thead><tbody>` + rows.map(b =>
        `<tr><td class="num">${b.id}</td><td class="num">${esc(fmtTime(b.created_at))}</td><td>${esc(b.username)}</td><td>${esc(b.summary)}</td>`
        + `<td>${bulkPill(BULK_RUN[b.status] || [b.status, "neutral"])}<span class="cellnote">${bulkCounts(b.counts)}</span></td>`
        + `<td><div class="actions"><button class="btn small" type="button" data-bulk-open="${b.id}">Anzeigen</button></div></td></tr>`).join("") + `</tbody></table></div>`;
    v.innerHTML = `<div style="display:grid;gap:16px"><section class="card"><div class="card-h"><h2>Neue Sammeländerung</h2><span class="sub">dieselbe Änderung an mehreren Switches</span></div>
      <div class="card-b">${may ? bulkFormHtml(bulkForm || bulkFormEmpty()) : `<p class="note gate">Sammeländerungen starten braucht die Rolle „Ändern“.</p>`}</div></section>
      <section class="card"><div class="card-h"><h2>Letzte Sammeländerungen</h2><span class="sub">neueste zuerst · die letzten 50</span></div>${list}</section></div>`;
    v.onclick = e => { const o = e.target.closest("[data-bulk-open]"); if (o) return openBulk(+o.dataset.bulkOpen); };
    // No form below Ändern, and none without a switch the user may change
    const form = $("#b-form"); if (!may || !form) return;
    form.addEventListener("change", () => { bulkForm = readBulkForm(); syncBulkFields(); });
    $("#b-preview").addEventListener("click", () => {
      const req = collectBulk();
      if (typeof req === "string") { toast(req); return; }
      return previewBulk(req, { fromForm: true, onError: bulkForm.cont ? "continue" : "stop" });
    });
  }

  // The form with the state f: the switches by zone (only those the user may change, mayChange), each with its port field, shown
  // for a ticked switch while the ports are chosen per switch (syncBulkFields); the change; what happens after a failure; with the
  // four-eyes principle on, that every bulk change is requested (the port form's sentence names only the expert mode)
  function bulkFormHtml(f) {
    const mine = MAP.switches.filter(mayChange);
    if (!mine.length) return `<p class="note gate">Kein Switch, an dem du ändern darfst und an dem SwitchView schreiben kann.</p>`;
    const byPorts = f.mode !== "vlan", vl = Object.keys(MAP.vlans).sort((a, b) => a - b), four = !!(ME && ME.four_eyes);
    const sel = (v, cur) => (v === cur ? " selected" : ""), on = x => (x ? " checked" : "");
    const vlanOpts = (cur, none) => `<option value="">${none}</option>` + vl.map(id => `<option value="${esc(id)}"${sel(id, cur)}>${esc(id)} · ${esc(vname(id))}</option>`).join("");
    const sw = s => {
      const ticked = f.picked.includes(s.id);
      return `<div class="toolrow"><label class="check"><input type="checkbox" data-bulk-sw="${s.id}"${on(ticked)}> <span>${esc(s.k)}${s.model ? ` <span class="muted">${esc(s.model)}</span>` : ""}</span></label>`
        + `<input type="text" data-bulk-ports="${s.id}" placeholder="z. B. 1-4, 7" aria-label="Ports an ${esc(s.k)}" autocomplete="off" value="${esc(f.ports[s.id] || "")}"${ticked && byPorts ? "" : " hidden"}></div>`;
    };
    return `<div id="b-form" style="display:grid;gap:14px">
      <fieldset class="fs"><legend>Switches und Ports</legend>
        <div class="toolrow"><select id="b-mode" aria-label="Auswahl der Ports"><option value="ports"${sel("ports", f.mode)}>Ports je Switch</option><option value="vlan"${sel("vlan", f.mode)}>Alle Zugangsports, die ungetaggt in einem VLAN sind</option></select>
          <select id="b-vlan" aria-label="VLAN der Auswahl"${byPorts ? " hidden" : ""}>${vlanOpts(f.vlan, "VLAN wählen")}</select></div>
        ${zones().map(z => { const zs = mine.filter(s => (s.zone || "Ohne Zone") === z); return zs.length ? `<div class="zonehead">${esc(z)}</div>` + zs.map(sw).join("") : ""; }).join("")}
        <p class="note" style="margin:0">Ports als Liste, Bereiche nur aus Ziffern: „1-4, 7, Gi1/0/2“. Höchstens 20 Switches und 1000 Ports je Sammeländerung.</p></fieldset>
      <fieldset class="fs"><legend>Änderung</legend>
        <div class="grid2"><label class="field"><span>Zustand</span><select id="b-st">${BULK_STATES.map(([k, t]) => `<option value="${k}"${sel(k, f.st)}>${t}</option>`).join("")}</select></label>
          <label class="field"><span>VLAN ungetaggt</span><select id="b-u">${vlanOpts(f.u, "unverändert")}</select></label></div>
        <p class="note" style="margin:0">Protected, Bekannte Geräte und RADIUS gehen nur mit SSH an ProCurve – andere Switches überspringt die Vorschau mit Grund.</p>
        <div class="grid2"><label class="field"><span>Getaggt hinzufügen</span><input id="b-tadd" placeholder="20, 30" autocomplete="off" value="${esc(f.tadd)}"></label>
          <label class="field"><span>Getaggt entfernen</span><input id="b-trem" placeholder="20, 30" autocomplete="off" value="${esc(f.trem)}"></label></div>
        <div class="grid2"><label class="field"><span>Name</span><input id="b-name" maxlength="64" placeholder="unverändert" autocomplete="off" value="${esc(f.name)}"><span class="hint">ohne Leerzeichen, z. B. Drucker-EK</span></label>
          <label class="field"><span>PoE</span><select id="b-poe"><option value="">unverändert</option><option value="on"${sel("on", f.poe)}>an</option><option value="off"${sel("off", f.poe)}>aus</option></select></label></div>
        <label class="check"><input type="checkbox" id="b-nclear"${on(f.nclear)}> Name entfernen</label>
        ${expertOk() ? `<label class="check warnbox"><input type="checkbox" id="b-expert"${on(f.expert)}${four ? ' aria-describedby="b-4eyes"' : ""}> Expertenmodus: Uplinks/Trunks ändern. Falsch gesetzt, trennt das den Switch vom Netz.</label>` : ""}</fieldset>
      <label class="check"><input type="checkbox" id="b-continue"${on(f.cont)}> Bei einem Fehler weitermachen (sonst stoppt der erste Fehler die übrigen Switches)</label>
      ${four ? `<p class="note" id="b-4eyes" style="margin:0">Vier-Augen-Prinzip: Jede Sammeländerung braucht die Freigabe durch eine zweite Person, mit und ohne Expertenmodus – die Vorschau fordert sie an.</p>` : ""}
      <div><button class="btn primary" type="button" id="b-preview">Vorschau</button></div></div>`;
  }

  // The form's fields as a state for bulkForm: the ticked switches in the order shown, the text of every port field by switch id, the
  // name as the port form writes it (blanks to "_"); the expert mode only for who may use it (expertOk)
  function readBulkForm() {
    const ports = {}, box = $("#b-expert");
    document.querySelectorAll("[data-bulk-ports]").forEach(i => { ports[i.dataset.bulkPorts] = i.value; });
    return { picked: [...document.querySelectorAll("[data-bulk-sw]")].filter(c => c.checked).map(c => +c.dataset.bulkSw), ports,
      mode: $("#b-mode").value === "vlan" ? "vlan" : "ports", vlan: $("#b-vlan").value, st: $("#b-st").value, u: $("#b-u").value,
      tadd: $("#b-tadd").value, trem: $("#b-trem").value, name: $("#b-name").value.trim().replace(/\s+/g, "_"), nclear: $("#b-nclear").checked,
      poe: $("#b-poe").value, expert: expertOk() && !!(box && box.checked), cont: $("#b-continue").checked };
  }
  // Shows the port field of every ticked switch while the ports are chosen per switch, and the VLAN of the filter otherwise
  function syncBulkFields() {
    const byPorts = $("#b-mode").value !== "vlan";
    const ticked = new Set([...document.querySelectorAll("[data-bulk-sw]")].filter(c => c.checked).map(c => c.dataset.bulkSw));
    document.querySelectorAll("[data-bulk-ports]").forEach(i => { i.hidden = !(byPorts && ticked.has(i.dataset.bulkPorts)); });
    $("#b-vlan").hidden = byPorts;
  }

  // The request for POST /api/bulk/plan from the form (which it reads into bulkForm), or as a text the first thing that keeps it
  // from being asked: no switch, no VLAN of the filter, a tagged VLAN that is no number, nothing to change, then per switch its ports
  // (SVLogic.parsePorts; the names the switch does not have are the preview's to say)
  function collectBulk() {
    const f = bulkForm = readBulkForm(), change = {};
    if (!f.picked.length) return "Bitte mindestens einen Switch wählen";
    if (f.mode === "vlan" && !f.vlan) return "Bitte das VLAN wählen, in dem die Ports ungetaggt sind";
    for (const [key, text] of [["tagged_add", f.tadd], ["tagged_remove", f.trem]]) {
      const ids = text.split(/[\s,]+/).filter(Boolean), bad = ids.find(id => !/^\d{1,4}$/.test(id));
      if (bad !== undefined) return `Getaggte VLANs: „${bad}“ ist keine VLAN-Nummer`;
      if (ids.length) change[key] = ids;
    }
    if (f.st) change.status = f.st;
    if (f.u) change.untagged = f.u;
    if (f.nclear) change.name = ""; else if (f.name) change.name = f.name;
    if (f.poe) change.poe = f.poe === "on";
    if (!Object.keys(change).length) return "Nichts ausgewählt, was sich ändern soll";
    const targets = [];
    for (const id of f.picked) {
      if (f.mode === "vlan") { targets.push({ switch_id: id, untagged_in: f.vlan }); continue; }
      const name = (swById(id) || { k: `#${id}` }).k, read = SVLogic.parsePorts(f.ports[id]);
      if (read.error) return `${name}: ${read.error}`;
      if (!read.ports.length) return `${name}: Bitte Ports eintragen`;
      targets.push({ switch_id: id, ports: read.ports });
    }
    return { targets, change, expert: f.expert };
  }

  // The preview of the bulk request req ({targets, change, expert}): every switch planned now, shown ready (its preview as a port
  // change shows it, previewBody) or skipped with its reason. The ready ones run with "Ausführen (N Switches)", or with the
  // four-eyes principle on (approval of the answer) are requested - with exactly these ports, tokens and write ways, the skipped
  // ones with their reasons for the summary -, optionally with confirmation (sv-confirm.js). o.onError: "continue" runs the rest
  // after a failure (default "stop"); o.fromForm: the form stands under the dialog - "Zurück" leaves it as filled, "Abbrechen" and
  // a start or a request empty it. A dialog closed or replaced while the switches are read opens nothing (modalShown).
  async function previewBulk(req, o = {}) {
    const title = "Sammeländerung: Vorschau", back = o.fromForm ? [{ label: "Zurück", onClick: closeModal }] : [];
    // The form is done with: empty at its next render, which comes at once where the view is shown
    const formDone = () => { if (!o.fromForm) return; bulkForm = null; if (current === "bulk") return renderBulk(); };
    const wait = modal(title, `<div class="empty">Plane ${SVLogic.plural(req.targets.length, "Switch", "Switches")} …</div>`, []);
    let r;
    try { if (!MAP) await loadMap(false); r = await api("POST", "/api/bulk/plan", req); }
    catch (e) { if (modalShown(wait)) modal(title, `<div class="error">${esc(e.message)}</div>`, [...back, { label: "Schließen", onClick: closeModal }]); return; }
    if (!modalShown(wait)) return;
    const ready = r.sections.filter(s => s.status === "ready"), skipped = r.sections.filter(s => s.status !== "ready"), ask = ready.length > 0 && !!r.approval;
    const section = s => `<div class="bulk-sec"><p style="margin:0"><b>${esc(s.switch)}</b> ${bulkPill(s.status === "ready" ? ["bereit", "ok"] : BULK_ST.skipped)} `
      + `<span class="muted">${esc(s.selection || (s.ports.length ? `${SVLogic.plural(s.ports.length, "Port", "Ports")}: ${s.ports.join(", ")}` : ""))}</span></p>`
      + (s.status === "ready" ? previewBody(swById(s.switch_id) || { id: s.switch_id, k: s.switch, caps: [] }, s.preview, { mode: "ports", ports: s.ports, change: req.change })
        : `<p class="note gate">${esc(s.reason)}</p>`) + `</div>`;
    const body = (ask ? `<div class="banner warn"><span><b>Vier-Augen-Prinzip:</b> Diese Sammeländerung wird erst ausgeführt, wenn eine zweite Person mit der Rolle „Freigeben“ sie freigibt. Niemand kann die eigene Anfrage freigeben.</span></div>` : "")
      + `<p style="margin:0"><b>${esc(r.summary)}</b> <span class="muted">· ${SVLogic.plural(ready.length, "Switch", "Switches")} bereit, ${skipped.length} übersprungen</span></p>`
      + r.sections.map(section).join("")
      + (ready.length ? confirmOptionHtml({ confirm: r.confirm }, { mode: "ports" }) : `<div class="banner">Kein Switch ist bereit.</div>`);
    // What starts: the ready switches as the preview showed them; a reason is cut to the 300 characters the server takes
    const started = () => {
      const m = confirmMinutes();
      return { items: ready.map(s => ({ switch_id: s.switch_id, ports: s.ports, token: s.preview.token, mechanism: s.preview.mechanism })),
        skipped: skipped.map(s => ({ switch_id: s.switch_id, reason: [...String(s.reason || "")].slice(0, 300).join("") })),
        change: req.change, expert: !!req.expert, on_error: o.onError === "continue" ? "continue" : "stop", ...(m === null ? {} : { confirm_minutes: m }) };
    };
    const btns = [...back, { label: "Abbrechen", onClick: () => { closeModal(); return formDone(); } }];
    if (ask) btns.push({ label: "Freigabe anfordern", cls: "primary", onClick: async b => {
      b.disabled = true;
      try {
        const res = await api("POST", "/api/approvals", { kind: "bulk_change", bulk: started() });
        if (modalShown(shown)) closeModal();
        toast(`Freigabe angefordert (Anfrage #${res.id})`);
        refreshApprovals(); if (current === "approvals") renderApprovals();
        formDone();
      } catch (e) { toast(e.message); b.disabled = false; }
    } });
    else if (ready.length) btns.push({ label: `Ausführen (${SVLogic.plural(ready.length, "Switch", "Switches")})`, cls: "primary", onClick: async b => {
      b.disabled = true;
      try { const res = await api("POST", "/api/bulk", started()); openBulk(res.id); formDone(); }
      catch (e) { toast(e.message); b.disabled = false; }
    } });
    const shown = modal(title, body, btns);
  }

  // The sections of a bulk request as its requester saw them (the stored preview) or, with review, as the reviewer's fresh preview
  // plans them now: per switch its name, its ports, why it cannot run now (reason), its warnings and what goes out; with review a
  // switch that is no longer the request's (matches false) says so
  const bulkSectionsHtml = (sections, review = false) => (sections || []).map(s =>
    `<div class="bulk-sec"><p style="margin:0"><b>${esc(s.switch)}</b> <span class="muted">· ${SVLogic.plural(s.ports.length, "Port", "Ports")}: <span class="mono">${esc(s.ports.join(", "))}</span></span>`
    + `${review && s.matches === false ? ` <span class="pill warn">passt nicht mehr</span>` : ""}</p>${s.reason ? `<p class="note gate">${esc(s.reason)}</p>` : ""}`
    + `${warnList(s.warnings)}<pre class="code">${esc((s.commands || []).join("\n") || "–")}</pre></div>`).join("");

  // Whether the user may cancel bulk change b (GET /api/bulk/{id}), as bulk.cancel: who started it (the case aside), else Freigeben
  // in the zone of every switch it runs at (a skipped or deleted one runs nothing); the server checks it again
  const mayCancelBulk = b => {
    const me = ((ME && ME.username) || "").toLowerCase();
    if (!roleOk("aendern")) return false;
    if (!!me && (b.username || "").toLowerCase() === me) return true;
    return roleOk("freigeben") && (b.items || []).every(i => i.status === "skipped" || i.switch_id == null || inZone({ zone: i.zone }));
  };
  // The state of switch i of a bulk change: a done one whose change waits for its confirmation or ended without one says so
  // (chState of sv-switch.js, the rule of the change list), any other its own state
  const bulkItemState = i => {
    const c = i.status === "done" ? i.change : null, waited = c && (c.status === "pending" || (c.status === "unclear" && chState(c) !== CH.unclear));
    return waited ? chState(c) : BULK_ST[i.status] || [i.status, "neutral"];
  };

  // Bulk change id in its dialog: who started it, its state and counts, and per switch its ports, its state, its change (a link to
  // the switch, whose change list has it; the dialog closes with it) and its detail. Asked every 2 s while it waits or runs or one of its changes waits for
  // its confirmation, and only while the dialog is the one shown (modalShown): closed, the bulk change runs on at the server and
  // stands in the list. "Abbrechen" (mayCancelBulk, until a cancel is asked for) stops it before its next switch, "Alle bestätigen"
  // (Ändern) confirms every waiting change; the footer is set anew only when its buttons change.
  async function openBulk(id) {
    const close = { label: "Schließen", onClick: closeModal };
    const shown = modal(`Sammeländerung #${id}`, `<div id="bulk-run"><div class="empty">Lade …</div></div>`, [close]);
    const cancel = { label: "Abbrechen", cls: "danger", onClick: async b => {
      b.disabled = true;
      try { await api("POST", `/api/bulk/${id}/cancel`); toast("Abbruch angefordert"); } catch (e) { toast(e.message); b.disabled = false; }
    } };
    const confirmAll = { label: "Alle bestätigen", cls: "primary", onClick: async b => {
      b.disabled = true;
      try {
        const res = await api("POST", `/api/bulk/${id}/confirm`), no = res.refused || [];
        toast(`${SVLogic.plural(res.confirmed.length, "Änderung", "Änderungen")} bestätigt` + (no.length ? `, ${no.length} nicht: ${no[0].detail}` : ""));
      } catch (e) { toast(e.message); }
      b.disabled = false;
    } };
    // The link of a change leads to its switch: the dialog closes with it (on the view of that very switch the hash stays as it is)
    $("#m-body").onclick = e => { if (e.target.closest("a[href]")) closeModal(); };
    let foot = close.label;
    for (;;) {
      let b;
      try { b = await api("GET", `/api/bulk/${id}`); }
      catch (e) { if (modalShown(shown)) $("#bulk-run").innerHTML = `<div class="error">${esc(e.message)}</div>`; return; }
      if (!modalShown(shown)) return;
      const running = ["queued", "running"].includes(b.status), live = running || b.counts.pending > 0;
      const facts = [`von ${esc(b.username)}`, b.approved_by ? `freigegeben von ${esc(b.approved_by)}` : "", esc(fmtTime(b.created_at)),
        bulkPill(BULK_RUN[b.status] || [b.status, "neutral"]), bulkCounts(b.counts), `bei einem Fehler: ${b.on_error === "continue" ? "weitermachen" : "stoppen"}`,
        b.confirm_minutes ? `mit Bestätigung (${SVLogic.plural(b.confirm_minutes, "Minute", "Minuten")})` : "", running && b.cancel_requested ? "Abbruch angefordert" : ""];
      $("#bulk-run").innerHTML = `<p style="margin:0"><b>${esc(b.summary)}</b></p><p class="note" style="margin:0 0 10px">${facts.filter(Boolean).join(" · ")}</p>`
        + `<div class="tbl-wrap"><table><thead><tr><th>Switch</th><th>Ports</th><th>Zustand</th><th>Änderung</th><th>Detail</th></tr></thead><tbody>` + b.items.map(i =>
          `<tr><td style="white-space:nowrap">${esc(i.switch)}</td><td class="mono">${esc(i.ports.join(", "))}</td><td>${bulkPill(bulkItemState(i))}</td>`
          + `<td>${!i.change ? "–" : i.switch_id == null ? `#${i.change.id}` : `<a href="#sw=${i.switch_id}">#${i.change.id}</a>`}</td><td>${esc(i.detail) || "–"}</td></tr>`).join("")
        + `</tbody></table></div>`;
      const btns = [...(running && !b.cancel_requested && mayCancelBulk(b) ? [cancel] : []), ...(b.counts.pending > 0 && roleOk("aendern") ? [confirmAll] : []), close];
      const labels = btns.map(x => x.label).join("|");
      if (labels !== foot) { foot = labels; modalFoot(btns); }
      if (!live) return;
      await new Promise(res => setTimeout(res, 2000));
      if (!modalShown(shown)) return;
    }
  }
