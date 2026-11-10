"use strict";

  /* ── Triage of unknown devices in the devices view (sv-admin.js renderDevices; no list and no card of its own): the server's
     suggestion per entry of GET /api/devices/unknown (suggest, first_seen, new) stands in the two lists an unknown device is in
     already - "Ohne Zugriff" (renderParkedInto, sv-auth.js) and "Ohne Anmeldung" (drawUnknown) - and fills the form of "Freigeben";
     with Ändern several devices of a list are picked and released with one type and role, or a CSV list is taken over, both through
     POST /api/devices/import (first checked, stored only without a faulty row); "Neu bewerten" asks PacketFence to evaluate the
     login of a known device anew. A suggestion is never applied by itself. ── */
  // The MACs picked in the lists, kept over a redraw; one set, counted per list (triageSync)
  let triagePicked = new Set();
  // The limits of POST /api/devices/import (triage.IMPORT_MAX, DeviceImportIn.csv): said here in German before the route refuses
  const IMPORT_ROWS = 200, IMPORT_CHARS = 50000;
  // Whether a list carries suggestions (entries of GET /api/devices/unknown, null for a parked device no switch has learned): only
  // then it gets the column "Vorschlag", the choice and its bar; a server from before the triage draws the lists as they were
  const triageOn = list => list.some(d => d && "suggest" in d);
  // The cell "Vorschlag": type, the role known devices of that type have and how many, the port mode, the reasons below and the
  // hint to the port; without a type "kein Vorschlag" and the hint
  const suggestHtml = sg => {
    if (!sg) return "";
    const hint = sg.hint ? `<span class="cellnote">${esc(sg.hint)}</span>` : "";
    if (!sg.kind) return `<span class="muted">kein Vorschlag</span>${hint}`;
    const n = sg.role_count === 1 ? "so bei 1 bekanntem Gerät dieses Typs" : `so bei ${esc(sg.role_count)} bekannten Geräten dieses Typs`;
    return `<b>${esc(sg.label || KINDS[sg.kind] || sg.kind)}</b>${sg.role ? ` · Rolle ${esc(sg.role)}${sg.role_count ? ` · <span class="muted">${n}</span>` : ""}` : ""}`
      + `${sg.port_mode ? ` · Port-Modus „${esc(ST[sg.port_mode] ? ST[sg.port_mode][0] : sg.port_mode)}“` : ""}`
      + `${(sg.why || []).length ? `<ul class="blist">${sg.why.map(w => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}${hint}`;
  };
  // "neu" and the first sighting of an entry, after its name
  const firstSeenHtml = d => `${d.new ? ` <span class="pill warn">neu</span>` : ""}${d.first_seen ? `<span class="cellnote">zuerst gesehen ${esc(fmtTime(d.first_seen))}</span>` : ""}`;
  // The device "Freigeben" opens the form with (editDevice): the name without its domain, the suggested type and, only with a
  // suggested role, that role (without one a new device starts in DEVICE_ROLE)
  const triageDevice = (d, location) => {
    const sg = d.suggest, dev = { mac: d.mac, name: (d.name || "").replace(/\..*$/, ""), kind: (sg && sg.kind) || "sonstiges", location };
    if (sg && sg.role) dev.role = sg.role;
    return dev;
  };
  // The first cell of a row: the box that picks its device; empty for a row that cannot be picked (a known device)
  const pickCell = (mac, can) => can ? `<td><input type="checkbox" data-pick-mac="${esc(mac)}" aria-label="${esc(mac)} auswählen"${triagePicked.has(mac) ? " checked" : ""}></td>` : "<td></td>";
  // The bar over a list (key: park or net): how many of its devices are picked and "Ausgewählte freigeben" (triageSync fills it)
  const triageBar = key => `<div class="toolrow tr-bar"><span id="tr-n-${key}"></span><button class="btn small primary" type="button" id="tr-batch-${key}" disabled>Ausgewählte freigeben</button></div>`;
  const pickedOf = pool => pool.filter(d => triagePicked.has(d.mac));
  function triageSync(key, pool) {
    const n = pickedOf(pool).length;
    $(`#tr-n-${CSS.escape(key)}`).textContent = SVLogic.plural(n, "Gerät ausgewählt", "Geräte ausgewählt");
    $(`#tr-batch-${CSS.escape(key)}`).disabled = !n;
  }
  // The choice of the list in el: pool are its entries that can be picked ([{mac, name, suggest}]); set as properties, a list is
  // drawn and bound more than once
  function bindTriage(el, key, pool) {
    el.onchange = e => {
      const b = e.target.closest("[data-pick-mac]"); if (!b) return;
      if (b.checked) triagePicked.add(b.dataset.pickMac); else triagePicked.delete(b.dataset.pickMac);
      triageSync(key, pool);
    };
    $(`#tr-batch-${CSS.escape(key)}`).onclick = () => openBatch(pickedOf(pool));
    triageSync(key, pool);
  }

  // The rows of a check (the answer of POST /api/devices/import): the counts, the server's note (roles not checked) and per row
  // what would be stored, what happens to it and, below that, why (a seventh column would not fit the dialog)
  const IMPORT_PILL = { ok: ["ok", "wird freigegeben"], exists: ["neutral", "bleibt"], error: ["crit", "Fehler"] };
  const importRowsHtml = r => `<p style="margin:0 0 8px"><b>${esc(r.ok)} übernehmen, ${esc(r.exists)} schon bekannt, ${esc(r.errors)} fehlerhaft</b></p>`
    + `${r.note ? `<p class="note" style="margin:0 0 8px">${esc(r.note)}</p>` : ""}`
    + `<div class="tbl-wrap"><table><thead><tr><th>Zeile</th><th>MAC</th><th>Name</th><th>Rolle</th><th>Typ</th><th>Ergebnis</th></tr></thead><tbody>`
    + r.rows.map(x => { const [cls, text] = IMPORT_PILL[x.status] || ["neutral", x.status]; return `<tr><td class="num">${esc(x.line)}</td><td class="mono">${esc(x.mac)}</td><td>${esc(x.name)}</td>`
      + `<td>${esc(x.role || "default")}</td><td>${esc(KINDS[x.kind] || x.kind)}</td><td><span class="pill ${cls}">${esc(text)}</span>${x.reason ? `<span class="cellnote">${esc(x.reason)}</span>` : ""}</td></tr>`; }).join("")
    + `</tbody></table></div>`;
  // The fields both dialogs share (p: tb or imp): the type and role for a device without its own, and until when the releases hold
  const importFields = (p, v) => `<div class="grid2"><label class="field"><span>Typ</span><select id="${p}-kind">${Object.entries(KINDS).map(([k, l]) => `<option value="${k}"${v.kind === k ? " selected" : ""}>${l}</option>`).join("")}</select></label>
      <label class="field"><span>Rolle</span>${roleFieldHtml(`${p}-role`, v.role)}</label>
      <label class="field"><span>Gültig bis (optional)</span><input id="${p}-until" type="date" value="${esc(v.until)}"></label></div>`;
  const importValues = p => ({ kind: $(`#${CSS.escape(p)}-kind`).value, role: $(`#${CSS.escape(p)}-role`).value.trim(), until: $(`#${CSS.escape(p)}-until`).value });
  // One dialog in two steps for both ways into POST /api/devices/import. o.form(v): the form with the values v; o.read(): what the
  // form holds, {v, body} (null: a toast said what is missing); "Prüfen" asks with dry_run and shows the rows, with "Zurück" to the
  // form as filled; only a check without a faulty row and with a device to store offers o.go, which sends the same body without
  // dry_run. Then the view is drawn once anew and the kept sessions go: PacketFence is synced in the background, and asking it
  // per device (authAfterChange(mac)) would be up to twelve questions and a poll of the switch each
  async function importDialog(o, start) {
    if (!ROLES.configured && !ROLES.roles.length) { try { ROLES = await api("GET", "/api/pf/roles"); } catch (e) { /* the role as text */ } }
    const failed = e => `<div class="error">${esc(e.message)}</div>`;
    const form = (v, err = "") => {
      const n = modal(o.title, err + o.form(v), [{ label: "Abbrechen", onClick: closeModal }, { label: "Prüfen", cls: "primary", onClick: async b => {
        const got = await o.read(); if (!got) return;
        b.disabled = true;
        let r;
        try { r = await api("POST", "/api/devices/import", { ...got.body, dry_run: true }); } catch (e) { if (modalShown(n)) form(got.v, failed(e)); return; }
        if (modalShown(n)) preview(got, r);
      } }]);
    };
    const preview = (got, r, err = "") => {
      const can = r.errors === 0 && r.ok > 0;
      const n = modal(o.title, err + (can ? "" : `<p class="note warn" style="margin:0 0 8px">${r.errors ? "Erst die fehlerhaften Zeilen beheben." : "Kein Gerät zu übernehmen."}</p>`) + importRowsHtml(r),
        [{ label: "Zurück", onClick: () => form(got.v) }, { label: "Abbrechen", onClick: closeModal }, ...(can ? [{ label: o.go, cls: "primary", onClick: async b => {
          b.disabled = true;
          let done;
          try { done = await api("POST", "/api/devices/import", { ...got.body, dry_run: false }); } catch (e) { if (modalShown(n)) preview(got, r, failed(e)); return; }
          if (modalShown(n)) closeModal();
          (got.body.rows || []).forEach(x => triagePicked.delete(x.mac));
          toast(`${SVLogic.plural(done.created, "Gerät", "Geräte")} ${o.done} – PacketFence wird abgeglichen`);
          MAP = null; authAfterChange(); if (current === "devices") renderDevices();
        } }] : [])]);
    };
    form(start);
  }
  // "Ausgewählte freigeben": the picked entries of a list ([{mac, name, suggest}]) with one type and one role - what every entry
  // suggests, else "Sonstiges" and DEVICE_ROLE
  async function openBatch(entries) {
    if (!entries.length) return;
    if (entries.length > IMPORT_ROWS) { toast(`Höchstens ${IMPORT_ROWS} Geräte auf einmal freigeben`); return; }
    const shared = k => { const a = entries[0].suggest && entries[0].suggest[k]; return a && entries.every(d => d.suggest && d.suggest[k] === a) ? a : ""; };
    const names = entries.map(d => { const name = (d.name || "").replace(/\..*$/, ""); return `<li>${name ? `${esc(name)} ` : ""}<span class="mono">${esc(d.mac)}</span></li>`; }).join("");
    await importDialog({ title: `${SVLogic.plural(entries.length, "Gerät", "Geräte")} freigeben`, go: "Freigeben", done: "freigegeben",
      form: v => `${importFields("tb", v)}<p class="note">Typ und Rolle gelten für alle; der Name kommt aus der ARP-Tabelle, sonst aus Hersteller und MAC. Der Server prüft die Liste, bevor etwas freigegeben wird.</p><ul class="blist">${names}</ul>`,
      read: async () => { const v = importValues("tb"); return { v, body: { rows: entries.map(d => ({ mac: d.mac })), kind: v.kind, role: v.role, valid_until: v.until || null } }; } },
    { kind: shared("kind") || "sonstiges", role: shared("role") || DEVICE_ROLE, until: "" });
  }
  // "CSV importieren" (the tab "MAC-Freigaben"): a file, read here in the browser, or pasted text; the server reads and checks it
  async function openImport() {
    await importDialog({ title: "CSV importieren", go: "Übernehmen", done: "übernommen",
      form: v => `<p class="note" style="margin:0 0 12px">Eine Zeile je Gerät: MAC;Rolle;Name;Typ – Rolle, Name und Typ sind optional, „;“ oder „,“ trennen, eine Kopfzeile ist erlaubt. Höchstens ${IMPORT_ROWS} Zeilen.</p>
        <label class="field"><span>CSV-Datei</span><input type="file" id="imp-file" accept=".csv,text/csv,text/plain"></label>
        <label class="field"><span>oder Text einfügen</span><textarea id="imp-text" rows="6" spellcheck="false">${esc(v.text)}</textarea></label>
        <p class="note">Für Zeilen ohne eigene Rolle oder eigenen Typ:</p>${importFields("imp", v)}`,
      read: async () => {
        const file = ($("#imp-file").files || [])[0], text = file ? await file.text() : $("#imp-text").value;
        if (!text.trim()) { toast("Bitte eine Datei wählen oder Text einfügen"); return null; }
        if (text.length > IMPORT_CHARS) { toast(`Die Liste ist zu lang (höchstens ${IMPORT_CHARS.toLocaleString("de-DE")} Zeichen)`); return null; }
        const v = { ...importValues("imp"), text };
        return { v, body: { csv: text, kind: v.kind, role: v.role, valid_until: v.until || null } };
      } },
    { kind: "sonstiges", role: DEVICE_ROLE, until: "", text: "" });
  }

  // "Neu bewerten": PacketFence evaluates the login of mac anew (CoA) - for a released device it parks anyway, or one that does
  // not switch over; then the sessions are asked anew until its port switched, as after a release
  async function reevaluateMac(mac) {
    if (!(await confirmModal("Neu bewerten", `<span class="mono">${esc(mac)}</span>: PacketFence bewertet die Anmeldung neu (CoA). Das Gerät meldet sich am Port neu an.`, "Neu bewerten"))) return;
    try { await api("POST", `/api/devices/${encodeURIComponent(mac)}/reevaluate`); } catch (e) { toast(e.message); return; }
    toast(`Neu bewertet${AUTH_SWITCH_NOTE}`);
    authAfterChange(mac); if (current === "devices") renderDevices();
  }
  // The button of the device dialog (editDevice) for a known device
  const reevalButton = d => ({ label: "Neu bewerten", onClick: () => { closeModal(); reevaluateMac(d.mac); } });
