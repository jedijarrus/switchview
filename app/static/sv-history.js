"use strict";

  /* ── Verlauf (Phase 4b): where a device was seen (GET /api/history, newest first, paged by the server's cursor), the events of every
     switch (GET /api/events), the switch view's cards "Ereignisse" and "Sicherheitsbefunde", "Bisher an diesem Port" in the port
     panel, and the overview's groups of the findings and of the changes outside SwitchView. The rows are the server's (times in UTC,
     shown with fmtTime), every text from them is escaped. ── */
  // histTerm: the device search as typed, histKind: the group of events shown ("" = all); both outlive a new render (go() resets
  // neither), like auditText of the audit. histTimer: the search waiting for the pause after the last key
  let histTerm = "", histKind = "", histTimer = null;
  const HIST_DELAY = 300;
  // The groups of GET /api/events (monitor.KIND_GROUPS) as the filter names them
  const EVENT_KINDS = [["", "Alle"], ["reach", "Erreichbarkeit"], ["lldp", "LLDP-Nachbarn"], ["drift", "Außerhalb von SwitchView"]];
  const MORE_ROW = `<div class="more-row"><button class="btn small" type="button" data-more>Mehr laden</button></div>`;
  const HIST_EXPLAIN = `<div class="empty">MAC, IP oder Namen eingeben: SwitchView zeigt, wo das Gerät gesehen wurde.</div>`;
  // A sighting at a port that may have been an uplink then (history.record's suspect: an unconfirmed uplink, the devices behind it)
  const SUSPECT_PILL = ` <span class="pill warn" title="Der Port war damals vielleicht ein Uplink">Uplink (unbestätigt)</span>`;
  // The severities of compliance.RULES as the findings card names them; an unknown one reads as "prüfen"
  const FINDING_SEV = { crit: ["kritisch", "crit"], warn: ["prüfen", "warn"] };

  // One page of url with params (SVLogic.query, the cursor last; or a function of the cursor that gives the query: the audit's
  // SVLogic.auditParams) into el: the first page (cursor undefined) replaces what el shows, a later one is appended to the rows
  // before it; draw(rows) gives the HTML of all rows, "Mehr laden" follows while the server names a
  // next page. An answer without rows draws none (the stubs of older tests answer every URL with a list). A load that a newer one of
  // el overtook (another search, a field emptied meanwhile: el._seq) draws nothing; a failed first page shows the server's text in el
  // (a 422 names what to ask), a failed later page is a toast and leaves the list. The focus inside el ("Mehr laden", the panel's
  // "Anzeigen", both replaced) goes to el itself, not to body. Returns the page, null when it failed or was overtaken.
  async function loadPaged(el, url, params, draw, cursor) {
    if (!el) return null;
    const seq = el._seq = (el._seq || 0) + 1;
    let page;
    try { page = await api("GET", url + (typeof params === "function" ? params(cursor) : SVLogic.query({ ...params, cursor }))); } catch (e) {
      if (el._seq === seq) { if (cursor == null) el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; else toast(e.message); }
      return null;
    }
    if (el._seq !== seq) return null;
    const rows = (cursor == null ? [] : el._rows || []).concat(page && Array.isArray(page.rows) ? page.rows : []);
    const next = page && page.next != null ? page.next : null;
    const had = document.activeElement && document.activeElement !== document.body && el.contains(document.activeElement);
    el._rows = rows;
    el.innerHTML = draw(rows) + (next != null ? MORE_ROW : "");
    if (had) { el.setAttribute("tabindex", "-1"); el.focus(); }
    el.onclick = async e => {
      const m = e.target.closest("[data-more]"); if (!m) return;
      // A focused button that is disabled drops its focus to body: the list takes it first (Task 10, browser check)
      if (document.activeElement === m) { el.setAttribute("tabindex", "-1"); el.focus(); }
      m.disabled = true;
      if (!(await loadPaged(el, url, params, draw, next))) m.disabled = false;
    };
    return page;
  }

  // The sightings as a table, newest first as the server sends them. The port of a switch the netmap knows opens that switch and its
  // port panel (as a hit of the search does), the port of a switch gone since is text; a suspect row carries the mark of the switch view
  function sightingTable(rows) {
    const port = r => r.switch_id != null && MAP && swById(r.switch_id)
      ? `<button type="button" class="linkbtn" data-hsw="${esc(r.switch_id)}" data-hport="${esc(r.port)}">${esc(r.port)}</button>` : esc(r.port);
    return `<div class="tbl-wrap"><table><thead><tr><th>Zuletzt gesehen</th><th>Zuerst gesehen</th><th>MAC</th><th>IP</th><th>Name</th><th>Switch</th><th>Port</th><th>VLAN</th></tr></thead><tbody>`
      + rows.map(r => `<tr><td class="num time">${esc(fmtTime(r.last_seen))}</td><td class="num time">${esc(fmtTime(r.first_seen))}</td>`
        + `<td class="mono">${esc(r.mac)}${r.vendor ? `<span class="cellnote">${esc(r.vendor)}</span>` : ""}</td><td class="mono">${esc(r.ip) || "–"}</td>`
        + `<td>${esc(r.name) || "–"}</td><td>${esc(r.switch) || "–"}</td><td>${port(r)}${r.suspect ? SUSPECT_PILL : ""}</td><td>${r.vlan ? chip(r.vlan) : "–"}</td></tr>`).join("")
      + `</tbody></table></div>`;
  }

  // The events as a table, newest first: time, switch (withSwitch; the switch view's own card leaves it out, as its change list
  // does), the kind's label (monitor.KINDS) and the text; a backup that differs without a SwitchView change (drift_config) offers its
  // comparison with the one before (openBackupDiff of detail.backup)
  function eventTable(rows, withSwitch = true) {
    const cmp = r => r.kind === "drift_config" && r.detail && r.detail.backup != null
      ? ` <button class="btn small" type="button" data-bdiff="${esc(r.detail.backup)}">Vergleich</button>` : "";
    return `<div class="tbl-wrap"><table><thead><tr><th>Zeit</th>${withSwitch ? "<th>Switch</th>" : ""}<th>Art</th><th>Was</th></tr></thead><tbody>`
      + rows.map(r => `<tr><td class="num time">${esc(fmtTime(r.ts))}</td>${withSwitch ? `<td>${esc(r.switch) || "–"}</td>` : ""}<td>${esc(r.label || r.kind)}</td>`
        + `<td>${esc(r.text)}${cmp(r)}</td></tr>`).join("")
      + `</tbody></table></div>`;
  }

  // The device search of the field (histTerm) into #hi-list, 50 at a time: without a term the view explains itself and asks nothing;
  // the CSV link (the same search as a download, at most history.EXPORT_MAX rows) follows a search with hits
  async function histSearch() {
    clearTimeout(histTimer); histTimer = null;
    const list = $("#hi-list"), tools = $("#hi-tools"), term = histTerm.trim();
    if (!list) return;
    tools.innerHTML = "";
    if (!term) { list._seq = (list._seq || 0) + 1; list.innerHTML = HIST_EXPLAIN; return; }
    const page = await loadPaged(list, "/api/history", { q: term, limit: 50 },
      rows => rows.length ? sightingTable(rows) : `<div class="empty">Keine Sichtungen für „${esc(term)}“.</div>`);
    if (page && Array.isArray(page.rows) && page.rows.length)
      tools.innerHTML = `<a class="btn small" id="hi-csv" href="/api/history.csv${esc(SVLogic.query({ q: term }))}" download>Als CSV</a>`;
  }
  // The events of the group histKind into #ev-list, 50 at a time
  function histEvents() {
    return loadPaged($("#ev-list"), "/api/events", { kind: histKind, limit: 50 }, rows => rows.length ? eventTable(rows) : `<div class="empty">Noch keine Ereignisse.</div>`);
  }
  // The view "Verlauf" (#verlauf): "Wo war ein Gerät?" asks the server HIST_DELAY ms after the last key (Enter at once); a text
  // changed or emptied drops the answer to the text before. The field takes the 100 characters GET /api/history takes (beyond them
  // FastAPI's 422 would be English). A port opens its switch and panel, "Vergleich" the backup comparison
  async function renderVerlauf() {
    const v = $("#view");
    // The netmap says which switch a port can open; without it every port is text
    try { await loadMap(false); } catch (e) { /* the ports as text */ }
    v.innerHTML = `<section class="card"><div class="card-h"><h2>Wo war ein Gerät?</h2><span class="sub">nach MAC, IP oder Name · zuletzt gesehen zuerst</span>
        <div class="right toolrow"><input type="search" id="hi-q" placeholder="MAC, IP oder Name" aria-label="Verlauf durchsuchen" maxlength="100" value="${esc(histTerm)}"><span id="hi-tools"></span></div></div>
        <div id="hi-list">${histTerm.trim() ? `<div class="empty">Lade …</div>` : ""}</div></section>
      <section class="card"><div class="card-h"><h2>Ereignisse</h2><span class="sub">Erreichbarkeit, LLDP-Nachbarn und Änderungen außerhalb von SwitchView · neueste zuerst</span>
        <div class="right toolrow"><select id="ev-kind" aria-label="Art der Ereignisse">${EVENT_KINDS.map(([k, l]) => `<option value="${k}"${k && k === histKind ? " selected" : ""}>${l}</option>`).join("")}</select></div></div>
        <div id="ev-list"><div class="empty">Lade …</div></div></section>`;
    const field = $("#hi-q");
    field.addEventListener("input", () => {
      histTerm = field.value; clearTimeout(histTimer); histTimer = null;
      const list = $("#hi-list"); list._seq = (list._seq || 0) + 1;
      if (histTerm.trim()) histTimer = setTimeout(histSearch, HIST_DELAY); else histSearch();
    });
    field.addEventListener("keydown", e => { if (e.key !== "Enter") return; e.preventDefault(); histTerm = field.value; histSearch(); });
    $("#ev-kind").addEventListener("change", e => { histKind = e.target.value; histEvents(); });
    v.onclick = e => {
      const b = e.target.closest("[data-hsw]"); if (b) return openHit({ sid: +b.dataset.hsw, port: b.dataset.hport }, null);
      const d = e.target.closest("[data-bdiff]"); if (d) return openBackupDiff(+d.dataset.bdiff);
    };
    await Promise.all([histSearch(), histEvents()]);
  }

  // The comparison of backup bid with the one before it (GET /api/backups/{bid}/diff, masked by the server) as a dialog: added lines
  // green, removed ones red. From the backups list and from an event "Konfiguration außerhalb von SwitchView geändert"
  async function openBackupDiff(bid) {
    let t;
    try { t = await api("GET", `/api/backups/${bid}/diff`); } catch (e) { toast(e.message); return; }
    const html = esc(t).split("\n").map(l => l.startsWith("+") && !l.startsWith("+++") ? `<span class="add">${l}</span>`
      : l.startsWith("-") && !l.startsWith("---") ? `<span class="del">${l}</span>` : l).join("\n");
    modal("Änderungen zur vorigen Sicherung", `<pre class="code">${html || "Keine Unterschiede."}</pre>`, [{ label: "Schließen", onClick: closeModal }]);
  }

  // The shells of the switch view's cards "Ereignisse" and "Sicherheitsbefunde" (after "Änderungen"), which loadSwitchHistory fills.
  // The findings come from the last configuration read only where the driver backs it up (the SSH CLI), else from the SNMP access alone
  function switchHistoryCards(s) {
    return `<section class="card"><div class="card-h"><h2>Ereignisse</h2><span class="sub">an diesem Switch, neueste zuerst</span></div><div id="sw-events"><div class="empty">Lade …</div></div></section>
      <section class="card"><div class="card-h"><h2>Sicherheitsbefunde</h2><span class="sub">${has(s, "backup") ? "aus der zuletzt gelesenen Konfiguration und den SNMP-Zugangsdaten"
        : "aus den SNMP-Zugangsdaten (dieser Treiber hat keine Konfigurationssicherung)"}</span></div><div id="sw-findings"><div class="empty">Lade …</div></div></section>`;
  }
  // A finding as a row: its severity, the rule's label with the detail below it, the masked line it points at ("–" for none)
  const findingRow = f => {
    const [txt, cls] = FINDING_SEV[f.severity] || FINDING_SEV.warn;
    return `<tr><td><span class="pill ${cls}">${txt}</span></td><td><b>${esc(f.label)}</b>${f.detail ? `<span class="cellnote">${esc(f.detail)}</span>` : ""}</td>`
      + `<td class="mono">${f.line_no != null ? `Zeile ${esc(f.line_no)}: ${esc(f.line)}` : "–"}</td></tr>`;
  };
  // The events of switch s (10 at a time) and its open findings (critical first, as compliance.open_findings orders them) into the
  // two cards; an answer without rows or findings draws the empty card, a failed one the server's text in its card
  async function loadSwitchHistory(s) {
    const events = loadPaged($("#sw-events"), "/api/events", { switch_id: s.id, limit: 10 },
      rows => rows.length ? eventTable(rows, false) : `<div class="empty">Noch keine Ereignisse.</div>`);
    const box = $("#sw-findings");
    let got = null;
    try { got = await api("GET", `/api/switches/${s.id}/findings`); } catch (e) { if (box) box.innerHTML = `<div class="empty">${esc(e.message)}</div>`; await events; return; }
    const list = got && Array.isArray(got.findings) ? got.findings : [];
    if (box) box.innerHTML = list.length ? `<div class="tbl-wrap"><table><thead><tr><th>Bewertung</th><th>Befund</th><th>Fundstelle</th></tr></thead><tbody>`
      + list.map(findingRow).join("") + `</tbody></table></div>` : `<div class="empty">Keine Befunde.</div>`;
    await events;
  }

  // "Bisher an diesem Port" in the port panel: at a port whose devices history.record keeps (topology.device_port: no Trk, no trunk or
  // member of one, no confirmed uplink) a button that asks the server (loadPortHistory; a panel that asked at every opening would ask
  // at every click on a port), at any other the sentence why there is nothing
  function portHistoryHtml(s, p) {
    const kept = !(p.n.startsWith("Trk") || p.tr || (p.up && p.uc));
    return `<p class="eyebrow">Bisher an diesem Port</p>` + (kept ? `<div id="dr-hist"><button class="btn small" type="button" id="dr-hist-btn">Anzeigen</button></div>`
      : `<p class="note">An Trunks und bestätigten Uplinks zeichnet SwitchView keine Geräte auf.</p>`);
  }
  // The sightings of port p of switch s into #dr-hist, 20 at a time, newest first, each like a learned device of the panel
  async function loadPortHistory(s, p) {
    return loadPaged($("#dr-hist"), "/api/history", { switch_id: s.id, port: p.n, limit: 20 }, rows => rows.length
      ? `<div class="devs">${rows.map(r => `<div class="dev"><div class="dn">${esc(r.name || r.vendor || "unbekannt")}${r.suspect ? SUSPECT_PILL : ""}</div>`
        + `<div>${r.vlan ? chip(r.vlan) : ""}</div><div class="dm">${esc(r.mac)}${r.ip ? " · " + esc(r.ip) : ""}</div>`
        + `<div class="dm when">zuletzt ${esc(fmtTime(r.last_seen))} · zuerst ${esc(fmtTime(r.first_seen))}</div></div>`).join("")}</div>`
      : `<p class="note">Noch keine Geräte an diesem Port aufgezeichnet.</p>`);
  }

  // The overview's groups beyond issueGroups() (same shape: sev, t, sum, items with t, d, go), each only with content and each on its
  // own: a failed request or an answer without the expected fields gives no group (the stubs of older tests answer every URL with the
  // netmap, a list or {}). For an Admin (the route is Admin) "Benachrichtigungen nicht zugestellt" first, crit: the messages that
  // failed in the last 24 hours, of the newest 20 (Task 10), each with its title, way and error, "Öffnen" to the settings - not those
  // an Admin's switch-off dropped (ALERT_SWITCHED_OFF), which failed no delivery; "mehr als" when the day fills the page and more follow;
  // "Sicherheitsbefunde": the open findings per switch (GET /api/compliance), crit when one is critical; "Änderungen außerhalb von
  // SwitchView": the drift events of the last 7 days, at most 20 ("mehr als 20" when the server has more)
  async function extraIssueGroups() {
    const since = new Date(Date.now() - 7 * 864e5).toISOString(), day = new Date(Date.now() - 864e5).toISOString().replace("T", " ").slice(0, 19);
    const [failed, comp, drift] = await Promise.all([roleOk("admin") ? api("GET", "/api/alerts/deliveries?status=failed&limit=20").catch(() => null) : null,
      api("GET", "/api/compliance").catch(() => null), api("GET", "/api/events" + SVLogic.query({ kind: "drift", since, limit: 20 })).catch(() => null)]);
    const g = [];
    try {
      const all = failed && Array.isArray(failed.rows) ? failed.rows : [], recent = all.filter(r => String(r.created_at) >= day);
      const rows = recent.filter(r => r.error !== ALERT_SWITCHED_OFF);
      if (rows.length) g.push({ sev: "crit", t: "Benachrichtigungen nicht zugestellt",
        sum: `${failed.next != null && recent.length === all.length ? "mehr als " : ""}${SVLogic.plural(rows.length, "Meldung", "Meldungen")} in den letzten 24 Stunden`,
        items: rows.map(r => ({ t: r.title, d: `${ALERT_WAYS[r.channel] || r.channel}: ${r.error || "–"}`, go: () => go("settings") })) });
    } catch (e) { /* no group */ }
    try {
      if (comp && comp.total > 0 && Array.isArray(comp.switches) && comp.switches.length)
        g.push({ sev: comp.crit > 0 ? "crit" : "warn", t: "Sicherheitsbefunde",
          sum: `${SVLogic.plural(comp.total, "Befund", "Befunde")} an ${SVLogic.plural(comp.switches.length, "Switch", "Switches")}`,
          items: comp.switches.map(x => ({ t: x.name, d: SVLogic.plural(x.count, "Befund", "Befunde") + (x.crit > 0 ? `, davon ${x.crit} kritisch` : ""),
            go: () => go("switches", x.id) })) });
    } catch (e) { /* no group */ }
    try {
      const rows = drift && Array.isArray(drift.rows) ? drift.rows : [];
      if (rows.length) g.push({ sev: "warn", t: "Änderungen außerhalb von SwitchView", sum: `${drift.next != null ? "mehr als " : ""}${rows.length} in den letzten 7 Tagen`,
        items: rows.map(r => ({ t: r.switch || "–", d: r.text, go: () => go("switches", r.switch_id) })) });
    } catch (e) { /* no group */ }
    return g;
  }
