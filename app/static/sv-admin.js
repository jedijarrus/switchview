"use strict";

  /* ── VLANs: Matrix VLAN × Switch ── */
  async function renderVlans() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    try { await loadMap(!MAP); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    const sw = MAP.switches;
    // One pass over the ports of each switch (SVLogic.vlanCounts); a VLAN without a key there is on none of its ports. Whether the
    // switch has a VLAN at all is its VLAN list of the poll (s.vl): one there without a port is "angelegt", one missing "–"; a switch
    // without a list (not polled yet) cannot say ("?"), and "Angelegt" counts only the switches with one
    const counts = sw.map(s => SVLogic.vlanCounts(s.ports)), has = sw.map(s => (s.vl && s.vl.length ? new Set(s.vl.map(String)) : null));
    const listed = has.filter(Boolean).length;
    const cell = (s, i, id) => {
      const c = counts[i][id], what = `${esc(s.k)} · VLAN ${esc(id)}`;
      if (c) return `<button type="button" class="mcell" data-sw="${s.id}" data-v="${esc(id)}" title="${what}"><span class="u">U ${c.u}</span><span class="t">T ${c.t}</span></button>`;
      if (!has[i]) return `<span class="muted" title="${esc(s.k)}: VLAN-Liste noch nicht gelesen">?</span>`;
      return has[i].has(id) ? `<span class="mdef" title="${what}: angelegt, an keinem Port">angelegt</span>`
        : `<span class="muted" aria-hidden="true" title="${what}: nicht angelegt">–</span><span class="sr-only">nicht angelegt</span>`;
    };
    v.innerHTML = `<section class="card"><div class="card-h"><h2>VLANs je Switch</h2><span class="sub">U = Ports ungetaggt, T = getaggt (Trunks zählen einfach), „angelegt“ = auf dem Switch angelegt, an keinem Port, – = nicht angelegt. Klick öffnet den Switch mit diesem VLAN.</span></div>
      <div class="tbl-wrap"><table class="matrix"><thead><tr><th>VLAN</th><th>Angelegt</th>${sw.map(s => `<th>${esc(s.k)}</th>`).join("")}</tr></thead><tbody>` +
      Object.keys(MAP.vlans).map(id => { const n = has.filter(h => h && h.has(id)).length;
        return `<tr><td>${chip(id, "")}</td><td class="num${n < listed ? " part" : ""}">${n} von ${listed}</td>${sw.map((s, i) => `<td>${cell(s, i, id)}</td>`).join("")}</tr>`; }).join("") +
      `</tbody></table></div></section>`;
    v.querySelector("table").addEventListener("click", e => { const b = e.target.closest(".mcell"); if (!b) return; swVlan = b.dataset.v; swPortFilter = "all"; swText = ""; go("switches", +b.dataset.sw); });
  }

  /* ── Globale Suche: a combobox (WAI-ARIA 1.2) over the listbox #results. The focus stays in #q, whose aria-activedescendant names
     the active hit; the arrows go round, Enter opens the active hit, Escape closes the list (Home/End stay with the field's cursor).
     A search runs SEARCH_DELAY ms after the last keystroke, over an index built once per netmap. ── */
  const q = $("#q"), res = $("#results");
  const SEARCH_DELAY = 150;
  // searchFound: the hits shown (SVLogic.searchIndex entries) and last the history entry {hist: true, text} (Phase 4b: the field's
  // text, at most the 100 characters of GET /api/history, for the view "Verlauf"; also under "Nichts gefunden"); searchActive: the
  // index of the active one, -1 for none; searchTerm: the term searchFound belongs to; searchRun: the promise of the last search
  // started; searchEscapes: the Escapes pressed in the field
  let searchFound = [], searchActive = -1, searchTimer = null, searchTerm = "", searchRun = null, searchEscapes = 0;
  const termOf = () => q.value.trim().toLowerCase().replace(/-/g, ":");
  // The search index of each MAP (MAP is only ever replaced: an old MAP's index goes with it)
  const searchIdxs = new WeakMap();
  function searchIdx() { let idx = searchIdxs.get(MAP); if (!idx) searchIdxs.set(MAP, idx = SVLogic.searchIndex(MAP.switches, peerSet())); return idx; }
  function showResults(on) { res.hidden = !on; q.setAttribute("aria-expanded", String(on)); if (!on) setActive(-1); }
  function setActive(i) {
    if (searchActive >= 0) { const old = document.getElementById("hit-" + searchActive); if (old) old.setAttribute("aria-selected", "false"); }
    searchActive = i;
    const b = i >= 0 ? document.getElementById("hit-" + i) : null;
    if (!b) { q.removeAttribute("aria-activedescendant"); return; }
    b.setAttribute("aria-selected", "true"); q.setAttribute("aria-activedescendant", "hit-" + i); b.scrollIntoView({ block: "nearest" });
  }
  async function runSearch() {
    const term = termOf(), escapes = searchEscapes;
    if (term.length < 2) { searchFound = []; searchTerm = term; showResults(false); return; }
    try { await loadMap(false); } catch (e) { return; }
    // A search that waited for the netmap while the field changed leaves the list to the search of the new text
    if (termOf() !== term) return;
    const hits = SVLogic.searchHits(searchIdx(), term, 30), n = hits.length, hist = { hist: true, text: q.value.trim().slice(0, 100) };
    searchFound = [...hits, hist]; searchTerm = term;
    searchActive = -1; q.removeAttribute("aria-activedescendant");
    res.innerHTML = (n ? hits.map((h, i) => `<button type="button" role="option" id="hit-${i}" aria-selected="false" tabindex="-1" data-i="${i}"><span class="r1">${esc(h.t)}</span><span class="r3">${esc(h.k)} · Port ${esc(h.port)}</span><span class="r2">${esc(h.x)}</span></button>`).join("")
      : `<div class="none" role="option" aria-disabled="true">Nichts gefunden. Uplinks mit vielen Geräten werden nicht durchsucht.</div>`)
      + `<button type="button" role="option" id="hit-${n}" aria-selected="false" tabindex="-1" data-i="${n}" class="hist"><span class="r1">Im Verlauf suchen</span><span class="r2">„${esc(hist.text)}“</span></button>`;
    // A search that ends after the focus left the field (the pause, a slow netmap) does not open the list over the page, nor one
    // that ends after an Escape closed it (its hits are there for the next arrow key)
    showResults(document.activeElement === q && searchEscapes === escapes);
  }
  function startSearch() { clearTimeout(searchTimer); searchTimer = null; return (searchRun = runSearch()); }
  // A hit opens its switch and the port panel (from: where the focus goes back when the panel closes, the search field unless the
  // caller names another: a port of the view "Verlauf" passes null); the history entry searches its text in the view "Verlauf"
  async function openHit(h, from = q) {
    showResults(false);
    if (h.hist) { histTerm = h.text; go("verlauf"); return; }
    swVlan = null; swPortFilter = "all"; swText = ""; go("switches", h.sid);
    for (let i = 0; i < 20 && !$("#plate"); i++) await new Promise(r => setTimeout(r, 100));
    const s = swById(h.sid); if (s) openPort(s, h.port, from);
  }
  q.addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(startSearch, SEARCH_DELAY); });
  q.addEventListener("keydown", async e => {
    // The first Escape only closes the list: Chrome and Edge empty a type=search field on Escape, that stays the second one's. A
    // search still waiting stays closed: the one of the pause does not run (searchTimer stays set, so an arrow key or Enter still
    // runs it), one waiting for the netmap does not open the list (searchEscapes)
    if (e.key === "Escape") { if (!res.hidden) e.preventDefault(); clearTimeout(searchTimer); searchEscapes++; showResults(false); return; }
    const arrow = e.key === "ArrowDown" || e.key === "ArrowUp";
    if (!arrow && e.key !== "Enter") return;
    if (termOf() !== searchTerm) {
      // The list shown is of an older text, the search of the field's text still waits (for the pause: it runs now; for the netmap:
      // the key waits with it). The key then acts on the new list, where no hit is active yet (Enter opens nothing)
      if (arrow) e.preventDefault();
      await (searchTimer ? startSearch() : searchRun);
      if (termOf() !== searchTerm) return;
    }
    if (arrow && searchFound.length) {
      e.preventDefault(); showResults(true); setActive(SVLogic.nextIndex(searchActive, searchFound.length, e.key));
    } else if (e.key === "Enter" && searchActive >= 0) { e.preventDefault(); openHit(searchFound[searchActive]); }
  });
  // Focus leaving the field closes the list (Tab goes on to the next control, the hits take no Tab stop); a press on the list keeps
  // the focus in #q, so the click on a hit still finds the list open
  q.addEventListener("focusout", e => { if (!res.contains(e.relatedTarget)) showResults(false); });
  res.addEventListener("mousedown", e => e.preventDefault());
  res.addEventListener("click", e => { const b = e.target.closest("[data-i]"); if (b) openHit(searchFound[+b.dataset.i]); });
  document.addEventListener("click", e => { if (!e.target.closest(".search")) showResults(false); });

  /* ── Switch anlegen / bearbeiten ── */
  let DRIVERS = null; // GET /api/drivers: [{name, caps, notes}]
  const CAP_TXT = { snmp_vlan: "VLANs", snmp_admin: "An/Aus", snmp_name: "Namen", snmp_poe: "PoE" };
  const capsTxt = caps => [caps.includes("cli") ? "SSH-CLI" + (caps.includes("nac") ? " mit RADIUS/802.1X" : "") + (caps.includes("backup") ? " und Sicherung" : "") : "keine SSH-CLI",
    "SNMP: " + (Object.keys(CAP_TXT).filter(c => caps.includes(c)).map(c => CAP_TXT[c]).join(", ") || "nichts"),
    caps.includes("snmp_autosave") ? "speichert SNMP-Änderungen selbst" : "speichert SNMP-Änderungen nicht selbst"].join(" · ");
  // How SNMP SETs to the switch row s go out spoofable, as the server's insecure_write of /plan names it: null without
  // snmp_rw_insecure, else "v3" (SNMPv3 without authentication: the writing identity is a v3 user) or "v2c" (the community in plain text)
  function insecureKind(s) {
    if (!s.snmp_rw_insecure) return null;
    return (s.snmp_write_via === "rw" ? !!s.snmp_rw_user : s.snmp_version === "3") ? "v3" : "v2c";
  }
  // Loud when SNMP SETs to this switch go out spoofable, by their kind ("v2c", "v3"; empty: secure). For the form, the dialog after
  // saving (insecureKind of the row) and the SNMP preview (insecure_write of the /plan answer).
  function insecureBanner(kind) {
    if (!kind) return "";
    return `<div class="banner crit" role="alert"><span><b>Unsicher:</b> SNMP schreibt hier ${kind === "v3" ? "per SNMPv3 ohne Authentifizierung" : "per SNMPv2c, die Community geht im Klartext übers Netz"}. Wer mitliest, kann damit selbst an diesem Switch schreiben. Empfohlen: eigener SNMPv3-Benutzer mit Auth und Verschlüsselung (authPriv).</span></div>`;
  }
  // Mit welcher Identität SNMP-SETs an diesen Switch gehen, gespeicherter Stand (der Server rechnet es mit poller.write_identity)
  function writeState(s) {
    if (!s.snmp_write) return "";
    if (!s.snmp_write_via) return `<div class="error"><b>SNMP-Schreiben geht so nicht:</b> ${esc(s.snmp_write_error || "kein Schreib-Zugang")}</div>`;
    const rw = s.snmp_write_via === "rw", v3 = rw ? !!s.snmp_rw_user : s.snmp_version === "3";
    const who = v3 ? `SNMPv3-Benutzer „${esc(rw ? s.snmp_rw_user : s.snmp_user)}“` : "v2c-Community";
    return `<p class="note" style="margin:0">Zurzeit: <span class="pill ${s.snmp_rw_insecure ? "crit" : "ok"}">${rw ? "schreibt mit eigenem Schreib-Zugang" : "schreibt mit Lese-Zugang"}</span> ${who}${rw ? "" : ", braucht dafür am Switch Schreibrechte"}</p>`
      + insecureBanner(insecureKind(s));
  }
  // After saving: when SNMP writes to this switch spoofably or not at all, this dialog stays open after a write-relevant change
  // (SVLogic.writeAlertMode "dialog"), else a hint of 8 s says it (writeHint, "hint"). The server alone is the source (GET
  // /api/switches, poller.write_identity).
  const writeHint = row => row.snmp_write_via ? "Gespeichert. Hinweis: SNMP schreibt an diesem Switch unsicher – siehe „Zugang bearbeiten“."
    : "Gespeichert. Hinweis: SNMP-Schreiben geht an diesem Switch so nicht – siehe „Zugang bearbeiten“.";
  function writeAlert(row) {
    modal(`SNMP-Schreiben prüfen: ${row.name}`, `<p style="margin:0">Gespeichert. SNMP-Schreiben an diesem Switch, wie der Server es jetzt sieht:</p>${writeState(row)}`,
      [{ label: "Zugang bearbeiten", onClick: () => editSwitch(row) }, { label: "Verstanden", cls: "primary", onClick: closeModal }]);
  }
  // F2: a stored secret only goes to the address it was entered for. Saving a new address deletes each one not entered anew, and the
  // server names them in "cleared" (PUT /api/switches/{id}, PUT /api/settings, PUT /api/settings/alerts); their names in the toast.
  const SECRET_NAMES = { snmp_community: "Lese-Community", snmp_auth_pass: "Lese-Auth-Kennwort", snmp_priv_pass: "Lese-Priv-Kennwort", ssh_pass: "SSH-Kennwort",
    snmp_rw_community: "Schreib-Community", snmp_rw_auth_pass: "RW-Auth-Kennwort", snmp_rw_priv_pass: "RW-Priv-Kennwort",
    opnsense_key: "OPNsense-API-Key", opnsense_secret: "OPNsense-API-Secret", radius_key: "Shared Secret", pf_pass: "PacketFence-Kennwort", smtp_pass: "Mail-Kennwort" };
  const savedTxt = cleared => cleared && cleared.length ? `Gespeichert. Gelöscht wegen neuer Adresse: ${cleared.map(k => SECRET_NAMES[k] || k).join(", ")}` : "Gespeichert";
  // An address as the server compares it (main.same_destination, less its IP rule): trimmed, without a trailing "/", in any case
  const destTxt = v => String(v == null ? "" : v).trim().replace(/\/+$/, "").toLowerCase();
  // Shows the warning noteId under the input inputId while show holds, and only then makes it the input's description (a hidden
  // element that aria-describedby names would still be read out)
  function syncNote(inputId, noteId, show) {
    $("#" + noteId).hidden = !show;
    if (show) $("#" + inputId).setAttribute("aria-describedby", noteId); else $("#" + inputId).removeAttribute("aria-describedby");
  }
  async function editSwitch(s) {
    const isNew = !s; s = s || { snmp_version: "2c", enabled: 1, sort: 0, zone: "", driver: "procurve", snmp_write: false };
    if (!DRIVERS) { try { DRIVERS = await api("GET", "/api/drivers"); } catch (e) { /* dann bleibt der Treiber, wie er ist */ } }
    const drv = DRIVERS, curDrv = s.driver || "procurve";
    // The zones of the switches (GET /api/switches): one is picked from the list or a new one typed (#f-zone holds the value either
    // way); with none yet, or the list not readable, only the field
    const zones = await api("GET", "/api/switches").then(list => [...new Set((Array.isArray(list) ? list : []).map(x => x.zone || "").filter(Boolean))]
      .sort((x, y) => x.localeCompare(y, "de")), () => []);
    const zoneField = zones.length
      ? `<div class="field"><label for="f-zone-pick">Zone</label><select id="f-zone-pick">${["", ...zones].map(z => `<option value="${esc(z)}"${z === (s.zone || "") ? " selected" : ""}>${z ? esc(z) : "Ohne Zone"}</option>`).join("")}`
        + `<option value="" data-new>Neue Zone …</option></select><input id="f-zone" value="${esc(s.zone || "")}" maxlength="40" placeholder="Name der neuen Zone" aria-label="Neue Zone" hidden></div>`
      : `<label class="field"><span>Zone</span><input id="f-zone" value="${esc(s.zone || "")}" maxlength="40" placeholder="z. B. Büro, Rechenzentrum"></label>`;
    // Ein gespeicherter Treiber, den die Liste nicht kennt (am Server wie generic), bleibt wählbar: sonst wechselte ihn ein Speichern still
    const drvs = !drv ? [{ name: curDrv, caps: s.caps || [], notes: "Treiberliste nicht ladbar, der Treiber bleibt unverändert." }]
      : drv.some(d => d.name === curDrv) ? drv : [...drv, { name: curDrv, caps: s.caps || [], notes: "Unbekannter Treiber, wirkt wie generic (nur Standard-MIBs)." }];
    const KEEP = "gesetzt – leer lassen = unverändert";
    // Geheimnis: leer = unverändert (null), „Löschen“ schickt "" (main.SECRET_FIELDS). Einen Wert liefert der Server nie, nur *_set.
    // „Löschen“ ist ein Umschalter (aria-pressed), sein Text bleibt; der Name nennt das Feld eindeutig (Lese- und RW-Kennwörter heißen
    // sichtbar gleich) und beginnt mit dem sichtbaren Text (WCAG 2.5.3).
    const secret = (id, label, set, what) => `<div class="field"><label for="${id}">${label}</label><div class="sec"><input id="${id}" type="password" autocomplete="new-password" placeholder="${set ? KEEP : ""}">${set ? `<button class="btn small" type="button" data-clr="${id}" aria-pressed="false" aria-label="Löschen: ${what}">Löschen</button>` : ""}</div></div>`;
    // Ein gespeicherter Wert, den die Auswahl nicht kennt, bleibt als eigene Option stehen (sonst nähme ein Speichern still die erste)
    const sel = (id, opts, val) => `<select id="${id}">${(opts.includes(val) ? opts : [...opts, val]).map(o => `<option value="${esc(o)}" ${o === val ? "selected" : ""}>${esc(o || "–")}</option>`).join("")}</select>`;
    const AUTH = ["SHA", "SHA-256", "SHA-512", "MD5"], PRIV = ["AES", "AES-256", "DES", ""];
    // RW-Protokolle: zu einem gespeicherten RW-Benutzer genau wie gespeichert (auch keins), sonst die Empfehlung authPriv (SHA, AES)
    const rwAp = s.snmp_rw_user ? s.snmp_rw_auth_proto || "" : s.snmp_rw_auth_proto || "SHA", rwPp = s.snmp_rw_user ? s.snmp_rw_priv_proto || "" : s.snmp_rw_priv_proto || "AES";
    const rwStored = !!(s.snmp_rw_user || s.snmp_rw_community_set || s.snmp_rw_auth_pass_set || s.snmp_rw_priv_pass_set);
    // A new address deletes every stored secret not entered anew (F2), and keeps the pinned SSH host key (E30): the note says what applies
    const anySecret = Object.keys(s).some(k => k.endsWith("_set") && s[k]);
    const hostNote = ["Neue Adresse:", anySecret ? "Gespeicherte Kennwörter und Communities gelten nur für die alte Adresse. Was du hier nicht neu eingibst, löscht das Speichern." : "",
      s.ssh_host_key_fp ? "Der gemerkte SSH-Hostschlüssel bleibt; ist es ein anderes Gerät, danach „SSH-Hostschlüssel vergessen“." : ""].filter(Boolean).join(" ");
    // The pinned SSH host key by its fingerprints (compare once with "show crypto host-public-key fingerprint" on the switch)
    const hostKey = s.ssh_host_key_fp
      ? `<p class="note" id="f-hostkey" style="margin:0">SSH-Hostschlüssel: <span class="mono">${esc(s.ssh_host_key_fp)}</span> (MD5 <span class="mono">${esc(s.ssh_host_key_md5)}</span>) · gemerkt am ${esc(fmtTime(s.ssh_host_key_at))}</p>
        <div><button class="btn small" type="button" id="f-hostkey-forget">SSH-Hostschlüssel vergessen</button></div>`
      : `<p class="note" id="f-hostkey" style="margin:0">SSH-Hostschlüssel: Noch keiner gemerkt – der erste SSH-Zugriff merkt ihn sich.</p>`;
    const body = `<div class="grid2"><label class="field"><span>Name</span><input id="f-name" value="${esc(s.name || "")}" required maxlength="64"></label>
      <label class="field"><span>Adresse (IP oder Hostname)</span><input id="f-host" value="${esc(s.host || "")}" required maxlength="64"></label>
      <p class="note warn" id="f-host-note" style="margin:0;grid-column:1/-1" hidden>${esc(hostNote)}</p>
      ${zoneField}
      <label class="field"><span>Reihenfolge</span><input id="f-sort" type="number" value="${esc(s.sort || 0)}"></label></div>
      <div class="field"><label for="f-driver">Treiber</label><select id="f-driver" aria-describedby="f-drv-notes f-drv-caps" ${drv ? "" : "disabled"}>${drvs.map(d => `<option value="${esc(d.name)}" ${d.name === curDrv ? "selected" : ""}>${esc(d.name)}</option>`).join("")}</select>
        <span class="hint" id="f-drv-notes"></span><span class="hint" id="f-drv-caps"></span></div>
      <label class="check"><input id="f-enabled" type="checkbox" ${s.enabled ? "checked" : ""}> Aktiv (wird abgefragt und gesichert)</label>
      <fieldset class="fs"><legend>SNMP (lesen)</legend>${(s.cred_warnings || []).map(w => `<p class="note warn" style="margin:0">${esc(w)}</p>`).join("")}<label class="field"><span>Version</span>${sel("f-snmpv", ["2c", "3"], s.snmp_version)}</label>
        <div id="snmp2">${secret("f-comm", "Community", s.snmp_community_set, "Lese-Community")}</div>
        <div id="snmp3" class="grid2"><label class="field"><span>Benutzer</span><input id="f-suser" value="${esc(s.snmp_user || "")}"></label>
          <label class="field"><span>Auth-Verfahren</span>${sel("f-aproto", AUTH, s.snmp_auth_proto || "SHA")}</label>
          ${secret("f-apass", "Auth-Kennwort", s.snmp_auth_pass_set, "Lese-Auth-Kennwort")}<label class="field"><span>Verschlüsselung</span>${sel("f-pproto", PRIV, s.snmp_priv_proto || "AES")}</label>
          ${secret("f-ppass", "Priv-Kennwort", s.snmp_priv_pass_set, "Lese-Priv-Kennwort")}</div></fieldset>
      <fieldset class="fs"><legend>SNMP (schreiben)</legend>
        <label class="check"><input id="f-sw" type="checkbox" aria-describedby="f-sw-hint" ${s.snmp_write ? "checked" : ""}> SNMP darf schreiben</label>
        <p class="note" id="f-sw-hint" style="margin:0"></p>
        ${isNew ? "" : writeState(s)}
        <div id="f-rw" style="display:grid;gap:12px">
          <p class="eyebrow" style="margin:0">Eigener Schreib-Zugang · empfohlen: SNMPv3 mit Auth und Verschlüsselung (authPriv)</p>
          <div class="grid2"><label class="field"><span>v3-Benutzer</span><input id="f-rwuser" value="${esc(s.snmp_rw_user || "")}" maxlength="64" autocomplete="off"></label>
            <label class="field"><span>Auth-Verfahren</span>${sel("f-rwaproto", AUTH, rwAp)}</label>
            ${secret("f-rwapass", "Auth-Kennwort", s.snmp_rw_auth_pass_set, "RW-Auth-Kennwort")}<label class="field"><span>Verschlüsselung</span>${sel("f-rwpproto", PRIV, rwPp)}</label>
            ${secret("f-rwppass", "Priv-Kennwort", s.snmp_rw_priv_pass_set, "RW-Priv-Kennwort")}</div>
          <details class="adv" ${s.snmp_rw_community_set ? "open" : ""}><summary>Statt v3: v2c-Schreib-Community (unsicher)</summary><div style="display:grid;gap:10px;margin-top:10px">
            <div class="banner crit"><span><b>v2c ist unsicher:</b> die Community geht im Klartext übers Netz. Wer sie mitliest, kann damit an diesem Switch schreiben. Nur, wenn der Switch kein SNMPv3 kann.</span></div>
            ${secret("f-rwcomm", "Schreib-Community", s.snmp_rw_community_set, "Schreib-Community")}</div></details>
          <p class="note" style="margin:0">Es schreibt der v3-Benutzer, ohne ihn die v2c-Community, ohne beide der Lese-Zugang oben (er braucht dann am Switch Schreibrechte). Die Community „public“ schreibt nie.</p>
        </div></fieldset>
      <fieldset class="fs" id="f-ssh"><legend>SSH (Sicherung und Änderungen)</legend><p class="note" id="f-ssh-hint" style="margin:0" hidden></p>
        <div class="grid2"><label class="field"><span>Benutzer</span><input id="f-ssh-user" value="${esc(s.ssh_user || "")}" autocomplete="off"></label>${secret("f-ssh-pass", "Kennwort", s.ssh_pass_set, "SSH-Kennwort")}</div>
        ${hostKey}</fieldset>`;
    const buttons = [];
    if (!isNew) buttons.push({ label: "Switch löschen", cls: "danger", onClick: async () => {
      closeModal();
      if (!(await confirmModal("Switch löschen", `<b>${esc(s.name)}</b> mit allen Port-Daten und Sicherungen löschen?`, "Löschen", true))) return editSwitch(s);
      try { await api("DELETE", `/api/switches/${s.id}`); toast("Gelöscht"); await loadMap(true); selSwitch = null; go("switches"); } catch (e) { toast(e.message); }
    } });
    buttons.push({ label: "Abbrechen", onClick: closeModal });
    buttons.push({ label: isNew ? "Anlegen" : "Speichern", cls: "primary", onClick: async btn => {
      const val = id => $("#" + id).value;
      const pw = id => { const x = $("#" + id); return x.closest(".sec").classList.contains("clr") ? "" : x.value === "" ? null : x.value; };
      // Ein verborgener RW-Block (SNMP-Schreiben aus, nichts RW gespeichert) schickt nichts, auch nicht, was vorher darin getippt wurde
      const rwOn = !$("#f-rw").hidden;
      // Ebenso der gesperrte SSH-Block (Treiber ohne CLI): der gespeicherte Zugang bleibt, wie er ist (Benutzer unverändert, Kennwort null)
      const sshOn = !$("#f-ssh").disabled;
      const payload = { name: val("f-name").trim(), host: val("f-host").trim(), zone: val("f-zone").trim(), sort: +val("f-sort") || 0, enabled: $("#f-enabled").checked, snmp_version: val("f-snmpv"),
        snmp_community: pw("f-comm"), snmp_user: val("f-suser").trim() || null, snmp_auth_proto: val("f-aproto") || null, snmp_auth_pass: pw("f-apass"), snmp_priv_proto: val("f-pproto") || null,
        snmp_priv_pass: pw("f-ppass"), ssh_user: sshOn ? val("f-ssh-user").trim() || null : s.ssh_user || null, ssh_pass: sshOn ? pw("f-ssh-pass") : null,
        snmp_rw_community: rwOn ? pw("f-rwcomm") : null, snmp_rw_auth_pass: rwOn ? pw("f-rwapass") : null, snmp_rw_priv_pass: rwOn ? pw("f-rwppass") : null };
      // Treiber, SNMP-Schreiben, RW-Benutzer und seine Protokolle lässt ein PUT ohne sie stehen (api_switches.UPDATE_IF_SENT): beim Anlegen alle,
      // beim Bearbeiten nur, was sich gegenüber dem gespeicherten Stand ändert. Die RW-Protokolle nur zu einem RW-Benutzer (ohne ihn unbenutzt).
      const upd = { snmp_write: $("#f-sw").checked };
      if (drv) upd.driver = val("f-driver");
      if (rwOn) {
        const rwUser = val("f-rwuser").trim() || null; upd.snmp_rw_user = rwUser;
        if (rwUser) { upd.snmp_rw_auth_proto = val("f-rwaproto") || null; upd.snmp_rw_priv_proto = val("f-rwpproto") || null; }
      }
      const was = { driver: curDrv, snmp_write: !!s.snmp_write, snmp_rw_user: s.snmp_rw_user || null, snmp_rw_auth_proto: s.snmp_rw_auth_proto || null, snmp_rw_priv_proto: s.snmp_rw_priv_proto || null };
      Object.entries(upd).forEach(([k, v]) => { if (isNew || v !== was[k]) payload[k] = v; });
      if (!payload.name || !payload.host) { toast("Name und Adresse sind Pflicht"); return; }
      btn.disabled = true;
      try {
        let id = s.id, cleared = [];
        if (isNew) id = (await api("POST", "/api/switches", payload)).id; else cleared = (await api("PUT", `/api/switches/${s.id}`, payload)).cleared;
        // How SNMP writes now is the server's to say (write_identity); spoofable or without write access: after a write-relevant
        // change a dialog that stays open, else a hint instead of the short message (R44)
        const row = await api("GET", "/api/switches").then(list => list.find(x => x.id === id), () => null);
        const mode = SVLogic.writeAlertMode(isNew ? null : s, payload, row);
        closeModal();
        if (mode === "hint") toast(writeHint(row), 8000); else toast(isNew ? "Angelegt, wird abgefragt …" : savedTxt(cleared));
        if (mode === "dialog") writeAlert(row);
        if (isNew) await api("POST", `/api/switches/${id}/poll`).catch(() => {});
        await loadMap(true); go("switches", id);
      } catch (e) { toast(e.message); btn.disabled = false; }
    } });
    modal(isNew ? "Switch hinzufügen" : `Zugang bearbeiten: ${s.name}`, body, buttons);
    // The note on a new address (hostNote): shown while the address differs from the stored one and something stored depends on it
    const syncHost = () => syncNote("f-host", "f-host-note", !isNew && (anySecret || !!s.ssh_host_key_fp) && destTxt($("#f-host").value) !== destTxt(s.host));
    $("#f-host").addEventListener("input", syncHost); syncHost();
    // Forgetting the pinned host key: only for an expected change; the next SSH contact pins the key it is then offered
    const forget = $("#f-hostkey-forget");
    if (forget) forget.addEventListener("click", async () => {
      closeModal();
      if (!(await confirmModal("SSH-Hostschlüssel vergessen", "Nur, wenn sich der Schlüssel erwartet geändert hat (Tausch, neue Firmware). Der nächste SSH-Zugriff merkt sich den dann gemeldeten Schlüssel.", "Vergessen", true))) return editSwitch(s);
      try { await api("DELETE", `/api/switches/${s.id}/ssh-host-key`); toast("SSH-Hostschlüssel vergessen"); } catch (e) { toast(e.message); }
      const row = await api("GET", "/api/switches").then(list => list.find(x => x.id === s.id), () => null);
      editSwitch(row || s);
    });
    // A zone picked fills #f-zone, "Neue Zone …" shows it empty to type into (left empty, the switch has no zone)
    const pick = $("#f-zone-pick");
    if (pick) pick.addEventListener("change", () => {
      const fresh = !!pick.selectedOptions[0] && pick.selectedOptions[0].hasAttribute("data-new"), field = $("#f-zone");
      field.hidden = !fresh; field.value = fresh ? "" : pick.value;
      if (fresh) field.focus();
    });
    const sync = () => { const v3 = $("#f-snmpv").value === "3"; $("#snmp2").hidden = v3; $("#snmp3").hidden = !v3; };
    $("#f-snmpv").addEventListener("change", sync); sync();
    const syncDrv = () => {
      const d = drvs.find(x => x.name === $("#f-driver").value) || drvs[0];
      $("#f-drv-notes").textContent = d.notes || "";
      // Ohne Treiberliste sind die Fähigkeiten unbekannt: dann kein Hinweis aus ihnen (ein leerer Ersatz hieße „keine SSH-CLI“ & Co.)
      const caps = drv ? d.caps || [] : null, cli = !!caps && caps.includes("cli");
      $("#f-drv-caps").textContent = caps ? capsTxt(caps) : "";
      $("#f-sw-hint").hidden = !caps;
      $("#f-sw-hint").textContent = !caps ? "" : (cli ? "Dieser Treiber ändert sonst per SSH: SNMP schreibt nur, wenn SSH nicht geht, und für PoE (PoE geht immer per SNMP)."
        : "Ohne SSH-CLI gehen alle Änderungen an diesem Switch per SNMP; ohne SNMP-Schreiben kann SwitchView hier nur lesen.")
        + (caps.includes("snmp_autosave") ? "" : " SNMP-Änderungen speichert dieser Switch nicht selbst: danach am Switch speichern.");
      // Ohne SSH-CLI öffnet SwitchView keine SSH-Sitzung (R39): der Block ist gesperrt, ein gespeicherter Zugang bleibt unbenutzt erhalten
      $("#f-ssh").disabled = !!caps && !cli;
      $("#f-ssh-hint").hidden = !caps || cli;
      $("#f-ssh-hint").textContent = caps && !cli ? `Treiber ${d.name} hat keine SSH-CLI: SwitchView nutzt hier kein SSH${s.ssh_user || s.ssh_pass_set ? ", der gespeicherte Zugang bleibt unbenutzt erhalten" : ""}.` : "";
    };
    $("#f-driver").addEventListener("change", syncDrv); syncDrv();
    const syncRw = () => { $("#f-rw").hidden = !$("#f-sw").checked && !rwStored; };
    $("#f-sw").addEventListener("change", syncRw); syncRw();
    // „Löschen“ je gespeichertem Geheimnis: markiert es (aria-pressed, rot), beim Speichern geht "" hinaus; noch einmal klicken nimmt es
    // zurück. Der Text des Knopfs bleibt gleich.
    $("#m-body").onclick = e => {
      const b = e.target.closest("[data-clr]"); if (!b) return;
      const inp = $("#" + b.dataset.clr), on = b.getAttribute("aria-pressed") !== "true";
      b.setAttribute("aria-pressed", String(on));
      inp.value = ""; inp.disabled = on; inp.placeholder = on ? "wird beim Speichern gelöscht" : KEEP; inp.closest(".sec").classList.toggle("clr", on);
    };
  }

  /* ── Geräte-Datenbank ── */
  // The PacketFence role a new device starts with (an example value: the role of the client VLAN)
  const DEVICE_ROLE = "vlan_140";
  const KINDS = { drucker: "Drucker", telefon: "Telefon", kamera: "Kamera", iot: "IoT / Sensor", zugang: "Zugangskontrolle", server: "Server", netzwerk: "Netzwerkgerät", sonstiges: "Sonstiges" };
  let ROLES = { configured: false, roles: [] }, devFilter = "all", devText = "";
  const today = () => new Date().toISOString().slice(0, 10);
  const freePill = d => !d.allowed ? `<span class="pill neutral">gesperrt</span>` : d.valid_until && d.valid_until < today() ? `<span class="pill warn">abgelaufen</span>` : `<span class="pill st-known">freigegeben</span>`;
  const pfPill = d => d.pf_state === "ok" && d.pf_error ? `<span class="pill warn" title="${esc(d.pf_error)}">übernommen, Hinweis</span>` : d.pf_state === "ok" ? `<span class="pill ok" title="${esc(fmtTime(d.pf_synced_at))}">übernommen</span>` : d.pf_state === "fehler" ? `<span class="pill crit" title="${esc(d.pf_error || "")}">Fehler</span>` : d.pf_state === "aus" ? `<span class="pill neutral" title="PacketFence-API nicht eingerichtet">nicht verbunden</span>` : `<span class="muted">–</span>`;
  // PacketFence's error under the pill (a title reaches no touch or keyboard user): for "übernommen, Hinweis" and "Fehler"
  const pfNote = d => d.pf_error && (d.pf_state === "ok" || d.pf_state === "fehler") ? `<span class="cellnote">${esc(d.pf_error)}</span>` : "";
  // The flags of GET /api/devices/unknown (api_devices.unknown_devices) as text under the entry's place; uplink_lldp keeps its name
  // for the API and stands for any unconfirmed uplink with a link or a switch as LLDP neighbour, uplink_bm for a port that is one
  // only by a base MAC learned on it
  const UNKNOWN_FLAG_TEXT = { uplink_lldp: () => "Port gilt als Uplink (unbestätigt)",
    uplink_bm: () => "Port gilt als Uplink (unbestätigt): dort wird die Basis-MAC eines Switches gelernt",
    lldp: d => d.lldp ? `hinter LLDP-Gerät „${d.lldp}“` : "hinter LLDP-Gerät", many: d => `Port mit ${d.mc} Geräten` };
  // The tab of the devices view: park (Ohne Zugriff), net (Im Netz), rel (MAC-Freigaben; "Freigaben" is the four-eyes tab), watch (Beobachtung); null until the sessions
  // are there the first time: Ohne Zugriff while a device is parked, else Im Netz. devBehind: Im Netz shows the unknown devices behind
  // an LLDP device or at a port with many devices too
  const DEV_TAB_KEY = "sv.devTab", DEV_OPEN_KEY = "sv.devUnknownOpen";
  const devStored = k => { try { return localStorage.getItem(k); } catch (e) { return null; } };
  const devKeep = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* a private window: not kept */ } };
  let devTab = ["park", "net", "rel", "watch"].includes(devStored(DEV_TAB_KEY)) ? devStored(DEV_TAB_KEY) : null, devBehind = false, devOpen = devStored(DEV_OPEN_KEY) === "1";
  const DEV_TABS = [["park", "Ohne Zugriff"], ["net", "Im Netz"], ["rel", "MAC-Freigaben"], ["watch", "Beobachtung"]];
  const NOISE_FLAGS = ["lldp", "many"];
  // The devices view, one question per tab: who has no access now (sessions PacketFence parked), who is on the network and how
  // (sessions logged in by 802.1X or a MAC release, and devices the switches learned at ports without login), what is released (the
  // device database) and which MACs are watched. A device stands once per tab
  async function renderDevices() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    let list;
    try { [list, ROLES] = await Promise.all([api("GET", "/api/devices"), api("GET", "/api/pf/roles")]); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    // Creating, changing and allowing devices (and the PacketFence sync, which writes there) is Ändern: below it the list only reads
    const may = roleOk("aendern"), tab = devTab || "park";
    const panel = (k, html) => `<div data-panel="${k}" id="dp-${k}" role="tabpanel" aria-labelledby="dt-${k}" style="display:grid;gap:20px"${tab === k ? "" : " hidden"}>${html}</div>`;
    v.innerHTML = `
      ${!ROLES.configured ? `<div class="banner warn">Die PacketFence-API ist nicht eingerichtet (Einstellungen). Freigaben wirken erst, wenn sie in PacketFence stehen.</div>` : ROLES.error ? `<div class="error">PacketFence: ${esc(ROLES.error)}</div>` : ""}
      <div class="dtabs" role="tablist" aria-label="Geräte" id="dtabs">${DEV_TABS.map(([k, l]) => `<button type="button" role="tab" id="dt-${k}" data-tab="${k}" aria-controls="dp-${k}" aria-selected="${tab === k}">${l}<span class="count" id="dn-${k}"></span></button>`).join("")}</div>
      ${panel("park", `<section class="card" id="park-card"><div class="card-h"><h2>Ohne Zugriff</h2></div><div class="empty">Lade …</div></section>`)}
      ${panel("net", `<section class="card" id="auth-card"></section>
        <section class="card"><div class="card-h"><h2><button type="button" class="fold" id="d-fold" aria-expanded="${devOpen}" aria-controls="d-unknown"><span class="chev" aria-hidden="true">›</span>Ohne Anmeldung<span class="count" id="dn-unknown"></span></button></h2><span class="sub">an Ports ohne Anmeldung gelernt und nicht freigegeben: sie haben Zugang, PacketFence fragt dort nicht</span>
          <label class="check right" style="font-size:12.5px"><input type="checkbox" id="d-behind"${devBehind ? " checked" : ""}> auch hinter anderen Geräten <span id="d-behind-n"></span></label></div><div id="d-unknown"${devOpen ? "" : " hidden"}><div id="ulist"><div class="empty">Lade …</div></div></div></section>`)}
      ${panel("rel", `<section class="card"><div class="card-h"><h2>MAC-Freigaben</h2><span class="sub">${list.length} ${list.length === 1 ? "Gerät" : "Geräte"} ohne Zertifikat · ${list.filter(d => !d.allowed).length} gesperrt</span>
        <div class="right toolrow"><div class="seg" role="group" aria-label="MAC-Freigaben filtern" id="df">${[["all", "Alle"], ["allowed", "Freigegeben"], ["blocked", "Gesperrt"], ["err", "Fehler"]].map(([k, l]) => `<button type="button" data-f="${k}" aria-pressed="${devFilter === k}">${l}</button>`).join("")}</div>
          <input type="search" id="dq" placeholder="Name, MAC, Standort" aria-label="MAC-Freigaben durchsuchen" value="${esc(devText)}">
          ${may ? `<button class="btn small" type="button" id="d-sync">Mit PacketFence abgleichen</button><button class="btn small" type="button" id="d-csv">CSV importieren</button><button class="btn small primary" type="button" id="d-add">Gerät freigeben</button>` : ""}</div></div>
        ${may ? "" : `<p class="note gate" id="d-why" style="margin:12px 16px">Geräte anlegen, ändern und freigeben braucht die Rolle „Ändern“.</p>`}
        <div class="tbl-wrap"><table><thead><tr><th>Name</th><th>MAC</th><th>Rolle</th><th>Status</th><th>Anmeldung</th><th>Zuletzt gesehen</th><th>PacketFence</th></tr></thead><tbody id="dbody"></tbody></table></div></section>`)}
      ${panel("watch", `<section class="card"><div class="card-h"><h2>Beobachtungsliste</h2><span class="sub">meldet, wenn eine dieser MAC-Adressen auftaucht, den Port wechselt oder wiederkommt</span></div><div id="w-card"><div class="empty">Lade …</div></div></section>`)}`;
    const show = (k, kept = true) => {
      devTab = k;
      if (kept) devKeep(DEV_TAB_KEY, k);
      document.querySelectorAll("[data-tab]").forEach(b => b.setAttribute("aria-selected", String(b.dataset.tab === k)));
      document.querySelectorAll("[data-panel]").forEach(p => { p.hidden = p.dataset.panel !== k; });
    };
    $("#dtabs").addEventListener("click", e => { const b = e.target.closest("[data-tab]"); if (b) show(b.dataset.tab); });
    const watched = renderWatchInto($("#w-card"));    // the watch list (sv-alerts.js)
    const rows = () => {
      const t = devText.toLowerCase();
      const f = list.filter(d => (devFilter === "all" || (devFilter === "allowed" && d.allowed) || (devFilter === "blocked" && !d.allowed) || (devFilter === "err" && d.pf_state === "fehler"))
        && (!t || [d.name, d.mac, d.location, d.owner, d.role, d.notes, KINDS[d.kind]].some(x => String(x || "").toLowerCase().includes(t))));
      $("#dbody").innerHTML = f.length ? f.map(d => `<tr${may ? ` class="clickrow" data-mac="${esc(d.mac)}"` : ""}><td><b>${esc(d.name)}</b><div class="muted" style="font-size:12px">${esc(KINDS[d.kind] || d.kind)}${d.location ? " · " + esc(d.location) : ""}</div></td>
        <td class="mono">${esc(d.mac)}${d.vendor ? `<div class="muted" style="font-family:var(--sans)">${esc(d.vendor)}</div>` : ""}</td><td>${esc(d.role || "default")}</td><td>${freePill(d)}${d.valid_until ? `<div class="muted" style="font-size:12px">bis ${esc(d.valid_until)}</div>` : ""}</td><td>${authCell(d.mac)}</td>
        <td>${d.seen ? `${esc(d.seen.sw)} · Port ${esc(d.seen.port)} · VLAN ${esc(d.seen.vlan)}${d.seen.ip ? `<div class="mono muted">${esc(d.seen.ip)}</div>` : ""}` : `<span class="muted">nicht gesehen</span>`}</td><td>${pfPill(d)}${pfNote(d)}</td></tr>`).join("")
        : `<tr><td colspan="7" class="muted">${list.length ? "Kein Gerät passt zum Filter." : may ? "Noch keine MAC-Freigaben. Unter „Ohne Zugriff“ oder „Im Netz“ freigeben, oder „Gerät freigeben“." : "Noch keine MAC-Freigaben."}</td></tr>`;
    };
    rows();
    $("#dn-rel").textContent = list.length;
    $("#df").addEventListener("click", e => { const b = e.target.closest("[data-f]"); if (!b) return; devFilter = b.dataset.f; document.querySelectorAll("#df [data-f]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.f === devFilter))); rows(); });
    $("#dq").addEventListener("input", e => { devText = e.target.value.trim(); rows(); });
    if (may) {
      $("#dbody").addEventListener("click", e => { const r = e.target.closest("[data-mac]"); if (r) editDevice(list.find(d => d.mac === r.dataset.mac), false); });
      $("#d-add").addEventListener("click", () => editDevice({ mac: "", name: "", kind: "drucker" }, true));
      $("#d-csv").addEventListener("click", () => openImport());    // the CSV import (sv-triage.js)
      $("#d-sync").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", "/api/devices/sync"); toast(r.ok ? `${r.done} Geräte abgeglichen` : (r.error || `${r.failed} Fehler`)); renderDevices(); } catch (err) { toast(err.message); e.target.disabled = false; } });
    }
    try {
      // With the sessions (sv-auth.js): a parked device stands under "Ohne Zugriff", one logged in (802.1X, MAC release) under
      // "Angemeldet"; "Ohne Anmeldung" lists the unknown ones without a session (a port without login)
      const [got] = await Promise.all([api("GET", "/api/devices/unknown"), loadAuth()]), all = Array.isArray(got) ? got : [];
      const parked = parkedOf(list, all);
      renderParkedInto($("#park-card"), parked, may);
      renderAuthInto($("#auth-card")).then(() => { if ($("#dbody")) rows(); });
      const un = all.filter(d => !authSession(d.mac)), noise = d => (d.flags || []).some(f => NOISE_FLAGS.includes(f));
      const live = authReady() ? SESS.sessions.filter(x => !x.park).length : 0;
      $("#dn-park").textContent = parked.length || ""; $("#dn-park").classList.toggle("alert", parked.length > 0);
      $("#dn-net").textContent = live + un.length;
      if (devTab == null) show(parked.length ? "park" : "net", false);
      $("#dn-unknown").textContent = un.length;
      const unknownFlags = d => (d.flags || []).filter(f => UNKNOWN_FLAG_TEXT[f]).map(f => `<div class="muted">${esc(UNKNOWN_FLAG_TEXT[f](d))}</div>`).join("");
      // The triage (sv-triage.js), only with an answer that carries suggestions: the column "Vorschlag", "neu" and the first
      // sighting, and with Ändern the choice per row with its bar - of the entries shown: a hidden one is not released
      const tri = triageOn(un), pick = tri && may;
      const drawUnknown = () => {
        const shown = un.filter(d => devBehind || !noise(d));
        $("#d-behind-n").textContent = `(${un.filter(noise).length})`;
        $("#ulist").innerHTML = shown.length ? `${pick ? triageBar("net") : ""}<div class="tbl-wrap"><table><thead><tr>${pick ? "<th></th>" : ""}<th>Gerät</th><th>MAC</th><th>Ort</th><th>Port-Zustand</th>${tri ? "<th>Vorschlag</th>" : ""}${may ? "<th></th>" : ""}</tr></thead><tbody>` + shown.map(d =>
          `<tr>${pick ? pickCell(d.mac, true) : ""}<td>${esc(d.name || d.vendor || "unbekannt")}${d.ip ? `<div class="mono muted">${esc(d.ip)}</div>` : ""}${tri ? firstSeenHtml(d) : ""}</td><td class="mono">${esc(d.mac)}${d.vendor && d.name ? `<div class="muted" style="font-family:var(--sans)">${esc(d.vendor)}</div>` : ""}</td>
          <td>${esc(d.sw)} · Port ${esc(d.port)} · ${chip(d.vlan)}${unknownFlags(d)}</td><td>${stPill(stOf(MAP && swById(d.sid), d.st))}</td>${tri ? `<td>${suggestHtml(d.suggest)}</td>` : ""}${may ? `<td><button class="btn small" type="button" data-u="${un.indexOf(d)}">Freigeben</button></td>` : ""}</tr>`).join("") + `</tbody></table></div>`
          : `<div class="empty">${un.length ? "Nur Geräte hinter anderen Geräten (oben einblenden)." : "Keine Geräte ohne Anmeldung."}</div>`;
        if (pick && shown.length) bindTriage($("#ulist"), "net", shown);
      };
      drawUnknown();
      $("#d-behind").addEventListener("change", e => { devBehind = e.target.checked; drawUnknown(); });
      $("#d-fold").addEventListener("click", () => { devOpen = !devOpen; devKeep(DEV_OPEN_KEY, devOpen ? "1" : "0"); $("#d-fold").setAttribute("aria-expanded", String(devOpen)); $("#d-unknown").hidden = !devOpen; });
      $("#ulist").onclick = e => { const b = e.target.closest("[data-u]"); if (!b) return; const d = un[+b.dataset.u]; editDevice(triageDevice(d, `${d.sw} Port ${d.port}`), true, true); };
    } catch (e) { if ($("#ulist")) $("#ulist").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
    await watched;
  }

  // The field "Rolle" of a device form (id): PacketFence's roles to choose from, else text
  const roleFieldHtml = (id, role) => ROLES.roles.length
    ? `<select id="${id}"><option value="">default</option>${ROLES.roles.filter(r => r.name !== "default").map(r => `<option value="${esc(r.name)}" ${role === r.name ? "selected" : ""}>${esc(r.name)}</option>`).join("")}</select><span class="hint">PacketFence ordnet der Rolle das VLAN zu</span>`
    : `<input id="${id}" value="${esc(role)}" maxlength="64" placeholder="default"><span class="hint">${ROLES.configured ? "Rollen aus PacketFence nicht lesbar" : "PacketFence-API nicht eingerichtet, Rolle als Text"}</span>`;
  // The device form; release: "Gerät freigeben" from the card "Ohne Zugriff" or the port panel - the box "Ohne Zertifikat
  // freigeben" ticked (it can still be unticked) and the button "Freigeben", for a new device or a known one
  async function editDevice(d, isNew, release = false) {
    if (!ROLES.configured && !ROLES.roles.length) { try { ROLES = await api("GET", "/api/pf/roles"); } catch (e) { /* egal */ } }
    // A new device starts in DEVICE_ROLE: a release without a role would get PacketFence's role "default"
    const roleField = roleFieldHtml("dv-role", d.role || (isNew ? DEVICE_ROLE : ""));
    // PacketFence's error of a stored device stands above the form (the list shows it under the pill)
    const body = `${!isNew && d.pf_error ? `<div class="banner warn"><span><b>PacketFence:</b> ${esc(d.pf_error)}</span></div>` : ""}<div class="grid2"><label class="field"><span>MAC-Adresse</span><input id="dv-mac" value="${esc(d.mac || "")}" ${isNew ? "" : "readonly"} placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off" required></label>
        <label class="field"><span>Name</span><input id="dv-name" value="${esc(d.name || "")}" maxlength="64" required autocomplete="off"></label>
        <label class="field"><span>Typ</span><select id="dv-kind">${Object.entries(KINDS).map(([k, l]) => `<option value="${k}" ${d.kind === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label class="field"><span>Rolle</span>${roleField}</label>
        <label class="field"><span>Standort</span><input id="dv-loc" value="${esc(d.location || "")}" maxlength="64"></label>
        <label class="field"><span>Verantwortlich</span><input id="dv-owner" value="${esc(d.owner || "")}" maxlength="64"></label></div>
      <label class="field"><span>Notiz</span><textarea id="dv-notes" rows="2" maxlength="500">${esc(d.notes || "")}</textarea></label>
      <fieldset class="fs"><legend>Freigabe</legend><label class="check"><input type="checkbox" id="dv-blocked" ${!isNew && !release && !d.allowed ? "checked" : ""}> Gesperrt (Eintrag bleibt, kein Zugang)</label>
        <label class="field" style="max-width:220px"><span>Gültig bis (optional)</span><input id="dv-until" type="date" value="${esc(d.valid_until || "")}"></label>
        <p class="note" style="margin:0">MAC-Adressen lassen sich fälschen. Nur für Geräte freigeben, die kein Zertifikat können, zum Beispiel Drucker oder Telefone.</p></fieldset>`;
    const btns = [];
    if (!isNew) btns.push({ label: "Löschen", cls: "danger", onClick: async () => {
      closeModal();
      if (!(await confirmModal("Gerät löschen", `<b>${esc(d.name)}</b> (${esc(d.mac)}) löschen? Die Freigabe in PacketFence wird zurückgenommen.`, "Löschen", true))) return editDevice(d, false);
      try { const r = await api("DELETE", `/api/devices/${encodeURIComponent(d.mac)}`); toast(r.warning || `Gelöscht${AUTH_SWITCH_NOTE}`); MAP = null; authAfterChange(d.mac); if (current === "devices") renderDevices(); } catch (e) { toast(e.message); }
    } });
    if (!isNew && !release && roleOk("aendern")) btns.push(reevalButton(d));    // "Neu bewerten" (sv-triage.js)
    btns.push({ label: "Abbrechen", onClick: closeModal });
    btns.push({ label: release || isNew ? "Freigeben" : "Speichern", cls: "primary", onClick: async b => {
      const payload = { mac: $("#dv-mac").value.trim(), name: $("#dv-name").value.trim(), kind: $("#dv-kind").value, role: $("#dv-role").value.trim(), location: $("#dv-loc").value.trim(),
        owner: $("#dv-owner").value.trim(), notes: $("#dv-notes").value.trim(), allowed: !$("#dv-blocked").checked, valid_until: $("#dv-until").value || null };
      if (!payload.mac || !payload.name) { toast("MAC und Name sind Pflicht"); return; }
      b.disabled = true;
      try {
        const r = isNew ? await api("POST", "/api/devices", payload) : await api("PUT", `/api/devices/${encodeURIComponent(d.mac)}`, payload);
        closeModal();
        toast(r.pf && r.pf.ok ? `Gespeichert und in PacketFence übernommen${AUTH_SWITCH_NOTE}` : `Gespeichert. PacketFence: ${(r.pf && (r.pf.error || "Fehler, siehe Liste")) || "–"}`);
        MAP = null; authAfterChange(payload.mac); if (current === "devices") renderDevices();    // the sessions anew until the port switched
      } catch (e) { toast(e.message); b.disabled = false; }
    } });
    modal(release || isNew ? "Gerät freigeben" : `Gerät: ${d.name}`, body, btns);
  }

  /* ── Sicherungen ── */
  async function renderBackups() {
    const v = $("#view");
    const list = await api("GET", "/api/switches").catch(e => { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return null; });
    if (!list) return;
    v.innerHTML = `<section class="card"><div class="card-h"><h2>Konfigurationssicherungen</h2><span class="sub">nächtlich 02:30, gespeichert nur bei Änderung</span>
      <div class="right toolrow"><select id="b-sw" aria-label="Switch">${list.map(s => `<option value="${s.id}" ${s.id === selSwitch ? "selected" : ""}>${esc(s.name)}${!has(s, "backup") ? " (ohne Sicherung)" : s.ssh_pass_set ? "" : " (ohne SSH)"}</option>`).join("")}</select>
      <button class="btn small" type="button" id="b-now" aria-describedby="b-why">Jetzt sichern</button></div></div><p class="note gate" id="b-why" style="margin:12px 16px 0" hidden></p><div id="b-list"><div class="empty">Kein Switch angelegt.</div></div></section>`;
    if (!list.length) return;
    const selected = () => list.find(x => String(x.id) === $("#b-sw").value);
    // Sichern geht nur über die SSH-CLI (Treiber mit backup, ProCurve): sonst ist „Jetzt sichern“ gesperrt, mit dem Grund daneben
    const gate = () => { const sw = selected(), ok = has(sw, "backup"); $("#b-now").disabled = !ok; $("#b-why").hidden = ok;
      $("#b-why").textContent = ok ? "" : `Treiber ${sw ? sw.driver : ""} sichert keine Konfiguration: das geht nur über die SSH-CLI (ProCurve).`; };
    // A backup that differs from the one before it without a SwitchView change between them (outside 1, monitor.backup_outside) is
    // marked in its cell "Anlass"; "Änderungen" shows the comparison (openBackupDiff, sv-history.js)
    const load = async () => {
      gate();
      const id = $("#b-sw").value, rows = await api("GET", `/api/switches/${id}/backups`);
      const sw = list.find(x => String(x.id) === id);
      $("#b-list").innerHTML = rows.length ? `<div class="tbl-wrap"><table><thead><tr><th>Zeitpunkt</th><th>Anlass</th><th>Größe</th><th></th></tr></thead><tbody>` +
        rows.map(r => `<tr><td>${esc(fmtTime(r.taken_at))}</td><td>${r.trigger === "manual" ? "von Hand" : r.trigger === "nightly" ? "nächtlich" : r.trigger === "lesen" ? "gelesen" : esc(r.trigger)}${r.outside === 1 ? ` <span class="pill warn">außerhalb von SwitchView</span>` : ""}</td><td class="num">${(r.size / 1024).toFixed(1).replace(".", ",")} KB</td>
          <td><div class="actions"><button class="btn small" type="button" data-show="${r.id}">Anzeigen</button><button class="btn small" type="button" data-diff="${r.id}">Änderungen</button></div></td></tr>`).join("") + `</tbody></table></div>`
        : `<div class="empty">${!has(sw, "backup") ? "Keine Sicherungen: dieser Treiber sichert nicht." : sw && !sw.ssh_pass_set ? "Für diesen Switch ist noch kein SSH-Zugang hinterlegt (Switches → Zugang bearbeiten)." : "Noch keine Sicherung. „Jetzt sichern“ klicken."}</div>`;
    };
    $("#b-sw").addEventListener("change", load);
    $("#b-now").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", `/api/switches/${$("#b-sw").value}/backup`); toast(r.ok ? (r.changed ? "Gesichert" : "Unverändert") : r.error); await load(); } catch (err) { toast(err.message); } gate(); });
    $("#b-list").addEventListener("click", async e => {
      const s = e.target.closest("[data-show]"), d = e.target.closest("[data-diff]");
      if (s) { const t = await api("GET", `/api/backups/${s.dataset.show}`); modal("Konfiguration", `<pre class="code">${esc(t)}</pre>`, [{ label: "Schließen", onClick: closeModal }]); }
      if (d) await openBackupDiff(+d.dataset.diff);
    });
    load();
  }

  /* ── Protokoll ── */
  // The text of each audit action (api_*.audit / changes.audit); an action without one shows its key
  const AUDIT_LABELS = { login: "Anmeldung", login_failed: "Anmeldung fehlgeschlagen", logout_all: "Überall abgemeldet", switch_create: "Switch angelegt", switch_update: "Switch geändert", switch_delete: "Switch gelöscht", switch_hostkey_reset: "SSH-Hostschlüssel vergessen", backup: "Sicherung", settings_update: "Einstellungen geändert",
    change_ok: "Änderung erledigt", change_unclear: "Änderung unklar", change_failed: "Änderung fehlgeschlagen", change_aborted: "Änderung abgebrochen",
    device_create: "Gerät angelegt", device_update: "Gerät geändert", device_delete: "Gerät gelöscht", device_sync: "PacketFence-Abgleich", device_reevaluate: "Gerät neu bewertet",
    approval_requested: "Freigabe angefordert", approval_approved: "Freigegeben", approval_run: "Freigegebene Änderung gestartet", approval_rejected: "Freigabe abgelehnt",
    approval_withdrawn: "Anfrage zurückgezogen", approval_expired: "Anfrage abgelaufen", approval_stale: "Anfrage veraltet", approval_settings: "Vier-Augen-Einstellung geändert",
    zone_scopes_update: "Zonen geändert", alert_settings: "Benachrichtigungen geändert", alert_test: "Benachrichtigung getestet", alert_failed: "Benachrichtigung nicht zugestellt", compliance_rules: "Sicherheitsregeln geändert", watch_add: "MAC beobachtet", watch_remove: "MAC nicht mehr beobachtet",
    token_create: "API-Token angelegt", token_revoke: "API-Token widerrufen", change_pending: "Änderung wartet auf Bestätigung", change_confirm: "Änderung bestätigt",
    bulk_start: "Sammeländerung gestartet", bulk_done: "Sammeländerung fertig", bulk_failed: "Sammeländerung mit Fehlern", bulk_cancel: "Abbruch einer Sammeländerung angefordert", bulk_cancelled: "Sammeländerung abgebrochen", bulk_interrupted: "Sammeländerung durch Neustart abgebrochen",
    pf_snmp_settings: "SNMP-Benutzer für PacketFence geändert" };
  // The audit log asks the server at every change of a filter (GET /api/audit, SVLogic.auditParams; 100 a page, "Mehr laden" by
  // the cursor, loadPaged): text and user AUDIT_DELAY ms after the last key, which drops the answer to the filter before, the
  // choices at once; "Als CSV" carries what the fields say. Each entry names its user's role then ("–" before Phase 4a) and its
  // detail (never a secret). The filters outlive a new render, like devText; a switch the netmap no longer has is dropped
  let auditText = "", auditAction = "", auditUser = "", auditRole = "", auditSw = "", auditFrom = "", auditTo = "", auditTimer = null; const AUDIT_DELAY = 300;
  const auditFilter = () => ({ text: auditText, action: auditAction, user: auditUser, role: auditRole, sw: auditSw, from: auditFrom, to: auditTo });
  const auditRow = r => `<tr><td class="num time">${esc(fmtTime(r.ts))}</td><td>${esc(r.username || "")}${r.token ? `<span class="cellnote">API-Token „${esc(r.token)}“</span>` : ""}</td><td>${esc(SVLogic.roleLabel(r.role))}</td>`
    + `<td>${esc(AUDIT_LABELS[r.action] || r.action)}${r.detail ? `<span class="cellnote">${esc(r.detail)}</span>` : ""}</td><td class="mono">${esc(r.target || "")}</td></tr>`;
  async function renderAudit() {
    const v = $("#view");
    try { await loadMap(false); } catch (e) { /* the switch filter without switches */ }
    const sws = MAP && Array.isArray(MAP.switches) ? MAP.switches : []; if (!sws.some(s => String(s.id) === auditSw)) auditSw = "";
    const opt = (val, label, cur) => `<option value="${esc(val)}"${val && val === cur ? " selected" : ""}>${esc(label)}</option>`;
    const actions = Object.keys(AUDIT_LABELS).sort((a, b) => AUDIT_LABELS[a].localeCompare(AUDIT_LABELS[b], "de"));
    v.innerHTML = `<section class="card"><div class="card-h"><h2>Änderungen an Switches</h2><span class="sub">neueste zuerst</span></div><div id="all-changes"><div class="empty">Lade …</div></div></section>
      <section class="card"><div class="card-h"><h2>Protokoll</h2><span class="sub">neueste zuerst · gefiltert am Server</span></div>
        <div class="card-b toolrow au-tools"><input type="search" id="au-q" placeholder="Benutzer, Aktion, Ziel, Details" aria-label="Protokoll durchsuchen" value="${esc(auditText)}" maxlength="100">
          <select id="au-act" aria-label="Aktion">${opt("", "Alle Aktionen", auditAction)}${actions.map(a => opt(a, AUDIT_LABELS[a], auditAction)).join("")}</select>
          <input type="search" id="au-user" placeholder="Benutzer" aria-label="Benutzer" value="${esc(auditUser)}" maxlength="100">
          <select id="au-role" aria-label="Rolle">${opt("", "Alle Rollen", auditRole)}${["lesen", "aendern", "freigeben", "admin"].map(k => opt(k, SVLogic.roleLabel(k), auditRole)).join("")}${opt("none", "ohne Rolle", auditRole)}</select>
          <select id="au-sw" aria-label="Switch">${opt("", "Alle Switches", auditSw)}${sws.map(s => opt(String(s.id), s.k, auditSw)).join("")}</select>
          <input type="date" id="au-from" aria-label="Von" value="${esc(auditFrom)}"><input type="date" id="au-to" aria-label="Bis" value="${esc(auditTo)}">
          <a class="btn small" id="au-csv" href="/api/audit.csv${esc(SVLogic.auditParams(auditFilter(), false))}" download>Als CSV</a></div>
        <div id="au-list"><div class="empty">Lade …</div></div></section>`;
    v.style.display = ""; renderChangesInto($("#all-changes"), null, 100);
    const list = $("#au-list");
    // A load whose view was replaced meanwhile (the pause ran out after a new render or another view) asks nothing
    const load = () => {
      clearTimeout(auditTimer); auditTimer = null;
      if ($("#au-list") !== list) return null;
      const f = auditFilter(), any = SVLogic.auditParams(f, false) !== "";
      return loadPaged(list, "/api/audit", cursor => SVLogic.auditParams({ ...f, cursor }), rows => rows.length
        ? `<div class="tbl-wrap"><table><thead><tr><th>Zeit</th><th>Benutzer</th><th>Rolle</th><th>Aktion</th><th>Ziel</th></tr></thead><tbody>${rows.map(auditRow).join("")}</tbody></table></div>`
        : `<div class="empty">${any ? "Keine Einträge für diesen Filter." : "Noch keine Einträge."}</div>`);
    };
    const on = (id, type, set) => $("#" + id).addEventListener(type, e => {
      set(e.target.value); $("#au-csv").setAttribute("href", "/api/audit.csv" + SVLogic.auditParams(auditFilter(), false));
      if (type === "change") return load();
      list._seq = (list._seq || 0) + 1; clearTimeout(auditTimer); auditTimer = setTimeout(load, AUDIT_DELAY);
    });
    on("au-q", "input", x => { auditText = x; }); on("au-user", "input", x => { auditUser = x; });
    on("au-act", "change", x => { auditAction = x; }); on("au-role", "change", x => { auditRole = x; }); on("au-sw", "change", x => { auditSw = x; });
    on("au-from", "change", x => { auditFrom = x; }); on("au-to", "change", x => { auditTo = x; });
    await load();
  }
