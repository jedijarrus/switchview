"use strict";

  /* ── VLANs: Matrix VLAN × Switch ── */
  async function renderVlans() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    try { await loadMap(!MAP); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    const sw = MAP.switches;
    // One pass over the ports of each switch (SVLogic.vlanCounts); a VLAN without a key there is on none of its ports
    const counts = sw.map(s => SVLogic.vlanCounts(s.ports));
    v.innerHTML = `<section class="card"><div class="card-h"><h2>VLANs je Switch</h2><span class="sub">U = Ports ungetaggt, T = getaggt (Trunks zählen einfach). Klick öffnet den Switch mit diesem VLAN.</span></div>
      <div class="tbl-wrap"><table class="matrix"><thead><tr><th>VLAN</th>${sw.map(s => `<th>${esc(s.k)}</th>`).join("")}</tr></thead><tbody>` +
      Object.keys(MAP.vlans).map(id => `<tr><td>${chip(id, "")}</td>${sw.map((s, i) => { const c = counts[i][id];
        return `<td>${c ? `<button type="button" class="mcell" data-sw="${s.id}" data-v="${esc(id)}" title="${esc(s.k)} · VLAN ${esc(id)}"><span class="u">U ${c.u}</span><span class="t">T ${c.t}</span></button>` : `<span class="muted">–</span>`}</td>`; }).join("")}</tr>`).join("") +
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
      <label class="field"><span>Zone</span><input id="f-zone" value="${esc(s.zone || "")}" maxlength="40" placeholder="z. B. Büro, Rechenzentrum"></label>
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
  const KINDS = { drucker: "Drucker", telefon: "Telefon", kamera: "Kamera", iot: "IoT / Sensor", zugang: "Zugangskontrolle", server: "Server", netzwerk: "Netzwerkgerät", sonstiges: "Sonstiges" };
  let ROLES = { configured: false, roles: [] }, devFilter = "all", devText = "";
  const today = () => new Date().toISOString().slice(0, 10);
  const freePill = d => !d.allowed ? `<span class="pill neutral">nicht freigegeben</span>` : d.valid_until && d.valid_until < today() ? `<span class="pill warn">abgelaufen</span>` : `<span class="pill st-known">freigegeben</span>`;
  const pfPill = d => d.pf_state === "ok" && d.pf_error ? `<span class="pill warn" title="${esc(d.pf_error)}">übernommen, Hinweis</span>` : d.pf_state === "ok" ? `<span class="pill ok" title="${esc(fmtTime(d.pf_synced_at))}">übernommen</span>` : d.pf_state === "fehler" ? `<span class="pill crit" title="${esc(d.pf_error || "")}">Fehler</span>` : d.pf_state === "aus" ? `<span class="pill neutral" title="PacketFence-API nicht eingerichtet">nicht verbunden</span>` : `<span class="muted">–</span>`;
  // PacketFence's error under the pill (a title reaches no touch or keyboard user): for "übernommen, Hinweis" and "Fehler"
  const pfNote = d => d.pf_error && (d.pf_state === "ok" || d.pf_state === "fehler") ? `<span class="cellnote">${esc(d.pf_error)}</span>` : "";
  // The flags of GET /api/devices/unknown (api_devices.unknown_devices) as text under the entry's place; uplink_lldp keeps its name
  // for the API and stands for any unconfirmed uplink with a link or a switch as LLDP neighbour, uplink_bm for a port that is one
  // only by a base MAC learned on it
  const UNKNOWN_FLAG_TEXT = { uplink_lldp: () => "Port gilt als Uplink (unbestätigt)",
    uplink_bm: () => "Port gilt als Uplink (unbestätigt): dort wird die Basis-MAC eines Switches gelernt",
    lldp: d => d.lldp ? `hinter LLDP-Gerät „${d.lldp}“` : "hinter LLDP-Gerät", many: d => `Port mit ${d.mc} Geräten` };
  async function renderDevices() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    let list;
    try { [list, ROLES] = await Promise.all([api("GET", "/api/devices"), api("GET", "/api/pf/roles")]); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    // Creating, changing and allowing devices (and the PacketFence sync, which writes there) is Ändern: below it the list only reads
    const may = roleOk("aendern");
    v.innerHTML = `
      ${!ROLES.configured ? `<div class="banner warn">Die PacketFence-API ist nicht eingerichtet (Einstellungen). Freigaben wirken erst, wenn sie in PacketFence stehen.</div>` : ROLES.error ? `<div class="error">PacketFence: ${esc(ROLES.error)}</div>` : ""}
      <section class="card"><div class="card-h"><h2>Geräte</h2><span class="sub">${list.length} bekannt · ${list.filter(d => d.allowed).length} ohne Zertifikat freigegeben</span>
        <div class="right toolrow"><div class="seg" role="group" aria-label="Geräte filtern" id="df">${[["all", "Alle"], ["allowed", "Freigegeben"], ["blocked", "Nicht freigegeben"], ["err", "Fehler"]].map(([k, l]) => `<button type="button" data-f="${k}" aria-pressed="${devFilter === k}">${l}</button>`).join("")}</div>
          <input type="search" id="dq" placeholder="Name, MAC, Standort" aria-label="Geräte durchsuchen" value="${esc(devText)}">
          ${may ? `<button class="btn small" type="button" id="d-sync">Mit PacketFence abgleichen</button><button class="btn small primary" type="button" id="d-add">Gerät hinzufügen</button>` : ""}</div></div>
        ${may ? "" : `<p class="note gate" id="d-why" style="margin:12px 16px">Geräte anlegen, ändern und freigeben braucht die Rolle „Ändern“.</p>`}
        <div class="tbl-wrap"><table><thead><tr><th>Name</th><th>MAC</th><th>Rolle</th><th>Freigabe</th><th>Zuletzt gesehen</th><th>PacketFence</th></tr></thead><tbody id="dbody"></tbody></table></div></section>
      <section class="card"><div class="card-h"><h2>Unbekannte Geräte an Zugangsports</h2><span class="sub">noch nicht in der Datenbank · Einträge hinter LLDP-Geräten, unbestätigten Uplinks oder an Ports mit vielen Geräten stehen markiert am Ende</span></div><div id="ulist"><div class="empty">Lade …</div></div></section>
      <section class="card"><div class="card-h"><h2>Beobachtungsliste</h2><span class="sub">meldet, wenn eine dieser MAC-Adressen auftaucht, den Port wechselt oder wiederkommt</span></div><div id="w-card"><div class="empty">Lade …</div></div></section>`;
    const watched = renderWatchInto($("#w-card"));    // the watch list (sv-alerts.js), beside the unknown devices
    const rows = () => {
      const t = devText.toLowerCase();
      const f = list.filter(d => (devFilter === "all" || (devFilter === "allowed" && d.allowed) || (devFilter === "blocked" && !d.allowed) || (devFilter === "err" && d.pf_state === "fehler"))
        && (!t || [d.name, d.mac, d.location, d.owner, d.role, d.notes, KINDS[d.kind]].some(x => String(x || "").toLowerCase().includes(t))));
      $("#dbody").innerHTML = f.length ? f.map(d => `<tr${may ? ` class="clickrow" data-mac="${esc(d.mac)}"` : ""}><td><b>${esc(d.name)}</b><div class="muted" style="font-size:12px">${esc(KINDS[d.kind] || d.kind)}${d.location ? " · " + esc(d.location) : ""}</div></td>
        <td class="mono">${esc(d.mac)}${d.vendor ? `<div class="muted" style="font-family:var(--sans)">${esc(d.vendor)}</div>` : ""}</td><td>${esc(d.role || "default")}</td><td>${freePill(d)}${d.valid_until ? `<div class="muted" style="font-size:12px">bis ${esc(d.valid_until)}</div>` : ""}</td>
        <td>${d.seen ? `${esc(d.seen.sw)} · Port ${esc(d.seen.port)} · VLAN ${esc(d.seen.vlan)}${d.seen.ip ? `<div class="mono muted">${esc(d.seen.ip)}</div>` : ""}` : `<span class="muted">nicht gesehen</span>`}</td><td>${pfPill(d)}${pfNote(d)}</td></tr>`).join("")
        : `<tr><td colspan="6" class="muted">${list.length ? "Kein Gerät passt zum Filter." : may ? "Noch keine Geräte. Unten aus den unbekannten übernehmen oder „Gerät hinzufügen“." : "Noch keine Geräte."}</td></tr>`;
    };
    rows();
    $("#df").addEventListener("click", e => { const b = e.target.closest("[data-f]"); if (!b) return; devFilter = b.dataset.f; document.querySelectorAll("#df [data-f]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.f === devFilter))); rows(); });
    $("#dq").addEventListener("input", e => { devText = e.target.value.trim(); rows(); });
    if (may) {
      $("#dbody").addEventListener("click", e => { const r = e.target.closest("[data-mac]"); if (r) editDevice(list.find(d => d.mac === r.dataset.mac), false); });
      $("#d-add").addEventListener("click", () => editDevice({ mac: "", name: "", kind: "drucker" }, true));
      $("#d-sync").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", "/api/devices/sync"); toast(r.ok ? `${r.done} Geräte abgeglichen` : (r.error || `${r.failed} Fehler`)); renderDevices(); } catch (err) { toast(err.message); e.target.disabled = false; } });
    }
    try {
      const un = await api("GET", "/api/devices/unknown");
      const unknownFlags = d => (d.flags || []).filter(f => UNKNOWN_FLAG_TEXT[f]).map(f => `<div class="muted">${esc(UNKNOWN_FLAG_TEXT[f](d))}</div>`).join("");
      if (!$("#ulist")) return;
      $("#ulist").innerHTML = un.length ? `<div class="tbl-wrap"><table><thead><tr><th>Gerät</th><th>MAC</th><th>Ort</th><th>Port-Zustand</th>${may ? "<th></th>" : ""}</tr></thead><tbody>` + un.map((d, i) =>
        `<tr><td>${esc(d.name || d.vendor || "unbekannt")}${d.ip ? `<div class="mono muted">${esc(d.ip)}</div>` : ""}</td><td class="mono">${esc(d.mac)}${d.vendor && d.name ? `<div class="muted" style="font-family:var(--sans)">${esc(d.vendor)}</div>` : ""}</td>
          <td>${esc(d.sw)} · Port ${esc(d.port)} · ${chip(d.vlan)}${unknownFlags(d)}</td><td>${stPill(stOf(MAP && swById(d.sid), d.st))}</td>${may ? `<td><button class="btn small" type="button" data-u="${i}">Übernehmen</button></td>` : ""}</tr>`).join("") + `</tbody></table></div>`
        : `<div class="empty">Keine unbekannten Geräte an Zugangsports.</div>`;
      $("#ulist").onclick = e => { const b = e.target.closest("[data-u]"); if (!b) return; const d = un[+b.dataset.u]; editDevice({ mac: d.mac, name: (d.name || "").replace(/\..*$/, ""), kind: "sonstiges", location: `${d.sw} Port ${d.port}` }, true); };
    } catch (e) { if ($("#ulist")) $("#ulist").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
    await watched;
  }

  async function editDevice(d, isNew) {
    if (!ROLES.configured && !ROLES.roles.length) { try { ROLES = await api("GET", "/api/pf/roles"); } catch (e) { /* egal */ } }
    const roleField = ROLES.roles.length
      ? `<select id="dv-role"><option value="">default</option>${ROLES.roles.filter(r => r.name !== "default").map(r => `<option value="${esc(r.name)}" ${d.role === r.name ? "selected" : ""}>${esc(r.name)}</option>`).join("")}</select><span class="hint">PacketFence ordnet der Rolle das VLAN zu</span>`
      : `<input id="dv-role" value="${esc(d.role || "")}" maxlength="64" placeholder="default"><span class="hint">${ROLES.configured ? "Rollen aus PacketFence nicht lesbar" : "PacketFence-API nicht eingerichtet, Rolle als Text"}</span>`;
    // PacketFence's error of a stored device stands above the form (the list shows it under the pill)
    const body = `${!isNew && d.pf_error ? `<div class="banner warn"><span><b>PacketFence:</b> ${esc(d.pf_error)}</span></div>` : ""}<div class="grid2"><label class="field"><span>MAC-Adresse</span><input id="dv-mac" value="${esc(d.mac || "")}" ${isNew ? "" : "readonly"} placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off" required></label>
        <label class="field"><span>Name</span><input id="dv-name" value="${esc(d.name || "")}" maxlength="64" required autocomplete="off"></label>
        <label class="field"><span>Typ</span><select id="dv-kind">${Object.entries(KINDS).map(([k, l]) => `<option value="${k}" ${d.kind === k ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label class="field"><span>Rolle</span>${roleField}</label>
        <label class="field"><span>Standort</span><input id="dv-loc" value="${esc(d.location || "")}" maxlength="64"></label>
        <label class="field"><span>Verantwortlich</span><input id="dv-owner" value="${esc(d.owner || "")}" maxlength="64"></label></div>
      <label class="field"><span>Notiz</span><textarea id="dv-notes" rows="2" maxlength="500">${esc(d.notes || "")}</textarea></label>
      <fieldset class="fs"><legend>Freigabe</legend><label class="check"><input type="checkbox" id="dv-allowed" ${d.allowed ? "checked" : ""}> Ohne Zertifikat freigeben (MAC-Anmeldung an Ports „RADIUS“ und „Bekannte Geräte“)</label>
        <label class="field" style="max-width:220px"><span>Gültig bis (optional)</span><input id="dv-until" type="date" value="${esc(d.valid_until || "")}"></label>
        <p class="note" style="margin:0">MAC-Adressen lassen sich fälschen. Nur für Geräte freigeben, die kein Zertifikat können, zum Beispiel Drucker oder Telefone.</p></fieldset>`;
    const btns = [];
    if (!isNew) btns.push({ label: "Löschen", cls: "danger", onClick: async () => {
      closeModal();
      if (!(await confirmModal("Gerät löschen", `<b>${esc(d.name)}</b> (${esc(d.mac)}) löschen? Die Freigabe in PacketFence wird zurückgenommen.`, "Löschen", true))) return editDevice(d, false);
      try { const r = await api("DELETE", `/api/devices/${encodeURIComponent(d.mac)}`); toast(r.warning || "Gelöscht"); MAP = null; if (current === "devices") renderDevices(); } catch (e) { toast(e.message); }
    } });
    btns.push({ label: "Abbrechen", onClick: closeModal });
    btns.push({ label: isNew ? "Anlegen" : "Speichern", cls: "primary", onClick: async b => {
      const payload = { mac: $("#dv-mac").value.trim(), name: $("#dv-name").value.trim(), kind: $("#dv-kind").value, role: $("#dv-role").value.trim(), location: $("#dv-loc").value.trim(),
        owner: $("#dv-owner").value.trim(), notes: $("#dv-notes").value.trim(), allowed: $("#dv-allowed").checked, valid_until: $("#dv-until").value || null };
      if (!payload.mac || !payload.name) { toast("MAC und Name sind Pflicht"); return; }
      b.disabled = true;
      try {
        const r = isNew ? await api("POST", "/api/devices", payload) : await api("PUT", `/api/devices/${encodeURIComponent(d.mac)}`, payload);
        closeModal();
        toast(r.pf && r.pf.ok ? "Gespeichert und in PacketFence übernommen" : `Gespeichert. PacketFence: ${(r.pf && (r.pf.error || "Fehler, siehe Liste")) || "–"}`);
        MAP = null; if (current === "devices") renderDevices();
      } catch (e) { toast(e.message); b.disabled = false; }
    } });
    modal(isNew ? "Gerät hinzufügen" : `Gerät: ${d.name}`, body, btns);
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
    device_create: "Gerät angelegt", device_update: "Gerät geändert", device_delete: "Gerät gelöscht", device_sync: "PacketFence-Abgleich",
    approval_requested: "Freigabe angefordert", approval_approved: "Freigegeben", approval_run: "Freigegebene Änderung gestartet", approval_rejected: "Freigabe abgelehnt",
    approval_withdrawn: "Anfrage zurückgezogen", approval_expired: "Anfrage abgelaufen", approval_stale: "Anfrage veraltet", approval_settings: "Vier-Augen-Einstellung geändert",
    zone_scopes_update: "Zonen geändert", alert_settings: "Benachrichtigungen geändert", alert_test: "Benachrichtigung getestet", alert_failed: "Benachrichtigung nicht zugestellt", compliance_rules: "Sicherheitsregeln geändert", watch_add: "MAC beobachtet", watch_remove: "MAC nicht mehr beobachtet" };
  // The audit log asks the server at every change of a filter (GET /api/audit, SVLogic.auditParams; 100 a page, "Mehr laden" by
  // the cursor, loadPaged): text and user AUDIT_DELAY ms after the last key, which drops the answer to the filter before, the
  // choices at once; "Als CSV" carries what the fields say. Each entry names its user's role then ("–" before Phase 4a) and its
  // detail (never a secret). The filters outlive a new render, like devText; a switch the netmap no longer has is dropped
  let auditText = "", auditAction = "", auditUser = "", auditRole = "", auditSw = "", auditFrom = "", auditTo = "", auditTimer = null; const AUDIT_DELAY = 300;
  const auditFilter = () => ({ text: auditText, action: auditAction, user: auditUser, role: auditRole, sw: auditSw, from: auditFrom, to: auditTo });
  const auditRow = r => `<tr><td class="num time">${esc(fmtTime(r.ts))}</td><td>${esc(r.username || "")}</td><td>${esc(SVLogic.roleLabel(r.role))}</td>`
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

  /* ── Einstellungen ── */
  // The settings and the zone list (GET /api/zone-scopes, kept in a textarea: SVLogic.formatScopes / parseScopes). Changing them is
  // Admin: below it every field is locked and the save buttons are gone, the card says why; what only reads (names, PacketFence test)
  // and ending the own sessions stay. The cards of sv-alerts.js ask beside them, each on its own (a failure is its card's text):
  // "Sicherheitsregeln" for everyone, "Benachrichtigungen" only for an Admin
  async function renderSettings() {
    const v = $("#view"), failed = e => ({ error: e.message });
    const cards = Promise.all([api("GET", "/api/compliance/rules").catch(failed), roleOk("admin") ? api("GET", "/api/settings/alerts").catch(failed) : null]);
    const got = await Promise.all([api("GET", "/api/settings"), api("GET", "/api/zone-scopes")])
      .catch(e => { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return null; });
    if (!got) return;
    const [s, scopes] = got, [rules, alertSet] = await cards, admin = roleOk("admin"), dis = admin ? "" : " disabled";
    // Stored entries the field cannot hold as they are (SVLogic.lossyScopes): named above it, so a save does not change them unseen;
    // that saving would change them is said to an Admin only, who has the button
    const lossy = SVLogic.lossyScopes(scopes.entries);
    const destNote = id => `<p class="note warn" id="${id}-note" style="margin:0" hidden>Neue Adresse: Das gespeicherte Kennwort bzw. der API-Schlüssel gilt nur für die alte Adresse. Was du hier nicht neu eingibst, löscht das Speichern.</p>`;
    const tlsNote = id => `<p class="note warn" id="${id}-note" style="margin:0" hidden>Ohne TLS-Prüfung (oder mit http://) kann jemand im Netz Kennwort bzw. API-Schlüssel mitlesen.</p>`;
    v.innerHTML = `<section class="card"><div class="card-h"><h2>Einstellungen</h2></div><div class="card-b" style="display:grid;gap:16px;max-width:640px">
      ${admin ? "" : `<p class="note gate">Einstellungen ändern braucht die Rolle „Admin“.</p>`}
      <label class="field"><span>Abfrage-Intervall (Minuten)</span><input id="s-poll" type="number" min="5" max="1440" value="${esc(s.poll_minutes)}"${dis}></label>
      <fieldset class="fs"><legend>Gerätenamen aus der OPNsense (ARP-Tabelle)</legend>
        <label class="field"><span>Adresse</span><input id="s-url" value="${esc(s.opnsense_url)}" placeholder="https://opnsense.example.com"${dis}><span class="hint">API-Benutzer mit Recht „Diagnostics: ARP Table“</span></label>
        ${destNote("s-url")}
        <div class="grid2">${secretInput(s, "s-key", "API-Key", "opnsense_key", s.opnsense_key_set, { disabled: !admin })}
        ${secretInput(s, "s-secret", "API-Secret", "opnsense_secret", s.opnsense_secret_set, { disabled: !admin })}</div>
        <label class="check"><input id="s-tls" type="checkbox" ${s.opnsense_verify_tls ? "checked" : ""}${dis}> TLS-Zertifikat prüfen</label>
        ${tlsNote("s-tls")}
        <div><button class="btn small" type="button" id="s-names">Namen jetzt aktualisieren</button></div></fieldset>
      <fieldset class="fs"><legend>RADIUS und PacketFence</legend>
        <div class="grid2"><label class="field"><span>RADIUS-Server (PacketFence-IP)</span><input id="s-rs" value="${esc(s.radius_server)}" placeholder="IP-Adresse"${dis}><span class="hint">wird beim „Vorbereiten“ eines Switches eingetragen</span></label>
        ${secretInput(s, "s-rk", "Shared Secret der Switches", "radius_key", s.radius_key_set, { hint: "wie in PacketFence beim Switch hinterlegt", disabled: !admin })}</div>
        ${destNote("s-rs")}
        <label class="field"><span>PacketFence-API</span><input id="s-pfu" value="${esc(s.pf_url)}" placeholder="https://packetfence:9999"${dis}><span class="hint">für die Geräte-Freigaben (Nodes mit Rolle)</span></label>
        ${destNote("s-pfu")}
        <div class="grid2"><label class="field"><span>API-Benutzer</span><input id="s-pfuser" value="${esc(s.pf_user)}" autocomplete="off"${dis}></label>
        ${secretInput(s, "s-pfpass", "API-Kennwort", "pf_pass", s.pf_pass_set, { disabled: !admin })}</div>
        <label class="check"><input id="s-pftls" type="checkbox" ${s.pf_verify_tls ? "checked" : ""}${dis}> TLS-Zertifikat prüfen</label>
        ${tlsNote("s-pftls")}
        <div><button class="btn small" type="button" id="s-pftest">PacketFence testen</button></div></fieldset>
      ${admin ? `<div><button class="btn primary" type="button" id="s-save">Speichern</button></div>` : ""}</div></section>
      <section class="card"><div class="card-h"><h2>Zonen</h2></div><div class="card-b" style="display:grid;gap:12px;max-width:640px">
        <p class="note" style="margin:0">Benutzer mit „Ändern“ oder „Freigeben“ und einer dieser Entra-App-Rollen ändern nur Switches dieser Zonen. Wer keine trägt, ist nicht beschränkt.</p>
        ${lossy.length ? `<p class="note warn" id="s-scopes-lossy" style="margin:0">Diese Einträge zeigt das Feld nicht so, wie sie gespeichert sind: ${lossy.map(x => `„${esc(x)}“`).join(", ")}. Eine Zone mit Komma oder mit dem Namen „Ohne Zone“ und eine App-Rolle mit „=“ oder „#“ am Anfang lassen sich hier nicht schreiben${admin ? "; „Zonen speichern“ würde sie ändern" : ""}.</p>` : ""}
        <label class="field"><span>Eine Zeile je App-Rolle</span><textarea id="s-scopes" rows="4" placeholder="SwitchView.Zone.EK = EK, Lager" aria-describedby="s-scopes-hint${lossy.length ? " s-scopes-lossy" : ""}"${dis}></textarea><span class="hint" id="s-scopes-hint">„Ohne Zone“ steht für Switches ohne Zone.</span></label>
        ${admin ? `<div><button class="btn small" type="button" id="s-zones-save">Zonen speichern</button></div>` : ""}</div></section>
      <section class="card"><div class="card-h"><h2>Vier-Augen-Prinzip</h2></div><div class="card-b" style="display:grid;gap:12px;max-width:640px">
        <label class="check"><input type="checkbox" id="s-4e"${s.four_eyes ? " checked" : ""}${dis}> Änderungen im Expertenmodus brauchen die Freigabe durch eine zweite Person (Rolle „Freigeben“ oder „Admin“)</label>
        <label class="field" style="max-width:220px"><span>Anfragen verfallen nach (Stunden)</span><input id="s-4h" type="number" min="1" max="168" value="${esc(s.approval_hours)}"${dis}></label>
        <p class="note warn" style="margin:0">Niemand kann die eigene Anfrage freigeben, auch nicht mit „Admin“, und der Notfall-Login gibt nichts frei. Mit nur einer Person mit „Freigeben“ oder „Admin“ gehen Änderungen im Expertenmodus dann nicht.</p>
        ${admin ? `<div><button class="btn small" type="button" id="s-4save">Vier-Augen-Einstellung speichern</button></div>` : ""}</div></section>
      <section class="card" id="alert-card">${alertCardHtml(alertSet, admin)}</section><section class="card" id="rules-card">${rulesCardHtml(rules, admin)}</section>
      <section class="card"><div class="card-h"><h2>Sitzungen</h2></div><div class="card-b" style="display:grid;gap:12px;max-width:640px">
        <p class="note" style="margin:0">Beendet jede Anmeldung von <b>${esc(ME.name)}</b> auf allen Geräten, auch diese.</p>
        <div><button class="btn danger" type="button" id="s-logout-all">Alle meine Sitzungen beenden</button></div></div></section>`;
    // A new address deletes the secret bound to it unless it is entered anew in the same save (F2, api_settings.DESTINATION_SECRETS)
    [["s-url", s.opnsense_url, s.opnsense_key_set || s.opnsense_secret_set], ["s-rs", s.radius_server, s.radius_key_set], ["s-pfu", s.pf_url, s.pf_pass_set]].forEach(([id, was, set]) => {
      const sync = () => syncNote(id, id + "-note", !!set && destTxt($("#" + id).value) !== destTxt(was));
      $("#" + id).addEventListener("input", sync); sync();
    });
    // Credentials readable on the wire (E32): warn while a check box is off or its address uses http:// (both stay allowed)
    [["s-tls", "s-url"], ["s-pftls", "s-pfu"]].forEach(([box, url]) => {
      const sync = () => syncNote(box, box + "-note", !$("#" + box).checked || /^http:\/\//i.test($("#" + url).value.trim()));
      $("#" + box).addEventListener("change", sync); $("#" + url).addEventListener("input", sync); sync();
    });
    $("#s-scopes").value = SVLogic.formatScopes(scopes.entries);
    // The zone list as typed: a line it cannot read is named and nothing is sent; saved, the field shows what the server stored
    // (merged, zones sorted)
    if (admin) $("#s-zones-save").addEventListener("click", async e => {
      const r = SVLogic.parseScopes($("#s-scopes").value);
      if (r.errors.length) { toast(r.errors[0]); return; }
      e.target.disabled = true;
      try {
        const saved = await api("PUT", "/api/zone-scopes", { entries: r.entries });
        $("#s-scopes").value = SVLogic.formatScopes(saved.entries);
        // The warning about stored entries the field cannot hold goes once the stored list has none (it said what no longer holds)
        if (lossy.length && !SVLogic.lossyScopes(saved.entries).length) { $("#s-scopes-lossy").hidden = true; $("#s-scopes").setAttribute("aria-describedby", "s-scopes-hint"); }
        toast("Gespeichert");
      }
      catch (err) { toast(err.message); }
      e.target.disabled = false;
    });
    // The four-eyes principle and the hours of a new request (PUT /api/settings/approvals, apart from "Speichern"): hours outside
    // 1-168 are named here (the server's 422 would read in English); saved, ME is read again, so the expert mode, the forms' note
    // and the tab "Freigaben" follow at once
    if (admin) $("#s-4save").addEventListener("click", async e => {
      const hours = Number($("#s-4h").value.trim() || NaN);
      if (!Number.isInteger(hours) || hours < 1 || hours > 168) { toast("Anfragen verfallen nach 1 bis 168 Stunden: bitte eine ganze Zahl eintragen"); return; }
      e.target.disabled = true;
      try { await api("PUT", "/api/settings/approvals", { four_eyes: $("#s-4e").checked, hours }); toast("Gespeichert"); ME = await api("GET", "/api/auth/me"); refreshApprovals(); }
      catch (err) { toast(err.message); }
      e.target.disabled = false;
    });
    if (admin) $("#s-save").addEventListener("click", async e => {
      e.target.disabled = true; const pw = id => { const x = $("#" + id).value; return x === "" ? null : x; };
      try { const r = await api("PUT", "/api/settings", { poll_minutes: +$("#s-poll").value || 15, opnsense_url: $("#s-url").value.trim(), opnsense_key: pw("s-key"), opnsense_secret: pw("s-secret"), opnsense_verify_tls: $("#s-tls").checked,
        radius_server: $("#s-rs").value.trim(), radius_key: pw("s-rk"), pf_url: $("#s-pfu").value.trim(), pf_user: $("#s-pfuser").value.trim(), pf_pass: pw("s-pfpass"), pf_verify_tls: $("#s-pftls").checked }); toast(savedTxt(r.cleared)); renderSettings(); }
      catch (err) { toast(err.message); e.target.disabled = false; }
    });
    // Log out everywhere: every session of this user ends on the server (main.logout_all), this one too, so the login follows
    $("#s-logout-all").addEventListener("click", async e => {
      if (!(await confirmModal("Alle Sitzungen beenden", `Jede Anmeldung von <b>${esc(ME.name)}</b> auf allen Geräten endet, auch diese. Danach meldest du dich neu an.`, "Alle beenden", true))) return;
      e.target.disabled = true;
      try { const r = await api("POST", "/api/auth/logout-all"); toast(r.ended === 1 ? "1 Sitzung beendet" : `${r.ended} Sitzungen beendet`); showLogin(); }
      catch (err) { toast(err.message); e.target.disabled = false; }
    });
    $("#s-pftest").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", "/api/pf/test"); modal("PacketFence", `<div class="testres"><div><span class="st-dot ${r.ok ? "" : "bad"}"></span><b>${r.ok ? "Verbunden" : "Fehlgeschlagen"}</b> <span class="muted">${esc(r.detail || r.error || "")}</span></div></div><p class="note">Vorher speichern, getestet wird der gespeicherte Stand.</p>`, [{ label: "Schließen", onClick: closeModal }]); } catch (err) { toast(err.message); } e.target.disabled = false; });
    $("#s-names").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", "/api/names/refresh"); toast(r.ok ? `${SVLogic.plural(r.entries, "Eintrag", "Einträge")} aus der ARP-Tabelle${r.skipped ? `, ${r.skipped} übersprungen` : ""}` : r.error); MAP = null; } catch (err) { toast(err.message); } e.target.disabled = false; });
    bindRulesCard(rules); await bindAlertCard(alertSet);
  }
