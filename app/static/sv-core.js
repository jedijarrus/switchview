"use strict";
/* SwitchView Frontend (Vanilla JS). Struktur: Übersicht → Switch-Detail → Port. */
  const $ = (s, r = document) => r.querySelector(s);
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const VC = { "1": "#a1a1aa", "110": "#78716c", "120": "#e11d48", "130": "#0ea5e9", "140": "#2563eb", "150": "#9333ea", "160": "#ca8a04", "170": "#65a30d",
    "210": "#ea580c", "220": "#0d9488", "230": "#14b8a6", "240": "#7c3aed", "250": "#a855f7", "260": "#16a34a", "270": "#db2777", "280": "#c026d3" };
  const vcol = id => VC[id] || ("hsl(" + ((parseInt(id, 10) * 47) % 360) + " 55% 50%)");
  const speedTxt = s => !s ? "–" : s >= 1000 ? (s / 1000).toString().replace(".", ",") + " Gbit" : s + " Mbit";
  const fmtTime = iso => { if (!iso) return "–"; const d = new Date(iso.includes("T") ? iso : iso.replace(" ", "T") + "Z"); return isNaN(d) ? iso : d.toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }); };
  const isNum = n => /^\d+$/.test(n);
  // Treiber-Fähigkeiten (caps vom Server: cli, nac, backup, snmp_vlan, snmp_admin, snmp_name, snmp_poe, snmp_autosave)
  const has = (s, cap) => !!s && (s.caps || []).includes(cap);
  // Kann SwitchView an diesem Switch schreiben: per SSH-CLI (Treiber mit CLI und SSH-Zugang) oder per SNMP (SNMP-Schreiben an)
  const writable = s => (s.ssh && has(s, "cli")) || !!s.snmp_write;
  // PoE eines Ports (netmap: {on, status, mw}); status = pethPsePortDetectionStatus (RFC 3621)
  const POE_ST = { 1: "abgeschaltet", 2: "kein Gerät erkannt", 3: "liefert Strom", 4: "Fehler", 5: "Test", 6: "Fehler" };
  const onTxt = on => on === true ? "an" : on === false ? "aus" : "unbekannt";
  const poeTxt = q => [onTxt(q.on), POE_ST[q.status] && !(q.status === 1 && q.on === false) ? POE_ST[q.status] : "",
    typeof q.mw === "number" && (q.mw > 0 || q.status === 3) ? (q.mw / 1000).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " W" : ""].filter(Boolean).join(" · ");
  const sentence = t => t && !/[.!?]$/.test(t) ? t + "." : t;
  // Model and firmware of a switch as HTML for a meta line, each part only if the poll read it: poller.parse_descr finds a firmware
  // only in a ProCurve sysDescr, and a switch that never answered has neither (fwLabel: "Firmware " in the switch view, none on a card)
  const modelFw = (s, fwLabel = "") => [esc(s.model), s.fw ? `${fwLabel}<span class="mono">${esc(s.fw)}</span>` : ""].filter(Boolean).join(" · ");

  /* ── API, Toast, Modal ── */
  async function api(method, url, body) {
    const opt = { method, headers: { "X-Requested-With": "SwitchView" }, credentials: "same-origin" };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    const r = await fetch(url, opt);
    // A session that ended: the login page names the server's reason (the idle logout, an expired session); "Nicht angemeldet" says
    // nothing the login page does not. A reason it shows stays: of two requests at once (renderSettings, renderDevices) the first
    // answer names the idle logout and deletes the session, the second then finds none ("Sitzung abgelaufen")
    if (r.status === 401 && !url.startsWith("/api/auth/")) {
      let why = "";
      try { const d = (r.headers.get("content-type") || "").includes("json") ? await r.json() : null; if (d && typeof d.detail === "string") why = d.detail; } catch (e) { /* kein JSON */ }
      if ($("#login").hidden || !$("#login-error").textContent) showLogin(why === "Nicht angemeldet" ? "" : why);
      throw new Error("Bitte erneut anmelden");
    }
    const data = (r.headers.get("content-type") || "").includes("json") ? await r.json() : await r.text();
    if (!r.ok) { let m = data && data.detail ? data.detail : (typeof data === "string" ? data : "Fehler " + r.status); if (Array.isArray(m)) m = m.map(x => x.msg).join(", "); throw new Error(m); }
    return data;
  }
  // Messages stack in #toasts (one aria-live container keeps the announcements in order), at most TOAST_MAX, each with its own
  // timer; the same text as the newest one restarts that one's timer instead of adding a second line
  const TOAST_MAX = 3;
  function toast(msg, ms = 3200) {
    const box = $("#toasts"), last = box.children[box.children.length - 1];
    if (last && last.textContent === msg) { clearTimeout(last._t); last._t = setTimeout(() => last.remove(), ms); return; }
    const t = document.createElement("div"); t.className = "toast"; t.textContent = msg;
    t._t = setTimeout(() => t.remove(), ms);
    box.appendChild(t);
    while (box.children.length > TOAST_MAX) { const old = box.children[0]; clearTimeout(old._t); old.remove(); }
  }

  /* ── Layers: the modal over the port panel (drawer) over the page. An open layer makes what lies below it inert (out of the tab
     order and the screen reader), Tab and Shift+Tab wrap at its ends, Escape closes the top one, and focus goes back to a live
     opener (else the port tile the panel came from, else #view, never body) once the background is live again. ── */
  const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';
  // The controls Tab reaches in root: those shown (an element of a hidden or display:none subtree has no client rects)
  const focusables = root => [...root.querySelectorAll(FOCUSABLE)].filter(el => el.getClientRects().length > 0);
  function trapTab(e, root) {
    const list = focusables(root), to = SVLogic.trapStep(list.length, list.indexOf(document.activeElement), e.shiftKey);
    if (to === null) return;
    e.preventDefault(); (to < 0 ? root : list[to]).focus();
  }
  // drLast (sv-switch.js): the port tile the panel was opened from, until it has taken the focus back once (a later dialog whose
  // opener left the DOM, a change list re-rendered say, goes to #view, not to that tile); an element in the closed panel is hidden
  // and takes no focus
  function restoreFocus(el) {
    const to = [el, drLast].find(x => x && x.isConnected && x !== document.body && typeof x.focus === "function" && !x.closest(".drawer:not(.open)"));
    if (to && to === drLast) drLast = null;
    (to || $("#view")).focus();
  }
  function syncLayers() {
    const m = !$("#modal").hidden, d = $("#drawer").classList.contains("open");
    $("#app").inert = m || d; $("#drawer").inert = m;
  }
  // Every layer closed without moving the focus (the login page, Back and Forward): there is no opener to go back to
  function dropLayers() { $("#modal").hidden = true; closeDrawer(true); showResults(false); syncLayers(); }
  function onLayerKey(e) {
    const m = !$("#modal").hidden, d = $("#drawer").classList.contains("open");
    if (e.key === "Escape") { if (m) closeModal(); else if (d) closeDrawer(); showResults(false); }
    else if (e.key === "Tab") { if (m) trapTab(e, $(".modal")); else if (d) trapTab(e, $("#drawer")); }
  }
  document.addEventListener("keydown", onLayerKey);

  // The opener of the first dialog of a chain (form → preview → progress replace the content of the one modal); modalSeq counts the
  // dialogs opened, modal() returns the number of its dialog
  let modalLastFocus = null, modalSeq = 0;
  // Whether dialog n (the return of modal()) is still the one shown: not closed (Back, Escape, ✕, the login) and not replaced by another
  const modalShown = n => !$("#modal").hidden && n === modalSeq;
  function modal(title, bodyHtml, buttons = []) {
    if ($("#modal").hidden) modalLastFocus = document.activeElement;
    modalSeq++;
    $("#m-title").textContent = title; $("#m-body").innerHTML = bodyHtml; $("#m-body").onclick = null; // Klick-Handler gehört zum jeweiligen Dialog
    const foot = $("#m-foot"); foot.innerHTML = "";
    buttons.forEach(b => { const el = document.createElement("button"); el.type = "button"; el.className = "btn " + (b.cls || ""); el.textContent = b.label; el.addEventListener("click", () => b.onClick(el)); foot.appendChild(el); });
    $("#modal").hidden = false; syncLayers();
    // Without a field or a footer button (the preview's loading dialog) the dialog itself takes the focus: it stays in the dialog,
    // not on the opener behind it
    const f = $("#m-body input, #m-body select, #m-foot .btn"); if (f) f.focus(); else $(".modal").focus();
    return modalSeq;
  }
  // syncLayers first: a browser does not focus an element inside an inert subtree
  function closeModal() { $("#modal").hidden = true; syncLayers(); restoreFocus(modalLastFocus); }
  $("#modal").addEventListener("click", e => { if (e.target.id === "modal" || e.target.closest("[data-close]")) closeModal(); });
  const confirmModal = (title, text, label, danger) => new Promise(res => modal(title, `<p style="margin:0">${text}</p>`,
    [{ label: "Abbrechen", onClick: () => { closeModal(); res(false); } }, { label, cls: danger ? "danger" : "primary", onClick: () => { closeModal(); res(true); } }]));

  /* ── Secret fields of the settings: one rule for the cards of renderSettings (sv-settings.js) and alertCardHtml (sv-alerts.js) - a
     stored secret is never shown, an empty field keeps it, and one that does not decrypt is named beside its field ── */
  const SECRET_KEPT = "gesetzt – leer lassen = unverändert";
  // A stored secret that does not decrypt (s = GET /api/settings or /api/settings/alerts, k its key in s.unreadable; SECRET_KEY
  // changed?): it has to be entered anew. id is the note's own id (<field id>-unread), which its field names in aria-describedby; the
  // note stands beside the field, not in its label (no block in a label, and a click on the note does not focus the field). Below
  // Admin the field is locked: the note names the role that can enter it
  const unreadNote = (s, k, id) => (s.unreadable || []).includes(k)
    ? `<span class="note warn" id="${id}">lässt sich nicht entschlüsseln – ${roleOk("admin") ? "bitte neu eingeben" : "neu eingeben braucht die Rolle „Admin“"}</span>` : "";
  // A secret field (s the card's answer, k its key in s.unreadable, set: a value is stored): the input with its hint (o.hint) and its
  // unread note as siblings, both naming the input's description; o.max its maxlength, o.disabled locks it (below Admin)
  const secretInput = (s, id, label, k, set, o = {}) => {
    const note = unreadNote(s, k, id + "-unread"), desc = [o.hint && id + "-hint", note && id + "-unread"].filter(Boolean).join(" ");
    return `<div class="field"><label for="${id}">${label}</label><input id="${id}" type="password" autocomplete="new-password" placeholder="${set ? SECRET_KEPT : ""}"`
      + `${o.max ? ` maxlength="${o.max}"` : ""}${desc ? ` aria-describedby="${desc}"` : ""}${o.disabled ? " disabled" : ""}>`
      + `${o.hint ? `<span class="hint" id="${id}-hint">${esc(o.hint)}</span>` : ""}${note}</div>`;
  };
  // The foot of a settings card: left a hint (hint, HTML) or, while the card holds changes not saved (setDirty of sv-settings.js),
  // "Ungespeicherte Änderungen"; right the card's other buttons (extra, HTML) and "Speichern" (saveId; none: no button). Every card
  // says "Speichern", its name is the button's for a screen reader ("<what> speichern")
  const cardFoot = (saveId, what, extra = "", hint = "") => `<div class="card-f"><span class="f-hint">${hint}</span><span class="f-dirty">Ungespeicherte Änderungen</span>`
    + `<div class="f-btns">${extra}${saveId ? `<button class="btn primary" type="button" id="${saveId}" aria-label="${what} speichern">Speichern</button>` : ""}</div></div>`;

  /* ── Login ── */
  let authCfg = null, msalApp = null, ME = null; // ME: the signed-in user (/api/auth/me), set by start()
  function showLogin(msg) { dropLayers(); $("#app").hidden = true; $("#login").hidden = false; const e = $("#login-error"); e.hidden = !msg; e.textContent = msg || ""; }
  async function initLogin() {
    authCfg = await api("GET", "/api/auth/config");
    $("#btn-sso").hidden = !authCfg.sso; $("#form-local").hidden = !authCfg.local; $("#sep-local").hidden = !(authCfg.sso && authCfg.local);
    if (!authCfg.sso && !authCfg.local) showLogin("Keine Anmeldeart eingerichtet (ENTRA_* oder ADMIN_* in der .env).");
  }
  $("#btn-sso").addEventListener("click", async () => {
    const btn = $("#btn-sso"); btn.disabled = true;
    try {
      if (!window.msal) throw new Error("MSAL-Bibliothek konnte nicht geladen werden");
      if (!msalApp) { msalApp = new msal.PublicClientApplication({ auth: { clientId: authCfg.client_id, authority: "https://login.microsoftonline.com/" + authCfg.tenant, redirectUri: location.origin + "/" }, cache: { cacheLocation: "sessionStorage" } }); await msalApp.initialize(); }
      // The server's nonce of this login attempt (bound to a cookie of this browser): Entra puts it into the id_token, /api/auth/azure checks it
      const { nonce } = await api("POST", "/api/auth/nonce");
      const r = await msalApp.loginPopup({ scopes: ["openid", "profile", "email"], prompt: "select_account", nonce });
      await api("POST", "/api/auth/azure", { id_token: r.idToken }); await start();
    } catch (e) { showLogin(e.message || String(e)); } finally { btn.disabled = false; }
  });
  $("#form-local").addEventListener("submit", async e => {
    e.preventDefault();
    try { await api("POST", "/api/auth/local", { username: $("#l-user").value, password: $("#l-pass").value }); $("#l-pass").value = ""; await start(); } catch (err) { showLogin(err.message); }
  });
  $("#btn-logout").addEventListener("click", async () => { try { await api("POST", "/api/auth/logout"); } catch (e) { /* egal */ } showLogin(); });

  /* ── Rights: what the role (ME.role) and the zones (ME.zones: null = not limited) of the signed-in user allow, as /api/auth/me said
     at the start of the page. The views hide or lock the rest and say why; the server checks every request (auth.require, roles). ── */
  const roleOk = min => SVLogic.atLeast(ME && ME.role, min);
  const inZone = s => !ME || ME.zones == null || ME.zones.includes((s && s.zone) || "");
  const mayChange = s => writable(s) && roleOk("aendern") && inZone(s);
  // Expert mode (uplinks, trunks): Freigeben, or with the four-eyes principle on a request for someone else to approve
  const expertOk = () => roleOk("freigeben") || !!(ME && ME.four_eyes);
  // Why the user may not change switch s, as one sentence ("" when they may): the role first, then the zone (roles.zone_denial's rule:
  // the empty zone is "Ohne Zone", in the list too; "der Zone" for one allowed zone, else "der Zonen")
  function rightsWhy(s) {
    if (roleOk("aendern") && inZone(s)) return "";
    if (!roleOk("aendern")) return `Deine Rolle „${SVLogic.roleLabel(ME && ME.role)}“ kann hier nur ansehen. Ändern braucht die Rolle „Ändern“.`;
    const named = z => z || "Ohne Zone", zone = z => `„${named(z)}“`;
    const allowed = (ME.zones.length === 1 ? "der Zone " : "der Zonen ") + ME.zones.map(zone).join(", ");
    return `Dieser Switch liegt in der Zone ${zone(s && s.zone)}. Du darfst nur an Switches ${allowed} ändern.`;
  }

  /* ── Daten ── */
  let MAP = null;
  async function loadMap(force) { if (!MAP || force) MAP = await api("GET", "/api/netmap"); return MAP; }
  // Switches by id (/api/netmap: links name theirs in a / b, unknown devices in sid); names (k, an / bn) are for display only
  const swById = id => MAP.switches.find(s => s.id === id);
  const vname = id => (MAP && MAP.vlans[id]) || ("VLAN " + id);
  const chip = (id, cls = "small") => `<span class="vchip static ${cls}" style="--vc:${vcol(id)}" title="${esc(vname(id))}"><i class="sw"></i><span class="id">${esc(id)}</span>${cls === "small" ? "" : `<span class="nm">${esc(vname(id))}</span>`}</span>`;
  const chips = (ids, cls, max) => { if (!ids || !ids.length) return `<span class="muted">–</span>`; const shown = max ? ids.slice(0, max) : ids; return `<div class="vlans">${shown.map(i => chip(i, cls)).join("")}${max && ids.length > max ? `<span class="more">+${ids.length - max}</span>` : ""}</div>`; };
  const physOf = s => s.ports.filter(p => !p.n.startsWith("Trk"));
  // A trunk / LAG itself (TrkN, or a port whose trunk is itself: Po1, ae0, ...); its members carry the trunk's name in tr
  const isTrunkPort = p => p.n.startsWith("Trk") || (!!p.tr && p.tr === p.n);
  const isMember = p => !!p && !!p.tr && p.tr !== p.n;
  // The names of the switches (SVLogic.peerKeys), built once per MAP: MAP is only ever replaced, never changed in place, and an old
  // MAP's set goes with it
  const peerSets = new WeakMap();
  const peerSet = () => { let keys = peerSets.get(MAP); if (!keys) peerSets.set(MAP, keys = SVLogic.peerKeys(MAP.switches)); return keys; };
  // An LLDP neighbour of the port is one of the switches; a neighbour without a name is none (as topology.switch_keys)
  const isPeer = p => p.l.some(x => peerSet().has(x[0]));
  const isUplink = p => isPeer(p) || !!p.tr || !!p.up || !!p.bm;
  const isUnconfirmedUplink = p => !p.tr && ((p.up && !p.uc) || (!p.up && (isPeer(p) || p.bm)));
  // Why a port counts as an unconfirmed uplink, as text for the port panel and the pill's title ("" for any other port): on a link
  // that not both switches confirm (up, not uc), else without a link by what makes it one (an LLDP neighbour named like a switch, a
  // base MAC of another switch learned on it; isUnconfirmedUplink)
  const unconfirmedWhy = p => !isUnconfirmedUplink(p) ? ""
    : p.up ? "Liegt auf einer Verbindung zu einem anderen Switch, die nicht beide Switches bestätigen. Vor Ort prüfen, ob dort wirklich ein Switch steckt."
    : [isPeer(p) && "Ein LLDP-Nachbar an diesem Port heißt wie ein verwalteter Switch.", p.bm && "An diesem Port wird die Basis-MAC eines verwalteten Switches gelernt."]
      .filter(Boolean).join(" ") + " Eine Verbindung ist nicht erkannt. Ein Gerät am Port kann LLDP und MAC-Adressen fälschen – vor Ort prüfen.";
  const uplinkPill = p => isUnconfirmedUplink(p) ? ` <span class="pill warn" title="${esc(unconfirmedWhy(p))}">Uplink (unbestätigt)</span>`
    : isUplink(p) ? ` <span class="pill neutral" title="Uplink: Änderungen nur im Expertenmodus">Uplink</span>` : "";
  // The ports of a link that build_map does not confirm ("uc": neither LLDP from both sides nor mutual base MACs), as "SW-A 3"; a link
  // can join a confirmed pair and a one-sided claim, so the tooltip names the ports instead of calling the whole link one-sided.
  const unconfPorts = l => [...new Set([[l.a, l.an, l.A], [l.b, l.bn, l.B]].flatMap(([id, name, x]) => {
    const s = swById(id);
    return x.ports.filter(n => !(s && s.ports.some(p => p.n === n && p.uc))).map(n => `${name} ${n}`);
  }))];
  const unconfTitle = l => l.confirmed ? "" : `Nicht von beiden Switches bestätigt: ${unconfPorts(l).join(", ")}`;
  const linkIssue = l => l.onlyA.length + l.onlyB.length + l.native.length;
  const stDot = s => `<span class="st-dot ${s.ok ? "" : "bad"}" aria-hidden="true"></span>`;
  function zones() { const z = []; MAP.switches.forEach(s => { const k = s.zone || "Ohne Zone"; if (!z.includes(k)) z.push(k); }); return z; }

  // Auffälligkeiten als Gruppen: je Art eine aufklappbare Zeile statt einer langen Liste.
  function issueGroups() {
    const g = [];
    const bad = MAP.switches.filter(s => !s.ok);
    if (bad.length) g.push({ sev: "crit", t: "Abfrage fehlgeschlagen", sum: bad.map(s => s.k).join(", "), open: true,
      items: bad.map(s => ({ t: s.k, d: s.error || "keine Antwort", go: () => go("switches", s.id) })) });
    // A poll that went through with gaps (poller.partial_note: failed walks, kept MACs / LLDP / base MAC, skipped VLAN rows) keeps its note in error
    const partial = MAP.switches.filter(s => s.ok && s.error);
    if (partial.length) g.push({ sev: "warn", t: "Abfrage unvollständig", sum: partial.map(s => s.k).join(", "),
      items: partial.map(s => ({ t: s.k, d: s.error, go: () => go("switches", s.id) })) });
    const lk = MAP.links.filter(linkIssue);
    if (lk.length) g.push({ sev: "warn", t: "VLANs auf Verbindungen unterschiedlich", sum: `${lk.length} von ${MAP.links.length} Verbindungen`,
      items: lk.map(l => {
        const parts = [];
        if (l.onlyA.length) parts.push(`nur ${l.an}: ${l.onlyA.join(", ")}`);
        if (l.onlyB.length) parts.push(`nur ${l.bn}: ${l.onlyB.join(", ")}`);
        if (l.native.length) parts.push(`ungetaggt verschieden: ${l.native.join(", ")}`);
        return { t: `${l.an} ⇄ ${l.bn}`, d: parts.join(" · "), go: () => go("switches", l.a) };
      }) });
    const free = MAP.switches.map(s => ({ s, ps: physOf(s).filter(p => !p.o && !isUplink(p) && p.u.includes("1")) })).filter(x => x.ps.length);
    if (free.length) g.push({ sev: "info", t: "Freie Ports im Standard-VLAN 1", sum: `${free.reduce((a, x) => a + x.ps.length, 0)} Ports auf ${free.length} Switches · Einstecken = Server-Netz`,
      items: free.map(x => ({ t: `${x.s.k}: ${x.ps.length} Ports`, d: x.ps.map(p => p.n).join(", "), go: () => { swVlan = "1"; swPortFilter = "free"; go("switches", x.s.id); } })) });
    return g;
  }
