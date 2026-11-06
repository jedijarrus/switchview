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

  /* ── API, Toast, Modal ── */
  async function api(method, url, body) {
    const opt = { method, headers: { "X-Requested-With": "SwitchView" }, credentials: "same-origin" };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    const r = await fetch(url, opt);
    if (r.status === 401 && !url.startsWith("/api/auth/")) { showLogin(); throw new Error("Bitte erneut anmelden"); }
    const data = (r.headers.get("content-type") || "").includes("json") ? await r.json() : await r.text();
    if (!r.ok) { let m = data && data.detail ? data.detail : (typeof data === "string" ? data : "Fehler " + r.status); if (Array.isArray(m)) m = m.map(x => x.msg).join(", "); throw new Error(m); }
    return data;
  }
  function toast(msg) { const t = $("#toast"); t.textContent = msg; t.hidden = false; clearTimeout(toast._t); toast._t = setTimeout(() => t.hidden = true, 3200); }
  let modalLastFocus = null;
  function modal(title, bodyHtml, buttons = []) {
    modalLastFocus = document.activeElement;
    $("#m-title").textContent = title; $("#m-body").innerHTML = bodyHtml; $("#m-body").onclick = null; // Klick-Handler gehört zum jeweiligen Dialog
    const foot = $("#m-foot"); foot.innerHTML = "";
    buttons.forEach(b => { const el = document.createElement("button"); el.type = "button"; el.className = "btn " + (b.cls || ""); el.textContent = b.label; el.addEventListener("click", () => b.onClick(el)); foot.appendChild(el); });
    $("#modal").hidden = false;
    const f = $("#m-body input, #m-body select, #m-foot .btn"); if (f) f.focus();
  }
  function closeModal() { $("#modal").hidden = true; if (modalLastFocus && modalLastFocus.focus) modalLastFocus.focus(); }
  $("#modal").addEventListener("click", e => { if (e.target.id === "modal" || e.target.closest("[data-close]")) closeModal(); });
  const confirmModal = (title, text, label, danger) => new Promise(res => modal(title, `<p style="margin:0">${text}</p>`,
    [{ label: "Abbrechen", onClick: () => { closeModal(); res(false); } }, { label, cls: danger ? "danger" : "primary", onClick: () => { closeModal(); res(true); } }]));

  /* ── Login ── */
  let authCfg = null, msalApp = null, ME = null; // ME: the signed-in user (/api/auth/me), set by start()
  function showLogin(msg) { $("#app").hidden = true; $("#login").hidden = false; const e = $("#login-error"); e.hidden = !msg; e.textContent = msg || ""; }
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
      const r = await msalApp.loginPopup({ scopes: ["openid", "profile", "email"], prompt: "select_account" });
      await api("POST", "/api/auth/azure", { id_token: r.idToken }); await start();
    } catch (e) { showLogin(e.message || String(e)); } finally { btn.disabled = false; }
  });
  $("#form-local").addEventListener("submit", async e => {
    e.preventDefault();
    try { await api("POST", "/api/auth/local", { username: $("#l-user").value, password: $("#l-pass").value }); $("#l-pass").value = ""; await start(); } catch (err) { showLogin(err.message); }
  });
  $("#btn-logout").addEventListener("click", async () => { try { await api("POST", "/api/auth/logout"); } catch (e) { /* egal */ } showLogin(); });

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
  const isPeer = p => p.l.some(x => MAP.switches.some(s => s.sys === x[0] || s.k === x[0]));
  const isUplink = p => isPeer(p) || !!p.tr || !!p.up || !!p.bm;
  const isUnconfirmedUplink = p => !p.tr && ((p.up && !p.uc) || (!p.up && (isPeer(p) || p.bm)));
  const uplinkPill = p => isUnconfirmedUplink(p) ? ` <span class="pill warn" title="Nur per LLDP gemeldet, die Gegenseite bestätigt es nicht. Ein Gerät am Port kann LLDP fälschen – vor Ort prüfen.">Uplink (unbestätigt)</span>`
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
