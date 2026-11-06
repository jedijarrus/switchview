/* SwitchView Frontend (Vanilla JS). Struktur: Übersicht → Switch-Detail → Port. */
(function () {
  "use strict";
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

  /* ── Router: #overview, #switches, #switch=<name>, #vlans, … ── */
  const VIEWS = { overview: renderOverview, switches: renderSwitchDetail, vlans: renderVlans, devices: renderDevices, backups: renderBackups, audit: renderAudit, settings: renderSettings };
  let current = "overview", selSwitch = null, swVlan = null, swPortFilter = "all", swText = "";
  function go(view, arg) {
    if (!VIEWS[view]) view = "overview";
    current = view;
    if (view === "switches" && arg !== undefined) selSwitch = arg;
    document.querySelectorAll(".tabs [data-view]").forEach(b => { if (b.dataset.view === view) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); });
    try { history.replaceState(null, "", "#" + (view === "switches" && selSwitch ? "switch=" + encodeURIComponent(selSwitch) : view)); } catch (e) { /* egal */ }
    closeDrawer(true);
    $("#view").onclick = null;
    VIEWS[view]();
    window.scrollTo(0, 0);
  }
  $(".tabs").addEventListener("click", e => { const b = e.target.closest("[data-view]"); if (b) go(b.dataset.view); });
  async function start() {
    ME = await api("GET", "/api/auth/me");
    $("#user-name").textContent = ME.name; $("#login").hidden = true; $("#app").hidden = false;
    const h = decodeURIComponent((location.hash || "").slice(1));
    if (h.startsWith("switch=")) go("switches", h.slice(7)); else go(h || "overview");
  }

  /* ── Daten ── */
  let MAP = null;
  async function loadMap(force) { if (!MAP || force) MAP = await api("GET", "/api/netmap"); return MAP; }
  const vname = id => (MAP && MAP.vlans[id]) || ("VLAN " + id);
  const chip = (id, cls = "small") => `<span class="vchip static ${cls}" style="--vc:${vcol(id)}" title="${esc(vname(id))}"><i class="sw"></i><span class="id">${esc(id)}</span>${cls === "small" ? "" : `<span class="nm">${esc(vname(id))}</span>`}</span>`;
  const chips = (ids, cls, max) => { if (!ids || !ids.length) return `<span class="muted">–</span>`; const shown = max ? ids.slice(0, max) : ids; return `<div class="vlans">${shown.map(i => chip(i, cls)).join("")}${max && ids.length > max ? `<span class="more">+${ids.length - max}</span>` : ""}</div>`; };
  const physOf = s => s.ports.filter(p => !p.n.startsWith("Trk"));
  // A trunk / LAG itself (TrkN, or a port whose trunk is itself: Po1, ae0, ...); its members carry the trunk's name in tr
  const isTrunkPort = p => p.n.startsWith("Trk") || (!!p.tr && p.tr === p.n);
  const isMember = p => !!p && !!p.tr && p.tr !== p.n;
  const isPeer = p => p.l.some(x => MAP.switches.some(s => s.sys === x[0] || s.k === x[0]));
  const isUplink = p => isPeer(p) || !!p.tr || !!p.up;
  const isUnconfirmedUplink = p => !p.tr && ((p.up && !p.uc) || (!p.up && isPeer(p)));
  const uplinkPill = p => isUnconfirmedUplink(p) ? ` <span class="pill warn" title="Nur per LLDP gemeldet, die Gegenseite bestätigt es nicht. Ein Gerät am Port kann LLDP fälschen – vor Ort prüfen.">Uplink (unbestätigt)</span>`
    : isUplink(p) ? ` <span class="pill neutral" title="Uplink: Änderungen nur im Expertenmodus">Uplink</span>` : "";
  // The ports of a link that build_map does not confirm ("uc": neither LLDP from both sides nor mutual base MACs), as "SW-A 3"; a link
  // can join a confirmed pair and a one-sided claim, so the tooltip names the ports instead of calling the whole link one-sided.
  const unconfPorts = l => [...new Set([[l.a, l.A], [l.b, l.B]].flatMap(([k, x]) => {
    const s = MAP.switches.find(v => v.k === k);
    return x.ports.filter(n => !(s && s.ports.some(p => p.n === n && p.uc))).map(n => `${k} ${n}`);
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
      items: bad.map(s => ({ t: s.k, d: s.error || "keine Antwort", go: () => go("switches", s.k) })) });
    const lk = MAP.links.filter(linkIssue);
    if (lk.length) g.push({ sev: "warn", t: "VLANs auf Verbindungen unterschiedlich", sum: `${lk.length} von ${MAP.links.length} Verbindungen`,
      items: lk.map(l => {
        const parts = [];
        if (l.onlyA.length) parts.push(`nur ${l.a}: ${l.onlyA.join(", ")}`);
        if (l.onlyB.length) parts.push(`nur ${l.b}: ${l.onlyB.join(", ")}`);
        if (l.native.length) parts.push(`ungetaggt verschieden: ${l.native.join(", ")}`);
        return { t: `${l.a} ⇄ ${l.b}`, d: parts.join(" · "), go: () => go("switches", l.a) };
      }) });
    const free = MAP.switches.map(s => ({ s, ps: physOf(s).filter(p => !p.o && !isUplink(p) && p.u.includes("1")) })).filter(x => x.ps.length);
    if (free.length) g.push({ sev: "info", t: "Freie Ports im Standard-VLAN 1", sum: `${free.reduce((a, x) => a + x.ps.length, 0)} Ports auf ${free.length} Switches · Einstecken = Server-Netz`,
      items: free.map(x => ({ t: `${x.s.k}: ${x.ps.length} Ports`, d: x.ps.map(p => p.n).join(", "), go: () => { swVlan = "1"; swPortFilter = "free"; go("switches", x.s.k); } })) });
    return g;
  }

  /* ── Übersicht ── */
  async function renderOverview() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    try { await loadMap(true); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    if (!MAP.switches.length) {
      v.innerHTML = `<div class="card"><div class="empty"><b>Noch keine Switches</b><span>Lege unter „Switches" den ersten Switch mit seinen Zugangsdaten an.</span><button class="btn primary" type="button" id="go-add">Switch hinzufügen</button></div></div>`;
      $("#go-add").addEventListener("click", () => editSwitch(null)); return;
    }
    const sw = MAP.switches, phys = sw.flatMap(physOf), up = phys.filter(p => p.o).length, bad = sw.filter(s => !s.ok).length;
    const groups = issueGroups(), items = groups.flatMap(x => x.items), nWarn = groups.filter(x => x.sev !== "info").reduce((a, x) => a + x.items.length, 0), nInfo = items.length - nWarn;
    const sevPill = { crit: `<span class="pill crit">Fehler</span>`, warn: `<span class="pill warn">Prüfen</span>`, info: `<span class="pill neutral">Hinweis</span>` };
    v.innerHTML = `
      <div class="kpis">
        <div class="kpi ${bad ? "crit" : ""}"><span class="k">Switches erreichbar</span><span class="v">${sw.length - bad}<small> / ${sw.length}</small></span><span class="s">${bad ? bad + " ohne Antwort" : "alle antworten"}</span></div>
        <div class="kpi"><span class="k">Ports aktiv</span><span class="v">${up}<small> / ${phys.length}</small></span><div class="bar2" aria-hidden="true"><i style="width:${Math.round(up / Math.max(1, phys.length) * 100)}%"></i></div></div>
        <div class="kpi"><span class="k">VLANs</span><span class="v">${Object.keys(MAP.vlans).length}</span><span class="s">über alle Switches</span></div>
        <div class="kpi ${nWarn ? "warn" : ""}"><span class="k">Zu prüfen</span><span class="v">${nWarn}</span><span class="s">${nInfo ? "dazu " + nInfo + " Hinweise" : "keine Hinweise"}</span></div>
      </div>
      <section class="card"><div class="card-h"><h2>Topologie</h2><span class="sub">Klick auf einen Switch öffnet ihn</span></div><div class="card-b topo" id="topo"></div></section>
      <div class="two">
        <section class="card"><div class="card-h"><h2>Switches</h2><div class="right"><span class="muted" style="font-size:12px">Stand ${esc(fmtTime(sw.map(s => s.lastPoll).sort().slice(-1)[0]))}</span><button class="btn small" type="button" id="btn-refresh">Alle abfragen</button></div></div>
          <div class="card-b" style="display:grid;gap:10px">${zones().map(z => `<div class="zonehead">${esc(z)}</div><div class="swgrid">${sw.filter(s => (s.zone || "Ohne Zone") === z).map(s => {
            const ph = physOf(s), u = ph.filter(p => p.o).length;
            return `<button type="button" class="swcard" data-sw="${esc(s.k)}"><span class="n">${stDot(s)}${esc(s.k)}</span><span class="m">${esc(s.model)} · <span class="mono">${esc(s.fw)}</span></span>
              <div class="bar2" aria-hidden="true"><i style="width:${Math.round(u / Math.max(1, ph.length) * 100)}%"></i></div><span class="row"><span>${u} / ${ph.length} Ports aktiv</span><span class="mono">${esc(s.host)}</span></span></button>`; }).join("")}</div>`).join("")}</div></section>
        <section class="card"><div class="card-h"><h2>Auffälligkeiten</h2><span class="sub">aus den Switch-Daten</span></div>
          ${groups.length ? `<div class="issues">${groups.map((x, gi) => `<details class="ig ${x.sev}" ${x.open ? "open" : ""}><summary>${sevPill[x.sev]}<span class="t">${esc(x.t)}</span><span class="cnt">${x.items.length}</span><svg class="chev" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg><span class="d">${esc(x.sum)}</span></summary>
            <div class="igl">${x.items.map((i, n) => `<div class="issue"><span class="t">${esc(i.t)}</span><span class="d">${esc(i.d)}</span><button class="btn small go" type="button" data-iss="${gi}:${n}">Öffnen</button></div>`).join("")}</div></details>`).join("")}</div>` : `<div class="empty">Nichts auffällig.</div>`}</section>
      </div>
      <section class="card"><div class="card-h"><h2>Verbindungen zwischen Switches</h2><span class="sub">${MAP.links.length} erkannt</span></div>${linksTable(MAP.links)}</section>`;
    v.onclick = e => {
      const b = e.target.closest("[data-iss]"); if (b) { const [gi, n] = b.dataset.iss.split(":"); return groups[+gi].items[+n].go(); }
      const c = e.target.closest(".swcard"); if (c) go("switches", c.dataset.sw);
    };
    $("#btn-refresh").addEventListener("click", async ev => { ev.target.disabled = true; try { await api("POST", "/api/poll"); toast("Alle Switches abgefragt"); renderOverview(); } catch (e) { toast(e.message); ev.target.disabled = false; } });
    renderTopo($("#topo"));
  }

  function linksTable(links, focus) {
    if (!links.length) return `<div class="empty">Keine Verbindungen erkannt.</div>`;
    return `<div class="tbl-wrap"><table><thead><tr><th>Verbindung</th><th>Ports</th><th>Geschwindigkeit</th><th>Erkannt über</th><th>VLAN-Abgleich</th></tr></thead><tbody>` + links.map(l => {
      const n = l.A.ports.length, per = n > 1 ? l.A.speed / n : l.A.speed;
      const issue = linkIssue(l);
      const det = issue ? `<details class="lk"><summary><span class="pill warn">${issue} Abweichung${issue > 1 ? "en" : ""}</span> <span class="linkbtn">Details</span></summary><div style="display:grid;gap:4px;margin-top:6px">
        ${l.onlyA.length ? `<div>nur ${esc(l.a)}: ${chips(l.onlyA)}</div>` : ""}${l.onlyB.length ? `<div>nur ${esc(l.b)}: ${chips(l.onlyB)}</div>` : ""}${l.native.length ? `<div>ungetaggt verschieden: ${chips(l.native)}</div>` : ""}</div></details>` : `<span class="pill ok">gleich</span>`;
      const side = (k, x) => `${esc(k)} <span class="mono muted">${esc(x.trunk || x.ports.join(","))}</span>`;
      return `<tr><td><b>${esc(focus && l.b === focus ? l.b : l.a)}</b> ⇄ <b>${esc(focus && l.b === focus ? l.a : l.b)}</b></td><td>${side(l.a, l.A)}<br>${side(l.b, l.B)}</td><td class="num">${n > 1 ? n + " × " : ""}${speedTxt(per)}</td><td${l.confirmed ? "" : ` title="${esc(unconfTitle(l))}"`}>${l.src === "mac" ? "MAC-Tabellen" : l.confirmed ? "LLDP (beide Seiten)" : "LLDP (nur eine Seite, unbestätigt)"}</td><td>${det}</td></tr>`;
    }).join("") + `</tbody></table></div>`;
  }

  function renderTopo(t) {
    const zs = zones(), NW = 150, NH = 46, DX = 186, DY = 96, PAD = 24;
    let x0 = 10, svg = "", pos = {}, maxH = 0;
    zs.forEach(z => {
      const list = MAP.switches.filter(s => (s.zone || "Ohne Zone") === z), cols = Math.min(2, list.length), rows = Math.ceil(list.length / cols);
      const w = cols * DX + PAD, h = rows * DY + 44;
      svg += `<rect class="zone" x="${x0}" y="10" width="${w}" height="${h}" rx="10"/><text class="zlabel" x="${x0 + 14}" y="30">${esc(z.toUpperCase())}</text>`;
      list.forEach((s, i) => { pos[s.k] = [x0 + PAD / 2 + (i % cols) * DX + DX / 2, 10 + 62 + Math.floor(i / cols) * DY]; });
      x0 += w + 40; maxH = Math.max(maxH, h);
    });
    let edges = "";
    MAP.links.forEach(l => {
      const a = pos[l.a], b = pos[l.b]; if (!a || !b) return;
      edges += `<line class="edge ${l.A.ports.length > 1 ? "thick" : ""} ${linkIssue(l) ? "warn" : ""} ${l.src === "mac" ? "mac" : ""} ${l.confirmed ? "" : "unconf"}" x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}"><title>${esc(l.a)} ⇄ ${esc(l.b)}${l.confirmed ? "" : ` · ${esc(unconfTitle(l))}`}</title></line>`;
    });
    let nodes = "";
    MAP.switches.forEach(s => {
      const p = pos[s.k], ph = physOf(s);
      nodes += `<g class="node ${s.ok ? "" : "bad"}" tabindex="0" role="link" data-goto="${esc(s.k)}" aria-label="${esc(s.k)} öffnen"><rect x="${p[0] - NW / 2}" y="${p[1] - NH / 2}" width="${NW}" height="${NH}" rx="7"/>
        <text class="nname" x="${p[0]}" y="${p[1] - 3}" text-anchor="middle">${esc(s.k)}</text><text class="nmeta" x="${p[0]}" y="${p[1] + 13}" text-anchor="middle">${ph.filter(x => x.o).length}/${ph.length} aktiv</text></g>`;
    });
    t.innerHTML = `<svg viewBox="0 0 ${x0 - 30} ${maxH + 20}" role="img" aria-label="Topologie">${svg}${edges}${nodes}</svg><p class="note">Dicke Linie = Trunk · orange = VLANs unterschiedlich · gestrichelt = ohne LLDP erkannt · gepunktet = unbestätigt (nicht von beiden Switches gemeldet)</p>`;
    const openNode = e => { const g = e.target.closest("[data-goto]"); if (g) go("switches", g.dataset.goto); };
    t.addEventListener("click", openNode);
    t.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openNode(e); } });
  }

  /* ── Switch-Detail (Master-Detail) ── */
  const ST = { off: ["Aus", "st-off"], on: ["An", "st-prot"], protected: ["Protected", "st-prot"], known: ["Bekannte Geräte", "st-known"], radius: ["RADIUS", "st-radius"] };
  const stPill = st => ST[st] ? `<span class="pill ${ST[st][1]}">${ST[st][0]}</span>` : `<span class="muted" title="Konfiguration noch nicht gelesen">–</span>`;
  // Der Zugang eines Ports, wie die Ansicht ihn zeigt und zählt. Ohne NAC (802.1X/MAC-Anmeldung liest und ändert SwitchView dort nicht)
  // gibt es nur An oder Aus: ein eingeschalteter Port heißt „An“ statt „Protected“. Nur die Beschriftung, p.st vom Server bleibt der Schlüssel.
  const stOf = (s, st) => s && !has(s, "nac") ? (st === "off" ? "off" : "on") : st;
  let portIdx = {}, picked = new Set(), pickedFor = null;
  // The server's credential warnings (poller.credential_warnings: fallback to "public", SNMPv3 downgrade, secrets that do not decrypt)
  const warnList = ws => (ws || []).length ? `<div class="banner warn"><ul class="blist">${ws.map(w => `<li>${esc(w)}</li>`).join("")}</ul></div>` : "";

  async function renderSwitchDetail() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    try { await loadMap(!MAP); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    if (!selSwitch || !MAP.switches.some(s => s.k === selSwitch)) selSwitch = MAP.switches.length ? MAP.switches[0].k : null;
    if (pickedFor !== selSwitch) { picked = new Set(); pickedFor = selSwitch; }
    const side = `<nav class="side" aria-label="Switches">${zones().map(z => `<div class="zonehead">${esc(z)}</div>` + MAP.switches.filter(s => (s.zone || "Ohne Zone") === z).map(s => {
      const ph = physOf(s); return `<button type="button" class="si" data-sw="${esc(s.k)}" aria-current="${s.k === selSwitch}">${stDot(s)}<span>${esc(s.k)}</span><span class="c">${ph.filter(p => p.o).length}/${ph.length}</span></button>`; }).join("")).join("")}
      <button type="button" class="btn small add" id="btn-add">Switch hinzufügen</button></nav>`;
    if (!selSwitch) { v.innerHTML = `<div class="md">${side}<div class="card"><div class="empty"><b>Noch keine Switches</b><span>Links „Switch hinzufügen".</span></div></div></div>`; bindSide(); return; }
    const s = MAP.switches.find(x => x.k === selSwitch), ph = physOf(s), trunks = s.ports.filter(p => p.n.startsWith("Trk"));
    const vset = [...new Set(ph.flatMap(p => [...p.u, ...p.t]))].sort((a, b) => a - b);
    if (swVlan && !vset.includes(swVlan)) swVlan = null;
    const links = MAP.links.filter(l => l.a === s.k || l.b === s.k);
    const cnt = st => ph.filter(p => stOf(s, p.st) === st).length;
    const stFacts = (has(s, "nac") ? [["radius", "RADIUS"], ["known", "Bekannte Geräte"], ["protected", "Protected"]] : [["on", "An"]]).concat([["off", "Aus"]]);
    // Schreibwege: SSH-CLI nur bei einem Treiber mit cli und SSH-Zugang, sonst SNMP (wenn SNMP-Schreiben an ist). Was nur über die CLI
    // geht (Sicherung, Konfiguration lesen, RADIUS), zeigt die Ansicht nur bei einem Treiber, der es kann.
    const cli = has(s, "cli"), canW = writable(s), edit = `<button class="btn small" type="button" data-a="edit">Zugang bearbeiten</button>`;
    const banner = !canW ? `<div class="banner">${cli ? "Ohne SSH-Zugang kann SwitchView hier nur lesen." : `Treiber ${esc(s.driver)} hat keine SSH-CLI, Änderungen gehen hier nur per SNMP. SNMP-Schreiben ist aus, SwitchView kann hier nur lesen.`} Für Änderungen: ${edit}</div>`
      : cli && !s.ssh ? `<div class="banner">Ohne SSH-Zugang gehen Änderungen hier nur per SNMP: VLANs, Namen${has(s, "snmp_poe") ? ", PoE" : ""} und Ports aus- und wieder einschalten („An“, die Anmeldung bleibt, wie sie ist). RADIUS, Bekannte Geräte und Protected brauchen SSH. ${edit}</div>`
      : cli && !s.cfgAt ? `<div class="banner">Die Port-Zustände (RADIUS, bekannte Geräte, Protected) sind noch nicht gelesen. <button class="btn small" type="button" data-a="readcfg">Konfiguration lesen</button></div>` : "";
    v.innerHTML = `<div class="md">${side}<div style="display:grid;gap:16px;min-width:0">
      <div class="dhead"><div><h1>${esc(s.k)}</h1><div class="meta">${esc(s.zone)}${s.zone ? " · " : ""}${esc(s.model)} · Firmware <span class="mono">${esc(s.fw)}</span> · <span class="mono">${esc(s.host)}</span> · Treiber <span class="mono">${esc(s.driver || "procurve")}</span> · Stand ${esc(fmtTime(s.lastPoll))}</div></div>
        <div class="actions"><button class="btn small" type="button" data-a="poll">Jetzt abfragen</button>${has(s, "backup") ? `<button class="btn small" type="button" data-a="backup">Konfiguration sichern</button>` : ""}<button class="btn small" type="button" data-a="test">Verbindung testen</button>${edit}</div></div>
      ${s.ok ? "" : `<div class="error">Letzte Abfrage fehlgeschlagen: ${esc(s.error)}</div>`}
      ${warnList(s.credWarnings)}
      ${banner}
      <div class="facts"><span class="fact"><b>${ph.filter(p => p.o).length}</b> / ${ph.length} Ports aktiv</span>${stFacts.map(([k, l]) => `<span class="fact"><b>${cnt(k)}</b> ${l}</span>`).join("")}<span class="fact"><b>${ph.filter(isUplink).length}</b> Uplink-Ports</span></div>
      <section class="card"><div class="card-h"><h2>Ports</h2><span class="sub">VLAN wählen, um es hervorzuheben</span></div>
        <div class="card-b" style="display:grid;gap:12px">
          <div class="vlans" id="sw-vlans">${vset.map(id => `<button type="button" class="vchip" aria-pressed="${id === swVlan}" data-v="${esc(id)}" style="--vc:${vcol(id)}"><i class="sw"></i><span class="id">${esc(id)}</span><span class="nm">${esc(vname(id))}</span></button>`).join("")}</div>
          <div class="filterhint" id="sw-hint"></div>
          <div class="plate"><div class="plate-in" id="plate"></div></div>
          ${trunks.length ? `<div class="trunks">${trunks.map(t => `<button type="button" class="trk" data-p="${esc(t.n)}"><b>${esc(t.n)}</b><span>Ports ${esc(t.mb.join(", "))} · ${speedTxt(t.s)}</span></button>`).join("")}</div>` : ""}
          <div class="legend"><span><i class="lg-port up" style="--lgc:#2563eb"></i>aktiv · Farbe oben = ungetaggtes VLAN</span><span><i class="lg-port down"></i>kein Link</span><span><i class="lg-port up link"></i>zu anderem Switch</span><span><b class="mono" style="color:var(--accent);font-size:10px">R</b>RADIUS</span><span><b class="mono" style="color:var(--violet);font-size:10px">K</b>Bekannte Geräte</span><span><i class="lg-port adown"></i>Aus</span><span><span class="mono muted">+8</span>getaggte VLANs</span><span><span class="mono" style="color:var(--accent);font-size:10px">T2</span>in Trunk 2</span></div>
        </div></section>
      <section class="card"><div class="card-h"><h2>Port-Liste</h2>
          <div class="right toolrow"><div class="seg" role="group" aria-label="Ports filtern" id="pf">${[["all", "Alle"], ["up", "Aktiv"], ["free", "Frei"], ["nac", "RADIUS/Bekannt"], ["uplink", "Uplinks"]].map(([k, l]) => `<button type="button" data-f="${k}" aria-pressed="${swPortFilter === k}">${l}</button>`).join("")}</div>
          <input type="search" id="pt" placeholder="Port, Gerät, Beschreibung" aria-label="Ports durchsuchen" value="${esc(swText)}"></div></div>
        <div class="selbar" id="selbar" hidden><span><b id="selcount">0</b> Ports ausgewählt</span><button class="btn small primary" type="button" id="sel-edit">Bearbeiten</button><button class="btn small ghost" type="button" id="sel-clear">Auswahl aufheben</button></div>
        <div class="tbl-wrap"><table><thead><tr><th class="ck">${canW ? `<input type="checkbox" id="pick-all" aria-label="Alle angezeigten Ports auswählen">` : ""}</th><th>Port</th><th>Link</th><th>Zugang</th><th>Ungetaggt</th><th>Getaggt</th><th>Beschreibung</th><th>Gerät / Nachbar</th></tr></thead><tbody id="ptbody"></tbody></table></div></section>
      ${radiusCard(s)}
      ${canW ? `<section class="card"><div class="card-h"><h2>Änderungen</h2><span class="sub">an diesem Switch, neueste zuerst</span></div><div id="sw-changes"><div class="empty">Lade …</div></div></section>` : ""}
      <section class="card"><div class="card-h"><h2>Verbindungen</h2><span class="sub">${links.length} zu anderen Switches</span></div>${linksTable(links, s.k)}</section>
    </div></div>`;
    bindSide();
    portIdx = {}; s.ports.forEach(p => portIdx[p.n] = p);
    renderPlate(s); renderPortRows(s); applySwFilter(s); syncPicked();
    $("#sw-vlans").addEventListener("click", e => { const b = e.target.closest("[data-v]"); if (!b) return; swVlan = swVlan === b.dataset.v ? null : b.dataset.v; document.querySelectorAll("#sw-vlans [data-v]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.v === swVlan))); applySwFilter(s); renderPortRows(s); });
    $("#pf").addEventListener("click", e => { const b = e.target.closest("[data-f]"); if (!b) return; swPortFilter = b.dataset.f; document.querySelectorAll("#pf [data-f]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.f === swPortFilter))); renderPortRows(s); });
    $("#pt").addEventListener("input", e => { swText = e.target.value.trim().toLowerCase(); renderPortRows(s); });
    $("#ptbody").addEventListener("change", e => { const c = e.target.closest("input[data-pick]"); if (!c) return; c.checked ? picked.add(c.dataset.pick) : picked.delete(c.dataset.pick); syncPicked(); });
    // Pick-all leaves trunk members out (they take only name and on / off, editPorts would lock the rest for the whole selection);
    // unticking it clears every shown port, members picked one by one included
    $("#pick-all") && $("#pick-all").addEventListener("change", e => { document.querySelectorAll("#ptbody input[data-pick]").forEach(c => { if (e.target.checked && isMember(portIdx[c.dataset.pick])) return; c.checked = e.target.checked; e.target.checked ? picked.add(c.dataset.pick) : picked.delete(c.dataset.pick); }); syncPicked(); });
    $("#sel-edit").addEventListener("click", () => editPorts(s, [...picked]));
    $("#sel-clear").addEventListener("click", () => { picked.clear(); document.querySelectorAll("#ptbody input[data-pick]").forEach(c => c.checked = false); syncPicked(); });
    v.onclick = e => {
      if (e.target.closest("input[data-pick], label.pick")) return;
      const a = e.target.closest("[data-a]"); if (a && !a.closest(".dhead")) return switchAction(e, s);
      const t = e.target.closest("[data-p]"); if (t && !t.closest(".side")) openPort(s, t.dataset.p, t);
    };
    $(".dhead .actions").addEventListener("click", e => switchAction(e, s));
    if (canW) renderChangesInto($("#sw-changes"), s.id, 10);
  }
  function syncPicked() {
    const bar = $("#selbar"); if (!bar) return;
    bar.hidden = picked.size === 0; $("#selcount").textContent = picked.size;
    document.querySelectorAll("#plate .port").forEach(el => el.classList.toggle("picked", picked.has(el.dataset.p)));
  }
  function radiusCard(s) {
    if (!s.ssh || !has(s, "nac")) return "";
    const r = s.ready, rs = !!(MAP && s.cfgAt);
    const li = (ok, t) => `<li class="${ok ? "ok" : "miss"}"><span class="st-dot ${ok ? "" : "down"}"></span>${t}</li>`;
    const miss = r && !(r.host && r.coa && r.tw && r.eap && r.active && r.park);
    return `<section class="card"><div class="card-h"><h2>RADIUS am Switch</h2><span class="sub">${rs ? "Stand " + esc(fmtTime(s.cfgAt)) : "noch nicht gelesen"}</span>
      <div class="right"><button class="btn small" type="button" data-a="readcfg">Neu lesen</button><button class="btn small" type="button" data-a="pa">Anmeldungen anzeigen</button>${miss ? `<button class="btn small primary" type="button" data-a="prepare">Vorbereiten</button>` : ""}</div></div>
      <div class="card-b">${r ? `<ul class="checks">${li(r.host, "RADIUS-Server (PacketFence) eingetragen")}${li(r.coa, "CoA erlaubt (dyn-authorization), damit PacketFence umschalten kann")}${li(r.tw, "CoA ohne Zeitstempel erlaubt (time-window 0), PacketFence schickt keinen")}${li(r.eap, "802.1X-Methode eap-radius")}${li(r.active, "802.1X am Switch aktiv")}${li(r.park, "Park-VLAN 3999 angelegt (für Unbekannte)")}</ul>
        ${r.login_radius ? `<p class="note">Die Anmeldung am Switch selbst nutzt RADIUS.</p>` : ""}${r.others && r.others.length ? `<p class="note">Weitere RADIUS-Server: ${esc(r.others.join(", "))}</p>` : ""}
        ${miss ? `<p class="note">Für die Zustände RADIUS und Bekannte Geräte muss der Switch vorbereitet sein. „Vorbereiten" fügt nur fehlende Zeilen hinzu und ändert keinen Port.</p>` : ""}`
        : `<p class="note" style="margin:0">Konfiguration noch nicht gelesen.</p>`}</div></section>`;
  }
  function bindSide() {
    document.querySelectorAll(".side .si").forEach(b => b.addEventListener("click", () => { swVlan = null; swPortFilter = "all"; swText = ""; go("switches", b.dataset.sw); }));
    $("#btn-add").addEventListener("click", () => editSwitch(null));
  }
  function renderPlate(s) {
    const ph = physOf(s), main = ph.filter(p => isNum(p.n) && +p.n <= 48).sort((a, b) => +a.n - +b.n), extra = ph.filter(p => !isNum(p.n) || +p.n > 48);
    const tile = p => {
      const u = p.u[0] || "", st = ST[stOf(s, p.st)], lab = `Port ${p.n}, ${st ? st[0] + ", " : ""}${p.o ? "aktiv, " + speedTxt(p.s) : "kein Link"}, ungetaggt ${u ? "VLAN " + u : "keins"}${p.t.length ? ", " + p.t.length + " VLANs getaggt" : ""}${p.tr ? ", " + p.tr : ""}${p.a ? ", " + p.a : ""}`;
      const sb = p.st === "radius" ? `<span class="sb r">R</span>` : p.st === "known" ? `<span class="sb k">K</span>` : "";
      return `<button type="button" class="port ${p.o ? "up" : "down"} ${p.ad ? "" : "adown"} ${isPeer(p) ? "link" : ""}" style="--vc:${u ? vcol(u) : "transparent"}" data-p="${esc(p.n)}" aria-label="${esc(lab)}" title="${esc(lab)}">${p.o ? '<i class="st"></i>' : ""}${p.tr ? `<span class="tk">${esc(p.tr.replace("Trk", "T"))}</span>` : ""}${sb}<span class="pn">${esc(p.n)}</span>${p.t.length ? `<span class="tg">+${p.t.length}</span>` : ""}</button>`;
    };
    let html = "";
    for (let i = 0; i < main.length; i += 12) { const g = main.slice(i, i + 12); html += `<div><div class="blabel">${g[0].n}–${g[g.length - 1].n}</div><div class="block">${g.filter(p => +p.n % 2 === 1).map(tile).join("")}${g.filter(p => +p.n % 2 === 0).map(tile).join("")}</div></div>`; }
    if (extra.length) html += `<div><div class="blabel">Uplink</div><div class="block" style="grid-template-columns:repeat(${Math.max(1, Math.ceil(extra.length / 2))},32px)">${extra.filter((_, i) => i % 2 === 0).map(tile).join("")}${extra.filter((_, i) => i % 2 === 1).map(tile).join("")}</div></div>`;
    $("#plate").innerHTML = html || `<div class="empty">Noch keine Portdaten.</div>`;
  }
  function applySwFilter(s) {
    const plate = $("#plate").closest(".plate"); plate.classList.toggle("dim", !!swVlan);
    let nu = 0, nt = 0;
    document.querySelectorAll("#plate .port").forEach(el => {
      const p = portIdx[el.dataset.p]; el.classList.remove("hit-u", "hit-t"); el.style.removeProperty("--vfc");
      if (!swVlan) return; el.style.setProperty("--vfc", vcol(swVlan));
      if (p.u.includes(swVlan)) { el.classList.add("hit-u"); nu++; } else if (p.t.includes(swVlan)) { el.classList.add("hit-t"); nt++; }
    });
    $("#sw-hint").innerHTML = swVlan ? `<b>VLAN ${esc(swVlan)} · ${esc(vname(swVlan))}</b>: ${nu} Ports ungetaggt (gefüllt), ${nt} getaggt (schraffiert)` : "";
  }
  function renderPortRows(s) {
    const ph = physOf(s).slice().sort((a, b) => (isNum(a.n) ? +a.n : 999) - (isNum(b.n) ? +b.n : 999));
    const rows = ph.filter(p => {
      if (swPortFilter === "up" && !p.o) return false;
      if (swPortFilter === "free" && (p.o || isUplink(p))) return false;
      if (swPortFilter === "uplink" && !isUplink(p)) return false;
      if (swPortFilter === "nac" && p.st !== "radius" && p.st !== "known") return false;
      if (swVlan && !p.u.includes(swVlan) && !p.t.includes(swVlan)) return false;
      if (swText && !(p.n.toLowerCase() === swText || matches(p, swText))) return false;
      return true;
    });
    const dev = p => p.l.length ? p.l.map(x => `${esc(x[0])} <span class="mono muted">${esc(x[1])}</span>`).join(", ") : p.tr && !p.n.startsWith("Trk") ? `<span class="muted">über ${esc(p.tr)}</span>` : p.mc > 3 ? `<span class="muted">${p.mc} Geräte</span>` : p.d.map(d => esc(d[3] || d[2] || d[4] || d[0])).join(", ") || `<span class="muted">–</span>`;
    const ck = p => writable(s) && !isTrunkPort(p) ? `<label class="pick"><input type="checkbox" data-pick="${esc(p.n)}" ${picked.has(p.n) ? "checked" : ""} aria-label="Port ${esc(p.n)} auswählen"></label>` : "";
    $("#ptbody").innerHTML = rows.length ? rows.map(p => `<tr class="clickrow" data-p="${esc(p.n)}"><td class="ck">${ck(p)}</td><td class="mono">${esc(p.n)}</td><td><span class="st-dot ${p.o ? "" : "down"}"></span>${p.o ? speedTxt(p.s) : p.ad ? "kein Link" : "aus"}</td><td>${stPill(stOf(s, p.st))}${uplinkPill(p)}</td><td>${chips(p.u)}</td><td>${chips(p.t, "small", 4)}</td><td>${esc(p.a) || `<span class="muted">–</span>`}</td><td>${dev(p)}</td></tr>`).join("")
      : `<tr><td colspan="8" class="muted">Keine Ports für diesen Filter.</td></tr>`;
    if ($("#pick-all")) $("#pick-all").checked = false;
  }
  const matches = (p, t) => (p.a || "").toLowerCase().includes(t) || p.l.some(x => (x[0] + " " + x[1]).toLowerCase().includes(t)) || p.d.some(d => d.some(v => String(v || "").toLowerCase().includes(t)));
  async function switchAction(e, s) {
    const b = e.target.closest("[data-a]"); if (!b) return;
    if (b.dataset.a === "edit") { const list = await api("GET", "/api/switches"); return editSwitch(list.find(x => x.id === s.id)); }
    if (b.dataset.a === "prepare") return previewChange(s, { mode: "prepare" });
    b.disabled = true;
    try {
      if (b.dataset.a === "poll") { const r = await api("POST", `/api/switches/${s.id}/poll`); toast(r.ok ? `${r.ports} Ports, ${r.macs} MACs gelesen` : r.error); await loadMap(true); renderSwitchDetail(); }
      if (b.dataset.a === "backup") { const r = await api("POST", `/api/switches/${s.id}/backup`); toast(r.ok ? (r.changed ? "Konfiguration gesichert" : "Unverändert seit letzter Sicherung") : r.error); await loadMap(true); renderSwitchDetail(); }
      if (b.dataset.a === "readcfg") { toast("Lese Konfiguration …"); await api("POST", `/api/switches/${s.id}/config/refresh`); await loadMap(true); renderSwitchDetail(); toast("Konfiguration gelesen"); }
      if (b.dataset.a === "test") {
        const r = await api("POST", `/api/switches/${s.id}/test`);
        // unused: ein Weg, den dieser Switch nicht hat (SSH bei einem Treiber ohne CLI), weder erreichbar noch fehlgeschlagen
        const line = (lbl, x) => x.unused ? `<div><span class="st-dot down"></span><b>${lbl}</b> <span class="muted">${esc(x.detail || "")}</span></div>`
          : `<div><span class="st-dot ${x.ok ? "" : "bad"}"></span><b>${lbl}</b> ${x.ok ? "erreichbar" : "fehlgeschlagen"} <span class="muted">${esc(x.detail || x.error || "")}</span></div>`;
        modal(`Verbindungstest ${s.k}`, `<div class="testres">${line("SNMP", r.snmp)}${line("SSH", r.ssh)}</div>${warnList(r.warnings)}`, [{ label: "Schließen", onClick: closeModal }]);
      }
      if (b.dataset.a === "pa") { const r = await api("POST", `/api/switches/${s.id}/port-access`); modal(`Anmeldungen an ${s.k}`, Object.entries(r).map(([c, o]) => `<p class="eyebrow">${esc(c)}</p><pre class="code">${esc(o || "–")}</pre>`).join(""), [{ label: "Schließen", onClick: closeModal }]); }
    } catch (err) { toast(err.message); } finally { b.disabled = false; }
  }

  /* ── Ports bearbeiten: Formular → Vorschau → Ausführen mit Fortschritt ── */
  const LIMITS = [1, 2, 4, 8, 16, 32];
  function editPorts(s, ports, prev) {
    ports = ports.filter(n => portIdx[n]).sort((a, b) => (isNum(a) ? +a : 999) - (isNum(b) ? +b : 999));
    if (!ports.length) return;
    const ps = ports.map(n => portIdx[n]), f = prev || { status: "", untagged: "", add: [], rem: [], name: "", nameEdited: false, nameClear: false, limit: "", guest: "-", poe: "", expert: false };
    const vl = (s.vl && s.vl.length ? s.vl : Object.keys(MAP.vlans)), tagUnion = [...new Set(ps.flatMap(p => p.t))].sort((a, b) => a - b);
    const curSt = [...new Set(ps.map(p => stOf(s, p.st)))], anyProt = ps.some(p => isUplink(p) || p.n.startsWith("Trk"));
    // 802.1X / MAC-Anmeldung (RADIUS, Bekannte Geräte, Geräte pro Port, Gast-VLAN) gibt es nur über die SSH-CLI; Protected auf einem
    // Treiber mit NAC auch (es heißt dort Anmeldung aus). Ohne CLI-Treiber oder ohne SSH-Zugang gesperrt, mit dem Grund im Formular.
    // „An“ schaltet nur ein, die Anmeldung bleibt, wie sie ist: das geht auf jedem Treiber und auf beiden Wegen.
    const nacCap = has(s, "cli") && has(s, "nac"), nac = nacCap && s.ssh, protOk = nac || !has(s, "nac");
    const nacWhy = nac ? "" : nacCap
      ? "Ohne SSH-Zugang gehen RADIUS, Bekannte Geräte und Protected, Geräte pro Port und Gast-VLAN nicht: per SNMP gibt es keine 802.1X-/MAC-Anmeldung. Einschalten geht mit „An“."
      : `Treiber ${s.driver} schreibt per SNMP: RADIUS, Bekannte Geräte, Geräte pro Port und Gast-VLAN gehen nur über die SSH-CLI (ProCurve).`;
    // Trunk members (tr = their trunk) take only name and on / off (changes.MEMBER_FIELDS); VLANs, NAC and PoE go through the trunk
    const memPs = ps.filter(isMember), mem = memPs.length > 0;
    const memWhy = mem ? `Trunk-Mitglied (${memPs.map(p => p.n).join(", ")}): VLANs, Anmeldung und PoE nur über den Trunk – hier gehen Name und An/Aus.` : "";
    const memGate = mem ? ' disabled aria-describedby="f-gate-mem"' : "";
    const nacOff = { radius: !nac, known: !nac, protected: !protOk };
    const stOff = { radius: nacOff.radius || mem, known: nacOff.known || mem, protected: nacOff.protected || mem };
    const stGate = k => [nacOff[k] ? "f-gate-nac" : "", mem ? "f-gate-mem" : ""].filter(Boolean).join(" ");
    // Ohne NAC nur An und Aus: RADIUS und Bekannte Geräte gibt es dort nicht, und Protected hieße nichts anderes als An
    const opts = [["", "Unverändert", curSt.length > 1 ? "gemischt" : ST[curSt[0]] ? "jetzt: " + ST[curSt[0]][0] : "jetzt: unbekannt"],
      ...(has(s, "nac") ? [["radius", "RADIUS", "Zertifikat (802.1X), sonst bekannte Geräte"], ["known", "Bekannte Geräte", "nur Geräte aus der Geräte-DB, per MAC"],
        ["protected", "Protected", "festes VLAN, egal wer steckt"]] : []),
      ["on", "An", "einschalten, Anmeldung (802.1X/MAC) bleibt, wie sie ist"], ["off", "Aus", "Port abgeschaltet"]];
    // PoE nur bei einem Treiber mit snmp_poe und nur, wenn jeder gewählte Port einen zugeordneten PoE-Eintrag hat (netmap: poe)
    const poeCap = has(s, "snmp_poe"), noPoe = ps.filter(p => !p.poe), poeAll = poeCap && !noPoe.length;
    const poeNow = [...new Set(ps.map(p => p.poe && p.poe.on))];
    const poeHtml = poeAll ? `<div class="grid2"><div class="field"><label for="f-poe">PoE</label><select id="f-poe" aria-describedby="f-poe-hint${s.snmp_write ? "" : " f-gate-poe"}${mem ? " f-gate-mem" : ""}" ${s.snmp_write && !mem ? "" : "disabled"}><option value="">unverändert</option><option value="on" ${f.poe === "on" ? "selected" : ""}>an</option><option value="off" ${f.poe === "off" ? "selected" : ""}>aus</option></select>
        <span class="hint" id="f-poe-hint">jetzt: ${esc(ps.length === 1 ? poeTxt(ps[0].poe) : poeNow.length === 1 ? onTxt(poeNow[0]) : "gemischt")}</span></div></div>
      ${!s.snmp_write ? `<p class="note gate" id="f-gate-poe">PoE schaltet SwitchView nur per SNMP: dafür im Zugang „SNMP darf schreiben“ einschalten.</p>`
        : has(s, "cli") ? `<p class="note" style="margin:0">PoE geht immer per SNMP, auch wenn SSH geht. Zusammen mit RADIUS, Bekannte Geräte, Protected, Geräte pro Port oder Gast-VLAN geht es nicht: bitte getrennt ändern.</p>` : ""}`
      : poeCap && noPoe.length < ps.length ? `<p class="note gate">PoE nur, wenn jeder gewählte Port PoE hat (ohne PoE: ${esc(noPoe.map(p => p.n).join(", "))}).</p>` : "";
    const chipBtns = (ids, sel, attr) => ids.length ? `<div class="chipset">${ids.map(id => `<button type="button" class="vchip small" data-${attr}="${esc(id)}" aria-pressed="${sel.includes(id)}" style="--vc:${vcol(id)}"${memGate}><i class="sw"></i><span class="id">${esc(id)}</span><span class="nm">${esc(vname(id))}</span></button>`).join("")}</div>` : `<span class="muted" style="font-size:12.5px">keine</span>`;
    const lims = LIMITS.filter(n => n <= (s.limitMax || 2));
    const body = `<p class="note" style="margin:0">${ports.length === 1 ? "Port" : ports.length + " Ports"}: <span class="mono">${esc(ports.join(", "))}</span></p>
      ${memWhy ? `<p class="note gate" id="f-gate-mem">${esc(memWhy)}</p>` : ""}
      <fieldset class="fs"><legend>Zustand</legend><div class="opts" role="radiogroup" aria-label="Zustand">${opts.map(([k, t, d]) => `<label class="opt"><input type="radio" name="f-st" value="${k}" ${f.status === k ? "checked" : ""} ${stOff[k] ? `disabled aria-describedby="${stGate(k)}"` : ""}><b>${t}</b><span>${esc(d)}</span></label>`).join("")}</div>
        ${nacWhy ? `<p class="note gate" id="f-gate-nac">${esc(nacWhy)}</p>` : ""}</fieldset>
      <div class="grid2"><label class="field"><span>VLAN ungetaggt</span><select id="f-u"${memGate}><option value="">unverändert</option>${vl.map(id => `<option value="${esc(id)}" ${f.untagged === id ? "selected" : ""}>${esc(id)} · ${esc(vname(id))}</option>`).join("")}</select><span class="hint" id="f-u-hint"></span></label>
        <label class="field"><span>Beschreibung</span><input id="f-name" value="${esc(f.name)}" maxlength="64" placeholder="unverändert" autocomplete="off"><span class="hint">ohne Leerzeichen, z. B. Drucker-EK</span></label></div>
      <label class="check"><input type="checkbox" id="f-nclear" ${f.nameClear ? "checked" : ""}> Beschreibung entfernen</label>
      ${poeHtml}
      <details class="adv"><summary>Getaggte VLANs, Geräte pro Port, Gast-VLAN</summary><div style="display:grid;gap:12px;margin-top:10px">
        <div class="field"><span>Getaggt hinzufügen</span>${chipBtns(vl, f.add, "ta")}</div>
        <div class="field"><span>Getaggt entfernen</span>${chipBtns(tagUnion, f.rem, "tr")}</div>
        <div class="grid2"><div class="field"><label for="f-lim">Geräte pro Port</label><select id="f-lim" aria-describedby="f-lim-hint${mem ? " f-gate-mem" : ""}" ${nac && !mem ? "" : "disabled"}><option value="">unverändert${ps.every(p => !p.lim) ? " (Standard 1)" : ""}</option>${lims.map(n => `<option value="${n}" ${String(f.limit) === String(n) ? "selected" : ""}>${n}</option>`).join("")}</select><span class="hint" id="f-lim-hint">${nac ? "gilt für RADIUS und Bekannte Geräte" : "nur über die SSH-CLI (ProCurve mit SSH-Zugang)"}</span></div>
          <div class="field"><label for="f-guest">Gast-VLAN für Unbekannte</label><select id="f-guest" aria-describedby="f-guest-hint${mem ? " f-gate-mem" : ""}" ${nac && !mem ? "" : "disabled"}><option value="-">unverändert</option><option value="" ${f.guest === "" ? "selected" : ""}>keins (gesperrt)</option>${vl.map(id => `<option value="${esc(id)}" ${f.guest === id ? "selected" : ""}>${esc(id)} · ${esc(vname(id))}</option>`).join("")}</select><span class="hint" id="f-guest-hint">${nac ? "statt Sperre, wenn die Anmeldung scheitert" : "nur über die SSH-CLI (ProCurve mit SSH-Zugang)"}</span></div></div>
      </div></details>
      ${anyProt ? `<label class="check warnbox"><input type="checkbox" id="f-expert" ${f.expert ? "checked" : ""}> Expertenmodus: Uplinks/Trunks ändern. Falsch gesetzt, trennt das den Switch vom Netz.</label>` : ""}`;
    const collect = () => {
      f.status = (document.querySelector('input[name="f-st"]:checked') || {}).value || "";
      f.untagged = mem ? "" : $("#f-u").value; f.name = $("#f-name").value.trim().replace(/\s+/g, "_"); f.nameClear = $("#f-nclear").checked;
      f.add = mem ? [] : [...document.querySelectorAll("[data-ta][aria-pressed=true]")].map(b => b.dataset.ta); f.rem = mem ? [] : [...document.querySelectorAll("[data-tr][aria-pressed=true]")].map(b => b.dataset.tr);
      f.limit = nac && !mem ? $("#f-lim").value : ""; f.guest = nac && !mem ? $("#f-guest").value : "-"; f.poe = poeAll && s.snmp_write && !mem ? $("#f-poe").value : "";
      f.expert = !!($("#f-expert") && $("#f-expert").checked);
      const c = {};
      if (f.status && !stOff[f.status]) c.status = f.status;
      if (f.untagged) c.untagged = f.untagged;
      if (f.add.length) c.tagged_add = f.add;
      if (f.rem.length) c.tagged_remove = f.rem;
      // name nur, wenn jemand ihn hier eingetippt hat: das Feld zeigt nie die Beschreibung von der Anzeige (die ist dort unter Umständen
      // maskiert oder als Hex), sonst schriebe ein Absenden genau diese Form auf den Switch
      if (f.nameClear) c.name = ""; else if (f.nameEdited && f.name) c.name = f.name;
      if (f.limit) c.limit = +f.limit;
      if (f.guest !== "-") c.guest = f.guest;
      if (f.poe) c.poe = f.poe === "on";
      return { mode: "ports", ports, change: c, expert: f.expert };
    };
    modal(ports.length === 1 ? `Port ${ports[0]} bearbeiten` : `${ports.length} Ports bearbeiten`, body, [
      { label: "Abbrechen", onClick: closeModal },
      { label: "Vorschau", cls: "primary", onClick: () => { const payload = collect(); if (!Object.keys(payload.change).length) { toast("Nichts ausgewählt, was sich ändern soll"); return; } previewChange(s, payload, () => editPorts(s, ports, f)); } }]);
    $("#m-body").onclick = e => { const b = e.target.closest("[data-ta],[data-tr]"); if (b) b.setAttribute("aria-pressed", String(b.getAttribute("aria-pressed") !== "true")); };
    $("#f-name").addEventListener("input", () => { f.nameEdited = true; });
    const hint = () => { const st = (document.querySelector('input[name="f-st"]:checked') || {}).value; $("#f-u-hint").textContent = st === "radius" || st === "known" ? "gilt, wenn PacketFence kein VLAN vorgibt" : st === "protected" ? "jedes Gerät landet in diesem VLAN" : ""; };
    document.querySelectorAll('input[name="f-st"]').forEach(r => r.addEventListener("change", hint)); hint();
  }

  async function previewChange(s, payload, back) {
    const title = payload.mode === "prepare" ? `RADIUS vorbereiten: ${s.k}` : payload.mode === "revert" ? `Rückgängig #${payload.of}` : payload.mode === "save" ? "Speichern (write memory)" : "Vorschau";
    modal(title, `<div class="empty">Lese die aktuelle Konfiguration von ${esc(s.k)} …</div>`, []);
    let r, row;
    try { [r, row] = await Promise.all([api("POST", `/api/switches/${s.id}/plan`, payload), liveRow(s)]); }
    catch (e) { modal(title, `<div class="error">${esc(e.message)}</div>`, [...(back ? [{ label: "Zurück", onClick: back }] : []), { label: "Schließen", onClick: closeModal }]); return; }
    const can = !r.blocked.length && (r.commands.length || r.kind === "save"), snmp = r.mechanism === "snmp", caps = (row && row.caps) || s.caps || [];
    // Per SNMP gibt es kein Staging und kein Backup: der SET wirkt sofort. Dauerhaft gespeichert ist er nur bei einem Treiber, der das
    // selbst tut (snmp_autosave, R26), und der speichert dabei die gesamte laufende Konfiguration (welche SSH-Änderungen das mitspeichert,
    // sagt eine Warnung des Servers); sonst bleibt das Speichern am Switch. Geht der SET fälschbar hinaus (snmp_rw_insecure), sagt es die
    // Vorschau laut.
    const way = !can || !snmp ? "" : (caps.includes("snmp_autosave")
      ? `<div class="banner"><span><b>Wird per SNMP sofort angewendet und automatisch gespeichert – der Switch speichert dabei die gesamte laufende Konfiguration.</b> Kein gestuftes write memory, kein Backup über diesen Weg.</span></div>`
      : `<div class="banner warn"><span><b>Wird per SNMP sofort angewendet, aber NICHT dauerhaft gespeichert – danach am Switch speichern (z. B. write memory / copy running-config startup-config).</b> Kein Backup über diesen Weg.</span></div>`)
      + (row ? insecureBanner(row) : "");
    const poeNote = snmp && caps.includes("cli") && payload.change && payload.change.poe != null ? " PoE schaltet SwitchView immer per SNMP, auch wenn SSH geht." : "";
    const body = `<p style="margin:0"><b>${esc(r.summary)}</b> <span class="muted">· ${esc(s.k)}</span></p>
      ${r.blocked.length ? `<div class="error"><b>Nicht möglich:</b><ul class="blist">${r.blocked.map(b => `<li>${b.port === "*" ? "" : "Port " + esc(b.port) + ": "}${esc(b.reason)}</li>`).join("")}</ul></div>` : ""}
      ${way}
      ${r.warnings.length ? `<div class="banner warn"><ul class="blist">${r.warnings.map(w => `<li>${esc(w)}</li>`).join("")}</ul></div>` : ""}
      ${r.commands.length ? `<div><p class="eyebrow">${snmp ? "Änderungen per SNMP" : "Befehle am Switch"}</p><pre class="code">${esc(r.commands.join("\n"))}</pre></div>` : r.kind === "save" ? "" : `<div class="banner">Es gibt nichts zu ändern, die Ports sind schon so eingestellt.</div>`}
      ${can ? `<p class="note" style="margin:0">${snmp ? "Danach liest SwitchView den Zustand per SNMP zurück und prüft ihn." + poeNote : "Danach liest SwitchView die Konfiguration zurück und prüft sie. Erst wenn alles passt, wird gespeichert (write memory)."}</p>` : ""}`;
    const btns = [];
    if (back) btns.push({ label: "Zurück", onClick: back });
    btns.push({ label: "Abbrechen", onClick: closeModal });
    if (can) btns.push({ label: r.kind === "save" ? "Speichern" : "Ausführen", cls: "primary", onClick: async b => {
      b.disabled = true;
      // genau der Schreibweg dieser Vorschau (nie eine eigene Wahl): geht er nicht mehr, lehnt der Server ab statt still den anderen zu nehmen
      try { const res = await api("POST", `/api/switches/${s.id}/apply`, { ...payload, mechanism: r.mechanism, token: r.token }); runProgress(s, res.id); }
      catch (e) { toast(e.message); b.disabled = false; }
    } });
    modal(title, body, btns);
  }
  // Die Switch-Zeile, wie der Server sie jetzt kennt (Treiber-Fähigkeiten, Schreib-Identität; der Netzplan im Browser kann älter sein),
  // oder null: dann gelten die Fähigkeiten aus dem Netzplan
  async function liveRow(s) {
    try { return (await api("GET", "/api/switches")).find(x => x.id === s.id) || null; } catch (e) { return null; }
  }

  const CH = { queued: ["wartet", "neutral"], running: ["läuft", "neutral"], ok: ["erledigt", "ok"], unclear: ["unklar", "warn"], failed: ["fehlgeschlagen", "crit"], aborted: ["abgebrochen", "neutral"] };
  const chPill = c => `<span class="pill ${CH[c.status] ? CH[c.status][1] : "neutral"}">${CH[c.status] ? CH[c.status][0] : esc(c.status)}</span>${c.status !== "ok" && c.saved ? ` <span class="pill ok">gespeichert</span>` : ""}${c.status === "ok" && !c.saved ? ` <span class="pill warn">nicht gespeichert</span>` : ""}${c.reverted_by ? ` <span class="pill neutral">zurückgenommen</span>` : ""}`;
  const stepsHtml = c => `<ul class="steps">${(c.steps || []).map(x => `<li class="${esc(x[2])}"><span class="t">${esc(fmtTime(x[0]).split(", ").pop())}</span><span>${esc(x[1])}</span></li>`).join("")}</ul>`;
  // Ergebnis einer Änderung. Gespeichert heißt nur saved=1. "unklar" in den Worten des Servers: sein letzter Fehlerschritt ist der Fehler
  // plus, was offen ist (per SNMP, ob das Übernommene schon gespeichert ist, nach dem Treiber zur Laufzeit; per SSH changes.SSH_KEPT: was
  // der Switch von den Befehlen übernommen hat, wirkt ungespeichert, oder ob write memory durchging). Beginnt er nicht mit dem Fehler der
  // Änderung (etwa nach einem Neustart, der nur den Fehler setzt), gilt per SNMP der Fehler allein, per SSH mit dem Satz für Befehle. Eine
  // SSH-Änderung, die danach gespeichert wurde („Trotzdem speichern“, R42), heißt gespeichert.
  function resultHead(c) {
    const lastErr = [...(c.steps || [])].reverse().find(x => x[2] === "error"), err = c.error || "";
    const told = lastErr && lastErr[1].startsWith(err) ? lastErr[1] : "";
    const unclear = c.mechanism === "snmp" ? (told || err)
      : c.saved ? `${sentence(err)} Die Änderung ist gespeichert.`
      : told && told !== err ? told : `${sentence(err)} Was der Switch davon übernommen hat, wirkt schon, ist aber nicht dauerhaft gespeichert.`;
    // "Abgebrochen durch Neustart …" (changes.mark_interrupted) reads "Abgebrochen: durch Neustart …", not "Abgebrochen: Abgebrochen …"
    const aborted = err.replace(/^Abgebrochen\s+/, "");
    return { ok: c.saved ? `<div class="banner ok"><b>Erledigt und gespeichert.</b></div>` : `<div class="banner warn"><b>Erledigt, aber nicht dauerhaft gespeichert – am Switch speichern.</b></div>`,
      unclear: `<div class="banner warn"><span><b>Unklar:</b> ${esc(unclear)}</span></div>`,
      failed: `<div class="error"><b>Fehlgeschlagen:</b> ${esc(err)}</div>`, aborted: `<div class="banner"><span><b>Abgebrochen:</b> ${esc(aborted)}</span></div>` }[c.status] || "";
  }
  async function runProgress(s, id) {
    modal(`Änderung #${id}`, `<div id="prog"><div class="empty">Starte …</div></div>`, [{ label: "Schließen", onClick: closeModal }]);
    for (;;) {
      if (!$("#prog")) return;
      let c; try { c = await api("GET", `/api/changes/${id}`); } catch (e) { $("#prog").innerHTML = `<div class="error">${esc(e.message)}</div>`; return; }
      const done = ["ok", "unclear", "failed", "aborted"].includes(c.status);
      const head = resultHead(c);
      if (!$("#prog")) return;
      $("#prog").innerHTML = `<p style="margin:0 0 10px"><b>${esc(c.summary)}</b></p>${head}<div style="margin-top:10px">${stepsHtml(c)}</div>${done && c.output ? `<details class="adv"><summary>Ausgabe des Switches</summary><pre class="code">${esc(c.output)}</pre></details>` : ""}`;
      if (done) {
        const btns = [];
        // Which follow-up actions a change has is the server's rule (can_revert / can_save, changes.actions_of): none for a change that
        // sent nothing, no save (write memory) over SNMP. Here "Rückgängig" only after unclear / failed, as before; the list offers it after ok
        if (["unclear", "failed"].includes(c.status) && c.can_revert) btns.push({ label: "Rückgängig", onClick: () => previewChange(s, { mode: "revert", of: id }) });
        if (c.can_save) btns.push({ label: "Trotzdem speichern", onClick: () => previewChange(s, { mode: "save", of: id }) });
        btns.push({ label: "Schließen", cls: "primary", onClick: closeModal });
        const foot = $("#m-foot"); foot.innerHTML = "";
        btns.forEach(b => { const el = document.createElement("button"); el.type = "button"; el.className = "btn " + (b.cls || ""); el.textContent = b.label; el.addEventListener("click", () => b.onClick(el)); foot.appendChild(el); });
        if (c.status === "ok") toast(c.saved ? "Änderung erledigt" : "Änderung erledigt, aber nicht dauerhaft gespeichert");
        setTimeout(async () => { try { await loadMap(true); if (current === "switches") { const keep = picked; renderSwitchDetail(); picked = c.status === "ok" ? new Set() : keep; syncPicked(); } } catch (e) { /* egal */ } }, c.kind === "save" ? 200 : 4500);
        return;
      }
      await new Promise(res => setTimeout(res, 1200));
    }
  }

  async function renderChangesInto(el, switchId, limit) {
    if (!el) return;
    let rows;
    try { rows = await api("GET", `/api/changes?limit=${limit || 100}${switchId ? "&switch_id=" + switchId : ""}`); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    if (!rows.length) { el.innerHTML = `<div class="empty">Noch keine Änderungen.</div>`; return; }
    el.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>#</th><th>Zeit</th><th>Benutzer</th>${switchId ? "" : "<th>Switch</th>"}<th>Änderung</th><th>Status</th><th></th></tr></thead><tbody>` + rows.map(c =>
      `<tr><td class="num">${c.id}</td><td class="num">${esc(fmtTime(c.created_at))}</td><td>${esc(c.username || "")}</td>${switchId ? "" : `<td>${esc(c.switch_name)}</td>`}<td>${esc(c.summary)}</td><td>${chPill(c)}</td>
        <td><div class="actions"><button class="btn small" type="button" data-cd="${c.id}">Details</button>${c.can_revert ? `<button class="btn small" type="button" data-cr="${c.id}" data-sw="${c.switch_id}">Rückgängig</button>` : ""}</div></td></tr>`).join("") + `</tbody></table></div>`;
    el.onclick = async e => {
      const d = e.target.closest("[data-cd]"), r = e.target.closest("[data-cr]");
      const swOf = id => MAP && MAP.switches.find(x => x.id === id);
      if (d) {
        const c = await api("GET", `/api/changes/${d.dataset.cd}`);
        modal(`Änderung #${c.id}`, `<p style="margin:0"><b>${esc(c.summary)}</b></p><p class="note" style="margin:0">${esc(c.switch_name)} · ${esc(c.username || "")} · ${esc(fmtTime(c.created_at))}${c.mechanism === "snmp" ? " · per SNMP" : ""} · ${chPill(c)}</p>
          ${c.error ? `<div class="error">${esc(c.error)}</div>` : ""}<div><p class="eyebrow">${c.mechanism === "snmp" ? "Änderungen per SNMP" : "Befehle"}</p><pre class="code">${esc((c.commands || []).join("\n") || "–")}</pre></div>
          <div><p class="eyebrow">Ablauf</p>${stepsHtml(c)}</div>${c.output ? `<details class="adv"><summary>Ausgabe des Switches</summary><pre class="code">${esc(c.output)}</pre></details>` : ""}`,
          [{ label: "Schließen", onClick: closeModal }]);
      }
      if (r) { if (!MAP) await loadMap(false); const s = swOf(+r.dataset.sw); if (s) previewChange(s, { mode: "revert", of: +r.dataset.cr }); }
    };
  }

  /* Port-Panel */
  let drLast = null, selEl = null;
  function openPort(s, n, trigger) {
    const p = portIdx[n]; if (!p) return;
    drLast = trigger || document.activeElement;
    if (selEl) selEl.classList.remove("sel");
    selEl = document.querySelector(`#plate .port[data-p="${CSS.escape(n)}"]`); if (selEl) selEl.classList.add("sel");
    $("#dr-title").textContent = (p.n.startsWith("Trk") ? "" : "Port ") + p.n; $("#dr-sub").textContent = s.k + " · " + s.model;
    const lldp = p.l.length ? p.l.map(x => `<div><b>${esc(x[0])}</b> <span class="mono muted">Port ${esc(x[1])}</span></div>`).join("") : "–";
    const kn = d => d[5] === 2 ? `<span class="pill st-known">freigegeben</span>` : d[5] === 1 ? `<span class="pill neutral">bekannt</span>` : `<button class="btn small" type="button" data-newdev="${esc(d[0])}">Als Gerät anlegen</button>`;
    const devs = p.mc ? `<p class="eyebrow">Gelernte Geräte (${p.mc})</p>${p.mc > p.d.length ? `<p class="note">Viele Geräte, hier die ersten ${p.d.length}.</p>` : ""}<div class="devs">` +
      p.d.map(d => `<div class="dev"><div class="dn">${esc(d[3] || d[4] || "unbekannt")}</div><div>${chip(d[1])}</div><div class="dm">${esc(d[0])}${d[2] ? " · " + esc(d[2]) : ""}${d[3] && d[4] ? " · " + esc(d[4]) : ""}</div><div>${isUplink(p) ? "" : kn(d)}</div></div>`).join("") + `</div>` : "";
    const canEdit = writable(s) && !isTrunkPort(p);
    $("#dr-body").innerHTML = `${canEdit ? `<div style="margin-bottom:12px"><button class="btn small primary" type="button" id="dr-edit">Port bearbeiten</button></div>` : ""}
      <dl class="kv"><dt>Zugang</dt><dd>${stPill(stOf(s, p.st))}${p.lim ? ` <span class="muted">max. ${p.lim} Geräte</span>` : ""}</dd><dt>Link</dt><dd><span class="st-dot ${p.o ? "" : "down"}"></span>${p.o ? "aktiv, " + speedTxt(p.s) : p.ad ? "kein Link" : "administrativ aus"}</dd>
      ${has(s, "snmp_poe") && p.poe ? `<dt>PoE</dt><dd>${esc(poeTxt(p.poe))}</dd>` : ""}
      <dt>Beschreibung</dt><dd>${esc(p.a) || "–"}</dd><dt>Ungetaggt</dt><dd>${chips(p.u, "")}</dd><dt>PVID</dt><dd class="mono">${esc(p.pv) || "–"}</dd><dt>Getaggt</dt><dd>${chips(p.t, "")}</dd>
      <dt>Trunk</dt><dd>${p.n.startsWith("Trk") ? "Ports " + esc(p.mb.join(", ")) : esc(p.tr) || "–"}</dd><dt>Nachbar (LLDP)</dt><dd>${lldp}</dd></dl>${devs}`;
    if (canEdit) $("#dr-edit").addEventListener("click", () => { closeDrawer(true); editPorts(s, [p.n]); });
    $("#dr-body").onclick = e => { const b = e.target.closest("[data-newdev]"); if (!b) return; const d = p.d.find(x => x[0] === b.dataset.newdev); closeDrawer(true); editDevice({ mac: d[0], name: (d[3] || "").replace(/\..*$/, ""), kind: "sonstiges" }, true); };
    $("#drawer").classList.add("open"); $("#drawer").setAttribute("aria-hidden", "false"); $("#scrim").hidden = false; $("#dr-x").focus();
  }
  function closeDrawer(silent) { $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); $("#scrim").hidden = true; if (selEl) selEl.classList.remove("sel"); if (!silent && drLast && drLast.focus) drLast.focus(); }
  $("#dr-x").addEventListener("click", () => closeDrawer()); $("#scrim").addEventListener("click", () => closeDrawer());
  document.addEventListener("keydown", e => { if (e.key !== "Escape") return; if (!$("#modal").hidden) closeModal(); else if ($("#drawer").classList.contains("open")) closeDrawer(); $("#results").hidden = true; });

  /* ── VLANs: Matrix VLAN × Switch ── */
  async function renderVlans() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    try { await loadMap(!MAP); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    const sw = MAP.switches;
    const cnt = (s, id) => { const ph = physOf(s).filter(p => !p.tr); const tr = s.ports.filter(p => p.n.startsWith("Trk")); const all = [...ph, ...tr]; return { u: all.filter(p => p.u.includes(id)).length, t: all.filter(p => p.t.includes(id)).length }; };
    v.innerHTML = `<section class="card"><div class="card-h"><h2>VLANs je Switch</h2><span class="sub">U = Ports ungetaggt, T = getaggt (Trunks zählen einfach). Klick öffnet den Switch mit diesem VLAN.</span></div>
      <div class="tbl-wrap"><table class="matrix"><thead><tr><th>VLAN</th>${sw.map(s => `<th>${esc(s.k)}</th>`).join("")}</tr></thead><tbody>` +
      Object.keys(MAP.vlans).map(id => `<tr><td>${chip(id, "")}</td>${sw.map(s => { const c = cnt(s, id); const exists = s.ports.some(p => p.u.includes(id) || p.t.includes(id));
        return `<td>${exists ? `<button type="button" class="mcell" data-sw="${esc(s.k)}" data-v="${esc(id)}" title="${esc(s.k)} · VLAN ${esc(id)}"><span class="u">U ${c.u}</span><span class="t">T ${c.t}</span></button>` : `<span class="muted">–</span>`}</td>`; }).join("")}</tr>`).join("") +
      `</tbody></table></div></section>`;
    v.querySelector("table").addEventListener("click", e => { const b = e.target.closest(".mcell"); if (!b) return; swVlan = b.dataset.v; swPortFilter = "all"; swText = ""; go("switches", b.dataset.sw); });
  }

  /* ── Globale Suche ── */
  const q = $("#q"), res = $("#results");
  q.addEventListener("input", async () => {
    const term = q.value.trim().toLowerCase().replace(/-/g, ":");
    if (term.length < 2) { res.hidden = true; return; }
    try { await loadMap(false); } catch (e) { return; }
    const hits = [];
    MAP.switches.forEach(s => s.ports.forEach(p => {
      if (p.n.startsWith("Trk")) return;
      if ((p.a || "").toLowerCase().includes(term)) hits.push({ s, p, t: p.a, x: "Port-Beschreibung" });
      p.l.forEach(x => { if ((x[0] + " " + x[1]).toLowerCase().includes(term)) hits.push({ s, p, t: x[0] + " Port " + x[1], x: "LLDP-Nachbar" }); });
      if (p.mc <= 12 && !isPeer(p) && !p.tr) p.d.forEach(d => { if (d.some(val => String(val || "").toLowerCase().includes(term))) hits.push({ s, p, t: d[3] || d[4] || d[0], x: d[0] + (d[2] ? " · " + d[2] : "") + " · VLAN " + d[1] }); });
    }));
    res.innerHTML = hits.length ? hits.slice(0, 30).map(h => `<button type="button" data-sw="${esc(h.s.k)}" data-p="${esc(h.p.n)}"><span class="r1">${esc(h.t)}</span><span class="r3">${esc(h.s.k)} · Port ${esc(h.p.n)}</span><span class="r2">${esc(h.x)}</span></button>`).join("") : `<div class="none">Nichts gefunden. Uplinks mit vielen Geräten werden nicht durchsucht.</div>`;
    res.hidden = false;
  });
  res.addEventListener("click", async e => {
    const b = e.target.closest("[data-sw]"); if (!b) return; res.hidden = true;
    swVlan = null; swPortFilter = "all"; swText = ""; go("switches", b.dataset.sw);
    for (let i = 0; i < 20 && !$("#plate"); i++) await new Promise(r => setTimeout(r, 100));
    const s = MAP.switches.find(x => x.k === b.dataset.sw); if (s) openPort(s, b.dataset.p, q);
  });
  document.addEventListener("click", e => { if (!e.target.closest(".search")) res.hidden = true; });

  /* ── Switch anlegen / bearbeiten ── */
  let DRIVERS = null; // GET /api/drivers: [{name, caps, notes}]
  const CAP_TXT = { snmp_vlan: "VLANs", snmp_admin: "An/Aus", snmp_name: "Namen", snmp_poe: "PoE" };
  const capsTxt = caps => [caps.includes("cli") ? "SSH-CLI" + (caps.includes("nac") ? " mit RADIUS/802.1X" : "") + (caps.includes("backup") ? " und Sicherung" : "") : "keine SSH-CLI",
    "SNMP: " + (Object.keys(CAP_TXT).filter(c => caps.includes(c)).map(c => CAP_TXT[c]).join(", ") || "nichts"),
    caps.includes("snmp_autosave") ? "speichert SNMP-Änderungen selbst" : "speichert SNMP-Änderungen nicht selbst"].join(" · ");
  // Laut, wenn SNMP-SETs an diesen Switch fälschbar hinausgehen (snmp_rw_insecure vom Server: v2c-Community im Klartext oder SNMPv3 ohne
  // Authentifizierung). Für das Formular, den Dialog nach dem Speichern und die SNMP-Vorschau.
  function insecureBanner(s) {
    if (!s.snmp_rw_insecure) return "";
    const v3 = s.snmp_write_via === "rw" ? !!s.snmp_rw_user : s.snmp_version === "3";
    return `<div class="banner crit" role="alert"><span><b>Unsicher:</b> SNMP schreibt hier ${v3 ? "per SNMPv3 ohne Authentifizierung" : "per SNMPv2c, die Community geht im Klartext übers Netz"}. Wer mitliest, kann damit selbst an diesem Switch schreiben. Empfohlen: eigener SNMPv3-Benutzer mit Auth und Verschlüsselung (authPriv).</span></div>`;
  }
  // Mit welcher Identität SNMP-SETs an diesen Switch gehen, gespeicherter Stand (der Server rechnet es mit poller.write_identity)
  function writeState(s) {
    if (!s.snmp_write) return "";
    if (!s.snmp_write_via) return `<div class="error"><b>SNMP-Schreiben geht so nicht:</b> ${esc(s.snmp_write_error || "kein Schreib-Zugang")}</div>`;
    const rw = s.snmp_write_via === "rw", v3 = rw ? !!s.snmp_rw_user : s.snmp_version === "3";
    const who = v3 ? `SNMPv3-Benutzer „${esc(rw ? s.snmp_rw_user : s.snmp_user)}“` : "v2c-Community";
    return `<p class="note" style="margin:0">Zurzeit: <span class="pill ${s.snmp_rw_insecure ? "crit" : "ok"}">${rw ? "schreibt mit eigenem Schreib-Zugang" : "schreibt mit Lese-Zugang"}</span> ${who}${rw ? "" : ", braucht dafür am Switch Schreibrechte"}</p>`
      + insecureBanner(s);
  }
  // Nach dem Speichern: schreibt SNMP an diesem Switch fälschbar oder gar nicht, bleibt dieser Dialog stehen, statt nur einer kurzen
  // Meldung. Die Quelle ist allein der Server (GET /api/switches, poller.write_identity).
  const writeNeedsAlert = row => !!row && !!row.snmp_write && (!!row.snmp_rw_insecure || !row.snmp_write_via || !!row.snmp_write_error);
  function writeAlert(row) {
    modal(`SNMP-Schreiben prüfen: ${row.name}`, `<p style="margin:0">Gespeichert. SNMP-Schreiben an diesem Switch, wie der Server es jetzt sieht:</p>${writeState(row)}`,
      [{ label: "Zugang bearbeiten", onClick: () => editSwitch(row) }, { label: "Verstanden", cls: "primary", onClick: closeModal }]);
  }
  // F2: a stored secret only goes to the address it was entered for. Saving a new address deletes each one not entered anew, and the
  // server names them in "cleared" (PUT /api/switches/{id} and PUT /api/settings); these are their names in the toast after saving.
  const SECRET_NAMES = { snmp_community: "Lese-Community", snmp_auth_pass: "Lese-Auth-Kennwort", snmp_priv_pass: "Lese-Priv-Kennwort", ssh_pass: "SSH-Kennwort",
    snmp_rw_community: "Schreib-Community", snmp_rw_auth_pass: "RW-Auth-Kennwort", snmp_rw_priv_pass: "RW-Priv-Kennwort",
    opnsense_key: "OPNsense-API-Key", opnsense_secret: "OPNsense-API-Secret", radius_key: "Shared Secret", pf_pass: "PacketFence-Kennwort" };
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
      // Treiber, SNMP-Schreiben, RW-Benutzer und seine Protokolle lässt ein PUT ohne sie stehen (main.UPDATE_IF_SENT): beim Anlegen alle,
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
        // Wie SNMP jetzt schreibt, rechnet der Server (write_identity); fälschbar oder ohne Schreib-Zugang: ein Dialog, der stehen bleibt
        const row = await api("GET", "/api/switches").then(list => list.find(x => x.id === id), () => null);
        closeModal(); toast(isNew ? "Angelegt, wird abgefragt …" : savedTxt(cleared));
        if (writeNeedsAlert(row)) writeAlert(row);
        if (isNew) await api("POST", `/api/switches/${id}/poll`).catch(() => {});
        await loadMap(true); go("switches", payload.name);
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
  async function renderDevices() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    let list;
    try { [list, ROLES] = await Promise.all([api("GET", "/api/devices"), api("GET", "/api/pf/roles")]); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    v.innerHTML = `
      ${!ROLES.configured ? `<div class="banner warn">Die PacketFence-API ist nicht eingerichtet (Einstellungen). Freigaben wirken erst, wenn sie in PacketFence stehen.</div>` : ROLES.error ? `<div class="error">PacketFence: ${esc(ROLES.error)}</div>` : ""}
      <section class="card"><div class="card-h"><h2>Geräte</h2><span class="sub">${list.length} bekannt · ${list.filter(d => d.allowed).length} ohne Zertifikat freigegeben</span>
        <div class="right toolrow"><div class="seg" role="group" aria-label="Geräte filtern" id="df">${[["all", "Alle"], ["allowed", "Freigegeben"], ["blocked", "Nicht freigegeben"], ["err", "Fehler"]].map(([k, l]) => `<button type="button" data-f="${k}" aria-pressed="${devFilter === k}">${l}</button>`).join("")}</div>
          <input type="search" id="dq" placeholder="Name, MAC, Standort" aria-label="Geräte durchsuchen" value="${esc(devText)}">
          <button class="btn small" type="button" id="d-sync">Mit PacketFence abgleichen</button><button class="btn small primary" type="button" id="d-add">Gerät hinzufügen</button></div></div>
        <div class="tbl-wrap"><table><thead><tr><th>Name</th><th>MAC</th><th>Rolle</th><th>Freigabe</th><th>Zuletzt gesehen</th><th>PacketFence</th></tr></thead><tbody id="dbody"></tbody></table></div></section>
      <section class="card"><div class="card-h"><h2>Unbekannte Geräte an Zugangsports</h2><span class="sub">noch nicht in der Datenbank · Einträge hinter LLDP-Geräten, unbestätigten Uplinks oder an Ports mit vielen Geräten stehen markiert am Ende</span></div><div id="ulist"><div class="empty">Lade …</div></div></section>`;
    const rows = () => {
      const t = devText.toLowerCase();
      const f = list.filter(d => (devFilter === "all" || (devFilter === "allowed" && d.allowed) || (devFilter === "blocked" && !d.allowed) || (devFilter === "err" && d.pf_state === "fehler"))
        && (!t || [d.name, d.mac, d.location, d.owner, d.role, d.notes, KINDS[d.kind]].some(x => String(x || "").toLowerCase().includes(t))));
      $("#dbody").innerHTML = f.length ? f.map(d => `<tr class="clickrow" data-mac="${esc(d.mac)}"><td><b>${esc(d.name)}</b><div class="muted" style="font-size:12px">${esc(KINDS[d.kind] || d.kind)}${d.location ? " · " + esc(d.location) : ""}</div></td>
        <td class="mono">${esc(d.mac)}${d.vendor ? `<div class="muted" style="font-family:var(--sans)">${esc(d.vendor)}</div>` : ""}</td><td>${esc(d.role || "default")}</td><td>${freePill(d)}${d.valid_until ? `<div class="muted" style="font-size:12px">bis ${esc(d.valid_until)}</div>` : ""}</td>
        <td>${d.seen ? `${esc(d.seen.sw)} · Port ${esc(d.seen.port)} · VLAN ${esc(d.seen.vlan)}${d.seen.ip ? `<div class="mono muted">${esc(d.seen.ip)}</div>` : ""}` : `<span class="muted">nicht gesehen</span>`}</td><td>${pfPill(d)}</td></tr>`).join("")
        : `<tr><td colspan="6" class="muted">${list.length ? "Kein Gerät passt zum Filter." : "Noch keine Geräte. Unten aus den unbekannten übernehmen oder „Gerät hinzufügen“."}</td></tr>`;
    };
    rows();
    $("#df").addEventListener("click", e => { const b = e.target.closest("[data-f]"); if (!b) return; devFilter = b.dataset.f; document.querySelectorAll("#df [data-f]").forEach(x => x.setAttribute("aria-pressed", String(x.dataset.f === devFilter))); rows(); });
    $("#dq").addEventListener("input", e => { devText = e.target.value.trim(); rows(); });
    $("#dbody").addEventListener("click", e => { const r = e.target.closest("[data-mac]"); if (r) editDevice(list.find(d => d.mac === r.dataset.mac), false); });
    $("#d-add").addEventListener("click", () => editDevice({ mac: "", name: "", kind: "drucker" }, true));
    $("#d-sync").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", "/api/devices/sync"); toast(r.ok ? `${r.done} Geräte abgeglichen` : (r.error || `${r.failed} Fehler`)); renderDevices(); } catch (err) { toast(err.message); e.target.disabled = false; } });
    try {
      const un = await api("GET", "/api/devices/unknown");
      const flagText = { uplink_lldp: () => "Port gilt per LLDP als Uplink (unbestätigt)", lldp: d => d.lldp ? `hinter LLDP-Gerät „${d.lldp}“` : "hinter LLDP-Gerät", many: d => `Port mit ${d.mc} Geräten` };
      const unknownFlags = d => (d.flags || []).filter(f => flagText[f]).map(f => `<div class="muted">${esc(flagText[f](d))}</div>`).join("");
      if (!$("#ulist")) return;
      $("#ulist").innerHTML = un.length ? `<div class="tbl-wrap"><table><thead><tr><th>Gerät</th><th>MAC</th><th>Ort</th><th>Port-Zustand</th><th></th></tr></thead><tbody>` + un.map((d, i) =>
        `<tr><td>${esc(d.name || d.vendor || "unbekannt")}${d.ip ? `<div class="mono muted">${esc(d.ip)}</div>` : ""}</td><td class="mono">${esc(d.mac)}${d.vendor && d.name ? `<div class="muted" style="font-family:var(--sans)">${esc(d.vendor)}</div>` : ""}</td>
          <td>${esc(d.sw)} · Port ${esc(d.port)} · ${chip(d.vlan)}${unknownFlags(d)}</td><td>${stPill(stOf(MAP && MAP.switches.find(x => x.k === d.sw), d.st))}</td><td><button class="btn small" type="button" data-u="${i}">Übernehmen</button></td></tr>`).join("") + `</tbody></table></div>`
        : `<div class="empty">Keine unbekannten Geräte an Zugangsports.</div>`;
      $("#ulist").onclick = e => { const b = e.target.closest("[data-u]"); if (!b) return; const d = un[+b.dataset.u]; editDevice({ mac: d.mac, name: (d.name || "").replace(/\..*$/, ""), kind: "sonstiges", location: `${d.sw} Port ${d.port}` }, true); };
    } catch (e) { if ($("#ulist")) $("#ulist").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  }

  async function editDevice(d, isNew) {
    if (!ROLES.configured && !ROLES.roles.length) { try { ROLES = await api("GET", "/api/pf/roles"); } catch (e) { /* egal */ } }
    const roleField = ROLES.roles.length
      ? `<select id="dv-role"><option value="">default</option>${ROLES.roles.filter(r => r.name !== "default").map(r => `<option value="${esc(r.name)}" ${d.role === r.name ? "selected" : ""}>${esc(r.name)}</option>`).join("")}</select><span class="hint">PacketFence ordnet der Rolle das VLAN zu</span>`
      : `<input id="dv-role" value="${esc(d.role || "")}" maxlength="64" placeholder="default"><span class="hint">${ROLES.configured ? "Rollen aus PacketFence nicht lesbar" : "PacketFence-API nicht eingerichtet, Rolle als Text"}</span>`;
    const body = `<div class="grid2"><label class="field"><span>MAC-Adresse</span><input id="dv-mac" value="${esc(d.mac || "")}" ${isNew ? "" : "readonly"} placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off" required></label>
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
      <div class="right toolrow"><select id="b-sw" aria-label="Switch" style="height:30px;border:1px solid var(--border-strong);border-radius:6px;background:var(--surface);padding:0 8px">${list.map(s => `<option value="${s.id}" ${s.name === selSwitch ? "selected" : ""}>${esc(s.name)}${!has(s, "backup") ? " (ohne Sicherung)" : s.ssh_pass_set ? "" : " (ohne SSH)"}</option>`).join("")}</select>
      <button class="btn small" type="button" id="b-now" aria-describedby="b-why">Jetzt sichern</button></div></div><p class="note gate" id="b-why" style="margin:12px 16px 0" hidden></p><div id="b-list"><div class="empty">Kein Switch angelegt.</div></div></section>`;
    if (!list.length) return;
    const selected = () => list.find(x => String(x.id) === $("#b-sw").value);
    // Sichern geht nur über die SSH-CLI (Treiber mit backup, ProCurve): sonst ist „Jetzt sichern“ gesperrt, mit dem Grund daneben
    const gate = () => { const sw = selected(), ok = has(sw, "backup"); $("#b-now").disabled = !ok; $("#b-why").hidden = ok;
      $("#b-why").textContent = ok ? "" : `Treiber ${sw ? sw.driver : ""} sichert keine Konfiguration: das geht nur über die SSH-CLI (ProCurve).`; };
    const load = async () => {
      gate();
      const id = $("#b-sw").value, rows = await api("GET", `/api/switches/${id}/backups`);
      const sw = list.find(x => String(x.id) === id);
      $("#b-list").innerHTML = rows.length ? `<div class="tbl-wrap"><table><thead><tr><th>Zeitpunkt</th><th>Anlass</th><th>Größe</th><th></th></tr></thead><tbody>` +
        rows.map(r => `<tr><td>${esc(fmtTime(r.taken_at))}</td><td>${r.trigger === "manual" ? "von Hand" : r.trigger === "nightly" ? "nächtlich" : r.trigger === "lesen" ? "gelesen" : esc(r.trigger)}</td><td class="num">${(r.size / 1024).toFixed(1).replace(".", ",")} KB</td>
          <td><div class="actions"><button class="btn small" type="button" data-show="${r.id}">Anzeigen</button><button class="btn small" type="button" data-diff="${r.id}">Änderungen</button></div></td></tr>`).join("") + `</tbody></table></div>`
        : `<div class="empty">${!has(sw, "backup") ? "Keine Sicherungen: dieser Treiber sichert nicht." : sw && !sw.ssh_pass_set ? "Für diesen Switch ist noch kein SSH-Zugang hinterlegt (Switches → Zugang bearbeiten)." : "Noch keine Sicherung. „Jetzt sichern\" klicken."}</div>`;
    };
    $("#b-sw").addEventListener("change", load);
    $("#b-now").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", `/api/switches/${$("#b-sw").value}/backup`); toast(r.ok ? (r.changed ? "Gesichert" : "Unverändert") : r.error); await load(); } catch (err) { toast(err.message); } gate(); });
    $("#b-list").addEventListener("click", async e => {
      const s = e.target.closest("[data-show]"), d = e.target.closest("[data-diff]");
      if (s) { const t = await api("GET", `/api/backups/${s.dataset.show}`); modal("Konfiguration", `<pre class="code">${esc(t)}</pre>`, [{ label: "Schließen", onClick: closeModal }]); }
      if (d) { const t = await api("GET", `/api/backups/${d.dataset.diff}/diff`); const html = esc(t).split("\n").map(l => l.startsWith("+") && !l.startsWith("+++") ? `<span class="add">${l}</span>` : l.startsWith("-") && !l.startsWith("---") ? `<span class="del">${l}</span>` : l).join("\n");
        modal("Änderungen zur vorigen Sicherung", `<pre class="code">${html || "Keine Unterschiede."}</pre>`, [{ label: "Schließen", onClick: closeModal }]); }
    });
    load();
  }

  /* ── Protokoll ── */
  async function renderAudit() {
    const v = $("#view"); const rows = await api("GET", "/api/audit").catch(() => []);
    const lbl = { login: "Anmeldung", login_failed: "Anmeldung fehlgeschlagen", logout_all: "Überall abgemeldet", switch_create: "Switch angelegt", switch_update: "Switch geändert", switch_delete: "Switch gelöscht", switch_hostkey_reset: "SSH-Hostschlüssel vergessen", backup: "Sicherung", settings_update: "Einstellungen geändert",
      change_ok: "Änderung erledigt", change_unclear: "Änderung unklar", change_failed: "Änderung fehlgeschlagen", change_aborted: "Änderung abgebrochen",
      device_create: "Gerät angelegt", device_update: "Gerät geändert", device_delete: "Gerät gelöscht", device_sync: "PacketFence-Abgleich" };
    v.innerHTML = `<section class="card"><div class="card-h"><h2>Änderungen an Switches</h2><span class="sub">letzte 100</span></div><div id="all-changes"><div class="empty">Lade …</div></div></section><section class="card"><div class="card-h"><h2>Protokoll</h2><span class="sub">letzte 200 Einträge</span></div>${rows.length ? `<div class="tbl-wrap"><table><thead><tr><th>Zeit</th><th>Benutzer</th><th>Aktion</th><th>Ziel</th></tr></thead><tbody>` +
      rows.map(r => `<tr><td class="num">${esc(fmtTime(r.ts))}</td><td>${esc(r.username || "")}</td><td>${esc(lbl[r.action] || r.action)}</td><td class="mono">${esc(r.target || "")}</td></tr>`).join("") + `</tbody></table></div>` : `<div class="empty">Noch keine Einträge.</div>`}</section>`;
    v.style.display = ""; renderChangesInto($("#all-changes"), null, 100);
  }

  /* ── Einstellungen ── */
  async function renderSettings() {
    const v = $("#view");
    const s = await api("GET", "/api/settings").catch(e => { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return null; });
    if (!s) return;
    const destNote = id => `<p class="note warn" id="${id}-note" style="margin:0" hidden>Neue Adresse: Das gespeicherte Kennwort bzw. der API-Schlüssel gilt nur für die alte Adresse. Was du hier nicht neu eingibst, löscht das Speichern.</p>`;
    const tlsNote = id => `<p class="note warn" id="${id}-note" style="margin:0" hidden>Ohne TLS-Prüfung (oder mit http://) kann jemand im Netz Kennwort bzw. API-Schlüssel mitlesen.</p>`;
    // A stored secret that does not decrypt (GET /api/settings "unreadable", SECRET_KEY changed?): it has to be entered anew
    const unreadNote = k => (s.unreadable || []).includes(k) ? `<p class="note warn" style="margin:0">lässt sich nicht entschlüsseln – bitte neu eingeben</p>` : "";
    v.innerHTML = `<section class="card"><div class="card-h"><h2>Einstellungen</h2></div><div class="card-b" style="display:grid;gap:16px;max-width:640px">
      <label class="field"><span>Abfrage-Intervall (Minuten)</span><input id="s-poll" type="number" min="5" max="1440" value="${esc(s.poll_minutes)}"></label>
      <fieldset class="fs"><legend>Gerätenamen aus der OPNsense (ARP-Tabelle)</legend>
        <label class="field"><span>Adresse</span><input id="s-url" value="${esc(s.opnsense_url)}" placeholder="https://opnsense.example.com"><span class="hint">API-Benutzer mit Recht „Diagnostics: ARP Table"</span></label>
        ${destNote("s-url")}
        <div class="grid2"><label class="field"><span>API-Key</span><input id="s-key" type="password" autocomplete="new-password" placeholder="${s.opnsense_key_set ? "gesetzt – leer lassen = unverändert" : ""}">${unreadNote("opnsense_key")}</label>
        <label class="field"><span>API-Secret</span><input id="s-secret" type="password" autocomplete="new-password" placeholder="${s.opnsense_secret_set ? "gesetzt – leer lassen = unverändert" : ""}">${unreadNote("opnsense_secret")}</label></div>
        <label class="check"><input id="s-tls" type="checkbox" ${s.opnsense_verify_tls ? "checked" : ""}> TLS-Zertifikat prüfen</label>
        ${tlsNote("s-tls")}
        <div><button class="btn small" type="button" id="s-names">Namen jetzt aktualisieren</button></div></fieldset>
      <fieldset class="fs"><legend>RADIUS und PacketFence</legend>
        <div class="grid2"><label class="field"><span>RADIUS-Server (PacketFence-IP)</span><input id="s-rs" value="${esc(s.radius_server)}" placeholder="IP-Adresse"><span class="hint">wird beim „Vorbereiten" eines Switches eingetragen</span></label>
        <label class="field"><span>Shared Secret der Switches</span><input id="s-rk" type="password" autocomplete="new-password" placeholder="${s.radius_key_set ? "gesetzt – leer lassen = unverändert" : ""}"><span class="hint">wie in PacketFence beim Switch hinterlegt</span>${unreadNote("radius_key")}</label></div>
        ${destNote("s-rs")}
        <label class="field"><span>PacketFence-API</span><input id="s-pfu" value="${esc(s.pf_url)}" placeholder="https://packetfence:9999"><span class="hint">für die Geräte-Freigaben (Nodes mit Rolle)</span></label>
        ${destNote("s-pfu")}
        <div class="grid2"><label class="field"><span>API-Benutzer</span><input id="s-pfuser" value="${esc(s.pf_user)}" autocomplete="off"></label>
        <label class="field"><span>API-Kennwort</span><input id="s-pfpass" type="password" autocomplete="new-password" placeholder="${s.pf_pass_set ? "gesetzt – leer lassen = unverändert" : ""}">${unreadNote("pf_pass")}</label></div>
        <label class="check"><input id="s-pftls" type="checkbox" ${s.pf_verify_tls ? "checked" : ""}> TLS-Zertifikat prüfen</label>
        ${tlsNote("s-pftls")}
        <div><button class="btn small" type="button" id="s-pftest">PacketFence testen</button></div></fieldset>
      <div><button class="btn primary" type="button" id="s-save">Speichern</button></div></div></section>
      <section class="card"><div class="card-h"><h2>Sitzungen</h2></div><div class="card-b" style="display:grid;gap:12px;max-width:640px">
        <p class="note" style="margin:0">Beendet jede Anmeldung von <b>${esc(ME.name)}</b> auf allen Geräten, auch diese.</p>
        <div><button class="btn danger" type="button" id="s-logout-all">Alle meine Sitzungen beenden</button></div></div></section>`;
    // A new address deletes the secret bound to it unless it is entered anew in the same save (F2, main.DESTINATION_SECRETS)
    [["s-url", s.opnsense_url, s.opnsense_key_set || s.opnsense_secret_set], ["s-rs", s.radius_server, s.radius_key_set], ["s-pfu", s.pf_url, s.pf_pass_set]].forEach(([id, was, set]) => {
      const sync = () => syncNote(id, id + "-note", !!set && destTxt($("#" + id).value) !== destTxt(was));
      $("#" + id).addEventListener("input", sync); sync();
    });
    // Credentials readable on the wire (E32): warn while a check box is off or its address uses http:// (both stay allowed)
    [["s-tls", "s-url"], ["s-pftls", "s-pfu"]].forEach(([box, url]) => {
      const sync = () => syncNote(box, box + "-note", !$("#" + box).checked || /^http:\/\//i.test($("#" + url).value.trim()));
      $("#" + box).addEventListener("change", sync); $("#" + url).addEventListener("input", sync); sync();
    });
    $("#s-save").addEventListener("click", async e => {
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
    $("#s-names").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", "/api/names/refresh"); toast(r.ok ? `${r.entries} Einträge aus der ARP-Tabelle` : r.error); MAP = null; } catch (err) { toast(err.message); } e.target.disabled = false; });
  }

  (async () => { try { await initLogin(); } catch (e) { showLogin(e.message); return; } try { await start(); } catch (e) { showLogin(); } })();
})();
