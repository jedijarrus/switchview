"use strict";

  /* ── Switch-Detail (Master-Detail) ── */
  const ST = { off: ["Aus", "st-off"], on: ["An", "st-prot"], protected: ["Protected", "st-prot"], known: ["Bekannte Geräte", "st-known"], radius: ["RADIUS", "st-radius"] };
  // A state not read yet: the dash says it to the eye (the switch view's banner says why), the hidden text to a screen reader
  const stPill = st => ST[st] ? `<span class="pill ${ST[st][1]}">${ST[st][0]}</span>`
    : `<span class="muted" title="Konfiguration noch nicht gelesen">–<span class="sr-only"> Konfiguration noch nicht gelesen</span></span>`;
  // Der Zugang eines Ports, wie die Ansicht ihn zeigt und zählt. Ohne NAC (802.1X/MAC-Anmeldung liest und ändert SwitchView dort nicht)
  // gibt es nur An oder Aus: ein eingeschalteter Port heißt „An“ statt „Protected“. Nur die Beschriftung, p.st vom Server bleibt der Schlüssel.
  const stOf = (s, st) => s && !has(s, "nac") ? (st === "off" ? "off" : "on") : st;
  let portIdx = {}, picked = new Set(), pickedFor = null;
  // The server's credential warnings (poller.credential_warnings: fallback to "public", SNMPv3 downgrade, secrets that do not decrypt)
  const warnList = ws => (ws || []).length ? `<div class="banner warn"><ul class="blist">${ws.map(w => `<li>${esc(w)}</li>`).join("")}</ul></div>` : "";
  // The button of the switch view's actions and write banners (its click: data-a="edit")
  const EDIT_ACCESS = `<button class="btn small" type="button" data-a="edit">Zugang bearbeiten</button>`;
  // The line under a switch's name: zone, model and firmware only where known (modelFw), address, driver, time of the last poll
  const switchMeta = s => [esc(s.zone), modelFw(s, "Firmware "), `<span class="mono">${esc(s.host)}</span>`,
    `Treiber <span class="mono">${esc(s.driver || "procurve")}</span>`, `Stand ${esc(fmtTime(s.lastPoll))}`].filter(Boolean).join(" · ");
  // The banners above a switch's facts: the last poll failed or went through with gaps (poller.partial_note keeps its note in error),
  // the credential warnings, and how SwitchView writes here.
  // Schreibwege: SSH-CLI nur bei einem Treiber mit cli und SSH-Zugang, sonst SNMP (wenn SNMP-Schreiben an ist). Was nur über die CLI
  // geht (Sicherung, Konfiguration lesen, RADIUS), zeigt die Ansicht nur bei einem Treiber, der es kann.
  function switchBanners(s) {
    const cli = has(s, "cli"), canW = writable(s);
    const banner = !canW ? `<div class="banner">${cli ? "Ohne SSH-Zugang kann SwitchView hier nur lesen." : `Treiber ${esc(s.driver)} hat keine SSH-CLI, Änderungen gehen hier nur per SNMP. SNMP-Schreiben ist aus, SwitchView kann hier nur lesen.`} Für Änderungen: ${EDIT_ACCESS}</div>`
      : cli && !s.ssh ? `<div class="banner">Ohne SSH-Zugang gehen Änderungen hier nur per SNMP: VLANs, Namen${has(s, "snmp_poe") ? ", PoE" : ""} und Ports aus- und wieder einschalten („An“, die Anmeldung bleibt, wie sie ist). RADIUS, Bekannte Geräte und Protected brauchen SSH. ${EDIT_ACCESS}</div>`
      : cli && !s.cfgAt ? `<div class="banner">Die Port-Zustände (RADIUS, bekannte Geräte, Protected) sind noch nicht gelesen. <button class="btn small" type="button" data-a="readcfg">Konfiguration lesen</button></div>` : "";
    return `${s.ok ? "" : `<div class="error">Letzte Abfrage fehlgeschlagen: ${esc(s.error)}</div>`}
      ${s.ok && s.error ? `<div class="banner warn">Abfrage unvollständig: ${esc(s.error)}</div>` : ""}
      ${warnList(s.credWarnings)}
      ${banner}`;
  }

  async function renderSwitchDetail() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    try { await loadMap(!MAP); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    selSwitch = SVLogic.switchIdOf(MAP.switches, selSwitch); syncHash();
    if (pickedFor !== selSwitch) { picked = new Set(); pickedFor = selSwitch; }
    const side = `<nav class="side" aria-label="Switches">${zones().map(z => `<div class="zonehead">${esc(z)}</div>` + MAP.switches.filter(s => (s.zone || "Ohne Zone") === z).map(s => {
      const ph = physOf(s); return `<button type="button" class="si" data-sw="${s.id}" aria-current="${s.id === selSwitch}">${stDot(s)}<span>${esc(s.k)}</span><span class="c">${ph.filter(p => p.o).length}/${ph.length}</span></button>`; }).join("")).join("")}
      <button type="button" class="btn small add" id="btn-add">Switch hinzufügen</button></nav>`;
    if (selSwitch == null) { v.innerHTML = `<div class="md">${side}<div class="card"><div class="empty"><b>Noch keine Switches</b><span>Links „Switch hinzufügen“.</span></div></div></div>`; bindSide(); return; }
    const s = swById(selSwitch), ph = physOf(s), trunks = s.ports.filter(p => p.n.startsWith("Trk"));
    const vset = [...new Set(ph.flatMap(p => [...p.u, ...p.t]))].sort((a, b) => a - b);
    if (swVlan && !vset.includes(swVlan)) swVlan = null;
    const links = MAP.links.filter(l => l.a === s.id || l.b === s.id);
    const cnt = st => ph.filter(p => stOf(s, p.st) === st).length;
    const stFacts = (has(s, "nac") ? [["radius", "RADIUS"], ["known", "Bekannte Geräte"], ["protected", "Protected"]] : [["on", "An"]]).concat([["off", "Aus"]]);
    const canW = writable(s);
    v.innerHTML = `<div class="md">${side}<div style="display:grid;gap:16px;min-width:0">
      <div class="dhead"><div><h1>${esc(s.k)}</h1><div class="meta">${switchMeta(s)}</div></div>
        <div class="actions"><button class="btn small" type="button" data-a="poll">Jetzt abfragen</button>${has(s, "backup") ? `<button class="btn small" type="button" data-a="backup">Konfiguration sichern</button>` : ""}<button class="btn small" type="button" data-a="test">Verbindung testen</button>${EDIT_ACCESS}</div></div>
      ${switchBanners(s)}
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
      <section class="card"><div class="card-h"><h2>Verbindungen</h2><span class="sub">${links.length} zu anderen Switches</span></div>${linksTable(links, s.id)}</section>
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
    return `<section class="card"><div class="card-h"><h2>RADIUS am Switch</h2><span class="sub">${rs ? "Stand " + esc(fmtTime(s.cfgAt)) + (s.cfgStale ? " · veraltet (Switch seither geändert)" : "") : "noch nicht gelesen"}</span>
      <div class="right"><button class="btn small" type="button" data-a="readcfg">Neu lesen</button><button class="btn small" type="button" data-a="pa">Anmeldungen anzeigen</button>${miss ? `<button class="btn small primary" type="button" data-a="prepare">Vorbereiten</button>` : ""}</div></div>
      <div class="card-b">${r ? `<ul class="checks">${li(r.host, "RADIUS-Server (PacketFence) eingetragen")}${li(r.coa, "CoA erlaubt (dyn-authorization), damit PacketFence umschalten kann")}${li(r.tw, "CoA ohne Zeitstempel erlaubt (time-window 0), PacketFence schickt keinen")}${li(r.eap, "802.1X-Methode eap-radius")}${li(r.active, "802.1X am Switch aktiv")}${li(r.park, "Park-VLAN 3999 angelegt (für Unbekannte)")}</ul>
        ${r.login_radius ? `<p class="note">Die Anmeldung am Switch selbst nutzt RADIUS.</p>` : ""}${r.others && r.others.length ? `<p class="note">Weitere RADIUS-Server: ${esc(r.others.join(", "))}</p>` : ""}
        ${miss ? `<p class="note">Für die Zustände RADIUS und Bekannte Geräte muss der Switch vorbereitet sein. „Vorbereiten“ fügt nur fehlende Zeilen hinzu und ändert keinen Port.</p>` : ""}`
        : `<p class="note" style="margin:0">Konfiguration noch nicht gelesen.</p>`}</div></section>`;
  }
  function bindSide() {
    document.querySelectorAll(".side .si").forEach(b => b.addEventListener("click", () => { swVlan = null; swPortFilter = "all"; swText = ""; go("switches", +b.dataset.sw); }));
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
  // The VLAN chips of a form (port and trunk): one toggle button per VLAN id in ids, pressed when sel holds it; data-<attr> names the
  // list it belongs to (ta: tagged add, tr: tagged remove), gate the attributes of a locked chip (disabled plus its reason)
  const vlanChipButtons = (ids, sel, attr, gate = "") => ids.length ? `<div class="chipset">${ids.map(id => `<button type="button" class="vchip small" data-${attr}="${esc(id)}" aria-pressed="${sel.includes(id)}" style="--vc:${vcol(id)}"${gate}><i class="sw"></i><span class="id">${esc(id)}</span><span class="nm">${esc(vname(id))}</span></button>`).join("")}</div>` : `<span class="muted" style="font-size:12.5px">keine</span>`;
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
        <div class="field"><span>Getaggt hinzufügen</span>${vlanChipButtons(vl, f.add, "ta", memGate)}</div>
        <div class="field"><span>Getaggt entfernen</span>${vlanChipButtons(tagUnion, f.rem, "tr", memGate)}</div>
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

  /* ── Editing a trunk: its VLANs only, in expert mode only (exclusion A2 of docs/logik-phase3.md, done in Phase 5) ── */
  // The plan request for trunk n: change holds only the fields that are set (untagged, tagged_add, tagged_remove)
  function trunkPayload(n, untagged, add, rem, expert) {
    const change = {};
    if (untagged) change.untagged = untagged;
    if (add.length) change.tagged_add = add;
    if (rem.length) change.tagged_remove = rem;
    return { mode: "ports", ports: [n], change, expert: !!expert };
  }
  // A trunk (TrkN or a LAG) takes only VLANs: name and on / off go to its member ports, an authentication (RADIUS, known devices)
  // never to a trunk (changes.plan_ports). The form asks for expert mode before the preview; the server stays the authority for
  // every lock. prev: the form's state when "Zurück" comes from the preview.
  function editTrunk(s, n, prev) {
    const p = portIdx[n]; if (!p) return;
    const f = prev || { untagged: "", add: [], rem: [], expert: false };
    const vl = s.vl && s.vl.length ? s.vl : Object.keys(MAP.vlans);
    const body = `<p class="note" style="margin:0">Trunk <span class="mono">${esc(n)}</span> aus den Ports <span class="mono">${esc(p.mb.join(", ") || "–")}</span> · ungetaggt jetzt <span class="mono">${esc(p.u.join(", ") || "keins")}</span> · getaggt jetzt <span class="mono">${esc(p.t.join(", ") || "keine")}</span></p>
      <p class="note gate" id="f-gate-trk">Am Trunk gehen nur VLANs. Name und An/Aus an den Mitglied-Ports, eine Anmeldung (RADIUS, Bekannte Geräte) nie an Trunks.</p>
      <div class="grid2"><label class="field"><span>VLAN ungetaggt</span><select id="f-u"><option value="">unverändert</option>${vl.map(id => `<option value="${esc(id)}" ${f.untagged === id ? "selected" : ""}>${esc(id)} · ${esc(vname(id))}</option>`).join("")}</select></label></div>
      <div class="field"><span>Getaggt hinzufügen</span>${vlanChipButtons(vl, f.add, "ta")}</div>
      <div class="field"><span>Getaggt entfernen</span>${vlanChipButtons(p.t, f.rem, "tr")}</div>
      <label class="check warnbox"><input type="checkbox" id="f-expert"${f.expert ? " checked" : ""}> Expertenmodus: Trunk ändern. Falsch gesetzt, trennt das den Switch vom Netz.</label>`;
    const collect = () => {
      f.untagged = $("#f-u").value;
      f.add = [...document.querySelectorAll("[data-ta][aria-pressed=true]")].map(b => b.dataset.ta);
      f.rem = [...document.querySelectorAll("[data-tr][aria-pressed=true]")].map(b => b.dataset.tr);
      f.expert = $("#f-expert").checked;
      return trunkPayload(n, f.untagged, f.add, f.rem, f.expert);
    };
    modal(`Trunk ${n} bearbeiten`, body, [
      { label: "Abbrechen", onClick: closeModal },
      { label: "Vorschau", cls: "primary", onClick: () => {
        const payload = collect();
        if (!f.expert) { toast("Für einen Trunk den Expertenmodus einschalten"); return; }
        if (!Object.keys(payload.change).length) { toast("Nichts ausgewählt, was sich ändern soll"); return; }
        previewChange(s, payload, () => editTrunk(s, n, f));
      } }]);
    $("#m-body").onclick = e => { const b = e.target.closest("[data-ta],[data-tr]"); if (b) b.setAttribute("aria-pressed", String(b.getAttribute("aria-pressed") !== "true")); };
  }

  async function previewChange(s, payload, back) {
    const title = payload.mode === "prepare" ? `RADIUS vorbereiten: ${s.k}` : payload.mode === "revert" ? `Rückgängig #${payload.of}` : payload.mode === "save" ? "Speichern (write memory)" : "Vorschau";
    const wait = modal(title, `<div class="empty">Lese die aktuelle Konfiguration von ${esc(s.k)} …</div>`, []);
    let r;
    // A live read takes seconds: closed meanwhile (Back, Escape, ✕, the login) or replaced by another dialog, the answer opens nothing
    try { r = await api("POST", `/api/switches/${s.id}/plan`, payload); }
    catch (e) { if (modalShown(wait)) modal(title, `<div class="error">${esc(e.message)}</div>`, [...(back ? [{ label: "Zurück", onClick: back }] : []), { label: "Schließen", onClick: closeModal }]); return; }
    if (!modalShown(wait)) return;
    const can = !r.blocked.length && (r.commands.length || r.kind === "save"), snmp = r.mechanism === "snmp";
    // Per SNMP gibt es kein Staging und kein Backup: der SET wirkt sofort. Dauerhaft gespeichert ist er nur bei einem Treiber, der das
    // selbst tut (autosave der /plan-Antwort = snmp_autosave, R26), und der speichert dabei die gesamte laufende Konfiguration (welche
    // SSH-Änderungen das mitspeichert, sagt eine Warnung des Servers); sonst bleibt das Speichern am Switch. Geht der SET fälschbar
    // hinaus (insecure_write der /plan-Antwort), sagt es die Vorschau laut. Beides ist der Stand des Servers zur Planzeit.
    const way = !can || !snmp ? "" : (r.autosave
      ? `<div class="banner"><span><b>Wird per SNMP sofort angewendet und automatisch gespeichert – der Switch speichert dabei die gesamte laufende Konfiguration.</b> Kein gestuftes write memory, kein Backup über diesen Weg.</span></div>`
      : `<div class="banner warn"><span><b>Wird per SNMP sofort angewendet, aber NICHT dauerhaft gespeichert – danach am Switch speichern (z. B. write memory / copy running-config startup-config).</b> Kein Backup über diesen Weg.</span></div>`)
      + insecureBanner(r.insecure_write);
    const poeNote = snmp && has(s, "cli") && payload.change && payload.change.poe != null ? " PoE schaltet SwitchView immer per SNMP, auch wenn SSH geht." : "";
    const body = `<p style="margin:0"><b>${esc(r.summary)}</b> <span class="muted">· ${esc(s.k)}</span></p>
      ${r.blocked.length ? `<div class="error"><b>Nicht möglich:</b><ul class="blist">${r.blocked.map(b => `<li>${b.port === "*" ? "" : "Port " + esc(b.port) + ": "}${esc(b.reason)}</li>`).join("")}</ul></div>` : ""}
      ${way}
      ${warnList(r.warnings)}
      ${r.commands.length ? `<div><p class="eyebrow">${snmp ? "Änderungen per SNMP" : "Befehle am Switch"}</p><pre class="code">${esc(r.commands.join("\n"))}</pre></div>` : r.kind === "save" || r.blocked.length ? "" : `<div class="banner">Es gibt nichts zu ändern, die Ports sind schon so eingestellt.</div>`}
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
    // "Abgebrochen durch Neustart …" (changes.mark_interrupted) reads "Abgebrochen: durch Neustart …", "Abgebrochen (Prozess beendet),
    // nichts gesendet" (changes.CANCELLED_UNSENT) "Abgebrochen: Prozess beendet, nichts gesendet", never "Abgebrochen: Abgebrochen …"
    const aborted = err.replace(/^Abgebrochen\s+\(?([^)]*)\)?/, "$1");
    return { ok: c.saved ? `<div class="banner ok"><b>Erledigt und gespeichert.</b></div>` : `<div class="banner warn"><b>Erledigt, aber nicht dauerhaft gespeichert – am Switch speichern.</b></div>`,
      unclear: `<div class="banner warn"><span><b>Unklar:</b> ${esc(unclear)}</span></div>`,
      failed: `<div class="error"><b>Fehlgeschlagen:</b> ${esc(err)}</div>`, aborted: `<div class="banner"><span><b>Abgebrochen:</b> ${esc(aborted)}</span></div>` }[c.status] || "";
  }
  async function runProgress(s, id) {
    const shown = modal(`Änderung #${id}`, `<div id="prog"><div class="empty">Starte …</div></div>`, [{ label: "Schließen", onClick: closeModal }]);
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
        const els = btns.map(b => { const el = document.createElement("button"); el.type = "button"; el.className = "btn " + (b.cls || ""); el.textContent = b.label; el.addEventListener("click", () => b.onClick(el)); foot.appendChild(el); return el; });
        // The focused "Schließen" went with the old footer, and the focus with it (to body, the dialog still open): it moves to the
        // new "Schließen"; a focus still in the dialog (the ✕) stays, a dialog closed meanwhile takes none
        if (modalShown(shown) && !$(".modal").contains(document.activeElement)) els[els.length - 1].focus();
        if (c.status === "ok") toast(c.saved ? "Änderung erledigt" : "Änderung erledigt, aber nicht dauerhaft gespeichert");
        // A change that sent nothing changed nothing at the switch: only its list in the switch view reloads (SVLogic.afterChange)
        const next = SVLogic.afterChange(c);
        if (next.reload === "list") setTimeout(() => { if (current === "switches" && selSwitch === s.id) renderChangesInto($("#sw-changes"), s.id, 10); }, next.delay);
        else setTimeout(async () => { try { await loadMap(true); if (current === "switches") { const keep = picked; renderSwitchDetail(); picked = c.status === "ok" ? new Set() : keep; syncPicked(); } } catch (e) { /* egal */ } }, next.delay);
        return;
      }
      await new Promise(res => setTimeout(res, 1200));
    }
  }

  // The changes (newest first) of one switch, or of all with switchId null, into el: limit rows (default 100). The follow-up
  // actions are the server's rule (can_revert / can_save, changes.actions_of); a list the API filled to limit offers "Mehr laden",
  // which doubles limit up to 500, the maximum of GET /api/changes.
  async function renderChangesInto(el, switchId, limit = 100) {
    if (!el) return;
    let rows;
    try { rows = await api("GET", `/api/changes?limit=${limit}${switchId ? "&switch_id=" + switchId : ""}`); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    if (!rows.length) { el.innerHTML = `<div class="empty">Noch keine Änderungen.</div>`; return; }
    const more = rows.length >= limit && limit < 500 ? `<div class="more-row"><button class="btn small" type="button" data-more="${Math.min(500, limit * 2)}">Mehr laden</button></div>` : "";
    el.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>#</th><th>Zeit</th><th>Benutzer</th>${switchId ? "" : "<th>Switch</th>"}<th>Änderung</th><th>Status</th><th></th></tr></thead><tbody>` + rows.map(c =>
      `<tr><td class="num">${c.id}</td><td class="num">${esc(fmtTime(c.created_at))}</td><td>${esc(c.username || "")}</td>${switchId ? "" : `<td>${esc(c.switch_name)}</td>`}<td>${esc(c.summary)}</td><td>${chPill(c)}</td>
        <td><div class="actions"><button class="btn small" type="button" data-cd="${c.id}">Details</button>${c.can_revert ? `<button class="btn small" type="button" data-cr="${c.id}" data-sw="${c.switch_id}">Rückgängig</button>` : ""}${c.can_save ? `<button class="btn small" type="button" data-cs="${c.id}" data-sw="${c.switch_id}">Trotzdem speichern</button>` : ""}</div></td></tr>`).join("") + `</tbody></table></div>${more}`;
    el.onclick = async e => {
      const d = e.target.closest("[data-cd]"), r = e.target.closest("[data-cr]"), sv = e.target.closest("[data-cs]"), m = e.target.closest("[data-more]");
      const swOf = id => MAP && MAP.switches.find(x => x.id === id);
      if (d) {
        const c = await api("GET", `/api/changes/${d.dataset.cd}`);
        modal(`Änderung #${c.id}`, `<p style="margin:0"><b>${esc(c.summary)}</b></p><p class="note" style="margin:0">${esc(c.switch_name)} · ${esc(c.username || "")} · ${esc(fmtTime(c.created_at))}${c.mechanism === "snmp" ? " · per SNMP" : ""} · ${chPill(c)}</p>
          ${c.error ? `<div class="error">${esc(c.error)}</div>` : ""}<div><p class="eyebrow">${c.mechanism === "snmp" ? "Änderungen per SNMP" : "Befehle"}</p><pre class="code">${esc((c.commands || []).join("\n") || "–")}</pre></div>
          <div><p class="eyebrow">Ablauf</p>${stepsHtml(c)}</div>${c.output ? `<details class="adv"><summary>Ausgabe des Switches</summary><pre class="code">${esc(c.output)}</pre></details>` : ""}`,
          [{ label: "Schließen", onClick: closeModal }]);
      }
      if (r) { if (!MAP) await loadMap(false); const s = swOf(+r.dataset.sw); if (s) previewChange(s, { mode: "revert", of: +r.dataset.cr }); }
      if (sv) { if (!MAP) await loadMap(false); const s = swOf(+sv.dataset.sw); if (s) previewChange(s, { mode: "save", of: +sv.dataset.cs }); }
      if (m) {
        // "Mehr laden" goes with the old list: the focus moves to the first row the click added (the last row, if none came), not body
        const shown = rows.length; await renderChangesInto(el, switchId, +m.dataset.more);
        const ds = el.querySelectorAll("[data-cd]"), f = ds[shown] || ds[ds.length - 1]; if (f) f.focus();
      }
    };
  }

  /* Port-Panel */
  let drLast = null, selEl = null;
  function openPort(s, n, trigger) {
    const p = portIdx[n]; if (!p) return;
    drLast = trigger || document.activeElement;
    if (selEl) selEl.classList.remove("sel");
    selEl = document.querySelector(`#plate .port[data-p="${CSS.escape(n)}"]`); if (selEl) selEl.classList.add("sel");
    $("#dr-title").textContent = (p.n.startsWith("Trk") ? "" : "Port ") + p.n; $("#dr-sub").textContent = [s.k, s.model].filter(Boolean).join(" · ");
    const lldp = p.l.length ? p.l.map(x => `<div><b>${esc(x[0])}</b> <span class="mono muted">Port ${esc(x[1])}</span></div>`).join("") : "–";
    const kn = d => d[5] === 2 ? `<span class="pill st-known">freigegeben</span>` : d[5] === 1 ? `<span class="pill neutral">bekannt</span>` : `<button class="btn small" type="button" data-newdev="${esc(d[0])}">Als Gerät anlegen</button>`;
    const devs = p.mc ? `<p class="eyebrow">Gelernte Geräte (${p.mc})</p>${p.mc > p.d.length ? `<p class="note">Viele Geräte, hier die ersten ${p.d.length}.</p>` : ""}<div class="devs">` +
      p.d.map(d => `<div class="dev"><div class="dn">${esc(d[3] || d[4] || "unbekannt")}</div><div>${chip(d[1])}</div><div class="dm">${esc(d[0])}${d[2] ? " · " + esc(d[2]) : ""}${d[3] && d[4] ? " · " + esc(d[4]) : ""}</div><div>${isUplink(p) ? "" : kn(d)}</div></div>`).join("") + `</div>` : "";
    // A trunk opens its own form (VLANs only, editTrunk), every other port the port form
    const canEdit = writable(s), trunk = isTrunkPort(p), why = unconfirmedWhy(p);
    $("#dr-body").innerHTML = `${canEdit ? `<div style="margin-bottom:12px"><button class="btn small primary" type="button" id="dr-edit">${trunk ? "Trunk bearbeiten" : "Port bearbeiten"}</button></div>` : ""}
      <dl class="kv"><dt>Zugang</dt><dd>${stPill(stOf(s, p.st))}${p.lim ? ` <span class="muted">max. ${p.lim} Geräte</span>` : ""}</dd>${why ? `<dt>Uplink</dt><dd><span class="pill warn">unbestätigt</span> ${esc(why)}</dd>` : ""}<dt>Link</dt><dd><span class="st-dot ${p.o ? "" : "down"}"></span>${p.o ? "aktiv, " + speedTxt(p.s) : p.ad ? "kein Link" : "administrativ aus"}</dd>
      ${has(s, "snmp_poe") && p.poe ? `<dt>PoE</dt><dd>${esc(poeTxt(p.poe))}</dd>` : ""}
      <dt>Beschreibung</dt><dd>${esc(p.a) || "–"}</dd><dt>Ungetaggt</dt><dd>${chips(p.u, "")}</dd><dt>PVID</dt><dd class="mono">${esc(p.pv) || "–"}</dd><dt>Getaggt</dt><dd>${chips(p.t, "")}</dd>
      <dt>Trunk</dt><dd>${p.n.startsWith("Trk") ? "Ports " + esc(p.mb.join(", ")) : esc(p.tr) || "–"}</dd><dt>Nachbar (LLDP)</dt><dd>${lldp}</dd></dl>${devs}`;
    if (canEdit) $("#dr-edit").addEventListener("click", () => { closeDrawer(true); if (trunk) editTrunk(s, p.n); else editPorts(s, [p.n]); });
    $("#dr-body").onclick = e => { const b = e.target.closest("[data-newdev]"); if (!b) return; const d = p.d.find(x => x[0] === b.dataset.newdev); closeDrawer(true); editDevice({ mac: d[0], name: (d[3] || "").replace(/\..*$/, ""), kind: "sonstiges" }, true); };
    $("#drawer").classList.add("open"); $("#drawer").setAttribute("aria-hidden", "false"); $("#scrim").hidden = false; syncLayers(); $("#dr-x").focus();
  }
  // The focus leaves the panel before it is hidden: a browser refuses aria-hidden on an ancestor of the focused element, and after a
  // silent close the next dialog may take the focus only later ("Als Gerät anlegen" waits for /api/pf/roles)
  function closeDrawer(silent) {
    const f = document.activeElement; if (f && f !== document.body && $("#drawer").contains(f)) f.blur();
    $("#drawer").classList.remove("open"); $("#drawer").setAttribute("aria-hidden", "true"); $("#scrim").hidden = true; if (selEl) selEl.classList.remove("sel"); syncLayers(); if (!silent) restoreFocus(drLast);
  }
  $("#dr-x").addEventListener("click", () => closeDrawer()); $("#scrim").addEventListener("click", () => closeDrawer());
