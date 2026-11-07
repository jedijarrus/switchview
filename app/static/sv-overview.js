"use strict";

  /* ── Übersicht ── */
  async function renderOverview() {
    const v = $("#view"); v.innerHTML = `<div class="empty">Lade …</div>`;
    try { await loadMap(true); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    if (!MAP.switches.length) {
      v.innerHTML = `<div class="card"><div class="empty"><b>Noch keine Switches</b><span>Lege unter „Switches“ den ersten Switch mit seinen Zugangsdaten an.</span><button class="btn primary" type="button" id="go-add">Switch hinzufügen</button></div></div>`;
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
            const ph = physOf(s), u = ph.filter(p => p.o).length, m = modelFw(s);
            return `<button type="button" class="swcard" data-sw="${s.id}"><span class="n">${stDot(s)}${esc(s.k)}</span>${m ? `<span class="m">${m}</span>` : ""}
              <div class="bar2" aria-hidden="true"><i style="width:${Math.round(u / Math.max(1, ph.length) * 100)}%"></i></div><span class="row"><span>${u} / ${ph.length} Ports aktiv</span><span class="mono">${esc(s.host)}</span></span></button>`; }).join("")}</div>`).join("")}</div></section>
        <section class="card"><div class="card-h"><h2>Auffälligkeiten</h2><span class="sub">aus den Switch-Daten</span></div>
          ${groups.length ? `<div class="issues">${groups.map((x, gi) => `<details class="ig ${x.sev}" ${x.open ? "open" : ""}><summary>${sevPill[x.sev]}<span class="t">${esc(x.t)}</span><span class="cnt">${x.items.length}</span><svg class="chev" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg><span class="d">${esc(x.sum)}</span></summary>
            <div class="igl">${x.items.map((i, n) => `<div class="issue"><span class="t">${esc(i.t)}</span><span class="d">${esc(i.d)}</span><button class="btn small go" type="button" data-iss="${gi}:${n}">Öffnen</button></div>`).join("")}</div></details>`).join("")}</div>` : `<div class="empty">Nichts auffällig.</div>`}</section>
      </div>
      <section class="card"><div class="card-h"><h2>Verbindungen zwischen Switches</h2><span class="sub">${MAP.links.length} erkannt</span></div>${linksTable(MAP.links)}</section>`;
    v.onclick = e => {
      const b = e.target.closest("[data-iss]"); if (b) { const [gi, n] = b.dataset.iss.split(":"); return groups[+gi].items[+n].go(); }
      const c = e.target.closest(".swcard"); if (c) go("switches", +c.dataset.sw);
    };
    $("#btn-refresh").addEventListener("click", async ev => { ev.target.disabled = true; try { await api("POST", "/api/poll"); toast("Alle Switches abgefragt"); renderOverview(); } catch (e) { toast(e.message); ev.target.disabled = false; } });
    renderTopo($("#topo"));
  }

  // How a link was found ("Erkannt über"); an unconfirmed one names its unconfirmed ports below, in the cell (a title reaches no touch
  // or keyboard user). Since Phase 3 Task 9 a MAC link can be unconfirmed too (its base MACs learned on more than one port).
  const linkVia = l => l.confirmed ? (l.src === "mac" ? "MAC-Tabellen" : "LLDP (beide Seiten)")
    : `${l.src === "mac" ? "MAC-Tabellen" : "LLDP"} (unbestätigt)<span class="cellnote">${esc(unconfTitle(l))}</span>`;
  // focusId: the switch whose detail shows the table (its name first)
  function linksTable(links, focusId) {
    if (!links.length) return `<div class="empty">Keine Verbindungen erkannt.</div>`;
    return `<div class="tbl-wrap"><table><thead><tr><th>Verbindung</th><th>Ports</th><th>Geschwindigkeit</th><th>Erkannt über</th><th>VLAN-Abgleich</th></tr></thead><tbody>` + links.map(l => {
      const n = l.A.ports.length, per = n > 1 ? l.A.speed / n : l.A.speed;
      const issue = linkIssue(l);
      const det = issue ? `<details class="lk"><summary><span class="pill warn">${issue} Abweichung${issue > 1 ? "en" : ""}</span> <span class="linkbtn">Details</span></summary><div style="display:grid;gap:4px;margin-top:6px">
        ${l.onlyA.length ? `<div>nur ${esc(l.an)}: ${chips(l.onlyA)}</div>` : ""}${l.onlyB.length ? `<div>nur ${esc(l.bn)}: ${chips(l.onlyB)}</div>` : ""}${l.native.length ? `<div>ungetaggt verschieden: ${chips(l.native)}</div>` : ""}</div></details>` : `<span class="pill ok">gleich</span>`;
      const side = (name, x) => `${esc(name)} <span class="mono muted">${esc(x.trunk || x.ports.join(","))}</span>`, flip = focusId != null && l.b === focusId;
      return `<tr><td><b>${esc(flip ? l.bn : l.an)}</b> ⇄ <b>${esc(flip ? l.an : l.bn)}</b></td><td>${side(l.an, l.A)}<br>${side(l.bn, l.B)}</td><td class="num">${n > 1 ? n + " × " : ""}${speedTxt(per)}</td><td>${linkVia(l)}</td><td>${det}</td></tr>`;
    }).join("") + `</tbody></table></div>`;
  }

  function renderTopo(t) {
    const zs = zones(), NW = 150, NH = 46, DX = 186, DY = 96, PAD = 24;
    let x0 = 10, svg = "", pos = {}, maxH = 0;
    zs.forEach(z => {
      const list = MAP.switches.filter(s => (s.zone || "Ohne Zone") === z), cols = Math.min(2, list.length), rows = Math.ceil(list.length / cols);
      const w = cols * DX + PAD, h = rows * DY + 44;
      svg += `<rect class="zone" x="${x0}" y="10" width="${w}" height="${h}" rx="10"/><text class="zlabel" x="${x0 + 14}" y="30">${esc(z.toUpperCase())}</text>`;
      list.forEach((s, i) => { pos[s.id] = [x0 + PAD / 2 + (i % cols) * DX + DX / 2, 10 + 62 + Math.floor(i / cols) * DY]; });
      x0 += w + 40; maxH = Math.max(maxH, h);
    });
    let edges = "";
    MAP.links.forEach(l => {
      const a = pos[l.a], b = pos[l.b]; if (!a || !b) return;
      edges += `<line class="edge ${l.A.ports.length > 1 ? "thick" : ""} ${linkIssue(l) ? "warn" : ""} ${l.src === "mac" ? "mac" : ""} ${l.confirmed ? "" : "unconf"}" x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}"><title>${esc(l.an)} ⇄ ${esc(l.bn)}${l.confirmed ? "" : ` · ${esc(unconfTitle(l))}`}</title></line>`;
    });
    let nodes = "";
    MAP.switches.forEach(s => {
      const p = pos[s.id], ph = physOf(s);
      nodes += `<g class="node ${s.ok ? "" : "bad"}" tabindex="0" role="link" data-goto="${s.id}" aria-label="${esc(s.k)} öffnen"><rect x="${p[0] - NW / 2}" y="${p[1] - NH / 2}" width="${NW}" height="${NH}" rx="7"/>
        <text class="nname" x="${p[0]}" y="${p[1] - 3}" text-anchor="middle">${esc(s.k)}</text><text class="nmeta" x="${p[0]}" y="${p[1] + 13}" text-anchor="middle">${ph.filter(x => x.o).length}/${ph.length} aktiv</text></g>`;
    });
    t.innerHTML = `<svg viewBox="0 0 ${x0 - 30} ${maxH + 20}" role="img" aria-label="Topologie">${svg}${edges}${nodes}</svg><p class="note">Dicke Linie = Trunk · orange = VLANs unterschiedlich · gestrichelt = ohne LLDP erkannt · gepunktet = unbestätigt (nicht von beiden Switches gemeldet)</p>`;
    const openNode = e => { const g = e.target.closest("[data-goto]"); if (g) go("switches", +g.dataset.goto); };
    t.addEventListener("click", openNode);
    t.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openNode(e); } });
  }
