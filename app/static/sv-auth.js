"use strict";

  /* ── Anmeldungen (GET /api/pf/sessions): who is logged in on the LAN now, as PacketFence holds it - by 802.1X (certificate), by
     MAC (a release) or parked. The switch view marks its port tiles (paintAuth, the legend beside) and names the sessions of a port
     in its panel (authKv); the devices view has the column "Anmeldung" for its devices (authCell) and the card "Angemeldet" with
     every session (renderAuthInto). Asked at most once a minute (SESS, SESS_AT; the server keeps its answer as long); a failure
     leaves the switch view and the column as they were, the card says why. ── */
  let SESS = null, SESS_AT = 0, authLoading = null, authFilter = "all";
  const AUTH_TTL = 60000;
  // How a session counts: [label, class suffix, rank]; a port with several sessions shows the highest rank (park, then MAC)
  const AUTH_HOW = { dot1x: ["802.1X", "x", 1], mac: ["MAC", "m", 2], park: ["Park", "p", 3] };
  const authKind = x => (x.park ? "park" : x.how === "dot1x" ? "dot1x" : "mac");
  const authPill = x => `<span class="pill au-${AUTH_HOW[authKind(x)][1]}">${AUTH_HOW[authKind(x)][0]}</span>`;
  // The details of a session: the account of an 802.1X login (without "host/"), the role, since when (PacketFence's clock)
  const authText = x => [x.how === "dot1x" && x.user ? esc(x.user.replace(/^host\//i, "")) : "", esc(x.role), x.since ? `seit ${esc(x.since)}` : ""].filter(Boolean).join(" · ");
  const authReady = () => !!SESS && SESS.configured !== false && SESS.ok !== false;

  // The sessions (GET /api/pf/sessions), reused for AUTH_TTL; a failed request is kept as an answer with its reason
  function loadAuth(force) {
    if (!force && SESS && Date.now() - SESS_AT < AUTH_TTL) return Promise.resolve(SESS);
    if (!authLoading) {
      authLoading = api("GET", "/api/pf/sessions").catch(e => ({ configured: true, ok: false, error: e.message, sessions: [] }))
        .then(r => { SESS = r && Array.isArray(r.sessions) ? r : { configured: true, ok: false, error: "Antwort ohne Sitzungen", sessions: [] }; SESS_AT = Date.now(); authLoading = null; return SESS; });
    }
    return authLoading;
  }

  // The port tiles of switch s by their sessions (classes au-x, au-m, au-p) and the legend beside them (#plate-legend), once the
  // sessions are there and s is still the switch shown
  async function paintAuth(s) {
    await loadAuth();
    if (!authReady() || selSwitch !== s.id || !$("#plate")) return;
    const by = {};
    SESS.sessions.filter(x => x.switch_id === s.id).forEach(x => { const k = authKind(x); if (!by[x.port] || AUTH_HOW[k][2] > AUTH_HOW[by[x.port]][2]) by[x.port] = k; });
    document.querySelectorAll("#plate .port").forEach(el => {
      el.classList.remove("au-x", "au-m", "au-p");
      const k = by[el.dataset.p]; if (k) el.classList.add("au-" + AUTH_HOW[k][1]);
    });
    const lg = $("#plate-legend");
    if (lg && !lg.querySelector(".au-lg") && Object.keys(by).length) {
      lg.insertAdjacentHTML("beforeend", Object.keys(AUTH_HOW).map(k => `<span class="au-lg"><i class="lg-au ${AUTH_HOW[k][1]}"></i>angemeldet: ${AUTH_HOW[k][0]}</span>`).join(""));
    }
  }
  // The row "Anmeldung" of the port panel: each session at port p of switch s ("" without one or before the sessions are there)
  function authKv(s, p) {
    const list = authReady() ? SESS.sessions.filter(x => x.switch_id === s.id && x.port === p.n) : [];
    return list.length ? `<dt>Anmeldung</dt><dd>${list.map(x => `<div>${authPill(x)} <span class="mono">${esc(x.mac)}</span>${x.device ? ` ${esc(x.device)}` : ""}`
      + `<div class="muted" style="font-size:12px">${authText(x)}</div></div>`).join("")}</dd>` : "";
  }
  // The cell "Anmeldung" of a device of the list: how and where it is logged in now, "…" while the sessions load, "–" without one
  function authCell(mac) {
    if (!SESS) return `<span class="muted">…</span>`;
    const list = authReady() ? SESS.sessions.filter(x => x.mac === mac) : [];
    return list.length ? list.map(x => `${authPill(x)}<div class="muted" style="font-size:12px">${esc(x.switch_name)} · Port ${esc(x.port)}${x.role ? " · " + esc(x.role) : ""}</div>`).join("")
      : `<span class="muted" title="keine Sitzung in PacketFence (z. B. ein Port ohne Anmeldung)">–</span>`;
  }

  // The card "Angemeldet" into el: every session with its device (the device of the database, else the account of an 802.1X login),
  // MAC, way, role and VLAN, switch and port, since; filtered by way (authFilter). Without PacketFence one sentence, a failure its reason
  async function renderAuthInto(el) {
    if (!el) return;
    const title = `<h2>Angemeldet (PacketFence)</h2>`;
    el.innerHTML = `<div class="card-h">${title}</div><div class="empty">Lade …</div>`;
    const a = await loadAuth();
    if (!el.isConnected) return;
    if (a.configured === false) { el.innerHTML = `<div class="card-h">${title}</div><div class="empty">PacketFence ist nicht eingerichtet (Einstellungen).</div>`; return; }
    if (a.ok === false) { el.innerHTML = `<div class="card-h">${title}</div><div class="empty">${esc(a.error)}</div>`; return; }
    const n = k => a.sessions.filter(x => authKind(x) === k).length;
    const draw = () => {
      const list = a.sessions.filter(x => authFilter === "all" || authKind(x) === authFilter);
      el.innerHTML = `<div class="card-h">${title}<span class="sub">${n("dot1x")} per 802.1X · ${n("mac")} per MAC · ${n("park")} im Park-VLAN</span>
        <div class="right"><div class="seg" role="group" aria-label="Anmeldungen filtern" id="auf">${[["all", "Alle"], ["dot1x", "802.1X"], ["mac", "MAC"], ["park", "Park"]]
          .map(([k, l]) => `<button type="button" data-af="${k}" aria-pressed="${authFilter === k}">${l}</button>`).join("")}</div></div></div>`
        + (list.length ? `<div class="tbl-wrap"><table><thead><tr><th>Gerät</th><th>MAC</th><th>Anmeldung</th><th>Rolle · VLAN</th><th>Switch · Port</th><th>Seit</th></tr></thead><tbody>`
          + list.map(x => `<tr><td>${esc(x.device || (x.how === "dot1x" ? x.user.replace(/^host\//i, "") : "") || "unbekannt")}</td><td class="mono">${esc(x.mac)}</td><td>${authPill(x)}</td>`
            + `<td>${esc(x.role || "–")}${x.vlan ? ` · ${esc(x.vlan)}` : ""}</td><td>${esc(x.switch_name || "–")} · ${esc(x.port || "–")}</td><td class="num">${esc(x.since)}</td></tr>`).join("")
          + `</tbody></table></div>` : `<div class="empty">${a.sessions.length ? "Keine Sitzung passt zum Filter." : "Gerade keine Sitzung."}</div>`);
    };
    draw();
    el.onclick = e => { const b = e.target.closest("[data-af]"); if (!b) return; authFilter = b.dataset.af; draw(); };
  }
