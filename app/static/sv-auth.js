"use strict";

  /* ── Anmeldungen (GET /api/pf/sessions): who is on the LAN now, as PacketFence holds it - logged in by 802.1X (certificate) or by
     MAC (a release), or not logged in and parked. The switch view marks its port tiles (paintAuth, the legend beside) and names the
     sessions of a port in its panel (authKv); the devices view has the column "Anmeldung" for its devices (authCell), the card
     "Angemeldet" with every session logged in (renderAuthInto; a parked one stands among the unknown devices, from which one logged in
     goes: authSession). Asked at most once a minute (SESS, SESS_AT; the server keeps its answer as long); a failure leaves the
     switch view and the lists as they were, the card says why. ── */
  let SESS = null, SESS_AT = 0, authLoading = null, authFilter = "all";
  const AUTH_TTL = 60000;
  // How a session counts: [label, class suffix, rank]; a port with several sessions shows the highest rank (park, then MAC)
  const AUTH_HOW = { dot1x: ["802.1X", "x", 1], mac: ["MAC", "m", 2], park: ["Park", "p", 3] };
  // The legend of the port tiles: a parked session is no login
  const AUTH_LEGEND = { dot1x: "angemeldet: 802.1X", mac: "angemeldet: MAC-Freigabe", park: "nicht angemeldet: Park" };
  const authKind = x => (x.park ? "park" : x.how === "dot1x" ? "dot1x" : "mac");
  const authPill = x => `<span class="pill au-${AUTH_HOW[authKind(x)][1]}">${AUTH_HOW[authKind(x)][0]}</span>`;
  // The details of a session: the account of an 802.1X login (without "host/"), the role, since when (PacketFence's clock)
  const authText = x => [x.how === "dot1x" && x.user ? esc(x.user.replace(/^host\//i, "")) : "", esc(x.role), x.since ? `seit ${esc(x.since)}` : ""].filter(Boolean).join(" · ");
  const authReady = () => !!SESS && SESS.configured !== false && SESS.ok !== false;
  // Whether mac has a session now (logged in, or parked): such a device is not among the unknown ones
  const authSession = mac => authReady() && SESS.sessions.some(x => x.mac === mac);

  // After a release of mac was saved or deleted PacketFence bounces its port and the device logs in anew, 10 to 25 s later. Until its
  // session changed (another start, parked or not) the sessions are asked anew every AUTH_POLL_MS, past PacketFence's answer the server
  // keeps (?fresh=1), at most AUTH_POLL_MAX times; meanwhile the device says "wird umgeschaltet …" (authPending). Then its switch is
  // polled once (its MAC table, "Zuletzt gesehen") and the view drawn anew. The promise of the whole, for a test
  let AUTH_POLL_MS = 5000;
  const AUTH_POLL_MAX = 12;
  const AUTH_SWITCH_NOTE = " · der Port schaltet gleich um";
  const authPending = new Set();
  const sessionKey = mac => (SESS && Array.isArray(SESS.sessions) ? SESS.sessions : []).filter(x => x.mac === mac).map(x => `${x.since}|${x.park}|${x.how}|${x.role}`).join(",");
  function authAfterChange(mac) {
    SESS_AT = 0;
    if (!mac) return Promise.resolve();
    const was = sessionKey(mac);
    authPending.add(mac);
    return new Promise(done => {
      let n = 0;
      const tick = async () => {
        n += 1;
        const a = await loadAuth(true, true), now = sessionKey(mac);
        if (now === was && n < AUTH_POLL_MAX) { setTimeout(tick, AUTH_POLL_MS); return; }
        authPending.delete(mac);
        const x = (a.sessions || []).find(s => s.mac === mac);
        if (now !== was && x && x.switch_id != null) {
          try { await api("POST", `/api/switches/${encodeURIComponent(x.switch_id)}/poll`); MAP = null; } catch (e) { /* the next poll brings it */ }
        }
        if (current === "devices") renderDevices();
        done(now !== was);
      };
      setTimeout(tick, AUTH_POLL_MS);
    });
  }
  // The sessions (GET /api/pf/sessions), reused for AUTH_TTL; fresh: past the answer the server keeps. A failed request is kept as
  // an answer with its reason
  function loadAuth(force, fresh) {
    if (!force && SESS && Date.now() - SESS_AT < AUTH_TTL) return Promise.resolve(SESS);
    if (!authLoading) {
      authLoading = api("GET", fresh ? "/api/pf/sessions?fresh=1" : "/api/pf/sessions").catch(e => ({ configured: true, ok: false, error: e.message, sessions: [] }))
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
      lg.insertAdjacentHTML("beforeend", Object.keys(AUTH_HOW).map(k => `<span class="au-lg"><i class="lg-au ${AUTH_HOW[k][1]}"></i>${AUTH_LEGEND[k]}</span>`).join(""));
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
    if (authPending.has(mac)) return `<span class="muted">wird umgeschaltet …</span>`;
    if (!SESS) return `<span class="muted">…</span>`;
    const list = authReady() ? SESS.sessions.filter(x => x.mac === mac) : [];
    return list.length ? list.map(x => `${authPill(x)}<div class="muted" style="font-size:12px">${esc(x.switch_name)} · Port ${esc(x.port)}${x.role ? " · " + esc(x.role) : ""}</div>`).join("")
      : `<span class="muted" title="keine Sitzung in PacketFence (z. B. ein Port ohne Anmeldung)">–</span>`;
  }

  // The devices without access now (the sessions PacketFence parked: a MAC login without a release, at a port "Bekannte Geräte" or
  // "RADIUS"), each with the device of the database (known: one not released, or one PacketFence parks anyway) and the unknown device
  // the switches learned (seen: name, vendor)
  function parkedOf(devices, unknown) {
    if (!authReady()) return [];
    const dev = new Map((devices || []).map(d => [d.mac, d])), un = new Map((unknown || []).map(d => [d.mac, d]));
    return SESS.sessions.filter(x => x.park).map(x => ({ ...x, known: dev.get(x.mac) || null, seen: un.get(x.mac) || null }));
  }
  // The card "Ohne Zugriff" into el (one sentence without a parked device): each with its name, why, MAC, switch and port, since;
  // with Ändern (may) "Freigeben", for a locked device "Entsperren" - the form of a known device, else a new one, released
  // (editDevice(…, release))
  function renderParkedInto(el, parked, may) {
    if (!el) return;
    if (!parked.length) { el.innerHTML = `<div class="card-h"><h2>Ohne Zugriff</h2></div><div class="empty">Gerade kein Gerät ohne Zugriff.</div>`; return; }
    const why = x => x.known ? (x.known.allowed ? "freigegeben, PacketFence parkt es trotzdem" : "in den MAC-Freigaben gesperrt") : "unbekannt";
    el.innerHTML = `<div class="card-h"><h2>Ohne Zugriff</h2><span class="sub">${parked.length === 1 ? "1 Gerät" : `${parked.length} Geräte`} im Park-VLAN: MAC-Anmeldung ohne Freigabe</span></div>`
      + `<div class="tbl-wrap"><table><thead><tr><th>Gerät</th><th>MAC</th><th>Switch · Port</th><th>Seit</th>${may ? "<th></th>" : ""}</tr></thead><tbody>`
      + parked.map((x, i) => `<tr><td>${esc(x.known ? x.known.name : (x.seen && (x.seen.name || x.seen.vendor)) || "unbekannt")}<span class="cellnote">${why(x)}</span></td>`
        + `<td class="mono">${esc(x.mac)}</td><td>${esc(x.switch_name || "–")} · ${esc(x.port || "–")}</td><td class="num">${esc(x.since)}</td>`
        + `${may ? `<td><button class="btn small primary" type="button" data-park="${i}">${x.known && !x.known.allowed ? "Entsperren" : "Freigeben"}</button></td>` : ""}</tr>`).join("") + `</tbody></table></div>`;
    el.onclick = e => {
      const b = e.target.closest("[data-park]"); if (!b) return;
      const x = parked[+b.dataset.park];
      if (x.known) editDevice(x.known, false, true);
      else editDevice({ mac: x.mac, name: ((x.seen && x.seen.name) || "").replace(/\..*$/, ""), kind: "sonstiges", location: `${x.switch_name} Port ${x.port}` }, true, true);
    };
  }
  // The card "Angemeldet" into el: every session logged in (not parked) with its device (the device of the database, else the account
  // of an 802.1X login), MAC, way, role and VLAN, switch and port, since; filtered by way (authFilter). The parked ones are only
  // counted, they stand among the unknown devices. Without PacketFence one sentence, a failure its reason
  async function renderAuthInto(el) {
    if (!el) return;
    const title = `<h2>Angemeldet (PacketFence)</h2>`;
    el.innerHTML = `<div class="card-h">${title}</div><div class="empty">Lade …</div>`;
    const a = await loadAuth();
    if (!el.isConnected) return;
    if (a.configured === false) { el.innerHTML = `<div class="card-h">${title}</div><div class="empty">PacketFence ist nicht eingerichtet (Einstellungen).</div>`; return; }
    if (a.ok === false) { el.innerHTML = `<div class="card-h">${title}</div><div class="empty">${esc(a.error)}</div>`; return; }
    const n = k => a.sessions.filter(x => authKind(x) === k).length, live = a.sessions.filter(x => !x.park);
    if (!["all", "dot1x", "mac"].includes(authFilter)) authFilter = "all";
    const draw = () => {
      const list = live.filter(x => authFilter === "all" || authKind(x) === authFilter);
      el.innerHTML = `<div class="card-h">${title}<span class="sub">${n("dot1x")} per 802.1X · ${n("mac")} per MAC-Freigabe${n("park") ? ` · ${n("park")} ohne Zugriff im Park-VLAN (Reiter „Ohne Zugriff“)` : ""}</span>
        <div class="right"><div class="seg" role="group" aria-label="Anmeldungen filtern" id="auf">${[["all", "Alle"], ["dot1x", "802.1X"], ["mac", "MAC-Freigabe"]]
          .map(([k, l]) => `<button type="button" data-af="${k}" aria-pressed="${authFilter === k}">${l}</button>`).join("")}</div></div></div>`
        + (list.length ? `<div class="tbl-wrap"><table><thead><tr><th>Gerät</th><th>MAC</th><th>Anmeldung</th><th>Rolle · VLAN</th><th>Switch · Port</th><th>Seit</th></tr></thead><tbody>`
          + list.map(x => `<tr><td>${esc(x.device || (x.how === "dot1x" ? x.user.replace(/^host\//i, "") : "") || "unbekannt")}</td><td class="mono">${esc(x.mac)}</td><td>${authPill(x)}</td>`
            + `<td>${esc(x.role || "–")}${x.vlan ? ` · ${esc(x.vlan)}` : ""}</td><td>${esc(x.switch_name || "–")} · ${esc(x.port || "–")}</td><td class="num">${esc(x.since)}</td></tr>`).join("")
          + `</tbody></table></div>` : `<div class="empty">${live.length ? "Keine Anmeldung passt zum Filter." : "Gerade niemand angemeldet."}</div>`);
    };
    draw();
    el.onclick = e => { const b = e.target.closest("[data-af]"); if (!b) return; authFilter = b.dataset.af; draw(); };
  }
