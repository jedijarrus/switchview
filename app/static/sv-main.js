"use strict";

  /* ── Router: #overview, #switches, #sw=<id>, #vlans, … (#switch=<name>: a bookmark from before ids, still valid) ── */
  const VIEWS = { overview: renderOverview, switches: renderSwitchDetail, vlans: renderVlans, devices: renderDevices, backups: renderBackups, audit: renderAudit, settings: renderSettings };
  // selSwitch: the id of the shown switch (a name is not unique); from an old bookmark briefly a name, which renderSwitchDetail resolves
  // with SVLogic.switchIdOf
  let current = "overview", selSwitch = null, swVlan = null, swPortFilter = "all", swText = "";
  // The hash of the current view: "#sw=<id>"; a name not resolved yet keeps its "#switch=<name>"
  function syncHash() {
    const sw = current === "switches" && selSwitch != null ? (typeof selSwitch === "number" ? "sw=" + selSwitch : "switch=" + encodeURIComponent(selSwitch)) : "";
    try { history.replaceState(null, "", "#" + (sw || current)); } catch (e) { /* egal */ }
  }
  function go(view, arg) {
    if (!VIEWS[view]) view = "overview";
    current = view;
    if (view === "switches" && arg !== undefined) selSwitch = arg;
    document.querySelectorAll(".tabs [data-view]").forEach(b => { if (b.dataset.view === view) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); });
    syncHash();
    closeDrawer(true);
    $("#view").onclick = null;
    VIEWS[view]();
    window.scrollTo(0, 0);
  }
  $(".tabs").addEventListener("click", e => { const b = e.target.closest("[data-view]"); if (b) go(b.dataset.view); });
  async function start() {
    ME = await api("GET", "/api/auth/me");
    $("#user-name").textContent = ME.name; $("#login").hidden = true; $("#app").hidden = false;
    // SVLogic.parseHash never throws: a malformed hash ("#%") no longer ends in the catch below, which showed the login
    const h = SVLogic.parseHash(location.hash);
    go(h.view, h.sw != null ? h.sw : h.swName != null ? h.swName : undefined);
  }

  (async () => { try { await initLogin(); } catch (e) { showLogin(e.message); return; } try { await start(); } catch (e) { showLogin(); } })();
