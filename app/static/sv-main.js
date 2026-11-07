"use strict";

  /* ── Router: #overview, #switches, #sw=<id>, #vlans, … (#switch=<name>: a bookmark from before ids, still valid). Every navigation
     of the user adds a history entry, so Back and Forward walk the views; popstate / hashchange show the view of the hash. ── */
  const VIEWS = { overview: renderOverview, switches: renderSwitchDetail, vlans: renderVlans, devices: renderDevices, verlauf: renderVerlauf,
    backups: renderBackups, approvals: renderApprovals, audit: renderAudit, settings: renderSettings };
  // selSwitch: the id of the shown switch (a name is not unique); from an old bookmark briefly a name, which renderSwitchDetail resolves
  // with SVLogic.switchIdOf
  let current = "overview", selSwitch = null, swVlan = null, swPortFilter = "all", swText = "";
  // The hash of the current view: "#sw=<id>"; a name not resolved yet keeps its "#switch=<name>"
  const shownHash = () => SVLogic.hashFor(current, current === "switches" ? selSwitch : null);
  // Puts the hash of the current view into the address bar. how: "replace" (start, renderSwitchDetail resolving a name or a missing
  // choice to "#sw=<id>": the entry stays the one the user came by), "push" (a navigation of the user; to the hash already shown it
  // replaces), "none" (Back, Forward, a typed hash: the entry is there already)
  function syncHash(how = "replace") {
    const to = shownHash(), op = SVLogic.historyOp(how, location.hash, to);
    try { if (op === "push") history.pushState(null, "", to); else if (op === "replace") history.replaceState(null, "", to); } catch (e) { /* egal */ }
  }
  function go(view, arg, how = "push") {
    if (!VIEWS[view]) view = "overview";
    current = view;
    if (view === "switches" && arg !== undefined) selSwitch = arg;
    document.querySelectorAll(".tabs [data-view]").forEach(b => { if (b.dataset.view === view) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); });
    syncHash(how);
    // The tile the panel came from goes with the view it stood in
    closeDrawer(true); drLast = null;
    $("#view").onclick = null;
    VIEWS[view]();
    // The count of open requests in the tab "Freigaben", at every navigation (start() too, through goToHash), never by timer: a
    // request in the background would count as activity and keep an open tab from the idle logout (T3-f, T9-a)
    refreshApprovals();
    window.scrollTo(0, 0);
  }
  $(".tabs").addEventListener("click", e => { const b = e.target.closest("[data-view]"); if (b) go(b.dataset.view); });
  // The view location.hash names, with the history step how (see syncHash): an id or a name selects the switch, none keeps the last.
  // SVLogic.parseHash never throws: a malformed hash ("#%") no longer ends in the catch of the start call, which showed the login
  function goToHash(how) {
    const h = SVLogic.parseHash(location.hash);
    go(h.view, h.sw != null ? h.sw : h.swName != null ? h.swName : undefined, how);
  }
  async function start() {
    ME = await api("GET", "/api/auth/me");
    $("#user-name").textContent = ME.name; $("#user-role").textContent = SVLogic.roleLabel(ME.role); $("#login").hidden = true; $("#app").hidden = false;
    goToHash("replace");
  }
  // Back, Forward and a hash typed in the address bar: the browser fires popstate, then hashchange, and the second finds its view shown
  // already. Every layer closes without asking (Back means "away from here"; a running change runs on at the server and stays in the
  // change list). Nothing on the login page: start() shows the hash after the login.
  function onPopState() {
    if ($("#app").hidden || location.hash === shownHash()) return;
    dropLayers(); goToHash("none");
  }
  window.addEventListener("popstate", onPopState);
  window.addEventListener("hashchange", onPopState);
  // Every view starts at the top (go): the views build asynchronously, a restore by the browser would jump ahead of the content
  if ("scrollRestoration" in history) history.scrollRestoration = "manual";

  (async () => { try { await initLogin(); } catch (e) { showLogin(e.message); return; } try { await start(); } catch (e) { showLogin(); } })();
