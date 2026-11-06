/* SwitchView: frontend logic without DOM, tested with node (tests/test_frontend_logic.py). In the browser window.SVLogic, in Node
   module.exports. Exactly one top-level name: every top-level name of a classic script is global, next to those of the app scripts. */
"use strict";
const SVLogic = {
  // The view a location.hash names: "#sw=<id>" a switch by id, "#switch=<name>" one by name (bookmarks from before ids), else the
  // view itself ("" = overview). Never throws: a malformed escape ("%", "%E0%A4%A") is taken as it stands, decodeURIComponent's
  // URIError reached start() and showed the login.
  parseHash(hash) {
    let rest = String(hash || "").replace(/^#/, "");
    try { rest = decodeURIComponent(rest); } catch (e) { /* URIError: the raw text */ }
    if (rest.startsWith("sw=")) {
      const v = rest.slice(3);
      return { view: "switches", sw: /^[0-9]{1,15}$/.test(v) ? Number(v) : null, swName: null };
    }
    if (rest.startsWith("switch=")) return { view: "switches", sw: null, swName: rest.slice(7) || null };
    return { view: rest || "overview", sw: null, swName: null };
  },
  // The id of the switch sel names: an id of the list, a name (the first switch of that name), else the first switch; null for none
  switchIdOf(switches, sel) {
    if (!switches || !switches.length) return null;
    const hit = typeof sel === "number" ? switches.find(s => s.id === sel) : typeof sel === "string" ? switches.find(s => s.k === sel) : undefined;
    return (hit || switches[0]).id;
  },
  // Where Tab (shift: Shift+Tab) goes in an open dialog of n focusable controls when control i has the focus (-1: none of them):
  // the index to focus, -1 for the dialog itself (it has no control), null to leave the move to the browser (inside the list)
  trapStep(n, i, shift) {
    if (n === 0) return -1;
    if (i === -1) return shift ? n - 1 : 0;
    if (!shift && i === n - 1) return 0;
    if (shift && i === 0) return n - 1;
    return null;
  },
};
if (typeof module === "object" && module.exports) module.exports = SVLogic; else globalThis.SVLogic = SVLogic;
