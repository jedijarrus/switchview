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
  // The hash of a view, the inverse of parseHash: the switch view with an id "#sw=<id>", with a name not resolved yet
  // "#switch=<name>" (encoded), else "#<view>"
  hashFor(view, sel) {
    if (view === "switches" && typeof sel === "number") return "#sw=" + sel;
    if (view === "switches" && typeof sel === "string") return "#switch=" + encodeURIComponent(sel);
    return "#" + view;
  },
  // The history step of a navigation from the hash from to the hash to: how "push" (the user navigates), "replace" (start, a name or
  // a missing choice resolved to an id) or "none" (Back, Forward, a typed hash: the entry is there already, null = no call). A push to
  // the hash already shown replaces it: no entry twice in a row.
  historyOp(how, from, to) {
    if (how === "none") return null;
    return how === "push" && from === to ? "replace" : how;
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
  // The names an LLDP neighbour carries when it is a switch of the list: every non-empty sysName and name (k), as
  // topology.switch_keys; an empty name is no switch
  peerKeys(switches) {
    const keys = new Set();
    switches.forEach(s => [s.sys, s.k].forEach(v => { if (v) keys.add(v); }));
    return keys;
  },
  // What the global search looks through, built once per netmap: an entry per port description, LLDP neighbour and device, in the
  // order the search lists them, each with hay (its text in lower case) and what a hit shows (t, x). Trunks themselves (Trk…) are
  // left out, and devices only of ports with at most 12 devices, no switch as LLDP neighbour (keys: peerKeys) and no trunk; a line
  // break joins the fields of a device, which a search term (input type=search) never holds.
  searchIndex(switches, keys) {
    const idx = [];
    switches.forEach(s => s.ports.forEach(p => {
      if (p.n.startsWith("Trk")) return;
      const at = { sid: s.id, k: s.k, port: p.n };
      if (p.a) idx.push({ ...at, hay: p.a.toLowerCase(), t: p.a, x: "Port-Beschreibung" });
      p.l.forEach(x => idx.push({ ...at, hay: (x[0] + " " + x[1]).toLowerCase(), t: x[0] + " Port " + x[1], x: "LLDP-Nachbar" }));
      if (p.mc <= 12 && !p.l.some(x => keys.has(x[0])) && !p.tr)
        p.d.forEach(d => idx.push({ ...at, hay: d.map(v => String(v || "").toLowerCase()).join("\n"), t: d[3] || d[4] || d[0],
          x: d[0] + (d[2] ? " · " + d[2] : "") + " · VLAN " + d[1] }));
    }));
    return idx;
  },
  // The first max entries of a searchIndex whose text holds term (lower case)
  searchHits(index, term, max = 30) {
    const hits = [];
    for (const e of index) {
      if (!e.hay.includes(term)) continue;
      hits.push(e);
      if (hits.length >= max) break;
    }
    return hits;
  },
  // The option a key makes active in a list of n options when option cur is (-1: none): the arrows go round, any other key keeps
  // cur; -1 for an empty list
  nextIndex(cur, n, key) {
    if (n === 0) return -1;
    if (key === "ArrowDown") return (cur + 1) % n;
    if (key === "ArrowUp") return cur <= 0 ? n - 1 : cur - 1;
    return cur;
  },
  // The VLAN matrix of one switch in one pass: per VLAN id any port names in u or t, the ports that carry it untagged (u) and tagged
  // (t). Counted are trunks named Trk… and ports without tr (a trunk counts once, not with each member); a LAG of another make (Po1,
  // ae0: tr is its own name) is not counted, but its VLANs still get their key, as the matrix had it before Phase 5. A port's u and t
  // name each VLAN once (poller.py builds them from the switch's VLAN table), so an entry is a port.
  vlanCounts(ports) {
    const c = Object.create(null);
    for (const p of ports) {
      const add = p.n.startsWith("Trk") || !p.tr ? 1 : 0;
      for (const id of p.u) (c[id] || (c[id] = { u: 0, t: 0 })).u += add;
      for (const id of p.t) (c[id] || (c[id] = { u: 0, t: 0 })).t += add;
    }
    return c;
  },
  // What follows saving a switch (R44), from the stored row before (null: a new switch), the payload sent and the row the server
  // now has (GET /api/switches): "" when SNMP writing is off or goes out authenticated; else "dialog" (SNMP-Schreiben prüfen) after
  // a write-relevant change, "hint" (a toast) otherwise. Write-relevant: a new switch; driver, SNMP writing, RW user or its
  // protocols sent (the form sends them only when they change); address or SNMP version changed; an SNMP secret entered or
  // deleted ("" deletes); or the write state of the server moved (writing identity, insecure, error).
  writeAlertMode(stored, payload, row) {
    if (!(row && row.snmp_write && (row.snmp_rw_insecure || !row.snmp_write_via || row.snmp_write_error))) return "";
    if (!stored) return "dialog";
    const same = (a, b) => (a == null ? "" : String(a)) === (b == null ? "" : String(b));
    const touched = ["driver", "snmp_write", "snmp_rw_user", "snmp_rw_auth_proto", "snmp_rw_priv_proto"].some(k => k in payload)
      || ["host", "snmp_version"].some(k => k in payload && !same(payload[k], stored[k]))
      || ["snmp_community", "snmp_auth_pass", "snmp_priv_pass", "snmp_rw_community", "snmp_rw_auth_pass", "snmp_rw_priv_pass"].some(k => payload[k] != null);
    const moved = !same(stored.snmp_write_via, row.snmp_write_via) || !!stored.snmp_rw_insecure !== !!row.snmp_rw_insecure
      || !same(stored.snmp_write_error, row.snmp_write_error);
    return touched || moved ? "dialog" : "hint";
  },
};
if (typeof module === "object" && module.exports) module.exports = SVLogic; else globalThis.SVLogic = SVLogic;
