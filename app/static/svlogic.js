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
  // What the UI reloads once change c (GET /api/changes/<id>) has ended, and after how many ms: a change that sent nothing
  // (sent 0) changed nothing at the switch, so only its change list ("list", at once); any other the netmap and the view ("map"),
  // 200 ms after a save, 4.5 s after any other change (the server polls its switch again 3 s after one, changes._repoll). sent
  // null (a row from before the column) counts as sent, as changes.may_have_sent.
  afterChange(c) {
    if (c.sent === 0) return { reload: "list", delay: 0 };
    return { reload: "map", delay: c.kind === "save" ? 200 : 4500 };
  },
  // The whole minutes left until `until` (UTC text "YYYY-MM-DD HH:MM:SS", as changes.confirm_until) at now (milliseconds), rounded up
  // and never below 0: "noch N Minuten" of a change that waits for its confirmation; text that is no time counts as 0
  minutesLeft(until, now) {
    const t = Date.parse(String(until || "").replace(" ", "T") + "Z");
    return isNaN(t) ? 0 : Math.max(0, Math.ceil((t - now) / 60000));
  },
  // The ports of one switch in the form of a bulk change, from its text ("1-4, 7, Gi1/0/2"): split at commas and white space; "a-b"
  // of digits is every port from a to b (a range the wrong way round is an error), any other part a port name as
  // api_changes.SNMP_PORT_RE allows it (so "ge-0/0/1" is a name); a port named twice counts once, at its first place. At most 200
  // ports (the limit of a /plan). {ports, error}: with an error (the first) no ports
  parsePorts(text) {
    const ports = [], bad = error => ({ ports: [], error });
    for (const part of String(text == null ? "" : text).split(/[\s,]+/).filter(Boolean)) {
      const range = /^(\d+)-(\d+)$/.exec(part), from = range ? Number(range[1]) : 0, to = range ? Number(range[2]) : 0;
      if (range && from > to) return bad(`Bereich „${part}“ ist rückwärts`);
      if (!range && !/^[A-Za-z0-9][A-Za-z0-9/._:-]{0,63}$/.test(part)) return bad(`Port „${part}“ ist ungültig`);
      // a range wider than the limit is over it whatever came before: refused without counting it out
      if (to - from >= 200) return bad("Höchstens 200 Ports je Switch");
      for (const n of range ? Array.from({ length: to - from + 1 }, (_, i) => String(from + i)) : [part]) if (!ports.includes(n)) ports.push(n);
      if (ports.length > 200) return bad("Höchstens 200 Ports je Switch");
    }
    return { ports, error: null };
  },
  // The query string of params for GET /api/history, /api/events and the audit: "?" and k=v (both encoded) for every value but "",
  // null and undefined (no filter), joined with "&" in the order of params; "" when none is left
  query(params) {
    const parts = Object.entries(params || {}).filter(([, v]) => v !== "" && v != null)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    return parts.length ? "?" + parts.join("&") : "";
  },
  // A count with its noun in the singular for 1, else in the plural ("1 Befund", "2 Befunde", "0 Befunde")
  plural(n, one, many) {
    return `${n} ${n === 1 ? one : many}`;
  },
  // The recipients of the alert card from its text field (PUT /api/settings/alerts mail_to): split at line breaks and commas,
  // trimmed, empty ones dropped; an entry without "@" or with a space is no address and named in errors as the server names it
  splitRecipients(text) {
    const list = [], errors = [];
    for (const a of String(text || "").split(/[\n,]/).map(x => x.trim()).filter(Boolean)) {
      if (a.includes("@") && !/\s/.test(a)) list.push(a); else errors.push(`Mail-Adresse ungültig: ${a}`);
    }
    return { list, errors };
  },
  // The query of GET /api/audit for the filter f of the audit view ({text, action, user, role, sw, from, to, order, cursor}, each
  // optional; SVLogic.query drops what is empty): q and user trimmed, switch_id, since the midnight that starts the day from and
  // until the midnight that ends the day to (a day "YYYY-MM-DD" of the browser's time zone, as toISOString writes the instant; a
  // day that is none sends nothing), order only "asc" (the server's default is the newest first), then cursor and limit 100. paged
  // false leaves cursor and limit out: the CSV (GET /api/audit.csv) of the same filters
  auditParams(f, paged = true) {
    const day = (d, next) => {
      const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(d || ""), t = new Date(2000, 0, 1);
      if (!m) return "";
      t.setFullYear(+m[1], +m[2] - 1, +m[3]);
      if (t.getFullYear() !== +m[1] || t.getMonth() !== +m[2] - 1 || t.getDate() !== +m[3]) return "";
      if (next) t.setDate(t.getDate() + 1);
      return t.toISOString();
    };
    const trim = v => String(v == null ? "" : v).trim();
    return SVLogic.query({ q: trim(f.text), action: f.action, user: trim(f.user), role: f.role, switch_id: f.sw, since: day(f.from, false),
      until: day(f.to, true), order: f.order === "asc" ? "asc" : "", cursor: paged ? f.cursor : null, limit: paged ? 100 : null });
  },
  // Whether role (of /api/auth/me) is min or above it, in the order of roles.ORDER on the server (lowest first); an unknown role
  // (or min) is none, never more
  atLeast(role, min) {
    const order = ["lesen", "aendern", "freigeben", "admin"], i = order.indexOf(role), j = order.indexOf(min);
    return i >= 0 && j >= 0 && i >= j;
  },
  // The number in the tab "Freigaben" of user me (/api/auth/me) over the requests list (GET /api/approvals, own: me asked for it):
  // with Freigeben or Admin the open requests of others it may review, at a switch of its zones (me.zones, null = every zone; a
  // switch without a zone is ""), as inZone in the list - a bulk request (kind bulk_change) has no switch of its own and counts for
  // every reviewer, as the list offers "Prüfen" for it (the server checks the zone of each of its switches); below that the open
  // requests of its own
  approvalCount(list, me) {
    const reviewer = SVLogic.atLeast(me && me.role, "freigeben"), zones = me && me.zones;
    return (list || []).filter(a => a.status === "open"
      && (reviewer ? !a.own && (zones == null || a.kind === "bulk_change" || zones.includes(a.switch_zone || "")) : !!a.own)).length;
  },
  // The name of a role as the UI shows it; an unknown one as it stands, none as "–" (an audit entry from before Phase 4a)
  roleLabel(role) {
    return { lesen: "Lesen", aendern: "Ändern", freigeben: "Freigeben", admin: "Admin" }[role] || (role ? String(role) : "–");
  },
  // The zone list of the settings (PUT /api/zone-scopes) from its text: a line "<App-Rolle> = <Zone>, <Zone>" per app role, empty
  // lines and lines starting with "#" skipped, "Ohne Zone" for the switches without a zone (""). One app role on two lines is one
  // entry, its zones once each in the order they first came; errors name the line (1 = the first), also for the limits of
  // api_settings.ZoneScope (an app role at most 200 characters, a zone at most 40, as Python counts them: code points; at most 100
  // zones per app role and 200 app roles), and a line with an error adds nothing
  parseScopes(text) {
    const entries = [], errors = [], chars = s => [...s].length;
    String(text || "").split("\n").forEach((raw, i) => {
      const line = raw.trim(), eq = line.indexOf("="), bad = why => errors.push(`Zeile ${i + 1}: ${why}`);
      if (!line || line.startsWith("#")) return;
      const principal = eq < 0 ? "" : line.slice(0, eq).trim();
      if (!principal) return bad("„App-Rolle = Zone, Zone“ erwartet");
      if (chars(principal) > 200) return bad("App-Rolle länger als 200 Zeichen");
      const zones = line.slice(eq + 1).split(",").map(z => z.trim()).filter(Boolean).map(z => (z === "Ohne Zone" ? "" : z));
      if (!zones.length) return bad("keine Zone");
      if (zones.some(z => chars(z) > 40)) return bad("Zone länger als 40 Zeichen");
      const e = entries.find(x => x.principal === principal), merged = [...new Set([...(e ? e.zones : []), ...zones])];
      if (merged.length > 100) return bad("mehr als 100 Zonen für eine App-Rolle");
      if (!e && entries.length === 200) return bad("mehr als 200 App-Rollen");
      if (e) e.zones = merged; else entries.push({ principal, zones: merged });
    });
    return { entries, errors };
  },
  // The text of a zone list (GET /api/zone-scopes entries), the inverse of parseScopes
  formatScopes(entries) {
    return (entries || []).map(e => `${e.principal} = ${e.zones.map(z => (z === "" ? "Ohne Zone" : z)).join(", ")}`).join("\n");
  },
  // The app roles of the entries whose line formatScopes writes and parseScopes reads back otherwise (the text has no quoting): a
  // comma in a zone, a zone named "Ohne Zone", an "=" in the app role or a "#" at its start. Saving the field would change them
  lossyScopes(entries) {
    const same = (a, b) => a.length === b.length && a.every((z, i) => z === b[i]);
    return (entries || []).filter(e => {
      const [back, more] = SVLogic.parseScopes(SVLogic.formatScopes([e])).entries;
      return !back || more || back.principal !== e.principal || !same(back.zones, e.zones);
    }).map(e => e.principal);
  },
};
if (typeof module === "object" && module.exports) module.exports = SVLogic; else globalThis.SVLogic = SVLogic;
