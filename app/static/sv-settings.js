"use strict";

  /* ── Einstellungen: the cards of the settings in one column, on the left a bar of their sections (SETTINGS_SECTIONS: a click
     scrolls to the card and focuses it, the section at the top is marked while scrolling). Every card saves only itself and draws
     only itself anew, so what another card holds unsaved stays; a card with changes not saved says so in its foot and with a dot in
     the bar (trackDirty marks it at every input, its save clears it: setDirty). The settings of GET /api/settings sit on three
     cards ("Allgemein", "Gerätenamen", "RADIUS und PacketFence") that share one PUT, which sets every field (one left out would be
     reset): each card sends its own fields and the stored values of the others, a secret of another card as null (= unchanged).
     "SNMP für PacketFence" and "Vier-Augen-Prinzip" read from it too, each with a PUT of its own.
     Changing them is Admin: below it every field is locked and the save buttons are gone, one sentence on top says why; what only
     reads (names, PacketFence test) and ending the own sessions stay. The cards of sv-alerts.js and sv-tokens.js ask
     beside them, each on its own (a failure is its card's text): "Sicherheitsregeln" for everyone, "Benachrichtigungen" only for
     an Admin; "API-Tokens" for everyone, "Alle API-Tokens" only for an Admin, which no one waits for. ── */
  // The sections of the bar in the order of the cards: [the card's id, its label]
  const SETTINGS_SECTIONS = [["set-general", "Allgemein"], ["set-names", "Gerätenamen"], ["set-pf", "RADIUS und PacketFence"],
    ["set-snmp", "SNMP für PacketFence"], ["alert-card", "Benachrichtigungen"], ["set-zones", "Zonen"], ["set-4e", "Vier-Augen-Prinzip"], ["rules-card", "Sicherheitsregeln"],
    ["set-sessions", "Sitzungen"], ["tok-card", "API-Tokens"]];
  // A card whose top is above this line (px from the top of the window, below the header) is the one the bar marks
  const SETTINGS_SPY_LINE = 140;

  // The head of a card of this file: its title and a short sentence beside it
  const setHead = (title, sub = "") => `<div class="card-h"><h2>${title}</h2>${sub ? `<span class="sub">${sub}</span>` : ""}</div>`;
  // A new address deletes the secret bound to it unless the same save enters it anew (F2, api_settings.DESTINATION_SECRETS)
  const setDestNote = id => `<p class="note warn" id="${id}-note" style="margin:0" hidden>Neue Adresse: Das gespeicherte Kennwort bzw. der API-Schlüssel gilt nur für die alte Adresse. Was du hier nicht neu eingibst, löscht das Speichern.</p>`;
  // Credentials readable on the wire (E32): shown while the check box is off or the address uses http:// (both stay allowed)
  const setTlsNote = id => `<p class="note warn" id="${id}-note" style="margin:0" hidden>Ohne TLS-Prüfung (oder mit http://) kann jemand im Netz Kennwort bzw. API-Schlüssel mitlesen.</p>`;

  // The three cards of GET /api/settings (s), each the inside of its section; below Admin locked and without "Speichern"
  function generalCard(s, admin) {
    return setHead("Allgemein") + `<div class="card-b set-b"><label class="field" style="max-width:320px"><span>Abfrage-Intervall (Minuten)</span><input id="s-poll" type="number" min="5" max="1440" value="${esc(s.poll_minutes)}"${admin ? "" : " disabled"}><span class="hint">so oft fragt SwitchView jeden Switch ab</span></label></div>`
      + (admin ? cardFoot("s-save", "Allgemein") : "");
  }
  function namesCard(s, admin) {
    const dis = admin ? "" : " disabled";
    return setHead("Gerätenamen", "aus der ARP-Tabelle der OPNsense") + `<div class="card-b set-b">
      <label class="field"><span>OPNsense-Adresse</span><input id="s-url" value="${esc(s.opnsense_url)}" placeholder="https://opnsense.example.com"${dis}><span class="hint">API-Benutzer mit Recht „Diagnostics: ARP Table“</span></label>
      ${setDestNote("s-url")}
      <div class="grid2">${secretInput(s, "s-key", "API-Key", "opnsense_key", s.opnsense_key_set, { disabled: !admin })}
      ${secretInput(s, "s-secret", "API-Secret", "opnsense_secret", s.opnsense_secret_set, { disabled: !admin })}</div>
      <label class="check"><input id="s-tls" type="checkbox" ${s.opnsense_verify_tls ? "checked" : ""}${dis}> TLS-Zertifikat prüfen</label>
      ${setTlsNote("s-tls")}</div>`
      + cardFoot(admin ? "s-names-save" : "", "Gerätenamen", `<button class="btn" type="button" id="s-names">Namen jetzt aktualisieren</button>`, "Aktualisieren nutzt den gespeicherten Stand.");
  }
  function pfCard(s, admin) {
    const dis = admin ? "" : " disabled";
    return setHead("RADIUS und PacketFence", "Anmeldung an den Ports, Geräte-Freigaben") + `<div class="card-b set-b">
      <div class="grid2"><label class="field"><span>RADIUS-Server (PacketFence-IP)</span><input id="s-rs" value="${esc(s.radius_server)}" placeholder="IP-Adresse"${dis}><span class="hint">wird beim „Vorbereiten“ eines Switches eingetragen</span></label>
      ${secretInput(s, "s-rk", "Shared Secret der Switches", "radius_key", s.radius_key_set, { hint: "wie in PacketFence beim Switch hinterlegt", disabled: !admin })}</div>
      ${setDestNote("s-rs")}
      <hr class="set-hr">
      <label class="field"><span>PacketFence-API</span><input id="s-pfu" value="${esc(s.pf_url)}" placeholder="https://packetfence:9999"${dis}><span class="hint">für die Geräte-Freigaben (Nodes mit Rolle)</span></label>
      ${setDestNote("s-pfu")}
      <div class="grid2"><label class="field"><span>API-Benutzer</span><input id="s-pfuser" value="${esc(s.pf_user)}" autocomplete="off"${dis}></label>
      ${secretInput(s, "s-pfpass", "API-Kennwort", "pf_pass", s.pf_pass_set, { disabled: !admin })}</div>
      <label class="check"><input id="s-pftls" type="checkbox" ${s.pf_verify_tls ? "checked" : ""}${dis}> TLS-Zertifikat prüfen</label>
      ${setTlsNote("s-pftls")}</div>`
      + cardFoot(admin ? "s-pf-save" : "", "RADIUS und PacketFence", `<button class="btn" type="button" id="s-pftest">PacketFence testen</button>`, "Testen nutzt den gespeicherten Stand.");
  }
  // The card "SNMP für PacketFence" (pf_snmp_* of GET /api/settings): the SNMPv3 user „Vorbereiten“ sets up on a switch, with which
  // PacketFence switches a port after a release. An empty passphrase field keeps what is stored
  function snmpCard(s, admin) {
    return setHead("SNMP für PacketFence", "Port umschalten ohne Kabelziehen") + `<div class="card-b set-b">
      <p class="note" style="margin:0">Nach einer Freigabe schaltet PacketFence den Port per SNMPv3 um. „Vorbereiten“ legt dafür diesen Benutzer auf dem Switch an (SHA und AES, Gruppe „managerpriv“). Ohne Benutzer lässt „Vorbereiten“ SNMPv3 unberührt.</p>
      <label class="field" style="max-width:320px"><span>SNMPv3-Benutzer</span><input id="s-snu" value="${esc(s.pf_snmp_user || "")}" maxlength="32" autocomplete="off" placeholder="packetfence"${admin ? "" : " disabled"}><span class="hint">wie in PacketFence beim Switch hinterlegt</span></label>
      <div class="grid2">${secretInput(s, "s-sna", "Auth-Passwort (SHA)", "pf_snmp_auth", s.pf_snmp_auth_set, { max: 32, disabled: !admin })}
      ${secretInput(s, "s-snp", "Priv-Passwort (AES)", "pf_snmp_priv", s.pf_snmp_priv_set, { max: 32, disabled: !admin })}</div></div>`
      + (admin ? cardFoot("s-snmp-save", "SNMP für PacketFence") : "");
  }
  // The card "Zonen" (the list of GET /api/zone-scopes is put into the textarea after the render: SVLogic.formatScopes). Stored
  // entries the field cannot hold as they are (SVLogic.lossyScopes) are named above it, so a save does not change them unseen; that
  // saving would change them is said to an Admin only, who has the button
  function zonesCard(lossy, admin) {
    return setHead("Zonen", "Entra-App-Rollen, die das Ändern auf Zonen beschränken") + `<div class="card-b set-b">
        <p class="note" style="margin:0">Benutzer mit „Ändern“ oder „Freigeben“ und einer dieser Entra-App-Rollen ändern nur Switches dieser Zonen. Wer keine trägt, ist nicht beschränkt.</p>
        ${lossy.length ? `<p class="note warn" id="s-scopes-lossy" style="margin:0">Diese Einträge zeigt das Feld nicht so, wie sie gespeichert sind: ${lossy.map(x => `„${esc(x)}“`).join(", ")}. Eine Zone mit Komma oder mit dem Namen „Ohne Zone“ und eine App-Rolle mit „=“ oder „#“ am Anfang lassen sich hier nicht schreiben${admin ? "; „Speichern“ würde sie ändern" : ""}.</p>` : ""}
        <label class="field"><span>Eine Zeile je App-Rolle</span><textarea id="s-scopes" rows="4" placeholder="SwitchView.Zone.EK = EK, Lager" aria-describedby="s-scopes-hint${lossy.length ? " s-scopes-lossy" : ""}"${admin ? "" : " disabled"}></textarea><span class="hint" id="s-scopes-hint">„Ohne Zone“ steht für Switches ohne Zone.</span></label></div>`
      + (admin ? cardFoot("s-zones-save", "Zonen") : "");
  }
  // The card "Vier-Augen-Prinzip" (four_eyes and approval_hours of GET /api/settings); the principle covers every change in expert
  // mode and, since Phase 4c, every bulk change (approvals.needs_approval)
  function fourEyesCard(s, admin) {
    const dis = admin ? "" : " disabled";
    return setHead("Vier-Augen-Prinzip") + `<div class="card-b set-b">
        <label class="check"><input type="checkbox" id="s-4e"${s.four_eyes ? " checked" : ""}${dis}> Änderungen im Expertenmodus und Sammeländerungen brauchen die Freigabe durch eine zweite Person (Rolle „Freigeben“ oder „Admin“)</label>
        <label class="field" style="max-width:220px"><span>Anfragen verfallen nach (Stunden)</span><input id="s-4h" type="number" min="1" max="168" value="${esc(s.approval_hours)}"${dis}></label>
        <p class="note warn" style="margin:0">Niemand kann die eigene Anfrage freigeben, auch nicht mit „Admin“, und der Notfall-Login gibt nichts frei. Mit nur einer Person mit „Freigeben“ oder „Admin“ gehen Änderungen im Expertenmodus und Sammeländerungen dann nicht.</p></div>`
      + (admin ? cardFoot("s-4save", "Vier-Augen-Prinzip") : "");
  }

  // Card id holds changes not saved (on) or not: its foot and its entry in the bar say so (CSS: .dirty)
  function setDirty(id, on) {
    const card = $("#" + id), entry = $("#nav-" + id);
    if (card) card.classList.toggle("dirty", !!on);
    if (entry) entry.classList.toggle("dirty", !!on);
  }
  // Every input in card id marks it, and so do adding and removing a custom rule (Sicherheitsregeln). The section stays when a card
  // draws its inside anew, so do these handlers
  function trackDirty(id) {
    const card = $("#" + id), on = () => setDirty(id, true);
    if (!card) return;
    card.addEventListener("input", on); card.addEventListener("change", on);
    card.addEventListener("click", e => { if (e.target.closest && e.target.closest("#r-add, [data-cdel]")) on(); });
  }
  // The bar: a click scrolls to its card (smooth unless the user asks for less motion) and focuses it; while scrolling the card at the
  // top is marked (aria-current), a click's own card for the time its scroll takes. A handler whose bar is gone (another view, the
  // page drawn anew) takes itself away
  function bindSettingsNav() {
    const nav = $("#set-nav"); let hold = 0;
    if (!nav) return;
    const mark = cur => SETTINGS_SECTIONS.forEach(([id]) => { const entry = $("#nav-" + id); if (!entry) return; if (id === cur) entry.setAttribute("aria-current", "location"); else entry.removeAttribute("aria-current"); });
    nav.addEventListener("click", e => {
      const b = e.target.closest("[data-sec]"), id = b && b.dataset.sec, card = id && $("#" + id);
      if (!card) return;
      hold = Date.now() + 900; mark(id);
      const calm = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      card.scrollIntoView({ behavior: calm ? "auto" : "smooth", block: "start" });
      if (card.getAttribute("tabindex") == null) card.setAttribute("tabindex", "-1");
      card.focus({ preventScroll: true });
    });
    const spy = () => {
      if (!nav.isConnected) { window.removeEventListener("scroll", spy); return; }
      if (Date.now() < hold) return;
      let cur = SETTINGS_SECTIONS[0][0];
      SETTINGS_SECTIONS.forEach(([id]) => { const card = $("#" + id); if (card && card.getBoundingClientRect().top < SETTINGS_SPY_LINE) cur = id; });
      mark(cur);
    };
    window.addEventListener("scroll", spy, { passive: true });
    mark(SETTINGS_SECTIONS[0][0]);
  }

  async function renderSettings() {
    const v = $("#view"), failed = e => ({ error: e.message }), admin = roleOk("admin");
    const cards = Promise.all([api("GET", "/api/compliance/rules").catch(failed), admin ? api("GET", "/api/settings/alerts").catch(failed) : null]);
    const got = await Promise.all([api("GET", "/api/settings"), api("GET", "/api/zone-scopes")])
      .catch(e => { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return null; });
    if (!got) return;
    const [rules, alertSet] = await cards, scopes = got[1], lossy = SVLogic.lossyScopes(scopes.entries);
    let s = got[0];
    const section = (id, html) => `<section class="card" id="${id}">${html}</section>`;
    v.innerHTML = `<div class="set-layout"><nav class="set-nav" id="set-nav" aria-label="Abschnitte der Einstellungen">${SETTINGS_SECTIONS.map(([id, label]) => `<button type="button" id="nav-${id}" data-sec="${id}">${label}<span class="dot" aria-hidden="true"></span></button>`).join("")}</nav>
      <div class="set-main">${admin ? "" : `<p class="note gate">Einstellungen ändern braucht die Rolle „Admin“.</p>`}
      ${section("set-general", generalCard(s, admin))}${section("set-names", namesCard(s, admin))}${section("set-pf", pfCard(s, admin))}${section("set-snmp", snmpCard(s, admin))}
      ${section("alert-card", alertCardHtml(alertSet, admin))}
      ${section("set-zones", zonesCard(lossy, admin))}${section("set-4e", fourEyesCard(s, admin))}${section("rules-card", rulesCardHtml(rules, admin))}
      ${section("set-sessions", setHead("Sitzungen") + `<div class="card-b set-b"><p class="note" style="margin:0">Beendet jede Anmeldung von <b>${esc(ME.name)}</b> auf allen Geräten, auch diese.</p></div>`
        + cardFoot("", "", `<button class="btn danger" type="button" id="s-logout-all">Alle meine Sitzungen beenden</button>`))}
      ${tokenCardsHtml(admin)}</div></div>`;
    // The three cards of GET /api/settings: own(id) are the fields a card sends, the rest go as stored; saved, s is read again and only
    // that card drawn anew (its handlers too: bindCard)
    const SCARDS = { "set-general": generalCard, "set-names": namesCard, "set-pf": pfCard }, SAVE = { "set-general": "s-save", "set-names": "s-names-save", "set-pf": "s-pf-save" };
    const pw = id => { const x = $("#" + id).value; return x === "" ? null : x; };
    const own = { "set-general": () => ({ poll_minutes: +$("#s-poll").value || 15 }),
      "set-names": () => ({ opnsense_url: $("#s-url").value.trim(), opnsense_key: pw("s-key"), opnsense_secret: pw("s-secret"), opnsense_verify_tls: $("#s-tls").checked }),
      "set-pf": () => ({ radius_server: $("#s-rs").value.trim(), radius_key: pw("s-rk"), pf_url: $("#s-pfu").value.trim(), pf_user: $("#s-pfuser").value.trim(), pf_pass: pw("s-pfpass"),
        pf_verify_tls: $("#s-pftls").checked }) };
    const stored = () => ({ poll_minutes: s.poll_minutes, opnsense_url: s.opnsense_url, opnsense_key: null, opnsense_secret: null, opnsense_verify_tls: !!s.opnsense_verify_tls,
      radius_server: s.radius_server, radius_key: null, pf_url: s.pf_url, pf_user: s.pf_user, pf_pass: null, pf_verify_tls: !!s.pf_verify_tls });
    // A new address deletes the secret bound to it unless it is entered anew in the same save (setDestNote); credentials readable on
    // the wire are warned of (setTlsNote)
    const dest = (id, was, set) => { const sync = () => syncNote(id, id + "-note", !!set && destTxt($("#" + id).value) !== destTxt(was)); $("#" + id).addEventListener("input", sync); sync(); };
    const tls = (box, url) => { const sync = () => syncNote(box, box + "-note", !$("#" + box).checked || /^http:\/\//i.test($("#" + url).value.trim())); $("#" + box).addEventListener("change", sync); $("#" + url).addEventListener("input", sync); sync(); };
    const bindCard = id => {
      if (id === "set-names") {
        dest("s-url", s.opnsense_url, s.opnsense_key_set || s.opnsense_secret_set); tls("s-tls", "s-url");
        $("#s-names").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", "/api/names/refresh"); toast(r.ok ? `${SVLogic.plural(r.entries, "Eintrag", "Einträge")} aus der ARP-Tabelle${r.skipped ? `, ${r.skipped} übersprungen` : ""}` : r.error); MAP = null; } catch (err) { toast(err.message); } e.target.disabled = false; });
      }
      if (id === "set-pf") {
        dest("s-rs", s.radius_server, s.radius_key_set); dest("s-pfu", s.pf_url, s.pf_pass_set); tls("s-pftls", "s-pfu");
        $("#s-pftest").addEventListener("click", async e => { e.target.disabled = true; try { const r = await api("POST", "/api/pf/test"); modal("PacketFence", `<div class="testres"><div><span class="st-dot ${r.ok ? "" : "bad"}"></span><b>${r.ok ? "Verbunden" : "Fehlgeschlagen"}</b> <span class="muted">${esc(r.detail || r.error || "")}</span></div></div><p class="note">Vorher speichern, getestet wird der gespeicherte Stand.</p>`, [{ label: "Schließen", onClick: closeModal }]); } catch (err) { toast(err.message); } e.target.disabled = false; });
      }
      const save = admin && document.getElementById(SAVE[id]);
      if (save) save.addEventListener("click", async e => {
        e.target.disabled = true;
        try {
          const r = await api("PUT", "/api/settings", { ...stored(), ...own[id]() }); toast(savedTxt(r.cleared));
          s = await api("GET", "/api/settings");
          $("#" + id).innerHTML = SCARDS[id](s, admin); bindCard(id); setDirty(id, false);
          const again = document.getElementById(SAVE[id]); if (again) again.focus();
        } catch (err) { toast(err.message); e.target.disabled = false; }
      });
    };
    Object.keys(SCARDS).forEach(bindCard);
    // The SNMPv3 user of PacketFence (PUT /api/settings/pf-snmp): a name or passphrase the switch CLI cannot take is named here, as
    // the server would; saved, s is read again and the card drawn anew, so its fields say what is stored
    const bindSnmp = () => {
      const save = admin && document.getElementById("s-snmp-save");
      if (save) save.addEventListener("click", async e => {
        const name = $("#s-snu").value.trim(), bad = id => { const x = $("#" + id).value; return x !== "" && !/^(?!.*[?~"'\\])[!-~]{8,32}$/.test(x); };
        if (name && !/^[A-Za-z0-9_.-]{1,32}$/.test(name)) { toast("SNMP-Benutzer: 1–32 Zeichen aus Buchstaben, Ziffern, Punkt, Bindestrich und Unterstrich"); return; }
        if (bad("s-sna") || bad("s-snp")) { toast("SNMP-Passwort: 8–32 Zeichen, ohne Leerzeichen, Anführungszeichen, Backslash, ? und ~ (die versteht die Switch-CLI nicht)"); return; }
        e.target.disabled = true;
        try {
          await api("PUT", "/api/settings/pf-snmp", { user: name, auth_pass: pw("s-sna"), priv_pass: pw("s-snp") }); toast("Gespeichert");
          s = await api("GET", "/api/settings"); MAP = null;
          $("#set-snmp").innerHTML = snmpCard(s, admin); bindSnmp(); setDirty("set-snmp", false);
          const again = document.getElementById("s-snmp-save"); if (again) again.focus();
        } catch (err) { toast(err.message); e.target.disabled = false; }
      });
    };
    bindSnmp();
    $("#s-scopes").value = SVLogic.formatScopes(scopes.entries);
    // The zone list as typed: a line it cannot read is named and nothing is sent; saved, the field shows what the server stored
    // (merged, zones sorted)
    if (admin) $("#s-zones-save").addEventListener("click", async e => {
      const r = SVLogic.parseScopes($("#s-scopes").value);
      if (r.errors.length) { toast(r.errors[0]); return; }
      e.target.disabled = true;
      try {
        const saved = await api("PUT", "/api/zone-scopes", { entries: r.entries });
        $("#s-scopes").value = SVLogic.formatScopes(saved.entries);
        // The warning about stored entries the field cannot hold goes once the stored list has none (it said what no longer holds)
        if (lossy.length && !SVLogic.lossyScopes(saved.entries).length) { $("#s-scopes-lossy").hidden = true; $("#s-scopes").setAttribute("aria-describedby", "s-scopes-hint"); }
        toast("Gespeichert"); setDirty("set-zones", false);
      }
      catch (err) { toast(err.message); }
      e.target.disabled = false;
    });
    // The four-eyes principle and the hours of a new request (PUT /api/settings/approvals): hours outside 1-168 are named here (the
    // server's 422 would read in English); saved, ME is read again, so the expert mode, the forms' note and the tab "Freigaben"
    // follow at once
    if (admin) $("#s-4save").addEventListener("click", async e => {
      const hours = Number($("#s-4h").value.trim() || NaN);
      if (!Number.isInteger(hours) || hours < 1 || hours > 168) { toast("Anfragen verfallen nach 1 bis 168 Stunden: bitte eine ganze Zahl eintragen"); return; }
      e.target.disabled = true;
      try { await api("PUT", "/api/settings/approvals", { four_eyes: $("#s-4e").checked, hours }); toast("Gespeichert"); setDirty("set-4e", false); ME = await api("GET", "/api/auth/me"); refreshApprovals(); }
      catch (err) { toast(err.message); }
      e.target.disabled = false;
    });
    // Log out everywhere: every session of this user ends on the server (main.logout_all), this one too, so the login follows
    $("#s-logout-all").addEventListener("click", async e => {
      if (!(await confirmModal("Alle Sitzungen beenden", `Jede Anmeldung von <b>${esc(ME.name)}</b> auf allen Geräten endet, auch diese. Danach meldest du dich neu an.`, "Alle beenden", true))) return;
      e.target.disabled = true;
      try { const r = await api("POST", "/api/auth/logout-all"); toast(r.ended === 1 ? "1 Sitzung beendet" : `${r.ended} Sitzungen beendet`); showLogin(); }
      catch (err) { toast(err.message); e.target.disabled = false; }
    });
    if (admin) ["set-general", "set-names", "set-pf", "set-snmp", "alert-card", "set-zones", "set-4e", "rules-card"].forEach(trackDirty);
    bindSettingsNav();
    bindTokenCards(admin); bindRulesCard(rules); await bindAlertCard(alertSet);
  }
