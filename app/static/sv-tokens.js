"use strict";

  /* ── API-Tokens (Phase 4c): the settings' cards "API-Tokens" (every role, also Lesen: a read-only token for a monitoring; one's
     own tokens, a new one, "Widerrufen") and "Alle API-Tokens" (Admin only: every token with its user). renderSettings draws the
     shells (tokenCardsHtml) and calls bindTokenCards, which fills both without waiting for them. Each card catches its own errors
     (a failed request shows the server's text in it, a refusal is a message) and draws an answer that is no list as an empty one
     (the stubs of older settings tests answer every other URL with {}). A new token stands once in a dialog and nowhere in the DOM
     afterwards, like a secret field: what is shown once must not hang on in a list. ── */
  // The days a new token is good for (the server takes 1-365); 90 is chosen, auth.TOKEN_DEFAULT_DAYS
  const TOKEN_DAYS = [30, 90, 180, 365];
  const tokenCardsHtml = admin => `<section class="card" id="tok-card"><div class="card-h"><h2>API-Tokens</h2></div><div id="tok-body"><div class="empty">Lade …</div></div></section>`
    + (admin ? `<section class="card" id="tok-all"><div class="card-h"><h2>Alle API-Tokens</h2></div><div id="tok-all-body"><div class="empty">Lade …</div></div></section>` : "");
  // Fills the cards of tokenCardsHtml(admin); the promise of both, for whoever wants to wait (renderSettings does not)
  function bindTokenCards(admin) { return Promise.all([renderTokensInto($("#tok-body")), admin ? renderAllTokensInto($("#tok-all-body")) : null]); }
  // The tokens of list (GET /api/tokens or, all, /api/settings/tokens) as a table: with the user (display name, the username below)
  // for the Admin's list, with the time it was made for one's own; a token without a maximum role has its user's ("wie Benutzer"),
  // one that ran out says so until the hourly prune deletes it. "Widerrufen" carries the id (data-tdel, revokeClicked)
  const tokenTable = (list, all) => `<div class="tbl-wrap"><table><thead><tr>${all ? "<th>Benutzer</th>" : ""}<th>Name</th><th>Höchstrolle</th>${all ? "" : "<th>Angelegt</th>"}`
    + `<th>Läuft ab</th><th>Zuletzt benutzt</th><th></th></tr></thead><tbody>${list.map(t => `<tr>${all ? `<td>${esc(t.display_name || t.username)}<span class="cellnote">${esc(t.username)}</span></td>` : ""}`
      + `<td>${esc(t.name)}</td><td>${t.max_role ? esc(SVLogic.roleLabel(t.max_role)) : `<span class="muted">wie Benutzer</span>`}</td>${all ? "" : `<td class="num time">${esc(fmtTime(t.created_at))}</td>`}`
      + `<td class="num time">${esc(fmtTime(t.expires_at))}${t.expired ? ` <span class="pill warn">abgelaufen</span>` : ""}</td>`
      + `<td class="num time">${t.last_used_at ? esc(fmtTime(t.last_used_at)) : `<span class="muted">nie benutzt</span>`}</td>`
      + `<td><button class="btn small danger" type="button" data-tdel="${esc(t.id)}" aria-label="Widerrufen: ${esc(t.name)}">Widerrufen</button></td></tr>`).join("")}</tbody></table></div>`;
  // "Widerrufen" in either list (e a click in it, list its tokens): asked first, then DELETE /api/tokens/{tid} (one's own, as Admin
  // any; a refusal is a message); both lists are read again either way (an Admin's own token stands in both), and the focus goes to
  // the name of a new token (the button is gone), else to the view
  async function revokeClicked(e, list) {
    const b = e.target.closest("[data-tdel]"), t = b && list.find(x => String(x.id) === b.dataset.tdel);
    if (!t) return;
    if (!(await confirmModal("API-Token widerrufen", `„${esc(t.name)}“ widerrufen? Skripte mit diesem Token werden sofort abgewiesen.`, "Widerrufen", true))) return;
    try { await api("DELETE", `/api/tokens/${encodeURIComponent(t.id)}`); toast("Widerrufen"); } catch (err) { toast(err.message); }
    await bindTokenCards(roleOk("admin"));
    ($("#tk-name") || $("#view")).focus();
  }
  // The card "API-Tokens" into el (#tok-body): one sentence on what a token is, one's own tokens (GET /api/tokens), below them the
  // form of a new one - a name (at most 60 characters), the days (TOKEN_DAYS), a maximum role up to one's own ("wie meine Rolle":
  // none) - and "Token anlegen" (POST /api/tokens, showNewToken). The emergency login only reads why it gets none, without a request
  async function renderTokensInto(el) {
    if (!el) return;
    const box = inner => `<div class="card-b" style="display:grid;gap:12px">${inner}</div>`;
    if (ME && ME.method === "local") { el.innerHTML = box(`<p class="note gate">Der Notfall-Login bekommt keine API-Tokens: er ist kein persönliches Konto.</p>`); return; }
    let got;
    try { got = await api("GET", "/api/tokens"); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    const list = Array.isArray(got) ? got : [], mine = ["lesen", "aendern", "freigeben", "admin"].filter(r => roleOk(r));
    el.innerHTML = box(`<p class="note" style="margin:0">Ein API-Token meldet ein Skript als dich an (<span class="mono">Authorization: Bearer …</span>), mit deiner Rolle oder einer niedrigeren. SwitchView zeigt es nur einmal.</p>`)
      + `<div id="tk-rows">${list.length ? tokenTable(list, false) : `<div class="empty">Noch keine API-Tokens.</div>`}</div>`
      + box(`<fieldset class="fs"><legend>Neues API-Token</legend><div class="grid2"><label class="field"><span>Name</span><input id="tk-name" maxlength="60" autocomplete="off" placeholder="z. B. Monitoring"></label>`
        + `<label class="field"><span>Gültig</span><select id="tk-days">${TOKEN_DAYS.map(d => `<option value="${d}"${d === 90 ? " selected" : ""}>${d} Tage</option>`).join("")}</select></label></div>`
        + `<div class="grid2"><label class="field"><span>Höchstrolle</span><select id="tk-role"><option value="">wie meine Rolle</option>${mine.map(r => `<option value="${r}">${esc(SVLogic.roleLabel(r))}</option>`).join("")}</select></label></div>`
        + `<div><button class="btn primary" type="button" id="tk-create">Token anlegen</button></div></fieldset>`);
    $("#tk-rows").addEventListener("click", e => revokeClicked(e, list));
    $("#tk-create").addEventListener("click", async e => {
      const name = $("#tk-name").value.trim();
      if (!name) { toast("Bitte einen Namen eintragen"); $("#tk-name").focus(); return; }
      e.target.disabled = true;
      try { showNewToken(await api("POST", "/api/tokens", { name, days: Number($("#tk-days").value), max_role: $("#tk-role").value || null })); }
      catch (err) { toast(err.message); }
      e.target.disabled = false;
    });
  }
  // The card "Alle API-Tokens" into el (#tok-all-body, Admin): every token with its user (GET /api/settings/tokens), each revocable
  async function renderAllTokensInto(el) {
    if (!el) return;
    let got;
    try { got = await api("GET", "/api/settings/tokens"); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
    const list = Array.isArray(got) ? got : [];
    el.innerHTML = `<div id="tka-rows">${list.length ? tokenTable(list, true) : `<div class="empty">Keine API-Tokens.</div>`}</div>`;
    $("#tka-rows").addEventListener("click", e => revokeClicked(e, list));
  }
  // A new token t (the answer of POST /api/tokens) in a dialog, the one place it ever stands: "Kopieren" puts it on the clipboard
  // (navigator.clipboard needs HTTPS; without it the hint to mark it), "Fertig" empties and closes the dialog, reads the lists again
  // (the new token in them, without itself) and gives the focus back to "Token anlegen"
  function showNewToken(t) {
    const copy = async () => {
      try { await navigator.clipboard.writeText(t.token); toast("Kopiert"); } catch (e) { toast("Kopieren ging nicht – bitte markieren und kopieren"); }
    };
    const done = async () => {
      $("#m-body").innerHTML = ""; closeModal();
      await bindTokenCards(roleOk("admin"));
      const again = $("#tk-create"); if (again) again.focus();
    };
    modal("Neues API-Token", `<p class="note warn">Nur jetzt sichtbar: kopieren und sicher ablegen. SwitchView zeigt es nie wieder.</p><pre class="code" id="tk-value">${esc(t.token)}</pre>`,
      [{ label: "Kopieren", onClick: copy }, { label: "Fertig", cls: "primary", onClick: done }]);
  }
