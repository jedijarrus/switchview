"use strict";

  /* ── Freigaben (Phase 4a, four-eyes principle): the requests of expert-mode changes (GET /api/approvals), their count in the tab,
     withdrawing one's own, asking again for one that ended without running, and the review of someone else's against a fresh
     preview, approved only when it is the requester's (approve starts the change through the guided loop of /apply). The server
     checks every step (api_approvals); the view offers what role, zone and owner allow (roleOk, inZone, own). Since Phase 4c a
     request is also a bulk change (kind bulk_change, isBulk): it has no switch of its own - its sections stand for the one preview
     (bulkSectionsHtml of sv-bulk.js), the server alone checks the zone of each of its switches, and approving opens its run. ── */
  // APPR: the open requests as refreshApprovals read them last; APPR_ST: the text and the pill of each status (approvals.STATUS_LABEL)
  let APPR = [];
  const APPR_ST = { open: ["offen", "warn"], approved: ["freigegeben", "ok"], rejected: ["abgelehnt", "crit"], withdrawn: ["zurückgezogen", "neutral"],
    expired: ["abgelaufen", "neutral"], stale: ["veraltet", "neutral"] };
  const apprPill = a => `<span class="pill ${APPR_ST[a.status] ? APPR_ST[a.status][1] : "neutral"}">${esc(APPR_ST[a.status] ? APPR_ST[a.status][0] : a.status)}</span>`;
  const apprWho = a => esc(a.requester_name || a.requested_by);
  const isBulk = a => a.kind === "bulk_change";
  // The switch of request a as the list and the details name it; a bulk request has several
  const apprWhere = a => isBulk(a) ? "mehrere Switches" : esc(a.switch_name || "–");
  // The switch of request a for a preview and the progress: from the netmap (read when the view was opened directly, #approvals), else
  // by its id and name only; the server answers for a switch it no longer has or has disabled
  async function apprSwitch(a) {
    if (!MAP) await loadMap(false);
    return MAP.switches.find(x => x.id === a.switch_id) || { id: a.switch_id, k: a.switch_name || "Switch", caps: [] };
  }

  // The tab "Freigaben": shown with the four-eyes principle on or while requests are open, its count SVLogic.approvalCount (the
  // requests for this user to review, else its own), named for a screen reader. Asked at every navigation (go), never by timer
  // (T9-a); without a user nothing, an error leaves the tab as it was
  async function refreshApprovals() {
    if (!ME) return;
    try {
      const rows = await api("GET", "/api/approvals?status=open");
      APPR = Array.isArray(rows) ? rows : [];
      const n = SVLogic.approvalCount(APPR, ME), count = $("#appr-n");
      $("#tab-appr").hidden = !(ME.four_eyes || APPR.length);
      count.textContent = String(n); count.hidden = !n;
      $("#tab-appr").setAttribute("aria-label", n ? `Freigaben, ${n} offen` : "Freigaben");
    } catch (e) { /* still: the next navigation asks again */ }
  }

  // The view: the last 100 requests, newest first. "Prüfen" for an open one of someone else at a switch of the reviewer's zones (a
  // bulk request: for every reviewer, the list does not know its zones), "Zurückziehen" for an open one of one's own (with Ändern,
  // the withdraw route's minimum), "Neu anfordern" for one's own that went stale, expired or was rejected (the preview of its
  // stored change; with what its /plan needs), "Details" for every one
  async function renderApprovals() {
    const v = $("#view");
    let rows;
    try { rows = await api("GET", "/api/approvals?status=all&limit=100"); } catch (e) { v.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`; return; }
    const reviewer = roleOk("freigeben");
    // Asking again plans the stored change (/plan): Ändern, the switch's zone and expert mode (expertOk), else the button would end in
    // a 403; a bulk request needs Ändern alone (its preview skips a switch the user may not change, with the reason)
    const again = a => roleOk("aendern") && (isBulk(a) || (expertOk() && inZone({ zone: a.switch_zone })));
    const btns = a => [
      a.status === "open" && !a.own && reviewer && (isBulk(a) || inZone({ zone: a.switch_zone })) ? `<button class="btn small primary" type="button" data-ar="${a.id}">Prüfen</button>` : "",
      a.status === "open" && a.own && roleOk("aendern") ? `<button class="btn small" type="button" data-aw="${a.id}">Zurückziehen</button>` : "",
      a.own && ["stale", "expired", "rejected"].includes(a.status) && again(a) ? `<button class="btn small" type="button" data-an="${a.id}">Neu anfordern</button>` : "",
      `<button class="btn small" type="button" data-ad="${a.id}">Details</button>`].join("");
    const list = rows.length ? `<div class="tbl-wrap"><table><thead><tr><th>#</th><th>Angefordert</th><th>von</th><th>Switch</th><th>Änderung</th><th>Status</th><th></th></tr></thead><tbody>` + rows.map(a =>
      `<tr><td class="num">${a.id}</td><td class="num">${esc(fmtTime(a.requested_at))}</td><td>${apprWho(a)}<span class="cellnote">${esc(SVLogic.roleLabel(a.requester_role))}</span></td><td>${apprWhere(a)}</td>`
      + `<td>${esc(a.summary)}<span class="cellnote">${esc(a.kind_label)}</span></td><td>${apprPill(a)}${a.status === "open" ? `<span class="cellnote">läuft ab ${esc(fmtTime(a.expires_at))}</span>` : ""}</td>`
      + `<td><div class="actions">${btns(a)}</div></td></tr>`).join("") + `</tbody></table></div>` : `<div class="empty">Keine Anfragen.</div>`;
    v.innerHTML = `<section class="card"><div class="card-h"><h2>Freigaben</h2><span class="sub">neueste zuerst · die letzten 100</span></div><div class="card-b" style="display:grid;gap:10px">
      <p class="note" style="margin:0">${ME && ME.four_eyes ? "Vier-Augen-Prinzip an: Änderungen im Expertenmodus werden erst nach der Freigabe durch eine zweite Person mit der Rolle „Freigeben“ ausgeführt."
        : "Vier-Augen-Prinzip aus: offene Anfragen lassen sich weiter prüfen, ablehnen oder zurückziehen."}</p>
      ${reviewer ? "" : `<p class="note gate">Anfragen prüfen und freigeben braucht die Rolle „Freigeben“.</p>`}</div>${list}</section>`;
    v.onclick = async e => {
      const r = e.target.closest("[data-ar]"), w = e.target.closest("[data-aw]"), n = e.target.closest("[data-an]"), d = e.target.closest("[data-ad]");
      if (r) return reviewApproval(+r.dataset.ar);
      if (w) {
        const a = rows.find(x => x.id === +w.dataset.aw);
        if (!a || !(await confirmModal("Anfrage zurückziehen", `Anfrage #${a.id} „${esc(a.summary)}“ zurückziehen? Danach kann sie niemand mehr freigeben.`, "Zurückziehen", true))) return;
        try { await api("POST", `/api/approvals/${a.id}/withdraw`); toast("Zurückgezogen"); } catch (err) { toast(err.message); }
        if (current === "approvals") await renderApprovals();
        refreshApprovals();
        return;
      }
      // The preview of the stored change (exactly what was requested), planned now: with the four-eyes principle on it offers
      // "Freigabe anfordern" again. A bulk request: the bulk preview of its switches with the ports it resolved, the same change
      // and what it did after a failure
      if (n) {
        try {
          const a = await api("GET", `/api/approvals/${n.dataset.an}`), p = a.payload;
          if (isBulk(a)) previewBulk({ targets: p.items.map(i => ({ switch_id: i.switch_id, ports: i.ports })), change: p.change, expert: p.expert }, { onError: p.on_error });
          else previewChange(await apprSwitch(a), p);
        } catch (err) { toast(err.message); }
        return;
      }
      if (d) { try { approvalDetails(await api("GET", `/api/approvals/${d.dataset.ad}`)); } catch (err) { toast(err.message); } }
    };
  }

  // The commands of the preview the requester of a saw, one per line, escaped ("–" without any)
  const apprCmds = a => esc(((a.preview && a.preview.commands) || []).join("\n") || "–");
  // The preview the requester of bulk request a saw: its sections and, where the preview skipped switches, those with their reason
  const apprBulkHtml = a => {
    const skipped = (a.preview && a.preview.skipped) || [];
    return bulkSectionsHtml(a.preview && a.preview.sections) + (skipped.length ? `<div><p class="eyebrow">Übersprungen</p><ul class="blist">`
      + skipped.map(s => `<li>${esc(s.switch)}: ${esc(s.reason)}</li>`).join("") + `</ul></div>` : "");
  };
  // Request a with everything it says: who asked and when, its status (open: until when), who decided, the comment, the reason of a
  // stale one, the change (or the bulk change) an approval started, and the preview its requester saw
  function approvalDetails(a) {
    const decided = ["approved", "rejected", "stale"].includes(a.status) && a.decided_by;
    const kv = [["Angefordert von", `${apprWho(a)} (${esc(SVLogic.roleLabel(a.requester_role))}) · ${esc(fmtTime(a.requested_at))}`],
      ["Status", apprPill(a) + (a.status === "open" ? ` <span class="muted">läuft ab ${esc(fmtTime(a.expires_at))}</span>` : "")],
      ["Prüfer", decided ? esc(a.decided_by) + (a.decided_at ? ` · ${esc(fmtTime(a.decided_at))}` : "") : "–"],
      ["Kommentar", esc(a.comment) || "–"], ["Grund", esc(a.reason) || "–"],
      ["Änderung", a.bulk_id ? `Sammeländerung #${a.bulk_id}` : a.change_id ? `#${a.change_id}` : "–"]];
    modal(`Anfrage #${a.id}`, `<p style="margin:0"><b>${esc(a.summary)}</b> <span class="muted">· ${apprWhere(a)} · ${esc(a.kind_label)}</span></p>
      <dl class="kv">${kv.map(([k, x]) => `<dt>${k}</dt><dd>${x}</dd>`).join("")}</dl>
      <div><p class="eyebrow">Vorschau des Antragstellers</p>${isBulk(a) ? apprBulkHtml(a) : `<pre class="code">${apprCmds(a)}</pre>`}</div>`,
      [{ label: "Schließen", onClick: closeModal }]);
  }

  // The review of request id: the switch read and the change planned now (POST …/preview, the code of /plan), shown like a preview
  // (previewBody) with who asked. "Freigeben und ausführen" only when the fresh preview is the requester's (matches: the same
  // commands, nothing blocked) and not for the emergency login, else the dialog says why (a different preview: with the requester's
  // preview); "Ablehnen" always, both with the optional comment. A fresh preview that fails says why and still offers "Ablehnen" for
  // an open request (rejecting needs no preview; Task 10). After a decision the count, and the list when it is shown, are read
  // again. A dialog closed or replaced while the switch is read opens nothing (modalShown). A bulk request (isBulk): every switch
  // planned now, shown as sections (bulkSectionsHtml, a switch that is no longer the request's marked), approved only when every
  // one matches; then the dialog closes and the run of the bulk change opens (openBulk).
  async function reviewApproval(id) {
    const title = `Anfrage #${id} prüfen`, wait = modal(title, `<div class="empty">Lese die aktuelle Konfiguration …</div>`, []);
    const comment = `<label class="field"><span>Kommentar (optional)</span><textarea id="ap-comment" rows="2" maxlength="500"></textarea></label>`;
    const after = () => { refreshApprovals(); if (current === "approvals") renderApprovals(); };
    let shown = null;
    const reject = { label: "Ablehnen", cls: "danger", onClick: async b => {
      b.disabled = true;
      try { await api("POST", `/api/approvals/${id}/reject`, { comment: $("#ap-comment").value }); if (modalShown(shown)) closeModal(); toast("Abgelehnt"); }
      catch (e) { toast(e.message); b.disabled = false; }
      after();
    } };
    let a, s, r;
    try { a = await api("GET", `/api/approvals/${id}`); s = isBulk(a) ? null : await apprSwitch(a); r = await api("POST", `/api/approvals/${id}/preview`); }
    catch (e) {
      if (!modalShown(wait)) return;
      const open = !!a && a.status === "open";
      shown = modal(title, `<div class="error">${esc(e.message)}</div>` + (open ? comment : ""), [{ label: "Schließen", onClick: closeModal }, ...(open ? [reject] : [])]);
      return;
    }
    if (!modalShown(wait)) return;
    // The emergency login may reject but never approves (a shared account, not a person: api_approvals.EMERGENCY, T7-e)
    const approve = r.matches && !(ME && ME.method === "local");
    const body = `<p class="note" style="margin:0">Angefordert von <b>${apprWho(a)}</b> (${esc(SVLogic.roleLabel(a.requester_role))}) · ${esc(fmtTime(a.requested_at))}</p>`
      + (isBulk(a) ? `<p style="margin:0"><b>${esc(r.summary)}</b> <span class="muted">· ${apprWhere(a)}</span></p>` + bulkSectionsHtml(r.sections, true) : previewBody(s, r, a.payload))
      + (r.matches ? "" : `<div class="error"><b>Freigeben geht nicht:</b> ${isBulk(a) ? "Mindestens ein Switch passt nicht mehr zur Anfrage: er hat sich seit der Anfrage geändert, ist gesperrt oder nicht lesbar."
        : "Der Switch hat sich seit der Anfrage geändert, diese Vorschau weicht von der des Antragstellers ab."} Ablehnen oder neu anfordern lassen.</div>`
        + `<details class="adv"><summary>Vorschau des Antragstellers</summary>${isBulk(a) ? apprBulkHtml(a) : `<pre class="code">${apprCmds(a)}</pre>`}</details>`)
      + (r.matches && !approve ? `<p class="note gate">Der Notfall-Login gibt keine Anfrage frei: er ist kein persönliches Konto.</p>` : "")
      + comment;
    const btns = [{ label: "Abbrechen", onClick: closeModal }, reject];
    if (approve) btns.push({ label: "Freigeben und ausführen", cls: "primary", onClick: async b => {
      b.disabled = true;
      try {
        const res = await api("POST", `/api/approvals/${id}/approve`, { token: r.token, comment: $("#ap-comment").value });
        if (isBulk(a)) { closeModal(); openBulk(res.id); } else runProgress(s, res.id);
      }
      catch (e) { toast(e.message); b.disabled = false; }
      after();
    } });
    shown = modal(title, body, btns);
  }
