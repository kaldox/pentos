// PentOS Console — Frontend (vanilla JS, offline, kein CDN).
const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR = {
  critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
  low: "var(--low)", info: "var(--info)",
};
const state = { project: null, view: "overview" };

const $ = (s, r = document) => r.querySelector(s);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html != null) e.innerHTML = html;
  return e;
};
const esc = (s) => (s == null ? "" : String(s).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])));

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${r.status} ${path}`);
  return r.json();
}

async function apiPost(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch (e) { /* ignore */ }
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return r.json();
}

let STATUSES = ["Zu verifizieren", "Bestätigt", "Ausgenutzt", "False Positive", "Geschlossen"];

// ── Boot ───────────────────────────────────────────────────────────────
async function boot() {
  try {
    const { projects, active } = await api("/api/projects");
    try { STATUSES = (await api("/api/meta")).statuses || STATUSES; } catch (e) { /* ok */ }
    const sel = $("#project-select");
    sel.innerHTML = "";
    projects.forEach((p) => {
      const o = el("option"); o.value = p; o.textContent = p;
      sel.appendChild(o);
    });
    state.project = active && projects.includes(active) ? active : projects[0];
    if (state.project) sel.value = state.project;
    sel.onchange = () => { state.project = sel.value; render(); };
    document.querySelectorAll(".nav-item").forEach((b) => {
      b.onclick = () => {
        document.querySelectorAll(".nav-item").forEach((x) => x.classList.remove("active"));
        b.classList.add("active");
        state.view = b.dataset.view;
        $("#view-title").textContent = b.textContent.trim();
        render();
      };
    });
    if (!state.project) { $("#content").innerHTML = emptyState("Kein Projekt", "Lege eins mit <code>pentos project new</code> an."); return; }
    render();
  } catch (e) {
    $("#conn").textContent = "offline";
    $("#content").innerHTML = emptyState("Backend nicht erreichbar", esc(e.message));
  }
}

function emptyState(title, sub) {
  return `<div class="empty"><b>${title}</b>${sub || ""}</div>`;
}

// ── Render-Dispatch ────────────────────────────────────────────────────
async function render() {
  $("#proj-name").textContent = state.project || "—";
  const c = $("#content");
  c.innerHTML = `<div class="loading">Lade …</div>`;
  try {
    if (state.view === "overview") return renderOverview(c);
    if (state.view === "findings") return renderFindings(c);
    if (state.view === "hosts") return renderHosts(c);
    if (state.view === "graph") return renderGraph(c);
    if (state.view === "loot") return renderLoot(c);
    if (state.view === "notes") return renderNotes(c);
  } catch (e) {
    c.innerHTML = emptyState("Fehler beim Laden", esc(e.message));
  }
}

// ── Lagebild ───────────────────────────────────────────────────────────
async function renderOverview(c) {
  const s = await api(`/api/project/${encodeURIComponent(state.project)}/summary`);
  const k = s.counts;
  const cards = [
    ["Hosts", k.hosts, ""],
    ["Dienste", k.services, ""],
    ["Findings", k.findings, ""],
    ["Loot", k.loot, ""],
    ["Aufgaben", `${k.tasks_done}/${k.tasks_total}`, "erledigt"],
  ].map(([l, v, sub]) => `
    <div class="card stat">
      <div class="stat-label">${l}</div>
      <div class="stat-val">${v}</div>
      <div class="stat-sub">${sub}</div>
    </div>`).join("");

  const total = SEV.reduce((a, x) => a + (s.severity[capitalize(x)] || 0), 0);
  const donut = donutSVG(s.severity);
  const legend = SEV.map((x) => {
    const n = s.severity[capitalize(x)] || 0;
    return `<div class="legend-row">
      <span class="sw" style="background:${SEV_COLOR[x]}"></span>
      <span class="lg-name">${x}</span><span class="lg-count">${n}</span></div>`;
  }).join("");

  const feed = (s.activity || []).map((a) => `
    <div class="feed-item">
      <span class="feed-tick">${esc((a.at || "").slice(5, 16))}</span>
      <span class="feed-body"><span class="fa">${esc(a.action)}</span>
        ${a.detail ? `<div class="fd">${esc(a.detail)}</div>` : ""}</span>
    </div>`).join("") || `<div class="fd" style="color:var(--muted)">Noch keine Aktivität.</div>`;

  c.innerHTML = `
    <div class="stat-grid">${cards}</div>
    <div class="grid-2">
      <div class="card">
        <div class="panel-h"><h2>Severity-Verteilung</h2><span class="mono" style="color:var(--muted)">${total}</span></div>
        <div class="donut-wrap">${donut}<div class="legend">${legend}</div></div>
      </div>
      <div class="card">
        <div class="panel-h"><h2>Letzte Aktivität</h2></div>
        <div class="feed">${feed}</div>
      </div>
    </div>`;
}

function donutSVG(sevObj) {
  const segs = SEV.map((x) => ({ key: x, val: sevObj[capitalize(x)] || 0 }));
  const total = segs.reduce((a, s) => a + s.val, 0);
  const R = 58, C = 2 * Math.PI * R, cx = 74, cy = 74;
  if (total === 0) {
    return `<svg class="donut" viewBox="0 0 148 148">
      <circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="var(--line)" stroke-width="16"/>
      <text x="${cx}" y="${cy + 5}" text-anchor="middle" fill="var(--muted)" font-size="13" font-family="var(--mono)">leer</text></svg>`;
  }
  let off = 0, arcs = "";
  segs.forEach((s) => {
    if (!s.val) return;
    const len = (s.val / total) * C;
    arcs += `<circle cx="${cx}" cy="${cy}" r="${R}" fill="none"
      stroke="${SEV_COLOR[s.key]}" stroke-width="16"
      stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}"
      transform="rotate(-90 ${cx} ${cy})"/>`;
    off += len;
  });
  return `<svg class="donut" viewBox="0 0 148 148">
    <circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="var(--line)" stroke-width="16"/>
    ${arcs}
    <text x="${cx}" y="${cy - 2}" text-anchor="middle" fill="var(--text)" font-size="26" font-weight="700" font-family="var(--mono)">${total}</text>
    <text x="${cx}" y="${cy + 16}" text-anchor="middle" fill="var(--muted)" font-size="10" letter-spacing="1.5">FINDINGS</text>
  </svg>`;
}

// ── Findings ───────────────────────────────────────────────────────────
let _findings = [], _filter = "all";
async function renderFindings(c) {
  const { findings } = await api(`/api/project/${encodeURIComponent(state.project)}/findings`);
  _findings = findings;
  const chips = ["all", ...SEV].map((f) =>
    `<button class="chip ${_filter === f ? "active" : ""}" data-f="${f}">${f === "all" ? "Alle" : f}</button>`).join("");
  c.innerHTML = `<div class="filters">${chips}</div><div id="ftable"></div>`;
  c.querySelectorAll(".chip").forEach((ch) => ch.onclick = () => {
    _filter = ch.dataset.f;
    c.querySelectorAll(".chip").forEach((x) => x.classList.toggle("active", x === ch));
    drawFindings();
  });
  drawFindings();
}
function drawFindings() {
  const list = _findings.filter((f) => _filter === "all" || f.severity.toLowerCase() === _filter);
  const rows = list.map((f) => {
    const cvss = f.cvss_score != null ? `<span class="mono">${f.cvss_score}</span>` : "<span style='color:var(--faint)'>—</span>";
    const opts = STATUSES.map((s) => `<option value="${esc(s)}"${s === f.status ? " selected" : ""}>${esc(s)}</option>`).join("");
    return `<tr>
      <td><span class="badge sev-${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
      <td><a class="f-link" data-id="${f.id}">${esc(f.title)}</a>${f.description ? `<div style="color:var(--muted);font-size:12.5px;margin-top:3px">${esc(f.description).slice(0, 160)}</div>` : ""}</td>
      <td>${esc(f.category)}</td>
      <td><select class="status-sel" data-id="${f.id}">${opts}</select></td>
      <td>${cvss}</td>
    </tr>`;
  }).join("");
  $("#ftable").innerHTML = rows
    ? `<table class="tbl"><thead><tr><th>Severity</th><th>Titel</th><th>Kategorie</th><th>Status</th><th>CVSS</th></tr></thead><tbody>${rows}</tbody></table>`
    : emptyState("Keine Findings", "in dieser Auswahl.");
  // Status-Änderung speichern (optimistic)
  $("#ftable").querySelectorAll(".status-sel").forEach((sel) => {
    sel.onchange = async () => {
      const id = +sel.dataset.id, val = sel.value, prev = sel.dataset.prev || "";
      sel.disabled = true;
      try {
        await apiPost(`/api/project/${encodeURIComponent(state.project)}/finding/${id}/status`, { status: val });
        const f = _findings.find((x) => x.id === id);
        if (f) f.status = val;
        flash(sel, "ok");
      } catch (e) {
        flash(sel, "err");
        if (prev) sel.value = prev;
        alert("Speichern fehlgeschlagen: " + e.message);
      } finally {
        sel.disabled = false;
        sel.dataset.prev = sel.value;
      }
    };
    sel.dataset.prev = sel.value;
  });
  $("#ftable").querySelectorAll(".f-link").forEach((a) => {
    a.onclick = () => openFindingDetail(+a.dataset.id);
  });
}

function flash(el, kind) {
  el.style.transition = "box-shadow .2s";
  el.style.boxShadow = kind === "ok" ? "0 0 0 2px var(--brand)" : "0 0 0 2px var(--crit)";
  setTimeout(() => { el.style.boxShadow = "none"; }, 700);
}

// ── Hosts ──────────────────────────────────────────────────────────────
async function renderHosts(c) {
  const { hosts } = await api(`/api/project/${encodeURIComponent(state.project)}/hosts`);
  if (!hosts.length) { c.innerHTML = emptyState("Keine Hosts", "Scanne ein Ziel mit <code>pentos sweep</code>."); return; }
  c.innerHTML = hosts.map((h) => {
    const ports = h.services.map((s) => `
      <div class="port"><span class="pn">${s.port}/${esc(s.protocol)}</span>
      <span class="ps">${esc(s.name || "")} ${esc(s.product || "")} ${esc(s.version || "")}</span></div>`).join("")
      || `<div class="ps" style="color:var(--muted);padding:4px 4px">keine Dienste erfasst</div>`;
    return `<div class="host-card">
      <div class="host-head">
        <span class="host-ip">${esc(h.address)}</span>
        <span class="host-meta">${esc(h.hostname || "")} ${h.os_guess ? "· " + esc(h.os_guess) : ""}</span>
        <span class="host-status">${esc(h.status || "")}</span>
      </div>
      <div class="ports">${ports}</div>
    </div>`;
  }).join("");
}

// ── Loot ───────────────────────────────────────────────────────────────
async function renderLoot(c) {
  const { loot } = await api(`/api/project/${encodeURIComponent(state.project)}/loot`);
  if (!loot.length) { c.innerHTML = emptyState("Kein Loot", "Erfasse Funde mit <code>pentos loot add</code>."); return; }
  const rows = loot.map((l) => `<tr>
    <td><span class="badge" style="color:var(--brand);background:rgba(45,212,191,.1)">${esc(l.type)}</span></td>
    <td>${esc(l.label)}</td>
    <td class="mono">${esc(l.value || "")}</td>
    <td>${esc(l.source || "")}</td></tr>`).join("");
  c.innerHTML = `<table class="tbl"><thead><tr><th>Typ</th><th>Label</th><th>Wert</th><th>Quelle</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ── Notizen ────────────────────────────────────────────────────────────
async function renderNotes(c) {
  const { notes } = await api(`/api/project/${encodeURIComponent(state.project)}/notes`);
  const form = `<div class="note-form card">
    <input id="nf-title" placeholder="Titel der Notiz" />
    <textarea id="nf-body" placeholder="Inhalt …" rows="3"></textarea>
    <div class="nf-row">
      <input id="nf-cat" placeholder="Kategorie (optional)" />
      <button id="nf-save" class="btn">Notiz speichern</button>
    </div>
  </div>`;
  const list = notes.length
    ? notes.map((n) => `<div class="note-card">
        <h3>${esc(n.title)}</h3>
        <div class="nmeta">${esc(n.category || "—")} · ${esc(n.created_at || "")}</div>
        <pre>${esc(n.body || "")}</pre></div>`).join("")
    : `<div class="empty"><b>Noch keine Notizen</b>Leg oben die erste an.</div>`;
  c.innerHTML = form + list;
  $("#nf-save").onclick = async () => {
    const title = $("#nf-title").value.trim();
    if (!title) { $("#nf-title").focus(); return; }
    const btn = $("#nf-save"); btn.disabled = true; btn.textContent = "Speichere …";
    try {
      await apiPost(`/api/project/${encodeURIComponent(state.project)}/notes`, {
        title, body: $("#nf-body").value, category: $("#nf-cat").value.trim() || null,
      });
      renderNotes(c);  // neu laden
    } catch (e) {
      alert("Speichern fehlgeschlagen: " + e.message);
      btn.disabled = false; btn.textContent = "Notiz speichern";
    }
  };
}

// ── Finding-Detail (Drawer mit Status-Historie) ────────────────────────
async function openFindingDetail(fid) {
  const drawer = $("#drawer"), panel = $("#drawer-panel");
  drawer.hidden = false;
  panel.innerHTML = `<div class="loading">Lade …</div>`;
  $("#drawer-back").onclick = closeDrawer;
  document.onkeydown = (e) => { if (e.key === "Escape") closeDrawer(); };
  let d;
  try {
    d = await api(`/api/project/${encodeURIComponent(state.project)}/finding/${fid}`);
  } catch (e) { panel.innerHTML = emptyState("Fehler", esc(e.message)); return; }

  const timeline = (d.history || []).map((h) => {
    const arrow = h.old ? `${esc(h.old)} → <b>${esc(h.new)}</b>` : `<b>${esc(h.new)}</b>`;
    return `<div class="tl-item">
      <span class="tl-dot"></span>
      <div class="tl-body">
        <div class="tl-head"><span class="tl-arrow">${arrow}</span>
          <span class="tl-ts mono">${esc((h.ts || "").slice(0, 16))}</span></div>
        ${h.note ? `<div class="tl-note">${esc(h.note)}</div>` : ""}
      </div></div>`;
  }).join("") || `<div class="fd" style="color:var(--muted)">Keine Historie.</div>`;

  const ev = (d.evidence || []).map((e) =>
    `<div class="ev-row"><span class="badge">${esc(e.kind)}</span> ${esc(e.description || e.path)}</div>`
  ).join("") || `<div class="fd" style="color:var(--muted)">Keine Belege.</div>`;

  const cvss = d.cvss_score != null
    ? `<span class="mono">${d.cvss_score}</span>${d.cvss_vector ? ` <span style="color:var(--muted)">${esc(d.cvss_vector)}</span>` : ""}`
    : "—";
  const opts = STATUSES.map((s) => `<option value="${esc(s)}"${s === d.status ? " selected" : ""}>${esc(s)}</option>`).join("");

  panel.innerHTML = `
    <div class="dr-head">
      <span class="badge sev-${d.severity.toLowerCase()}">${esc(d.severity)}</span>
      <button class="dr-close" id="dr-x">✕</button>
    </div>
    <h2 class="dr-title">${esc(d.title)}</h2>
    <div class="dr-meta">
      <span>${esc(d.category)}</span>${d.location ? ` · <span class="mono">${esc(d.location)}</span>` : ""}
      · <span>${d.auto ? "automatisch" : "manuell"}</span> · CVSS ${cvss}
    </div>
    ${d.description ? `<p class="dr-desc">${esc(d.description)}</p>` : ""}
    ${d.remediation ? `<div class="dr-rem"><b>Remediation</b><p>${esc(d.remediation)}</p></div>` : ""}

    <div class="dr-section"><h3>Status ändern</h3>
      <div class="dr-status">
        <select id="dr-status">${opts}</select>
        <input id="dr-note" placeholder="Notiz (z.B. 'Retest ok, gefixt')" />
        <button id="dr-save" class="btn">Setzen</button>
      </div>
    </div>

    <div class="dr-section"><h3>Status-Verlauf</h3><div class="timeline">${timeline}</div></div>
    <div class="dr-section"><h3>Belege</h3>${ev}</div>`;

  $("#dr-x").onclick = closeDrawer;
  $("#dr-save").onclick = async () => {
    const status = $("#dr-status").value, note = $("#dr-note").value.trim();
    const btn = $("#dr-save"); btn.disabled = true; btn.textContent = "…";
    try {
      await apiPost(`/api/project/${encodeURIComponent(state.project)}/finding/${fid}/status`,
        { status, note: note || null });
      openFindingDetail(fid);           // neu laden -> Timeline aktualisiert
      const f = _findings.find((x) => x.id === fid); if (f) f.status = status;
    } catch (e) {
      alert("Speichern fehlgeschlagen: " + e.message);
      btn.disabled = false; btn.textContent = "Setzen";
    }
  };
}
function closeDrawer() {
  $("#drawer").hidden = true;
  document.onkeydown = null;
  if (state.view === "findings") render();   // Tabelle ggf. mit neuem Status
}

// ── Angriffspfad (SVG, drei Spalten: Host -> Dienst -> Finding) ─────────
async function renderGraph(c) {
  const g = await api(`/api/project/${encodeURIComponent(state.project)}/graph`);
  if (!g.hosts.length && !g.findings.length) {
    c.innerHTML = emptyState("Kein Angriffspfad", "Scanne ein Ziel und erfasse Findings."); return;
  }
  // Spalten-Layout
  const COLX = { host: 90, svc: 360, find: 660 };
  const rowH = 34, padY = 40;
  const nodes = {}; const lines = [];
  let y = { host: padY, svc: padY, find: padY };

  const hostY = {}, svcY = {};
  g.hosts.forEach((h) => { hostY[h.id] = y.host; y.host += rowH * Math.max(1, countChildren(g, h.id)); });
  function countChildren(g, hid) {
    const svc = g.services.filter((s) => s.host_id === hid).length;
    const fh = g.findings.filter((f) => f.host_id === hid && !f.service_id).length;
    return Math.max(1, svc + fh);
  }
  g.services.forEach((s) => { svcY[s.id] = y.svc; y.svc += rowH; });
  const findY = {};
  g.findings.forEach((f) => { findY[f.id] = y.find; y.find += rowH; });

  const W = 860, H = Math.max(y.host, y.svc, y.find) + padY;
  let svg = `<svg viewBox="0 0 ${W} ${H}" class="apgraph" preserveAspectRatio="xMidYMin meet">`;
  // Kanten host->svc
  g.services.forEach((s) => {
    if (hostY[s.host_id] == null) return;
    svg += edge(COLX.host + 120, hostY[s.host_id] + 11, COLX.svc, svcY[s.id] + 11);
  });
  // Kanten svc/host -> finding
  g.findings.forEach((f) => {
    if (f.service_id != null && svcY[f.service_id] != null)
      svg += edge(COLX.svc + 150, svcY[f.service_id] + 11, COLX.find, findY[f.id] + 11);
    else if (f.host_id != null && hostY[f.host_id] != null)
      svg += edge(COLX.host + 120, hostY[f.host_id] + 11, COLX.find, findY[f.id] + 11, true);
  });
  // Knoten
  g.hosts.forEach((h) => {
    svg += node(COLX.host, hostY[h.id], 120, esc(h.label), "g-host");
  });
  g.services.forEach((s) => {
    svg += node(COLX.svc, svcY[s.id], 150, esc(s.label), "g-svc");
  });
  g.findings.forEach((f) => {
    svg += node(COLX.find, findY[f.id], 190, esc(f.title), "g-find",
      SEV_COLOR[f.severity.toLowerCase()] || "var(--line)", f.id);
  });
  svg += `</svg>`;

  c.innerHTML = `<div class="ap-legend">
      <span><span class="sw" style="background:var(--brand)"></span>Host</span>
      <span><span class="sw" style="background:var(--med)"></span>Dienst</span>
      <span><span class="sw" style="background:var(--high)"></span>Finding (Severity-Farbe)</span>
      <span style="color:var(--muted)">· Finding anklicken für Details</span>
    </div>
    <div class="ap-scroll">${svg}</div>`;
  c.querySelectorAll("[data-fid]").forEach((n) =>
    n.addEventListener("click", () => openFindingDetail(+n.dataset.fid)));

  function edge(x1, y1, x2, y2, dashed) {
    const mx = (x1 + x2) / 2;
    return `<path d="M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}"
      fill="none" stroke="var(--line)" stroke-width="1.5"${dashed ? ' stroke-dasharray="4 3"' : ""}/>`;
  }
  function node(x, yy, w, label, cls, accent, fid) {
    const click = fid != null ? ` class="g-node ${cls}" data-fid="${fid}" style="cursor:pointer"` : ` class="g-node ${cls}"`;
    const bar = accent ? `<rect x="${x}" y="${yy}" width="4" height="22" rx="2" fill="${accent}"/>` : "";
    const tx = accent ? x + 12 : x + 10;
    return `<g${click}>
      <rect x="${x}" y="${yy}" width="${w}" height="22" rx="5" fill="var(--surface-2)" stroke="var(--line)"/>
      ${bar}
      <text x="${tx}" y="${yy + 15}" font-size="11.5" fill="var(--text)">${clip(label, w - 18)}</text>
    </g>`;
  }
  function clip(s, px) { const max = Math.floor(px / 6.2); return s.length > max ? s.slice(0, max - 1) + "…" : s; }
}



const capitalize = (s) => s.charAt(0).toUpperCase() + s.slice(1);
boot();
