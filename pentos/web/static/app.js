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

// ── Boot ───────────────────────────────────────────────────────────────
async function boot() {
  try {
    const { projects, active } = await api("/api/projects");
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
  const rows = _findings
    .filter((f) => _filter === "all" || f.severity.toLowerCase() === _filter)
    .map((f) => {
      const cvss = f.cvss_score != null ? `<span class="mono">${f.cvss_score}</span>` : "<span style='color:var(--faint)'>—</span>";
      return `<tr>
        <td><span class="badge sev-${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
        <td>${esc(f.title)}${f.description ? `<div style="color:var(--muted);font-size:12.5px;margin-top:3px">${esc(f.description).slice(0, 160)}</div>` : ""}</td>
        <td>${esc(f.category)}</td>
        <td>${esc(f.status)}</td>
        <td>${cvss}</td>
      </tr>`;
    }).join("");
  $("#ftable").innerHTML = rows
    ? `<table class="tbl"><thead><tr><th>Severity</th><th>Titel</th><th>Kategorie</th><th>Status</th><th>CVSS</th></tr></thead><tbody>${rows}</tbody></table>`
    : emptyState("Keine Findings", "in dieser Auswahl.");
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
  if (!notes.length) { c.innerHTML = emptyState("Keine Notizen", "Halte was fest mit <code>pentos note add</code>."); return; }
  c.innerHTML = notes.map((n) => `<div class="note-card">
    <h3>${esc(n.title)}</h3>
    <div class="nmeta">${esc(n.category || "—")} · ${esc(n.created_at || "")}</div>
    <pre>${esc(n.body || "")}</pre></div>`).join("");
}

const capitalize = (s) => s.charAt(0).toUpperCase() + s.slice(1);
boot();
