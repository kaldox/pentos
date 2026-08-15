"""
Export für PentOS: gebrandete HTML- und PDF-Reports.

- HTML: abhängigkeitsfrei (reines Templating), im Browser druck-/PDF-fähig.
- PDF: via reportlab (optionale Dependency, pure Python – läuft auf jeder Kali).

Beide nutzen dieselben Projektdaten (Findings, Hosts/Services, Loot, Aufgaben).
Branding (Firmenname/Farbe) kommt aus der Config (report-Block) mit Defaults.

"""
from __future__ import annotations

import base64
import html as _html
import mimetypes
from pathlib import Path

from .models import SEVERITY_ORDER, Severity, TaskStatus, TimelineKind, _now
from .repository import Repository
from .risk import compute_risk

_IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
_SEV_COLOR_MAP = {
    Severity.CRITICAL: "#c0392b", Severity.HIGH: "#e67e22",
    Severity.MEDIUM: "#f1c40f", Severity.LOW: "#3498db", Severity.INFO: "#95a5a6",
}
_TIMELINE_LABEL = {
    TimelineKind.MILESTONE: "Meilenstein", TimelineKind.WINDOW: "Zeitfenster", TimelineKind.BLACKOUT: "Blackout",
}


def _donut_svg(sev_count: dict, size: int = 148) -> str:
    """Reines, abhängigkeitsfreies SVG-Donut-Chart (kein CDN, kein JS) --
    dasselbe Prinzip wie donutSVG() im Web-Dashboard (app.js), nur als
    Python-String für den statischen Report."""
    import math
    r, cx, cy = size * 0.39, size / 2, size / 2
    circumference = 2 * math.pi * r
    total = sum(sev_count.values())
    if total == 0:
        return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e5e7eb" stroke-width="16"/>'
                f'<text x="{cx}" y="{cy+5}" text-anchor="middle" fill="#9ca3af" font-size="12">keine</text></svg>')
    arcs, offset = [], 0.0
    for sev in Severity:
        val = sev_count.get(sev, 0)
        if not val:
            continue
        length = (val / total) * circumference
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{_SEV_COLOR_MAP[sev]}" '
            f'stroke-width="16" stroke-dasharray="{length:.2f} {circumference - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += length
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e5e7eb" stroke-width="16"/>'
        f'{"".join(arcs)}'
        f'<text x="{cx}" y="{cy-2}" text-anchor="middle" fill="#1f2937" font-size="24" font-weight="700">{total}</text>'
        f'<text x="{cx}" y="{cy+15}" text-anchor="middle" fill="#9ca3af" font-size="9" letter-spacing="1">FINDINGS</text>'
        f'</svg>'
    )


def _pdf_severity_pie(sev_count: dict, colors_mod, drawing_cls, pie_cls, size: float = 100):
    """Reportlab-natives Pie-Chart (reportlab.graphics) für die Severity-
    Verteilung im PDF -- keine zusätzliche Abhängigkeit, reportlab ist für
    den PDF-Export ohnehin Pflicht. None, wenn keine Findings vorhanden sind."""
    data, sev_colors = [], []
    for s in Severity:
        v = sev_count.get(s, 0)
        if v:
            data.append(v)
            sev_colors.append(colors_mod.HexColor(_SEV_COLOR_MAP[s]))
    if not data:
        return None
    d = drawing_cls(size, size)
    pie = pie_cls()
    pie.x = 2
    pie.y = 2
    pie.width = size - 4
    pie.height = size - 4
    pie.data = data
    pie.labels = None
    pie.sideLabels = False
    for i, c in enumerate(sev_colors):
        pie.slices[i].fillColor = c
        pie.slices[i].strokeColor = colors_mod.white
        pie.slices[i].strokeWidth = 1
    d.add(pie)
    return d


def _is_image(ev) -> bool:
    """Evidence als Bild behandeln? (kind=screenshot oder Bild-Endung)"""
    if (ev.kind or "").lower() == "screenshot":
        return True
    return Path(ev.path or "").suffix.lower() in _IMG_EXT


def _evidence_by_finding(repo: Repository) -> dict[int, list]:
    """Gruppiert Evidence nach finding_id (nur das, was einem Finding zugeordnet ist)."""
    out: dict[int, list] = {}
    for ev in repo.list_evidence():
        if ev.finding_id:
            out.setdefault(ev.finding_id, []).append(ev)
    return out


def _img_data_uri(path: str) -> str | None:
    """Liest ein Bild und gibt es als base64 data:-URI zurück (self-contained HTML)."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    if p.stat().st_size > 4 * 1024 * 1024:   # >4 MB nicht inlinen
        return None
    mime = mimetypes.guess_type(str(p))[0] or "image/png"
    try:
        data = base64.b64encode(p.read_bytes()).decode("ascii")
    except OSError:
        return None
    return f"data:{mime};base64,{data}"

# Severity-Farben (für HTML-Badges und PDF)
_SEV_COLOR = {
    Severity.CRITICAL: "#7c1d1d",
    Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#b45309",
    Severity.LOW: "#1d4ed8",
    Severity.INFO: "#374151",
}


def _branding(cfg: dict | None) -> dict:
    rep = (cfg or {}).get("report", {}) if isinstance(cfg, dict) else {}
    return {
        "company": rep.get("company", ""),
        "color": rep.get("color", "#0f766e"),
        "author": rep.get("author", ""),
    }


def _collect(repo: Repository) -> dict:
    hosts = repo.list_hosts()
    services = repo.list_services()
    findings = sorted(repo.list_findings(), key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    tasks = repo.list_tasks()
    loot = repo.list_loot()
    sev_count = {s: 0 for s in Severity}
    for f in findings:
        sev_count[f.severity] += 1
    done = sum(1 for t in tasks if t.status == TaskStatus.DONE)
    return {
        "hosts": hosts, "services": services, "findings": findings,
        "tasks": tasks, "loot": loot, "sev_count": sev_count, "done": done,
        "evidence_by_finding": _evidence_by_finding(repo),
        "history_by_finding": _history_by_finding(repo, findings),
        "risk": compute_risk(findings),
        "timeline": repo.list_timeline_entries(),
    }


def _history_by_finding(repo: Repository, findings: list) -> dict[int, list]:
    """Status-Verlauf je Finding, nur echte Wechsel (Ersteintrag mit
    old_status=None wird wie im Markdown-Report nicht mit ausgegeben)."""
    out: dict[int, list] = {}
    for f in findings:
        if not f.id:
            continue
        changes = [h for h in repo.finding_history(f.id) if h.old_status is not None]
        if changes:
            out[f.id] = changes
    return out


def _loc(repo: Repository, f) -> str:
    if f.service_id:
        s = repo.get_service(f.service_id)
        if s:
            h = repo.get_host(s.host_id)
            return f"{h.address if h else ''}:{s.port}/{s.protocol}"
    if f.host_id:
        h = repo.get_host(f.host_id)
        if h:
            return h.address
    return ""


# ── HTML ──────────────────────────────────────────────────────────────────────
def build_html(repo: Repository, project: str, cfg: dict | None = None) -> str:
    b = _branding(cfg)
    d = _collect(repo)
    e = _html.escape

    sev_chips = " ".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s]}">{s.value}: {d["sev_count"][s]}</span>'
        for s in Severity if d["sev_count"][s] > 0
    ) or '<span class="muted">keine</span>'

    rows_find = []
    for f in d["findings"]:
        loc = _loc(repo, f)
        cvss = ""
        if f.cvss_score is not None:
            vec = f" · {e(f.cvss_vector)}" if f.cvss_vector else ""
            cvss = f' · CVSS {f.cvss_score}{vec}'
        remediation = (f'<p class="remediation"><strong>Remediation:</strong> '
                       f'{e(f.remediation)}</p>') if f.remediation else ""
        loc_html = f' <span class="muted">— {e(loc)}</span>' if loc else ""
        # Status-Verlauf (Retest-Tracking), wie im Markdown-Report
        hist_html = ""
        changes = d["history_by_finding"].get(f.id, [])
        if changes:
            items = "".join(
                f'<li><code>{e(h.ts)}</code> {e(h.old_status)} → {e(h.new_status)}'
                f'{f" — {e(h.note)}" if h.note else ""}</li>'
                for h in changes
            )
            hist_html = f'<div class="history"><strong>Status-Verlauf:</strong><ul>{items}</ul></div>'
        # Evidence einbetten: Bilder inline (base64), übrige als Liste
        ev_html = ""
        evs = d["evidence_by_finding"].get(f.id, [])
        if evs:
            parts = ['<div class="evidence"><strong>Belege:</strong>']
            for ev in evs:
                cap = e(ev.description or Path(ev.path).name)
                if _is_image(ev):
                    uri = _img_data_uri(ev.path)
                    if uri:
                        parts.append(f'<figure><img src="{uri}" alt="{cap}"/>'
                                     f'<figcaption>{cap}</figcaption></figure>')
                    else:
                        parts.append(f'<div class="ev-file">🖼️ {cap} '
                                     f'<span class="muted">({e(ev.path)})</span></div>')
                else:
                    parts.append(f'<div class="ev-file">📄 {cap} '
                                 f'<span class="muted">[{e(ev.kind)}] {e(ev.path)}</span></div>')
            parts.append('</div>')
            ev_html = "".join(parts)
        rows_find.append(
            f'<div class="finding">'
            f'<div class="fhead"><span class="badge" style="background:{_SEV_COLOR[f.severity]}">{e(f.severity.value)}</span>'
            f'<strong>{e(f.title)}</strong>{loc_html}</div>'
            f'<div class="meta">Kategorie: {e(f.category.value)} · Status: {e(f.status.value)}{cvss} · '
            f'{"automatisch" if f.auto else "manuell"} erkannt</div>'
            f'<p>{e(f.description or "Keine Beschreibung.")}</p>'
            f'{remediation}'
            f'{hist_html}'
            f'{ev_html}'
            f'</div>'
        )
    find_html = "\n".join(rows_find) or '<p class="muted">Keine Findings erfasst.</p>'

    rows_host = []
    for h in d["hosts"]:
        svc_rows = "".join(
            f"<tr><td>{s.port}</td><td>{e(s.protocol)}</td><td>{e(s.name or '-')}</td>"
            f"<td>{e(s.product or '-')}</td><td>{e(s.version or '-')}</td></tr>"
            for s in d["services"] if s.host_id == h.id
        )
        rows_host.append(
            f'<h3>{e(h.hostname or h.address)} <span class="muted">({e(h.address)})</span></h3>'
            + (f'<p class="muted">OS: {e(h.os_guess)}</p>' if h.os_guess else "")
            + '<table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Produkt</th><th>Version</th></tr></thead>'
            + f'<tbody>{svc_rows}</tbody></table>'
        )
    host_html = "\n".join(rows_host) or '<p class="muted">Keine Hosts erfasst.</p>'

    loot_rows = "".join(
        f"<tr><td>{e(l.type.value)}</td><td>{e(l.label or '-')}</td><td><code>{e(str(l.value))}</code></td>"
        f"<td>{e(l.source or '-')}</td></tr>"
        for l in d["loot"]
    )
    loot_html = (f'<table><thead><tr><th>Typ</th><th>Label</th><th>Wert</th><th>Quelle</th></tr></thead>'
                 f'<tbody>{loot_rows}</tbody></table>') if d["loot"] else '<p class="muted">Kein Loot erfasst.</p>'

    tl_rows = "".join(
        f"<tr><td>{e(_TIMELINE_LABEL.get(t.kind, str(t.kind)))}</td><td>{e(t.title)}</td>"
        f"<td>{e(t.start_ts or '-')}</td><td>{e(t.end_ts or '-')}</td><td>{e(t.note or '-')}</td></tr>"
        for t in d["timeline"]
    )
    timeline_section = ""
    if d["timeline"]:
        timeline_section = (
            '<h2>Engagement-Zeitplan</h2>'
            '<table><thead><tr><th>Art</th><th>Titel</th><th>Start</th><th>Ende</th><th>Notiz</th></tr></thead>'
            f'<tbody>{tl_rows}</tbody></table>'
        )

    return f"""<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<title>Pentest-Report: {e(project)}</title>
<style>
 :root {{ --brand: {b['color']}; }}
 * {{ box-sizing: border-box; }}
 body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
   color:#1f2937; max-width: 900px; margin: 0 auto; padding: 40px 24px; line-height:1.5; }}
 header {{ border-bottom: 4px solid var(--brand); padding-bottom:16px; margin-bottom:24px; }}
 header .company {{ color: var(--brand); font-weight:700; letter-spacing:.5px; }}
 h1 {{ margin:.2em 0; font-size: 1.8rem; }}
 h2 {{ color: var(--brand); border-bottom:1px solid #e5e7eb; padding-bottom:4px; margin-top:2em; }}
 h3 {{ margin-top:1.4em; }}
 .muted {{ color:#6b7280; font-weight:normal; }}
 .chip, .badge {{ color:#fff; padding:2px 10px; border-radius:12px; font-size:.8rem; font-weight:600; }}
 .summary-chips {{ display:flex; gap:8px; flex-wrap:wrap; margin:12px 0; align-content:flex-start; }}
 .risk-box {{ display:flex; align-items:center; gap:16px; background:#f9fafb; border:1px solid #e5e7eb;
   border-left:6px solid #9ca3af; border-radius:8px; padding:14px 18px; margin:16px 0 8px; }}
 .risk-score {{ font-size:2.4rem; font-weight:800; line-height:1; }}
 .risk-level {{ font-size:1.05rem; font-weight:700; }}
 .chart-row {{ display:flex; align-items:center; gap:20px; flex-wrap:wrap; }}
 .cards {{ display:flex; gap:16px; flex-wrap:wrap; margin:16px 0; }}
 .card {{ flex:1; min-width:120px; background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:14px; text-align:center; }}
 .card .num {{ font-size:1.6rem; font-weight:700; color:var(--brand); }}
 .card .lbl {{ font-size:.8rem; color:#6b7280; }}
 .finding {{ border:1px solid #e5e7eb; border-left:4px solid var(--brand); border-radius:6px; padding:12px 16px; margin:12px 0; }}
 .finding .fhead {{ display:flex; align-items:center; gap:10px; }}
 .finding .meta {{ font-size:.8rem; color:#6b7280; margin:6px 0; }}
 .finding .remediation {{ font-size:.9rem; background:#f0fdfa; border-radius:4px; padding:6px 10px; margin-top:6px; }}
 .finding .history {{ font-size:.85rem; margin-top:8px; }}
 .finding .history ul {{ margin:4px 0 0; padding-left:1.2em; }}
 .finding .history li {{ margin:2px 0; color:#374151; }}
 .evidence {{ margin-top:10px; font-size:.85rem; }}
 .evidence figure {{ margin:8px 0; }}
 .evidence img {{ max-width:100%; border:1px solid #d1d5db; border-radius:4px; }}
 .evidence figcaption {{ color:#6b7280; font-size:.8rem; margin-top:2px; }}
 .evidence .ev-file {{ margin:4px 0; }}
 table {{ width:100%; border-collapse:collapse; margin:8px 0; font-size:.9rem; }}
 th, td {{ text-align:left; padding:6px 10px; border-bottom:1px solid #e5e7eb; }}
 th {{ background:#f3f4f6; }}
 code {{ background:#f3f4f6; padding:1px 5px; border-radius:4px; font-size:.85em; }}
 footer {{ margin-top:3em; padding-top:12px; border-top:1px solid #e5e7eb; color:#9ca3af; font-size:.8rem; }}
 @media print {{ body {{ padding:0; }} h2 {{ page-break-after:avoid; }} .finding {{ page-break-inside:avoid; }} }}
</style></head><body>
<header>
 {f'<div class="company">{e(b["company"])}</div>' if b['company'] else ''}
 <h1>Pentest-Report: {e(project)}</h1>
 <div class="muted">Erstellt: {_now()}{f" · {e(b['author'])}" if b['author'] else ""}</div>
</header>

<h2>Zusammenfassung</h2>
<div class="risk-box" style="border-left-color:{d['risk']['color']}">
 <div class="risk-score" style="color:{d['risk']['color']}">{d['risk']['score']}</div>
 <div class="risk-text"><div class="risk-level" style="color:{d['risk']['color']}">{e(d['risk']['level'])}</div>
 <div class="muted">Risk-Score aus {d['risk']['active_count']} offenen Findings (Geschlossen/False Positive zählen nicht mit)</div></div>
</div>
<div class="cards">
 <div class="card"><div class="num">{len(d['hosts'])}</div><div class="lbl">Hosts</div></div>
 <div class="card"><div class="num">{len(d['services'])}</div><div class="lbl">Services</div></div>
 <div class="card"><div class="num">{len(d['findings'])}</div><div class="lbl">Findings</div></div>
 <div class="card"><div class="num">{len(d['loot'])}</div><div class="lbl">Loot</div></div>
 <div class="card"><div class="num">{d['done']}/{len(d['tasks'])}</div><div class="lbl">Aufgaben</div></div>
</div>
<div class="chart-row">
 {_donut_svg(d['sev_count'])}
 <div class="summary-chips">{sev_chips}</div>
</div>

<h2>Findings</h2>
{find_html}

<h2>Hosts &amp; Services</h2>
{host_html}

<h2>Loot / Credentials</h2>
{loot_html}
{timeline_section}

<footer>Erzeugt mit PentOS{f" · {e(b['company'])}" if b['company'] else ""} · Nur für autorisierte Sicherheitstests.</footer>
</body></html>"""


# ── PDF (reportlab) ─────────────────────────────────────────────────────────────
def build_pdf(repo: Repository, project: str, out_path, cfg: dict | None = None) -> None:
    """Erzeugt ein gebrandetes PDF. Benötigt reportlab (`pip install reportlab`)."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (HRFlowable, Image, Paragraph,
                                        SimpleDocTemplate, Spacer, Table, TableStyle)
        from reportlab.lib.utils import ImageReader
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics.charts.piecharts import Pie
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "PDF-Export benötigt 'reportlab'. Installieren mit: pip install reportlab"
        ) from exc

    b = _branding(cfg)
    d = _collect(repo)
    brand = colors.HexColor(b["color"])
    e = _html.escape

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Brand", parent=styles["Title"], textColor=brand, fontSize=20, spaceAfter=2))
    styles.add(ParagraphStyle("Company", parent=styles["Normal"], textColor=brand,
                              fontSize=10, leading=12, spaceAfter=0))
    styles.add(ParagraphStyle("H2b", parent=styles["Heading2"], textColor=brand, spaceBefore=14))
    styles.add(ParagraphStyle("FTitle", parent=styles["Heading3"], fontSize=11, spaceAfter=2, spaceBefore=8))
    styles.add(ParagraphStyle("Meta", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#6b7280")))
    body = styles["BodyText"]

    story = []
    if b["company"]:
        story.append(Paragraph(e(b["company"]), styles["Company"]))
    story.append(Paragraph(f"Pentest-Report: {e(project)}", styles["Brand"]))
    sub = f"Erstellt: {_now()}" + (f" · {e(b['author'])}" if b["author"] else "")
    story.append(Paragraph(sub, styles["Meta"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=brand))
    story.append(Spacer(1, 10))

    # Zusammenfassung als Tabelle
    story.append(Paragraph("Zusammenfassung", styles["H2b"]))
    risk = d["risk"]
    risk_color = colors.HexColor(risk["color"])
    styles.add(ParagraphStyle("RiskScore", parent=styles["Normal"], fontSize=26,
                              textColor=risk_color, fontName="Helvetica-Bold", spaceAfter=0))
    story.append(Paragraph(f"Risk-Score: {risk['score']} — {e(risk['level'])}", styles["RiskScore"]))
    story.append(Paragraph(
        f"aus {risk['active_count']} offenen Findings (Geschlossen/False Positive zählen nicht mit)",
        styles["Meta"]))
    story.append(Spacer(1, 8))

    sev = d["sev_count"]
    summ = [
        ["Hosts", "Services", "Findings", "Loot", "Aufgaben"],
        [str(len(d["hosts"])), str(len(d["services"])), str(len(d["findings"])),
         str(len(d["loot"])), f"{d['done']}/{len(d['tasks'])}"],
    ]
    t = Table(summ, colWidths=[3.2 * cm] * 5)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("TEXTCOLOR", (0, 1), (-1, 1), brand),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    pie = _pdf_severity_pie(sev, colors, Drawing, Pie)
    if pie is not None:
        combo = Table([[t, pie]], colWidths=[16 * cm, 3.6 * cm])
        combo.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        story.append(combo)
    else:
        story.append(t)
    story.append(Spacer(1, 4))
    sevline = "  ".join(f"{s.value}: {sev[s]}" for s in Severity if sev[s] > 0) or "keine"
    story.append(Paragraph(f"Schweregrade — {e(sevline)}", styles["Meta"]))

    # Findings
    story.append(Paragraph("Findings", styles["H2b"]))
    if not d["findings"]:
        story.append(Paragraph("Keine Findings erfasst.", styles["Meta"]))
    for f in d["findings"]:
        loc = _loc(repo, f)
        sevcol = colors.HexColor(_SEV_COLOR[f.severity])
        head = (f'<font color="{sevcol.hexval()}"><b>[{e(f.severity.value)}]</b></font> '
                f'<b>{e(f.title)}</b>')
        if loc:
            head += f' <font size="8" color="#6b7280">— {e(loc)}</font>'
        story.append(Paragraph(head, styles["FTitle"]))
        cvss = ""
        if f.cvss_score is not None:
            vec = f" · {e(f.cvss_vector)}" if f.cvss_vector else ""
            cvss = f" · CVSS {f.cvss_score}{vec}"
        story.append(Paragraph(
            f"Kategorie: {e(f.category.value)} · Status: {e(f.status.value)}{cvss} · "
            f'{"automatisch" if f.auto else "manuell"} erkannt', styles["Meta"]))
        story.append(Paragraph(e(f.description or "Keine Beschreibung."), body))
        if f.remediation:
            story.append(Paragraph(f"<b>Remediation:</b> {e(f.remediation)}", body))
        # Status-Verlauf (Retest-Tracking), wie im Markdown-Report
        changes = d["history_by_finding"].get(f.id, [])
        if changes:
            story.append(Paragraph("<b>Status-Verlauf:</b>", styles["Meta"]))
            for h in changes:
                note = f" — {e(h.note)}" if h.note else ""
                story.append(Paragraph(
                    f"{e(h.ts)}  {e(h.old_status)} → {e(h.new_status)}{note}", styles["Meta"]))
        # Evidence: Bilder einbetten (skaliert), übrige als Referenz
        evs = d["evidence_by_finding"].get(f.id, [])
        if evs:
            story.append(Paragraph("<b>Belege:</b>", styles["Meta"]))
            for ev in evs:
                cap = e(ev.description or Path(ev.path).name)
                if _is_image(ev) and Path(ev.path).exists():
                    try:
                        iw, ih = ImageReader(ev.path).getSize()
                        max_w = 15 * cm
                        w = min(max_w, iw)
                        h_ = w * ih / iw if iw else 0
                        if h_ > 18 * cm:                 # sehr hohe Bilder deckeln
                            h_ = 18 * cm
                            w = h_ * iw / ih
                        story.append(Image(ev.path, width=w, height=h_))
                        story.append(Paragraph(cap, styles["Meta"]))
                    except Exception:
                        story.append(Paragraph(f"[Bild nicht einbettbar] {cap} — {e(ev.path)}",
                                               styles["Meta"]))
                else:
                    story.append(Paragraph(f"[{e(ev.kind)}] {cap} — {e(ev.path)}", styles["Meta"]))

    # Hosts & Services
    story.append(Paragraph("Hosts & Services", styles["H2b"]))
    if not d["hosts"]:
        story.append(Paragraph("Keine Hosts erfasst.", styles["Meta"]))
    for h in d["hosts"]:
        story.append(Paragraph(f"{e(h.hostname or h.address)} ({e(h.address)})", styles["FTitle"]))
        data = [["Port", "Proto", "Service", "Produkt", "Version"]]
        for s in [s for s in d["services"] if s.host_id == h.id]:
            data.append([str(s.port), s.protocol, s.name or "-", s.product or "-", s.version or "-"])
        if len(data) > 1:
            ht = Table(data, colWidths=[2 * cm, 2 * cm, 4 * cm, 4 * cm, 4 * cm])
            ht.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(ht)

    # Loot
    story.append(Paragraph("Loot / Credentials", styles["H2b"]))
    if d["loot"]:
        cell = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=8, leading=10)
        ldata = [["Typ", "Label", "Wert", "Quelle"]]
        for l in d["loot"]:
            ldata.append([
                Paragraph(e(l.type.value), cell),
                Paragraph(e(l.label or "-"), cell),
                Paragraph(e(str(l.value or "-")), cell),
                Paragraph(e(l.source or "-"), cell),
            ])
        lt = Table(ldata, colWidths=[2.5 * cm, 5 * cm, 4.5 * cm, 4 * cm])
        lt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ]))
        story.append(lt)
    else:
        story.append(Paragraph("Kein Loot erfasst.", styles["Meta"]))

    # Engagement-Zeitplan (Meilensteine, Zeitfenster, Blackout-Zeiten)
    if d["timeline"]:
        story.append(Paragraph("Engagement-Zeitplan", styles["H2b"]))
        cell = ParagraphStyle("TlCell", parent=styles["Normal"], fontSize=8, leading=10)
        tldata = [["Art", "Titel", "Start", "Ende", "Notiz"]]
        for t in d["timeline"]:
            tldata.append([
                Paragraph(e(_TIMELINE_LABEL.get(t.kind, str(t.kind))), cell),
                Paragraph(e(t.title), cell),
                Paragraph(e(t.start_ts or "-"), cell),
                Paragraph(e(t.end_ts or "-"), cell),
                Paragraph(e(t.note or "-"), cell),
            ])
        tlt = Table(tldata, colWidths=[2.5 * cm, 4 * cm, 3.5 * cm, 3.5 * cm, 2.5 * cm])
        tlt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
        ]))
        story.append(tlt)

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#9ca3af"))
        footer_txt = "PentOS" + (f" · {b['company']}" if b['company'] else "") + " · Nur für autorisierte Sicherheitstests."
        canvas.drawString(2 * cm, 1 * cm, footer_txt)
        canvas.drawRightString(19 * cm, 1 * cm, f"Seite {doc_.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(out_path), pagesize=A4,
                            topMargin=1.5 * cm, bottomMargin=1.5 * cm,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            title=f"Pentest-Report: {project}", author=b["company"] or "PentOS")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
