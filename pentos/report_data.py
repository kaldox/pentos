"""
Gemeinsame Datensammlung für die Severity-basierten Reports (Markdown, HTML,
PDF -- siehe report.py::build_markdown und export.py::build_html/build_pdf).

Vorher dupliziert: build_markdown sammelte dieselben Aggregate (Sev-Zählung,
Evidence-Gruppierung, Status-Historie, Location-String) komplett unabhängig
von export.py's `_collect()`. Jedes neue Finding-Feld (z.B. ATT&CK/EPSS
diese Session) musste dadurch an mehreren Stellen einzeln nachgezogen
werden. Eine Stelle für "was wird gesammelt", drei für "wie wird's
dargestellt" (Markdown-Zeilen/HTML-Tags/ReportLab-Flowables sind zu
unterschiedlich für ein gemeinsames Template).

Bewusst NICHT hier: der Lern-Report (report.py::build_learning_markdown) --
strukturell ein anderer Report (chronologische Run-Historie mit
didaktischen Erklärungen statt Severity-Übersicht), keine gemeinsame Basis.
"""
from __future__ import annotations

from .models import SEVERITY_ORDER, Severity, TaskStatus
from .repository import Repository
from .risk import compute_risk


def evidence_by_finding(repo: Repository) -> dict[int, list]:
    """Gruppiert Evidence nach finding_id (nur das, was einem Finding zugeordnet ist)."""
    out: dict[int, list] = {}
    for ev in repo.list_evidence():
        if ev.finding_id:
            out.setdefault(ev.finding_id, []).append(ev)
    return out


def history_by_finding(repo: Repository, findings: list) -> dict[int, list]:
    """Status-Verlauf je Finding, nur echte Wechsel (Ersteintrag mit
    old_status=None wird in keinem Report mit ausgegeben)."""
    out: dict[int, list] = {}
    for f in findings:
        if not f.id:
            continue
        changes = [h for h in repo.finding_history(f.id) if h.old_status is not None]
        if changes:
            out[f.id] = changes
    return out


def location_of(repo: Repository, f) -> str:
    """Host/Service-Ort eines Findings als Anzeige-String (z.B. '10.0.0.5:80/tcp')."""
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


def collect(repo: Repository) -> dict:
    """Sammelt die Projektdaten, die alle drei Severity-basierten Reports
    (Markdown/HTML/PDF) gemeinsam brauchen."""
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
        "evidence_by_finding": evidence_by_finding(repo),
        "history_by_finding": history_by_finding(repo, findings),
        "risk": compute_risk(findings),
        "timeline": repo.list_timeline_entries(),
        "policy": repo.get_engagement_policy(),
    }
