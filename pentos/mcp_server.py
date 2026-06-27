"""
MCP-Server für PentOS (optional, `pip install -e ".[mcp]"`).

Stellt den PentOS-Workspace als MCP-Tools für Clients wie Claude Code/Cursor
bereit. ALLE Tools sind **lesend/analysierend** – kein Tool führt Scans,
Exploits oder sonstige Aktionen aus. Damit bleibt die Kern-Leitplanke gewahrt:
Die KI analysiert und schlägt vor, ausgeführt wird nur, was der Mensch selbst
in der CLI startet.

Dieses Modul trennt die reine Logik (`_logic`-Funktionen, testbar ohne MCP)
vom MCP-Server-Aufbau (`build_server`).
"""
from __future__ import annotations

import json
from typing import Optional

from . import config
from .models import SEVERITY_ORDER, Severity
from .repository import Repository
from .workspace import list_projects


def _repo(project: str) -> Repository:
    if project not in list_projects():
        raise ValueError(f"Projekt '{project}' nicht gefunden. "
                         f"Verfügbar: {', '.join(list_projects()) or '(keine)'}")
    return Repository(config.db_path(project))


def _resolve(project: Optional[str]) -> str:
    if project:
        return project
    projects = list_projects()
    if not projects:
        raise ValueError("Kein Projekt vorhanden. Erst `pentos project new <name>` anlegen.")
    active = None
    try:
        active = config.get_active_project()
    except Exception:
        pass
    return active if active in projects else projects[0]


# ── Logik (reine Funktionen, geben Text/JSON für den LLM-Client zurück) ───────
def logic_list_projects() -> str:
    projects = list_projects()
    if not projects:
        return "Keine Projekte vorhanden."
    active = None
    try:
        active = config.get_active_project()
    except Exception:
        pass
    lines = [f"Projekte ({len(projects)}):"]
    for p in projects:
        lines.append(f"  - {p}" + ("  [aktiv]" if p == active else ""))
    return "\n".join(lines)


def logic_summary(project: Optional[str] = None) -> str:
    name = _resolve(project)
    repo = _repo(name)
    try:
        findings = repo.list_findings()
        hosts = repo.list_hosts()
        services = repo.list_services()
        loot = repo.list_loot()
        tasks = repo.list_tasks()
        sev = {s.value: 0 for s in Severity}
        for f in findings:
            sev[f.severity.value] += 1
        done = sum(1 for t in tasks if t.status.value == "done")
        out = {
            "project": name,
            "hosts": len(hosts), "services": len(services),
            "findings": len(findings), "loot": len(loot),
            "tasks": f"{done}/{len(tasks)}",
            "severity": {k: v for k, v in sev.items() if v},
        }
        return json.dumps(out, ensure_ascii=False, indent=2)
    finally:
        repo.close()


def logic_findings(project: Optional[str] = None, severity: Optional[str] = None) -> str:
    name = _resolve(project)
    repo = _repo(name)
    try:
        findings = sorted(repo.list_findings(),
                          key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        if severity:
            sev = severity.strip().lower()
            findings = [f for f in findings if f.severity.value.lower() == sev]
        if not findings:
            return f"Keine Findings in '{name}'" + (f" mit Severity '{severity}'." if severity else ".")
        out = []
        for f in findings:
            out.append({
                "id": f.id, "severity": f.severity.value, "title": f.title,
                "category": f.category.value, "status": f.status.value,
                "cvss": f.cvss_score, "host_id": f.host_id,
                "description": (f.description or "")[:400],
                "remediation": (f.remediation or "")[:400] or None,
            })
        return json.dumps({"project": name, "count": len(out), "findings": out},
                          ensure_ascii=False, indent=2)
    finally:
        repo.close()


def logic_hosts(project: Optional[str] = None) -> str:
    name = _resolve(project)
    repo = _repo(name)
    try:
        services = repo.list_services()
        hosts = []
        for h in repo.list_hosts():
            svcs = sorted([s for s in services if s.host_id == h.id],
                          key=lambda s: s.port or 0)
            hosts.append({
                "id": h.id, "address": h.address, "hostname": h.hostname,
                "os": h.os_guess, "status": h.status,
                "services": [
                    f"{s.port}/{s.protocol} {s.name or ''} {s.product or ''} {s.version or ''}".strip()
                    for s in svcs
                ],
            })
        if not hosts:
            return f"Keine Hosts in '{name}'."
        return json.dumps({"project": name, "hosts": hosts}, ensure_ascii=False, indent=2)
    finally:
        repo.close()


def logic_loot(project: Optional[str] = None) -> str:
    name = _resolve(project)
    repo = _repo(name)
    try:
        loot = repo.list_loot()
        if not loot:
            return f"Kein Loot in '{name}'."
        out = [{
            "type": l.type.value if hasattr(l.type, "value") else l.type,
            "label": l.label, "value": l.value, "source": l.source,
        } for l in loot]
        return json.dumps({"project": name, "loot": out}, ensure_ascii=False, indent=2)
    finally:
        repo.close()


def logic_notes(project: Optional[str] = None, query: Optional[str] = None) -> str:
    name = _resolve(project)
    repo = _repo(name)
    try:
        notes = repo.list_notes()
        if query:
            q = query.lower()
            notes = [n for n in notes
                     if q in (n.title or "").lower() or q in (n.body or "").lower()]
        if not notes:
            return f"Keine Notizen in '{name}'" + (f" zu '{query}'." if query else ".")
        out = [{"id": n.id, "title": n.title, "category": n.category,
                "body": (n.body or "")[:1500]} for n in notes]
        return json.dumps({"project": name, "notes": out}, ensure_ascii=False, indent=2)
    finally:
        repo.close()


def logic_knowledge(query: Optional[str] = None) -> str:
    """Durchsucht die kuratierte Wissensbasis (handgeprüft, keine KI-Generierung)."""
    from .knowledge import TOOL_KNOWLEDGE, FINDING_KNOWLEDGE
    q = (query or "").lower()
    hits = []
    # TOOL_KNOWLEDGE: dict {tag: {...}}
    for tag, entry in TOOL_KNOWLEDGE.items():
        text = f"{tag} {entry}".lower()
        if not q or q in text:
            hits.append({"tag": tag, "info": str(entry)[:600]})
    # FINDING_KNOWLEDGE: list[dict] (z.B. {"match":..., "why":...})
    for entry in FINDING_KNOWLEDGE:
        text = str(entry).lower()
        if not q or q in text:
            tag = entry.get("match") if isinstance(entry, dict) else str(entry)[:40]
            hits.append({"tag": tag, "info": str(entry)[:600]})
    if not hits:
        return f"Nichts in der Wissensbasis zu '{query}'."
    return json.dumps({"count": len(hits), "entries": hits[:20]},
                      ensure_ascii=False, indent=2)


# ── MCP-Server-Aufbau ─────────────────────────────────────────────────────────
def build_server():
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise SystemExit(
            'MCP-SDK fehlt. Installiere die MCP-Extras: pip install -e ".[mcp]"'
        ) from exc

    mcp = FastMCP("pentos", instructions=(
        "PentOS – lokaler, einzelbenutziger Pentest-Workspace. Diese Tools sind "
        "ausschliesslich LESEND/ANALYSIEREND: sie lesen Findings, Hosts, Loot, "
        "Notizen und die kuratierte Wissensbasis eines autorisierten Projekts "
        "(CTF/Lab/freigegebene Tests). Es gibt KEINE Tools, die Scans oder Angriffe "
        "ausführen – schlage Befehle vor, die der Mensch selbst in der PentOS-CLI startet."
    ))

    @mcp.tool()
    def pentos_list_projects() -> str:
        """Listet alle PentOS-Projekte (Workspaces) und markiert das aktive."""
        return logic_list_projects()

    @mcp.tool()
    def pentos_summary(project: Optional[str] = None) -> str:
        """Überblick eines Projekts: Zähler (Hosts/Dienste/Findings/Loot/Aufgaben)
        und Severity-Verteilung. Ohne project wird das aktive/erste genommen."""
        return logic_summary(project)

    @mcp.tool()
    def pentos_findings(project: Optional[str] = None, severity: Optional[str] = None) -> str:
        """Findings eines Projekts (nach Severity sortiert), optional gefiltert nach
        severity (critical|high|medium|low|info). Enthält CVSS, Beschreibung, Remediation."""
        return logic_findings(project, severity)

    @mcp.tool()
    def pentos_hosts(project: Optional[str] = None) -> str:
        """Hosts und ihre offenen Dienste (Port/Protokoll/Produkt/Version) eines Projekts."""
        return logic_hosts(project)

    @mcp.tool()
    def pentos_loot(project: Optional[str] = None) -> str:
        """Erfasstes Loot (Credentials/Hashes/Tokens/…) eines Projekts."""
        return logic_loot(project)

    @mcp.tool()
    def pentos_notes(project: Optional[str] = None, query: Optional[str] = None) -> str:
        """Notizen eines Projekts, optional nach einem Suchbegriff gefiltert."""
        return logic_notes(project, query)

    @mcp.tool()
    def pentos_knowledge(query: Optional[str] = None) -> str:
        """Durchsucht die kuratierte (handgeprüfte) Wissensbasis zu Tools und Findings."""
        return logic_knowledge(query)

    return mcp


def serve():
    """Startet den MCP-Server über stdio (vom MCP-Client gestartet)."""
    build_server().run()
