"""
Reporting für PentOS.

Erzeugt einen Markdown-Report aus Findings, Journal, Aufgabenstatus, Hosts,
Services und Attack-Path. Basis für spätere HTML-/PDF-Ausgabe.

"""
from __future__ import annotations

from . import graph, knowledge
from .models import SEVERITY_ORDER, Severity, TaskStatus, _now
from .repository import Repository
from .runners import registry as tool_registry


def build_markdown(repo: Repository, project: str) -> str:
    hosts = repo.list_hosts()
    services = repo.list_services()
    findings = sorted(repo.list_findings(), key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    tasks = repo.list_tasks()
    loot = repo.list_loot()
    journal = repo.journal()
    ev_by_finding: dict[int, list] = {}
    for ev in repo.list_evidence():
        if ev.finding_id:
            ev_by_finding.setdefault(ev.finding_id, []).append(ev)

    sev_count = {s: 0 for s in Severity}
    for f in findings:
        sev_count[f.severity] += 1

    done = sum(1 for t in tasks if t.status == TaskStatus.DONE)

    md: list[str] = []
    md.append(f"# Pentest-Report: {project}")
    md.append("")
    md.append(f"_Erzeugt: {_now()} · PentOS_")
    md.append("")

    # Management Summary
    md.append("## Zusammenfassung")
    md.append("")
    md.append(f"- Hosts: **{len(hosts)}**")
    md.append(f"- Services: **{len(services)}**")
    md.append(f"- Findings: **{len(findings)}** "
              f"(Critical: {sev_count[Severity.CRITICAL]}, High: {sev_count[Severity.HIGH]}, "
              f"Medium: {sev_count[Severity.MEDIUM]}, Low: {sev_count[Severity.LOW]}, "
              f"Info: {sev_count[Severity.INFO]})")
    md.append(f"- Aufgaben erledigt: **{done}/{len(tasks)}**")
    md.append(f"- Loot/Credentials: **{len(loot)}**")
    md.append("")

    # Findings
    md.append("## Findings")
    md.append("")
    if not findings:
        md.append("_Keine Findings erfasst._")
    for f in findings:
        loc = ""
        if f.service_id:
            s = repo.get_service(f.service_id)
            if s:
                h = repo.get_host(s.host_id)
                loc = f" — {h.address if h else ''}:{s.port}/{s.protocol}"
        md.append(f"### [{f.severity.value}] {f.title}{loc}")
        md.append("")
        md.append(f"- **Kategorie:** {f.category.value}")
        md.append(f"- **Status:** {f.status.value}")
        if f.cvss_score is not None:
            vec = f" (`{f.cvss_vector}`)" if f.cvss_vector else ""
            md.append(f"- **CVSS:** {f.cvss_score}{vec}")
        md.append(f"- **Erkennung:** {'automatisch' if f.auto else 'manuell'}")
        md.append("")
        md.append(f.description or "_Keine Beschreibung._")
        md.append("")
        if f.remediation:
            md.append(f"**Remediation:** {f.remediation}")
            md.append("")
        hist = repo.finding_history(f.id) if f.id else []
        changes = [h for h in hist if h.old_status is not None]
        if changes:
            md.append("**Status-Verlauf:**")
            md.append("")
            for h in changes:
                note = f" — {h.note}" if h.note else ""
                md.append(f"- `{h.ts}` {h.old_status} → {h.new_status}{note}")
            md.append("")
        evs = ev_by_finding.get(f.id, [])
        if evs:
            md.append("**Belege:**")
            md.append("")
            for ev in evs:
                from pathlib import Path as _P
                cap = ev.description or _P(ev.path).name
                is_img = (ev.kind or "").lower() == "screenshot" or \
                    _P(ev.path).suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
                if is_img:
                    md.append(f"![{cap}]({ev.path})")
                    md.append(f"*{cap}*")
                else:
                    md.append(f"- `[{ev.kind}]` {cap} — `{ev.path}`")
                md.append("")

    # Hosts & Services
    md.append("## Hosts & Services")
    md.append("")
    for h in hosts:
        title = h.hostname or h.address
        md.append(f"### {title} ({h.address})")
        if h.os_guess:
            md.append(f"- OS: {h.os_guess}")
        md.append("")
        md.append("| Port | Proto | Service | Produkt | Version |")
        md.append("|------|-------|---------|---------|---------|")
        for s in [s for s in services if s.host_id == h.id]:
            md.append(f"| {s.port} | {s.protocol} | {s.name or '-'} | {s.product or '-'} | {s.version or '-'} |")
        md.append("")

    # Attack Path
    md.append("## Attack Path")
    md.append("")
    md.append("```mermaid")
    md.append(graph.to_mermaid(repo))
    md.append("```")
    md.append("")

    # Offene Aufgaben
    open_tasks = [t for t in tasks if t.status != TaskStatus.DONE]
    md.append("## Offene Aufgaben")
    md.append("")
    if not open_tasks:
        md.append("_Alle Aufgaben erledigt._")
    for t in open_tasks:
        md.append(f"- [ ] {t.title} _({t.status.value})_")
    md.append("")

    # Journal / Timeline
    md.append("## Timeline (Journal)")
    md.append("")
    for e in journal:
        md.append(f"- `{e.ts}` **{e.action}**" + (f" — {e.detail}" if e.detail else ""))
    md.append("")

    return "\n".join(md)


def build_learning_markdown(repo: Repository, project: str) -> str:
    """Didaktischer Lern-Report: chronologische Schritte mit Erklärungen.

    Verknüpft die echten ausgeführten Tools (Run-History) und Findings mit der
    kuratierten Wissensbasis (knowledge.py) zu einem 'Was/Warum/Ergebnis'-Bericht.
    Ziel: aus einem Engagement eine nachvollziehbare Lektion machen.
    """
    runs = repo.list_runs()
    findings = sorted(repo.list_findings(), key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    loot = repo.list_loot()
    hosts = repo.list_hosts()

    md: list[str] = []
    md.append(f"# Lern-Report: {project}")
    md.append("")
    md.append(f"_Erzeugt: {_now()} · PentOS_")
    md.append("")
    md.append("> Dieser Report erklärt **was** gemacht wurde, **warum** an dieser Stelle "
              "und **wie** das Ergebnis zu lesen ist. Erklärungen stammen aus der "
              "geprüften PentOS-Wissensbasis, nicht aus automatischer Generierung.")
    md.append("")

    # Überblick
    md.append("## Überblick")
    md.append("")
    md.append(f"- Ausgeführte Tool-Läufe: **{len(runs)}**")
    md.append(f"- Findings: **{len(findings)}**")
    md.append(f"- Gefundene Credentials/Loot: **{len(loot)}**")
    md.append(f"- Hosts: **{len(hosts)}**")
    md.append("")

    # Vorgehensschritte (chronologisch nach Run-History)
    md.append("## Vorgehen Schritt für Schritt")
    md.append("")
    if not runs:
        md.append("_Keine Tool-Läufe protokolliert. Führe Tools über `pentos run`/`pentos sweep` aus._")
        md.append("")
    for i, r in enumerate(runs, 1):
        spec = tool_registry.get(r.tool)
        phase = knowledge.PHASE_BY_CATEGORY.get(spec.category, "Schritt") if spec else "Schritt"
        md.append(f"### Schritt {i}: {r.tool} — {phase}")
        md.append("")
        if r.command:
            md.append("```bash")
            md.append(r.command)
            md.append("```")
            md.append("")
        info = knowledge.tool_info(r.tool)
        if info:
            md.append(f"**Was macht das?** {info['what']}")
            md.append("")
            md.append(f"**Warum hier?** {info['why']}")
            md.append("")
            md.append(f"**Ergebnis lesen:** {info['read']}")
            md.append("")
        else:
            md.append("_Für dieses Tool liegt noch keine Erklärung in der Wissensbasis vor._")
            md.append("")
        meta = []
        if r.target:
            meta.append(f"Ziel: `{r.target}`")
        if r.returncode is not None:
            meta.append(f"Exit-Code: {r.returncode}")
        if r.duration_ms is not None:
            meta.append(f"Dauer: {r.duration_ms} ms")
        if meta:
            md.append("_" + " · ".join(meta) + "_")
            md.append("")

    # Findings mit didaktischer Einordnung
    md.append("## Was wurde gefunden — und was bedeutet es?")
    md.append("")
    if not findings:
        md.append("_Keine Findings erfasst._")
        md.append("")
    for f in findings:
        md.append(f"### [{f.severity.value}] {f.title}")
        md.append("")
        if f.description:
            md.append(f.description)
            md.append("")
        info = knowledge.finding_info(f.title)
        if info:
            md.append(f"**Warum ist das ein Problem?** {info['why']}")
            md.append("")
            md.append(f"**Wie wird es ausgenutzt?** {info['exploit']}")
            md.append("")
            md.append(f"**Wie behebt man es?** {info['fix']}")
            md.append("")

    # Gelernt
    md.append("## Was du hier gelernt hast")
    md.append("")
    phases_used = []
    for r in runs:
        spec = tool_registry.get(r.tool)
        if spec:
            ph = knowledge.PHASE_BY_CATEGORY.get(spec.category)
            if ph and ph not in phases_used:
                phases_used.append(ph)
    if phases_used:
        md.append("Durchlaufene Methodik-Phasen: " + ", ".join(phases_used) + ".")
        md.append("")
    tools_used = sorted({r.tool for r in runs})
    if tools_used:
        md.append("Eingesetzte Werkzeuge: " + ", ".join(f"`{t}`" for t in tools_used) + ".")
        md.append("")
    sev_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if sev_high:
        md.append(f"Kritischster Befund: **{sev_high[0].title}** "
                  f"([{sev_high[0].severity.value}]). Das ist der Punkt, der bei einem "
                  "echten Engagement zuerst behoben werden müsste.")
        md.append("")
    md.append("> Tipp: Versuche vor dem nächsten Schritt jeweils selbst zu formulieren, "
              "*warum* du ein Tool einsetzt und *was* du im Output erwartest. Genau dieses "
              "bewusste Begründen ist der eigentliche Lerneffekt.")
    md.append("")

    return "\n".join(md)
