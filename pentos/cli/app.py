"""
PentOS – Kommandozeile (Typer + Rich).

Bindet sämtliche Subsysteme: Projekte/Workspace, Hosts, Services, Scan-Import,
Empfehlungen, Aufgaben, Findings, Notizen, Loot, Evidence, Wissen, Journal,
Attack-Path-Graph, Obsidian-Export, Reporting und KI-Mentor.

"""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Optional

import sys
import typer
from rich.console import Console
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table

from .. import config
from ..ai import AIClient
from .. import findings_rules, graph as graph_mod, obsidian as obsidian_mod, recommend, report as report_mod
from .. import export as export_mod
from .. import playbooks as playbooks_mod
from ..importers import nmap as nmap_importer
from ..importers import scanners as scanner_importer
from ..runners import base as runner_base, parsers as runner_parsers, registry as runner_registry
from ..models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingTemplate,
    FindingStatus,
    Host,
    KnowledgeEntry,
    Loot,
    LootType,
    Note,
    Service,
    Severity,
    Task,
    TaskStatus,
)
from ..repository import Repository
from ..workspace import create_workspace, list_projects

console = Console()
app = typer.Typer(help="PentOS – Knowledge-Driven Offensive Security Workspace",
                  no_args_is_help=True, add_completion=False)


# ── Hilfsfunktionen ──────────────────────────────────────────────────────────
def _active_or_exit() -> str:
    name = config.get_active_project()
    if not name:
        console.print("[red]Kein aktives Projekt.[/red] Lege eines an: "
                      "[cyan]pentos project new <name>[/cyan]")
        raise typer.Exit(1)
    return name


def _repo() -> tuple[Repository, str]:
    name = _active_or_exit()
    return Repository(config.db_path(name)), name


SEVERITY_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}
CATEGORY_MAP = {
    "misconfig": FindingCategory.MISCONFIG, "vuln": FindingCategory.VULN,
    "exposure": FindingCategory.EXPOSURE, "credential": FindingCategory.CREDENTIAL,
    "infodisc": FindingCategory.INFO_DISCLOSURE, "other": FindingCategory.OTHER,
}
FSTATUS_MAP = {
    "unverified": FindingStatus.UNVERIFIED, "confirmed": FindingStatus.CONFIRMED,
    "exploited": FindingStatus.EXPLOITED, "fp": FindingStatus.FALSE_POSITIVE,
    "closed": FindingStatus.CLOSED,
}
TSTATUS_MAP = {
    "open": TaskStatus.OPEN, "progress": TaskStatus.IN_PROGRESS, "done": TaskStatus.DONE,
}
LOOT_MAP = {
    "cred": LootType.CREDENTIAL, "hash": LootType.HASH, "token": LootType.TOKEN,
    "cookie": LootType.COOKIE, "apikey": LootType.API_KEY, "sshkey": LootType.SSH_KEY,
    "other": LootType.OTHER,
}

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red", Severity.HIGH: "red",
    Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim",
}


# ── Projekte ─────────────────────────────────────────────────────────────────
project_app = typer.Typer(help="Projekte / Workspaces verwalten")
app.add_typer(project_app, name="project", rich_help_panel="Workspace")


@project_app.command("new")
def project_new(name: str = typer.Argument(..., help="Projektname, z.B. THM_Alfred")):
    """Legt einen neuen Workspace an und setzt ihn aktiv."""
    root = create_workspace(name)
    repo = Repository(config.db_path(name))
    repo.log("Projekt angelegt", name)
    repo.close()
    config.set_active_project(name)
    console.print(Panel.fit(f"[green]Workspace angelegt:[/green] {root}\n"
                            f"[green]Aktives Projekt:[/green] {name}",
                            title="PentOS"))


@project_app.command("list")
def project_list():
    """Listet alle Projekte."""
    active = config.get_active_project()
    table = Table(title="Projekte")
    table.add_column("Aktiv", justify="center")
    table.add_column("Name")
    for p in list_projects():
        table.add_row("●" if p == active else "", p)
    console.print(table)


@project_app.command("use")
def project_use(name: str):
    """Wechselt das aktive Projekt."""
    if name not in list_projects():
        console.print(f"[red]Projekt '{name}' existiert nicht.[/red]")
        raise typer.Exit(1)
    config.set_active_project(name)
    console.print(f"[green]Aktives Projekt:[/green] {name}")


@project_app.command("show")
def project_show():
    """Zeigt eine Übersicht des aktiven Projekts."""
    repo, name = _repo()
    h = len(repo.list_hosts()); s = len(repo.list_services())
    f = len(repo.list_findings()); t = repo.list_tasks()
    done = sum(1 for x in t if x.status == TaskStatus.DONE)
    repo.close()
    console.print(Panel.fit(
        f"[bold]{name}[/bold]\n"
        f"Hosts: {h}   Services: {s}   Findings: {f}\n"
        f"Aufgaben: {done}/{len(t)} erledigt\n"
        f"Pfad: {config.project_path(name)}",
        title="Projekt"))


# ── Hosts ────────────────────────────────────────────────────────────────────
host_app = typer.Typer(help="Hosts verwalten")
app.add_typer(host_app, name="host", rich_help_panel="Workspace")


@host_app.command("add")
def host_add(address: str, hostname: Optional[str] = typer.Option(None, "--name"),
             os_guess: Optional[str] = typer.Option(None, "--os")):
    repo, _ = _repo()
    host = repo.add_host(Host(address=address, hostname=hostname, os_guess=os_guess))
    repo.close()
    console.print(f"[green]Host #{host.id}:[/green] {host.address}")


@host_app.command("list")
def host_list():
    repo, _ = _repo()
    hosts = repo.list_hosts()
    repo.close()
    table = Table(title="Hosts")
    for c in ["ID", "Adresse", "Hostname", "OS", "Status"]:
        table.add_column(c)
    for h in hosts:
        table.add_row(str(h.id), h.address, h.hostname or "-", h.os_guess or "-", h.status)
    console.print(table)


# ── Services ─────────────────────────────────────────────────────────────────
service_app = typer.Typer(help="Services verwalten")
app.add_typer(service_app, name="service", rich_help_panel="Workspace")


@service_app.command("add")
def service_add(host_id: int, port: int,
                protocol: str = typer.Option("tcp", "--proto"),
                name: Optional[str] = typer.Option(None, "--name"),
                product: Optional[str] = typer.Option(None, "--product"),
                version: Optional[str] = typer.Option(None, "--version"),
                tasks: bool = typer.Option(True, "--tasks/--no-tasks",
                                           help="Automatisch Aufgaben generieren")):
    repo, _ = _repo()
    if not repo.get_host(host_id):
        console.print(f"[red]Host #{host_id} existiert nicht.[/red]")
        repo.close(); raise typer.Exit(1)
    svc = repo.add_service(Service(host_id=host_id, port=port, protocol=protocol,
                                   name=name, product=product, version=version))
    created = 0
    if tasks:
        for t in recommend.tasks_for(svc):
            if repo.add_task(t):
                created += 1
    findings = 0
    for f in findings_rules.detect_for_service(svc):
        if not repo.finding_exists(f.title, f.service_id):
            repo.add_finding(f); findings += 1
    repo.close()
    console.print(f"[green]Service #{svc.id}:[/green] {svc.port}/{svc.protocol} {svc.name or ''} "
                  f"→ {created} Aufgaben, {findings} Auto-Findings")


@service_app.command("list")
def service_list(host_id: Optional[int] = typer.Option(None, "--host")):
    repo, _ = _repo()
    services = repo.list_services(host_id)
    repo.close()
    table = Table(title="Services")
    for c in ["ID", "Host", "Port", "Proto", "Service", "Produkt", "Version"]:
        table.add_column(c)
    for s in services:
        table.add_row(str(s.id), str(s.host_id), str(s.port), s.protocol,
                      s.name or "-", s.product or "-", s.version or "-")
    console.print(table)


# ── Scan-Import ──────────────────────────────────────────────────────────────
scan_app = typer.Typer(help="Scanner-Outputs importieren")
app.add_typer(scan_app, name="scan", rich_help_panel="Recon & Import")


@scan_app.command("import-nmap")
def scan_import_nmap(xml_file: Path = typer.Argument(..., exists=True, readable=True,
                                                     help="nmap XML (nmap -oX)")):
    """Importiert nmap-XML: Hosts, Services, Auto-Aufgaben, Auto-Findings, Auto-Notiz."""
    repo, name = _repo()
    parsed = nmap_importer.parse_nmap_xml(xml_file)
    repo.log("Nmap-Import gestartet", str(xml_file))

    n_hosts = n_services = n_tasks = n_findings = 0
    note_lines = [f"# Nmap-Import — {xml_file.name}", ""]
    for host, services in parsed:
        h = repo.add_host(host); n_hosts += 1
        note_lines.append(f"## {h.hostname or h.address} ({h.address})")
        for svc in services:
            svc.host_id = h.id
            persisted = repo.add_service(svc); n_services += 1
            note_lines.append(f"- {persisted.port}/{persisted.protocol} "
                              f"{persisted.name or ''} {persisted.product or ''} {persisted.version or ''}".rstrip())
            for t in recommend.tasks_for(persisted):
                if repo.add_task(t):
                    n_tasks += 1
            for f in findings_rules.detect_for_service(persisted):
                if not repo.finding_exists(f.title, f.service_id):
                    repo.add_finding(f); n_findings += 1
        note_lines.append("")

    # Automatische Notiz auf Platte + in DB
    note_path = config.project_path(name) / "notes" / "nmap.md"
    note_path.write_text("\n".join(note_lines), encoding="utf-8")
    repo.add_note(Note(title=f"Nmap-Import {xml_file.name}", body="\n".join(note_lines), category="nmap"))
    repo.log("Nmap-Import abgeschlossen",
             f"{n_hosts} Hosts, {n_services} Services, {n_tasks} Tasks, {n_findings} Findings")
    repo.close()

    console.print(Panel.fit(
        f"[green]Import abgeschlossen[/green]\n"
        f"Hosts: {n_hosts}   Services: {n_services}\n"
        f"Neue Aufgaben: {n_tasks}   Auto-Findings: {n_findings}\n"
        f"Notiz: {note_path}",
        title="Nmap"))


@scan_app.command("import-scanner")
def scan_import_scanner(
    xml_file: Path = typer.Argument(..., exists=True, readable=True,
                                    help="Scanner-XML (Nessus/OpenVAS/Burp)"),
    fmt: Optional[str] = typer.Option(None, "--format", "-f",
                                      help="Format erzwingen: nessus|openvas|burp (sonst Auto)"),
):
    """Importiert Schwachstellen-Scanner-Reports (Nessus, OpenVAS/Greenbone, Burp).

    Erkennt Hosts/Services und legt die Scanner-Findings mit Severity, CVSS und
    Remediation an. Findings werden gegen bestehende dedupliziert.
    """
    repo, name = _repo()
    try:
        detected, targets = scanner_importer.parse(xml_file, fmt)
    except ValueError as exc:
        repo.close()
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    repo.log("Scanner-Import gestartet", f"{xml_file} (Format: {detected})")
    n_hosts = n_services = n_findings = n_dupe = 0
    for pt in targets:
        h = repo.add_host(pt.host); n_hosts += 1
        # Services anlegen, Port->service_id-Map für Finding-Bindung
        port_map: dict[tuple[int, str], int] = {}
        for svc in pt.services:
            svc.host_id = h.id
            persisted = repo.add_service(svc); n_services += 1
            if persisted.port:
                port_map[(persisted.port, persisted.protocol)] = persisted.id
        for f, port_hint in zip(pt.findings, pt.finding_ports):
            f.host_id = h.id
            if port_hint and port_hint in port_map:
                f.service_id = port_map[port_hint]
            # Dedup: pro Service bzw. pro Host
            if repo.finding_exists(f.title, f.service_id, h.id):
                n_dupe += 1
                continue
            repo.add_finding(f); n_findings += 1

    repo.log("Scanner-Import abgeschlossen",
             f"{detected}: {n_hosts} Hosts, {n_services} Services, {n_findings} Findings")
    repo.close()
    console.print(Panel.fit(
        f"[green]Import abgeschlossen[/green]  ([bold]{detected}[/bold])\n"
        f"Hosts: {n_hosts}   Services: {n_services}\n"
        f"Neue Findings: {n_findings}   Übersprungen (Dublette): {n_dupe}",
        title="Scanner-Import"))


# ── Empfehlungen ─────────────────────────────────────────────────────────────
@app.command("recommend", rich_help_panel="Recon & Import")
def recommend_cmd(service_id: int,
                  create_tasks: bool = typer.Option(False, "--create-tasks",
                                                     help="Vorgeschlagene Aufgaben anlegen")):
    """Zeigt empfohlene nächste Schritte für einen Service (keine Ausführung)."""
    import shutil
    repo, _ = _repo()
    svc = repo.get_service(service_id)
    if not svc:
        console.print(f"[red]Service #{service_id} existiert nicht.[/red]")
        repo.close(); raise typer.Exit(1)
    host = repo.get_host(svc.host_id)
    recs = recommend.recommendations_for(svc)
    console.print(Panel.fit(
        f"[bold]{svc.port}/{svc.protocol} {svc.name or ''}[/bold]\n\n" +
        "\n".join(f"  {i+1}. {r}" for i, r in enumerate(recs)),
        title="Empfohlene nächste Schritte"))

    # Run-Shortcuts: passende Registry-Tools, die installiert sind
    addr = host.address if host else None
    if addr:
        web = recommend.is_web(svc)
        scheme = "https" if (svc.name or "").lower() == "https" or (svc.tunnel or "") == "ssl" \
            or svc.port in (443, 8443) else "http"
        url = f"{scheme}://{addr}:{svc.port}" if svc.port not in (80, 443) else f"{scheme}://{addr}"
        lines, missing = [], []
        for tname in recommend.tools_for(svc):
            spec = runner_registry.get(tname)
            if not spec:
                continue
            tgt = url if (web and spec.category == "web") else addr
            if shutil.which(spec.binary):
                lines.append(f"  pentos run {tname} {tgt}")
            else:
                missing.append(tname)
        if lines:
            body = "[green]Bereit (installiert):[/green]\n" + "\n".join(lines)
            if missing:
                body += f"\n\n[dim]Nicht installiert: {', '.join(missing)}[/dim]"
            console.print(Panel.fit(body, title="▶ Ausführen via Runner"))
        elif missing:
            console.print(f"[dim]Passende Tools nicht installiert: {', '.join(missing)}[/dim]")

    if create_tasks:
        created = sum(1 for t in recommend.tasks_for(svc) if repo.add_task(t))
        console.print(f"[green]{created} Aufgaben angelegt.[/green]")
    repo.close()


# ── Aufgaben ─────────────────────────────────────────────────────────────────
task_app = typer.Typer(help="Aufgaben verwalten")
app.add_typer(task_app, name="task", rich_help_panel="Befunde & Doku")


@task_app.command("list")
def task_list(status: Optional[str] = typer.Option(None, "--status",
                                                   help="open|progress|done")):
    repo, _ = _repo()
    st = TSTATUS_MAP.get(status) if status else None
    tasks = repo.list_tasks(st)
    repo.close()
    table = Table(title="Aufgaben")
    for c in ["ID", "Status", "Aufgabe", "Quelle", "Svc"]:
        table.add_column(c)
    badge = {TaskStatus.OPEN: "[ ]", TaskStatus.IN_PROGRESS: "[~]", TaskStatus.DONE: "[x]"}
    for t in tasks:
        table.add_row(str(t.id), f"{badge[t.status]} {t.status.value}", t.title,
                      t.source or "-", str(t.service_id or "-"))
    console.print(table)


@task_app.command("add")
def task_add(title: str, host_id: Optional[int] = typer.Option(None, "--host"),
             service_id: Optional[int] = typer.Option(None, "--service")):
    repo, _ = _repo()
    t = repo.add_task(Task(title=title, host_id=host_id, service_id=service_id, source="manuell"),
                      dedup=False)
    repo.close()
    console.print(f"[green]Aufgabe #{t.id}:[/green] {t.title}")


@task_app.command("start")
def task_start(task_id: int):
    repo, _ = _repo()
    ok = repo.set_task_status(task_id, TaskStatus.IN_PROGRESS); repo.close()
    console.print(f"[green]#{task_id} → In Bearbeitung[/green]" if ok else "[red]Nicht gefunden.[/red]")


@task_app.command("done")
def task_done(task_id: int):
    repo, _ = _repo()
    ok = repo.set_task_status(task_id, TaskStatus.DONE); repo.close()
    console.print(f"[green]#{task_id} → Erledigt[/green]" if ok else "[red]Nicht gefunden.[/red]")


# ── Findings ─────────────────────────────────────────────────────────────────
finding_app = typer.Typer(help="Findings verwalten")
app.add_typer(finding_app, name="finding", rich_help_panel="Befunde & Doku")


@finding_app.command("add")
def finding_add(title: str,
                severity: str = typer.Option("medium", "--sev", "--severity", help="info|low|medium|high|critical"),
                category: str = typer.Option("other", "--cat",
                                             help="misconfig|vuln|exposure|credential|infodisc|other"),
                description: Optional[str] = typer.Option(None, "--desc"),
                host_id: Optional[int] = typer.Option(None, "--host"),
                service_id: Optional[int] = typer.Option(None, "--service")):
    repo, _ = _repo()
    f = repo.add_finding(Finding(
        title=title, severity=SEVERITY_MAP.get(severity, Severity.MEDIUM),
        category=CATEGORY_MAP.get(category, FindingCategory.OTHER),
        description=description, host_id=host_id, service_id=service_id))
    repo.close()
    console.print(f"[green]Finding #{f.id}:[/green] [{f.severity.value}] {f.title}")


@finding_app.command("list")
def finding_list():
    repo, _ = _repo()
    findings = repo.list_findings()
    hosts = {h.id: h.address for h in repo.list_hosts()}
    services = {s.id: s for s in repo.list_services()}
    repo.close()
    table = Table(title="Findings")
    for c in ["ID", "Severity", "Titel", "Kategorie", "Status", "Host", "Auto"]:
        table.add_column(c)
    for f in findings:
        host_label = hosts.get(f.host_id, "-") if f.host_id else "-"
        if f.service_id and f.service_id in services:
            host_label = f"{host_label}:{services[f.service_id].port}"
        table.add_row(str(f.id),
                      f"[{SEV_STYLE[f.severity]}]{f.severity.value}[/]",
                      f.title, f.category.value, f.status.value, host_label,
                      "✓" if f.auto else "")
    console.print(table)


@finding_app.command("rm")
def finding_rm(finding_id: int,
               yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage löschen")):
    repo, _ = _repo()
    f = repo.get_finding(finding_id)
    if not f:
        console.print("[red]Nicht gefunden.[/red]"); repo.close(); raise typer.Exit(1)
    if not yes and not typer.confirm(f"Finding #{f.id} '{f.title}' wirklich löschen?"):
        console.print("Abgebrochen."); repo.close(); raise typer.Exit()
    ok = repo.delete_finding(finding_id); repo.close()
    console.print(f"[green]Finding #{finding_id} gelöscht.[/green]" if ok else "[red]Nicht gefunden.[/red]")


@finding_app.command("show")
def finding_show(finding_id: int):
    repo, _ = _repo()
    f = repo.get_finding(finding_id)
    repo.close()
    if not f:
        console.print("[red]Nicht gefunden.[/red]"); raise typer.Exit(1)
    console.print(Panel.fit(
        f"[bold]{f.title}[/bold]\n\n"
        f"Severity: {f.severity.value}\nKategorie: {f.category.value}\nStatus: {f.status.value}\n"
        f"Erkennung: {'automatisch' if f.auto else 'manuell'}\n\n{f.description or '_keine Beschreibung_'}",
        title=f"Finding #{f.id}"))


@finding_app.command("status")
def finding_status(finding_id: int,
                   status: str = typer.Argument(..., help="unverified|confirmed|exploited|fp|closed")):
    repo, _ = _repo()
    st = FSTATUS_MAP.get(status)
    if not st:
        console.print("[red]Unbekannter Status.[/red]"); repo.close(); raise typer.Exit(1)
    ok = repo.set_finding_status(finding_id, st.value); repo.close()
    console.print(f"[green]#{finding_id} → {st.value}[/green]" if ok else "[red]Nicht gefunden.[/red]")


# ── Finding-Template-Bibliothek ──────────────────────────────────────────────
template_app = typer.Typer(help="Wiederverwendbare Finding-Vorlagen (pro Projekt)")
app.add_typer(template_app, name="template", rich_help_panel="Befunde & Doku")


@template_app.command("seed")
def template_seed():
    """Befüllt die Bibliothek aus der geprüften Wissensbasis (idempotent)."""
    repo, _ = _repo()
    n = repo.seed_builtin_templates(); repo.close()
    if n:
        console.print(f"[green]{n} Vorlage(n) aus der Wissensbasis ergänzt.[/green]")
    else:
        console.print("[dim]Alle Standard-Vorlagen bereits vorhanden.[/dim]")


@template_app.command("list")
def template_list():
    """Listet alle Finding-Vorlagen des Projekts."""
    repo, _ = _repo()
    templates = repo.list_templates(); repo.close()
    if not templates:
        console.print("[dim]Keine Vorlagen. Mit `pentos template seed` vorbefüllen.[/dim]")
        return
    table = Table(title="Finding-Vorlagen")
    table.add_column("ID", justify="right")
    table.add_column("Key")
    table.add_column("Titel")
    table.add_column("Severity")
    table.add_column("CVSS")
    table.add_column("Quelle")
    for t in templates:
        table.add_row(str(t.id), t.key, t.title, t.severity.value,
                      (f"{t.cvss_score}" if t.cvss_score is not None else "-"),
                      "Standard" if t.builtin else "eigen")
    console.print(table)


@template_app.command("show")
def template_show(ident: str = typer.Argument(..., help="ID oder Key")):
    """Zeigt eine Vorlage im Detail."""
    repo, _ = _repo()
    t = repo.get_template(ident); repo.close()
    if not t:
        console.print("[red]Nicht gefunden.[/red]"); raise typer.Exit(1)
    cvss = f"{t.cvss_score} ({t.cvss_vector})" if t.cvss_score is not None else "—"
    body = (f"[bold]{t.title}[/bold]  [dim]({t.key})[/dim]\n\n"
            f"Severity: {t.severity.value}\nKategorie: {t.category.value}\nCVSS: {cvss}\n\n"
            f"[bold]Beschreibung[/bold]\n{t.description or '—'}\n\n"
            f"[bold]Remediation[/bold]\n{t.remediation or '—'}")
    if t.references:
        body += f"\n\n[bold]Referenzen[/bold]\n{t.references}"
    console.print(Panel.fit(body, title=f"Template #{t.id}"))


@template_app.command("add")
def template_add(
    key: str = typer.Argument(..., help="Eindeutiger Slug, z.B. 'open-redis'"),
    title: str = typer.Option(..., "--title", help="Titel der Vorlage"),
    severity: str = typer.Option("medium", "--severity", help="info|low|medium|high|critical"),
    category: str = typer.Option("other", "--cat", help="misconfig|vuln|exposure|credential|infodisc|other"),
    description: str = typer.Option("", "--desc", help="Beschreibung"),
    remediation: str = typer.Option("", "--fix", help="Behebung/Remediation"),
    cvss_score: Optional[float] = typer.Option(None, "--cvss", help="CVSS-Basisscore, z.B. 7.5"),
    cvss_vector: Optional[str] = typer.Option(None, "--vector", help="CVSS-Vektor"),
    references: Optional[str] = typer.Option(None, "--ref", help="Referenzen/URLs"),
):
    """Legt eine eigene Finding-Vorlage an."""
    repo, _ = _repo()
    if repo.get_template(key):
        console.print(f"[red]Key '{key}' existiert bereits.[/red]"); repo.close(); raise typer.Exit(1)
    t = repo.add_template(FindingTemplate(
        key=key, title=title,
        severity=SEVERITY_MAP.get(severity, Severity.MEDIUM),
        category=CATEGORY_MAP.get(category, FindingCategory.OTHER),
        description=description, remediation=remediation,
        cvss_score=cvss_score, cvss_vector=cvss_vector, references=references,
        builtin=False,
    )); repo.close()
    console.print(f"[green]Vorlage #{t.id} angelegt:[/green] {t.key} – {t.title}")


@template_app.command("rm")
def template_rm(ident: str = typer.Argument(..., help="ID oder Key"),
                yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage löschen")):
    """Löscht eine Vorlage."""
    repo, _ = _repo()
    t = repo.get_template(ident)
    if not t:
        console.print("[red]Nicht gefunden.[/red]"); repo.close(); raise typer.Exit(1)
    if not yes and not typer.confirm(f"Vorlage '{t.key}' wirklich löschen?"):
        console.print("Abgebrochen."); repo.close(); raise typer.Exit()
    repo.delete_template(t.id); repo.close()
    console.print(f"[green]Vorlage '{t.key}' gelöscht.[/green]")


@template_app.command("apply")
def template_apply(
    ident: str = typer.Argument(..., help="ID oder Key der Vorlage"),
    host: Optional[str] = typer.Option(None, "--host", help="Host-Adresse zum Verknüpfen"),
    suffix: str = typer.Option("", "--suffix", help="Titel-Zusatz, z.B. '(192.168.56.10)'"),
):
    """Erzeugt aus einer Vorlage ein konkretes Finding im Projekt."""
    repo, _ = _repo()
    host_id = None
    if host:
        h = repo.get_host_by_address(host) if hasattr(repo, "get_host_by_address") else None
        if h:
            host_id = h.id
        else:
            console.print(f"[yellow]Host '{host}' nicht im Projekt – Finding ohne Host-Bindung.[/yellow]")
    f = repo.instantiate_template(ident, host_id=host_id, title_suffix=suffix)
    repo.close()
    if not f:
        console.print("[red]Vorlage nicht gefunden.[/red]"); raise typer.Exit(1)
    console.print(f"[green]Finding #{f.id} aus Vorlage erstellt:[/green] [{f.severity.value}] {f.title}")


# ── Notizen ──────────────────────────────────────────────────────────────────
note_app = typer.Typer(help="Notizen verwalten")
app.add_typer(note_app, name="note", rich_help_panel="Befunde & Doku")


@note_app.command("add")
def note_add(title: str, body: str = typer.Option("", "--body"),
             category: Optional[str] = typer.Option(None, "--cat")):
    repo, _ = _repo()
    n = repo.add_note(Note(title=title, body=body, category=category)); repo.close()
    console.print(f"[green]Notiz #{n.id}:[/green] {n.title}")


@note_app.command("list")
def note_list():
    repo, _ = _repo()
    notes = repo.list_notes(); repo.close()
    table = Table(title="Notizen")
    for c in ["ID", "Titel", "Kategorie", "Erstellt"]:
        table.add_column(c)
    for n in notes:
        table.add_row(str(n.id), n.title, n.category or "-", n.created_at)
    console.print(table)


@note_app.command("show")
def note_show(note_id: int):
    """Zeigt den vollständigen Inhalt einer Notiz."""
    repo, _ = _repo()
    n = repo.get_note(note_id); repo.close()
    if not n:
        console.print("[red]Nicht gefunden.[/red]"); raise typer.Exit(1)
    console.print(Panel(
        n.body or "[dim]_leer_[/dim]",
        title=f"#{n.id} · {n.title}",
        subtitle=f"{n.category or '-'} · {n.created_at}"))


@note_app.command("rm")
def note_rm(note_id: int,
            yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage löschen")):
    repo, _ = _repo()
    if not yes and not typer.confirm(f"Notiz #{note_id} wirklich löschen?"):
        console.print("Abgebrochen."); repo.close(); raise typer.Exit()
    ok = repo.delete_note(note_id); repo.close()
    console.print(f"[green]Notiz #{note_id} gelöscht.[/green]" if ok else "[red]Nicht gefunden.[/red]")


# ── Loot ─────────────────────────────────────────────────────────────────────
loot_app = typer.Typer(help="Loot / Credentials verwalten")
app.add_typer(loot_app, name="loot", rich_help_panel="Befunde & Doku")


@loot_app.command("add")
def loot_add(label: str,
             type_: str = typer.Option("cred", "--type",
                                       help="cred|hash|token|cookie|apikey|sshkey|other"),
             value: Optional[str] = typer.Option(None, "--value"),
             host_id: Optional[int] = typer.Option(None, "--host"),
             source: Optional[str] = typer.Option(None, "--source")):
    repo, _ = _repo()
    l = repo.add_loot(Loot(label=label, type=LOOT_MAP.get(type_, LootType.OTHER),
                           value=value, host_id=host_id, source=source))
    repo.close()
    console.print(f"[green]Loot #{l.id}:[/green] [{l.type.value}] {l.label}")


@loot_app.command("list")
def loot_list():
    repo, _ = _repo()
    items = repo.list_loot(); repo.close()
    table = Table(title="Loot / Credentials")
    for c in ["ID", "Typ", "Label", "Wert", "Host", "Quelle"]:
        table.add_column(c)
    for l in items:
        table.add_row(str(l.id), l.type.value, l.label, l.value or "-",
                      str(l.host_id or "-"), l.source or "-")
    console.print(table)


@loot_app.command("rm")
def loot_rm(loot_id: int,
            yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage löschen")):
    repo, _ = _repo()
    if not yes and not typer.confirm(f"Loot #{loot_id} wirklich löschen?"):
        console.print("Abgebrochen."); repo.close(); raise typer.Exit()
    ok = repo.delete_loot(loot_id); repo.close()
    console.print(f"[green]Loot #{loot_id} gelöscht.[/green]" if ok else "[red]Nicht gefunden.[/red]")


# ── Evidence ─────────────────────────────────────────────────────────────────
evidence_app = typer.Typer(help="Beweise verwalten")
app.add_typer(evidence_app, name="evidence", rich_help_panel="Befunde & Doku")


@evidence_app.command("add")
def evidence_add(path: str,
                 kind: str = typer.Option("file", "--kind",
                                          help="file|screenshot|output|config|html"),
                 description: Optional[str] = typer.Option(None, "--desc"),
                 finding_id: Optional[int] = typer.Option(None, "--finding"),
                 host_id: Optional[int] = typer.Option(None, "--host")):
    repo, _ = _repo()
    e = repo.add_evidence(Evidence(path=path, kind=kind, description=description,
                                   finding_id=finding_id, host_id=host_id))
    repo.close()
    console.print(f"[green]Evidence #{e.id}:[/green] {e.kind} → {e.path}")


@evidence_app.command("list")
def evidence_list():
    repo, _ = _repo()
    items = repo.list_evidence(); repo.close()
    table = Table(title="Evidence")
    for c in ["ID", "Art", "Pfad", "Beschreibung", "Finding"]:
        table.add_column(c)
    for e in items:
        table.add_row(str(e.id), e.kind, e.path, e.description or "-", str(e.finding_id or "-"))
    console.print(table)


@evidence_app.command("rm")
def evidence_rm(evidence_id: int,
                yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage löschen")):
    repo, _ = _repo()
    if not yes and not typer.confirm(f"Evidence #{evidence_id} wirklich löschen?"):
        console.print("Abgebrochen."); repo.close(); raise typer.Exit()
    ok = repo.delete_evidence(evidence_id); repo.close()
    console.print(f"[green]Evidence #{evidence_id} gelöscht.[/green]" if ok else "[red]Nicht gefunden.[/red]")


# ── Wissensdatenbank ─────────────────────────────────────────────────────────
knowledge_app = typer.Typer(help="CTF/THM-Wissensdatenbank")
app.add_typer(knowledge_app, name="knowledge", rich_help_panel="Befunde & Doku")


@knowledge_app.command("add")
def knowledge_add(tag: str, title: str, body: str = typer.Option("", "--body")):
    repo, _ = _repo()
    k = repo.add_knowledge(KnowledgeEntry(tag=tag, title=title, body=body)); repo.close()
    console.print(f"[green]Wissen #{k.id}:[/green] [{k.tag}] {k.title}")


@knowledge_app.command("list")
def knowledge_list(tag: Optional[str] = typer.Option(None, "--tag")):
    repo, _ = _repo()
    items = repo.list_knowledge(tag); repo.close()
    table = Table(title="Wissensdatenbank")
    for c in ["ID", "Tag", "Titel"]:
        table.add_column(c)
    for k in items:
        table.add_row(str(k.id), k.tag, k.title)
    console.print(table)


# ── Journal ──────────────────────────────────────────────────────────────────
journal_app = typer.Typer(help="Journal / Timeline")
app.add_typer(journal_app, name="journal", rich_help_panel="Befunde & Doku")


@journal_app.command("show")
def journal_show():
    repo, _ = _repo()
    entries = repo.journal(); repo.close()
    table = Table(title="Journal")
    for c in ["Zeit", "Aktion", "Detail"]:
        table.add_column(c)
    for e in entries:
        table.add_row(e.ts, e.action, e.detail or "")
    console.print(table)


# ── Graph ────────────────────────────────────────────────────────────────────
graph_app = typer.Typer(help="Attack-Path-Graph")
app.add_typer(graph_app, name="graph", rich_help_panel="Reporting & Übersicht")


@graph_app.command("mermaid")
def graph_mermaid(out: Optional[Path] = typer.Option(None, "--out", help="Datei statt stdout")):
    repo, name = _repo()
    text = graph_mod.to_mermaid(repo); repo.close()
    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]Mermaid geschrieben:[/green] {out}")
    else:
        console.print(text)


@graph_app.command("dot")
def graph_dot(out: Optional[Path] = typer.Option(None, "--out", help="Datei statt stdout")):
    repo, name = _repo()
    text = graph_mod.to_dot(repo); repo.close()
    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]DOT geschrieben:[/green] {out}  "
                      f"([dim]Render: dot -Tpng {out} -o graph.png[/dim])")
    else:
        console.print(text)


# ── Obsidian ─────────────────────────────────────────────────────────────────
@app.command("obsidian", rich_help_panel="Reporting & Übersicht")
def obsidian_export(out: Optional[Path] = typer.Option(None, "--out",
                                                       help="Vault-Verzeichnis (Default: <projekt>/obsidian)")):
    """Exportiert die Projektdaten als verlinkten Obsidian-Vault."""
    repo, name = _repo()
    vault = out or (config.project_path(name) / "obsidian")
    obsidian_mod.export_vault(repo, vault, name); repo.close()
    console.print(f"[green]Obsidian-Vault exportiert:[/green] {vault}")


# ── Reporting ────────────────────────────────────────────────────────────────
@app.command("report", rich_help_panel="Reporting & Übersicht")
def report_build(out: Optional[Path] = typer.Option(None, "--out",
                                                    help="Default: <projekt>/reports/report.<ext>"),
                 explain: bool = typer.Option(False, "--explain",
                                              help="Lern-Report: erklärt Schritte/Befehle didaktisch"),
                 html: bool = typer.Option(False, "--html", help="Gebrandeter HTML-Report (druck-/PDF-fähig)"),
                 pdf: bool = typer.Option(False, "--pdf", help="Gebrandetes PDF (benötigt reportlab)")):
    """Erzeugt einen Report aus Findings, Journal, Aufgaben und Attack-Path.

    Formate: Markdown (Standard), --html (gebrandet), --pdf (gebrandet, reportlab).
    Mit --explain wird ein didaktischer Lern-Report erzeugt (nur Markdown).
    """
    repo, name = _repo()
    reports_dir = config.project_path(name) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    if explain and (html or pdf):
        console.print("[yellow]--explain erzeugt nur Markdown; --html/--pdf werden ignoriert.[/yellow]")

    # PDF
    if pdf and not explain:
        target = out or (reports_dir / "report.pdf")
        try:
            export_mod.build_pdf(repo, name, target, cfg=config.load_config())
        except RuntimeError as exc:
            repo.close()
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)
        repo.log("PDF-Report erstellt", str(target))
        console.print(f"[green]PDF-Report erstellt:[/green] {target}")

    # HTML
    if html and not explain:
        target = out if (out and out.suffix == ".html") else (reports_dir / "report.html")
        target.write_text(export_mod.build_html(repo, name, cfg=config.load_config()), encoding="utf-8")
        repo.log("HTML-Report erstellt", str(target))
        console.print(f"[green]HTML-Report erstellt:[/green] {target}")

    # Markdown (Standard oder Lern-Report) – immer, wenn weder html noch pdf allein gewählt
    if explain or not (html or pdf):
        if explain:
            md = report_mod.build_learning_markdown(repo, name)
            target = out or (reports_dir / "learning-report.md")
            label = "Lern-Report"
        else:
            md = report_mod.build_markdown(repo, name)
            target = out or (reports_dir / "report.md")
            label = "Report"
        target.write_text(md, encoding="utf-8")
        repo.log(f"{label} erstellt", str(target))
        console.print(f"[green]{label} erstellt:[/green] {target}")

    repo.close()


# ── Dashboard ─────────────────────────────────────────────────────────────────
_SEV_BAR = {
    Severity.CRITICAL: "red", Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "grey50",
}


def _bar(n: int, total: int, color: str, width: int = 16) -> str:
    filled = int(round((n / total) * width)) if total else 0
    return f"[{color}]" + "█" * filled + "[/]" + "[grey30]" + "░" * (width - filled) + "[/]"


@app.command("dashboard", rich_help_panel="Reporting & Übersicht")
def dashboard_cmd():
    """Kompakte Übersicht des aktiven Projekts (Findings, Tasks, Loot, letzte Läufe)."""
    repo, name = _repo()
    hosts = repo.list_hosts()
    services = repo.list_services()
    findings = repo.list_findings()
    tasks = repo.list_tasks()
    loot = repo.list_loot()
    runs = repo.list_runs()
    repo.close()

    sev_count = {s: 0 for s in Severity}
    for f in findings:
        sev_count[f.severity] += 1
    total_f = len(findings)
    done = sum(1 for t in tasks if t.status == TaskStatus.DONE)
    inprog = sum(1 for t in tasks if t.status == TaskStatus.IN_PROGRESS)
    total_t = len(tasks)

    # Kennzahlen
    stats = (
        f"[bold cyan]{name}[/bold cyan]\n\n"
        f"Hosts     [bold]{len(hosts)}[/]\n"
        f"Services  [bold]{len(services)}[/]\n"
        f"Findings  [bold]{total_f}[/]\n"
        f"Loot      [bold]{len(loot)}[/]\n"
        f"Runs      [bold]{len(runs)}[/]"
    )

    # Findings nach Severity
    sev_rows = []
    for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        sev_rows.append(f"{s.value:<9} {_bar(sev_count[s], max(total_f, 1), _SEV_BAR[s])} {sev_count[s]}")
    sev_panel = "\n".join(sev_rows) if total_f else "[grey50]Keine Findings[/]"

    # Aufgaben-Fortschritt
    pct = int(round((done / total_t) * 100)) if total_t else 0
    task_panel = (
        f"Fortschritt {_bar(done, max(total_t, 1), 'green')} {pct}%\n\n"
        f"[green]Erledigt[/]      {done}\n"
        f"[yellow]In Arbeit[/]     {inprog}\n"
        f"[grey50]Offen[/]         {total_t - done - inprog}"
    )

    console.print(Columns([
        Panel(stats, title="Projekt", width=28),
        Panel(sev_panel, title="Findings", width=40),
        Panel(task_panel, title="Aufgaben", width=34),
    ], equal=False))

    # Offene High/Critical hervorheben
    crit = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.status != FindingStatus.CLOSED]
    if crit:
        lines = [f"[{_SEV_BAR[f.severity]}]●[/] [{f.severity.value}] {f.title}  "
                 f"[grey50]({f.status.value})[/]" for f in crit[:8]]
        console.print(Panel("\n".join(lines), title="⚠ Priorität", border_style="red"))

    # Letzte Läufe
    if runs:
        table = Table(title="Letzte Läufe", show_edge=False)
        for c in ["Zeit", "Tool", "Ziel", "RC"]:
            table.add_column(c)
        for r in runs[-5:]:
            table.add_row(r.started_at, r.tool, r.target or "-", str(r.returncode))
        console.print(table)


# ── KI-Mentor ────────────────────────────────────────────────────────────────
ai_app = typer.Typer(help="KI-Mentor (lokal, nur Analyse)")
app.add_typer(ai_app, name="ai", rich_help_panel="KI & Integration")


@ai_app.command("status")
def ai_status():
    """Prüft, ob das konfigurierte KI-Backend erreichbar ist (inkl. Modelle)."""
    info = AIClient(config.load_config()["ai"]).ping()
    ok = "[green]erreichbar[/green]" if info["ok"] else "[red]nicht erreichbar[/red]"
    lines = [
        f"Provider:  {info['provider']}",
        f"Base-URL:  {info['base_url'] or '-'}",
        f"Modell:    {info['model'] or '-'}",
        f"Status:    {ok}",
    ]
    if info["ok"]:
        models = [m for m in info["models"] if m]
        lines.append(f"Modelle:   {', '.join(models) if models else '(keine gefunden)'}")
        if info["model"] and models and info["model"] not in models:
            lines.append(f"[yellow]Hinweis: '{info['model']}' nicht installiert — "
                         f"z.B. 'ollama pull {info['model']}'.[/yellow]")
    if info["error"]:
        lines.append(f"[red]Fehler: {info['error']}[/red]")
        if info["provider"] != "none":
            lines.append("[dim]Checkliste: Ollama mit OLLAMA_HOST=0.0.0.0 gestartet? "
                         "Port 11434 in der Firewall offen? IP/Route von der VM erreichbar "
                         "(curl http://<ip>:11434/api/tags)?[/dim]")
        else:
            lines.append("[dim]Backend aktivieren: pentos ai config --provider ollama "
                         "--base-url http://<ip>:11434 --model <modell>[/dim]")
    console.print(Panel("\n".join(lines), title="KI-Status"))


@ai_app.command("config")
def ai_config(provider: Optional[str] = typer.Option(None, "--provider",
                                                     help="ollama | lmstudio | openai | none"),
              base_url: Optional[str] = typer.Option(None, "--base-url",
                                                     help="z.B. http://192.168.1.20:11434"),
              model: Optional[str] = typer.Option(None, "--model", help="z.B. llama3.1"),
              embed_model: Optional[str] = typer.Option(None, "--embed-model",
                                                         help="Embedding-Modell für RAG, z.B. nomic-embed-text"),
              timeout: Optional[int] = typer.Option(None, "--timeout"),
              api_key_env: Optional[str] = typer.Option(None, "--api-key-env"),
              advisor: Optional[bool] = typer.Option(None, "--advisor/--no-advisor",
                                                     help="Aktive Vorschläge an/aus (Human-in-the-Loop)"),
              check: bool = typer.Option(True, "--check/--no-check",
                                         help="Nach dem Speichern Erreichbarkeit prüfen")):
    """Setzt die KI-Anbindung (schreibt in config.yaml) – ohne YAML-Editieren."""
    valid = {"ollama", "lmstudio", "openai", "none"}
    if provider and provider not in valid:
        console.print(f"[red]Unbekannter Provider '{provider}'.[/red] Erlaubt: {', '.join(sorted(valid))}")
        raise typer.Exit(1)
    cfg = config.load_config()
    ai = dict(cfg.get("ai", {}))
    if provider: ai["provider"] = provider
    if base_url: ai["base_url"] = base_url
    if model: ai["model"] = model
    if embed_model: ai["embed_model"] = embed_model
    if timeout: ai["timeout"] = timeout
    if api_key_env: ai["api_key_env"] = api_key_env
    if advisor is not None: ai["advisor"] = advisor
    cfg["ai"] = ai
    path = config.save_config(cfg)
    console.print(f"[green]Config gespeichert:[/green] {path}")
    console.print(f"  provider={ai.get('provider')}  base_url={ai.get('base_url')}  "
                  f"model={ai.get('model')}  embed_model={ai.get('embed_model')}")
    if check and ai.get("provider") not in (None, "none"):
        ai_status()


@ai_app.command("explain-finding")
def ai_explain_finding(finding_id: int):
    repo, _ = _repo()
    f = repo.get_finding(finding_id)
    repo.close()
    if not f:
        console.print("[red]Finding nicht gefunden.[/red]"); raise typer.Exit(1)
    client = AIClient(config.load_config()["ai"])
    console.print(Panel(client.explain_finding(f), title=f"KI-Mentor · Finding #{finding_id}"))


@ai_app.command("enum")
def ai_enum(service_id: int):
    repo, _ = _repo()
    svc = repo.get_service(service_id)
    repo.close()
    if not svc:
        console.print("[red]Service nicht gefunden.[/red]"); raise typer.Exit(1)
    client = AIClient(config.load_config()["ai"])
    console.print(Panel(client.enumeration_ideas(svc),
                        title=f"KI-Mentor · Enumeration {svc.port}/{svc.protocol}"))


def _ai_client() -> AIClient:
    cfg = config.load_config()
    return AIClient(cfg["ai"], language=cfg.get("language", "de"))


@ai_app.command("index")
def ai_index():
    """Baut den RAG-Index über die Projektdaten neu (Embeddings via KI-Backend)."""
    from .. import rag
    client = _ai_client()
    if not client.available():
        console.print("[red]Kein KI-Backend konfiguriert.[/red] Siehe [cyan]pentos ai config[/cyan].")
        raise typer.Exit(1)
    repo, name = _repo()
    console.print(f"[dim]Indexiere Projekt '{name}' mit Embedding-Modell "
                  f"'{client.embed_model}' …[/dim]")
    ok, fail = rag.index_project(repo, client.embed)
    repo.close()
    if ok == 0:
        console.print("[red]Keine Embeddings erzeugt.[/red] Backend erreichbar? "
                      f"Modell '{client.embed_model}' installiert? "
                      f"([cyan]ollama pull {client.embed_model}[/cyan])")
        raise typer.Exit(1)
    msg = f"[green]Index aufgebaut:[/green] {ok} Einträge"
    if fail:
        msg += f" ([yellow]{fail} übersprungen[/yellow])"
    console.print(msg)


@ai_app.command("ask")
def ai_ask(frage: str,
           k: int = typer.Option(5, "--k", help="Anzahl Kontext-Treffer")):
    """Beantwortet eine Frage über die Projektdaten (RAG, mit Quellenangabe)."""
    from .. import rag
    client = _ai_client()
    if not client.available():
        console.print("[red]Kein KI-Backend konfiguriert.[/red] Siehe [cyan]pentos ai config[/cyan].")
        raise typer.Exit(1)
    repo, name = _repo()
    if repo.rag_count() == 0:
        repo.close()
        console.print("[yellow]Index ist leer.[/yellow] Erst aufbauen: [cyan]pentos ai index[/cyan]")
        raise typer.Exit(1)
    qvec = client.embed(frage)
    if not qvec:
        repo.close()
        console.print("[red]Frage konnte nicht eingebettet werden[/red] (Backend/Embedding-Modell?).")
        raise typer.Exit(1)
    hits = rag.search(repo, qvec, k=k)
    repo.close()
    contexts = [f"{h.label()}: {h.chunk}" for h in hits]
    answer = client.answer_with_context(frage, contexts)
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar?).")
        raise typer.Exit(1)
    console.print(Panel(answer, title=f"KI · Frag dein Projekt ({name})"))
    if hits:
        srcs = "  ".join(f"[dim]{h.label()} ({h.score:.2f})[/dim]" for h in hits)
        console.print(srcs)


def _confirm_ai_send(client: AIClient, what: str, yes: bool) -> bool:
    """Fragt vor dem Senden an die KI nach – warnt, wenn Daten den Rechner verlassen."""
    if not client.available():
        console.print("[red]Kein KI-Backend konfiguriert.[/red] Siehe [cyan]pentos ai config[/cyan].")
        return False
    if yes:
        return True
    if client.provider in ("ollama", "lmstudio"):
        # lokal -> Daten bleiben auf dem Rechner; leise Bestätigung
        return typer.confirm(f"{what} an lokales Modell ({client.provider}) senden?", default=True)
    # Cloud -> deutliche Warnung
    console.print(f"[yellow]Achtung:[/yellow] {what} wird an einen externen Anbieter "
                  f"([bold]{client.provider}[/bold]) gesendet – Daten verlassen deinen Rechner.")
    return typer.confirm("Wirklich senden?", default=False)


@ai_app.command("analyze")
def ai_analyze(
    file: Optional[Path] = typer.Argument(None, exists=True, readable=True,
                                          help="Datei mit Scan/Log/Output (oder --text)"),
    text: Optional[str] = typer.Option(None, "--text", help="Text direkt übergeben"),
    label: str = typer.Option("Output", "--as", help="Was ist das? z.B. nmap, ffuf, log"),
    save: bool = typer.Option(False, "--save", help="Ergebnis als Notiz im Projekt speichern"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden"),
):
    """Füttert die KI mit einem Scan/Log/Output und bekommt eine Deutung + nächste Schritte.

    Beispiele:
      pentos ai analyze scan.txt --as nmap
      cat nikto.txt | pentos ai analyze --as nikto
      pentos ai analyze --text "$(ss -tlnp)" --as ports
    """
    # Eingabe sammeln: Datei, --text, oder stdin
    content = None
    if text is not None:
        content = text
    elif file is not None:
        content = file.read_text(encoding="utf-8", errors="ignore")
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
    if not content or not content.strip():
        console.print("[red]Keine Eingabe.[/red] Datei, --text oder per Pipe (stdin) übergeben.")
        raise typer.Exit(1)

    client = _ai_client()
    cfg = config.load_config()
    if not _confirm_ai_send(client, f"'{label}'-Ausgabe ({len(content)} Zeichen)", yes):
        console.print("Abgebrochen.")
        raise typer.Exit()

    advisor = bool(cfg["ai"].get("advisor", True))
    with console.status("[cyan]KI analysiert…[/cyan]"):
        answer = client.interpret_output(label, content, advisor=advisor)
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar? `pentos ai status`).")
        raise typer.Exit(1)
    console.print(Panel(answer, title=f"KI · Analyse ({label})"))
    if save:
        repo, _ = _repo()
        repo.add_note(Note(title=f"KI-Analyse · {label}", body=answer, category="ai"))
        repo.close()
        console.print("[green]Als Notiz gespeichert.[/green]")


@ai_app.command("next")
def ai_next(yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden")):
    """Schlägt auf Basis des aktuellen Projektstands die nächsten sinnvollen Schritte vor."""
    repo, name = _repo()
    hosts = repo.list_hosts()
    services = repo.list_services()
    findings = repo.list_findings()
    notes = repo.list_notes()
    # kompakten Stand bauen
    lines = [f"Projekt: {name}", f"Hosts: {len(hosts)}, Services: {len(services)}, "
             f"Findings: {len(findings)}, Notizen: {len(notes)}", ""]
    for h in hosts:
        svcs = [s for s in services if s.host_id == h.id]
        lines.append(f"Host {h.address} ({h.hostname or '-'}, OS {h.os_guess or '?'}):")
        for s in svcs:
            lines.append(f"  - {s.port}/{s.protocol} {s.name or ''} {s.product or ''} {s.version or ''}".rstrip())
    if findings:
        lines.append("\nFindings:")
        for f in findings:
            lines.append(f"  - [{f.severity.value}] {f.title}")
    state = "\n".join(lines)
    repo.close()

    client = _ai_client()
    cfg = config.load_config()
    if not _confirm_ai_send(client, "den Projektstand", yes):
        console.print("Abgebrochen.")
        raise typer.Exit()
    advisor = bool(cfg["ai"].get("advisor", True))
    with console.status("[cyan]KI denkt über die nächsten Schritte nach…[/cyan]"):
        answer = client.next_steps(state, advisor=advisor)
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar? `pentos ai status`).")
        raise typer.Exit(1)
    console.print(Panel(answer, title=f"KI · Nächste Schritte ({name})"))


@app.command("serve", rich_help_panel="KI & Integration")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind-Adresse (Default nur lokal)"),
    port: int = typer.Option(8787, "--port", "-p", help="Port"),
    project: Optional[str] = typer.Option(None, "--project", help="Startprojekt (sonst aktives/erstes)"),
):
    """Startet das Web-Dashboard (lokal, read-only Ansicht deines Workspace).

    Standardmässig nur über 127.0.0.1 erreichbar – keine offene Angriffsfläche.
    Benötigt die Web-Extras: pip install -e ".[web]"
    """
    try:
        from ..web import server as web_server
    except ModuleNotFoundError:
        console.print('[red]Web-Extras fehlen.[/red] Installiere: [cyan]pip install -e ".[web]"[/cyan]')
        raise typer.Exit(1)
    proj = project
    if proj is None:
        try:
            proj = config.get_active_project()
        except Exception:
            proj = None
    url = f"http://{host}:{port}"
    console.print(Panel.fit(
        f"[bold]PentOS Dashboard[/bold]\n"
        f"URL:      [cyan]{url}[/cyan]\n"
        f"Projekt:  {proj or '(erstes verfügbares)'}\n"
        f"Bind:     {host}:{port}  ([green]nur lokal[/green])\n\n"
        f"[dim]Stoppen mit Strg+C[/dim]",
        title="serve"))
    try:
        web_server.serve(project=proj, host=host, port=port)
    except ModuleNotFoundError:
        console.print('[red]Web-Extras fehlen.[/red] Installiere: [cyan]pip install -e ".[web]"[/cyan]')
        raise typer.Exit(1)
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard gestoppt.[/dim]")


@app.command("mcp", rich_help_panel="KI & Integration")
def mcp_cmd():
    """Startet den MCP-Server (stdio) – macht den Workspace für Claude Code/Cursor lesbar.

    Wird normalerweise nicht von Hand gestartet, sondern vom MCP-Client als
    Subprozess. Alle MCP-Tools sind lesend/analysierend – nichts wird ausgeführt.
    Benötigt die MCP-Extras: pip install -e ".[mcp]"

    Client-Konfiguration (z.B. Claude Code / Cursor), Beispiel:
      {"mcpServers": {"pentos": {"command": "pentos", "args": ["mcp"]}}}
    """
    try:
        from .. import mcp_server
    except ModuleNotFoundError:
        console.print('[red]MCP-Extras fehlen.[/red] Installiere: [cyan]pip install -e ".[mcp]"[/cyan]')
        raise typer.Exit(1)
    # WICHTIG: keine Konsolenausgabe auf stdout – stdio gehört dem MCP-Protokoll.
    try:
        mcp_server.serve()
    except ModuleNotFoundError:
        console.print('[red]MCP-Extras fehlen.[/red] Installiere: [cyan]pip install -e ".[mcp]"[/cyan]')
        raise typer.Exit(1)


# ── Runner-Layer (Opt-in Tool-Ausführung) ────────────────────────────────────
@app.command("tools", rich_help_panel="Recon & Import")
def tools_cmd():
    """Listet verfügbare Tools des Runners (inkl. Installations-Check)."""
    import shutil
    table = Table(title="Runner – verfügbare Tools")
    for c in ["Tool", "Kategorie", "Binary", "Installiert", "Wordlist", "Parser"]:
        table.add_column(c)
    for name in runner_registry.names():
        spec = runner_registry.get(name)
        present = "[green]✓[/green]" if shutil.which(spec.binary) else "[red]✗[/red]"
        table.add_row(spec.name, spec.category, spec.binary, present,
                      "ja" if spec.needs_wordlist else "-", spec.parser or "capture")
    console.print(table)
    console.print("[dim]Start: pentos run <tool> <ziel>   ·   Vorschau: --dry-run[/dim]")


@app.command("run", rich_help_panel="Recon & Import")
def run_cmd(tool: str = typer.Argument(..., help="Tool-Name (siehe: pentos tools)"),
            target: str = typer.Argument(..., help="Ziel: IP, Host oder URL"),
            profile: Optional[str] = typer.Option(None, "--profile",
                                                   help="Profil (z.B. nmap: basic|standard|full|custom)"),
            args: Optional[str] = typer.Option(None, "--args", help="Zusätzliche Tool-Argumente"),
            wordlist: Optional[str] = typer.Option(None, "--wordlist", help="Wordlist überschreiben"),
            timeout: Optional[int] = typer.Option(None, "--timeout", help="Timeout in Sekunden"),
            dry_run: bool = typer.Option(False, "--dry-run", help="Nur das Kommando zeigen"),
            shell: bool = typer.Option(False, "--shell",
                                       help="Shell-Modus für interaktive Tools (z.B. smbclient -c '...'). "
                                            "ACHTUNG: interpretiert Shell-Metazeichen."),
            force: bool = typer.Option(False, "--force", help="Scope-Prüfung übergehen")):
    """Führt ein Tool aus und übernimmt die Ausgabe in den Workspace (opt-in)."""
    spec = runner_registry.get(tool)
    if not spec:
        console.print(f"[red]Unbekanntes Tool '{tool}'.[/red] Liste: [cyan]pentos tools[/cyan]")
        raise typer.Exit(1)
    repo, name = _repo()
    host = runner_base.host_of(target)
    if spec.network and not force and not dry_run and repo.scope_defined() and not repo.in_scope(host):
        console.print(f"[red]'{host}' liegt nicht im definierten Scope.[/red] "
                      f"Mit [cyan]--force[/cyan] überschreiben oder erweitern: "
                      f"[cyan]pentos scope add {host}[/cyan]")
        repo.close(); raise typer.Exit(2)
    if shell and not dry_run:
        console.print("[yellow]⚠ Shell-Modus:[/yellow] Argumente werden durch die Shell "
                      "interpretiert (Metazeichen, Quoting). Nur mit vertrauenswürdiger Eingabe verwenden.")
        if not args:
            console.print("[red]--shell benötigt --args \"...\" mit dem vollständigen Tool-Aufruf.[/red]")
            repo.close(); raise typer.Exit(1)
    extra = shlex.split(args) if (args and not shell) else None
    scans_dir = config.project_path(name) / "scans"
    try:
        result = runner_base.run_tool(spec, target, scans_dir, extra_args=extra,
                                      wordlist=wordlist, timeout=timeout, dry_run=dry_run,
                                      profile=profile, shell=shell, raw_args=args)
    except runner_base.RunnerError as e:
        console.print(f"[red]{e}[/red]"); repo.close(); raise typer.Exit(1)

    if result.dry:
        repo.close()
        console.print(Panel.fit(" ".join(result.command), title="Dry-Run (kein Lauf)"))
        return

    summary = runner_parsers.ingest(repo, spec, target, result, name)
    repo.close()
    status = "[yellow]Timeout[/yellow]" if result.timed_out else f"rc={result.returncode}"
    console.print(Panel.fit(
        f"[bold]{spec.name}[/bold] → {target}   ({status}, {result.duration_ms} ms)\n"
        f"Ausgabe: {result.output_path}\n"
        f"Neu: {summary['hosts']} Hosts · {summary['services']} Services · "
        f"{summary['tasks']} Tasks · {summary['findings']} Findings · "
        f"{summary['loot']} Loot · {summary['notes']} Notizen · {summary['evidence']} Evidence",
        title="Run abgeschlossen"))


# ── Sweep: geführte Recon-/Enum-Kette (regelbasiert, keine Auto-Exploitation) ─
_SWEEP_SAFE_CATEGORIES = {"web", "smb", "snmp", "ldap", "dns", "vuln", "recon"}
_SWEEP_AUTO_DENY = {"gobuster", "ffuf", "nikto", "rustscan"}  # redundant/heavy -> nur vorschlagen
_SWEEP_TAG = {"bruteforce": "Brute-Force", "exploit": "Exploit", "cracking": "Cracking"}


def _sweep_is_auto(spec) -> bool:
    """Sichere, ohne Zusatzargumente sinnvolle Recon/Enum-Tools laufen automatisch."""
    if spec.category not in _SWEEP_SAFE_CATEGORIES or spec.name in _SWEEP_AUTO_DENY:
        return False
    if spec.needs_wordlist and not spec.default_wordlist:
        return False
    return True


def _run_and_ingest(repo, name, spec, target, profile=None, timeout=None) -> bool:
    scans_dir = config.project_path(name) / "scans"
    try:
        result = runner_base.run_tool(spec, target, scans_dir, profile=profile, timeout=timeout)
    except runner_base.RunnerError as e:
        console.print(f"   [red]{e}[/red]")
        return False
    s = runner_parsers.ingest(repo, spec, target, result, name)
    status = "Timeout" if result.timed_out else f"rc={result.returncode}"
    console.print(f"   [green]✓[/green] {spec.name} ({status}, {result.duration_ms} ms) – "
                  f"+{s['findings']}F +{s['loot']}L +{s['notes']}N +{s['services']}S +{s['tasks']}T")
    return True


@app.command("sweep", rich_help_panel="Recon & Import")
def sweep_cmd(target: str = typer.Argument(..., help="Ziel: IP oder Host"),
              run: bool = typer.Option(False, "--run",
                                       help="Sichere Enum-Tools automatisch ausführen (mit Rückfrage)"),
              profile: Optional[str] = typer.Option(None, "--profile",
                                                    help="nmap-Profil (basic|standard|full|custom)"),
              timeout: Optional[int] = typer.Option(None, "--timeout"),
              yes: bool = typer.Option(False, "--yes", "-y", help="Alle Rückfragen automatisch bestätigen"),
              force: bool = typer.Option(False, "--force", help="Scope-Prüfung übergehen")):
    """Geführte Recon-/Enum-Kette: nmap, dann pro Dienst die nächsten Tools.

    Sichere Recon/Enum-Tools können mit --run automatisch laufen (je Schritt eine
    Rückfrage). Brute-Force/Exploits werden NIE automatisch ausgeführt – nur vorgeschlagen.
    """
    host = runner_base.host_of(target)
    repo, name = _repo()
    if not force and repo.scope_defined() and not repo.in_scope(host):
        console.print(f"[red]'{host}' liegt nicht im Scope.[/red] "
                      f"[cyan]pentos scope add {host}[/cyan] oder --force")
        repo.close(); raise typer.Exit(2)

    console.rule(f"[bold]Sweep[/bold] · {host}")

    # Schritt 1: nmap (Basis-Recon)
    nmap_spec = runner_registry.get("nmap")
    if run:
        if yes or typer.confirm(f"Schritt 1: nmap{' ' + profile if profile else ''} gegen {host}?", default=True):
            _run_and_ingest(repo, name, nmap_spec, host, profile=profile, timeout=timeout)
    else:
        prof = f" --profile {profile}" if profile else ""
        console.print(f"[bold]Schritt 1 – Basis-Recon:[/bold]\n  [cyan]pentos run nmap {host}{prof}[/cyan]")

    # Services des Ziels laden
    hosts = {h.address: h for h in repo.list_hosts()}
    hid = hosts[host].id if host in hosts else None
    services = [s for s in repo.list_services() if s.host_id == hid] if hid else []
    if not services:
        msg = "nmap lieferte keine Services." if run else \
            "Noch keine Services bekannt – erst nmap laufen lassen oder [cyan]--run[/cyan] nutzen."
        console.print(f"[dim]{msg}[/dim]")
        repo.close(); return

    # Plan: auto vs. nur-vorschlagen
    seen: set = set()
    auto: list = []
    suggest: list = []
    for svc in services:
        for tool in recommend.tools_for(svc):
            spec = runner_registry.get(tool)
            if not spec:
                continue
            tgt = f"http://{host}" if recommend.is_web(svc) else host
            key = (tool, tgt)
            if key in seen:
                continue
            seen.add(key)
            (auto if _sweep_is_auto(spec) else suggest).append((spec, tgt, svc))

    # Auto-Enumeration
    console.print(f"\n[bold]Schritt 2 – Auto-Enumeration[/bold] ({len(auto)} sichere Recon/Enum-Schritte):")
    for spec, tgt, svc in auto:
        if run:
            if yes or typer.confirm(f"→ {spec.name} gegen {tgt} (Dienst {svc.name or svc.port})?", default=True):
                _run_and_ingest(repo, name, spec, tgt, timeout=timeout)
            else:
                console.print(f"   [dim]übersprungen: {spec.name}[/dim]")
        else:
            console.print(f"  [cyan]pentos run {spec.name} {tgt}[/cyan]   [dim]({svc.name or svc.port})[/dim]")

    # Nur-Vorschläge (nie automatisch)
    if suggest:
        console.print(f"\n[bold]Schritt 3 – Manuell prüfen[/bold] "
                      f"({len(suggest)}; Brute-Force/Exploit/Alternativen – nie automatisch):")
        for spec, tgt, svc in suggest:
            tag = _SWEEP_TAG.get(spec.category, "Alternative")
            console.print(f"  [yellow]pentos run {spec.name} {tgt}[/yellow]   "
                          f"[dim]({tag}; ggf. --args/--shell)[/dim]")

    console.print("\n[dim]Methodik & GUI-Tools (Burp, ZAP, BloodHound, wpscan …): "
                  "[cyan]pentos playbook show web|ad[/cyan][/dim]")
    repo.close()


@app.command("runs", rich_help_panel="Reporting & Übersicht")
def runs_cmd():
    """Zeigt die Historie ausgeführter Tools."""
    repo, _ = _repo()
    repo, _ = _repo()
    items = repo.list_runs(); repo.close()
    table = Table(title="Run-Historie")
    for c in ["ID", "Zeit", "Tool", "Ziel", "RC", "Dauer (ms)", "Ausgabe"]:
        table.add_column(c)
    for r in items:
        table.add_row(str(r.id), r.started_at, r.tool, r.target or "-",
                      str(r.returncode), str(r.duration_ms or "-"), r.output_path or "-")
    console.print(table)


# ── Playbooks / Methodik ──────────────────────────────────────────────────────
playbook_app = typer.Typer(help="Methodik-Playbooks (Checklisten)")
app.add_typer(playbook_app, name="playbook", rich_help_panel="Recon & Import")

_KIND_ICON = {"pentos": "🔧", "external": "🌐", "manual": "📝"}


@playbook_app.command("list")
def playbook_list():
    """Verfügbare Playbooks anzeigen."""
    pbs = playbooks_mod.load_all()
    if not pbs:
        console.print("[dim]Keine Playbooks gefunden.[/dim]"); return
    table = Table(title="Playbooks")
    for c in ["Name", "Titel", "Schritte"]:
        table.add_column(c)
    for name, pb in sorted(pbs.items()):
        table.add_row(name, pb.title, str(len(pb.steps)))
    console.print(table)
    console.print("[dim]Legende: 🔧 PentOS-Tool · 🌐 externes Tool · 📝 manuell[/dim]")
    console.print("[dim]Details: [cyan]pentos playbook show <name> [--target <ziel>][/cyan][/dim]")


@playbook_app.command("show")
def playbook_show(name: str,
                  target: Optional[str] = typer.Option(None, "--target",
                                                       help="Ziel in Kommandos einsetzen")):
    """Playbook als Checkliste anzeigen (mit Fortschritt)."""
    pb = playbooks_mod.get(name)
    if not pb:
        console.print(f"[red]Playbook '{name}' nicht gefunden.[/red]"); raise typer.Exit(1)
    repo, _ = _repo()
    prog = repo.playbook_progress(name); repo.close()
    done = sum(1 for s in pb.steps if s.id in prog)
    lines: list[str] = []
    if pb.description:
        lines.append(f"[dim]{pb.description}[/dim]\n")
    for s in pb.steps:
        st = prog.get(s.id)
        mark = "[green]✓[/green]" if st and st["status"] == "done" else \
               "[yellow]»[/yellow]" if st and st["status"] == "skip" else "[dim]○[/dim]"
        icon = _KIND_ICON.get(s.kind, "")
        lines.append(f"{mark} {icon} [bold]{s.id}[/bold] — {s.title}")
        if s.tool:
            lines.append(f"      Tool: {s.tool}")
        cmd = playbooks_mod.render_command(s.command, target)
        if cmd:
            lines.append(f"      [cyan]{cmd}[/cyan]")
        if s.when:
            lines.append(f"      [dim]wenn: {s.when}[/dim]")
        if s.why:
            lines.append(f"      [dim]{s.why}[/dim]")
        if st and st["note"]:
            lines.append(f"      [dim]Notiz: {st['note']}[/dim]")
    console.print(Panel("\n".join(lines), title=f"{pb.title}  ({done}/{len(pb.steps)})"))
    console.print(f"[dim]Abhaken: [cyan]pentos playbook check {name} <step-id>[/cyan][/dim]")


@playbook_app.command("check")
def playbook_check(name: str, step_id: str,
                   note: Optional[str] = typer.Option(None, "--note"),
                   skip: bool = typer.Option(False, "--skip", help="Als übersprungen markieren")):
    """Einen Schritt als erledigt (oder übersprungen) markieren."""
    pb = playbooks_mod.get(name)
    if not pb:
        console.print(f"[red]Playbook '{name}' nicht gefunden.[/red]"); raise typer.Exit(1)
    if step_id not in {s.id for s in pb.steps}:
        console.print(f"[red]Schritt '{step_id}' existiert nicht in '{name}'.[/red]")
        raise typer.Exit(1)
    repo, _ = _repo()
    repo.set_playbook_step(name, step_id, "skip" if skip else "done", note); repo.close()
    console.print(f"[green]{name}/{step_id} → {'übersprungen' if skip else 'erledigt'}.[/green]")


@playbook_app.command("uncheck")
def playbook_uncheck(name: str, step_id: str):
    """Markierung eines Schritts entfernen."""
    repo, _ = _repo()
    ok = repo.unset_playbook_step(name, step_id); repo.close()
    console.print(f"[green]{name}/{step_id} zurückgesetzt.[/green]" if ok else "[dim]Nichts zu tun.[/dim]")


@playbook_app.command("status")
def playbook_status():
    """Fortschritt aller Playbooks im aktiven Projekt."""
    pbs = playbooks_mod.load_all()
    repo, _ = _repo()
    table = Table(title="Playbook-Fortschritt")
    for c in ["Name", "Titel", "Fortschritt"]:
        table.add_column(c)
    for name, pb in sorted(pbs.items()):
        prog = repo.playbook_progress(name)
        done = sum(1 for s in pb.steps if s.id in prog)
        total = len(pb.steps)
        pct = int(done / total * 100) if total else 0
        bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
        table.add_row(name, pb.title, f"{bar} {done}/{total}")
    repo.close()
    console.print(table)


# ── Scope ────────────────────────────────────────────────────────────────────
scope_app = typer.Typer(help="Scope (erlaubte Ziele) verwalten")
app.add_typer(scope_app, name="scope", rich_help_panel="Workspace")


@scope_app.command("add")
def scope_add(value: str = typer.Argument(..., help="Host/Domain oder CIDR (z.B. 10.10.0.0/16)")):
    kind = "cidr" if "/" in value else "host"
    repo, _ = _repo()
    e = repo.add_scope(value, kind); repo.close()
    console.print(f"[green]Scope #{e.id}:[/green] {e.kind} {e.value}")


@scope_app.command("list")
def scope_list():
    repo, _ = _repo()
    items = repo.list_scope(); repo.close()
    if not items:
        console.print("[dim]Kein Scope gesetzt – Runner laufen ohne Einschränkung (CTF-Modus).[/dim]")
        return
    table = Table(title="Scope")
    for c in ["ID", "Typ", "Wert"]:
        table.add_column(c)
    for e in items:
        table.add_row(str(e.id), e.kind, e.value)
    console.print(table)


@scope_app.command("rm")
def scope_rm(scope_id: int):
    repo, _ = _repo()
    ok = repo.remove_scope(scope_id); repo.close()
    console.print("[green]Aus Scope entfernt.[/green]" if ok else "[red]Nicht gefunden.[/red]")


if __name__ == "__main__":
    app()