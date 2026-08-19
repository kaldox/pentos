"""
PentOS – Kommandozeile (Typer + Rich).

Bindet sämtliche Subsysteme: Projekte/Workspace, Hosts, Services, Scan-Import,
Empfehlungen, Aufgaben, Findings, Notizen, Loot, Evidence, Wissen, Journal,
Attack-Path-Graph, Obsidian-Export, Reporting und KI-Mentor.

"""
from __future__ import annotations

import json
import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Optional

import sys
import typer
from rich.console import Console
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table

from .. import archive as archive_mod
from .. import attack_navigator as attack_navigator_mod
from .. import bruteforce as bruteforce_mod
from .. import config
from ..ai import AIClient
from .. import epss as epss_mod
from .. import policy as policy_mod
from .. import findings_rules, graph as graph_mod, obsidian as obsidian_mod, recommend, report as report_mod
from .. import export as export_mod
from .. import playbooks as playbooks_mod
from .. import diff as diff_mod
from .. import credmatch as credmatch_mod
from ..importers import bloodhound as bloodhound_importer
from ..importers import nmap as nmap_importer
from ..importers import scanners as scanner_importer
from ..runners import base as runner_base, parsers as runner_parsers, registry as runner_registry
from .. import wordlists as wordlists_mod
from ..models import (
    BloodHoundImport,
    EngagementPolicy,
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
    TimelineEntry,
    TimelineKind,
)
from ..repository import Repository
from ..workspace import create_workspace, list_projects

console = Console()
app = typer.Typer(help="PentOS – Knowledge-Driven Offensive Security Workspace",
                  no_args_is_help=True, add_completion=True)

# Auf Windows läuft stdout gerne in einer nicht-UTF-8-Codepage (z.B. cp1252 als
# Konsolen-Default, oder wenn `pentos`/`python -m pentos` als Subprozess ohne
# PYTHONUTF8=1 / PYTHONIOENCODING=utf-8 aufgerufen wird). Rich schreibt in dem
# Fall roh in den Stream, und ein UnicodeEncodeError für Zeichen wie ●, →, ✓
# oder ⚠ lässt den Befehl abstürzen statt die Ausgabe zu zeigen. Deshalb hier
# durchgängig ASCII-Ersatzzeichen für Marker/Status-Symbole in Rich-Ausgaben.
SYM_BULLET = "*"     # aktives Projekt / Prioritäts-Bullet
SYM_ARROW = "->"     # Statuswechsel / Wertübergänge
SYM_NEXT = ">>"      # "Nächste Schritte"-Panels
SYM_WARN = "!"       # Warnhinweis
SYM_OK = "x"         # erledigt / installiert (grün)
SYM_MISSING = "-"    # fehlt / nicht installiert (rot)
SYM_SKIP = ">"       # übersprungen (gelb)
SYM_PENDING = "."    # offen / ausstehend (dim)
BAR_FULL = "#"       # Fortschrittsbalken: gefüllt
BAR_EMPTY = "-"      # Fortschrittsbalken: leer


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
        table.add_row(SYM_BULLET if p == active else "", p)
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


@project_app.command("export")
def project_export(
    name: Optional[str] = typer.Argument(None, help="Projekt (Default: aktives Projekt)"),
    out: Optional[Path] = typer.Option(
        None, "--out", "-o",
        help="Zieldatei (Default: <projekt>/exports/<name>_<zeitstempel>.pentos.zip)"),
):
    """Packt den kompletten Projekt-Workspace (Datenbank + alle Ordner) als eine ZIP-Datei.

    Zum Sichern, Umziehen auf einen anderen Rechner oder Teilen eines Projekts.
    Evidence-Dateien ausserhalb des Projektordners werden nicht mit verpackt –
    für volle Portabilität Evidence im Workspace ablegen (z.B. unter evidence/).
    """
    target_name = name or config.get_active_project()
    if not target_name:
        console.print("[red]Kein Projekt angegeben und kein aktives Projekt.[/red]")
        raise typer.Exit(1)
    if target_name not in list_projects():
        console.print(f"[red]Projekt '{target_name}' existiert nicht.[/red]")
        raise typer.Exit(1)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = out or (config.project_path(target_name) / "exports" / f"{target_name}_{ts}.pentos.zip")
    try:
        path = archive_mod.export_project(target_name, dest)
    except archive_mod.ArchiveError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    repo = Repository(config.db_path(target_name))
    repo.log("Projekt exportiert", str(path))
    repo.close()
    size_mb = path.stat().st_size / (1024 * 1024)
    console.print(f"[green]Projekt exportiert:[/green] {path} ({size_mb:.1f} MB)")


@project_app.command("import")
def project_import(
    archive: Path = typer.Argument(..., help="Pfad zur .pentos.zip-Exportdatei"),
    name: Optional[str] = typer.Option(None, "--name", help="Zielname (Default: Name aus dem Archiv)"),
    force: bool = typer.Option(False, "--force", help="Existierendes Projekt gleichen Namens überschreiben"),
    activate: bool = typer.Option(True, "--activate/--no-activate", help="Nach dem Import aktiv setzen"),
):
    """Importiert einen mit 'project export' erzeugten Workspace als (neues) Projekt."""
    try:
        imported = archive_mod.import_project(archive, name=name, force=force)
    except archive_mod.ArchiveError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    repo = Repository(config.db_path(imported))
    repo.log("Projekt importiert", str(archive))
    repo.close()
    if activate:
        config.set_active_project(imported)
    console.print(f"[green]Projekt importiert:[/green] {imported}" + (" (aktiv)" if activate else ""))


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
                  f"{SYM_ARROW} {created} Aufgaben, {findings} Auto-Findings")


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

    # Projektweite Folge-Tool-Vorschläge sammeln (nur installierte = "bereit").
    hosts_by_id = {h.id: h for h in repo.list_hosts()}
    svc_addr = [(s, (hosts_by_id.get(s.host_id).address if hosts_by_id.get(s.host_id) else None))
                for s in repo.list_services()]
    ready, missing = recommend.project_shortcuts(svc_addr)
    repo.close()

    console.print(Panel.fit(
        f"[green]Import abgeschlossen[/green]\n"
        f"Hosts: {n_hosts}   Services: {n_services}\n"
        f"Neue Aufgaben: {n_tasks}   Auto-Findings: {n_findings}\n"
        f"Notiz: {note_path}",
        title="Nmap"))

    if ready or missing:
        body = ""
        if ready:
            shown = ready[:12]
            body += "[green]Bereit (installiert):[/green]\n" + "\n".join(f"  {c}" for c in shown)
            if len(ready) > len(shown):
                body += f"\n  [dim]… und {len(ready) - len(shown)} weitere[/dim]"
        if missing:
            body += ("\n\n" if ready else "") + f"[dim]Nicht installiert: {', '.join(missing)}[/dim]"
        body += "\n\n[dim]Vorschläge - nichts wird automatisch ausgeführt.[/dim]"
        console.print(Panel.fit(body, title=f"{SYM_NEXT} Nächste Schritte (Runner)"))


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


@scan_app.command("import-bloodhound")
def scan_import_bloodhound(
    path: Path = typer.Argument(..., exists=True, readable=True,
                                help="SharpHound-Export: ZIP-Datei oder entpackter Ordner"),
    host: Optional[str] = typer.Option(None, "--host",
                                       help="Host-ID oder -Adresse zum Verknüpfen (z.B. der Domain Controller)"),
):
    """Importiert einen SharpHound-Export (BloodHound CE, on-prem AD).

    Baut keinen Graphen nach (das bleibt BloodHounds Job) -- wertet die Rohdaten aus
    und legt Findings an: Kerberoastable Accounts, AS-REP-roastbare Accounts,
    uneingeschränkte Delegation, Domain-Admin-Mitgliedschaft. Für die volle
    Angriffspfad-Analyse den Export zusätzlich in BloodHound selbst öffnen.
    Nur SharpHound (on-prem AD); AzureHound (Entra ID) wird (noch) nicht unterstützt.
    """
    repo, _ = _repo()
    try:
        summary = bloodhound_importer.parse_sharphound(path)
    except bloodhound_importer.BloodHoundImportError as exc:
        repo.close()
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    host_id = None
    if host:
        h = repo.get_host(int(host)) if host.isdigit() else None
        if h is None:
            h = repo.get_host_by_address(host)
        if h:
            host_id = h.id
        else:
            console.print(f"[yellow]Host '{host}' nicht im Projekt – Findings/Notiz ohne Host-Bindung.[/yellow]")

    def _add(title: str, sev: Severity, cat: FindingCategory, desc: str) -> bool:
        if repo.finding_exists(title, host_id=host_id):
            return False
        repo.add_finding(Finding(title=title, severity=sev, category=cat,
                                 status=FindingStatus.UNVERIFIED, description=desc,
                                 host_id=host_id, auto=True))
        return True

    def _list_desc(items: list[str], limit: int = 20) -> str:
        shown = ", ".join(items[:limit])
        if len(items) > limit:
            shown += f" (+{len(items) - limit} weitere)"
        return shown

    find_n = 0
    dom = summary["domain"] or "Domäne"
    if summary["kerberoastable"]:
        if _add(f"Kerberoastable Accounts in {dom}", Severity.HIGH, FindingCategory.CREDENTIAL,
               f"{len(summary['kerberoastable'])} aktive Benutzerkonten mit gesetztem SPN "
               f"(Kerberoasting möglich – Service-Ticket anfordern, Hash offline cracken):\n"
               f"{_list_desc(summary['kerberoastable'])}"):
            find_n += 1
    if summary["asrep_roastable"]:
        if _add(f"AS-REP-roastbare Accounts in {dom}", Severity.HIGH, FindingCategory.CREDENTIAL,
               f"{len(summary['asrep_roastable'])} aktive Benutzerkonten ohne Kerberos-Preauth "
               f"(AS-REP-Roasting möglich, kein Passwort nötig):\n{_list_desc(summary['asrep_roastable'])}"):
            find_n += 1
    if summary["unconstrained_delegation"]:
        if _add(f"Uneingeschränkte Delegation in {dom}", Severity.HIGH, FindingCategory.MISCONFIG,
               f"{len(summary['unconstrained_delegation'])} Konten/Computer mit uneingeschränkter "
               f"Kerberos-Delegation (bei Kompromittierung TGTs abgreifbar):\n"
               f"{_list_desc(summary['unconstrained_delegation'])}"):
            find_n += 1
    if summary["domain_admins"]:
        if _add(f"Domain-Admin-Mitgliedschaft in {dom} ({len(summary['domain_admins'])})",
               Severity.MEDIUM, FindingCategory.EXPOSURE,
               f"Mitglieder der Gruppe 'Domain Admins':\n{_list_desc(summary['domain_admins'], limit=50)}\n\n"
               "Für die volle Angriffspfad-Analyse (wer kann wie Domain Admin werden) "
               "den Export in der echten BloodHound-Oberfläche öffnen."):
            find_n += 1

    body = (
        f"SharpHound-Import — {dom}\n\n"
        f"Benutzer: {summary['user_count']}   Computer: {summary['computer_count']}   "
        f"Gruppen: {summary['group_count']}\n\n"
        f"Kerberoastable: {len(summary['kerberoastable'])}\n"
        f"AS-REP-roastbar: {len(summary['asrep_roastable'])}\n"
        f"Uneingeschränkte Delegation: {len(summary['unconstrained_delegation'])}\n"
        f"Domain Admins: {len(summary['domain_admins'])}\n\n"
        "PentOS wertet nur aus – für die volle Graphen-/Angriffspfad-Analyse "
        "den Export in BloodHound selbst öffnen."
    )
    repo.add_note(Note(title=f"BloodHound-Import · {dom}", body=body, category="ad", host_id=host_id))
    # Zusammenfassung persistieren -> speist den AD-Angriffspfad im Graph-Dashboard
    # (siehe pentos/graph.py und GET /api/project/{name}/graph)
    repo.add_bloodhound_import(BloodHoundImport(domain=summary["domain"], summary_json=json.dumps(summary)))
    repo.log("BloodHound-Import", f"{path} ({dom}): {find_n} Findings")
    repo.close()

    console.print(Panel.fit(
        f"[green]BloodHound-Import abgeschlossen[/green]  ({dom})\n"
        f"Benutzer: {summary['user_count']}   Computer: {summary['computer_count']}   "
        f"Gruppen: {summary['group_count']}\n"
        f"Neue Findings: {find_n}\n"
        f"Kerberoastable: {len(summary['kerberoastable'])}   "
        f"AS-REP-roastbar: {len(summary['asrep_roastable'])}   "
        f"Domain Admins: {len(summary['domain_admins'])}",
        title="BloodHound"))


@scan_app.command("diff")
def scan_diff(xml_file: Path = typer.Argument(..., exists=True, readable=True,
                                              help="nmap XML (nmap -oX) zum Vergleich")):
    """Vergleicht einen nmap-Scan mit dem aktuellen Projektstand (nur lesend).

    Zeigt neue Hosts, neue Dienste, Versionswechsel und was im neuen Scan fehlt.
    Schreibt NICHTS - zum Importieren weiterhin `scan import-nmap` nutzen.
    """
    repo, _ = _repo()
    parsed = nmap_importer.parse_nmap_xml(xml_file)
    d = diff_mod.diff_parsed_against_repo(parsed, repo.list_hosts(), repo.list_services())
    repo.close()

    if not d.has_changes:
        console.print(Panel.fit(
            f"[green]Keine Änderungen[/green]\nÜbereinstimmende Dienste: {d.unchanged}",
            title=f"Scan-Diff — {xml_file.name}"))
        return

    lines: list[str] = []
    if d.new_hosts:
        lines.append("[bold green]Neue Hosts:[/bold green]")
        lines += [f"  + {h}" for h in d.new_hosts]
    if d.new_services:
        lines.append("[bold green]Neue Dienste:[/bold green]")
        lines += [f"  + {s.host}  {s.port}/{s.protocol}  {s.banner()}" for s in d.new_services]
    if d.changed_services:
        lines.append("[bold yellow]Versionswechsel:[/bold yellow]")
        lines += [f"  ~ {c.host}  {c.port}/{c.protocol}  {c.before} {SYM_ARROW} {c.after}"
                  for c in d.changed_services]
    if d.missing_hosts:
        lines.append("[bold red]Im neuen Scan nicht gesehen (Hosts):[/bold red]")
        lines += [f"  - {h}" for h in d.missing_hosts]
    if d.missing_services:
        lines.append("[bold red]Im neuen Scan nicht gesehen (Dienste):[/bold red]")
        lines += [f"  - {s.host}  {s.port}/{s.protocol}  {s.banner()}" for s in d.missing_services]
    lines.append(f"[dim]Unverändert: {d.unchanged}[/dim]")

    console.print(Panel.fit("\n".join(lines), title=f"Scan-Diff — {xml_file.name}"))


# ── Empfehlungen ─────────────────────────────────────────────────────────────
@app.command("recommend", rich_help_panel="Recon & Import")
def recommend_cmd(service_id: Optional[int] = typer.Argument(
                      None, help="Service-ID; ohne Angabe projektweite Übersicht"),
                  create_tasks: bool = typer.Option(False, "--create-tasks",
                                                     help="Vorgeschlagene Aufgaben anlegen")):
    """Zeigt empfohlene nächste Schritte (keine Ausführung).

    Mit Service-ID: Empfehlungen für genau diesen Dienst. Ohne Argument: eine
    projektweite Übersicht der ausführbaren Run-Shortcuts über alle Dienste.
    """
    repo, _ = _repo()

    # ── Projektweite Übersicht ───────────────────────────────────────────────
    if service_id is None:
        hosts_by_id = {h.id: h for h in repo.list_hosts()}
        svc_addr = [(s, (hosts_by_id.get(s.host_id).address if hosts_by_id.get(s.host_id) else None))
                    for s in repo.list_services()]
        repo.close()
        if not svc_addr:
            console.print("[dim]Keine Dienste im Projekt. Erst importieren oder anlegen.[/dim]")
            return
        ready, missing = recommend.project_shortcuts(svc_addr)
        if not ready and not missing:
            console.print("[dim]Keine passenden Runner-Tools für die vorhandenen Dienste.[/dim]")
            return
        body = ""
        if ready:
            body += "[green]Bereit (installiert):[/green]\n" + "\n".join(f"  {c}" for c in ready)
        if missing:
            body += ("\n\n" if ready else "") + f"[dim]Nicht installiert: {', '.join(missing)}[/dim]"
        body += "\n\n[dim]Vorschläge - nichts wird automatisch ausgeführt.[/dim]"
        console.print(Panel.fit(body, title=f"{SYM_NEXT} Nächste Schritte (projektweit)"))
        return

    # ── Einzelner Dienst ─────────────────────────────────────────────────────
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
    ready, missing = recommend.run_shortcuts_for(svc, addr)
    if ready:
        body = "[green]Bereit (installiert):[/green]\n" + "\n".join(f"  {cmd}" for _t, cmd in ready)
        if missing:
            body += f"\n\n[dim]Nicht installiert: {', '.join(missing)}[/dim]"
        console.print(Panel.fit(body, title=f"{SYM_NEXT} Ausführen via Runner"))
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
    console.print(f"[green]#{task_id} {SYM_ARROW} In Bearbeitung[/green]" if ok else "[red]Nicht gefunden.[/red]")


@task_app.command("done")
def task_done(task_id: int):
    repo, _ = _repo()
    ok = repo.set_task_status(task_id, TaskStatus.DONE); repo.close()
    console.print(f"[green]#{task_id} {SYM_ARROW} Erledigt[/green]" if ok else "[red]Nicht gefunden.[/red]")


# ── Findings ─────────────────────────────────────────────────────────────────
finding_app = typer.Typer(help="Findings verwalten")
app.add_typer(finding_app, name="finding", rich_help_panel="Befunde & Doku")


@finding_app.command("add")
def finding_add(title: str,
                severity: str = typer.Option("medium", "--sev", "--severity", help="info|low|medium|high|critical"),
                category: str = typer.Option("other", "--cat", "--category",
                                             help="misconfig|vuln|exposure|credential|infodisc|other"),
                description: Optional[str] = typer.Option(None, "--desc"),
                host_id: Optional[int] = typer.Option(None, "--host"),
                service_id: Optional[int] = typer.Option(None, "--service")):
    repo, _ = _repo()
    if host_id is not None and repo.get_host(host_id) is None:
        repo.close()
        console.print(f"[red]Host #{host_id} nicht im Projekt.[/red]"); raise typer.Exit(1)
    if service_id is not None and repo.get_service(service_id) is None:
        repo.close()
        console.print(f"[red]Service #{service_id} nicht im Projekt.[/red]"); raise typer.Exit(1)
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
                      SYM_OK if f.auto else "")
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
    epss_line = ""
    if f.epss_score is not None:
        epss_line = f"\nEPSS: {f.epss_score:.3f} (Perzentil {f.epss_percentile:.2f})"
    attack_line = ""
    if f.attack_technique:
        label = f" ({f.attack_technique_name})" if f.attack_technique_name else ""
        attack_line = f"\nATT&CK: {f.attack_technique}{label}"
    console.print(Panel.fit(
        f"[bold]{f.title}[/bold]\n\n"
        f"Severity: {f.severity.value}\nKategorie: {f.category.value}\nStatus: {f.status.value}\n"
        f"Erkennung: {'automatisch' if f.auto else 'manuell'}{epss_line}{attack_line}\n\n"
        f"{f.description or '_keine Beschreibung_'}",
        title=f"Finding #{f.id}"))


@finding_app.command("status")
def finding_status(finding_id: int,
                   status: str = typer.Argument(..., help="unverified|confirmed|exploited|fp|closed"),
                   note: Optional[str] = typer.Option(None, "--note", "-n",
                                                      help="Begründung/Kontext für den Wechsel")):
    repo, _ = _repo()
    st = FSTATUS_MAP.get(status)
    if not st:
        console.print("[red]Unbekannter Status.[/red]"); repo.close(); raise typer.Exit(1)
    ok = repo.set_finding_status(finding_id, st.value, note=note); repo.close()
    console.print(f"[green]#{finding_id} {SYM_ARROW} {st.value}[/green]" if ok else "[red]Nicht gefunden.[/red]")


@finding_app.command("history")
def finding_history(finding_id: int):
    """Zeigt die Status-Zeitleiste eines Findings (Retest-Tracking)."""
    repo, _ = _repo()
    f = repo.get_finding(finding_id)
    if not f:
        console.print(f"[red]Finding #{finding_id} existiert nicht.[/red]"); repo.close(); raise typer.Exit(1)
    hist = repo.finding_history(finding_id); repo.close()
    lines = []
    for h in hist:
        arrow = f"{h.old_status} {SYM_ARROW} {h.new_status}" if h.old_status else h.new_status
        note = f"  [dim]{h.note}[/dim]" if h.note else ""
        lines.append(f"[dim]{h.ts}[/dim]  {arrow}{note}")
    body = "\n".join(lines) if lines else "[dim]Keine Historie erfasst.[/dim]"
    console.print(Panel.fit(body, title=f"Status-Historie · Finding #{finding_id}: {f.title}"))


def _confirm_epss_send(cve_count: int, yes: bool) -> bool:
    """Fragt vor dem Senden an die FIRST.org-EPSS-API nach -- CVE-IDs
    verlassen den Rechner (analog zu _confirm_ai_send bei Cloud-KI-Aufrufen).
    Anders als bei der KI gibt es hier keine 'lokal'-Variante: EPSS ist immer
    ein externer Dienst, also immer die deutliche Warnung."""
    if yes:
        return True
    console.print(f"[yellow]Achtung:[/yellow] {cve_count} CVE-ID(s) werden an einen externen "
                  f"Dienst ([bold]api.first.org[/bold], EPSS) gesendet – Daten verlassen deinen Rechner.")
    return typer.confirm("Wirklich senden?", default=False)


@finding_app.command("epss")
def finding_epss(yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden")):
    """Reichert Findings mit erkennbarer CVE-Referenz um einen EPSS-Score an.

    EPSS (kostenlose FIRST.org-API) sagt, wie wahrscheinlich eine Lücke in den
    nächsten 30 Tagen tatsächlich ausgenutzt wird -- ergänzt CVSS (wie schlimm
    sie wäre) um die Ausnutzungswahrscheinlichkeit. Opt-in, wie bei KI-Cloud-
    Aufrufen: fragt vor dem Senden nach, sofern nicht --yes gesetzt ist.
    """
    repo, _ = _repo()
    findings = repo.list_findings()
    by_cve: dict[str, list[Finding]] = {}
    for f in findings:
        for cve in epss_mod.extract_cves(f):
            by_cve.setdefault(cve, []).append(f)
    if not by_cve:
        repo.close()
        console.print("[dim]Keine Findings mit erkennbarer CVE-Referenz (Titel/Beschreibung).[/dim]")
        return
    if not _confirm_epss_send(len(by_cve), yes):
        repo.close()
        console.print("Abgebrochen.")
        raise typer.Exit()
    try:
        scores = epss_mod.fetch_epss(list(by_cve.keys()))
    except epss_mod.EpssError as exc:
        repo.close()
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    updated = 0
    table = Table(title="EPSS-Anreicherung")
    for c in ["CVE", "EPSS", "Perzentil", "Findings"]:
        table.add_column(c)
    for cve, fs in by_cve.items():
        data = scores.get(cve)
        if not data:
            table.add_row(cve, "–", "–", str(len(fs)))
            continue
        table.add_row(cve, f"{data['epss']:.3f}", f"{data['percentile']:.2f}", str(len(fs)))
        for f in fs:
            if f.id is not None and repo.set_finding_epss(f.id, data["epss"], data["percentile"]):
                updated += 1
    repo.close()
    console.print(table)
    console.print(f"[green]{updated} Finding(s) aktualisiert.[/green] "
                  f"({len(by_cve)} eindeutige CVE(s) abgefragt)")


@finding_app.command("attack")
def finding_attack(
    finding_id: int,
    technique_id: Optional[str] = typer.Argument(
        None, help="MITRE-ATT&CK-Technique-ID, z.B. T1110 oder T1110.001"),
    name: Optional[str] = typer.Option(None, "--name", help="Kurzbezeichnung, z.B. 'Brute Force' (nur Anzeige)"),
    clear: bool = typer.Option(False, "--clear", help="Vorhandenes Technique-Tag entfernen"),
):
    """Ordnet einem Finding eine ATT&CK-Technique zu (oder entfernt sie mit --clear).

    Rein manuelle/kuratierte Zuordnung -- PentOS prüft nur das ID-Format
    (Txxxx oder Txxxx.xxx), nicht gegen die echte ATT&CK-Matrix. Export aller
    getaggten Findings als Navigator-Layer: 'pentos report --attack-navigator'.
    """
    repo, _ = _repo()
    f = repo.get_finding(finding_id)
    if not f:
        console.print(f"[red]Finding #{finding_id} existiert nicht.[/red]"); repo.close(); raise typer.Exit(1)
    if clear:
        repo.set_finding_attack(finding_id, None, None)
        repo.close()
        console.print(f"[green]Technique-Tag von Finding #{finding_id} entfernt.[/green]")
        return
    if not technique_id:
        console.print("[red]Technique-ID fehlt (oder --clear zum Entfernen).[/red]")
        repo.close(); raise typer.Exit(1)
    tid = technique_id.strip().upper()
    if not attack_navigator_mod.is_valid_technique_id(tid):
        console.print(f"[red]'{technique_id}' sieht nicht wie eine ATT&CK-Technique-ID aus "
                      "(erwartet: Txxxx oder Txxxx.xxx, z.B. T1110 oder T1110.001).[/red]")
        repo.close(); raise typer.Exit(1)
    repo.set_finding_attack(finding_id, tid, name)
    repo.close()
    label = f" ({name})" if name else ""
    console.print(f"[green]Finding #{finding_id} {SYM_ARROW} {tid}{label}[/green]")


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
    host: Optional[str] = typer.Option(None, "--host", help="Host-ID oder -Adresse zum Verknüpfen"),
    suffix: str = typer.Option("", "--suffix", help="Titel-Zusatz, z.B. '(192.168.56.10)'"),
):
    """Erzeugt aus einer Vorlage ein konkretes Finding im Projekt."""
    repo, _ = _repo()
    host_id = None
    if host:
        h = repo.get_host(int(host)) if host.isdigit() else None
        if h is None:
            h = repo.get_host_by_address(host)
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
             category: Optional[str] = typer.Option(None, "--cat", "--category")):
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


@loot_app.command("match")
def loot_match(loot_id: Optional[int] = typer.Argument(
                   None, help="Loot-ID; ohne Angabe alle passenden Loot-Einträge")):
    """Schlägt vor, gegen welche Dienste sich ein Loot wiederverwenden lässt.

    Reine Vorschläge mit Kopier-Befehlen (Spray / Pass-the-Hash / Key-Login).
    Es wird NICHTS ausgeführt.
    """
    repo, _ = _repo()
    loot_items = repo.list_loot()
    hosts_by_id = {h.id: h for h in repo.list_hosts()}
    host_services = [
        (hosts_by_id[s.host_id].address, s)
        for s in repo.list_services()
        if s.host_id in hosts_by_id
    ]
    repo.close()

    if loot_id is not None:
        loot_items = [l for l in loot_items if l.id == loot_id]
        if not loot_items:
            console.print(f"[red]Loot #{loot_id} existiert nicht.[/red]")
            raise typer.Exit(1)

    if not host_services:
        console.print("[dim]Keine Dienste im Projekt - erst importieren oder anlegen.[/dim]")
        return

    any_shown = False
    for l in loot_items:
        ms = credmatch_mod.matches_for(l, host_services)
        if not ms:
            continue
        any_shown = True
        lines = []
        for m in ms:
            where = f"{m.host}:{m.port}/{m.protocol}" if m.host != "-" else "(offline)"
            tool = f"  [dim](pentos run {m.tool} …)[/dim]" if m.tool else ""
            lines.append(f"[bold]{m.method}[/bold] {SYM_ARROW} {where}{tool}\n    {m.hint}")
        console.print(Panel.fit(
            "\n".join(lines),
            title=f"Loot #{l.id} [{l.type.value}] {l.label}"))

    if not any_shown:
        console.print("[dim]Keine passenden Dienste für diese(n) Loot-Eintrag/Einträge gefunden.[/dim]")


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
    console.print(f"[green]Evidence #{e.id}:[/green] {e.kind} {SYM_ARROW} {e.path}")


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
        console.print(text, markup=False)


@graph_app.command("dot")
def graph_dot(out: Optional[Path] = typer.Option(None, "--out", help="Datei statt stdout")):
    repo, name = _repo()
    text = graph_mod.to_dot(repo); repo.close()
    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]DOT geschrieben:[/green] {out}  "
                      f"([dim]Render: dot -Tpng {out} -o graph.png[/dim])")
    else:
        console.print(text, markup=False)


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
                 pdf: bool = typer.Option(False, "--pdf", help="Gebrandetes PDF (benötigt reportlab)"),
                 attack_navigator: bool = typer.Option(
                     False, "--attack-navigator",
                     help="ATT&CK-Navigator-Layer (.json) aus getaggten Findings exportieren "
                          "(siehe 'finding attack')")):
    """Erzeugt einen Report aus Findings, Journal, Aufgaben und Attack-Path.

    Formate: Markdown (Standard), --html (gebrandet), --pdf (gebrandet, reportlab),
    --attack-navigator (ATT&CK-Navigator-Layer-JSON). Mit --explain wird ein
    didaktischer Lern-Report erzeugt (nur Markdown).
    """
    repo, name = _repo()
    reports_dir = config.project_path(name) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    if attack_navigator:
        layer = attack_navigator_mod.build_navigator_layer(name, repo.list_findings())
        target = out or (reports_dir / "attack-navigator.json")
        target.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")
        repo.log("ATT&CK-Navigator-Layer erstellt", str(target))
        console.print(f"[green]ATT&CK-Navigator-Layer erstellt:[/green] {target}")
        n = len(layer["techniques"])
        if n:
            console.print(f"[dim]{n} Technik(en) – in https://mitre-attack.github.io/attack-navigator/ "
                          "öffnen und die Datei importieren.[/dim]")
        else:
            console.print("[dim]Keine Findings mit Technique-Tag – siehe 'pentos finding attack'.[/dim]")
        repo.close()
        return

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
        target = out or (reports_dir / "report.html")  # --out gilt unabhängig von der Endung, wie bei --pdf
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
    return f"[{color}]" + BAR_FULL * filled + "[/]" + "[grey30]" + BAR_EMPTY * (width - filled) + "[/]"


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
        lines = [f"[{_SEV_BAR[f.severity]}]{SYM_BULLET}[/] [{f.severity.value}] {f.title}  "
                 f"[grey50]({f.status.value})[/]" for f in crit[:8]]
        console.print(Panel("\n".join(lines), title=f"{SYM_WARN} Priorität", border_style="red"))

    # Letzte Läufe
    if runs:
        table = Table(title="Letzte Läufe", show_edge=False)
        for c in ["Zeit", "Tool", "Ziel", "RC"]:
            table.add_column(c)
        for r in runs[-5:]:
            table.add_row(r.started_at, r.tool, r.target or "-", str(r.returncode))
        console.print(table)


@app.command("tui", rich_help_panel="Reporting & Übersicht")
def tui_cmd(project: Optional[str] = typer.Option(None, "--project", "-p",
                                                  help="Projekt (sonst aktives)")):
    """Interaktives Terminal-Lagebild (Textual).

    Durch Hosts, Dienste, Findings, Tasks, Loot und Journal blättern;
    Finding- und Task-Status per Taste durchschalten. Es wird nichts
    ausgeführt - reine Ansicht und Status-Pflege.

    Benötigt die TUI-Extras: pip install -e ".\\[tui]"
    """
    proj = project or _active_or_exit()
    try:
        from ..tui import app as tui_app
    except ModuleNotFoundError:
        console.print('[red]TUI-Extras fehlen.[/red] Installiere: [cyan]pip install -e ".\\[tui]"[/cyan]')
        raise typer.Exit(1)
    tui_app.run(proj)



# ── KI-Mentor ────────────────────────────────────────────────────────────────
ai_app = typer.Typer(help="KI-Mentor (lokal, nur Analyse)")
app.add_typer(ai_app, name="ai", rich_help_panel="KI & Integration")


@ai_app.command("status")
def ai_status():
    """Prüft, ob das konfigurierte KI-Backend erreichbar ist (inkl. Modelle)."""
    info = AIClient(config.load_config()["ai"]).ping()
    aicfg = config.load_config()["ai"]
    ok = "[green]erreichbar[/green]" if info["ok"] else "[red]nicht erreichbar[/red]"
    from ..ai import LANGUAGES
    lang = aicfg.get("language", "de")
    lines = [
        f"Provider:  {info['provider']}",
        f"Base-URL:  {info['base_url'] or '-'}",
        f"Modell:    {info['model'] or '-'}",
        f"Status:    {ok}",
        f"Sprache:   {LANGUAGES.get(lang, lang)}"
        + ("" if aicfg.get("language_set") else " [dim](noch nicht bewusst gewählt)[/dim]"),
        f"Auto-Modell: {'an' if aicfg.get('auto_model') else 'aus'}"
        f"   Verbosity: {aicfg.get('verbosity', 'normal')}"
        f"   Temp: {aicfg.get('temperature', 0.3)}",
    ]
    if aicfg.get("persona"):
        lines.append(f"Persona:   {aicfg['persona']}")
    if aicfg.get("vision_model"):
        lines.append(f"Vision:    {aicfg['vision_model']}")
    if aicfg.get("models"):
        pairs = ", ".join(f"{t}={m}" for t, m in aicfg["models"].items())
        lines.append(f"Pro-Task:  {pairs}")
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
              language: Optional[str] = typer.Option(None, "--language", "--lang",
                                                     help="Ausgabesprache: de,en,es,fr,zh,hi,ar,pt,ru,ja oder Freitext"),
              auto_model: Optional[bool] = typer.Option(None, "--auto-model/--no-auto-model",
                                                        help="Bestes installiertes Modell je Aufgabe wählen"),
              persona: Optional[str] = typer.Option(None, "--persona",
                                                    help="Zusatz-System-Prompt, z.B. 'knapper OSCP-Mentor'"),
              temperature: Optional[float] = typer.Option(None, "--temperature", help="0.0-1.0"),
              verbosity: Optional[str] = typer.Option(None, "--verbosity",
                                                      help="concise | normal | detailed"),
              vision_model: Optional[str] = typer.Option(None, "--vision-model",
                                                         help="Modell für Bildanalyse, z.B. qwen3-vl:4b"),
              keep_terms: Optional[bool] = typer.Option(None, "--keep-terms/--no-keep-terms",
                                                        help="Fachbegriffe/CVEs im Original lassen"),
              model_for: list[str] = typer.Option(None, "--model-for",
                                                  help="Pro-Task-Modell, z.B. analyze=deepseek-r1:14b (mehrfach)"),
              check: bool = typer.Option(True, "--check/--no-check",
                                         help="Nach dem Speichern Erreichbarkeit prüfen")):
    """Setzt die KI-Anbindung und das KI-Verhalten (schreibt in config.yaml)."""
    valid = {"ollama", "lmstudio", "openai", "none"}
    if provider and provider not in valid:
        console.print(f"[red]Unbekannter Provider '{provider}'.[/red] Erlaubt: {', '.join(sorted(valid))}")
        raise typer.Exit(1)
    if verbosity and verbosity not in {"concise", "normal", "detailed"}:
        console.print("[red]verbosity: concise | normal | detailed[/red]"); raise typer.Exit(1)
    cfg = config.load_config()
    ai = dict(cfg.get("ai", {}))
    if provider: ai["provider"] = provider
    if base_url: ai["base_url"] = base_url
    if model: ai["model"] = model
    if embed_model: ai["embed_model"] = embed_model
    if timeout: ai["timeout"] = timeout
    if api_key_env: ai["api_key_env"] = api_key_env
    if advisor is not None: ai["advisor"] = advisor
    if language:
        ai["language"] = language.lower(); ai["language_set"] = True
    if auto_model is not None: ai["auto_model"] = auto_model
    if persona is not None: ai["persona"] = persona
    if temperature is not None: ai["temperature"] = max(0.0, min(1.0, temperature))
    if verbosity: ai["verbosity"] = verbosity
    if vision_model is not None: ai["vision_model"] = vision_model
    if keep_terms is not None: ai["keep_terms"] = keep_terms
    if model_for:
        models = dict(ai.get("models") or {})
        for pair in model_for:
            if "=" in pair:
                t, m = pair.split("=", 1)
                models[t.strip()] = m.strip()
        ai["models"] = models
    cfg["ai"] = ai
    path = config.save_config(cfg)
    console.print(f"[green]Config gespeichert:[/green] {path}")
    console.print(f"  provider={ai.get('provider')}  base_url={ai.get('base_url')}  "
                  f"model={ai.get('model')}  sprache={ai.get('language')}  "
                  f"auto-modell={ai.get('auto_model')}")
    if check and ai.get("provider") not in (None, "none"):
        ai_status()


@ai_app.command("explain-finding")
def ai_explain_finding(finding_id: int,
                       lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache"),
                       yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden")):
    repo, _ = _repo()
    f = repo.get_finding(finding_id)
    repo.close()
    if not f:
        console.print("[red]Finding nicht gefunden.[/red]"); raise typer.Exit(1)
    _ensure_language()
    client = _ai_client(lang)
    if not _confirm_ai_send(client, f"Finding #{finding_id} ('{f.title}')", yes):
        console.print("Abgebrochen."); raise typer.Exit()
    console.print(Panel(client.explain_finding(f), title=f"KI-Mentor · Finding #{finding_id}"))


@ai_app.command("enum")
def ai_enum(service_id: int,
            lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache"),
            yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden")):
    repo, _ = _repo()
    svc = repo.get_service(service_id)
    repo.close()
    if not svc:
        console.print("[red]Service nicht gefunden.[/red]"); raise typer.Exit(1)
    _ensure_language()
    client = _ai_client(lang)
    if not _confirm_ai_send(client, f"Service {svc.port}/{svc.protocol}", yes):
        console.print("Abgebrochen."); raise typer.Exit()
    console.print(Panel(client.enumeration_ideas(svc),
                        title=f"KI-Mentor · Enumeration {svc.port}/{svc.protocol}"))


@ai_app.command("analyze-image")
def ai_analyze_image(
    image: Path = typer.Argument(..., exists=True, readable=True, help="Bild/Screenshot (PNG/JPG)"),
    question: Optional[str] = typer.Option(None, "--q", help="Konkrete Frage zum Bild"),
    lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden"),
):
    """Wertet einen Screenshot/ein Bild mit einem Vision-Modell aus (z.B. qwen3-vl).

    Nutzt das in der Config gesetzte vision_model bzw. die Auto-Wahl.
    """
    import base64
    _ensure_language()
    client = _ai_client(lang)
    if not _confirm_ai_send(client, f"das Bild '{image.name}'", yes):
        console.print("Abgebrochen."); raise typer.Exit()
    b64 = base64.b64encode(image.read_bytes()).decode()
    model = client.select_model("vision")
    with console.status(f"[cyan]Vision-Modell ({model}) analysiert das Bild…[/cyan]"):
        answer = client.analyze_image(b64, question)
    if not answer:
        console.print("[red]Keine Antwort.[/red] Vision-Modell installiert/erreichbar? "
                      "([cyan]ollama pull qwen3-vl[/cyan], dann "
                      "[cyan]pentos ai config --vision-model qwen3-vl:4b[/cyan])")
        raise typer.Exit(1)
    console.print(Panel(answer, title=f"KI · Bildanalyse ({image.name}, {model})"))


def _ai_client(lang: Optional[str] = None) -> AIClient:
    cfg = config.load_config()
    ai = dict(cfg["ai"])
    if lang:                       # Pro-Befehl-Override
        ai["language"] = lang.lower()
    return AIClient(ai, language=cfg.get("language", "de"))


def _ensure_language() -> None:
    """Fragt einmalig die Ausgabesprache ab, falls noch nie bewusst gewählt."""
    cfg = config.load_config()
    ai = cfg.get("ai", {})
    if ai.get("language_set") or ai.get("provider") in (None, "none"):
        return
    if not sys.stdin.isatty():     # nicht-interaktiv (Pipe/CI) -> nicht fragen
        return
    from ..ai import LANGUAGES
    console.print("[bold]In welcher Sprache soll die KI antworten?[/bold]")
    codes = list(LANGUAGES.keys())
    for i, code in enumerate(codes, 1):
        console.print(f"  {i}. {LANGUAGES[code]} [dim]({code})[/dim]")
    console.print(f"  {len(codes)+1}. Andere (Code eingeben)")
    choice = typer.prompt("Auswahl", default="1")
    code = ai.get("language", "de")
    if choice.isdigit() and 1 <= int(choice) <= len(codes):
        code = codes[int(choice) - 1]
    elif choice.isdigit() and int(choice) == len(codes) + 1:
        code = typer.prompt("Sprachcode/-name").strip().lower() or code
    elif choice.strip():
        code = choice.strip().lower()
    ai = dict(ai); ai["language"] = code; ai["language_set"] = True
    cfg["ai"] = ai; config.save_config(cfg)
    console.print(f"[green]Sprache gesetzt:[/green] {LANGUAGES.get(code, code)} "
                  f"[dim](änderbar mit pentos ai config --language ..)[/dim]\n")


def _stream_to_console(title: str):
    """Gibt einen on_token-Callback zurück, der live in ein Rich-Panel/Plain schreibt."""
    console.print(f"[dim]-- {title} --[/dim]")

    def on_token(t: str):
        console.print(t, end="", markup=False, highlight=False)
    return on_token


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
           k: int = typer.Option(5, "--k", help="Anzahl Kontext-Treffer"),
           lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache nur für diesen Aufruf"),
           stream: bool = typer.Option(False, "--stream", help="Antwort live streamen")):
    """Beantwortet eine Frage über die Projektdaten (RAG, mit Quellenangabe)."""
    from .. import rag
    _ensure_language()
    client = _ai_client(lang)
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
    if stream:
        answer = client.answer_with_context(frage, contexts, stream=True,
                                            on_token=_stream_to_console(f"Frag dein Projekt ({name})"))
        console.print()
    else:
        answer = client.answer_with_context(frage, contexts)
        if answer:
            console.print(Panel(answer, title=f"KI · Frag dein Projekt ({name})"))
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar?).")
        raise typer.Exit(1)
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
    lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache nur für diesen Aufruf"),
    stream: bool = typer.Option(False, "--stream", help="Antwort live streamen"),
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

    _ensure_language()
    client = _ai_client(lang)
    cfg = config.load_config()
    if not _confirm_ai_send(client, f"'{label}'-Ausgabe ({len(content)} Zeichen)", yes):
        console.print("Abgebrochen.")
        raise typer.Exit()

    advisor = bool(cfg["ai"].get("advisor", True))
    if stream:
        answer = client.interpret_output(label, content, advisor=advisor,
                                         stream=True, on_token=_stream_to_console(f"Analyse ({label})"))
        console.print()
    else:
        with console.status("[cyan]KI analysiert…[/cyan]"):
            answer = client.interpret_output(label, content, advisor=advisor)
        if answer:
            console.print(Panel(answer, title=f"KI · Analyse ({label})"))
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar? `pentos ai status`).")
        raise typer.Exit(1)
    if save:
        repo, _ = _repo()
        repo.add_note(Note(title=f"KI-Analyse · {label}", body=answer, category="ai"))
        repo.close()
        console.print("[green]Als Notiz gespeichert.[/green]")


# pentos-run-Vorschläge aus der freien KI-Antwort herausfiltern (der Advisor-
# System-Prompt bittet gezielt um genau dieses Format). Nur Tool+Ziel, keine
# von der KI vorgeschlagenen Zusatz-Flags -- die werden bewusst ignoriert,
# damit nicht unbeaufsichtigt beliebige Optionen mitlaufen.
_AI_CMD_RE = re.compile(r"pentos run\s+([a-zA-Z0-9_.\-]+)\s+(\S+)")


def _extract_ai_commands(answer: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _AI_CMD_RE.finditer(answer or ""):
        tool, target = m.group(1), m.group(2).rstrip(".,;:`)")
        if runner_registry.get(tool) and (tool, target) not in out:
            out.append((tool, target))
    return out[:5]


def _run_tool_confirmed(repo, name: str, spec, target: str) -> bool:
    """Scope-Check + Ausführung + Ingest + Ergebnis-Panel für einen einzelnen,
    vom Menschen bereits bestätigten Lauf. Geteilte Logik für 'ai next --act'
    (die eigentliche Ausführung von 'pentos run' bleibt unverändert, deckt
    aber mehr Optionen ab als hier gebraucht werden)."""
    host = runner_base.host_of(target)
    if spec.network and repo.scope_defined() and not repo.in_scope(host):
        console.print(f"[red]'{host}' liegt nicht im definierten Scope.[/red] "
                      f"Erweitern mit: [cyan]pentos scope add {host}[/cyan]")
        return False
    scans_dir = config.project_path(name) / "scans"
    try:
        result = runner_base.run_tool(spec, target, scans_dir)
    except runner_base.RunnerError as e:
        console.print(f"[red]{e}[/red]")
        return False
    summary = runner_parsers.ingest(repo, spec, target, result, name)
    status = "[yellow]Timeout[/yellow]" if result.timed_out else f"rc={result.returncode}"
    console.print(Panel.fit(
        f"[bold]{spec.name}[/bold] {SYM_ARROW} {target}   ({status}, {result.duration_ms} ms)\n"
        f"Ausgabe: {result.output_path}\n"
        f"Neu: {summary['hosts']} Hosts · {summary['services']} Services · "
        f"{summary['tasks']} Tasks · {summary['findings']} Findings · "
        f"{summary['loot']} Loot · {summary['notes']} Notizen · {summary['evidence']} Evidence",
        title="Von der KI vorgeschlagen, von dir bestätigt"))
    return True


@ai_app.command("next")
def ai_next(yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage senden"),
            lang: Optional[str] = typer.Option(None, "--lang", help="Ausgabesprache nur für diesen Aufruf"),
            stream: bool = typer.Option(False, "--stream", help="Antwort live streamen"),
            act: bool = typer.Option(False, "--act",
                                     help="Aus der Antwort vorgeschlagene 'pentos run'-Befehle "
                                          "anbieten -- du wählst und bestätigst, bevor irgendetwas "
                                          "läuft. Ohne --act reine Textausgabe wie bisher.")):
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

    _ensure_language()
    client = _ai_client(lang)
    cfg = config.load_config()
    if not _confirm_ai_send(client, "den Projektstand", yes):
        console.print("Abgebrochen.")
        raise typer.Exit()
    advisor = bool(cfg["ai"].get("advisor", True))
    if stream:
        answer = client.next_steps(state, advisor=advisor,
                                   stream=True, on_token=_stream_to_console(f"Nächste Schritte ({name})"))
        console.print()
    else:
        with console.status("[cyan]KI denkt über die nächsten Schritte nach…[/cyan]"):
            answer = client.next_steps(state, advisor=advisor)
        if answer:
            console.print(Panel(answer, title=f"KI · Nächste Schritte ({name})"))
    if not answer:
        console.print("[red]Keine Antwort vom Modell[/red] (Backend erreichbar? `pentos ai status`).")
        raise typer.Exit(1)

    if not act:
        return

    candidates = _extract_ai_commands(answer)
    if not candidates:
        console.print("\n[dim]Keine ausführbare 'pentos run <tool> <ziel>'-Empfehlung im "
                      "Antworttext gefunden -- nichts zum Bestätigen.[/dim]")
        return
    console.print("\n[bold]Vorgeschlagene Befehle (nur Tool + Ziel, Zusatz-Optionen der KI "
                  "werden ignoriert):[/bold]")
    for i, (tool, target) in enumerate(candidates, 1):
        console.print(f"  {i}. pentos run {tool} {target}")
    choice = typer.prompt("Welchen ausführen? (Nummer, Enter = keinen)", default="", show_default=False)
    if not choice.strip():
        console.print("Nichts ausgeführt.")
        return
    try:
        idx = int(choice.strip()) - 1
        if idx < 0:
            raise ValueError
        tool, target = candidates[idx]
    except (ValueError, IndexError):
        console.print("[red]Ungültige Auswahl.[/red]")
        raise typer.Exit(1)
    spec = runner_registry.get(tool)
    if not typer.confirm(f"'pentos run {tool} {target}' jetzt wirklich ausführen?", default=False):
        console.print("Abgebrochen.")
        return
    repo2, name2 = _repo()
    _run_tool_confirmed(repo2, name2, spec, target)
    repo2.close()


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


# ── Standard-Wordlists (Usernames gebündelt, Passwörter opt-in per Download) ─
wordlists_app = typer.Typer(help="Standard-Wordlists fürs Projekt einrichten (hydra/medusa/gobuster/...)")
app.add_typer(wordlists_app, name="wordlists", rich_help_panel="Recon & Import")


@wordlists_app.command("setup")
def wordlists_setup(
    no_passwords: bool = typer.Option(False, "--no-passwords",
                                      help="Nur Usernames einrichten, keine Passwort-Liste laden"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage herunterladen"),
):
    """Legt wordlists/usernames.txt (+ optional passwords.txt) im Projekt an.

    usernames.txt kommt direkt aus PentOS (generische Namen/Muster, kein
    Download nötig). passwords.txt ist opt-in: lädt die kuratierte
    rockyou-75.txt (SecLists) von GitHub -- eine bewusst kleine, fürs
    schnelle Durchprobieren gedachte Liste, keine vollständige Breach-Kopie.
    """
    repo, name = _repo()
    repo.close()
    wl_dir = config.project_path(name) / "wordlists"
    download = not no_passwords
    if download:
        existing = (wl_dir / "passwords.txt").exists()
        if not existing and not yes:
            console.print(f"[yellow]Lädt eine kleine Passwort-Liste ({wordlists_mod.PASSWORD_LIST_URL}) "
                          "herunter.[/yellow] Keine eigenen Daten werden gesendet, nur ein "
                          "öffentliches Textfile geholt.")
            if not typer.confirm("Herunterladen?", default=True):
                download = False
    try:
        result = wordlists_mod.setup(wl_dir, download_passwords=download)
    except wordlists_mod.WordlistError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Usernames:[/green] {result['usernames_path']}")
    if result["passwords_path"]:
        tag = "neu heruntergeladen" if result["passwords_downloaded"] else "bereits vorhanden, unverändert"
        console.print(f"[green]Passwords:[/green] {result['passwords_path']} ({tag})")
    else:
        console.print("[dim]Keine Passwort-Liste eingerichtet.[/dim]")
    console.print(
        "\n[dim]Beispiel:[/dim] pentos run hydra <ziel> --proto ssh   "
        "[dim](nutzt automatisch diese Wordlists)[/dim]"
    )


@wordlists_app.command("catalog")
def wordlists_catalog(
    category: Optional[str] = typer.Option(
        None, "--category", help="Nur eine Kategorie: usernames|passwords|directories|subdomains"),
    filter_: Optional[str] = typer.Option(None, "--filter", help="Name/Beschreibung durchsuchen"),
):
    """Durchsucht den kuratierten SecLists-Katalog (Browse/Filter, kein Download)."""
    entries = wordlists_mod.catalog_list(category=category, query=filter_)
    if not entries:
        console.print("[dim]Keine Treffer.[/dim]")
        return
    table = Table(title="Wordlist-Katalog")
    for c in ["Name", "Kategorie", "Beschreibung"]:
        table.add_column(c)
    for e in entries:
        table.add_row(e.name, e.category, e.description)
    console.print(table)
    console.print("[dim]Laden mit:[/dim] pentos wordlists add <name>")


@wordlists_app.command("add")
def wordlists_add(
    name: str = typer.Argument(..., help="Katalog-Name, siehe 'pentos wordlists catalog'"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage herunterladen"),
):
    """Lädt eine einzelne, namentlich gewählte Liste aus dem Katalog ins Projekt."""
    entry = wordlists_mod.catalog_get(name)
    if not entry:
        console.print(f"[red]Unbekannter Katalog-Eintrag '{name}'.[/red] "
                      f"Übersicht: [cyan]pentos wordlists catalog[/cyan]")
        raise typer.Exit(1)
    repo, proj = _repo()
    repo.close()
    wl_dir = config.project_path(proj) / "wordlists"
    out_path = wl_dir / f"{entry.name}.txt"
    if not yes:
        console.print(f"[yellow]Lädt '{entry.name}' ({entry.url}) herunter.[/yellow] "
                      "Keine eigenen Daten werden gesendet, nur ein öffentliches Textfile geholt.")
        if not typer.confirm("Herunterladen?", default=True):
            console.print("Abgebrochen.")
            raise typer.Exit()
    try:
        text = wordlists_mod.fetch_catalog_entry(entry)
    except wordlists_mod.WordlistError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    wl_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    console.print(f"[green]{entry.name}[/green] ({entry.category}) {SYM_ARROW} {out_path}")


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
        present = f"[green]{SYM_OK}[/green]" if shutil.which(spec.binary) else f"[red]{SYM_MISSING}[/red]"
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
            userlist: Optional[str] = typer.Option(
                None, "--userlist",
                help="Username-Liste für hydra/medusa/nxc-smb/nxc-winrm "
                     "(Default: wordlists/usernames.txt im Projekt)"),
            passlist: Optional[str] = typer.Option(
                None, "--passlist",
                help="Passwort-Liste für hydra/medusa/nxc-smb/nxc-winrm "
                     "(Default: wordlists/passwords.txt im Projekt)"),
            proto: Optional[str] = typer.Option(
                None, "--proto",
                help="Protokoll-Modul für hydra/medusa, z.B. ssh, ftp, http-get"),
            timeout: Optional[int] = typer.Option(None, "--timeout", help="Timeout in Sekunden"),
            dry_run: bool = typer.Option(False, "--dry-run", help="Nur das Kommando zeigen"),
            shell: bool = typer.Option(False, "--shell",
                                       help="Shell-Modus für interaktive Tools (z.B. smbclient -c '...'). "
                                            "ACHTUNG: interpretiert Shell-Metazeichen."),
            proxy: Optional[str] = typer.Option(
                None, "--proxy",
                help="Proxy-Chain voranstellen, z.B. \"proxychains4 -q\" (SOCKS-Pivot nach einem "
                     "Foothold ins interne Netz). Nur TCP-Connect-Traffic geht zuverlässig durch -- "
                     "SYN-/UDP-Scans (nmap -sS, naabu, rustscan) i.d.R. nicht."),
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
    if not force and not dry_run:
        reason = policy_mod.category_blocked(repo.get_engagement_policy(), spec.category)
        if reason:
            console.print(f"[red]{reason}[/red] Mit [cyan]--force[/cyan] überschreiben "
                          "(nur wenn du wirklich sicher bist).")
            repo.close(); raise typer.Exit(2)
    if shell and not dry_run:
        console.print(f"[yellow]{SYM_WARN} Shell-Modus:[/yellow] Argumente werden durch die Shell "
                      "interpretiert (Metazeichen, Quoting). Nur mit vertrauenswürdiger Eingabe verwenden.")
        if not args:
            console.print("[red]--shell benötigt --args \"...\" mit dem vollständigen Tool-Aufruf.[/red]")
            repo.close(); raise typer.Exit(1)

    if (userlist or passlist or proto) and args:
        console.print("[red]--userlist/--passlist/--proto nicht zusammen mit --args nutzen[/red] -- "
                       "entweder die Kurzform oder --args mit dem vollständigen Rest, nicht beides.")
        repo.close(); raise typer.Exit(1)
    if (userlist or passlist or proto) and not bruteforce_mod.is_supported(tool):
        console.print(f"[red]'{tool}' unterstützt --userlist/--passlist/--proto nicht.[/red] "
                      f"Unterstützte Tools: {', '.join(bruteforce_mod.SUPPORTED_TOOLS)}.")
        repo.close(); raise typer.Exit(1)

    if bruteforce_mod.is_supported(tool) and not args and not shell:
        # hydra/medusa/nxc brauchen zwingend User-/Passwort-Liste (+ Protokoll
        # bei hydra/medusa) -- ohne diesen Zweig würde ein blanker
        # "pentos run hydra <ziel>" nur hängen bzw. nichts Sinnvolles tun.
        wl_dir = config.project_path(name) / "wordlists"
        ul = userlist or str(wl_dir / "usernames.txt")
        pl = passlist or str(wl_dir / "passwords.txt")
        if bruteforce_mod.needs_proto(tool) and not proto:
            console.print(f"[red]'{tool}' braucht --proto (z.B. ssh, ftp, http-get).[/red]")
            repo.close(); raise typer.Exit(1)
        fehlend = [p for p in (ul, pl) if not Path(p).exists()]
        if fehlend and not dry_run:
            console.print(f"[red]Wordlist(en) nicht gefunden:[/red] {', '.join(fehlend)}\n"
                          "Einrichten mit [cyan]pentos wordlists setup[/cyan], "
                          "oder eigene Dateien mit [cyan]--userlist[/cyan]/[cyan]--passlist[/cyan] angeben.")
            repo.close(); raise typer.Exit(1)
        extra = bruteforce_mod.build_args(tool, ul, pl, proto)
    else:
        extra = shlex.split(args) if (args and not shell) else None
    scans_dir = config.project_path(name) / "scans"
    try:
        result = runner_base.run_tool(spec, target, scans_dir, extra_args=extra,
                                      wordlist=wordlist, timeout=timeout, dry_run=dry_run,
                                      profile=profile, shell=shell, raw_args=args, proxy=proxy)
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
        f"[bold]{spec.name}[/bold] {SYM_ARROW} {target}   ({status}, {result.duration_ms} ms)\n"
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
    console.print(f"   [green]{SYM_OK}[/green] {spec.name} ({status}, {result.duration_ms} ms) – "
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
    if run and not force and policy_mod.category_blocked(repo.get_engagement_policy(), "recon"):
        # 'recon' ist über keine echte Kategorie-Gate-Regel gesperrt -- der obige
        # Aufruf greift hier nur, wenn automated_scanning_allowed=False gesetzt ist
        # (sperrt dann ausnahmslos alles, siehe pentos/policy.py).
        console.print("[red]Programm-Regeln: automatisierte Tools sind für dieses Projekt nicht erlaubt "
                      "(nur manuelles Testen).[/red] Mit [cyan]--force[/cyan] überschreiben, "
                      "oder ohne --run nur die Kommando-Vorschläge ansehen.")
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
            if yes or typer.confirm(f"{SYM_ARROW} {spec.name} gegen {tgt} (Dienst {svc.name or svc.port})?", default=True):
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

_KIND_ICON = {"pentos": "(P)", "external": "(E)", "manual": "(M)"}


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
    console.print("[dim]Legende: (P) PentOS-Tool · (E) externes Tool · (M) manuell[/dim]")
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
        mark = f"[green]{SYM_OK}[/green]" if st and st["status"] == "done" else \
               f"[yellow]{SYM_SKIP}[/yellow]" if st and st["status"] == "skip" else f"[dim]{SYM_PENDING}[/dim]"
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
    console.print(f"[green]{name}/{step_id} {SYM_ARROW} {'übersprungen' if skip else 'erledigt'}.[/green]")


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
        bar = BAR_FULL * (pct // 10) + BAR_EMPTY * (10 - pct // 10)
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


# ── Engagement-Zeitplan ────────────────────────────────────────────────────
timeline_app = typer.Typer(help="Engagement-Zeitplan verwalten (Meilensteine, Zeitfenster, Blackout-Zeiten)")
app.add_typer(timeline_app, name="timeline", rich_help_panel="Workspace")

_TIMELINE_KIND_MAP = {
    "milestone": TimelineKind.MILESTONE, "window": TimelineKind.WINDOW, "blackout": TimelineKind.BLACKOUT,
}
_TIMELINE_KIND_LABEL = {
    TimelineKind.MILESTONE: "Meilenstein", TimelineKind.WINDOW: "Zeitfenster", TimelineKind.BLACKOUT: "Blackout",
}


@timeline_app.command("add")
def timeline_add(
    title: str = typer.Argument(..., help="z.B. 'Kickoff', 'Testfenster Woche 1', 'Wartungsfenster Kunde'"),
    kind: str = typer.Option("milestone", "--kind",
                             help="milestone (Meilenstein) | window (Testfenster) | blackout (Sperrzeit)"),
    start: Optional[str] = typer.Option(None, "--start", help="z.B. '2026-08-20 08:00'"),
    end: Optional[str] = typer.Option(None, "--end", help="z.B. '2026-08-20 18:00'"),
    note: Optional[str] = typer.Option(None, "--note", help="z.B. Eskalationskontakt, Grund der Sperrzeit"),
):
    """Legt einen Eintrag im Engagement-Zeitplan an (Rules-of-Engagement-Zeitfenster,
    Blackout-/Sperrzeiten, Projekt-Meilensteine) -- erscheint im Report."""
    k = _TIMELINE_KIND_MAP.get(kind)
    if k is None:
        console.print(f"[red]Ungültige --kind '{kind}'. Erlaubt: milestone|window|blackout[/red]")
        raise typer.Exit(1)
    repo, _ = _repo()
    t = repo.add_timeline_entry(TimelineEntry(kind=k, title=title, start_ts=start, end_ts=end, note=note))
    repo.close()
    console.print(f"[green]Zeitplan-Eintrag #{t.id}:[/green] [{_TIMELINE_KIND_LABEL[k]}] {t.title}")


@timeline_app.command("list")
def timeline_list():
    """Zeigt den Engagement-Zeitplan, chronologisch sortiert."""
    repo, _ = _repo()
    entries = repo.list_timeline_entries()
    repo.close()
    if not entries:
        console.print("[dim]Noch kein Zeitplan erfasst. Anlegen mit 'pentos timeline add \"Titel\" --start ...'.[/dim]")
        return
    table = Table(title="Engagement-Zeitplan")
    for c in ["ID", "Art", "Titel", "Start", "Ende", "Notiz"]:
        table.add_column(c)
    for t in entries:
        table.add_row(str(t.id), _TIMELINE_KIND_LABEL.get(t.kind, str(t.kind)),
                     t.title, t.start_ts or "-", t.end_ts or "-", t.note or "-")
    console.print(table)


@timeline_app.command("rm")
def timeline_rm(entry_id: int):
    repo, _ = _repo()
    ok = repo.delete_timeline_entry(entry_id); repo.close()
    console.print("[green]Aus dem Zeitplan entfernt.[/green]" if ok else "[red]Nicht gefunden.[/red]")


# ── Engagement-Policy (Programm-/Auftrags-Regeln, z.B. Bug-Bounty-Scope) ─────
policy_app = typer.Typer(help="Programm-Regeln festlegen (Bug-Bounty-Scope): was ist erlaubt?")
app.add_typer(policy_app, name="policy", rich_help_panel="Workspace")


def _policy_table(policy: Optional[EngagementPolicy]) -> Table:
    table = Table(title="Programm-Regeln")
    for c in ["Regel", "Status", "Wirkung"]:
        table.add_column(c)
    for row in policy_mod.summary_rows(policy):
        wirkung = "sperrt Tools" if row["enforced"] else "nur Report"
        style = "dim" if not row["set"] else ("red" if row["value"] == "nicht erlaubt" else "green")
        table.add_row(row["label"], f"[{style}]{row['value']}[/{style}]", wirkung)
    return table


@policy_app.command("setup")
def policy_setup(
    bruteforce: Optional[bool] = typer.Option(
        None, "--bruteforce/--no-bruteforce", help="Brute-Force erlaubt? (sperrt hydra/medusa/nxc/kerbrute)"),
    exploitation: Optional[bool] = typer.Option(
        None, "--exploitation/--no-exploitation", help="Aktive Exploitation erlaubt? (sperrt sqlmap)"),
    cracking: Optional[bool] = typer.Option(
        None, "--cracking/--no-cracking", help="Offline-Hash-Cracking erlaubt? (sperrt john)"),
    automated: Optional[bool] = typer.Option(
        None, "--automated/--no-automated",
        help="Automatisierte Tools überhaupt erlaubt? Nein = nur manuelles Testen, sperrt praktisch 'pentos run'"),
    dos: Optional[bool] = typer.Option(
        None, "--dos/--no-dos", help="DoS-/Rate-Limit-Tests erlaubt? (nur dokumentiert, nicht durchgesetzt)"),
    social_engineering: Optional[bool] = typer.Option(
        None, "--social-engineering/--no-social-engineering", help="Social Engineering erlaubt? (nur dokumentiert)"),
    production_only: Optional[bool] = typer.Option(
        None, "--production-only/--not-production-only",
        help="Nur Produktivsystem im Scope, kein Staging? (nur dokumentiert)"),
    rate_limit: Optional[str] = typer.Option(None, "--rate-limit", help="Freitext, z.B. '10 req/s'"),
    scope_note: Optional[str] = typer.Option(None, "--scope-note", help="Freitext zu Scope-Besonderheiten"),
    program_url: Optional[str] = typer.Option(None, "--program-url", help="Link zur Programm-Policy"),
    interactive: bool = typer.Option(
        True, "--interactive/--no-interactive",
        help="Fehlende Werte interaktiv abfragen (aus, um nur die übergebenen Flags zu setzen)"),
):
    """Legt die Programm-/Auftrags-Regeln für dieses Projekt fest (z.B. Bug-Bounty-Scope).

    Was durchsetzbar ist (Brute-Force/Exploitation/Cracking/automatisierte
    Tools generell), sperrt 'pentos run'/'sweep --run' mit klarer Meldung
    (Override: --force, wie beim Scope-Guard). Der Rest (DoS, Social
    Engineering, Produktiv-only, Rate-Limit) wird nur dokumentiert und
    erscheint im Report -- PentOS kann das technisch nicht erzwingen.

    Nicht beantwortete Fragen bleiben 'nicht erfasst' und schränken nichts ein.
    Das ist ein Gedächtnisstütze/Selbstschutz, keine Compliance-Garantie.
    """
    def _ask(current: Optional[bool], question: str) -> Optional[bool]:
        if current is not None or not interactive:
            return current
        return typer.confirm(question, default=False)

    bruteforce = _ask(bruteforce, "Ist Brute-Force erlaubt?")
    exploitation = _ask(exploitation, "Ist aktive Exploitation erlaubt?")
    cracking = _ask(cracking, "Ist Offline-Hash-Cracking erlaubt?")
    automated = _ask(automated, "Sind automatisierte Tools überhaupt erlaubt (sonst nur manuelles Testen)?")
    dos = _ask(dos, "Sind DoS-/Rate-Limit-Tests erlaubt?")
    social_engineering = _ask(social_engineering, "Ist Social Engineering erlaubt?")
    production_only = _ask(production_only, "Nur Produktivsystem im Scope (kein Staging)?")
    if rate_limit is None and interactive:
        rate_limit = typer.prompt("Rate-Limit-Hinweis (leer = keiner)", default="", show_default=False) or None
    if scope_note is None and interactive:
        scope_note = typer.prompt("Scope-Besonderheiten (leer = keine)", default="", show_default=False) or None
    if program_url is None and interactive:
        program_url = typer.prompt("Link zur Programm-Policy (leer = keiner)", default="", show_default=False) or None

    repo, _ = _repo()
    policy = repo.set_engagement_policy(EngagementPolicy(
        bruteforce_allowed=bruteforce, exploitation_allowed=exploitation, cracking_allowed=cracking,
        automated_scanning_allowed=automated, dos_testing_allowed=dos,
        social_engineering_allowed=social_engineering, production_only=production_only,
        rate_limit_note=rate_limit, scope_note=scope_note, program_url=program_url,
    ))
    repo.close()
    console.print("[green]Programm-Regeln gespeichert.[/green]")
    console.print(_policy_table(policy))


@policy_app.command("show")
def policy_show():
    """Zeigt die aktuell gültigen Programm-Regeln dieses Projekts."""
    repo, _ = _repo()
    policy = repo.get_engagement_policy()
    repo.close()
    if not policy_mod.has_any_answer(policy):
        console.print("[dim]Keine Programm-Regeln erfasst. Einrichten mit 'pentos policy setup'.[/dim]")
        return
    console.print(_policy_table(policy))


@policy_app.command("clear")
def policy_clear(yes: bool = typer.Option(False, "--yes", "-y", help="Ohne Rückfrage löschen")):
    """Entfernt alle Programm-Regeln dieses Projekts (keine Einschränkungen mehr)."""
    if not yes and not typer.confirm("Programm-Regeln wirklich entfernen?"):
        console.print("Abgebrochen.")
        raise typer.Exit()
    repo, _ = _repo()
    ok = repo.clear_engagement_policy()
    repo.close()
    console.print("[green]Programm-Regeln entfernt.[/green]" if ok else "[dim]Keine Regeln vorhanden.[/dim]")


if __name__ == "__main__":
    app()