"""
CLI-Befehle: Workspace (Projekte, Hosts, Services, Scope, Engagement-
Zeitplan, Engagement-Policy).

Ausgelagert aus cli/app.py (Kill-List-/Struktur-Aufräumung) -- reine
Verschiebung, kein Verhalten geändert. Jede Gruppe bringt ihr eigenes
`typer.Typer()` mit; die Registrierung am Haupt-`app` (Name, Hilfe-Panel)
passiert zentral in app.py.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from .. import archive as archive_mod
from .. import config
from .. import findings_rules, recommend
from .. import policy as policy_mod
from ..models import EngagementPolicy, Host, Service, TaskStatus, TimelineEntry, TimelineKind
from ..repository import Repository
from ..workspace import create_workspace, list_projects
from ._shared import console, SYM_ARROW, SYM_BULLET, _repo


# ── Projekte ─────────────────────────────────────────────────────────────────
project_app = typer.Typer(help="Projekte / Workspaces verwalten")


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

# ── Scope ────────────────────────────────────────────────────────────────────
scope_app = typer.Typer(help="Scope (erlaubte Ziele) verwalten")


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
