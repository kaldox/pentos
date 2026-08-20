"""
PentOS – Kommandozeile (Typer + Rich).

Definiert das Haupt-`app`-Objekt und die Befehle, die direkt daran hängen
(recommend/report/dashboard/serve/mcp/tools/run/sweep/runs -- bewusst OHNE
eigenes Sub-Typer, sonst würde z.B. aus `pentos run` ein verschachteltes
`pentos recon run` und bestehende Skripte/Muster würden brechen).

Alle anderen Befehlsgruppen (Projekte/Hosts/Services/Scope/Zeitplan/Policy,
Findings/Aufgaben/Notizen/Loot/Evidence/Journal/Graph, Scan-Import/
Wordlists/Playbooks, KI-Mentor) sind eigene, in sich geschlossene
`typer.Typer()`-Instanzen in cli/workspace.py, cli/findings.py,
cli/recon_extra.py und cli/ai_cmds.py -- hier nur importiert und am
Haupt-`app` registriert (Name, Hilfe-Panel).
"""
from __future__ import annotations

import json
import secrets
import shlex
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table

from .. import attack_navigator as attack_navigator_mod
from .. import bruteforce as bruteforce_mod
from .. import config
from .. import policy as policy_mod
from .. import recommend, report as report_mod
from .. import export as export_mod
from ..models import FindingStatus, Severity, TaskStatus
from ..runners import base as runner_base, parsers as runner_parsers, registry as runner_registry

from ._shared import (
    console, BAR_EMPTY, BAR_FULL, SYM_ARROW, SYM_BULLET, SYM_MISSING,
    SYM_NEXT, SYM_OK, SYM_WARN, _repo,
)
from .workspace import project_app, host_app, service_app, scope_app, timeline_app, policy_app
from .findings import (
    task_app, finding_app, template_app, note_app, loot_app, evidence_app,
    journal_app, graph_app,
)
from .recon_extra import scan_app, wordlists_app, playbook_app
from .ai_cmds import ai_app

app = typer.Typer(help="PentOS – Knowledge-Driven Offensive Security Workspace",
                  no_args_is_help=True, add_completion=True)

app.add_typer(project_app, name="project", rich_help_panel="Workspace")
app.add_typer(host_app, name="host", rich_help_panel="Workspace")
app.add_typer(service_app, name="service", rich_help_panel="Workspace")
app.add_typer(scan_app, name="scan", rich_help_panel="Recon & Import")


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

app.add_typer(task_app, name="task", rich_help_panel="Befunde & Doku")
app.add_typer(finding_app, name="finding", rich_help_panel="Befunde & Doku")
app.add_typer(template_app, name="template", rich_help_panel="Befunde & Doku")
app.add_typer(note_app, name="note", rich_help_panel="Befunde & Doku")
app.add_typer(loot_app, name="loot", rich_help_panel="Befunde & Doku")
app.add_typer(evidence_app, name="evidence", rich_help_panel="Befunde & Doku")
app.add_typer(journal_app, name="journal", rich_help_panel="Befunde & Doku")
app.add_typer(graph_app, name="graph", rich_help_panel="Reporting & Übersicht")


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

app.add_typer(ai_app, name="ai", rich_help_panel="KI & Integration")

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


@app.command("serve", rich_help_panel="KI & Integration")
def serve_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind-Adresse (Default nur lokal)"),
    port: int = typer.Option(8787, "--port", "-p", help="Port"),
    project: Optional[str] = typer.Option(None, "--project", help="Startprojekt (sonst aktives/erstes)"),
    yes: bool = typer.Option(False, "--yes", "-y",
                             help="Nicht-lokale Bind-Adresse ohne Rückfrage bestätigen"),
):
    """Startet das Web-Dashboard (Ansicht + Status-/Notiz-Pflege deines Workspace).

    Standardmässig nur über 127.0.0.1 erreichbar. Jeder Start erzeugt einen
    Zufalls-Token (nur hier im Terminal sichtbar) - alle API-Endpunkte, auch
    lesende (inkl. Loot/Credentials), verlangen ihn. Benötigt die Web-Extras:
    pip install -e ".[web]"
    """
    try:
        from ..web import server as web_server
    except ModuleNotFoundError:
        console.print('[red]Web-Extras fehlen.[/red] Installiere: [cyan]pip install -e ".[web]"[/cyan]')
        raise typer.Exit(1)
    if host not in _LOOPBACK_HOSTS and not yes:
        console.print(
            f"[yellow]{SYM_WARN} Nicht-lokale Bind-Adresse:[/yellow] '{host}' macht das Dashboard "
            "für andere Geräte im selben Netz erreichbar (der Zugriffs-Token schützt weiterhin "
            "vor Mitlesen, aber der Traffic läuft unverschlüsselt). Nur in einem vertrauenswürdigen "
            "Netz nutzen, sonst per SSH-Tunnel/VPN auf 127.0.0.1 bleiben."
        )
        if not typer.confirm(f"Wirklich auf '{host}' binden?", default=False):
            console.print("Abgebrochen."); raise typer.Exit()
    proj = project
    if proj is None:
        try:
            proj = config.get_active_project()
        except Exception:
            proj = None
    token = secrets.token_urlsafe(24)
    url = f"http://{host}:{port}/?token={token}"
    lokal = host in _LOOPBACK_HOSTS
    console.print(Panel.fit(
        f"[bold]PentOS Dashboard[/bold]\n"
        f"URL:      [cyan]{url}[/cyan]\n"
        f"Projekt:  {proj or '(erstes verfügbares)'}\n"
        f"Bind:     {host}:{port}  "
        + ("([green]nur lokal[/green])" if lokal else "([yellow]netzwerkweit erreichbar[/yellow])")
        + "\n\n[dim]Zugriffs-Token nur oben im Link sichtbar, nicht wiederholbar abrufbar. "
          "Stoppen mit Strg+C[/dim]",
        title="serve"))
    try:
        web_server.serve(project=proj, host=host, port=port, token=token)
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

app.add_typer(wordlists_app, name="wordlists", rich_help_panel="Recon & Import")


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
            proto_extra: Optional[str] = typer.Option(
                None, "--proto-extra",
                help="Zusatzparameter fürs Protokoll-Modul (nur hydra), z.B. bei "
                     "http-post-form: \"/login.php:user=^USER^&pass=^PASS^:F=Login failed\""),
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

    if (userlist or passlist or proto or proto_extra) and args:
        console.print("[red]--userlist/--passlist/--proto/--proto-extra nicht zusammen mit --args "
                       "nutzen[/red] -- entweder die Kurzform oder --args mit dem vollständigen Rest, "
                       "nicht beides.")
        repo.close(); raise typer.Exit(1)
    if (userlist or passlist or proto or proto_extra) and not bruteforce_mod.is_supported(tool):
        console.print(f"[red]'{tool}' unterstützt --userlist/--passlist/--proto/--proto-extra "
                      f"nicht.[/red] Unterstützte Tools: {', '.join(bruteforce_mod.SUPPORTED_TOOLS)}.")
        repo.close(); raise typer.Exit(1)
    if proto_extra and not bruteforce_mod.supports_proto_extra(tool):
        console.print(f"[red]'{tool}' unterstützt --proto-extra nicht.[/red] "
                      f"Unterstützte Tools: {', '.join(bruteforce_mod.PROTO_EXTRA_SUPPORTED)}. "
                      "Für andere Module-Optionen --args verwenden.")
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
        extra = bruteforce_mod.build_args(tool, ul, pl, proto, proto_extra)
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

app.add_typer(playbook_app, name="playbook", rich_help_panel="Recon & Import")
app.add_typer(scope_app, name="scope", rich_help_panel="Workspace")
app.add_typer(timeline_app, name="timeline", rich_help_panel="Workspace")
app.add_typer(policy_app, name="policy", rich_help_panel="Workspace")


if __name__ == "__main__":
    app()
