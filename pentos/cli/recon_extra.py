"""
CLI-Befehle: Recon-Import und Drumherum (Scanner-Import, Standard-
Wordlists, Methodik-Playbooks).

Ausgelagert aus cli/app.py -- reine Verschiebung, kein Verhalten geändert.
Die übrigen "Recon & Import"-Befehle (recommend/tools/run/sweep) hängen
direkt am Haupt-`app` (kein eigenes Sub-Typer) und bleiben deshalb in
app.py -- sonst würde z.B. aus `pentos run` ein verschachteltes
`pentos recon run` und bestehende Skripte/Muster würden brechen.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from .. import config
from .. import diff as diff_mod
from .. import findings_rules, recommend
from .. import playbooks as playbooks_mod
from .. import wordlists as wordlists_mod
from ..importers import bloodhound as bloodhound_importer
from ..importers import nmap as nmap_importer
from ..importers import scanners as scanner_importer
from ..models import BloodHoundImport, Finding, FindingCategory, FindingStatus, Note, Severity
from ._shared import (
    console, BAR_EMPTY, BAR_FULL, SYM_ARROW, SYM_NEXT, SYM_OK, SYM_PENDING, SYM_SKIP, _repo,
)


# ── Scan-Import ──────────────────────────────────────────────────────────────
scan_app = typer.Typer(help="Scanner-Outputs importieren")


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

# ── Standard-Wordlists (Usernames gebündelt, Passwörter opt-in per Download) ─
wordlists_app = typer.Typer(help="Standard-Wordlists fürs Projekt einrichten (hydra/medusa/gobuster/...)")


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

# ── Playbooks / Methodik ──────────────────────────────────────────────────────
playbook_app = typer.Typer(help="Methodik-Playbooks (Checklisten)")

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
