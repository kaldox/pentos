"""
CLI-Befehle: Findings & Doku (Aufgaben, Findings, Finding-Vorlagen, Notizen,
Loot/Credentials, Evidence, Journal, Attack-Path-Graph).

Ausgelagert aus cli/app.py -- reine Verschiebung, kein Verhalten geändert.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from .. import attack_navigator as attack_navigator_mod
from .. import config
from .. import credmatch as credmatch_mod
from .. import epss as epss_mod
from .. import graph as graph_mod
from ..models import (
    Evidence, Finding, FindingCategory, FindingStatus, FindingTemplate,
    Loot, LootType, Note, Severity, Task, TaskStatus,
)
from ._shared import console, SYM_ARROW, SYM_OK, _repo

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


# ── Aufgaben ─────────────────────────────────────────────────────────────────
task_app = typer.Typer(help="Aufgaben verwalten")


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

# ── Journal ──────────────────────────────────────────────────────────────────
journal_app = typer.Typer(help="Journal / Timeline")


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
