"""
Textual-App für PentOS: ein tastaturgesteuertes Lagebild des aktiven Projekts.

Bewusst dünn gehalten - die Daten kommen aus `tui/data.py`. Navigierbare Tabs
für Übersicht, Hosts, Dienste, Findings, Tasks, Loot und Journal. Findings- und
Task-Status lassen sich direkt per Taste durchschalten (schreibt ins Projekt).
Es wird nichts ausgeführt - reines Betrachten und Status-/Notiz-Pflege.
"""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Header, Static, TabbedContent, TabPane

from .. import config
from ..models import FindingStatus, Severity
from ..repository import Repository
from . import data as tui_data


_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _bar(value: int, total: int, width: int = 16) -> str:
    filled = int(round((value / total) * width)) if total else 0
    return "█" * filled + "░" * (width - filled)


class PentosTUI(App):
    """Terminal-Oberfläche für ein PentOS-Projekt."""

    CSS = """
    DataTable { height: 1fr; }
    #overview { padding: 1 2; }
    """

    BINDINGS = [
        Binding("q", "quit", "Beenden"),
        Binding("r", "refresh", "Aktualisieren"),
        Binding("s", "cycle_status", "Status wechseln"),
        Binding("ctrl+c", "quit", "Beenden", show=False),
    ]

    def __init__(self, project: str):
        super().__init__()
        self.project = project
        self.snapshot: tui_data.Snapshot | None = None
        # Parallele ID-Listen je Tabelle (Reihenfolge = Einfügereihenfolge)
        self._finding_ids: list[int] = []
        self._task_ids: list[int] = []

    # ── Aufbau ───────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-overview"):
            with TabPane("Übersicht", id="tab-overview"):
                yield Static(id="overview")
            with TabPane("Hosts", id="tab-hosts"):
                yield DataTable(id="t-hosts", cursor_type="row", zebra_stripes=True)
            with TabPane("Dienste", id="tab-services"):
                yield DataTable(id="t-services", cursor_type="row", zebra_stripes=True)
            with TabPane("Findings", id="tab-findings"):
                yield DataTable(id="t-findings", cursor_type="row", zebra_stripes=True)
            with TabPane("Tasks", id="tab-tasks"):
                yield DataTable(id="t-tasks", cursor_type="row", zebra_stripes=True)
            with TabPane("Loot", id="tab-loot"):
                yield DataTable(id="t-loot", cursor_type="row", zebra_stripes=True)
            with TabPane("Journal", id="tab-journal"):
                yield DataTable(id="t-journal", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "PentOS"
        try:
            self._setup_columns()
            self.load()
        except Exception as exc:  # robust: lieber Hinweis als Absturz
            self.sub_title = f"Fehler: {exc}"

    def _setup_columns(self) -> None:
        self.query_one("#t-hosts", DataTable).add_columns("ID", "Adresse", "Hostname", "OS", "Status")
        self.query_one("#t-services", DataTable).add_columns(
            "ID", "Host", "Port", "Proto", "Dienst", "Produkt", "Version")
        self.query_one("#t-findings", DataTable).add_columns(
            "ID", "Severity", "Status", "Titel", "Host")
        self.query_one("#t-tasks", DataTable).add_columns("ID", "Status", "Titel", "Quelle")
        self.query_one("#t-loot", DataTable).add_columns("ID", "Typ", "Label", "Host", "Quelle")
        self.query_one("#t-journal", DataTable).add_columns("Zeit", "Aktion", "Detail")

    # ── Laden / Rendern ──────────────────────────────────────────────────────
    def load(self) -> None:
        repo = Repository(config.db_path(self.project))
        try:
            self.snapshot = tui_data.build_snapshot(repo, self.project)
        finally:
            repo.close()
        self.sub_title = self.project
        self._render_overview()
        self._render_hosts()
        self._render_services()
        self._render_findings()
        self._render_tasks()
        self._render_loot()
        self._render_journal()

    def _render_overview(self) -> None:
        s = self.snapshot
        lines = [
            f"[bold cyan]{s.project}[/bold cyan]",
            "",
            f"Hosts {s.n_hosts}   Dienste {s.n_services}   Findings {s.n_findings}"
            f"   Loot {s.n_loot}   Runs {s.n_runs}",
            "",
            "[bold]Findings nach Severity[/bold]",
        ]
        total_f = max(s.n_findings, 1)
        for sev in _SEV_ORDER:
            c = s.severity_counts.get(sev, 0)
            lines.append(f"  [{_SEV_STYLE[sev]}]{sev.value:<9}[/] {_bar(c, total_f)} {c}")
        total_t = max(len(s.tasks), 1)
        pct = int(round((s.tasks_done / total_t) * 100)) if s.tasks else 0
        lines += [
            "",
            "[bold]Aufgaben[/bold]",
            f"  Fortschritt {_bar(s.tasks_done, total_t)} {pct}%",
            f"  [green]Erledigt[/] {s.tasks_done}   [yellow]In Arbeit[/] {s.tasks_in_progress}"
            f"   Offen {s.tasks_open}",
        ]
        prio = s.open_priority(8)
        if prio:
            lines += ["", "[bold red]⚠ Priorität (offene High/Critical)[/bold red]"]
            for f in prio:
                lines.append(f"  [{_SEV_STYLE[f.severity]}]●[/] [{f.severity.value}] {f.title} "
                             f"[dim]({f.status.value})[/]")
        lines += ["", "[dim]r = aktualisieren · s = Status wechseln (Findings/Tasks) · q = beenden[/dim]"]
        self.query_one("#overview", Static).update("\n".join(lines))

    def _render_hosts(self) -> None:
        t = self.query_one("#t-hosts", DataTable)
        t.clear()
        for h in self.snapshot.hosts:
            t.add_row(str(h.id), h.address, h.hostname or "-", h.os_guess or "-", h.status)

    def _render_services(self) -> None:
        t = self.query_one("#t-services", DataTable)
        t.clear()
        for svc in self.snapshot.services:
            t.add_row(str(svc.id), self.snapshot.host_addr(svc.host_id), str(svc.port),
                      svc.protocol, svc.name or "-", svc.product or "-", svc.version or "-")

    def _render_findings(self) -> None:
        t = self.query_one("#t-findings", DataTable)
        t.clear()
        self._finding_ids = []
        for f in self.snapshot.findings:
            self._finding_ids.append(f.id)
            sev = f"[{_SEV_STYLE[f.severity]}]{f.severity.value}[/]"
            t.add_row(str(f.id), sev, f.status.value, f.title,
                      self.snapshot.host_addr(f.host_id))

    def _render_tasks(self) -> None:
        t = self.query_one("#t-tasks", DataTable)
        t.clear()
        self._task_ids = []
        for task in self.snapshot.tasks:
            self._task_ids.append(task.id)
            t.add_row(str(task.id), task.status.value, task.title, task.source or "-")

    def _render_loot(self) -> None:
        t = self.query_one("#t-loot", DataTable)
        t.clear()
        for l in self.snapshot.loot:
            t.add_row(str(l.id), l.type.value, l.label,
                      self.snapshot.host_addr(l.host_id), l.source or "-")

    def _render_journal(self) -> None:
        t = self.query_one("#t-journal", DataTable)
        t.clear()
        for e in self.snapshot.journal[-200:]:
            t.add_row(e.ts, e.action, e.detail or "-")

    # ── Aktionen ─────────────────────────────────────────────────────────────
    def action_refresh(self) -> None:
        self.load()
        self.notify("Aktualisiert.", timeout=2)

    def action_cycle_status(self) -> None:
        active = self.query_one(TabbedContent).active
        if active == "tab-findings":
            self._cycle_finding()
        elif active == "tab-tasks":
            self._cycle_task()
        else:
            self.notify("Status wechseln geht im Findings- oder Tasks-Tab.", timeout=2)

    def _cycle_finding(self) -> None:
        t = self.query_one("#t-findings", DataTable)
        row = t.cursor_row
        if row is None or row < 0 or row >= len(self._finding_ids):
            return
        fid = self._finding_ids[row]
        cur = next((f for f in self.snapshot.findings if f.id == fid), None)
        if cur is None:
            return
        new = tui_data.next_finding_status(cur.status)
        repo = Repository(config.db_path(self.project))
        try:
            repo.set_finding_status(fid, new.value)
        finally:
            repo.close()
        self.load()
        t.move_cursor(row=min(row, max(len(self._finding_ids) - 1, 0)))
        self.notify(f"Finding #{fid} → {new.value}", timeout=2)

    def _cycle_task(self) -> None:
        t = self.query_one("#t-tasks", DataTable)
        row = t.cursor_row
        if row is None or row < 0 or row >= len(self._task_ids):
            return
        tid = self._task_ids[row]
        cur = next((x for x in self.snapshot.tasks if x.id == tid), None)
        if cur is None:
            return
        new = tui_data.next_task_status(cur.status)
        repo = Repository(config.db_path(self.project))
        try:
            repo.set_task_status(tid, new)
        finally:
            repo.close()
        self.load()
        t.move_cursor(row=min(row, max(len(self._task_ids) - 1, 0)))
        self.notify(f"Task #{tid} → {new.value}", timeout=2)


def run(project: str) -> None:
    """Startet die TUI für das angegebene Projekt."""
    PentosTUI(project=project).run()
