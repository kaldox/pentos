"""
Datenschicht für die PentOS-TUI.

Bewusst frei von Textual: hier wird nur aus dem Repository ein `Snapshot`
gebaut und es liegen die reinen Status-Zyklus-Helfer. So ist die Logik ohne
laufende Oberfläche testbar; die Textual-App in `app.py` rendert nur.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import (
    Finding,
    FindingStatus,
    Host,
    JournalEntry,
    Loot,
    RunRecord,
    Service,
    Severity,
    Task,
    TaskStatus,
)
from ..repository import Repository


# ── Snapshot ─────────────────────────────────────────────────────────────────
@dataclass
class Snapshot:
    project: str
    hosts: list[Host] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tasks: list[Task] = field(default_factory=list)
    loot: list[Loot] = field(default_factory=list)
    runs: list[RunRecord] = field(default_factory=list)
    journal: list[JournalEntry] = field(default_factory=list)
    severity_counts: dict[Severity, int] = field(default_factory=dict)
    _host_addr: dict[int, str] = field(default_factory=dict)

    # — abgeleitete Kennzahlen —
    @property
    def n_hosts(self) -> int:
        return len(self.hosts)

    @property
    def n_services(self) -> int:
        return len(self.services)

    @property
    def n_findings(self) -> int:
        return len(self.findings)

    @property
    def n_loot(self) -> int:
        return len(self.loot)

    @property
    def n_runs(self) -> int:
        return len(self.runs)

    @property
    def tasks_done(self) -> int:
        return sum(1 for t in self.tasks if t.status == TaskStatus.DONE)

    @property
    def tasks_in_progress(self) -> int:
        return sum(1 for t in self.tasks if t.status == TaskStatus.IN_PROGRESS)

    @property
    def tasks_open(self) -> int:
        return len(self.tasks) - self.tasks_done - self.tasks_in_progress

    def host_addr(self, host_id: Optional[int]) -> str:
        """Adresse zu einer host_id (oder '-')."""
        if host_id is None:
            return "-"
        return self._host_addr.get(host_id, "-")

    def open_priority(self, limit: int = 12) -> list[Finding]:
        """Offene High/Critical-Findings (für die Übersicht)."""
        crit = [
            f for f in self.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
            and f.status != FindingStatus.CLOSED
        ]
        return crit[:limit]


def build_snapshot(repo: Repository, project: str) -> Snapshot:
    """Liest den kompletten Projektstand in einen Snapshot."""
    hosts = repo.list_hosts()
    services = repo.list_services()
    findings = repo.list_findings()
    tasks = repo.list_tasks()
    loot = repo.list_loot()
    runs = repo.list_runs()
    journal = repo.journal()

    sev_counts = {s: 0 for s in Severity}
    for f in findings:
        sev_counts[f.severity] += 1

    addr = {h.id: h.address for h in hosts if h.id is not None}

    return Snapshot(
        project=project,
        hosts=hosts,
        services=services,
        findings=findings,
        tasks=tasks,
        loot=loot,
        runs=runs,
        journal=journal,
        severity_counts=sev_counts,
        _host_addr=addr,
    )


# ── Status-Zyklen (rein) ─────────────────────────────────────────────────────
FINDING_STATUS_CYCLE: list[FindingStatus] = [
    FindingStatus.UNVERIFIED,
    FindingStatus.CONFIRMED,
    FindingStatus.EXPLOITED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.CLOSED,
]

TASK_STATUS_CYCLE: list[TaskStatus] = [
    TaskStatus.OPEN,
    TaskStatus.IN_PROGRESS,
    TaskStatus.DONE,
]


def _next_in_cycle(current, cycle):
    try:
        idx = cycle.index(current)
    except ValueError:
        return cycle[0]
    return cycle[(idx + 1) % len(cycle)]


def next_finding_status(current: FindingStatus) -> FindingStatus:
    """Nächster Finding-Status im Zyklus (wraparound)."""
    return _next_in_cycle(current, FINDING_STATUS_CYCLE)


def next_task_status(current: TaskStatus) -> TaskStatus:
    """Nächster Task-Status im Zyklus (Offen → In Bearbeitung → Erledigt → …)."""
    return _next_in_cycle(current, TASK_STATUS_CYCLE)
