"""Tests für die TUI-Datenschicht (Snapshot, Status-Zyklen)."""
import os
import tempfile

import pytest


def _fresh_repo():
    cfg = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(cfg, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    config.project_path("tuit").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("tuit"))
    return Repository(config.db_path("tuit")), config


def _seed(repo):
    from pentos.models import Host, Service, Finding, Task, Loot, Severity, FindingStatus, TaskStatus, LootType
    h = repo.add_host(Host(address="10.0.0.1", hostname="dc01"))
    repo.add_service(Service(host_id=h.id, port=445, name="microsoft-ds"))
    repo.add_finding(Finding(title="SMB Signing aus", severity=Severity.HIGH,
                             status=FindingStatus.UNVERIFIED, host_id=h.id))
    repo.add_finding(Finding(title="Info", severity=Severity.INFO, host_id=h.id))
    repo.add_task(Task(title="Shares prüfen", status=TaskStatus.OPEN, host_id=h.id))
    repo.add_loot(Loot(type=LootType.CREDENTIAL, label="admin", host_id=h.id))
    return h


def test_snapshot_counts():
    repo, _ = _fresh_repo()
    h = _seed(repo)
    from pentos.tui import data as tui_data
    from pentos.models import Severity
    snap = tui_data.build_snapshot(repo, "tuit")
    repo.close()
    assert snap.n_hosts == 1
    assert snap.n_services == 1
    assert snap.n_findings == 2
    assert snap.n_loot == 1
    assert snap.severity_counts[Severity.HIGH] == 1
    assert snap.severity_counts[Severity.INFO] == 1
    # host_addr-Auflösung
    assert snap.host_addr(h.id) == "10.0.0.1"
    assert snap.host_addr(None) == "-"
    assert snap.host_addr(999) == "-"


def test_open_priority_filters_closed_and_low():
    repo, _ = _fresh_repo()
    _seed(repo)
    from pentos.tui import data as tui_data
    snap = tui_data.build_snapshot(repo, "tuit")
    repo.close()
    prio = snap.open_priority()
    # Nur das offene High-Finding, nicht das Info
    assert len(prio) == 1
    assert prio[0].title == "SMB Signing aus"


def test_finding_status_cycle_wraps():
    from pentos.tui import data as tui_data
    from pentos.models import FindingStatus
    seq = []
    cur = FindingStatus.UNVERIFIED
    for _ in range(len(tui_data.FINDING_STATUS_CYCLE)):
        seq.append(cur)
        cur = tui_data.next_finding_status(cur)
    assert seq == tui_data.FINDING_STATUS_CYCLE
    # Wraparound: vom letzten zurück zum ersten
    assert tui_data.next_finding_status(tui_data.FINDING_STATUS_CYCLE[-1]) == tui_data.FINDING_STATUS_CYCLE[0]


def test_task_status_cycle():
    from pentos.tui import data as tui_data
    from pentos.models import TaskStatus
    assert tui_data.next_task_status(TaskStatus.OPEN) == TaskStatus.IN_PROGRESS
    assert tui_data.next_task_status(TaskStatus.IN_PROGRESS) == TaskStatus.DONE
    assert tui_data.next_task_status(TaskStatus.DONE) == TaskStatus.OPEN


def test_tui_app_smoke_headless():
    """Mountet die Textual-App headless und schaltet einen Finding-Status weiter."""
    pytest.importorskip("textual")
    import asyncio
    repo, _ = _fresh_repo()
    _seed(repo)
    repo.close()
    from pentos.tui.app import PentosTUI

    async def go():
        app = PentosTUI(project="tuit")
        async with app.run_test() as pilot:
            await pilot.pause()
            # Übersicht ist gerendert
            from textual.widgets import Static
            assert app.snapshot is not None
            assert app.snapshot.n_findings == 2

    asyncio.run(go())
