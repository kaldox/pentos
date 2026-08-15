"""Tests für die Engagement-Zeitplan-Integration in Markdown-, HTML- und
PDF-Report (pentos/report.py, pentos/export.py)."""
import os
import tempfile

import pytest


def _repo_with_timeline():
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
    from pentos.models import TimelineEntry, TimelineKind
    config.project_path("tlr").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("tlr"))
    repo = Repository(config.db_path("tlr"))
    repo.add_timeline_entry(TimelineEntry(
        kind=TimelineKind.MILESTONE, title="Kickoff", start_ts="2026-08-20 09:00",
    ))
    repo.add_timeline_entry(TimelineEntry(
        kind=TimelineKind.WINDOW, title="Testfenster", start_ts="2026-08-20 08:00",
        end_ts="2026-08-24 18:00", note="Eskalation: siehe RoE",
    ))
    repo.add_timeline_entry(TimelineEntry(
        kind=TimelineKind.BLACKOUT, title="Wartungsfenster Kunde", start_ts="2026-08-22 00:00",
        end_ts="2026-08-22 04:00",
    ))
    return repo, cfg


def _repo_without_timeline(name="tlr-empty"):
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
    config.project_path(name).mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path(name))
    return Repository(config.db_path(name)), cfg


def test_markdown_report_shows_timeline_table():
    from pentos import report
    repo, _tmp = _repo_with_timeline()
    md = report.build_markdown(repo, "tlr")
    assert "## Engagement-Zeitplan" in md
    assert "Meilenstein" in md and "Kickoff" in md
    assert "Zeitfenster" in md and "Testfenster" in md
    assert "Blackout" in md and "Wartungsfenster Kunde" in md
    assert "Eskalation: siehe RoE" in md


def test_markdown_report_omits_timeline_section_when_empty():
    from pentos import report
    repo, _tmp = _repo_without_timeline()
    md = report.build_markdown(repo, "tlr-empty")
    assert "## Engagement-Zeitplan" not in md


def test_html_report_shows_timeline_table():
    from pentos import export
    repo, _tmp = _repo_with_timeline()
    html = export.build_html(repo, "tlr", cfg={})
    assert "Engagement-Zeitplan" in html
    assert "Kickoff" in html
    assert "Testfenster" in html
    assert "Wartungsfenster Kunde" in html


def test_html_report_omits_timeline_section_when_empty():
    from pentos import export
    repo, _tmp = _repo_without_timeline()
    html = export.build_html(repo, "tlr-empty", cfg={})
    assert "Engagement-Zeitplan" not in html


def test_pdf_report_with_timeline_builds():
    pytest.importorskip("reportlab")
    from pentos import export
    repo, tmp = _repo_with_timeline()
    out = os.path.join(tmp, "timeline-report.pdf")
    export.build_pdf(repo, "tlr", out, cfg={})
    repo.close()
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_pdf_report_without_timeline_builds():
    pytest.importorskip("reportlab")
    from pentos import export
    repo, cfg = _repo_without_timeline("tlr-empty-pdf")
    out = os.path.join(cfg, "empty-timeline.pdf")
    export.build_pdf(repo, "tlr-empty-pdf", out, cfg={})
    repo.close()
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"
