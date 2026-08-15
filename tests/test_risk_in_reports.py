"""Tests für die Risk-Score-/Chart-Integration in Markdown-, HTML- und
PDF-Report (pentos/report.py, pentos/export.py)."""
import os
import tempfile

import pytest


def _repo_with_mixed_findings():
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
    from pentos.models import Finding, FindingCategory, FindingStatus, Severity
    config.project_path("rr").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("rr"))
    repo = Repository(config.db_path("rr"))
    repo.add_finding(Finding(title="Kritisch", severity=Severity.CRITICAL,
                             category=FindingCategory.VULN, status=FindingStatus.CONFIRMED))
    repo.add_finding(Finding(title="Hoch", severity=Severity.HIGH,
                             category=FindingCategory.VULN, status=FindingStatus.UNVERIFIED))
    repo.add_finding(Finding(title="Erledigt", severity=Severity.CRITICAL,
                             category=FindingCategory.VULN, status=FindingStatus.CLOSED))
    return repo, cfg


def test_markdown_report_shows_risk_score():
    from pentos import report
    repo, _tmp = _repo_with_mixed_findings()
    md = report.build_markdown(repo, "rr")
    # Kritisch + Hoch aktiv = Score 16, geschlossenes Kritisch zaehlt nicht mit
    assert "Risk-Score: 16 (Kritisch)" in md
    assert "2 offene Findings" in md


def test_html_report_shows_risk_score_and_chart():
    from pentos import export
    repo, _tmp = _repo_with_mixed_findings()
    html = export.build_html(repo, "rr", cfg={})
    assert "Risk-Score" in html or "risk-score" in html
    assert "16" in html
    assert "Kritisch" in html
    assert "<svg" in html  # Donut-Chart ist inline-SVG, kein externes Bild
    assert "FINDINGS" in html  # Zentrale Beschriftung im Donut


def test_html_report_risk_zero_when_no_findings():
    from pentos import export
    import tempfile as _t, os as _o
    cfg = _t.mkdtemp()
    _o.environ["PENTOS_CONFIG"] = _o.path.join(cfg, "config.yaml")
    open(_o.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    config.project_path("empty").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("empty"))
    repo = Repository(config.db_path("empty"))
    html = export.build_html(repo, "empty", cfg={})
    repo.close()
    assert "Minimal" in html
    assert "keine" in html  # Donut-Leerzustand


def test_pdf_report_with_risk_score_builds():
    pytest.importorskip("reportlab")
    from pentos import export
    repo, tmp = _repo_with_mixed_findings()
    out = os.path.join(tmp, "risk-report.pdf")
    export.build_pdf(repo, "rr", out, cfg={})
    repo.close()
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_pdf_report_without_findings_builds():
    """Kein Pie-Chart bei 0 Findings (_pdf_severity_pie gibt None zurueck) --
    darf den PDF-Aufbau trotzdem nicht kaputt machen."""
    pytest.importorskip("reportlab")
    import tempfile as _t, os as _o
    from pentos import export
    cfg = _t.mkdtemp()
    _o.environ["PENTOS_CONFIG"] = _o.path.join(cfg, "config.yaml")
    open(_o.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    config.project_path("empty2").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("empty2"))
    repo = Repository(config.db_path("empty2"))
    out = os.path.join(cfg, "empty.pdf")
    export.build_pdf(repo, "empty2", out, cfg={})
    repo.close()
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_risk_donut_svg_helper_directly():
    from pentos.export import _donut_svg
    from pentos.models import Severity
    svg = _donut_svg({Severity.CRITICAL: 2, Severity.LOW: 1})
    assert svg.startswith("<svg")
    assert svg.count("<circle") >= 2  # Hintergrundring + mind. 1 Segment
    assert ">3<" in svg  # Gesamtzahl mittig
