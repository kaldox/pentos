"""Tests für die EPSS-Anzeige in Markdown-, HTML- und PDF-Report (neben CVSS)."""
import os
import tempfile

import pytest


def _repo_with_enriched_finding():
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
    from pentos.models import Finding, FindingCategory, Severity
    config.project_path("er").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("er"))
    repo = Repository(config.db_path("er"))
    f = repo.add_finding(Finding(
        title="Heartbleed", severity=Severity.HIGH, category=FindingCategory.VULN,
        description="CVE-2014-0160", cvss_score=7.5, cvss_vector="AV:N/AC:L/Au:N/C:P/I:N/A:N",
    ))
    repo.set_finding_epss(f.id, 0.94123, 0.99001)
    return repo, cfg


def test_markdown_report_shows_epss_next_to_cvss():
    from pentos import report
    repo, _tmp = _repo_with_enriched_finding()
    md = report.build_markdown(repo, "er")
    assert "**EPSS:** 0.941 (Perzentil 0.99)" in md


def test_markdown_report_omits_epss_when_not_enriched():
    from pentos import report
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
    from pentos.models import Finding
    config.project_path("er-empty").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("er-empty"))
    repo = Repository(config.db_path("er-empty"))
    repo.add_finding(Finding(title="Ohne CVE", description="kein Bezug"))
    md = report.build_markdown(repo, "er-empty")
    repo.close()
    assert "EPSS" not in md


def test_html_report_shows_epss():
    from pentos import export
    repo, _tmp = _repo_with_enriched_finding()
    html = export.build_html(repo, "er", cfg={})
    assert "EPSS 0.941" in html
    assert "Perzentil 0.99" in html


def test_pdf_report_with_epss_builds():
    pytest.importorskip("reportlab")
    from pentos import export
    repo, tmp = _repo_with_enriched_finding()
    out = os.path.join(tmp, "epss-report.pdf")
    export.build_pdf(repo, "er", out, cfg={})
    repo.close()
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"
