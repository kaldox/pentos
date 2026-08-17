"""Tests für die ATT&CK-Technique-Anzeige in Markdown-, HTML- und PDF-Report
(neben CVSS/EPSS)."""
import os
import tempfile

import pytest


def _repo_with_tagged_finding():
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
    config.project_path("atkr").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("atkr"))
    repo = Repository(config.db_path("atkr"))
    repo.add_finding(Finding(
        title="SSH-Brute-Force erfolgreich", severity=Severity.HIGH, category=FindingCategory.CREDENTIAL,
        attack_technique="T1110", attack_technique_name="Brute Force",
    ))
    return repo, cfg


def test_markdown_report_shows_attack_technique():
    from pentos import report
    repo, _tmp = _repo_with_tagged_finding()
    md = report.build_markdown(repo, "atkr")
    assert "**ATT&CK:** T1110 – Brute Force" in md


def test_markdown_report_omits_attack_line_when_untagged():
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
    config.project_path("atkr-empty").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("atkr-empty"))
    repo = Repository(config.db_path("atkr-empty"))
    repo.add_finding(Finding(title="Ohne Tag"))
    md = report.build_markdown(repo, "atkr-empty")
    repo.close()
    assert "ATT&CK" not in md


def test_html_report_shows_attack_technique():
    from pentos import export
    repo, _tmp = _repo_with_tagged_finding()
    html = export.build_html(repo, "atkr", cfg={})
    assert "ATT&amp;CK T1110" in html
    assert "Brute Force" in html


def test_pdf_report_with_attack_technique_builds():
    pytest.importorskip("reportlab")
    from pentos import export
    repo, tmp = _repo_with_tagged_finding()
    out = os.path.join(tmp, "attack-report.pdf")
    export.build_pdf(repo, "atkr", out, cfg={})
    repo.close()
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"
