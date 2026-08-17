"""Tests für die Programm-Regeln-Anzeige in Markdown-, HTML- und PDF-Report."""
import os
import tempfile

import pytest


def _repo_with_policy():
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
    from pentos.models import EngagementPolicy
    config.project_path("polr").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("polr"))
    repo = Repository(config.db_path("polr"))
    repo.set_engagement_policy(EngagementPolicy(
        bruteforce_allowed=False, exploitation_allowed=True, dos_testing_allowed=False,
        rate_limit_note="10 req/s", program_url="https://hackerone.com/example",
    ))
    return repo, cfg


def _repo_without_policy(name="polr-empty"):
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


def test_markdown_report_shows_policy_table():
    from pentos import report
    repo, _tmp = _repo_with_policy()
    md = report.build_markdown(repo, "polr")
    assert "## Programm-Regeln" in md
    assert "| Brute-Force | nicht erlaubt |" in md
    assert "| Rate-Limit | 10 req/s |" in md
    assert "hackerone.com/example" in md


def test_markdown_report_omits_policy_section_when_none_set():
    from pentos import report
    repo, _tmp = _repo_without_policy()
    md = report.build_markdown(repo, "polr-empty")
    assert "Programm-Regeln" not in md


def test_html_report_shows_policy_table():
    from pentos import export
    repo, _tmp = _repo_with_policy()
    html = export.build_html(repo, "polr", cfg={})
    assert "Programm-Regeln" in html
    assert "Brute-Force" in html
    assert "10 req/s" in html


def test_html_report_omits_policy_section_when_none_set():
    from pentos import export
    repo, _tmp = _repo_without_policy()
    html = export.build_html(repo, "polr-empty", cfg={})
    assert "Programm-Regeln" not in html


def test_pdf_report_with_policy_builds():
    pytest.importorskip("reportlab")
    from pentos import export
    repo, tmp = _repo_with_policy()
    out = os.path.join(tmp, "policy-report.pdf")
    export.build_pdf(repo, "polr", out, cfg={})
    repo.close()
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_pdf_report_without_policy_builds():
    pytest.importorskip("reportlab")
    from pentos import export
    repo, cfg = _repo_without_policy("polr-empty-pdf")
    out = os.path.join(cfg, "empty-policy.pdf")
    export.build_pdf(repo, "polr-empty-pdf", out, cfg={})
    repo.close()
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"
