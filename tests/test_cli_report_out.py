"""Regression: 'pentos report --html --out <pfad>' muss den angegebenen Pfad
immer respektieren, unabhängig von der Dateiendung -- wie es '--pdf --out'
schon tut. Vorher wurde --out bei --html stillschweigend verworfen, wenn die
Endung nicht exakt '.html' war, und stattdessen nach reports/report.html
geschrieben, ohne jede Warnung.
"""
import os
import tempfile
from pathlib import Path

from typer.testing import CliRunner


def _project_with_finding():
    cfg = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(cfg, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
        "report: {company: '', color: '#0f766e', author: ''}\n"
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    from pentos.models import Finding, Severity, FindingCategory, FindingStatus
    config.project_path("k").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("k"))
    repo = Repository(config.db_path("k"))
    repo.add_finding(Finding(title="X", severity=Severity.LOW, category=FindingCategory.OTHER,
                             status=FindingStatus.UNVERIFIED))
    repo.close()
    config.set_active_project("k")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app, cfg


def test_report_html_out_with_non_html_suffix_is_honored():
    app, cfg = _project_with_finding()
    target = Path(cfg) / "myreport.txt"
    r = CliRunner().invoke(app, ["report", "--html", "--out", str(target)])
    assert r.exit_code == 0, r.output
    assert target.exists()
    assert str(target) in r.output


def test_report_html_out_with_html_suffix_still_works():
    app, cfg = _project_with_finding()
    target = Path(cfg) / "custom.html"
    r = CliRunner().invoke(app, ["report", "--html", "--out", str(target)])
    assert r.exit_code == 0, r.output
    assert target.exists()
