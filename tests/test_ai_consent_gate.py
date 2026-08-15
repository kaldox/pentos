"""Regression: 'ai explain-finding' und 'ai enum' müssen wie alle anderen
KI-Befehle über _confirm_ai_send laufen (Cloud-Zustimmungsabfrage), statt
das KI-Backend direkt und ungefragt aufzurufen.
"""
import os
import tempfile

from typer.testing import CliRunner


def _project_with_finding_and_service():
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
    from pentos.models import Host, Service, Finding, Severity, FindingCategory, FindingStatus
    config.project_path("k").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("k"))
    repo = Repository(config.db_path("k"))
    h = repo.add_host(Host(address="10.10.10.5"))
    svc = repo.add_service(Service(host_id=h.id, port=80, protocol="tcp", name="http"))
    f = repo.add_finding(Finding(title="Test-Finding", severity=Severity.LOW,
                                 category=FindingCategory.OTHER, status=FindingStatus.UNVERIFIED,
                                 host_id=h.id))
    repo.close()
    config.set_active_project("k")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app, f.id, svc.id


def test_explain_finding_requires_backend_via_confirm_gate():
    # exit_code 0 ist hier korrekt (bare typer.Exit(), wie bei den anderen
    # _confirm_ai_send-gegateten Befehlen z.B. ai analyze) -- entscheidend ist,
    # dass _confirm_ai_send ueberhaupt greift statt das Backend ungefragt zu rufen.
    app, fid, _sid = _project_with_finding_and_service()
    r = CliRunner().invoke(app, ["ai", "explain-finding", str(fid)])
    assert r.exit_code == 0
    assert "Kein KI-Backend konfiguriert" in r.output
    assert "Abgebrochen" in r.output


def test_ai_enum_requires_backend_via_confirm_gate():
    app, _fid, sid = _project_with_finding_and_service()
    r = CliRunner().invoke(app, ["ai", "enum", str(sid)])
    assert r.exit_code == 0
    assert "Kein KI-Backend konfiguriert" in r.output
    assert "Abgebrochen" in r.output
