"""Regression: 'finding add --host/--service' mit einer nicht existierenden
ID darf nicht mit einem rohen sqlite3.IntegrityError-Traceback abstürzen
(FOREIGN KEY constraint failed), sondern muss sauber und verständlich
fehlschlagen -- wie es andere Befehle (z.B. template apply --host) schon tun.
"""
import os
import tempfile

from typer.testing import CliRunner


def _project_with_host():
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
    from pentos.models import Host
    config.project_path("k").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("k"))
    repo = Repository(config.db_path("k"))
    h = repo.add_host(Host(address="10.10.10.5"))
    repo.close()
    config.set_active_project("k")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app, h.id


def test_finding_add_unknown_host_fails_cleanly():
    app, _hid = _project_with_host()
    r = CliRunner().invoke(app, ["finding", "add", "X", "--host", "999"])
    assert r.exit_code != 0
    assert "nicht im Projekt" in r.output
    assert "IntegrityError" not in r.output
    assert "Traceback" not in r.output


def test_finding_add_unknown_service_fails_cleanly():
    app, _hid = _project_with_host()
    r = CliRunner().invoke(app, ["finding", "add", "X", "--service", "999"])
    assert r.exit_code != 0
    assert "nicht im Projekt" in r.output
    assert "IntegrityError" not in r.output


def test_finding_add_valid_host_still_works():
    app, hid = _project_with_host()
    r = CliRunner().invoke(app, ["finding", "add", "X", "--host", str(hid)])
    assert r.exit_code == 0, r.output
    assert "Finding #" in r.output
