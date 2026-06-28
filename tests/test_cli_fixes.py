"""Tests für CLI-Verbesserungen aus dem Kenobi-Livetest:
- `template apply --host` akzeptiert Host-ID ODER -Adresse
- `note add --category` als Alias für `--cat`
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
    h = repo.add_host(Host(address="10.80.185.99"))
    repo.seed_builtin_templates()
    repo.close()
    config.set_active_project("k")
    hid = h.id
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app, hid


def _last_finding_host():
    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("k"))
    f = repo.list_findings()[-1]
    repo.close()
    return f.host_id


def test_template_apply_host_by_id():
    app, hid = _project_with_host()
    r = CliRunner().invoke(app, ["template", "apply", "null-session", "--host", str(hid)])
    assert r.exit_code == 0, r.output
    assert "nicht im Projekt" not in r.output
    assert _last_finding_host() == hid


def test_template_apply_host_by_address():
    app, hid = _project_with_host()
    r = CliRunner().invoke(app, ["template", "apply", "null-session", "--host", "10.80.185.99"])
    assert r.exit_code == 0, r.output
    assert "nicht im Projekt" not in r.output
    assert _last_finding_host() == hid


def test_template_apply_unknown_host_warns_but_creates():
    app, _ = _project_with_host()
    r = CliRunner().invoke(app, ["template", "apply", "null-session", "--host", "9.9.9.9"])
    assert r.exit_code == 0, r.output
    assert "nicht im Projekt" in r.output
    assert _last_finding_host() is None


def test_note_category_alias():
    app, _ = _project_with_host()
    r = CliRunner().invoke(app, ["note", "add", "SMB-Notiz", "--category", "smb"])
    assert r.exit_code == 0, r.output
    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("k"))
    n = repo.list_notes()[-1]
    repo.close()
    assert n.category == "smb"
