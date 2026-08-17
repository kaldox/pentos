"""CLI-Tests für 'pentos finding attack' und 'pentos report --attack-navigator'."""
import json
import os
import tempfile

from typer.testing import CliRunner


def _project():
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
    from pentos.models import Finding
    config.project_path("cliatk").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("cliatk"))
    repo = Repository(config.db_path("cliatk"))
    f1 = repo.add_finding(Finding(title="Schwaches SSH-Passwort"))
    f2 = repo.add_finding(Finding(title="Kein Technique-Tag"))
    repo.close()
    config.set_active_project("cliatk")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod, f1.id, f2.id


def test_finding_attack_tags_with_valid_id():
    app_mod, f1, _f2 = _project()
    r = CliRunner().invoke(app_mod.app, ["finding", "attack", str(f1), "T1110", "--name", "Brute Force"])
    assert r.exit_code == 0, r.output
    assert "T1110" in r.output

    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("cliatk"))
    f = repo.get_finding(f1)
    repo.close()
    assert f.attack_technique == "T1110"
    assert f.attack_technique_name == "Brute Force"


def test_finding_attack_rejects_invalid_id():
    app_mod, f1, _f2 = _project()
    r = CliRunner().invoke(app_mod.app, ["finding", "attack", str(f1), "not-a-technique"])
    assert r.exit_code == 1
    assert "sieht nicht wie eine ATT&CK-Technique-ID aus" in r.output


def test_finding_attack_unknown_finding_fails_cleanly():
    app_mod, _f1, _f2 = _project()
    r = CliRunner().invoke(app_mod.app, ["finding", "attack", "999999", "T1110"])
    assert r.exit_code == 1
    assert "existiert nicht" in r.output


def test_finding_attack_clear_removes_tag():
    app_mod, f1, _f2 = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["finding", "attack", str(f1), "T1110"])
    r = runner.invoke(app_mod.app, ["finding", "attack", str(f1), "--clear"])
    assert r.exit_code == 0, r.output
    assert "entfernt" in r.output

    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("cliatk"))
    f = repo.get_finding(f1)
    repo.close()
    assert f.attack_technique is None


def test_finding_attack_missing_id_without_clear_fails():
    app_mod, f1, _f2 = _project()
    r = CliRunner().invoke(app_mod.app, ["finding", "attack", str(f1)])
    assert r.exit_code == 1
    assert "fehlt" in r.output


def test_finding_show_displays_attack_technique():
    app_mod, f1, _f2 = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["finding", "attack", str(f1), "T1110", "--name", "Brute Force"])
    r = runner.invoke(app_mod.app, ["finding", "show", str(f1)])
    assert r.exit_code == 0, r.output
    assert "T1110" in r.output
    assert "Brute Force" in r.output


# ── report --attack-navigator ────────────────────────────────────────────────
def test_report_attack_navigator_writes_valid_layer_json():
    app_mod, f1, _f2 = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["finding", "attack", str(f1), "T1110", "--name", "Brute Force"])
    r = runner.invoke(app_mod.app, ["report", "--attack-navigator"])
    assert r.exit_code == 0, r.output
    assert "ATT&CK-Navigator-Layer erstellt" in r.output

    from pentos import config
    out = config.project_path("cliatk") / "reports" / "attack-navigator.json"
    assert out.exists()
    layer = json.loads(out.read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"][0]["techniqueID"] == "T1110"


def test_report_attack_navigator_no_tags_shows_hint():
    app_mod, _f1, _f2 = _project()
    r = CliRunner().invoke(app_mod.app, ["report", "--attack-navigator"])
    assert r.exit_code == 0, r.output
    assert "Keine Findings mit Technique-Tag" in r.output


def test_report_attack_navigator_respects_out_flag():
    app_mod, f1, _f2 = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["finding", "attack", str(f1), "T1110"])
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "custom-layer.json")
        r = runner.invoke(app_mod.app, ["report", "--attack-navigator", "--out", target])
        assert r.exit_code == 0, r.output
        assert os.path.exists(target)
