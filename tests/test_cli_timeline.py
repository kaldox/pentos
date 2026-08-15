"""CLI-Tests für 'pentos timeline add/list/rm' (Engagement-Zeitplan)."""
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
    config.project_path("tl").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("tl"))
    Repository(config.db_path("tl")).close()
    config.set_active_project("tl")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app


def test_timeline_add_default_kind_is_milestone():
    app = _project()
    r = CliRunner().invoke(app, ["timeline", "add", "Kickoff"])
    assert r.exit_code == 0, r.output
    assert "Meilenstein" in r.output


def test_timeline_add_window_with_start_end_note():
    app = _project()
    r = CliRunner().invoke(app, [
        "timeline", "add", "Testfenster Woche 1", "--kind", "window",
        "--start", "2026-08-20 08:00", "--end", "2026-08-24 18:00",
        "--note", "Eskalation: +41 79 000 00 00",
    ])
    assert r.exit_code == 0, r.output
    assert "Zeitfenster" in r.output


def test_timeline_add_invalid_kind_fails_cleanly():
    app = _project()
    r = CliRunner().invoke(app, ["timeline", "add", "X", "--kind", "quatsch"])
    assert r.exit_code != 0
    assert "Ungültige" in r.output


def test_timeline_list_shows_entries_sorted():
    app = _project()
    runner = CliRunner()
    runner.invoke(app, ["timeline", "add", "Spaeter", "--start", "2026-08-25 00:00"])
    runner.invoke(app, ["timeline", "add", "Frueher", "--start", "2026-08-20 00:00"])
    r = runner.invoke(app, ["timeline", "list"])
    assert r.exit_code == 0, r.output
    assert r.output.index("Frueher") < r.output.index("Spaeter")


def test_timeline_list_empty_shows_hint():
    app = _project()
    r = CliRunner().invoke(app, ["timeline", "list"])
    assert r.exit_code == 0, r.output
    assert "Noch kein Zeitplan" in r.output


def test_timeline_rm():
    app = _project()
    runner = CliRunner()
    add = runner.invoke(app, ["timeline", "add", "X"])
    assert add.exit_code == 0, add.output
    eid = int(add.output.split("#")[1].split(":")[0])
    r = runner.invoke(app, ["timeline", "rm", str(eid)])
    assert r.exit_code == 0, r.output
    assert "entfernt" in r.output.lower()
    r2 = runner.invoke(app, ["timeline", "list"])
    assert "Noch kein Zeitplan" in r2.output


def test_timeline_rm_unknown_id():
    app = _project()
    r = CliRunner().invoke(app, ["timeline", "rm", "999"])
    assert "Nicht gefunden" in r.output
