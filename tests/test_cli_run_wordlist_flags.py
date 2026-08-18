"""Tests für 'pentos run --userlist/--passlist/--proto' (pentos/cli/app.py::run_cmd).

Deckt die zwei ursprünglichen Live-Test-Probleme ab:
- der alte, per --args hartkodierte relative Wordlist-Pfad ("wordlists/…")
  löste sich nie zuverlässig auf (PentOS' aktives Projekt ist DB-, nicht
  CWD-gebunden) -> jetzt Default aus dem Projektverzeichnis.
- ein blindes 'pentos run hydra <ziel>' ohne Listen lief nur in einen
  kryptischen rc=255 -- jetzt ein klarer Fehler vor dem eigentlichen Lauf.
"""
import os
import tempfile

from typer.testing import CliRunner


def _project():
    # Breite erzwingen: Rich umbricht/kuerzt Panel-Inhalte sonst bei der in
    # Tests (kein echtes Terminal) genutzten Default-Breite (~80 Spalten) --
    # die vollen Wordlist-Pfade in der Dry-Run-Vorschau wuerden sonst mit
    # "..." abgeschnitten.
    os.environ["COLUMNS"] = "300"
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
    config.project_path("rp").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("rp"))
    Repository(config.db_path("rp")).close()
    config.set_active_project("rp")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app, config.project_path("rp")


def test_hydra_without_wordlists_gives_friendly_error_not_bare_run(monkeypatch):
    """Kein --dry-run, keine Wordlists eingerichtet: klare Fehlermeldung statt
    eines Laufs, der nur mit rc=255 stirbt."""
    app, _proj_dir = _project()
    r = CliRunner().invoke(app, ["run", "hydra", "10.0.0.1", "--proto", "ssh"])
    assert r.exit_code == 1, r.output
    assert "Wordlist" in r.output
    assert "pentos wordlists setup" in r.output


def test_hydra_without_proto_gives_friendly_error():
    app, _proj_dir = _project()
    r = CliRunner().invoke(app, ["run", "hydra", "10.0.0.1", "--dry-run"])
    assert r.exit_code == 1, r.output
    assert "--proto" in r.output


def test_hydra_dry_run_shows_resolved_default_paths_even_if_missing():
    """--dry-run zeigt die Vorschau trotz fehlender Dateien -- reine Vorschau,
    kein echter Lauf (gleiche Logik wie beim bestehenden Scope-Check)."""
    app, proj_dir = _project()
    r = CliRunner().invoke(app, ["run", "hydra", "10.0.0.1", "--proto", "ssh", "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "-L" in r.output and "usernames.txt" in r.output
    assert "-P" in r.output and "passwords.txt" in r.output
    assert str(proj_dir) in r.output
    assert "ssh" in r.output


def test_hydra_dry_run_with_explicit_userlist_passlist_uses_given_paths():
    app, _proj_dir = _project()
    tmp = tempfile.mkdtemp()
    userlist = os.path.join(tmp, "own_users.txt")
    passlist = os.path.join(tmp, "own_pass.txt")
    open(userlist, "w").write("admin\n")
    open(passlist, "w").write("hunter2\n")
    r = CliRunner().invoke(app, [
        "run", "hydra", "10.0.0.1", "--proto", "ssh", "--dry-run",
        "--userlist", userlist, "--passlist", passlist,
    ])
    assert r.exit_code == 0, r.output
    assert userlist in r.output
    assert passlist in r.output


def test_nxc_smb_dry_run_needs_no_proto():
    """nxc-smb braucht kein --proto -- das Protokoll steckt im Tool-Namen."""
    app, proj_dir = _project()
    r = CliRunner().invoke(app, ["run", "nxc-smb", "10.0.0.1", "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "-u" in r.output and "-p" in r.output
    assert str(proj_dir) in r.output


def test_userlist_flag_rejected_for_unsupported_tool():
    """kerbrute nutzt bewusst den generischen --wordlist-Mechanismus, nicht
    --userlist/--passlist -- klare Fehlermeldung statt stillem Ignorieren."""
    app, _proj_dir = _project()
    r = CliRunner().invoke(app, ["run", "kerbrute", "10.0.0.1", "--userlist", "/x/u.txt"])
    assert r.exit_code == 1, r.output
    assert "kerbrute" in r.output
    assert "unterst" in r.output


def test_userlist_flag_conflicts_with_args():
    app, _proj_dir = _project()
    r = CliRunner().invoke(app, [
        "run", "hydra", "10.0.0.1", "--proto", "ssh",
        "--userlist", "/x/u.txt", "--args", "-l admin",
    ])
    assert r.exit_code == 1, r.output
    assert "--args" in r.output


def test_args_escape_hatch_still_works_unaffected(monkeypatch):
    """Alter --args-Weg bleibt unverändert funktionsfähig (Regressionsschutz),
    auch ohne eingerichtete Projekt-Wordlists."""
    app, _proj_dir = _project()
    r = CliRunner().invoke(app, [
        "run", "hydra", "10.0.0.1", "--dry-run",
        "--args", "-l admin -P /irgendwo/pass.txt ssh",
    ])
    assert r.exit_code == 0, r.output
    assert "-l admin" in r.output
