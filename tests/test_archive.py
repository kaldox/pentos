"""Tests für Projekt-Export/-Import (pentos/archive.py).

Export packt den kompletten Workspace als eine ZIP-Datei, Import entpackt sie
wieder als Projekt. Deckt ab: Roundtrip, Namenskonflikt ohne/mit --force,
fehlendes/ungültiges Archiv, Zip-Slip-Schutz.
"""
import os
import tempfile
import zipfile

import pytest


def _fresh_config():
    cfg = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(cfg, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    return config


def _project_with_data(config, name="Kenobi"):
    from pentos.workspace import create_workspace
    from pentos import db as db_mod
    from pentos.repository import Repository
    from pentos.models import Host, Note

    create_workspace(name)
    db_mod.init_db(config.db_path(name))
    repo = Repository(config.db_path(name))
    h = repo.add_host(Host(address="10.10.10.5", hostname="kenobi"))
    repo.add_note(Note(title="Plan", body="Rekon zuerst", host_id=h.id))
    repo.close()
    # zusätzliche Datei im Workspace, die mit exportiert werden muss
    (config.project_path(name) / "scans" / "nmap.xml").write_text("<xml/>", encoding="utf-8")
    return h.id


def test_export_creates_zip_with_manifest_and_files():
    config = _fresh_config()
    _project_with_data(config)
    from pentos import archive

    out = config.project_path("Kenobi") / "exports" / "backup.zip"
    path = archive.export_project("Kenobi", out)
    assert path.exists()
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        assert "pentos-export.json" in names
        assert "database/pentos.db" in names
        assert "scans/nmap.xml" in names
        # das Ziel-ZIP selbst darf nicht im Archiv landen, auch wenn es im
        # Projektordner (exports/) liegt
        assert not any(n.endswith("backup.zip") for n in names)


def test_export_unknown_project_raises():
    config = _fresh_config()
    from pentos import archive
    with pytest.raises(archive.ArchiveError):
        archive.export_project("Nope", config.projects_dir() / "x.zip")


def test_import_roundtrip_recreates_project():
    config = _fresh_config()
    hid = _project_with_data(config)
    from pentos import archive
    from pentos.repository import Repository

    out = config.projects_dir() / "backup.zip"
    archive.export_project("Kenobi", out)

    imported = archive.import_project(out, name="Kenobi-Restored")
    assert imported == "Kenobi-Restored"
    assert config.project_path("Kenobi-Restored").exists()
    assert (config.project_path("Kenobi-Restored") / "scans" / "nmap.xml").exists()

    repo = Repository(config.db_path("Kenobi-Restored"))
    hosts = repo.list_hosts()
    notes = repo.list_notes()
    repo.close()
    assert len(hosts) == 1 and hosts[0].address == "10.10.10.5"
    assert hosts[0].id == hid
    assert len(notes) == 1 and notes[0].title == "Plan"


def test_import_uses_manifest_name_when_no_explicit_name():
    import shutil
    config = _fresh_config()
    _project_with_data(config)
    from pentos import archive

    out = config.projects_dir() / "backup.zip"
    archive.export_project("Kenobi", out)
    shutil.rmtree(config.project_path("Kenobi"))  # Original weg, wie auf einem neuen Rechner

    imported = archive.import_project(out)  # kein --name -> Name aus dem Manifest
    assert imported == "Kenobi"
    assert config.project_path("Kenobi").exists()


def test_import_existing_project_without_force_fails():
    config = _fresh_config()
    _project_with_data(config)
    from pentos import archive

    out = config.projects_dir() / "backup.zip"
    archive.export_project("Kenobi", out)
    with pytest.raises(archive.ArchiveError):
        archive.import_project(out)  # "Kenobi" existiert schon


def test_import_existing_project_with_force_overwrites():
    config = _fresh_config()
    _project_with_data(config)
    from pentos import archive
    from pentos.repository import Repository
    from pentos.models import Note

    out = config.projects_dir() / "backup.zip"
    archive.export_project("Kenobi", out)

    # Projekt danach verändern, damit sichtbar ist, dass --force wirklich überschreibt
    repo = Repository(config.db_path("Kenobi"))
    repo.add_note(Note(title="Nachträglich", body="sollte weg sein"))
    repo.close()

    imported = archive.import_project(out, force=True)
    assert imported == "Kenobi"
    repo = Repository(config.db_path("Kenobi"))
    titles = [n.title for n in repo.list_notes()]
    repo.close()
    assert titles == ["Plan"]  # der Stand aus dem Backup, nicht die nachträgliche Notiz


def test_import_missing_file_raises():
    config = _fresh_config()
    from pentos import archive
    with pytest.raises(archive.ArchiveError):
        archive.import_project(config.projects_dir() / "does-not-exist.zip")


def test_import_invalid_zip_raises():
    config = _fresh_config()
    bogus = config.projects_dir() / "bogus.zip"
    bogus.write_text("not actually a zip", encoding="utf-8")
    from pentos import archive
    with pytest.raises(archive.ArchiveError):
        archive.import_project(bogus)


def test_import_zip_without_database_raises():
    config = _fresh_config()
    bogus = config.projects_dir() / "no-db.zip"
    with zipfile.ZipFile(bogus, "w") as zf:
        zf.writestr("scans/nmap.xml", "<xml/>")
    from pentos import archive
    with pytest.raises(archive.ArchiveError):
        archive.import_project(bogus)


def test_import_rejects_path_traversal():
    config = _fresh_config()
    evil = config.projects_dir() / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("database/pentos.db", "fake")
        zf.writestr("../../outside.txt", "sollte niemals landen")
    from pentos import archive
    with pytest.raises(archive.ArchiveError):
        archive.import_project(evil, name="EvilProject")
    # nichts wurde angelegt (Validierung passiert vor der Extraktion)
    assert not config.project_path("EvilProject").exists()


# ── CLI-Ebene (project export / project import) ─────────────────────────────
def _cli_app():
    import importlib
    from pentos.cli import app as app_mod
    importlib.reload(app_mod)
    return app_mod.app


def test_cli_export_active_project():
    from typer.testing import CliRunner
    config = _fresh_config()
    _project_with_data(config)
    config.set_active_project("Kenobi")
    app = _cli_app()
    out = config.projects_dir() / "cli-backup.zip"
    r = CliRunner().invoke(app, ["project", "export", "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert out.exists()
    assert "exportiert" in r.output.lower()


def test_cli_import_sets_active_project():
    from typer.testing import CliRunner
    config = _fresh_config()
    _project_with_data(config)
    from pentos import archive
    out = config.projects_dir() / "cli-backup.zip"
    archive.export_project("Kenobi", out)

    app = _cli_app()
    r = CliRunner().invoke(app, ["project", "import", str(out), "--name", "Kenobi2"])
    assert r.exit_code == 0, r.output
    assert config.get_active_project() == "Kenobi2"


def test_cli_import_no_activate():
    from typer.testing import CliRunner
    config = _fresh_config()
    _project_with_data(config)
    config.set_active_project("Kenobi")
    from pentos import archive
    out = config.projects_dir() / "cli-backup.zip"
    archive.export_project("Kenobi", out)

    app = _cli_app()
    r = CliRunner().invoke(
        app, ["project", "import", str(out), "--name", "Kenobi3", "--no-activate"])
    assert r.exit_code == 0, r.output
    assert config.get_active_project() == "Kenobi"  # unverändert


def test_cli_import_conflict_without_force_exits_nonzero():
    from typer.testing import CliRunner
    config = _fresh_config()
    _project_with_data(config)
    from pentos import archive
    out = config.projects_dir() / "cli-backup.zip"
    archive.export_project("Kenobi", out)

    app = _cli_app()
    r = CliRunner().invoke(app, ["project", "import", str(out)])  # "Kenobi" existiert schon
    assert r.exit_code != 0
