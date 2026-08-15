"""CLI-Tests für 'pentos scan import-bloodhound' (SharpHound-Import)."""
import os
import pathlib
import tempfile

from typer.testing import CliRunner

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "sharphound"


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
    h = repo.add_host(Host(address="10.10.10.5", hostname="dc01"))
    repo.close()
    config.set_active_project("k")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app, h.id


def _findings():
    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("k"))
    findings = repo.list_findings()
    repo.close()
    return findings


def test_cli_import_persists_summary_for_graph():
    """Regression: der Import muss die Zusammenfassung persistieren, damit
    der Angriffspfad-Graph AD-Objekte (Domain Admins, Kerberoastable, ...)
    anzeigen kann, ohne den Export erneut einzulesen."""
    import json
    from pentos import config
    from pentos.repository import Repository
    app, _hid = _project_with_host()
    r = CliRunner().invoke(app, ["scan", "import-bloodhound", str(FIXTURES)])
    assert r.exit_code == 0, r.output
    repo = Repository(config.db_path("k"))
    bh = repo.latest_bloodhound_import()
    repo.close()
    assert bh is not None
    assert bh.domain == "CORP.LOCAL"
    summary = json.loads(bh.summary_json)
    assert summary["kerberoastable"] == ["SVC-SQL@CORP.LOCAL"]


def test_cli_import_creates_expected_findings():
    app, _hid = _project_with_host()
    r = CliRunner().invoke(app, ["scan", "import-bloodhound", str(FIXTURES)])
    assert r.exit_code == 0, r.output
    titles = {f.title for f in _findings()}
    assert any("Kerberoastable" in t for t in titles)
    assert any("AS-REP" in t for t in titles)
    assert any("Uneingeschränkte Delegation" in t for t in titles)
    assert any("Domain-Admin-Mitgliedschaft" in t for t in titles)
    assert "BloodHound-Import" in r.output


def test_cli_import_links_findings_to_host_by_id():
    app, hid = _project_with_host()
    r = CliRunner().invoke(app, ["scan", "import-bloodhound", str(FIXTURES), "--host", str(hid)])
    assert r.exit_code == 0, r.output
    findings = _findings()
    assert findings and all(f.host_id == hid for f in findings)


def test_cli_import_links_findings_to_host_by_address():
    app, hid = _project_with_host()
    r = CliRunner().invoke(app, ["scan", "import-bloodhound", str(FIXTURES), "--host", "10.10.10.5"])
    assert r.exit_code == 0, r.output
    findings = _findings()
    assert findings and all(f.host_id == hid for f in findings)


def test_cli_import_unknown_host_warns_but_still_imports():
    app, _hid = _project_with_host()
    r = CliRunner().invoke(app, ["scan", "import-bloodhound", str(FIXTURES), "--host", "999"])
    assert r.exit_code == 0, r.output
    assert "nicht im Projekt" in r.output
    findings = _findings()
    assert findings and all(f.host_id is None for f in findings)


def test_cli_import_no_duplicate_findings_on_second_run():
    app, _hid = _project_with_host()
    r1 = CliRunner().invoke(app, ["scan", "import-bloodhound", str(FIXTURES)])
    assert r1.exit_code == 0, r1.output
    n1 = len(_findings())
    r2 = CliRunner().invoke(app, ["scan", "import-bloodhound", str(FIXTURES)])
    assert r2.exit_code == 0, r2.output
    n2 = len(_findings())
    assert n1 == n2  # zweiter Import legt nichts doppelt an


def test_cli_import_bad_path_exits_nonzero():
    app, _hid = _project_with_host()
    with tempfile.TemporaryDirectory() as tmp:
        r = CliRunner().invoke(app, ["scan", "import-bloodhound", tmp])
        assert r.exit_code != 0
