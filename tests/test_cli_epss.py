"""CLI-Tests für 'pentos finding epss' (EPSS-Anreicherung, opt-in wie KI-Cloud-Aufrufe).

epss_mod lebt seit der cli/app.py-Aufteilung in cli/findings.py (wo der
finding-Befehlsbaum jetzt zuhause ist), nicht mehr in cli/app.py selbst.
"""
import os
import tempfile

from typer.testing import CliRunner

from pentos.cli import findings as findings_mod


def _project(with_cve=True):
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
    config.project_path("e").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("e"))
    repo = Repository(config.db_path("e"))
    if with_cve:
        repo.add_finding(Finding(title="Heartbleed", description="Verwundbar für CVE-2014-0160."))
        repo.add_finding(Finding(title="Keine CVE hier", description="Schwaches Cipher, kein CVE."))
    else:
        repo.add_finding(Finding(title="Keine CVE hier", description="Schwaches Cipher, kein CVE."))
    repo.close()
    config.set_active_project("e")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod


def test_finding_epss_no_cve_findings_shows_hint_and_does_not_prompt():
    app_mod = _project(with_cve=False)
    r = CliRunner().invoke(app_mod.app, ["finding", "epss"])
    assert r.exit_code == 0, r.output
    assert "Keine Findings mit erkennbarer CVE-Referenz" in r.output


def test_finding_epss_yes_flag_skips_confirmation_and_updates_findings(monkeypatch):
    app_mod = _project(with_cve=True)

    def fake_fetch(cve_ids, timeout=10):
        assert cve_ids == ["CVE-2014-0160"]
        return {"CVE-2014-0160": {"epss": 0.94123, "percentile": 0.99001}}

    monkeypatch.setattr(findings_mod.epss_mod, "fetch_epss", fake_fetch)
    r = CliRunner().invoke(app_mod.app, ["finding", "epss", "--yes"])
    assert r.exit_code == 0, r.output
    assert "CVE-2014-0160" in r.output
    assert "0.941" in r.output
    assert "1 Finding(s) aktualisiert" in r.output

    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("e"))
    findings = {f.title: f for f in repo.list_findings()}
    repo.close()
    assert findings["Heartbleed"].epss_score == 0.94123
    assert findings["Keine CVE hier"].epss_score is None


def test_finding_epss_without_yes_asks_and_aborts_on_no(monkeypatch):
    app_mod = _project(with_cve=True)
    called = {"n": 0}

    def fake_fetch(cve_ids, timeout=10):
        called["n"] += 1
        return {}

    monkeypatch.setattr(findings_mod.epss_mod, "fetch_epss", fake_fetch)
    r = CliRunner().invoke(app_mod.app, ["finding", "epss"], input="n\n")
    assert r.exit_code == 0, r.output
    assert "Achtung" in r.output
    assert "Abgebrochen" in r.output
    assert called["n"] == 0  # bei Ablehnung wird die API gar nicht erst angefragt

    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("e"))
    heartbleed = next(f for f in repo.list_findings() if f.title == "Heartbleed")
    repo.close()
    assert heartbleed.epss_score is None


def test_finding_epss_without_yes_proceeds_on_yes_confirmation(monkeypatch):
    app_mod = _project(with_cve=True)

    def fake_fetch(cve_ids, timeout=10):
        return {"CVE-2014-0160": {"epss": 0.5, "percentile": 0.6}}

    monkeypatch.setattr(findings_mod.epss_mod, "fetch_epss", fake_fetch)
    r = CliRunner().invoke(app_mod.app, ["finding", "epss"], input="y\n")
    assert r.exit_code == 0, r.output
    assert "1 Finding(s) aktualisiert" in r.output


def test_finding_epss_handles_api_error_gracefully(monkeypatch):
    app_mod = _project(with_cve=True)

    def fake_fetch(cve_ids, timeout=10):
        raise findings_mod.epss_mod.EpssError("EPSS-API nicht erreichbar: timeout")

    monkeypatch.setattr(findings_mod.epss_mod, "fetch_epss", fake_fetch)
    r = CliRunner().invoke(app_mod.app, ["finding", "epss", "--yes"])
    assert r.exit_code == 1
    assert "EPSS-API nicht erreichbar" in r.output


def test_finding_epss_missing_cve_score_shown_as_dash(monkeypatch):
    app_mod = _project(with_cve=True)

    def fake_fetch(cve_ids, timeout=10):
        return {}  # CVE unbekannt bei EPSS -> kein Eintrag

    monkeypatch.setattr(findings_mod.epss_mod, "fetch_epss", fake_fetch)
    r = CliRunner().invoke(app_mod.app, ["finding", "epss", "--yes"])
    assert r.exit_code == 0, r.output
    assert "0 Finding(s) aktualisiert" in r.output
