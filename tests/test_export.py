"""Tests für den HTML-/PDF-Export (`report --html` / `--pdf`)."""
import os
import tempfile

import pytest


def _project_with_data():
    """Legt ein temporäres Projekt mit Host, Finding und Loot an, gibt (repo, name)."""
    cfg = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(cfg, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'report: {company: "Example Security", color: "#0f766e", author: "Tester"}\n'
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    from pentos.models import (Host, Service, Finding, Severity,
                               FindingCategory, FindingStatus, Loot, LootType)

    config.project_path("ex").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("ex"))
    repo = Repository(config.db_path("ex"))
    h = repo.add_host(Host(address="192.168.56.10", hostname="dc01",
                           os_guess="Windows Server 2019"))
    repo.add_service(Service(host_id=h.id, port=445, protocol="tcp",
                             name="microsoft-ds", product="SMB"))
    repo.add_finding(Finding(title="Administrativer Zugriff (Pwn3d) via nxc-smb: x",
                             severity=Severity.HIGH, category=FindingCategory.CREDENTIAL,
                             status=FindingStatus.CONFIRMED, description="Admin-Zugriff.",
                             host_id=h.id, auto=True))
    repo.add_loot(Loot(type=LootType.CREDENTIAL, label="admin", value="secret",
                       source="nxc-smb"))
    return repo, "ex", config


def test_html_contains_branding_and_findings():
    repo, name, config = _project_with_data()
    from pentos import export
    html = export.build_html(repo, name, cfg=config.load_config())
    assert "Example Security" in html          # Branding
    assert "#0f766e" in html              # Markenfarbe
    assert "Pwn3d" in html                # Finding
    assert "dc01" in html         # Host
    assert "<!DOCTYPE html>" in html      # valides HTML-Gerüst


def test_pdf_builds_without_error():
    reportlab = pytest.importorskip("reportlab")  # überspringen, wenn nicht installiert
    repo, name, config = _project_with_data()
    from pentos import export
    out = os.path.join(tempfile.mkdtemp(), "report.pdf")
    export.build_pdf(repo, name, out, cfg=config.load_config())
    assert os.path.exists(out)
    with open(out, "rb") as fh:
        head = fh.read(5)
    assert head == b"%PDF-"               # gültige PDF-Signatur


def test_pdf_missing_reportlab_raises_clean_error(monkeypatch):
    """Ohne reportlab muss eine klare RuntimeError-Meldung kommen, kein ImportError."""
    repo, name, config = _project_with_data()
    from pentos import export
    import builtins
    real_import = builtins.__import__

    def fake_import(name_, *a, **k):
        if name_.startswith("reportlab"):
            raise ImportError("simuliert: reportlab fehlt")
        return real_import(name_, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    out = os.path.join(tempfile.mkdtemp(), "x.pdf")
    with pytest.raises(RuntimeError, match="reportlab"):
        export.build_pdf(repo, name, out, cfg=config.load_config())
