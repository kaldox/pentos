"""Tests für die Wissensbasis und den Lern-Report (`report --explain`)."""
import os
import tempfile

from pentos import knowledge


def test_knowledge_covers_core_tools():
    # Die wichtigsten Tools müssen eine Erklärung haben
    for tool in ("nmap", "enum4linux-ng", "nxc-smb", "ffuf", "hydra", "nuclei"):
        info = knowledge.tool_info(tool)
        assert info is not None, f"Keine Wissensbasis für {tool}"
        assert info["what"] and info["why"] and info["read"]


def test_finding_explanations_match():
    # Finding-Muster werden anhand des Titels erkannt
    pwn = knowledge.finding_info("Administrativer Zugriff (Pwn3d) via nxc-smb: x")
    assert pwn is not None and "kontrolle" in pwn["why"].lower()
    dom = knowledge.finding_info("Domänen-Enumeration möglich (10.0.0.1)")
    assert dom is not None and "krbtgt" in dom["why"].lower()
    null = knowledge.finding_info("SMB Null-Session erlaubt (10.0.0.1)")
    assert null is not None


def test_unknown_finding_returns_none():
    assert knowledge.finding_info("Irgendein unbekanntes Finding") is None


def test_learning_report_builds():
    # Voller Aufbau gegen eine echte temporäre DB
    cfg = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(cfg, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        "ai: {provider: none, base_url: \"\", model: \"\", embed_model: x, api_key_env: X, timeout: 5}\n"
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos.repository import Repository
    from pentos import report, db as db_mod
    from pentos.models import RunRecord, Finding, Severity, FindingCategory, FindingStatus

    config.project_path("lr_test").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("lr_test"))
    repo = Repository(config.db_path("lr_test"))
    repo.add_run(RunRecord(tool="nmap", target="10.0.0.1",
                           command="nmap -sV 10.0.0.1", returncode=0, duration_ms=100))
    repo.add_finding(Finding(title="Administrativer Zugriff (Pwn3d) via nxc-smb: x",
                             severity=Severity.HIGH, category=FindingCategory.CREDENTIAL,
                             status=FindingStatus.CONFIRMED, description="x", auto=True))
    md = report.build_learning_markdown(repo, "lr_test")
    # Didaktische Bausteine müssen vorhanden sein
    assert "Was macht das?" in md
    assert "Warum hier?" in md
    assert "Wie wird es ausgenutzt?" in md
    assert "Was du hier gelernt hast" in md
    # nmap-Erklärung muss im Schritt auftauchen
    assert "Portscanner" in md
