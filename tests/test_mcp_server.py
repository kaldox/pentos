"""Tests für den MCP-Server (Logik-Schicht + Tool-Registrierung).

Die reine Logik wird ohne MCP-SDK getestet; die Server-/Tool-Registrierung nur,
wenn das MCP-SDK installiert ist (sonst übersprungen).
"""
import json
import os
import tempfile

import pytest


def _project_with_data():
    tmp = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(tmp, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {tmp}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    from pentos.models import (Host, Service, Finding, Severity, FindingCategory,
                               FindingStatus, Loot, LootType, Note)
    config.project_path("Box").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("Box"))
    r = Repository(config.db_path("Box"))
    h = r.add_host(Host(address="10.10.10.5", hostname="kenobi", os_guess="Linux", status="up"))
    r.add_service(Service(host_id=h.id, port=22, protocol="tcp", name="ssh"))
    r.add_finding(Finding(title="RCE upload", severity=Severity.CRITICAL,
                          category=FindingCategory.VULN, status=FindingStatus.CONFIRMED,
                          host_id=h.id, cvss_score=9.8))
    r.add_finding(Finding(title="Verbose header", severity=Severity.LOW,
                          category=FindingCategory.VULN, status=FindingStatus.UNVERIFIED,
                          host_id=h.id))
    r.add_loot(Loot(type=LootType.CREDENTIAL, label="ftp", value="a:b", host_id=h.id))
    r.add_note(Note(title="Foothold", body="upload php5 then SUID", category="plan"))
    return "Box"


def test_logic_list_projects():
    name = _project_with_data()
    from pentos import mcp_server as m
    out = m.logic_list_projects()
    assert name in out


def test_logic_summary():
    _project_with_data()
    from pentos import mcp_server as m
    data = json.loads(m.logic_summary("Box"))
    assert data["hosts"] == 1
    assert data["findings"] == 2
    assert data["severity"]["Critical"] == 1


def test_logic_findings_filtered():
    _project_with_data()
    from pentos import mcp_server as m
    data = json.loads(m.logic_findings("Box", severity="critical"))
    assert data["count"] == 1
    assert data["findings"][0]["severity"] == "Critical"
    assert data["findings"][0]["cvss"] == 9.8


def test_logic_findings_sorted_critical_first():
    _project_with_data()
    from pentos import mcp_server as m
    data = json.loads(m.logic_findings("Box"))
    assert data["findings"][0]["severity"] == "Critical"


def test_logic_notes_query():
    _project_with_data()
    from pentos import mcp_server as m
    data = json.loads(m.logic_notes("Box", query="SUID"))
    assert len(data["notes"]) == 1
    assert "SUID" in data["notes"][0]["body"]


def test_logic_unknown_project_raises():
    _project_with_data()
    from pentos import mcp_server as m
    with pytest.raises(ValueError, match="nicht gefunden"):
        m.logic_summary("Nope")


def test_logic_knowledge_handles_both_structures():
    _project_with_data()
    from pentos import mcp_server as m
    # darf nicht crashen (TOOL_KNOWLEDGE=dict, FINDING_KNOWLEDGE=list)
    out = m.logic_knowledge("smb")
    assert isinstance(out, str)


def test_mcp_server_registers_readonly_tools():
    pytest.importorskip("mcp")
    import asyncio
    _project_with_data()
    from pentos.mcp_server import build_server
    srv = build_server()
    tools = asyncio.run(srv.list_tools())
    names = {t.name for t in tools}
    # erwartete lesende Tools vorhanden
    assert "pentos_findings" in names
    assert "pentos_summary" in names
    # KEINE ausführenden Tools (kein run/scan/exploit) – Guardrail
    assert not any(x in n for n in names for x in ("run", "scan", "exploit", "exec"))
