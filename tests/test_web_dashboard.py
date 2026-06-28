"""Tests für das Web-Dashboard-Backend (FastAPI-API).

Übersprungen, wenn die Web-Extras (fastapi/httpx) nicht installiert sind.
"""
import os
import tempfile

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402


def _client_with_data():
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
    r.add_service(Service(host_id=h.id, port=80, protocol="tcp", name="http"))
    r.add_finding(Finding(title="RCE", severity=Severity.CRITICAL,
                          category=FindingCategory.VULN, status=FindingStatus.UNVERIFIED,
                          host_id=h.id, cvss_score=9.8))
    r.add_finding(Finding(title="Info leak", severity=Severity.LOW,
                          category=FindingCategory.VULN, status=FindingStatus.UNVERIFIED,
                          host_id=h.id))
    r.add_loot(Loot(type=LootType.CREDENTIAL, label="ftp", value="a:b", host_id=h.id))
    r.add_note(Note(title="Plan", body="do things", category="plan"))
    from pentos.web.server import create_app
    return TestClient(create_app("Box"))


def test_projects_endpoint():
    c = _client_with_data()
    data = c.get("/api/projects").json()
    assert "Box" in data["projects"]


def test_summary_counts_and_severity():
    c = _client_with_data()
    s = c.get("/api/project/Box/summary").json()
    assert s["counts"]["hosts"] == 1
    assert s["counts"]["services"] == 2
    assert s["counts"]["findings"] == 2
    assert s["severity"]["Critical"] == 1
    assert s["severity"]["Low"] == 1


def test_findings_sorted_by_severity():
    c = _client_with_data()
    f = c.get("/api/project/Box/findings").json()["findings"]
    # Critical muss vor Low kommen
    assert f[0]["severity"] == "Critical"
    assert f[0]["cvss_score"] == 9.8


def test_hosts_include_ports():
    c = _client_with_data()
    h = c.get("/api/project/Box/hosts").json()["hosts"]
    assert h[0]["address"] == "10.10.10.5"
    assert [s["port"] for s in h[0]["services"]] == [22, 80]


def test_loot_and_notes():
    c = _client_with_data()
    assert c.get("/api/project/Box/loot").json()["loot"][0]["type"] == "Credential"
    assert c.get("/api/project/Box/notes").json()["notes"][0]["title"] == "Plan"


def test_unknown_project_404():
    c = _client_with_data()
    assert c.get("/api/project/Nope/summary").status_code == 404


def test_frontend_served():
    c = _client_with_data()
    assert c.get("/").status_code == 200
    assert "text/html" in c.get("/").headers["content-type"]
    assert c.get("/static/app.js").status_code == 200


# ── #3: Finding-Detail, Graph, Status-Notiz ──────────────────────────────
def test_finding_detail_with_history():
    c = _client_with_data()
    # Finding 1 (RCE) Status setzen, dann Detail prüfen
    c.post("/api/project/Box/finding/1/status",
           json={"status": "Bestätigt", "note": "verifiziert"},
           headers={"origin": "http://127.0.0.1:8787"})
    d = c.get("/api/project/Box/finding/1").json()
    assert d["title"] == "RCE"
    assert d["location"] == "10.10.10.5"
    # Ersteintrag + Wechsel
    assert len(d["history"]) == 2
    assert d["history"][-1]["new"] == "Bestätigt"
    assert d["history"][-1]["note"] == "verifiziert"


def test_finding_detail_404():
    c = _client_with_data()
    assert c.get("/api/project/Box/finding/999").status_code == 404


def test_graph_endpoint_structure():
    c = _client_with_data()
    g = c.get("/api/project/Box/graph").json()
    assert len(g["hosts"]) == 1
    assert len(g["services"]) == 2
    assert len(g["findings"]) == 2
    assert g["hosts"][0]["address"] == "10.10.10.5"
    # Findings nach Severity sortiert (Critical zuerst)
    assert g["findings"][0]["severity"] == "Critical"


def test_status_post_records_note():
    c = _client_with_data()
    c.post("/api/project/Box/finding/2/status",
           json={"status": "Geschlossen", "note": "Retest ok"},
           headers={"origin": "http://127.0.0.1:8787"})
    d = c.get("/api/project/Box/finding/2").json()
    assert d["status"] == "Geschlossen"
    assert any(h["note"] == "Retest ok" for h in d["history"])


# ── 2.27.0: KI-Endpoints ─────────────────────────────────────────────────
def test_ai_config_get_defaults():
    c = _client_with_data()
    cfg = c.get("/api/ai/config").json()
    assert "language" in cfg and "auto_model" in cfg and "temperature" in cfg


def test_ai_config_post_updates():
    c = _client_with_data()
    r = c.post("/api/ai/config",
               json={"language": "en", "verbosity": "concise", "temperature": 0.7,
                     "auto_model": True, "persona": "OSCP mentor"},
               headers={"origin": "http://127.0.0.1:8787"})
    assert r.status_code == 200
    cfg = c.get("/api/ai/config").json()
    assert cfg["language"] == "en"
    assert cfg["verbosity"] == "concise"
    assert cfg["temperature"] == 0.7
    assert cfg["auto_model"] is True
    assert cfg["persona"] == "OSCP mentor"


def test_ai_config_temperature_validation():
    c = _client_with_data()
    r = c.post("/api/ai/config", json={"temperature": "abc"},
               headers={"origin": "http://127.0.0.1:8787"})
    assert r.status_code == 422


def test_ai_ask_requires_question():
    c = _client_with_data()
    r = c.post("/api/project/Box/ai/ask", json={"question": "  "},
               headers={"origin": "http://127.0.0.1:8787"})
    assert r.status_code == 422


def test_ai_ask_no_backend():
    # _client_with_data setzt provider=none -> Ask muss 400 liefern
    c = _client_with_data()
    r = c.post("/api/project/Box/ai/ask", json={"question": "Was läuft?"},
               headers={"origin": "http://127.0.0.1:8787"})
    assert r.status_code == 400
