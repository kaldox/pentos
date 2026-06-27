"""Tests für die interaktiven Schreib-Endpoints des Web-Dashboards.

Übersprungen, wenn die Web-Extras (fastapi/httpx) fehlen.
"""
import os
import tempfile

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402


def _client():
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
    from pentos.models import (Host, Finding, Severity, FindingCategory, FindingStatus)
    config.project_path("Box").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("Box"))
    r = Repository(config.db_path("Box"))
    h = r.add_host(Host(address="10.10.10.5", status="up"))
    r.add_finding(Finding(title="RCE", severity=Severity.CRITICAL,
                          category=FindingCategory.VULN,
                          status=FindingStatus.UNVERIFIED, host_id=h.id))
    from pentos.web.server import create_app
    return TestClient(create_app("Box", _bind_host="127.0.0.1", _bind_port=8787))


def test_set_status_persists():
    c = _client()
    r = c.post("/api/project/Box/finding/1/status", json={"status": "Bestätigt"})
    assert r.status_code == 200 and r.json()["ok"] is True
    f = c.get("/api/project/Box/findings").json()["findings"][0]
    assert f["status"] == "Bestätigt"


def test_set_status_invalid_value():
    c = _client()
    assert c.post("/api/project/Box/finding/1/status", json={"status": "Quatsch"}).status_code == 422


def test_set_status_unknown_finding():
    c = _client()
    assert c.post("/api/project/Box/finding/999/status", json={"status": "Bestätigt"}).status_code == 404


def test_add_note_via_api():
    c = _client()
    r = c.post("/api/project/Box/notes", json={"title": "Plan", "body": "x", "category": "web"})
    assert r.status_code == 200
    notes = c.get("/api/project/Box/notes").json()["notes"]
    assert any(n["title"] == "Plan" for n in notes)


def test_add_note_requires_title():
    c = _client()
    assert c.post("/api/project/Box/notes", json={"body": "ohne titel"}).status_code == 422


def test_meta_returns_statuses():
    c = _client()
    st = c.get("/api/meta").json()["statuses"]
    assert "Bestätigt" in st and "Geschlossen" in st


def test_write_blocked_from_foreign_origin():
    c = _client()
    # fremde Website darf nicht schreiben
    r = c.post("/api/project/Box/finding/1/status", json={"status": "Geschlossen"},
               headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    # eigenes Dashboard darf
    r = c.post("/api/project/Box/finding/1/status", json={"status": "Geschlossen"},
               headers={"origin": "http://127.0.0.1:8787"})
    assert r.status_code == 200
