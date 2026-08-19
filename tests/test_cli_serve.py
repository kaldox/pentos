"""Tests für 'pentos serve' (pentos/cli/app.py::serve_cmd).

Deckt den Host-Warnhinweis/die Rückfrage bei Nicht-Loopback-Bind ab (siehe
Security-Fix: Web-Dashboard exponiert sonst Loot/Credentials unauthentifiziert
im Netz). uvicorn.run() selbst wird nie erreicht -- web.server.serve wird
gemockt, da es blockierend ist.
"""
import os
import tempfile

import pytest
from typer.testing import CliRunner

pytest.importorskip("fastapi")


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
    config.project_path("sp").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("sp"))
    Repository(config.db_path("sp")).close()
    config.set_active_project("sp")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app


def test_serve_loopback_default_no_prompt(monkeypatch):
    import pentos.web.server as web_server
    calls = []
    monkeypatch.setattr(web_server, "serve", lambda **kw: calls.append(kw))
    app = _project()
    r = CliRunner().invoke(app, ["serve"])
    assert r.exit_code == 0, r.output
    assert "Wirklich auf" not in r.output
    assert len(calls) == 1
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["token"]  # ein Token wurde erzeugt


def test_serve_nonloopback_declined_does_not_start(monkeypatch):
    """Ablehnen der Rueckfrage ist wie ueberall im Codebase kein Fehler
    (exit 0, 'Abgebrochen.') -- entscheidend ist, dass serve() NICHT laeuft."""
    import pentos.web.server as web_server
    calls = []
    monkeypatch.setattr(web_server, "serve", lambda **kw: calls.append(kw))
    app = _project()
    r = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0"], input="n\n")
    assert r.exit_code == 0, r.output
    assert "Abgebrochen" in r.output
    assert calls == []


def test_serve_nonloopback_with_yes_skips_prompt(monkeypatch):
    import pentos.web.server as web_server
    calls = []
    monkeypatch.setattr(web_server, "serve", lambda **kw: calls.append(kw))
    app = _project()
    r = CliRunner().invoke(app, ["serve", "--host", "0.0.0.0", "--yes"])
    assert r.exit_code == 0, r.output
    assert len(calls) == 1
    assert calls[0]["host"] == "0.0.0.0"


def test_serve_prints_token_in_url(monkeypatch):
    import pentos.web.server as web_server
    monkeypatch.setattr(web_server, "serve", lambda **kw: None)
    app = _project()
    r = CliRunner().invoke(app, ["serve"])
    assert r.exit_code == 0, r.output
    assert "?token=" in r.output
