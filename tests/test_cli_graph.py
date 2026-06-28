"""Regression: `graph mermaid`/`graph dot` auf stdout dürfen nicht am
Rich-Markup scheitern, wenn Loot-/Knoten-Labels Klammern enthalten
(z.B. Mermaid-Form `[/"…"/]`)."""
import os
import tempfile

from typer.testing import CliRunner


def _setup_project_with_loot():
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
    from pentos.models import Host, Loot, LootType
    config.project_path("g").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("g"))
    repo = Repository(config.db_path("g"))
    h = repo.add_host(Host(address="10.0.0.1"))
    repo.add_loot(Loot(type=LootType.CREDENTIAL, label="web-admin", host_id=h.id))
    repo.close()
    config.set_active_project("g")
    return config


def test_graph_mermaid_stdout_with_loot():
    _setup_project_with_loot()
    import importlib
    from pentos.cli import app as app_mod
    importlib.reload(app_mod)
    result = CliRunner().invoke(app_mod.app, ["graph", "mermaid"])
    assert result.exit_code == 0, result.output
    assert "graph TD" in result.output
    assert "web-admin" in result.output


def test_graph_dot_stdout_with_loot():
    _setup_project_with_loot()
    import importlib
    from pentos.cli import app as app_mod
    importlib.reload(app_mod)
    result = CliRunner().invoke(app_mod.app, ["graph", "dot"])
    assert result.exit_code == 0, result.output
    assert "digraph" in result.output
