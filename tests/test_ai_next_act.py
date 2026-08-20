"""Tests für 'ai next --act': KI schlägt einen Befehl vor, der Mensch wählt
und bestätigt ihn explizit -- kein autonomer Lauf ohne Bestätigung pro Schritt.
"""
import os
import sys
import tempfile

from typer.testing import CliRunner


# ── _extract_ai_commands: reine Extraktionslogik ─────────────────────────────
def test_extract_ai_commands_finds_known_tool():
    from pentos.cli.ai_cmds import _extract_ai_commands
    answer = "Als nächstes würde ich `pentos run nikto http://10.10.10.5` ausführen, um den Webserver zu prüfen."
    cmds = _extract_ai_commands(answer)
    assert cmds == [("nikto", "http://10.10.10.5")]


def test_extract_ai_commands_ignores_unknown_tool_names():
    from pentos.cli.ai_cmds import _extract_ai_commands
    answer = "Versuch mal `pentos run totallymadeuptool 10.10.10.5`."
    assert _extract_ai_commands(answer) == []


def test_extract_ai_commands_dedups_and_caps_at_five():
    from pentos.cli.ai_cmds import _extract_ai_commands
    answer = "\n".join([f"pentos run nikto 10.10.10.{i}" for i in range(1, 8)] +
                       ["pentos run nikto 10.10.10.1"])  # Duplikat der ersten Zeile
    cmds = _extract_ai_commands(answer)
    assert len(cmds) == 5
    assert cmds[0] == ("nikto", "10.10.10.1")
    assert len(set(cmds)) == 5  # keine Duplikate


def test_extract_ai_commands_strips_trailing_punctuation():
    from pentos.cli.ai_cmds import _extract_ai_commands
    answer = "Vorschlag: pentos run nikto 10.10.10.5, danach weiter mit ffuf."
    cmds = _extract_ai_commands(answer)
    assert cmds[0] == ("nikto", "10.10.10.5")


def test_extract_ai_commands_empty_on_no_match():
    from pentos.cli.ai_cmds import _extract_ai_commands
    assert _extract_ai_commands("Ich würde erstmal die Ergebnisse genauer ansehen.") == []
    assert _extract_ai_commands("") == []
    assert _extract_ai_commands(None) == []


# ── CLI-Ebene: 'pentos ai next --act' ─────────────────────────────────────────
def _project():
    cfg = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(cfg, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'ai: {provider: ollama, base_url: "http://x", model: "m", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    from pentos.models import Host
    config.project_path("act").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("act"))
    repo = Repository(config.db_path("act"))
    repo.add_host(Host(address="10.10.10.5"))
    repo.close()
    config.set_active_project("act")
    import importlib as il
    from pentos.cli import app as app_mod
    from pentos.cli import ai_cmds as ai_cmds_mod
    il.reload(app_mod)
    return app_mod, ai_cmds_mod


def _stub_probe_tool(app_mod, monkeypatch, network=False):
    """Ersetzt runner_registry.get() so, dass 'probe' auf den echten Python-
    Interpreter zeigt (garantiert vorhanden, harmlos) statt auf ein echtes
    Pentest-Tool -- damit der Test einen echten Lauf ohne externe Abhängigkeit
    durchspielen kann."""
    from pentos.runners.base import ToolSpec
    real_get = app_mod.runner_registry.get
    spec = ToolSpec(name="probe", binary=sys.executable, category="recon",
                    argv=[sys.executable, "-c", "print(1)"], parser="capture", network=network)

    def fake_get(name):
        return spec if name == "probe" else real_get(name)

    monkeypatch.setattr(app_mod.runner_registry, "get", fake_get)


def test_ai_next_act_no_candidates_in_answer(monkeypatch):
    app_mod, ai_cmds_mod = _project()
    monkeypatch.setattr(ai_cmds_mod.AIClient, "available", lambda self: True)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "next_steps", lambda self, *a, **kw: "Schau dir die Ergebnisse genauer an.")
    r = CliRunner().invoke(app_mod.app, ["ai", "next", "--yes", "--act"])
    assert r.exit_code == 0, r.output
    assert "Keine ausführbare" in r.output


def test_ai_next_act_skip_when_no_selection(monkeypatch):
    app_mod, ai_cmds_mod = _project()
    _stub_probe_tool(app_mod, monkeypatch)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "available", lambda self: True)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "next_steps",
                        lambda self, *a, **kw: "Führe `pentos run probe 10.10.10.5` aus.")
    r = CliRunner().invoke(app_mod.app, ["ai", "next", "--yes", "--act"], input="\n")
    assert r.exit_code == 0, r.output
    assert "Vorgeschlagene Befehle" in r.output
    assert "Nichts ausgeführt" in r.output


def test_ai_next_act_runs_confirmed_selection(monkeypatch):
    app_mod, ai_cmds_mod = _project()
    _stub_probe_tool(app_mod, monkeypatch, network=False)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "available", lambda self: True)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "next_steps",
                        lambda self, *a, **kw: "Führe `pentos run probe 10.10.10.5` aus.")
    r = CliRunner().invoke(app_mod.app, ["ai", "next", "--yes", "--act"], input="1\ny\n")
    assert r.exit_code == 0, r.output
    assert "Von der KI vorgeschlagen, von dir bestätigt" in r.output


def test_ai_next_act_declines_final_confirmation(monkeypatch):
    """Auswahl getroffen, aber die finale 'wirklich ausführen?'-Rückfrage
    verneint -- es darf trotzdem nichts laufen."""
    app_mod, ai_cmds_mod = _project()
    _stub_probe_tool(app_mod, monkeypatch)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "available", lambda self: True)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "next_steps",
                        lambda self, *a, **kw: "Führe `pentos run probe 10.10.10.5` aus.")
    r = CliRunner().invoke(app_mod.app, ["ai", "next", "--yes", "--act"], input="1\nn\n")
    assert r.exit_code == 0, r.output
    assert "Abgebrochen" in r.output
    assert "Von der KI vorgeschlagen" not in r.output


def test_ai_next_without_act_flag_never_prompts_to_execute(monkeypatch):
    """Regressionsschutz fürs bestehende Verhalten: ohne --act bleibt es bei
    reiner Textausgabe, auch wenn die Antwort einen ausführbaren Befehl enthält."""
    app_mod, ai_cmds_mod = _project()
    _stub_probe_tool(app_mod, monkeypatch)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "available", lambda self: True)
    monkeypatch.setattr(ai_cmds_mod.AIClient, "next_steps",
                        lambda self, *a, **kw: "Führe `pentos run probe 10.10.10.5` aus.")
    r = CliRunner().invoke(app_mod.app, ["ai", "next", "--yes"])
    assert r.exit_code == 0, r.output
    assert "Vorgeschlagene Befehle" not in r.output
