"""CLI-Tests für 'pentos policy setup/show/clear' und die Durchsetzung in
'pentos run'/'pentos sweep --run'."""
import os
import tempfile

from typer.testing import CliRunner


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
    config.project_path("clipol").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("clipol"))
    Repository(config.db_path("clipol")).close()
    config.set_active_project("clipol")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod


# ── policy setup / show / clear ──────────────────────────────────────────────
def test_policy_show_empty_hints_at_setup():
    app_mod = _project()
    r = CliRunner().invoke(app_mod.app, ["policy", "show"])
    assert r.exit_code == 0, r.output
    assert "pentos policy setup" in r.output


def test_policy_setup_non_interactive_via_flags():
    app_mod = _project()
    r = CliRunner().invoke(app_mod.app, [
        "policy", "setup", "--no-interactive",
        "--no-bruteforce", "--exploitation", "--rate-limit", "10 req/s",
    ])
    assert r.exit_code == 0, r.output
    assert "gespeichert" in r.output.lower()

    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("clipol"))
    policy = repo.get_engagement_policy()
    repo.close()
    assert policy.bruteforce_allowed is False
    assert policy.exploitation_allowed is True
    assert policy.rate_limit_note == "10 req/s"
    assert policy.cracking_allowed is None  # nicht übergeben, nicht interaktiv -> unbeantwortet


def test_policy_show_after_setup_lists_rules():
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-bruteforce"])
    r = runner.invoke(app_mod.app, ["policy", "show"])
    assert r.exit_code == 0, r.output
    assert "Brute-Force" in r.output


def test_policy_clear_removes_rules():
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-bruteforce"])
    r = runner.invoke(app_mod.app, ["policy", "clear", "--yes"])
    assert r.exit_code == 0, r.output
    r2 = runner.invoke(app_mod.app, ["policy", "show"])
    assert "pentos policy setup" in r2.output


def test_policy_setup_interactive_prompts_for_unanswered_fields():
    app_mod = _project()
    # Reihenfolge der Prompts: bruteforce, exploitation, cracking, automated,
    # dos, social-engineering, production-only, rate-limit, scope-note, program-url
    answers = "n\nn\nn\nn\nn\nn\nn\n\n\n\n"
    r = CliRunner().invoke(app_mod.app, ["policy", "setup"], input=answers)
    assert r.exit_code == 0, r.output

    from pentos import config
    from pentos.repository import Repository
    repo = Repository(config.db_path("clipol"))
    policy = repo.get_engagement_policy()
    repo.close()
    assert policy.bruteforce_allowed is False
    assert policy.automated_scanning_allowed is False


# ── Durchsetzung in 'pentos run' ─────────────────────────────────────────────
def test_run_blocked_when_bruteforce_forbidden(monkeypatch):
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-bruteforce"])
    r = runner.invoke(app_mod.app, ["run", "hydra", "10.10.10.5", "--dry-run"])
    # dry-run wird wie beim Scope-Guard nicht blockiert (zeigt nur das Kommando)
    assert r.exit_code == 0, r.output


def test_run_blocked_for_real_without_dry_run(monkeypatch):
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-bruteforce"])
    r = runner.invoke(app_mod.app, ["run", "hydra", "10.10.10.5"])
    assert r.exit_code == 2
    assert "Brute-Force" in r.output
    assert "--force" in r.output


def test_run_force_overrides_policy_block():
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-bruteforce"])
    r = runner.invoke(app_mod.app, ["run", "hydra", "10.10.10.5", "--force", "--dry-run"])
    assert r.exit_code == 0, r.output


def test_run_not_blocked_for_unrelated_category():
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-bruteforce"])
    r = runner.invoke(app_mod.app, ["run", "whatweb", "10.10.10.5", "--dry-run"])
    assert r.exit_code == 0, r.output


def test_run_blocked_entirely_when_automated_scanning_forbidden():
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-automated"])
    r = runner.invoke(app_mod.app, ["run", "whatweb", "10.10.10.5"])
    assert r.exit_code == 2
    assert "automatisierte Tools" in r.output


# ── Durchsetzung in 'pentos sweep --run' ─────────────────────────────────────
def test_sweep_run_blocked_when_automated_scanning_forbidden():
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-automated"])
    r = runner.invoke(app_mod.app, ["sweep", "10.10.10.5", "--run"])
    assert r.exit_code == 2
    assert "automatisierte Tools" in r.output


def test_sweep_preview_not_blocked_by_automated_scanning_forbidden():
    """Ohne --run zeigt sweep nur Kommando-Vorschläge -- kein echter Lauf, also kein Block."""
    app_mod = _project()
    runner = CliRunner()
    runner.invoke(app_mod.app, ["policy", "setup", "--no-interactive", "--no-automated"])
    r = runner.invoke(app_mod.app, ["sweep", "10.10.10.5"])
    assert r.exit_code == 0, r.output
