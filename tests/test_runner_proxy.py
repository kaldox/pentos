"""Tests für die Proxychains-Unterstützung im Runner (pentos/runners/base.py).

Opt-in --proxy-Flag: stellt eine Proxy-Chain (z.B. "proxychains4 -q") vor den
eigentlichen Tool-Aufruf, für den SOCKS-Pivot-Fall nach einem Foothold ins
interne Netz. Tests nutzen wo möglich dry_run=True, um die Argv-Konstruktion
zu prüfen, ohne echte Prozesse/Binaries zu benötigen.
"""
import sys
import tempfile
from pathlib import Path

import pytest

from pentos.runners.base import RunnerError, ToolSpec, run_tool


def _spec(**overrides) -> ToolSpec:
    defaults = dict(
        name="probe", binary="probe-bin", category="recon",
        argv=["probe-bin", "-x", "{target}"], parser="capture",
    )
    defaults.update(overrides)
    return ToolSpec(**defaults)


def _scans_dir() -> Path:
    return Path(tempfile.mkdtemp()) / "scans"


def test_dry_run_without_proxy_has_plain_argv():
    result = run_tool(_spec(), "10.10.10.5", _scans_dir(), dry_run=True)
    assert result.command == ["probe-bin", "-x", "10.10.10.5"]


def test_dry_run_with_proxy_prepends_tokens():
    result = run_tool(_spec(), "10.10.10.5", _scans_dir(), dry_run=True, proxy="proxychains4 -q")
    assert result.command == ["proxychains4", "-q", "probe-bin", "-x", "10.10.10.5"]


def test_dry_run_with_single_token_proxy():
    result = run_tool(_spec(), "10.10.10.5", _scans_dir(), dry_run=True, proxy="proxychains")
    assert result.command == ["proxychains", "probe-bin", "-x", "10.10.10.5"]


def test_dry_run_shell_mode_with_proxy_prepends_as_string():
    result = run_tool(_spec(), "10.10.10.5", _scans_dir(), dry_run=True, shell=True,
                      proxy="proxychains4 -q", raw_args="-c 'whoami'")
    assert result.command == ["proxychains4 -q probe-bin -c 'whoami'"]


def test_whitespace_only_proxy_raises_runner_error():
    with pytest.raises(RunnerError, match="leer"):
        run_tool(_spec(), "10.10.10.5", _scans_dir(), dry_run=True, proxy="   ")


def test_missing_proxy_binary_raises_runner_error_before_exec():
    """Nutzt den echten Python-Interpreter als spec.binary (garantiert vorhanden
    in der Testumgebung), damit der Test bis zum Proxy-Binary-Check kommt --
    ohne dass echt etwas läuft (der Proxy-Name existiert nicht, Fehler fliegt
    davor)."""
    spec = _spec(binary=sys.executable, argv=[sys.executable, "-c", "print(1)"])
    with pytest.raises(RunnerError, match="Proxy-Binary"):
        run_tool(spec, "10.10.10.5", _scans_dir(), dry_run=False,
                proxy="definitely-not-a-real-proxychains-binary-xyz")


def test_no_proxy_does_not_touch_command():
    """--proxy nicht gesetzt -> Verhalten unverändert (Regressionsschutz)."""
    result = run_tool(_spec(), "example.local", _scans_dir(), dry_run=True, proxy=None)
    assert result.command == ["probe-bin", "-x", "example.local"]


# ── CLI-Ebene: 'pentos run <tool> <target> --proxy ... --dry-run' ───────────
def _project():
    import os
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
    config.project_path("rp").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("rp"))
    Repository(config.db_path("rp")).close()
    config.set_active_project("rp")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod.app


def test_cli_run_dry_run_shows_proxy_prefixed_command():
    from typer.testing import CliRunner
    app = _project()
    r = CliRunner().invoke(app, ["run", "nikto", "10.10.10.5", "--proxy", "proxychains4 -q", "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "proxychains4 -q nikto" in r.output or "proxychains4 -q" in r.output

