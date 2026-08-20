"""
Regressionstest für Rich-Ausgaben auf nicht-UTF-8-Konsolen (Windows).

Hintergrund: `pentos project list` markierte das aktive Projekt mit "●"
(U+25CF). Läuft stdout unter Windows in einer nicht-UTF-8-Codepage - z.B.
cp1252 als Konsolen-Default, oder wenn `pentos`/`python -m pentos` als
Subprozess ohne PYTHONUTF8=1 / PYTHONIOENCODING=utf-8 aufgerufen wird -,
schreibt Rich roh in den Stream und ein striktes UnicodeEncodeError lässt
den Befehl abstürzen, statt die Tabelle auszugeben:

    UnicodeEncodeError: 'charmap' codec can't encode character '\\u25cf'

Die Tests hier bilden genau diese Situation nach (ein Rich-Console-Stream
mit encoding="cp1252", errors="strict") und rufen die betroffenen Befehle
direkt auf. Vor dem Fix schlägt bereits der erste Test mit dem obigen
UnicodeEncodeError fehl.
"""
from __future__ import annotations

import io
import os
import pathlib
import tempfile

from rich.console import Console


def _cp1252_console() -> tuple[Console, io.BytesIO]:
    """Rich-Console, deren Ausgabestream Zeichen ausserhalb von cp1252 (z.B.
    ●, →, ✓, ⚠, Emoji) mit einem strikten UnicodeEncodeError quittiert - so
    wie eine nicht-UTF-8-Windows-Konsole es auch tut."""
    buf = io.BytesIO()
    stream = io.TextIOWrapper(buf, encoding="cp1252", errors="strict", newline="")
    console = Console(file=stream, force_terminal=False, no_color=True, width=120)
    return console, buf


def _project(name: str, active: bool = True):
    """Legt ein frisches, isoliertes Projekt an (eigene PENTOS_CONFIG) und
    liefert (app-Modul, Repository) - Muster aus tests/test_cli_fixes.py."""
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
    config.project_path(name).mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path(name))
    if active:
        config.set_active_project(name)
    import importlib as il
    from pentos.cli import app as app_mod
    from pentos.cli import findings as findings_mod
    from pentos.cli import recon_extra as recon_extra_mod
    from pentos.cli import workspace as workspace_mod
    il.reload(app_mod)
    return app_mod, findings_mod, recon_extra_mod, workspace_mod, Repository(config.db_path(name))


def test_project_list_survives_non_utf8_console(monkeypatch):
    """Exakter Repro-Fall aus dem Bugreport: `pentos project list` darf auf
    einer cp1252-Konsole nicht crashen (war: '●'-Marker fürs aktive Projekt).

    project_list() lebt in cli/workspace.py -- das Modul importiert `console`
    per `from ._shared import console` und braucht deshalb seine eigene,
    lokale Umleitung (app_mod.console umzusetzen reicht nicht, das ist eine
    andere Namensbindung). monkeypatch statt Direktzuweisung, sonst bliebe
    die auf BytesIO umgeleitete Konsole für den Rest der Testsession stehen
    und alle späteren Tests, die workspace.py-Befehle aufrufen, würden
    stillschweigend ins Leere schreiben (leerer CliRunner-Output)."""
    app_mod, _findings_mod, _recon_extra_mod, workspace_mod, repo = _project("alpha")
    repo.close()
    from pentos import config
    config.project_path("beta").mkdir(parents=True, exist_ok=True)  # zweites, inaktives Projekt

    console, buf = _cp1252_console()
    monkeypatch.setattr(workspace_mod, "console", console)
    workspace_mod.project_list()  # löste vor dem Fix UnicodeEncodeError aus

    out = buf.getvalue().decode("cp1252")
    assert "alpha" in out and "beta" in out
    assert workspace_mod.SYM_BULLET in out
    assert workspace_mod.SYM_BULLET.isascii()


def test_dashboard_tools_and_findings_survive_non_utf8_console(monkeypatch):
    """Weitere Befehle, die vormals Unicode-only-Glyphen ausgaben: ●/⚠ im
    Dashboard-Prioritätspanel, ✓/✗ in der Tools-Tabelle, ✓ in der
    Findings-Tabelle, Fortschrittsbalken (█/░).

    dashboard_cmd/tools_cmd bleiben in app.py, finding_list lebt in
    cli/findings.py -- jedes der beiden Module braucht seine eigene
    Konsolen-Umleitung (monkeypatch, siehe Begründung oben)."""
    app_mod, findings_mod, _recon_extra_mod, _workspace_mod, repo = _project("gamma")
    from pentos.models import Finding, Severity, Host, Task
    repo.add_host(Host(address="10.0.0.5"))
    repo.add_finding(Finding(title="Kritischer Fund", severity=Severity.CRITICAL, auto=True))
    repo.add_task(Task(title="Nachschauen"))
    repo.close()

    console, buf = _cp1252_console()
    monkeypatch.setattr(app_mod, "console", console)
    monkeypatch.setattr(findings_mod, "console", console)
    app_mod.dashboard_cmd()
    app_mod.tools_cmd()
    findings_mod.finding_list()

    out = buf.getvalue().decode("cp1252")
    assert "Kritischer Fund" in out


def test_playbook_show_check_status_survive_non_utf8_console(monkeypatch):
    """playbook show/check/status: vormals ✓/»/○-Marker, (P)/(E)/(M)-Icons
    (früher Emoji) und Fortschrittsbalken. Leben in cli/recon_extra.py
    (monkeypatch, siehe Begründung oben)."""
    app_mod, _findings_mod, recon_extra_mod, _workspace_mod, repo = _project("delta")
    repo.close()

    console, buf = _cp1252_console()
    monkeypatch.setattr(recon_extra_mod, "console", console)
    recon_extra_mod.playbook_show("web", target=None)
    recon_extra_mod.playbook_check("web", "ports", note=None, skip=False)
    recon_extra_mod.playbook_status()

    out = buf.getvalue().decode("cp1252")
    assert "Web" in out


def test_no_non_ascii_status_glyphs_in_console_output_sources():
    """Statischer Wächter gegen Regressionen: In den console.print()/Table/
    Panel-Strings der CLI-Module und runners/base.py dürfen keine Zeichen
    ausserhalb von cp1252 auftauchen (Kommentare mit Box-Drawing-Trennern
    wie '# ── Foo ──' sind ausgenommen, die landen nie auf stdout).

    Die CLI war ursprünglich eine einzelne app.py -- seit der Aufteilung in
    cli/workspace.py, cli/findings.py, cli/recon_extra.py, cli/ai_cmds.py und
    cli/_shared.py deckt der Wächter alle fünf ab, nicht nur app.py."""
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for rel in ("pentos/cli/app.py", "pentos/cli/workspace.py", "pentos/cli/findings.py",
               "pentos/cli/recon_extra.py", "pentos/cli/ai_cmds.py", "pentos/cli/_shared.py",
               "pentos/runners/base.py"):
        path = repo_root / rel
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for ch in line:
                if ord(ch) > 127:
                    try:
                        ch.encode("cp1252")
                    except UnicodeEncodeError:
                        offenders.append(f"{rel}:{lineno}: {ch!r} in {line.strip()[:80]!r}")
    assert not offenders, "nicht cp1252-kodierbare Zeichen ausserhalb von Kommentaren:\n" + "\n".join(offenders)
