"""Tests für die Datei-/Verzeichnis-Härtung (pentos.config.harden).

Projekt-DB und -Ordner enthalten Loot/Credentials im Klartext -- auf
Mehrbenutzer-Systemen mit permissivem umask sonst potenziell für andere
lokale Nutzer lesbar. harden() ist bewusst POSIX-only (Windows kennt keine
chmod-Owner/Group/Other-Semantik); auf Windows testen wir nur, dass nichts
kaputtgeht (No-op, kein Fehler), auf POSIX zusätzlich die tatsächlichen
Modus-Bits.
"""
import os
import stat
import tempfile
from pathlib import Path

import pytest

from pentos import config

_POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="chmod-Semantik nur unter POSIX relevant")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_harden_never_raises_for_missing_path():
    """Best effort: ein nicht existierender Pfad darf keinen Fehler werfen,
    weder unter POSIX noch unter Windows."""
    missing = Path(tempfile.mkdtemp()) / "does-not-exist" / "nested"
    config.harden(missing, 0o600)  # darf nicht raisen


@_POSIX_ONLY
def test_harden_sets_exact_mode_on_file():
    p = Path(tempfile.mkstemp()[1])
    p.chmod(0o644)
    config.harden(p, 0o600)
    assert _mode(p) == 0o600


@_POSIX_ONLY
def test_harden_sets_exact_mode_on_directory():
    d = Path(tempfile.mkdtemp())
    d.chmod(0o755)
    config.harden(d, 0o700)
    assert _mode(d) == 0o700


def test_harden_is_noop_on_non_posix(monkeypatch):
    """Auf 'nicht-POSIX' (simuliert) darf chmod() gar nicht erst aufgerufen
    werden -- keine falsche Sicherheit vortäuschen."""
    monkeypatch.setattr(config.os, "name", "nt")
    calls = []
    p = Path(tempfile.mkstemp()[1])
    monkeypatch.setattr(Path, "chmod", lambda self, mode: calls.append(mode))
    config.harden(p, 0o600)
    assert calls == []


@_POSIX_ONLY
def test_create_workspace_hardens_project_root(tmp_path):
    cfg = tmp_path / "config.yaml"
    os.environ["PENTOS_CONFIG"] = str(cfg)
    import importlib
    importlib.reload(config)
    from pentos.workspace import create_workspace
    root = create_workspace("hardened-proj")
    assert _mode(root) == 0o700


@_POSIX_ONLY
def test_db_connect_hardens_database_file(tmp_path):
    from pentos import db as db_mod
    db_file = tmp_path / "sub" / "pentos.db"
    conn = db_mod.connect(db_file)
    conn.close()
    assert _mode(db_file) == 0o600
