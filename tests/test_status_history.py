"""Tests für die Finding-Status-Historie (Retest-Tracking, #1)."""
import os
import tempfile

import pytest


def _repo():
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
    config.project_path("h").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("h"))
    return Repository(config.db_path("h"))


def test_history_initial_entry_on_create():
    repo = _repo()
    from pentos.models import Finding, FindingStatus
    f = repo.add_finding(Finding(title="X", status=FindingStatus.UNVERIFIED))
    hist = repo.finding_history(f.id)
    repo.close()
    assert len(hist) == 1
    assert hist[0].old_status is None
    assert hist[0].new_status == FindingStatus.UNVERIFIED.value
    assert hist[0].note == "Erstellt"


def test_history_records_change_with_note():
    repo = _repo()
    from pentos.models import Finding, FindingStatus
    f = repo.add_finding(Finding(title="X"))
    repo.set_finding_status(f.id, FindingStatus.CONFIRMED.value, note="manuell verifiziert")
    repo.set_finding_status(f.id, FindingStatus.CLOSED.value, note="Retest ok, gefixt")
    hist = repo.finding_history(f.id)
    repo.close()
    assert len(hist) == 3                      # Erstellt + 2 Wechsel
    assert hist[1].old_status == FindingStatus.UNVERIFIED.value
    assert hist[1].new_status == FindingStatus.CONFIRMED.value
    assert hist[1].note == "manuell verifiziert"
    assert hist[2].new_status == FindingStatus.CLOSED.value
    assert hist[2].note == "Retest ok, gefixt"


def test_no_history_when_status_unchanged():
    repo = _repo()
    from pentos.models import Finding, FindingStatus
    f = repo.add_finding(Finding(title="X", status=FindingStatus.UNVERIFIED))
    # gleicher Status -> kein neuer Eintrag
    repo.set_finding_status(f.id, FindingStatus.UNVERIFIED.value)
    hist = repo.finding_history(f.id)
    repo.close()
    assert len(hist) == 1


def test_set_status_unknown_finding_returns_false():
    repo = _repo()
    from pentos.models import FindingStatus
    assert repo.set_finding_status(999, FindingStatus.CONFIRMED.value) is False
    repo.close()


def test_history_deleted_with_finding():
    repo = _repo()
    from pentos.models import Finding, FindingStatus
    f = repo.add_finding(Finding(title="X"))
    repo.set_finding_status(f.id, FindingStatus.CONFIRMED.value)
    repo.delete_finding(f.id)
    hist = repo.finding_history(f.id)
    repo.close()
    assert hist == []
