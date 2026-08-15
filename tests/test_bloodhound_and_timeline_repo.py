"""Tests für die neuen Repository-Tabellen: BloodHound-Import-Persistenz
(fürs den AD-Angriffspfad im Graph) und Engagement-Timeline.
"""
import json
import os
import tempfile


def _fresh_repo():
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
    config.project_path("bt").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("bt"))
    return Repository(config.db_path("bt"))


# ── BloodHound-Import-Persistenz ─────────────────────────────────────────────
def test_bloodhound_import_roundtrip():
    from pentos.models import BloodHoundImport
    repo = _fresh_repo()
    summary = {"domain": "CORP.LOCAL", "domain_admins": ["ADMIN.BOB@CORP.LOCAL"]}
    bh = repo.add_bloodhound_import(BloodHoundImport(domain="CORP.LOCAL",
                                                      summary_json=json.dumps(summary)))
    repo.close()
    assert bh.id is not None


def test_latest_bloodhound_import_returns_most_recent():
    from pentos.models import BloodHoundImport
    repo = _fresh_repo()
    repo.add_bloodhound_import(BloodHoundImport(domain="OLD.LOCAL", summary_json='{"domain": "OLD.LOCAL"}'))
    repo.add_bloodhound_import(BloodHoundImport(domain="NEW.LOCAL", summary_json='{"domain": "NEW.LOCAL"}'))
    latest = repo.latest_bloodhound_import()
    repo.close()
    assert latest.domain == "NEW.LOCAL"


def test_latest_bloodhound_import_none_when_empty():
    repo = _fresh_repo()
    latest = repo.latest_bloodhound_import()
    repo.close()
    assert latest is None


# ── Timeline ──────────────────────────────────────────────────────────────────
def test_timeline_add_and_list():
    from pentos.models import TimelineEntry, TimelineKind
    repo = _fresh_repo()
    repo.add_timeline_entry(TimelineEntry(kind=TimelineKind.WINDOW, title="Testfenster",
                                          start_ts="2026-08-20 08:00", end_ts="2026-08-20 18:00"))
    repo.add_timeline_entry(TimelineEntry(kind=TimelineKind.BLACKOUT, title="Wartungsfenster",
                                          start_ts="2026-08-21 00:00", note="keine Scans"))
    entries = repo.list_timeline_entries()
    repo.close()
    assert len(entries) == 2
    assert entries[0].title == "Testfenster"  # nach start_ts sortiert
    assert entries[1].kind == TimelineKind.BLACKOUT


def test_timeline_default_kind_is_milestone():
    from pentos.models import TimelineEntry, TimelineKind
    repo = _fresh_repo()
    t = repo.add_timeline_entry(TimelineEntry(title="Kickoff"))
    repo.close()
    assert t.kind == TimelineKind.MILESTONE


def test_timeline_delete():
    from pentos.models import TimelineEntry
    repo = _fresh_repo()
    t = repo.add_timeline_entry(TimelineEntry(title="X"))
    assert repo.delete_timeline_entry(t.id) is True
    assert repo.list_timeline_entries() == []
    assert repo.delete_timeline_entry(999) is False
    repo.close()
