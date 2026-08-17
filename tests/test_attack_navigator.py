"""Tests für das MITRE-ATT&CK-Mapping (pentos/attack_navigator.py): ID-Format-
Prüfung, Navigator-Layer-Aufbau und Persistenz über das Repository.

Kein eigenes ATT&CK-Datenmodell in PentOS -- die Zuordnung (Technique-ID pro
Finding) bleibt manuell/kuratiert. Layer-Schema verifiziert gegen
layers/spec/v4.5/layerformat.md im mitre-attack/attack-navigator-Repo.
"""
import os
import tempfile

import pytest


# ── is_valid_technique_id ────────────────────────────────────────────────────
def test_valid_technique_ids():
    from pentos.attack_navigator import is_valid_technique_id
    assert is_valid_technique_id("T1110")
    assert is_valid_technique_id("t1110")          # Kleinschreibung ok
    assert is_valid_technique_id("T1110.001")       # Sub-Technique
    assert is_valid_technique_id("  T1110  ")       # umgebende Whitespace ok


def test_invalid_technique_ids():
    from pentos.attack_navigator import is_valid_technique_id
    assert not is_valid_technique_id("1110")
    assert not is_valid_technique_id("T111")        # zu kurz
    assert not is_valid_technique_id("T11100")      # zu lang
    assert not is_valid_technique_id("T1110.1")     # Sub-Technique zu kurz
    assert not is_valid_technique_id("Brute Force")
    assert not is_valid_technique_id("")
    assert not is_valid_technique_id(None)


# ── build_navigator_layer ────────────────────────────────────────────────────
def _finding(title, technique=None):
    from pentos.models import Finding
    return Finding(title=title, attack_technique=technique)


def test_build_navigator_layer_required_top_level_fields():
    from pentos.attack_navigator import build_navigator_layer
    layer = build_navigator_layer("demo", [])
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"] == {"navigator": "4.9.0", "layer": "4.5"}
    assert "demo" in layer["name"]
    assert layer["techniques"] == []


def test_build_navigator_layer_ignores_untagged_findings():
    from pentos.attack_navigator import build_navigator_layer
    findings = [_finding("A"), _finding("B", technique=None)]
    layer = build_navigator_layer("demo", findings)
    assert layer["techniques"] == []


def test_build_navigator_layer_groups_by_technique_with_score():
    from pentos.attack_navigator import build_navigator_layer
    findings = [
        _finding("Weak SSH password", "T1110"),
        _finding("SMB login brute force", "t1110"),   # Kleinschreibung -> gruppiert mit T1110
        _finding("Kerberoasting", "T1558.003"),
    ]
    layer = build_navigator_layer("demo", findings)
    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by_id["T1110"]["score"] == 2
    assert by_id["T1558.003"]["score"] == 1
    assert "Weak SSH password" in by_id["T1110"]["comment"]
    assert "SMB login brute force" in by_id["T1110"]["comment"]
    assert by_id["T1110"]["enabled"] is True


def test_build_navigator_layer_truncates_long_comment_list():
    from pentos.attack_navigator import build_navigator_layer
    findings = [_finding(f"Finding {i}", "T1110") for i in range(8)]
    layer = build_navigator_layer("demo", findings)
    t1110 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1110")
    assert t1110["score"] == 8
    assert "weitere" in t1110["comment"]


def test_build_navigator_layer_techniques_sorted():
    from pentos.attack_navigator import build_navigator_layer
    findings = [_finding("A", "T1595"), _finding("B", "T1110"), _finding("C", "T1078")]
    layer = build_navigator_layer("demo", findings)
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert ids == sorted(ids)


# ── Repository-Persistenz ────────────────────────────────────────────────────
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
    config.project_path("atk").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("atk"))
    return Repository(config.db_path("atk"))


def test_set_finding_attack_persists_and_round_trips():
    from pentos.models import Finding
    repo = _repo()
    f = repo.add_finding(Finding(title="Brute Force möglich"))
    assert f.attack_technique is None
    ok = repo.set_finding_attack(f.id, "T1110", "Brute Force")
    assert ok
    got = repo.get_finding(f.id)
    listed = {x.id: x for x in repo.list_findings()}[f.id]
    repo.close()
    assert got.attack_technique == "T1110"
    assert got.attack_technique_name == "Brute Force"
    assert listed.attack_technique == "T1110"


def test_set_finding_attack_clear_with_none():
    from pentos.models import Finding
    repo = _repo()
    f = repo.add_finding(Finding(title="X"))
    repo.set_finding_attack(f.id, "T1110", "Brute Force")
    repo.set_finding_attack(f.id, None, None)
    got = repo.get_finding(f.id)
    repo.close()
    assert got.attack_technique is None
    assert got.attack_technique_name is None


def test_set_finding_attack_returns_false_for_unknown_id():
    repo = _repo()
    ok = repo.set_finding_attack(999999, "T1110")
    repo.close()
    assert ok is False
