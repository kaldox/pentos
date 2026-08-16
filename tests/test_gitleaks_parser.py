"""Regressionstest für den gitleaks-Parser (JSON-Report, Findings + Loot).

Vorbild ist der nxc-Parser (Credential-Funde werden Loot). Anders als nikto
liefert gitleaks keine Severity -- jeder echte Fund ist ein Secret, daher
einheitlich HIGH/CREDENTIAL. Volle Secret-Werte landen als Loot, im
Finding-Text (der auch in Reports gedruckt wird) nur eine maskierte Vorschau.

Fixture tests/fixtures/gitleaks_report.json folgt dem Schema aus dem
offiziellen report.Finding-Struct (gitleaks/gitleaks, report/finding.go):
ein flaches Array von {RuleID, Description, Secret, File, Commit, Author,
Email, Date, Tags, Fingerprint, ...}. Enthält bewusst ein Duplikat (gleicher
Fingerprint) zum Testen des Innerhalb-eines-Laufs-Dedups.
"""
import os
import pathlib
import tempfile

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


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
    config.project_path("gl").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("gl"))
    return Repository(config.db_path("gl"))


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class _FakeSpec:
    name = "gitleaks"
    category = "secrets"


def test_parse_gitleaks_json_extracts_all_items():
    from pentos.runners.parsers import _parse_gitleaks_json
    hits = _parse_gitleaks_json(_load("gitleaks_report.json"))
    assert len(hits) == 5  # inkl. des absichtlichen Duplikats
    assert hits[0]["rule_id"] == "aws-access-token"
    assert hits[0]["secret"] == "AKIAABCDEFGHIJKLMNOP"


def test_parse_gitleaks_json_handles_garbage():
    from pentos.runners.parsers import _parse_gitleaks_json
    assert _parse_gitleaks_json("not json at all") == []
    assert _parse_gitleaks_json("") == []
    assert _parse_gitleaks_json("{}") == []
    assert _parse_gitleaks_json("null") == []


def test_mask_secret_short_and_long():
    from pentos.runners.parsers import _mask_secret
    assert _mask_secret("abc") == "***"
    masked = _mask_secret("AKIAABCDEFGHIJKLMNOP")
    assert masked.startswith("AKIA")
    assert masked.endswith("MNOP")
    assert "ABCDEFGHIJKL" not in masked  # Mittelteil maskiert
    assert "*" in masked


def test_gitleaks_creates_findings_and_loot_deduped_by_fingerprint():
    from pentos.runners.parsers import _parse_gitleaks
    repo = _repo()
    find_n, loot_n = _parse_gitleaks(repo, _FakeSpec(), "/tmp/dump", _load("gitleaks_report.json"), None)
    # 5 Rohtreffer, 1 Duplikat (gleicher Fingerprint) -> 4 eindeutige
    assert find_n == 4
    assert loot_n == 4
    assert len(repo.list_findings()) == 4
    assert len(repo.list_loot()) == 4


def test_gitleaks_finding_shows_masked_secret_not_full_value():
    from pentos.runners.parsers import _parse_gitleaks
    repo = _repo()
    _parse_gitleaks(repo, _FakeSpec(), "/tmp/dump", _load("gitleaks_report.json"), None)
    aws_finding = next(f for f in repo.list_findings() if "aws-access-token" in f.title)
    assert "AKIAABCDEFGHIJKLMNOP" not in aws_finding.description  # voller Wert nicht im Finding
    assert "AKIA" in aws_finding.description  # maskierte Vorschau schon


def test_gitleaks_loot_has_full_secret_value():
    from pentos.runners.parsers import _parse_gitleaks
    from pentos.models import Severity, FindingCategory
    repo = _repo()
    _parse_gitleaks(repo, _FakeSpec(), "/tmp/dump", _load("gitleaks_report.json"), None)
    aws_finding = next(f for f in repo.list_findings() if "aws-access-token" in f.title)
    assert aws_finding.severity == Severity.HIGH
    assert aws_finding.category == FindingCategory.CREDENTIAL
    aws_loot = next(l for l in repo.list_loot() if "aws-access-token" in l.label)
    assert aws_loot.value == "AKIAABCDEFGHIJKLMNOP"  # voller Wert nur hier


def test_gitleaks_loot_type_heuristic_from_rule_id():
    from pentos.runners.parsers import _parse_gitleaks
    from pentos.models import LootType
    repo = _repo()
    _parse_gitleaks(repo, _FakeSpec(), "/tmp/dump", _load("gitleaks_report.json"), None)
    by_rule = {}
    for l in repo.list_loot():
        for key in ("aws-access-token", "generic-api-key", "generic-password", "private-key"):
            if key in l.label:
                by_rule[key] = l.type
    assert by_rule["generic-api-key"] == LootType.API_KEY
    assert by_rule["generic-password"] == LootType.CREDENTIAL
    assert by_rule["private-key"] == LootType.SSH_KEY
    assert by_rule["aws-access-token"] == LootType.TOKEN  # RuleID enthaelt "token"


def test_gitleaks_loot_type_falls_back_to_other():
    from pentos.runners.parsers import _gitleaks_loot_type
    from pentos.models import LootType
    assert _gitleaks_loot_type("stripe-secret-key") == LootType.API_KEY  # "secret-key" matcht
    assert _gitleaks_loot_type("generic-high-entropy-string") == LootType.OTHER  # nichts passt


def test_gitleaks_no_duplicate_findings_on_second_run():
    from pentos.runners.parsers import _parse_gitleaks
    repo = _repo()
    text = _load("gitleaks_report.json")
    n1, _ = _parse_gitleaks(repo, _FakeSpec(), "/tmp/dump", text, None)
    n2, loot2 = _parse_gitleaks(repo, _FakeSpec(), "/tmp/dump", text, None)
    assert n1 == 4
    assert n2 == 0  # Findings dedupliziert
    assert loot2 == 4  # Loot akkumuliert bewusst weiter (wie beim nxc-Parser)
