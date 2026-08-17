"""Tests für die Engagement-Policy (pentos/policy.py): Kategorie-Sperrlogik,
Zusammenfassung und Persistenz über das Repository.

Zwei Arten von Regeln: durchsetzbar (bruteforce/exploitation/cracking/
automated_scanning_allowed -- sperren Runner-Kategorien) und nur dokumentiert
(dos/social_engineering/production_only/Freitext -- landen nur im Report).
"""
import os
import tempfile

from pentos.models import EngagementPolicy
from pentos.policy import category_blocked, has_any_answer, summary_rows


# ── category_blocked ─────────────────────────────────────────────────────────
def test_no_policy_blocks_nothing():
    assert category_blocked(None, "bruteforce") is None
    assert category_blocked(None, "exploit") is None
    assert category_blocked(None, "web") is None


def test_unanswered_field_blocks_nothing():
    p = EngagementPolicy()  # alles None
    assert category_blocked(p, "bruteforce") is None
    assert category_blocked(p, "exploit") is None


def test_bruteforce_false_blocks_bruteforce_category_only():
    p = EngagementPolicy(bruteforce_allowed=False)
    assert category_blocked(p, "bruteforce") is not None
    assert category_blocked(p, "exploit") is None
    assert category_blocked(p, "web") is None


def test_bruteforce_true_does_not_block():
    p = EngagementPolicy(bruteforce_allowed=True)
    assert category_blocked(p, "bruteforce") is None


def test_exploitation_false_blocks_exploit_category():
    p = EngagementPolicy(exploitation_allowed=False)
    assert category_blocked(p, "exploit") is not None
    assert category_blocked(p, "bruteforce") is None


def test_cracking_false_blocks_cracking_category():
    p = EngagementPolicy(cracking_allowed=False)
    assert category_blocked(p, "cracking") is not None


def test_automated_scanning_false_blocks_everything():
    p = EngagementPolicy(automated_scanning_allowed=False)
    assert category_blocked(p, "web") is not None
    assert category_blocked(p, "recon") is not None
    assert category_blocked(p, "bruteforce") is not None
    assert category_blocked(p, "anything-not-a-real-category") is not None


def test_automated_scanning_true_does_not_override_specific_blocks():
    p = EngagementPolicy(automated_scanning_allowed=True, bruteforce_allowed=False)
    assert category_blocked(p, "bruteforce") is not None
    assert category_blocked(p, "web") is None


def test_documented_only_fields_never_block_anything():
    p = EngagementPolicy(dos_testing_allowed=False, social_engineering_allowed=False,
                         production_only=True)
    assert category_blocked(p, "bruteforce") is None
    assert category_blocked(p, "exploit") is None
    assert category_blocked(p, "web") is None


# ── summary_rows / has_any_answer ────────────────────────────────────────────
def test_has_any_answer_false_for_none():
    assert has_any_answer(None) is False


def test_has_any_answer_false_for_all_unset():
    assert has_any_answer(EngagementPolicy()) is False


def test_has_any_answer_true_when_one_bool_set():
    assert has_any_answer(EngagementPolicy(bruteforce_allowed=False)) is True


def test_has_any_answer_true_for_freetext_only():
    assert has_any_answer(EngagementPolicy(scope_note="nur *.example.com")) is True


def test_summary_rows_marks_enforced_vs_documented():
    p = EngagementPolicy(bruteforce_allowed=False, dos_testing_allowed=True)
    rows = {r["label"]: r for r in summary_rows(p)}
    assert rows["Brute-Force"]["enforced"] is True
    assert rows["Brute-Force"]["value"] == "nicht erlaubt"
    assert rows["DoS-/Rate-Limit-Tests"]["enforced"] is False
    assert rows["DoS-/Rate-Limit-Tests"]["value"] == "erlaubt"


def test_summary_rows_shows_not_set_for_unanswered():
    rows = {r["label"]: r for r in summary_rows(EngagementPolicy())}
    assert rows["Brute-Force"]["value"] == "nicht erfasst"
    assert rows["Brute-Force"]["set"] is False


def test_summary_rows_empty_for_none_policy():
    assert summary_rows(None) == []


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
    config.project_path("pol").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("pol"))
    return Repository(config.db_path("pol"))


def test_get_engagement_policy_none_when_never_set():
    repo = _repo()
    assert repo.get_engagement_policy() is None
    repo.close()


def test_set_and_get_engagement_policy_round_trips_bools_and_text():
    repo = _repo()
    repo.set_engagement_policy(EngagementPolicy(
        bruteforce_allowed=False, exploitation_allowed=True, automated_scanning_allowed=None,
        dos_testing_allowed=False, rate_limit_note="10 req/s", scope_note="nur *.example.com",
        program_url="https://hackerone.com/example",
    ))
    got = repo.get_engagement_policy()
    repo.close()
    assert got.bruteforce_allowed is False
    assert got.exploitation_allowed is True
    assert got.automated_scanning_allowed is None
    assert got.dos_testing_allowed is False
    assert got.rate_limit_note == "10 req/s"
    assert got.scope_note == "nur *.example.com"
    assert got.program_url == "https://hackerone.com/example"


def test_set_engagement_policy_twice_keeps_latest():
    repo = _repo()
    repo.set_engagement_policy(EngagementPolicy(bruteforce_allowed=False))
    repo.set_engagement_policy(EngagementPolicy(bruteforce_allowed=True))
    got = repo.get_engagement_policy()
    repo.close()
    assert got.bruteforce_allowed is True


def test_clear_engagement_policy_removes_it():
    repo = _repo()
    repo.set_engagement_policy(EngagementPolicy(bruteforce_allowed=False))
    ok = repo.clear_engagement_policy()
    got = repo.get_engagement_policy()
    repo.close()
    assert ok is True
    assert got is None


def test_clear_engagement_policy_false_when_nothing_set():
    repo = _repo()
    ok = repo.clear_engagement_policy()
    repo.close()
    assert ok is False
