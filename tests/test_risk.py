"""Tests für den Risk-Score (pentos/risk.py)."""
from pentos.models import Finding, FindingCategory, FindingStatus, Severity
from pentos.risk import compute_risk


def _f(sev, status=FindingStatus.UNVERIFIED):
    return Finding(title="X", severity=sev, category=FindingCategory.OTHER, status=status)


def test_no_findings_is_minimal():
    r = compute_risk([])
    assert r["level"] == "Minimal"
    assert r["score"] == 0
    assert r["active_count"] == 0


def test_single_critical_is_kritisch():
    r = compute_risk([_f(Severity.CRITICAL)])
    assert r["level"] == "Kritisch"
    assert r["score"] == 10


def test_single_high_is_hoch():
    r = compute_risk([_f(Severity.HIGH)])
    assert r["level"] == "Hoch"
    assert r["score"] == 6


def test_many_mediums_reach_hoch_via_score_threshold():
    # 6 Medium = Score 18 >= 15 -> "Hoch", auch ohne High/Critical
    r = compute_risk([_f(Severity.MEDIUM) for _ in range(6)])
    assert r["score"] == 18
    assert r["level"] == "Hoch"


def test_single_medium_is_mittel():
    r = compute_risk([_f(Severity.MEDIUM)])
    assert r["score"] == 3
    assert r["level"] == "Mittel"


def test_single_low_is_niedrig():
    r = compute_risk([_f(Severity.LOW)])
    assert r["score"] == 1
    assert r["level"] == "Niedrig"


def test_only_info_is_minimal():
    r = compute_risk([_f(Severity.INFO), _f(Severity.INFO)])
    assert r["score"] == 0
    assert r["level"] == "Minimal"
    assert r["active_count"] == 2  # zählen mit, tragen nur nichts zum Score bei


def test_closed_and_false_positive_excluded_from_score():
    findings = [
        _f(Severity.CRITICAL, status=FindingStatus.CLOSED),
        _f(Severity.CRITICAL, status=FindingStatus.FALSE_POSITIVE),
        _f(Severity.LOW, status=FindingStatus.CONFIRMED),
    ]
    r = compute_risk(findings)
    assert r["score"] == 1               # nur das aktive Low zählt
    assert r["level"] == "Niedrig"
    assert r["active_count"] == 1
    assert r["total_count"] == 3         # total zählt weiterhin alle


def test_by_severity_counts_all_severities_even_zero():
    r = compute_risk([_f(Severity.HIGH)])
    assert set(r["by_severity"].keys()) == set(Severity)
    assert r["by_severity"][Severity.HIGH] == 1
    assert r["by_severity"][Severity.CRITICAL] == 0
