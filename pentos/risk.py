"""
Risk-Score für PentOS.

Ein transparenter, dokumentierter Score aus den eigenen Findings des
Projekts – keine externe KI-Bewertung, keine Cloud-Anfrage, reine Arithmetik
über die vorhandenen Severities. "Geschlossen" und "False Positive" zählen
bewusst nicht mit: der Score soll das aktuelle, offene Risiko zeigen, nicht
die Historie.

Von Markdown-/HTML-/PDF-Report und dem Web-Dashboard gemeinsam genutzt.
"""
from __future__ import annotations

from .models import Finding, FindingStatus, Severity

# Gewichtung je Severity -- bewusst einfach und nachvollziehbar (kein
# CVSS-Mix, kein Machine-Learning-Score), damit der Score erklärbar bleibt.
WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_INACTIVE = {FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE}

_LEVEL_COLOR = {
    "Kritisch": "#c0392b", "Hoch": "#e67e22", "Mittel": "#f1c40f",
    "Niedrig": "#3498db", "Minimal": "#27ae60",
}


def compute_risk(findings: list[Finding]) -> dict:
    """Berechnet Score, Risiko-Stufe und Severity-Verteilung über die aktiven
    (nicht geschlossenen/als False Positive markierten) Findings."""
    active = [f for f in findings if f.status not in _INACTIVE]
    by_severity = {s: 0 for s in Severity}
    for f in active:
        by_severity[f.severity] += 1
    score = sum(WEIGHTS.get(f.severity, 0) for f in active)

    if by_severity[Severity.CRITICAL] > 0:
        level = "Kritisch"
    elif by_severity[Severity.HIGH] > 0 or score >= 15:
        level = "Hoch"
    elif by_severity[Severity.MEDIUM] > 0 or score >= 5:
        level = "Mittel"
    elif score > 0:
        level = "Niedrig"
    else:
        level = "Minimal"

    return {
        "score": score,
        "level": level,
        "color": _LEVEL_COLOR[level],
        "active_count": len(active),
        "total_count": len(findings),
        "by_severity": by_severity,
    }
