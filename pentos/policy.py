"""
Engagement-Policy für PentOS -- Programm-/Auftrags-Regeln pro Projekt.

Gedacht für Bug-Bounty-Programme (aber auch für klassische Pentests
brauchbar): viele Programme verbieten explizit bestimmte Techniken (kein
Brute-Force, keine aktive Exploitation, teils "nur manuelles Testen, keine
automatisierten Scanner"). `pentos policy setup` fragt das einmal pro
Projekt ab, `pentos run`/`sweep --run` setzen es durch.

Zwei Kategorien, bewusst getrennt:
- Durchsetzbar: bruteforce_allowed/exploitation_allowed/cracking_allowed
  sperren die jeweilige Runner-Kategorie (siehe runners/registry.py).
  automated_scanning_allowed=False sperrt ausnahmslos alles.
- Nur dokumentiert: dos_testing_allowed, social_engineering_allowed,
  production_only, rate_limit_note, scope_note, program_url. PentOS kann
  z.B. kein DoS-Verhalten technisch verhindern -- das hängt von Tool-
  Konfiguration/Rate ab, nicht vom gewählten Tool. Diese Felder landen
  stattdessen sichtbar im Report, als Beleg unter welchen Einschränkungen
  getestet wurde.

WICHTIG: Das ist ein Gedächtnisstütze/Selbstschutz, keine Compliance-Garantie.
Wer unbedingt will, kann Tools ausserhalb von PentOS oder im --shell-Modus
laufen lassen -- wie beim bestehenden Scope-Guard schützt das vor
Versehen, nicht vor Vorsatz. Override mit --force, wie beim Scope-Guard.
"""
from __future__ import annotations

from typing import Optional

from .models import EngagementPolicy

# Runner-Kategorie (siehe runners/registry.py) -> Policy-Feld, das sie steuert.
_CATEGORY_GATES: dict[str, str] = {
    "bruteforce": "bruteforce_allowed",
    "exploit": "exploitation_allowed",
    "cracking": "cracking_allowed",
}

_GATE_LABEL = {
    "bruteforce_allowed": "Brute-Force",
    "exploitation_allowed": "aktive Exploitation",
    "cracking_allowed": "Offline-Cracking",
}


def category_blocked(policy: Optional[EngagementPolicy], category: str) -> Optional[str]:
    """Prüft, ob eine Runner-Kategorie laut Policy gesperrt ist.

    Gibt einen menschenlesbaren Sperrgrund zurück, oder None wenn erlaubt
    (inkl. wenn keine Policy gesetzt ist -- Feature ist rein opt-in).
    """
    if policy is None:
        return None
    if policy.automated_scanning_allowed is False:
        return ("Programm-Regeln: automatisierte Tools sind für dieses Projekt "
                "nicht erlaubt (nur manuelles Testen).")
    field = _CATEGORY_GATES.get(category)
    if field is None:
        return None
    if getattr(policy, field) is False:
        return f"Programm-Regeln: {_GATE_LABEL[field]} ist für dieses Projekt nicht erlaubt."
    return None


# Reihenfolge = Anzeige-Reihenfolge in 'policy show' und im Report.
_SUMMARY_FIELDS: list[tuple[str, str, bool]] = [
    # (Feldname, Label, durchgesetzt?)
    ("automated_scanning_allowed", "Automatisierte Tools", True),
    ("bruteforce_allowed", "Brute-Force", True),
    ("exploitation_allowed", "Aktive Exploitation", True),
    ("cracking_allowed", "Offline-Cracking", True),
    ("dos_testing_allowed", "DoS-/Rate-Limit-Tests", False),
    ("social_engineering_allowed", "Social Engineering", False),
    ("production_only", "Nur Produktivsystem (kein Staging)", False),
]


def _bool_label(value: Optional[bool]) -> str:
    if value is None:
        return "nicht erfasst"
    return "erlaubt" if value else "nicht erlaubt"


def summary_rows(policy: Optional[EngagementPolicy]) -> list[dict]:
    """Liefert eine flache Liste für Anzeige/Report: [{label, value, enforced}]."""
    if policy is None:
        return []
    rows = []
    for field, label, enforced in _SUMMARY_FIELDS:
        value = getattr(policy, field)
        rows.append({
            "label": label, "value": _bool_label(value), "enforced": enforced,
            "set": value is not None,
        })
    return rows


def has_any_answer(policy: Optional[EngagementPolicy]) -> bool:
    """True, wenn irgendein Feld der Policy tatsächlich beantwortet/gesetzt ist."""
    if policy is None:
        return False
    for field, _label, _enf in _SUMMARY_FIELDS:
        if getattr(policy, field) is not None:
            return True
    return bool(policy.rate_limit_note or policy.scope_note or policy.program_url)
