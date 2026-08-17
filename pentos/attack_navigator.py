"""
MITRE-ATT&CK-Mapping für PentOS.

Reine Free-Text-Zuordnung: ein optionales Technique-Tag (z.B. "T1110") pro
Finding, ohne eigene ATT&CK-Datenbank im Projekt -- die Zuordnung bleibt
manuell/kuratiert wie bei allen anderen Wissens-Inhalten (siehe knowledge.py).

Export als offizielles ATT&CK-Navigator-Layer-JSON. Schema verifiziert gegen
layers/spec/v4.5/layerformat.md im mitre-attack/attack-navigator-Repo:
{name, domain, versions{navigator, layer}, techniques[{techniqueID, score,
comment, enabled}]}. Tactic/Farbe/offizieller Name werden bewusst NICHT von
PentOS gesetzt -- die kennt die echte Navigator-Anwendung selbst aus der
aktuellen ATT&CK-Matrix beim Import; PentOS müsste diese Zuordnung sonst
eigenständig pflegen (Drift-Risiko bei jeder ATT&CK-Revision).

"""
from __future__ import annotations

import re

from .models import Finding

# Enterprise-ATT&CK-Technique-ID: "T" + 4 Ziffern, optional Sub-Technique
# ".NNN" (z.B. T1110 oder T1110.001). Reine Formatprüfung, keine Prüfung
# gegen die tatsächliche Matrix (die pflegt PentOS bewusst nicht selbst).
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

NAVIGATOR_VERSIONS = {"navigator": "4.9.0", "layer": "4.5"}


def is_valid_technique_id(value: str) -> bool:
    return bool(TECHNIQUE_ID_RE.match((value or "").strip().upper()))


def build_navigator_layer(project: str, findings: list[Finding]) -> dict:
    """Baut ein ATT&CK-Navigator-Layer-JSON aus den getaggten Findings.

    Ein Eintrag pro eindeutiger Technique-ID (sortiert). score = Anzahl
    Findings mit dieser Technique, comment = Kurzliste der Finding-Titel.
    Findings ohne Tag werden ignoriert. Leere Findings-Liste -> Layer mit
    leerem techniques-Array (gültiges, aber leeres Layer-JSON).
    """
    by_technique: dict[str, list[Finding]] = {}
    for f in findings:
        tid = (f.attack_technique or "").strip().upper()
        if not tid:
            continue
        by_technique.setdefault(tid, []).append(f)

    techniques = []
    for tid, fs in sorted(by_technique.items()):
        titles = [f.title for f in fs]
        comment = "; ".join(titles[:5])
        if len(titles) > 5:
            comment += f" … (+{len(titles) - 5} weitere)"
        techniques.append({
            "techniqueID": tid,
            "score": len(fs),
            "comment": comment,
            "enabled": True,
        })

    total_tagged = sum(len(fs) for fs in by_technique.values())
    return {
        "name": f"PentOS – {project}",
        "domain": "enterprise-attack",
        "versions": dict(NAVIGATOR_VERSIONS),
        "description": (
            f"Automatisch aus PentOS-Findings exportiert "
            f"({len(techniques)} Technik(en), {total_tagged} getaggte Finding(s))."
        ),
        "techniques": techniques,
    }
