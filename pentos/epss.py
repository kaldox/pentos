"""
EPSS-Anreicherung für PentOS.

Fragt für Findings mit erkennbarer CVE-Referenz den Exploit Prediction
Scoring System (EPSS) Score bei der kostenlosen FIRST.org-API ab
(https://api.first.org/data/v1/epss). CVSS sagt, wie schlimm eine Lücke
wäre -- EPSS sagt, wie wahrscheinlich sie in den nächsten 30 Tagen
tatsächlich ausgenutzt wird.

Wie bei Cloud-KI-Aufrufen: opt-in, mit expliziter Rückfrage vor dem Senden
(siehe cli/app.py::_confirm_epss_send) -- CVE-IDs verlassen den Rechner.
Reine Arithmetik/HTTP, keine KI beteiligt.

"""
from __future__ import annotations

import re

import requests

from .models import Finding

EPSS_API_URL = "https://api.first.org/data/v1/epss"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Die API begrenzt den 'cve'-Filter-Parameter auf 2000 Zeichen (siehe
# api.first.org/epss) -- 40 CVE-IDs pro Batch bleibt mit grosszügiger Marge
# darunter, auch bei den längsten gültigen CVE-IDs.
_BATCH_SIZE = 40


class EpssError(Exception):
    """Netzwerk-/API-Fehler beim Abfragen von EPSS-Scores."""


def extract_cves(f: Finding) -> list[str]:
    """Extrahiert CVE-IDs aus Titel + Beschreibung eines Findings.

    PentOS hat (noch) kein eigenes CVE-Feld -- CVEs stehen heute als Freitext
    in title/description (so legen es nikto-, testssl.sh- und der
    Nessus/OpenVAS/Burp-Scanner-Parser bereits an, z.B. "CVE: CVE-2014-0160").
    Reihenfolge bleibt erhalten, Duplikate werden entfernt, Grossschreibung
    normalisiert (CVE-IDs sind offiziell immer Grossbuchstaben).
    """
    text = f"{f.title or ''}\n{f.description or ''}"
    seen: list[str] = []
    for m in _CVE_RE.finditer(text):
        cve = m.group(0).upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def fetch_epss(cve_ids: list[str], timeout: int = 10) -> dict[str, dict]:
    """Fragt EPSS-Scores für eine Liste von CVE-IDs ab (in Batches).

    Gibt {cve: {"epss": float, "percentile": float}} zurück. CVEs ohne
    EPSS-Eintrag (z.B. sehr neue oder unbekannte CVEs) fehlen einfach im
    Ergebnis -- das ist kein Fehler. Wirft EpssError bei Netzwerk-/API-
    Problemen (Timeout, HTTP-Fehler, kaputtes JSON).
    """
    out: dict[str, dict] = {}
    uniq = list(dict.fromkeys(c.upper() for c in cve_ids if c))
    for i in range(0, len(uniq), _BATCH_SIZE):
        batch = uniq[i:i + _BATCH_SIZE]
        try:
            resp = requests.get(EPSS_API_URL, params={"cve": ",".join(batch)}, timeout=timeout)
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException as exc:
            raise EpssError(f"EPSS-API nicht erreichbar: {exc}") from exc
        except ValueError as exc:
            raise EpssError(f"EPSS-API lieferte kein gültiges JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise EpssError("EPSS-API lieferte eine unerwartete Antwortstruktur.")
        for item in payload.get("data", []) or []:
            if not isinstance(item, dict):
                continue
            cve = str(item.get("cve") or "").upper()
            if not cve:
                continue
            try:
                out[cve] = {"epss": float(item["epss"]), "percentile": float(item["percentile"])}
            except (KeyError, TypeError, ValueError):
                continue
    return out
