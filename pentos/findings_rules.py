"""
Automatische Finding-Erkennung für PentOS.

Detektoren prüfen einen Service (inkl. NSE-Script-Output im Feld `extra`) und
schlagen potenzielle Findings vor. Erkennung ist konservativ und erweiterbar –
weitere Detektoren kommen mit den Scanner-Parsern (spätere Phase).

"""
from __future__ import annotations

from typing import Callable, Optional

from .models import Finding, FindingCategory, FindingStatus, Service

# Ein Detektor liefert (Titel, Kategorie, Severity, Beschreibung) oder None.
DetectorResult = Optional[tuple[str, FindingCategory, "object", str]]


def _extra(svc: Service) -> str:
    return (svc.extra or "").lower()


def det_telnet(svc: Service) -> DetectorResult:
    if svc.port == 23 or "telnet" in (svc.name or "").lower():
        from .models import Severity
        return (
            "Telnet im Klartext exponiert",
            FindingCategory.EXPOSURE,
            Severity.MEDIUM,
            "Telnet überträgt Anmeldedaten unverschlüsselt. Verschlüsselte Alternative (SSH) prüfen.",
        )
    return None


def det_ftp_anon(svc: Service) -> DetectorResult:
    text = _extra(svc)
    if "anonymous ftp login allowed" in text or "anonymous login allowed" in text:
        from .models import Severity
        return (
            "Anonymer FTP-Zugriff erlaubt",
            FindingCategory.MISCONFIG,
            Severity.MEDIUM,
            "FTP erlaubt anonymen Login. Lese-/Schreibrechte und exponierte Daten prüfen.",
        )
    return None


def det_smb_signing(svc: Service) -> DetectorResult:
    text = _extra(svc)
    signing_off = (
        "message signing enabled but not required" in text
        or "signing: disabled" in text
        or ("signing" in text and "not required" in text)
    )
    if signing_off:
        from .models import Severity
        return (
            "SMB Signing Disabled",
            FindingCategory.MISCONFIG,
            Severity.MEDIUM,
            "SMB-Signing ist nicht erzwungen. Anfällig für Relay-Angriffe (z.B. NTLM-Relay).",
        )
    return None


def det_http_plain(svc: Service) -> DetectorResult:
    name = (svc.name or "").lower()
    if name == "http" and (svc.tunnel or "").lower() != "ssl" and svc.port not in (443, 8443):
        from .models import Severity
        return (
            "Unverschlüsseltes HTTP",
            FindingCategory.EXPOSURE,
            Severity.LOW,
            "Dienst über unverschlüsseltes HTTP erreichbar. Auf TLS-Pflicht / Redirect prüfen.",
        )
    return None


DETECTORS: list[Callable[[Service], DetectorResult]] = [
    det_telnet,
    det_ftp_anon,
    det_smb_signing,
    det_http_plain,
]


def detect_for_service(svc: Service) -> list[Finding]:
    """Wendet alle Detektoren auf einen Service an und baut Finding-Objekte."""
    out: list[Finding] = []
    for det in DETECTORS:
        res = det(svc)
        if res:
            title, category, severity, desc = res
            out.append(
                Finding(
                    title=title,
                    category=category,
                    severity=severity,
                    status=FindingStatus.UNVERIFIED,
                    description=desc,
                    host_id=svc.host_id,
                    service_id=svc.id,
                    auto=True,
                )
            )
    return out
