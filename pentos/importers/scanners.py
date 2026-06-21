"""
Scanner-Import für PentOS: Nessus, OpenVAS/Greenbone und Burp Suite.

Jedes Format wird in eine einheitliche Struktur normalisiert:
    list[ParsedTarget]  mit  host, services, findings

- Nessus  (.nessus): NessusClientData_v2 → ReportHost/ReportItem
- OpenVAS (GVM-XML):  report → results/result (+ nvt)
- Burp    (XML):      issues → issue (HTML-Felder werden entschärft)

Severity/CVSS/Remediation werden, wo vorhanden, übernommen. Findings sind
NICHT auto-erkannt im Sinne der Heuristik, sondern stammen aus dem Scanner.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path

from ..models import (Finding, FindingCategory, FindingStatus, Host, Service,
                      Severity)


@dataclass
class ParsedTarget:
    host: Host
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Port-Hinweis je Finding (Index-gleich), um später an Services zu binden
    finding_ports: list[tuple[int, str] | None] = field(default_factory=list)


# ── Hilfsfunktionen ────────────────────────────────────────────────────────────
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]*\n[ \t]*\n[ \t]*\n+")


def _strip_html(text: str | None) -> str:
    if not text:
        return ""
    t = unescape(_TAG_RE.sub(" ", text))
    t = re.sub(r"[ \t]{2,}", " ", t)
    return _WS_RE.sub("\n\n", t).strip()


def _txt(el) -> str:
    return (el.text or "").strip() if el is not None else ""


def _float_or_none(s: str | None):
    try:
        return float(s) if s not in (None, "") else None
    except (TypeError, ValueError):
        return None


# Nessus: numerische severity 0..4
_NESSUS_SEV = {
    "0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM,
    "3": Severity.HIGH, "4": Severity.CRITICAL,
}
# OpenVAS threat / Burp severity (Text)
_TEXT_SEV = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "log": Severity.INFO, "info": Severity.INFO,
    "information": Severity.INFO, "informational": Severity.INFO, "none": Severity.INFO,
}


def _sev_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _port_proto(raw: str) -> tuple[int | None, str]:
    """'443/tcp' oder '443' -> (443, 'tcp'). 'general/tcp' -> (None, 'tcp')."""
    if not raw:
        return None, "tcp"
    m = re.match(r"(\d+)\s*/\s*(\w+)", raw)
    if m:
        return int(m.group(1)), m.group(2).lower()
    if raw.isdigit():
        return int(raw), "tcp"
    m2 = re.search(r"/(\w+)", raw)
    return None, (m2.group(1).lower() if m2 else "tcp")


def detect_format(path: Path) -> str:
    """Erkennt das Scanner-Format anhand des Wurzelelements/Inhalts."""
    try:
        for _, el in ET.iterparse(str(path), events=("start",)):
            tag = el.tag.lower()
            if "nessusclientdata" in tag:
                return "nessus"
            if tag == "issues":
                return "burp"
            if tag in ("report", "get_results_response", "results"):
                return "openvas"
            # erstes Element reicht zur Entscheidung in den meisten Fällen
            break
    except ET.ParseError:
        pass
    # Fallback: Inhalt schnüffeln
    head = path.read_text(encoding="utf-8", errors="ignore")[:4000].lower()
    if "nessusclientdata" in head:
        return "nessus"
    if "<issues" in head and "burp" in head:
        return "burp"
    if "<nvt" in head or "openvas" in head or "greenbone" in head:
        return "openvas"
    return "unknown"


# ── Nessus ──────────────────────────────────────────────────────────────────────
def parse_nessus(path: Path) -> list[ParsedTarget]:
    root = ET.parse(str(path)).getroot()
    targets: list[ParsedTarget] = []
    for rh in root.iter("ReportHost"):
        props = {t.get("name"): _txt(t) for t in rh.findall("HostProperties/tag")}
        address = props.get("host-ip") or rh.get("name")
        if not address:
            continue
        host = Host(address=address, hostname=props.get("host-fqdn"),
                    os_guess=props.get("operating-system"), status="up")
        pt = ParsedTarget(host=host)
        seen_ports: set[tuple[int, str]] = set()
        for item in rh.findall("ReportItem"):
            sev_raw = item.get("severity", "0")
            port = int(item.get("port", "0") or 0)
            proto = (item.get("protocol") or "tcp").lower()
            svc_name = item.get("svc_name")
            # Service anlegen (einmal je Port)
            if port and (port, proto) not in seen_ports:
                seen_ports.add((port, proto))
                pt.services.append(Service(host_id=0, port=port, protocol=proto,
                                           name=svc_name))
            # Info-Items (severity 0) nicht als Finding übernehmen
            if sev_raw == "0":
                continue
            cvss = (_float_or_none(_txt(item.find("cvss3_base_score")))
                    or _float_or_none(_txt(item.find("cvss_base_score"))))
            vector = (_txt(item.find("cvss3_vector")) or _txt(item.find("cvss_vector")) or None)
            desc = _txt(item.find("description")) or _txt(item.find("synopsis"))
            cve = ", ".join(_txt(c) for c in item.findall("cve"))
            if cve:
                desc = f"{desc}\n\nCVE: {cve}".strip()
            plugin = item.get("pluginName") or "Nessus-Finding"
            f = Finding(
                title=plugin,
                severity=_NESSUS_SEV.get(sev_raw, _sev_from_cvss(cvss)),
                category=FindingCategory.VULN,
                status=FindingStatus.UNVERIFIED,
                description=desc or None,
                remediation=_txt(item.find("solution")) or None,
                cvss_score=cvss, cvss_vector=vector, auto=True,
            )
            pt.findings.append(f)
            pt.finding_ports.append((port, proto) if port else None)
        targets.append(pt)
    return targets


# ── OpenVAS / Greenbone ───────────────────────────────────────────────────────
def parse_openvas(path: Path) -> list[ParsedTarget]:
    root = ET.parse(str(path)).getroot()
    by_host: dict[str, ParsedTarget] = {}

    # results können unter report/results/result oder direkt results/result liegen
    results = root.iter("result")
    for res in results:
        address = _txt(res.find("host"))
        if not address:
            continue
        # 'host' kann zusätzliche Kindelemente haben; nur die IP/erste Zeile nehmen
        address = address.splitlines()[0].strip()
        pt = by_host.get(address)
        if pt is None:
            pt = ParsedTarget(host=Host(address=address, status="up"))
            by_host[address] = pt

        port_raw = _txt(res.find("port"))
        port, proto = _port_proto(port_raw)
        if port and not any(s.port == port and s.protocol == proto for s in pt.services):
            pt.services.append(Service(host_id=0, port=port, protocol=proto))

        threat = _txt(res.find("threat")).lower()
        severity_val = _float_or_none(_txt(res.find("severity")))
        nvt = res.find("nvt")
        name = _txt(nvt.find("name")) if nvt is not None else ""
        cvss = (_float_or_none(_txt(nvt.find("cvss_base"))) if nvt is not None else None)
        if cvss is None:
            cvss = severity_val if (severity_val and severity_val > 0) else None
        # Threat 'Log'/leer + keine CVSS -> Info, überspringen
        sev = _TEXT_SEV.get(threat) or _sev_from_cvss(cvss)
        if sev == Severity.INFO:
            continue
        desc = _txt(res.find("description"))
        # Lösung steht je nach Version in nvt/tags (solution=...) oder nvt/solution
        remediation = None
        if nvt is not None:
            sol_el = nvt.find("solution")
            if sol_el is not None:
                remediation = _txt(sol_el)
            else:
                tags = _txt(nvt.find("tags"))
                m = re.search(r"solution=([^|]+)", tags)
                if m:
                    remediation = m.group(1).strip()
        vector = None
        if nvt is not None:
            tags = _txt(nvt.find("tags"))
            mv = re.search(r"cvss_base_vector=([^|]+)", tags)
            if mv:
                vector = mv.group(1).strip()
        f = Finding(
            title=name or "OpenVAS-Finding",
            severity=sev, category=FindingCategory.VULN,
            status=FindingStatus.UNVERIFIED,
            description=desc or None, remediation=remediation,
            cvss_score=cvss, cvss_vector=vector, auto=True,
        )
        pt.findings.append(f)
        pt.finding_ports.append((port, proto) if port else None)
    return list(by_host.values())


# ── Burp Suite ────────────────────────────────────────────────────────────────
def parse_burp(path: Path) -> list[ParsedTarget]:
    root = ET.parse(str(path)).getroot()
    by_host: dict[str, ParsedTarget] = {}

    for issue in root.findall("issue"):
        host_el = issue.find("host")
        ip = host_el.get("ip") if host_el is not None else None
        url = _txt(host_el)
        address = ip or url or "unknown"
        pt = by_host.get(address)
        if pt is None:
            pt = ParsedTarget(host=Host(address=address, hostname=url or None, status="up"))
            by_host[address] = pt

        sev = _TEXT_SEV.get(_txt(issue.find("severity")).lower(), Severity.INFO)
        if sev == Severity.INFO:
            continue
        name = _txt(issue.find("name")) or "Burp-Finding"
        path_str = _txt(issue.find("path"))
        title = f"{name} ({path_str})" if path_str else name
        bg = _strip_html(_txt(issue.find("issueBackground")))
        detail = _strip_html(_txt(issue.find("issueDetail")))
        desc = "\n\n".join(p for p in (detail, bg) if p) or None
        remediation = _strip_html(_txt(issue.find("remediationBackground"))) or None
        f = Finding(
            title=title, severity=sev, category=FindingCategory.VULN,
            status=FindingStatus.UNVERIFIED, description=desc,
            remediation=remediation, auto=True,
        )
        pt.findings.append(f)
        pt.finding_ports.append(None)
    return list(by_host.values())


_PARSERS = {"nessus": parse_nessus, "openvas": parse_openvas, "burp": parse_burp}


def parse(path: Path, fmt: str | None = None) -> tuple[str, list[ParsedTarget]]:
    """Parst eine Scanner-Datei. fmt erzwingt ein Format, sonst Auto-Erkennung."""
    fmt = fmt or detect_format(path)
    parser = _PARSERS.get(fmt)
    if not parser:
        raise ValueError(
            f"Unbekanntes/zu erzwingendes Format: '{fmt}'. "
            "Unterstützt: nessus, openvas, burp."
        )
    return fmt, parser(path)
