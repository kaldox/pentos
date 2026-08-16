"""
Ingest-Logik für PentOS-Runs.

Verarbeitet die Rohausgabe eines Tool-Laufs in DB-Objekte:
- nmap             -> volle Pipeline (Hosts/Services/Auto-Tasks/Auto-Findings)
- nuclei           -> Findings aus den Treffer-Zeilen
- nikto            -> Findings aus dem XML-Report
- testssl          -> Findings aus dem JSON-Report (--jsonfile)
- httpx/naabu/dnsx -> strukturierte Sammelnotiz aus JSONL (-json), reine Recon
- gitleaks         -> Findings + Loot aus dem JSON-Report (Secret-Scan gegen einen Repo-Dump)
- sonst            -> Capture: Evidence + Notiz mit der Ausgabe

Jeder Lauf wird zusätzlich als Evidence (Rohdatei) und im runs-Log erfasst.

"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from .. import findings_rules, recommend
from ..importers import nmap as nmap_importer
from ..models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    Loot,
    LootType,
    Note,
    RunRecord,
    Service,
    Severity,
)
from ..repository import Repository
from .base import RunResult, ToolSpec, host_of

# nuclei-Severity-Token -> Severity
_NUCLEI_SEV = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL, "unknown": Severity.INFO,
}


def _link_host_id(repo: Repository, target: str) -> Optional[int]:
    """Best-effort: vorhandenen Host per Adresse/Hostname finden (nicht neu anlegen)."""
    host = host_of(target)
    for h in repo.list_hosts():
        if h.address == host or (h.hostname and h.hostname == host):
            return h.id
    return None


def ingest(repo: Repository, spec: ToolSpec, target: str, result: RunResult,
           project_name: str) -> dict:
    summary = {"hosts": 0, "services": 0, "tasks": 0, "findings": 0,
               "notes": 0, "evidence": 0, "loot": 0}

    # Lauf protokollieren
    repo.add_run(RunRecord(
        tool=spec.name, target=target, command=" ".join(result.command),
        returncode=result.returncode, output_path=result.output_path,
        duration_ms=result.duration_ms,
    ))

    # Rohausgabe als Evidence ablegen
    host_id = _link_host_id(repo, target)
    if result.output_path:
        repo.add_evidence(Evidence(
            kind="output", path=result.output_path,
            description=f"{spec.name} gegen {target}", host_id=host_id,
        ))
        summary["evidence"] += 1

    parser = spec.parser or "capture"

    # ── nmap: volle Pipeline ────────────────────────────────────────────────
    if parser == "nmap" and result.output_path and Path(result.output_path).exists():
        try:
            parsed = nmap_importer.parse_nmap_xml(Path(result.output_path))
        except Exception:
            parsed = []
        for host, services in parsed:
            h = repo.add_host(host); summary["hosts"] += 1
            for svc in services:
                svc.host_id = h.id
                persisted = repo.add_service(svc); summary["services"] += 1
                for t in recommend.tasks_for(persisted):
                    if repo.add_task(t):
                        summary["tasks"] += 1
                for f in findings_rules.detect_for_service(persisted):
                    if not repo.finding_exists(f.title, f.service_id):
                        repo.add_finding(f); summary["findings"] += 1
        return summary

    # ── nuclei: strukturierte Findings + Info-Sammelnotiz ────────────────────
    if parser == "nuclei" and result.output_path and Path(result.output_path).exists():
        text = Path(result.output_path).read_text(encoding="utf-8", errors="ignore")
        find_n, info_lines = _parse_nuclei(repo, spec, target, text, host_id)
        summary["findings"] += find_n
        # Info-Treffer (tech-detect, Header, Cookies …) gesammelt als EINE Notiz,
        # nicht als Dutzende Rausch-Findings.
        if info_lines:
            body = (f"nuclei Info-Treffer ({len(info_lines)}) — Kontext, keine Findings:\n\n"
                    + "\n".join(f"- {ln}" for ln in info_lines[:200]))
            repo.add_note(Note(title=f"nuclei (info) · {target} — {len(info_lines)}",
                               body=body, category="vuln", host_id=host_id))
            summary["notes"] += 1
        return summary

    # ── nikto: strukturierte Findings + Info-Sammelnotiz ─────────────────────
    if parser == "nikto" and result.output_path and Path(result.output_path).exists():
        text = Path(result.output_path).read_text(encoding="utf-8", errors="ignore")
        find_n, info_lines = _parse_nikto(repo, spec, target, text, host_id)
        summary["findings"] += find_n
        if info_lines:
            body = (f"nikto Info-Treffer ({len(info_lines)}) — Kontext, keine Findings:\n\n"
                    + "\n".join(f"- {ln}" for ln in info_lines[:200]))
            repo.add_note(Note(title=f"nikto (info) · {target} — {len(info_lines)}",
                               body=body, category="vuln", host_id=host_id))
            summary["notes"] += 1
        return summary

    # ── testssl.sh: strukturierte Findings + Info-Sammelnotiz ────────────────
    if parser == "testssl" and result.output_path and Path(result.output_path).exists():
        text = Path(result.output_path).read_text(encoding="utf-8", errors="ignore")
        find_n, info_lines = _parse_testssl(repo, spec, target, text, host_id)
        summary["findings"] += find_n
        if info_lines:
            body = (f"testssl.sh Info-/Warn-Treffer ({len(info_lines)}) — Kontext, keine Findings:\n\n"
                    + "\n".join(f"- {ln}" for ln in info_lines[:200]))
            repo.add_note(Note(title=f"testssl.sh (info) · {target} — {len(info_lines)}",
                               body=body, category="vuln", host_id=host_id))
            summary["notes"] += 1
        return summary

    # ── gitleaks: Secret-Scan gegen einen lokalen Repo-Dump -> Findings + Loot ─
    if parser == "gitleaks" and result.output_path and Path(result.output_path).exists():
        text = Path(result.output_path).read_text(encoding="utf-8", errors="ignore")
        find_n, loot_n = _parse_gitleaks(repo, spec, target, text, host_id)
        summary["findings"] += find_n
        summary["loot"] += loot_n
        return summary

    # ── Zeilenbasierte Ausgabe (z.B. subfinder -> Subdomains) als Notiz ──────
    if parser == "lines_note":
        text = _read_output(result)
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        body = ("Gefunden ({}):\n\n".format(len(lines)) + "\n".join(f"- {ln}" for ln in lines[:500])) \
            if lines else "Keine Treffer."
        repo.add_note(Note(title=f"{spec.name} · {target} — {len(lines)}",
                           body=body, category=spec.category, host_id=host_id))
        summary["notes"] += 1
        return summary

    # ── ProjectDiscovery-Tools (httpx/naabu/dnsx): natives JSON -> Sammelnotiz ──
    # Reine Recon-/Enumeration-Tools (kein Schwachstellen-Scan) -- wie subfinder
    # und rustscan werden Treffer NICHT zu Findings, sondern zu einer strukturiert
    # formatierten Notiz (jede Zeile ein JSON-Objekt, "-json"-Ausgabe).
    if parser in ("httpx", "naabu", "dnsx"):
        text = _read_output(result)
        if parser == "httpx":
            lines = _parse_httpx(text)
        elif parser == "naabu":
            lines = _parse_naabu(text)
        else:
            lines = _parse_dnsx(text)
        body = ("Gefunden ({}):\n\n".format(len(lines)) + "\n".join(f"- {ln}" for ln in lines[:500])) \
            if lines else "Keine Treffer."
        repo.add_note(Note(title=f"{spec.name} · {target} — {len(lines)}",
                           body=body, category=spec.category, host_id=host_id))
        summary["notes"] += 1
        return summary

    # ── Web-Pfad-Enumeration (ffuf JSON / gobuster / feroxbuster) ────────────
    if parser in ("ffuf_json", "dir_text", "ferox_text"):
        text = _read_output(result)
        if parser == "ffuf_json":
            hits = _parse_ffuf(text)
        elif parser == "dir_text":
            hits = _parse_gobuster(text)
        else:
            hits = _parse_feroxbuster(text)
        summary["notes"] += _paths_note(repo, spec, target, host_id, hits)
        summary["findings"] += _paths_findings(repo, spec, target, host_id, hits)
        return summary

    # ── nxc / netexec: Credentials + Pwn3d ──────────────────────────────────
    if parser == "nxc":
        text = _read_output(result)
        loot_n, find_n = _parse_nxc(repo, spec, target, text, host_id)
        summary["loot"] += loot_n
        summary["findings"] += find_n
        summary["notes"] += _capture_note(repo, spec, target, result, host_id)
        return summary

    # ── enum4linux-ng: strukturierte Auswertung ─────────────────────────────
    if parser == "enum4linux":
        text = _read_output(result)
        n_notes, n_find = _ingest_enum4linux(repo, spec, target, text, host_id)
        summary["notes"] += n_notes
        summary["findings"] += n_find
        return summary

    # ── Default: Capture (Notiz mit Ausgabe), optional Creds -> Loot ─────────
    body_src = _read_output(result)
    if parser == "creds":
        summary["loot"] += _extract_creds(repo, spec, target, body_src, host_id)
    summary["notes"] += _capture_note(repo, spec, target, result, host_id)
    return summary


def _read_output(result: RunResult) -> str:
    """Liefert die Tool-Ausgabe: bevorzugt die Ausgabedatei, sonst stdout.

    Bei Tools mit -o/-oX/-oJ steht das verwertbare Ergebnis in der Datei
    (stdout enthält oft nur Status/Banner). Bei Tools ohne Ausgabedatei wird
    stdout zuvor in eine Capture-Datei geschrieben – auch dann ist die Datei korrekt.
    """
    if result.output_path and Path(result.output_path).exists():
        txt = Path(result.output_path).read_text(encoding="utf-8", errors="ignore")
        if txt.strip():
            return txt
    return result.stdout or ""


def _capture_note(repo: Repository, spec: ToolSpec, target: str,
                  result: RunResult, host_id: Optional[int]) -> int:
    snippet = _read_output(result).strip()
    if len(snippet) > 4000:
        snippet = snippet[:4000] + "\n... [gekürzt – vollständige Ausgabe in scans/]"
    note_body = (
        f"Kommando: `{' '.join(result.command)}`\n"
        f"Exit-Code: {result.returncode}  ·  Dauer: {result.duration_ms} ms\n\n"
        f"```\n{snippet}\n```"
    )
    repo.add_note(Note(title=f"{spec.name} · {target}", body=note_body,
                       category=spec.category, host_id=host_id))
    return 1


# ── Web-Pfad-Parser ───────────────────────────────────────────────────────────
_GOBUSTER = re.compile(r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]")


def _parse_ffuf(text: str) -> list[tuple]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    hits = []
    for r in data.get("results", []):
        url = r.get("url") or str(r.get("input", ""))
        hits.append((url, r.get("status"), r.get("length")))
    return hits


def _parse_gobuster(text: str) -> list[tuple]:
    hits = []
    for line in text.splitlines():
        m = _GOBUSTER.match(line.strip())
        if m:
            hits.append((m.group("path"), int(m.group("status")), int(m.group("size"))))
    return hits


# nuclei -silent-Zeile: [template-id] [protocol] [severity] url [extractor...]
_NUCLEI_LINE = re.compile(
    r"^\[(?P<tpl>[^\]]+)\]\s+\[(?P<proto>[^\]]+)\]\s+"
    r"\[(?P<sev>info|low|medium|high|critical|unknown)\]\s+"
    r"(?P<url>\S+)(?P<rest>.*)$",
    re.IGNORECASE,
)


def _parse_nuclei(repo: Repository, spec, target: str, text: str,
                  host_id: Optional[int]) -> tuple[int, list[str]]:
    """Strukturierter nuclei-Parser.

    Liefert (Anzahl angelegter Findings, Liste der Info-Treffer-Texte).
    - Nur Low+ werden Findings (mit sauberem Titel = Template-ID).
    - Info-Treffer (tech-detect, Header, Cookies) werden NICHT zu Findings,
      sondern vom Aufrufer als eine Sammelnotiz abgelegt.
    - Zeilen ohne gültiges nuclei-Format (Config/Banner) werden ignoriert.
    """
    find_n = 0
    info_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _NUCLEI_LINE.match(line)
        if not m:
            continue  # kein gültiger Treffer -> ignorieren (kein Müll-Finding)
        tpl = m.group("tpl").strip()
        sev = _NUCLEI_SEV.get(m.group("sev").lower(), Severity.INFO)
        url = m.group("url").strip()
        rest = m.group("rest").strip()
        if sev == Severity.INFO:
            info_lines.append(f"{tpl} → {url}{(' ' + rest) if rest else ''}")
            continue
        title = f"{tpl} ({target})"
        if repo.finding_exists(title, host_id=host_id):
            continue
        desc = f"nuclei-Treffer: {tpl}\nURL: {url}"
        if rest:
            desc += f"\nDetails: {rest}"
        repo.add_finding(Finding(
            title=title, severity=sev, category=FindingCategory.VULN,
            status=FindingStatus.UNVERIFIED, description=desc,
            host_id=host_id, auto=True,
        ))
        find_n += 1
    return find_n, info_lines


# ── nikto: XML-Report ("-o {outfile} -Format xml") -> Findings ──────────────
# Vorbild: das offizielle nikto_report_xml.plugin (program/plugins/ im
# sullo/nikto-Repo). <item id=".." method="..">-Elemente mit den
# Kindelementen description/uri/namelink/iplink/references, beliebig tief
# verschachtelt unter <scandetails> -- deshalb root.iter() statt fixer Pfade.

# Häufige Low-Signal-Treffer (fehlende Security-Header etc.) werden NICHT zu
# Findings, sondern gesammelt als eine Notiz abgelegt (wie nuclei-Info-Treffer).
_NIKTO_NOISE = re.compile(
    r"x-frame-options|x-content-type-options|x-xss-protection|"
    r"strict-transport-security|content-security-policy|anti-clickjacking|"
    r"uncommon header|referrer-policy|permissions-policy|"
    r"cookie.*(httponly|secure)",
    re.IGNORECASE,
)

# Reihenfolge = Priorität; erste passende Regel gewinnt. Kein CVSS von nikto
# selbst verfügbar -> Severity wird heuristisch aus Text/Referenzen abgeleitet.
_NIKTO_SEV_RULES: list[tuple[re.Pattern, "Severity"]] = [
    (re.compile(r"remote (code|command) execution|backdoor", re.IGNORECASE), Severity.CRITICAL),
    (re.compile(
        r"sql injection|cross[- ]site scripting|\bxss\b|command injection|"
        r"authentication bypass|default (account|credential|password)|"
        r"cve-\d{4}-\d+", re.IGNORECASE), Severity.HIGH),
    (re.compile(
        r"outdated|vulnerable|directory (indexing|listing)|disclosure|"
        r"backup|\.bak\b|phpinfo|shellshock|sensitive|config(uration)? file",
        re.IGNORECASE), Severity.MEDIUM),
]


def _nikto_severity(text: str) -> Severity:
    for pattern, sev in _NIKTO_SEV_RULES:
        if pattern.search(text):
            return sev
    return Severity.LOW


def _parse_nikto_xml(text: str) -> list[dict]:
    """Parst nikto-XML-Output in eine Liste von Rohtreffern.

    Robust gegen bekannte nikto-XML-Eigenheiten (z.B. leere/fehlerhafte
    Dokumente bei Nicht-Webserver-Zielen) -- liefert dann [] statt zu werfen.
    """
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    hits = []
    for item in root.iter("item"):
        desc = (item.findtext("description") or "").strip()
        if not desc:
            continue
        hits.append({
            "id": item.get("id", ""), "method": item.get("method", ""),
            "description": desc,
            "uri": (item.findtext("uri") or "").strip(),
            "references": (item.findtext("references") or "").strip(),
        })
    return hits


def _parse_nikto(repo: Repository, spec, target: str, text: str,
                 host_id: Optional[int]) -> tuple[int, list[str]]:
    """Strukturierter nikto-Parser (Vorbild: der nuclei-Parser).

    Liefert (Anzahl angelegter Findings, Liste der Info-Treffer-Texte) genau
    wie `_parse_nuclei`. Header-Rauschen wird gesammelt statt Findings zu
    spammen; alles andere wird ein Finding mit heuristischer Severity.
    """
    find_n = 0
    info_lines: list[str] = []
    for h in _parse_nikto_xml(text):
        combined = f"{h['description']} {h['references']}"
        if _NIKTO_NOISE.search(combined):
            info_lines.append(f"{h['uri'] or '/'} — {h['description']}")
            continue
        title_body = h["description"]
        if len(title_body) > 100:
            title_body = title_body[:97] + "…"
        title = f"{title_body} ({target})"
        if repo.finding_exists(title, host_id=host_id):
            continue
        desc = h["description"]
        if h["uri"]:
            desc += f"\nPfad: {h['uri']}"
        if h["references"]:
            desc += f"\nReferenzen: {h['references']}"
        repo.add_finding(Finding(
            title=title, severity=_nikto_severity(combined), category=FindingCategory.VULN,
            status=FindingStatus.UNVERIFIED, description=desc,
            host_id=host_id, auto=True,
        ))
        find_n += 1
    return find_n, info_lines


# ── testssl.sh: JSON-Report ("--jsonfile {outfile}", flaches Array) -> Findings ──
# Vorbild: die offizielle fileout_json_finding()-Funktion im testssl/testssl.sh-
# Repo (ab Version 3.2). Jedes Element: {"id","ip","port","severity","cve","cwe",
# "hint"?,"finding"}. Severity kommt direkt vom Tool -- anders als bei nikto
# braucht es keine eigene Heuristik. OK/DEBUG sind reines "Test bestanden"/
# Diagnose-Rauschen und werden verworfen; INFO/WARN/FATAL (Scan-Probleme,
# Kontext-Infos) landen als Sammelnotiz; LOW+ werden Findings.
_TESTSSL_SEV = {
    "LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL,
}
_TESTSSL_NOISE_SEV = {"INFO", "WARN", "FATAL"}   # als Notiz, kein Finding
_TESTSSL_SKIP_SEV = {"OK", "DEBUG"}              # kein Sicherheitswert -> verwerfen


def _parse_testssl_json(text: str) -> list[dict]:
    """Parst testssl.sh --jsonfile-Output (flaches Array) in eine Liste von
    Rohtreffern. Robust gegen leere/fehlerhafte Dateien (z.B. abgebrochener
    Scan) -- liefert dann [] statt zu werfen. Akzeptiert zusätzlich den
    Pretty-Wrapper mit 'scanResult' (--jsonfile-pretty), falls jemand
    versehentlich die Pretty-Variante als Ausgabedatei übergibt."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if isinstance(data, dict):
        data = data.get("scanResult", [])
    if not isinstance(data, list):
        return []
    hits = []
    for item in data:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity") or "").upper()
        finding = (item.get("finding") or "").strip()
        if not sev or not finding:
            continue
        hits.append({
            "id": str(item.get("id") or ""), "port": str(item.get("port") or ""),
            "severity": sev, "cve": (item.get("cve") or "").strip(),
            "cwe": (item.get("cwe") or "").strip(), "finding": finding,
        })
    return hits


def _parse_testssl(repo: Repository, spec, target: str, text: str,
                   host_id: Optional[int]) -> tuple[int, list[str]]:
    """Strukturierter testssl.sh-Parser (Vorbild: der nikto-Parser).

    Liefert (Anzahl angelegter Findings, Liste der Info-/Warn-Treffer-Texte)
    genau wie `_parse_nikto`. OK/DEBUG werden verworfen (kein Sicherheitswert,
    wären reines Rauschen bei hunderten Einzelchecks pro Scan).
    """
    find_n = 0
    info_lines: list[str] = []
    for h in _parse_testssl_json(text):
        sev_raw = h["severity"]
        if sev_raw in _TESTSSL_SKIP_SEV:
            continue
        port_txt = f":{h['port']}" if h["port"] else ""
        if sev_raw in _TESTSSL_NOISE_SEV:
            info_lines.append(f"{h['id']}{port_txt} — {h['finding']}")
            continue
        sev = _TESTSSL_SEV.get(sev_raw)
        if sev is None:
            continue  # unbekannter Wert -> auf Nummer sicher, kein Müll-Finding
        title_body = h["finding"]
        if len(title_body) > 100:
            title_body = title_body[:97] + "…"
        title = f"{h['id']}: {title_body} ({target}{port_txt})"
        if repo.finding_exists(title, host_id=host_id):
            continue
        desc = h["finding"]
        if h["cve"]:
            desc += f"\nCVE: {h['cve']}"
        if h["cwe"]:
            desc += f"\nCWE: {h['cwe']}"
        category = FindingCategory.VULN if h["cve"] else FindingCategory.MISCONFIG
        repo.add_finding(Finding(
            title=title, severity=sev, category=category,
            status=FindingStatus.UNVERIFIED, description=desc,
            host_id=host_id, auto=True,
        ))
        find_n += 1
    return find_n, info_lines


# ── ProjectDiscovery-Tools: httpx / naabu / dnsx (JSONL, "-json") ────────────
# Schema verifiziert gegen die Go-Structs der jeweiligen Repos
# (projectdiscovery/httpx runner/types.go, naabu pkg/result, dnsx libs/dnsx):
# ein JSON-Objekt pro Zeile, kein Rahmen/Array drumherum.
def _parse_jsonl(text: str) -> list[dict]:
    """Parst zeilenbasiertes JSON (ein Objekt pro Zeile). Robust gegen leere/
    kaputte Zeilen (z.B. Banner-/Warnzeilen von -silent-Tools) -- diese werden
    einfach übersprungen statt den ganzen Parse fehlschlagen zu lassen."""
    items = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            items.append(obj)
    return items


def _parse_httpx(text: str) -> list[str]:
    """httpx -json: u.a. url, status_code, title, webserver, tech (Liste)."""
    lines = []
    for obj in _parse_jsonl(text):
        url = (obj.get("url") or obj.get("input") or "").strip()
        if not url:
            continue
        parts = [url]
        status = obj.get("status_code")
        if status:
            parts.append(f"[{status}]")
        title = (obj.get("title") or "").strip()
        if title:
            parts.append(f"– {title}")
        server = (obj.get("webserver") or "").strip()
        if server:
            parts.append(f"({server})")
        tech = obj.get("tech") or []
        if tech:
            parts.append("· " + ", ".join(str(t) for t in tech))
        lines.append(" ".join(parts))
    return lines


def _parse_naabu(text: str) -> list[str]:
    """naabu -json: mindestens ip + port, optional host/protocol."""
    lines = []
    for obj in _parse_jsonl(text):
        ip = str(obj.get("ip") or "").strip()
        port = obj.get("port")
        if not ip or port is None:
            continue
        host = str(obj.get("host") or "").strip()
        proto = obj.get("protocol") or "tcp"
        label = f"{host} ({ip})" if host and host != ip else ip
        lines.append(f"{label}:{port}/{proto}")
    return lines


def _parse_dnsx(text: str) -> list[str]:
    """dnsx -json: host + a/aaaa/cname (jeweils Liste von Strings)."""
    lines = []
    for obj in _parse_jsonl(text):
        host = str(obj.get("host") or "").strip()
        if not host:
            continue
        parts = [host]
        a = obj.get("a") or []
        if a:
            parts.append("→ " + ", ".join(str(x) for x in a))
        aaaa = obj.get("aaaa") or []
        if aaaa:
            parts.append("(AAAA " + ", ".join(str(x) for x in aaaa) + ")")
        cname = obj.get("cname") or []
        if cname:
            parts.append("(CNAME " + ", ".join(str(x) for x in cname) + ")")
        lines.append(" ".join(parts))
    return lines


# ── gitleaks: JSON-Report ("--report-format json") -> Findings + Loot ────────
# Vorbild: der report.Finding-Struct im gitleaks/gitleaks-Repo (report/finding.go).
# Flaches Array; Felder u.a. RuleID, Description, Secret, File, Commit, Author,
# Email, Date, Tags, Fingerprint. gitleaks liefert keine eigene Severity --
# jeder echte Fund ist ein Secret, daher einheitlich HIGH/CREDENTIAL statt
# einer Heuristik wie bei nikto. Wie beim nxc-Parser: Findings fürs Tracking,
# Loot für den vollen Wert (Secret nur maskiert im Finding-Text, das auch in
# Reports landet).
_LOOT_TYPE_HINTS: list[tuple[re.Pattern, "LootType"]] = [
    (re.compile(r"ssh|private[-_ ]?key|pem", re.IGNORECASE), LootType.SSH_KEY),
    (re.compile(r"token|bearer|jwt", re.IGNORECASE), LootType.TOKEN),
    (re.compile(r"api[-_ ]?key|secret[-_ ]?key|access[-_ ]?key", re.IGNORECASE), LootType.API_KEY),
    (re.compile(r"password|pwd|passwd", re.IGNORECASE), LootType.CREDENTIAL),
]


def _gitleaks_loot_type(rule_id: str) -> "LootType":
    for pattern, lt in _LOOT_TYPE_HINTS:
        if pattern.search(rule_id):
            return lt
    return LootType.OTHER


def _mask_secret(secret: str) -> str:
    """Zeigt nur Anfang/Ende eines Secrets -- der volle Wert landet als Loot,
    nicht zusätzlich im Finding-Text (der auch in Reports gedruckt wird)."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"


def _parse_gitleaks_json(text: str) -> list[dict]:
    """Parst gitleaks --report-format json (flaches Array) in eine Liste von
    Rohtreffern. Robust gegen leere/kaputte Dateien (z.B. 'keine Funde' ->
    leeres Array, oder abgebrochener Scan) -- liefert dann [] statt zu werfen."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    hits = []
    for item in data:
        if not isinstance(item, dict):
            continue
        secret = (item.get("Secret") or "").strip()
        file_ = (item.get("File") or "").strip()
        if not secret or not file_:
            continue
        hits.append({
            "rule_id": str(item.get("RuleID") or "unknown"),
            "description": (item.get("Description") or "").strip(),
            "secret": secret,
            "file": file_,
            "commit": str(item.get("Commit") or "")[:12],
            "author": (item.get("Author") or "").strip(),
            "email": (item.get("Email") or "").strip(),
            "date": (item.get("Date") or "").strip(),
            "fingerprint": str(item.get("Fingerprint") or ""),
        })
    return hits


def _parse_gitleaks(repo: Repository, spec, target: str, text: str,
                    host_id: Optional[int]) -> tuple[int, int]:
    """Strukturierter gitleaks-Parser (Vorbild: der nxc-Parser für Credential-
    Funde). Liefert (Anzahl Findings, Anzahl Loot-Einträge). Dedup nur
    innerhalb eines Laufs (per Fingerprint), wie bei nxc -- kein DB-weiter
    Loot-Dedup, das ist im Projekt so etabliert."""
    find_n = 0
    loot_n = 0
    seen: set[str] = set()
    for h in _parse_gitleaks_json(text):
        key = h["fingerprint"] or f"{h['file']}:{h['rule_id']}:{h['secret']}"
        if key in seen:
            continue
        seen.add(key)
        title = f"Secret in Git-Historie: {h['rule_id']} ({h['file']})"
        if not repo.finding_exists(title, host_id=host_id):
            desc = (
                f"{h['description'] or h['rule_id']}\n"
                f"Datei: {h['file']}\n"
                f"Commit: {h['commit'] or '-'}  ·  Autor: {h['author'] or '-'} <{h['email'] or '-'}>  "
                f"·  Datum: {h['date'] or '-'}\n"
                f"Vorschau: {_mask_secret(h['secret'])} (voller Wert als Loot gespeichert)"
            )
            repo.add_finding(Finding(
                title=title, severity=Severity.HIGH, category=FindingCategory.CREDENTIAL,
                status=FindingStatus.UNVERIFIED, description=desc,
                host_id=host_id, auto=True,
            ))
            find_n += 1
        repo.add_loot(Loot(
            type=_gitleaks_loot_type(h["rule_id"]), label=f"gitleaks: {h['rule_id']} ({h['file']})",
            value=h["secret"], host_id=host_id, source=f"gitleaks · {target}",
        ))
        loot_n += 1
    return find_n, loot_n


def _parse_feroxbuster(text: str) -> list[tuple]:
    hits = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit() and parts[-1].startswith("http"):
            size = None
            for tok in parts:
                if tok.endswith("c") and tok[:-1].isdigit():
                    size = int(tok[:-1])
                    break
            hits.append((parts[-1], int(parts[0]), size))
    return hits


def _paths_note(repo: Repository, spec: ToolSpec, target: str,
                host_id: Optional[int], hits: list[tuple]) -> int:
    if hits:
        lines = [f"Gefundene Pfade ({len(hits)}):", ""]
        for url, status, size in hits[:300]:
            sz = f"  [{size}]" if size is not None else ""
            lines.append(f"- {status}  {url}{sz}")
        if len(hits) > 300:
            lines.append(f"... (+{len(hits) - 300} weitere, vollständig in scans/)")
        body = "\n".join(lines)
    else:
        body = "Keine Treffer."
    repo.add_note(Note(title=f"{spec.name} · {target} — {len(hits)} Pfade",
                       body=body, category=spec.category, host_id=host_id))
    return 1


# Nur Pfade mit einem dieser Status-Codes gelten als "erreichbar" (403 zeigt
# Existenz trotz Sperre, 401 zeigt Existenz hinter Auth).
_REACHABLE_STATUS = {200, 204, 301, 302, 401, 403}

# (Muster, Titel, Severity, Kategorie, Beschreibung) – erster Treffer pro Pfad zählt.
_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern, str, "Severity", "FindingCategory", str]] = [
    (re.compile(r"id_rsa$|id_ed25519$|id_dsa$", re.IGNORECASE),
     "Privater SSH-Schlüssel erreichbar", Severity.CRITICAL, FindingCategory.CREDENTIAL,
     "Eine Datei, die wie ein privater SSH-Schlüssel benannt ist, ist über HTTP erreichbar."),
    (re.compile(r"\.git(/|$)", re.IGNORECASE),
     "Exponiertes .git-Verzeichnis", Severity.HIGH, FindingCategory.EXPOSURE,
     "Das .git-Verzeichnis ist erreichbar. Repository-Historie (ggf. Quellcode/Secrets) "
     "kann daraus rekonstruiert werden (z.B. mit git-dumper). Nach dem Dump: "
     "'pentos run gitleaks <pfad-zum-dump>' durchsucht die komplette Commit-Historie "
     "nach Secrets (API-Keys, Passwörter, Token) und legt Treffer als Findings + Loot an."),
    (re.compile(r"(^|/)\.svn(/|$)|(^|/)\.hg(/|$)", re.IGNORECASE),
     "Exponiertes VCS-Verzeichnis", Severity.HIGH, FindingCategory.EXPOSURE,
     "Ein Versionskontroll-Verzeichnis (SVN/Mercurial) ist erreichbar."),
    (re.compile(r"\.env$", re.IGNORECASE),
     "Exponierte .env-Datei", Severity.HIGH, FindingCategory.CREDENTIAL,
     "Eine .env-Datei ist erreichbar. Enthält häufig Zugangsdaten/API-Keys."),
    (re.compile(r"\.htpasswd$", re.IGNORECASE),
     "Exponierte .htpasswd", Severity.HIGH, FindingCategory.CREDENTIAL,
     ".htpasswd ist erreichbar und kann Passwort-Hashes offenlegen."),
    (re.compile(r"\.(sql|sqlite3?|bak|backup|old|zip|tar\.gz|tgz|swp)$", re.IGNORECASE),
     "Backup-/Altdatei erreichbar", Severity.MEDIUM, FindingCategory.INFO_DISCLOSURE,
     "Eine Backup-/Altdatei ist erreichbar und kann Quellcode, Konfiguration oder "
     "Datenbankinhalte offenlegen."),
    (re.compile(r"web\.config$", re.IGNORECASE),
     "Exponierte web.config", Severity.MEDIUM, FindingCategory.INFO_DISCLOSURE,
     "web.config ist erreichbar und kann Konfigurationsdetails offenlegen."),
    (re.compile(r"(^|/)(phpmyadmin|adminer)(/|$)", re.IGNORECASE),
     "Datenbank-Admin-Interface erreichbar", Severity.MEDIUM, FindingCategory.EXPOSURE,
     "Ein Datenbank-Verwaltungsinterface (phpMyAdmin/Adminer) ist erreichbar."),
    (re.compile(r"(^|/)(admin|administrator|manager/html|wp-admin)(/|$)", re.IGNORECASE),
     "Admin-Interface erreichbar", Severity.LOW, FindingCategory.EXPOSURE,
     "Ein Admin-/Management-Interface ist erreichbar."),
]


def _paths_findings(repo: Repository, spec: ToolSpec, target: str,
                    host_id: Optional[int], hits: list[tuple]) -> int:
    """Erkennt sicherheitsrelevante Pfade (VCS, Secrets, Backups, Admin-Interfaces)
    aus Web-Pfad-Enumeration und legt dafür Findings an – strukturiert statt nur
    als Rohnotiz (Vorbild: nuclei-/enum4linux-ng-Parser)."""
    matched: dict[str, list[str]] = {}
    for url, status, _size in hits:
        if status not in _REACHABLE_STATUS:
            continue
        for pattern, title, _sev, _cat, _desc in _SENSITIVE_PATH_PATTERNS:
            if pattern.search(url):
                matched.setdefault(title, []).append(url)
                break  # erstes passendes Muster pro Pfad reicht

    find_n = 0
    for _pattern, title, sev, cat, desc in _SENSITIVE_PATH_PATTERNS:
        urls = matched.get(title)
        if not urls:
            continue
        full_title = f"{title} ({target})"
        if repo.finding_exists(full_title, host_id=host_id):
            continue
        shown = urls[:20]
        urls_txt = "\n".join(f"- {u}" for u in shown)
        if len(urls) > len(shown):
            urls_txt += f"\n... (+{len(urls) - len(shown)} weitere, siehe Notiz)"
        repo.add_finding(Finding(
            title=full_title, severity=sev, category=cat,
            status=FindingStatus.UNVERIFIED,
            description=f"{desc}\n\nGefundene Pfade ({len(urls)}):\n{urls_txt}",
            host_id=host_id, auto=True,
        ))
        find_n += 1
    return find_n


# ── nxc / netexec: Credentials + Pwn3d ────────────────────────────────────────
_NXC = re.compile(
    r"\[\+\]\s+(?:(?P<dom>[^\\\s]+)\\)?(?P<user>[^\s:]+):(?P<pwd>\S+?)(?P<pwn>\s+\(Pwn3d!\))?\s*$"
)


def _parse_nxc(repo: Repository, spec: ToolSpec, target: str,
               text: str, host_id: Optional[int]) -> tuple[int, int]:
    loot_n = find_n = 0
    seen: set[tuple] = set()
    for line in (text or "").splitlines():
        m = _NXC.search(line.strip())
        if not m:
            continue
        dom, user, pwd = m.group("dom"), m.group("user"), m.group("pwd")
        if (dom, user, pwd) in seen:
            continue
        seen.add((dom, user, pwd))
        label = f"{dom}\\{user}:{pwd}" if dom else f"{user}:{pwd}"
        repo.add_loot(Loot(
            type=LootType.CREDENTIAL, label=label, value=pwd,
            host_id=host_id, source=f"{spec.name} {target}",
        ))
        loot_n += 1
        if m.group("pwn"):
            who = f"{dom}\\{user}" if dom else user
            title = f"Administrativer Zugriff (Pwn3d) via {spec.name}: {who}"
            if not repo.finding_exists(title, host_id=host_id):
                repo.add_finding(Finding(
                    title=title, severity=Severity.HIGH, category=FindingCategory.CREDENTIAL,
                    status=FindingStatus.CONFIRMED,
                    description=f"NetExec meldet administrativen Zugriff für {who} auf {target}.",
                    host_id=host_id, auto=True,
                ))
                find_n += 1
    return loot_n, find_n


# ── enum4linux-ng: strukturierte Auswertung ───────────────────────────────────
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "")


def _parse_enum4linux_data(text: str) -> dict:
    """Extrahiert strukturierte Felder aus enum4linux-ng-Ausgabe (ANSI-tolerant)."""
    t = _strip_ansi(text)
    d: dict = {
        "workgroup": None, "computer_name": None, "fqdn": None,
        "os": None, "server_string": None, "smb_signing_required": None,
        "null_session": False, "guest_access": False,
        "users": [], "user_count": 0, "groups": [], "group_count": 0, "shares": [],
        "domain_sid": None, "krbtgt_visible": False, "priv_groups": [],
    }

    def _find(pat):
        m = re.search(pat, t, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    d["workgroup"] = _find(r"Got domain/workgroup name:\s*(\S+)") or _find(r"^\[\+\]\s*Domain:\s*(\S+)")
    d["computer_name"] = _find(r"NetBIOS computer name:\s*(\S+)")
    d["fqdn"] = _find(r"FQDN:\s*(\S+)")
    d["os"] = _find(r"^OS:\s*(.+)$")
    d["server_string"] = _find(r"Server type string:\s*(.+)$")

    sig = _find(r"SMB signing required:\s*(true|false)")
    if sig is not None:
        d["smb_signing_required"] = (sig.lower() == "true")

    low = t.lower()
    d["null_session"] = "authentication via username '' and password ''" in low
    d["guest_access"] = bool(re.search(r"authentication via username '\S+' and password ''", t))

    # Benutzer & Gruppen (ng-RPC-Format: 'username:'/'groupname:', Namen können Leerzeichen haben)
    d["users"] = sorted({m.strip() for m in re.findall(r"^\s*username:\s*(.+?)\s*$", t, re.MULTILINE)})
    d["groups"] = sorted({m.strip() for m in re.findall(r"^\s*groupname:\s*(.+?)\s*$", t, re.MULTILINE)})
    # Anzahl bevorzugt aus der "we have N ... total"-Zeile (sonst Teilzahlen/Liste)
    total_users = re.search(r"we have (\d+) user\(s\) total", t)
    if total_users:
        d["user_count"] = int(total_users.group(1))
    else:
        uc = [int(n) for n in re.findall(r"Found (\d+) user\(s\)", t)]
        d["user_count"] = max(uc) if uc else len(d["users"])
    total_groups = re.search(r"we have (\d+) group\(s\) total", t)
    if total_groups:
        d["group_count"] = int(total_groups.group(1))
    else:
        gc = [int(n) for n in re.findall(r"Found (\d+) group\(s\)", t)]
        d["group_count"] = max(gc) if gc else len(d["groups"])

    d["domain_sid"] = _find(r"Domain SID:\s*(S-1-5-\S+)")
    d["krbtgt_visible"] = any(u.lower() == "krbtgt" for u in d["users"])
    _PRIV = {"domain admins", "enterprise admins", "schema admins",
             "administrators", "domain controllers", "group policy creator owners"}
    d["priv_groups"] = [g for g in d["groups"] if g.lower() in _PRIV]

    # Shares: Name/Typ aus Definitionsblock, Zugriff aus 'Testing share'-Zeilen.
    # enum4linux-ng schreibt Default-Shares Backslash-escaped ('ADMIN\$:',
    # 'IPC\$:'); die Namen werden normalisiert (Backslash entfernt), damit
    # z.B. der IPC$-Ausschluss unten und finding-Titel den sauberen Namen
    # ('IPC$') statt der escapten Rohform sehen.
    types: dict[str, str] = {}
    cur = None
    for line in t.splitlines():
        m = re.match(r"^([A-Za-z0-9$_.\\-]+):\s*$", line)
        if m:
            cur = m.group(1).replace("\\", "")
            continue
        mt = re.match(r"^\s+type:\s*(\S+)", line)
        if mt and cur:
            types[cur] = mt.group(1)
            cur = None

    access: dict[str, str] = {}
    lines = t.splitlines()
    for i, line in enumerate(lines):
        mt = re.match(r"\[\*\]\s*Testing share (.+)", line)
        if not mt:
            continue
        name = mt.group(1).strip().replace("\\", "")
        result_line = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if result_line.startswith("[+]"):
            access[name] = result_line[3:].strip()
        elif result_line.startswith("[-]"):
            access[name] = "nicht prüfbar"
    for name in sorted(set(list(types) + list(access))):
        d["shares"].append({
            "name": name,
            "type": types.get(name, "?"),
            "access": access.get(name, "?"),
        })
    return d


def _ingest_enum4linux(repo: Repository, spec: ToolSpec, target: str,
                       text: str, host_id: Optional[int]) -> tuple[int, int]:
    d = _parse_enum4linux_data(text)

    # Strukturierte Notiz
    body = [
        f"Workgroup/Domain: {d['workgroup'] or '-'}",
        f"Domain-SID:       {d['domain_sid'] or '-'}",
        f"Computername:     {d['computer_name'] or '-'}",
        f"FQDN:             {d['fqdn'] or '-'}",
        f"OS:               {d['os'] or '-'}",
        f"Server:           {d['server_string'] or '-'}",
        f"SMB Signing:      {'erzwungen' if d['smb_signing_required'] else 'NICHT erzwungen' if d['smb_signing_required'] is False else '-'}",
        f"Null-Session:     {'ja' if d['null_session'] else 'nein'}",
        f"Guest-Zugriff:    {'ja' if d['guest_access'] else 'nein'}",
        "",
        f"Benutzer ({d['user_count']}): {', '.join(d['users']) if d['users'] else '-'}",
        f"Gruppen ({d['group_count']}): {', '.join(d['groups']) if d['groups'] else '-'}",
        "",
        "Shares:",
    ]
    for s in d["shares"]:
        body.append(f"  - {s['name']} ({s['type']}) — {s['access']}")
    if not d["shares"]:
        body.append("  - keine")
    repo.add_note(Note(title=f"enum4linux-ng · {target}", body="\n".join(body),
                       category="smb", host_id=host_id))

    # Findings
    find_n = 0

    def _add(title, sev, cat, desc):
        nonlocal find_n
        if not repo.finding_exists(title, host_id=host_id):
            repo.add_finding(Finding(title=title, severity=sev, category=cat,
                                     status=FindingStatus.UNVERIFIED, description=desc,
                                     host_id=host_id, auto=True))
            find_n += 1

    if d["null_session"]:
        _add(f"SMB Null-Session erlaubt ({target})", Severity.MEDIUM, FindingCategory.MISCONFIG,
             "Anonyme SMB-Authentifizierung (Benutzer/Passwort leer) wird akzeptiert.")
    if d["smb_signing_required"] is False:
        _add(f"SMB Signing nicht erzwungen ({target})", Severity.MEDIUM, FindingCategory.MISCONFIG,
             "SMB-Signing ist nicht erforderlich – anfällig für NTLM-Relay.")
    for s in d["shares"]:
        acc = s["access"].lower()
        if "mapping: ok" in acc and "listing: ok" in acc and s["name"].upper() != "IPC$":
            _add(f"Anonym lesbarer SMB-Share: {s['name']} ({target})",
                 Severity.MEDIUM, FindingCategory.EXPOSURE,
                 f"Der Share '{s['name']}' ist ohne Authentifizierung les-/auflistbar.")

    # Authentifizierte Domänen-Enumeration: Benutzer/Gruppen + krbtgt sichtbar
    if d["krbtgt_visible"] and d["user_count"] > 0:
        names = ", ".join(d["priv_groups"][:6]) or "—"
        _add(f"Domänen-Enumeration möglich ({target})", Severity.MEDIUM,
             FindingCategory.EXPOSURE,
             f"Konto- und Gruppenliste der Domäne ist auslesbar "
             f"({d['user_count']} Benutzer, {d['group_count']} Gruppen, Domain-SID {d['domain_sid'] or '?'}). "
             f"Das Konto 'krbtgt' ist sichtbar (AS-REP-/Kerberoasting-Angriffsfläche). "
             f"Privilegierte Gruppen: {names}.")

    return 1, find_n


# hydra:  [22][ssh] host: 10.10.10.10   login: bob   password: secret
# medusa: ACCOUNT FOUND: [ssh] Host: x User: bob Password: secret [SUCCESS]
_CRED_PATTERNS = [
    re.compile(r"login:\s*(?P<user>\S+)\s+password:\s*(?P<pwd>\S+)", re.IGNORECASE),
    re.compile(r"User:\s*(?P<user>\S+)\s+Password:\s*(?P<pwd>\S+)", re.IGNORECASE),
]


def _extract_creds(repo: Repository, spec: ToolSpec, target: str,
                   text: str, host_id: Optional[int]) -> int:
    found = 0
    seen: set[tuple[str, str]] = set()
    for pat in _CRED_PATTERNS:
        for m in pat.finditer(text or ""):
            user, pwd = m.group("user"), m.group("pwd")
            if (user, pwd) in seen:
                continue
            seen.add((user, pwd))
            repo.add_loot(Loot(
                type=LootType.CREDENTIAL, label=f"{user}:{pwd}", value=pwd,
                host_id=host_id, source=f"{spec.name} {target}",
            ))
            found += 1
    return found
