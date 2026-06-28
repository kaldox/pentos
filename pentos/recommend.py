"""
Empfehlungs-Engine für PentOS.

Bildet erkannte Services (Port / Service-Name) auf
- konkrete Workflow-Empfehlungen (nächste Schritte) und
- automatisch generierte Aufgaben (Tasks)
ab. Rein regelbasiert. KEINE automatische Ausführung – nur Vorschläge.

"""
from __future__ import annotations

from typing import Optional

from .models import Service, Task

# Jede Regel: passt auf bestimmte Ports und/oder Service-Namen-Stichwörter.
# "recommendations" = empfohlene Tools/Vorgehen (Reihenfolge = Priorität)
# "tasks"           = automatisch zu erzeugende Aufgaben
# "label"           = kurzer Bezeichner für die Quelle (source) der Tasks
RULES: list[dict] = [
    {
        "label": "ftp",
        "ports": [21],
        "keywords": ["ftp"],
        "recommendations": ["Anonymous Login testen", "Banner/Version prüfen", "Bekannte CVEs prüfen"],
        "tasks": ["Anonymous FTP testen", "Banner/Version erfassen", "Schreibrechte prüfen"],
    },
    {
        "label": "ssh",
        "ports": [22],
        "keywords": ["ssh"],
        "recommendations": ["ssh-audit", "Auth-Methoden prüfen", "Schwache Algorithmen prüfen"],
        "tasks": ["SSH-Version erfassen", "Auth-Methoden enumerieren", "Schwache Algorithmen prüfen"],
    },
    {
        "label": "smtp",
        "ports": [25, 465, 587],
        "keywords": ["smtp"],
        "recommendations": ["VRFY/EXPN testen", "Open-Relay prüfen", "Banner erfassen"],
        "tasks": ["VRFY/EXPN Benutzer-Enum testen", "Open-Relay prüfen"],
    },
    {
        "label": "dns",
        "ports": [53],
        "keywords": ["dns", "domain"],
        "recommendations": ["Zonentransfer (AXFR) testen", "Subdomain-Enum", "Records erfassen"],
        "tasks": ["Zonentransfer (AXFR) testen", "Subdomains enumerieren"],
    },
    {
        "label": "http",
        "ports": [80, 8000, 8080, 8081, 8888],
        "keywords": ["http"],
        "recommendations": ["WhatWeb", "Header prüfen", "Feroxbuster", "FFUF", "Nikto"],
        "tasks": [
            "Header analysieren",
            "Verzeichnisse enumerieren",
            "Login-Bereich prüfen",
            "Technologien identifizieren",
            "robots.txt / sitemap.xml prüfen",
            "Backup-/Config-Dateien suchen",
        ],
    },
    {
        "label": "https",
        "ports": [443, 8443],
        "keywords": ["https", "ssl/http"],
        "recommendations": ["WhatWeb", "TLS/Zertifikat prüfen (sslscan)", "Feroxbuster", "FFUF", "Nikto"],
        "tasks": [
            "Header analysieren",
            "TLS/Zertifikat prüfen",
            "Verzeichnisse enumerieren",
            "Technologien identifizieren",
        ],
    },
    {
        "label": "kerberos",
        "ports": [88],
        "keywords": ["kerberos"],
        "recommendations": ["kerbrute User-Enum", "AS-REP Roasting prüfen"],
        "tasks": ["Benutzer via kerbrute enumerieren", "AS-REP Roasting prüfen"],
    },
    {
        "label": "rpc",
        "ports": [111, 135],
        "keywords": ["rpcbind", "msrpc"],
        "recommendations": ["rpcinfo", "rpcclient", "Endpoint-Mapper abfragen"],
        "tasks": ["RPC-Endpoints erfassen", "rpcclient anonym testen"],
    },
    {
        "label": "smb",
        "ports": [139, 445],
        "keywords": ["smb", "microsoft-ds", "netbios-ssn"],
        "host_level": True,
        "recommendations": ["enum4linux-ng", "smbclient -L", "SMB Signing prüfen", "Benutzer sammeln"],
        "tasks": [
            "Shares prüfen",
            "Anonymous Access testen",
            "Benutzer enumerieren",
            "SMB Signing prüfen",
        ],
    },
    {
        "label": "snmp",
        "ports": [161],
        "keywords": ["snmp"],
        "recommendations": ["Community-Strings testen", "snmpwalk"],
        "tasks": ["Community-Strings bruteforcen", "snmpwalk auf System-Tree"],
    },
    {
        "label": "ldap",
        "ports": [389, 636, 3268, 3269],
        "keywords": ["ldap"],
        "recommendations": ["Naming Context abrufen", "Benutzer erfassen", "Gruppen erfassen"],
        "tasks": [
            "Naming Context abrufen",
            "Benutzer erfassen",
            "Gruppen erfassen",
            "Anonymous Bind testen",
        ],
    },
    {
        "label": "mssql",
        "ports": [1433],
        "keywords": ["ms-sql", "mssql"],
        "recommendations": ["Login testen", "xp_cmdshell prüfen", "Version erfassen"],
        "tasks": ["Schwache Credentials testen", "xp_cmdshell prüfen"],
    },
    {
        "label": "mysql",
        "ports": [3306],
        "keywords": ["mysql", "mariadb"],
        "recommendations": ["Login testen", "Version erfassen"],
        "tasks": ["Schwache Credentials testen", "Version/CVE prüfen"],
    },
    {
        "label": "rdp",
        "ports": [3389],
        "keywords": ["ms-wbt-server", "rdp"],
        "recommendations": ["NLA prüfen", "BlueKeep prüfen", "Login testen"],
        "tasks": ["NLA-Status prüfen", "Bekannte RDP-CVEs prüfen"],
    },
    {
        "label": "postgres",
        "ports": [5432],
        "keywords": ["postgresql", "postgres"],
        "recommendations": ["Login testen", "Version erfassen"],
        "tasks": ["Schwache Credentials testen", "Version/CVE prüfen"],
    },
    {
        "label": "winrm",
        "ports": [5985, 5986],
        "keywords": ["winrm", "wsman"],
        "recommendations": ["Login testen (evil-winrm)", "Auth-Methoden prüfen"],
        "tasks": ["Credentials gegen WinRM testen"],
    },
    {
        "label": "redis",
        "ports": [6379],
        "keywords": ["redis"],
        "recommendations": ["Unauth-Zugriff testen", "INFO/CONFIG dump"],
        "tasks": ["Unauthentifizierten Zugriff testen", "CONFIG/Keys prüfen"],
    },
    {
        "label": "mongodb",
        "ports": [27017],
        "keywords": ["mongod", "mongodb"],
        "recommendations": ["Unauth-Zugriff testen", "Datenbanken auflisten"],
        "tasks": ["Unauthentifizierten Zugriff testen"],
    },
    {
        "label": "telnet",
        "ports": [23],
        "keywords": ["telnet"],
        "recommendations": ["Banner erfassen", "Default-Credentials testen"],
        "tasks": ["Banner/Version erfassen", "Default-Credentials testen"],
    },
]

# Fallback, wenn keine Regel passt
GENERIC = {
    "label": "generic",
    "recommendations": ["Banner/Version erfassen", "Service identifizieren", "Bekannte CVEs prüfen"],
    "tasks": ["Banner/Version erfassen", "Bekannte CVEs prüfen"],
}


def _matches(rule: dict, svc: Service) -> bool:
    if svc.port in rule.get("ports", []):
        return True
    name = (svc.name or "").lower()
    return any(kw in name for kw in rule.get("keywords", []))


def rules_for(svc: Service) -> list[dict]:
    """Alle passenden Regeln für einen Service (kann mehrere sein)."""
    hits = [r for r in RULES if _matches(r, svc)]
    return hits if hits else [GENERIC]


def recommendations_for(svc: Service) -> list[str]:
    out: list[str] = []
    for r in rules_for(svc):
        for rec in r["recommendations"]:
            if rec not in out:
                out.append(rec)
    return out


def tasks_for(svc: Service) -> list[Task]:
    """Erzeugt (noch nicht persistierte) Task-Objekte für einen Service."""
    out: list[Task] = []
    seen: set[str] = set()
    for r in rules_for(svc):
        scope = "host" if r.get("host_level") else "service"
        for title in r["tasks"]:
            if title in seen:
                continue
            seen.add(title)
            out.append(
                Task(
                    title=title,
                    source=f"{r['label']} auto",
                    host_id=svc.host_id,
                    service_id=svc.id,
                    dedup_scope=scope,
                )
            )
    return out


# Empfohlene Runner-Tools je Service-Typ (Registry-Namen).
# Wird von `pentos recommend` für die Run-Shortcuts genutzt.
TOOLS_MAP: dict[str, list[str]] = {
    "ftp": ["hydra"],
    "ssh": ["hydra"],
    "dns": ["dig-axfr"],
    "http": ["whatweb", "feroxbuster", "gobuster", "ffuf", "nikto", "nuclei"],
    "https": ["whatweb", "feroxbuster", "gobuster", "ffuf", "nikto", "nuclei"],
    "smb": ["enum4linux-ng", "smbclient", "smbmap", "nxc-smb"],
    "snmp": ["snmpwalk"],
    "ldap": ["ldapsearch"],
    "winrm": ["nxc-winrm"],
    "telnet": ["hydra"],
}


def tools_for(svc: Service) -> list[str]:
    """Empfohlene Runner-Tools (Registry-Namen) für einen Service, dedupliziert."""
    out: list[str] = []
    for r in rules_for(svc):
        for tool in TOOLS_MAP.get(r["label"], []):
            if tool not in out:
                out.append(tool)
    return out


def is_web(svc: Service) -> bool:
    """True, wenn der Service als Web-Dienst gilt (für URL-Zielbildung)."""
    name = (svc.name or "").lower()
    return "http" in name or svc.port in (80, 443, 8000, 8080, 8081, 8443, 8888)


def target_url(svc: Service, addr: str) -> str:
    """Bildet die Ziel-URL für einen Web-Service (Schema + Port-Logik)."""
    is_https = (
        (svc.name or "").lower() == "https"
        or (svc.tunnel or "") == "ssl"
        or svc.port in (443, 8443)
    )
    scheme = "https" if is_https else "http"
    if svc.port in (80, 443):
        return f"{scheme}://{addr}"
    return f"{scheme}://{addr}:{svc.port}"


def run_shortcuts_for(svc: Service, addr: Optional[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Run-Shortcuts für einen Service.

    Liefert (ready, missing):
    - ready   = Liste aus (Tool-Name, fertiger `pentos run ...`-Befehl) für
                installierte Tools.
    - missing = Tool-Namen, die passen würden, aber nicht installiert sind.
    Es wird NICHTS ausgeführt - reine Vorschläge.
    """
    import shutil
    from .runners import registry as _registry

    ready: list[tuple[str, str]] = []
    missing: list[str] = []
    if not addr:
        return ready, missing
    web = is_web(svc)
    url = target_url(svc, addr)
    for tname in tools_for(svc):
        spec = _registry.get(tname)
        if not spec:
            continue
        tgt = url if (web and spec.category == "web") else addr
        if shutil.which(spec.binary):
            ready.append((tname, f"pentos run {tname} {tgt}"))
        else:
            missing.append(tname)
    return ready, missing


def project_shortcuts(
    services_with_addr: list[tuple[Service, Optional[str]]],
) -> tuple[list[str], list[str]]:
    """Projektweite Run-Shortcuts über alle Services, dedupliziert.

    Liefert (ready_cmds, missing_tools) - beide ohne Duplikate, Reihenfolge
    stabil. Gedacht für die Übersicht nach einem Import oder `pentos recommend`
    ohne Argument.
    """
    ready: list[str] = []
    missing: list[str] = []
    for svc, addr in services_with_addr:
        r, m = run_shortcuts_for(svc, addr)
        for _tool, cmd in r:
            if cmd not in ready:
                ready.append(cmd)
        for tool in m:
            if tool not in missing:
                missing.append(tool)
    return ready, missing

