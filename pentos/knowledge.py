"""
Kuratierte Wissensbasis für den Lern-Report (`pentos report --explain`).

WICHTIG: Diese Erklärungen sind handgeprüfter Inhalt — KEINE KI-Generierung.
Der Lern-Report stützt sich bewusst auf dieses Material, damit didaktische
Aussagen fachlich korrekt sind. Ein optionaler KI-Mentor darf diese Texte
ausformulieren/zusammenfassen, aber nie die fachliche Substanz erfinden.

Aufbau pro Tool:
  what  – Was macht das Tool? (1–2 Sätze)
  why   – Warum/an welcher Stelle der Methodik setzt man es ein?
  read  – Wie liest man das Ergebnis? Worauf achten?

Quelle der Methodik-Reihenfolge: gängige Pentest-Phasen
(Recon → Enumeration → Exploitation → Post-Exploitation).
"""
from __future__ import annotations

# ── Tool-Erklärungen ──────────────────────────────────────────────────────────
TOOL_KNOWLEDGE: dict[str, dict[str, str]] = {
    "nmap": {
        "what": "Portscanner, der offene TCP/UDP-Ports und – mit -sV – die dahinter laufenden Dienste samt Version erkennt.",
        "why": "Erster Schritt jeder Recon: die Angriffsfläche kartieren. Ohne zu wissen, welche Dienste laufen, gibt es nichts gezielt zu enumerieren.",
        "read": "Pro offenem Port stehen Dienst und Version. Versionsnummern sind der Ansatzpunkt für die Suche nach bekannten Schwachstellen; ungewöhnliche/alte Versionen zuerst prüfen.",
    },
    "rustscan": {
        "what": "Sehr schneller Port-Discovery-Scanner, der gefundene Ports anschließend an nmap übergeben kann.",
        "why": "Vorstufe zu nmap, wenn viele Hosts/Ports schnell gesichtet werden sollen.",
        "read": "Liefert primär die Liste offener Ports; die eigentliche Dienst-/Versionsanalyse macht danach nmap.",
    },
    "whatweb": {
        "what": "Erkennt Web-Technologien (Server, CMS, Frameworks, JS-Bibliotheken) einer Website.",
        "why": "Frühe Web-Enumeration: Die eingesetzte Technologie bestimmt, welche Angriffe und welche bekannten Schwachstellen relevant sind.",
        "read": "Achte auf CMS-Namen + Versionen (z.B. WordPress x.y) und veraltete Komponenten – das sind die Spuren für die weitere Suche.",
    },
    "feroxbuster": {
        "what": "Bruteforced Verzeichnisse und Dateien einer Website anhand einer Wortliste (Content Discovery).",
        "why": "Versteckte Pfade (Admin-Panels, Backups, APIs) sind selten verlinkt, aber oft erreichbar – sie erweitern die Angriffsfläche.",
        "read": "Status 200/301/302 sind interessant; 403 kann auf Existenz hinweisen. Gefundene Pfade einzeln prüfen.",
    },
    "gobuster": {
        "what": "Verzeichnis-/DNS-Bruteforcer, funktional ähnlich zu feroxbuster.",
        "why": "Content Discovery auf Webservern; Alternative je nach Vorliebe/Output-Format.",
        "read": "Wie feroxbuster: relevante Statuscodes und gefundene Pfade weiterverfolgen.",
    },
    "ffuf": {
        "what": "Schneller Web-Fuzzer; ersetzt das Schlüsselwort FUZZ in URL/Parametern durch Wortlisten-Einträge.",
        "why": "Flexibel für Verzeichnis-, Parameter- und vHost-Discovery.",
        "read": "Antwortgröße/Statuscode-Ausreißer markieren interessante Treffer; Standardrauschen herausfiltern.",
    },
    "nikto": {
        "what": "Webserver-Schwachstellenscanner für bekannte Fehlkonfigurationen und veraltete Software.",
        "why": "Schnelle erste Indikatoren für offensichtliche Web-Schwachstellen.",
        "read": "Liefert Hinweise (OSVDB/CVE-Bezüge); jeden Treffer manuell verifizieren, Fehlalarme sind möglich.",
    },
    "nuclei": {
        "what": "Template-basierter Schwachstellenscanner, der bekannte Muster (CVEs, Exposures, Misconfigs) prüft.",
        "why": "Breite, schnelle Abdeckung bekannter Schwachstellen über aktuelle Community-Templates.",
        "read": "Severity-Tags [info]/[low]/[medium]/[high]/[critical] beachten; High/Critical zuerst, Info ist meist nur Kontext.",
    },
    "enum4linux-ng": {
        "what": "Enumeriert SMB/RPC/LDAP eines Windows-/Samba-Systems: Domäne, Benutzer, Gruppen, Shares, Passwort-Policy.",
        "why": "Kernschritt der AD-/SMB-Enumeration. Ein Domänencontroller verrät hier oft die komplette Konto- und Gruppenstruktur.",
        "read": "Null-Session = anonymer Zugriff (Schwachstelle). Sichtbare Benutzerlisten und das Konto 'krbtgt' deuten auf AS-REP-/Kerberoasting-Fläche. 'SMB signing not required' = NTLM-Relay-Gefahr.",
    },
    "smbclient": {
        "what": "SMB-Client zum Auflisten und Zugreifen auf Netzwerkfreigaben.",
        "why": "Nach der Share-Enumeration: tatsächlich auf Freigaben zugreifen und Dateien sichten.",
        "read": "Anonym/gast-lesbare Shares mit sensiblen Dateien (Konfigs, Backups, Keys) sind direkte Funde.",
    },
    "smbmap": {
        "what": "Listet SMB-Freigaben samt Lese-/Schreibrechten auf.",
        "why": "Schneller Überblick, auf welche Shares mit welchen Rechten zugegriffen werden kann.",
        "read": "READ/WRITE-Rechte auf ungewöhnlichen Shares sind interessant; WRITE kann zu Code-Ausführung führen.",
    },
    "snmpwalk": {
        "what": "Fragt SNMP-Dienste ab (oft mit Standard-Community 'public').",
        "why": "SNMP verrät häufig System-, Prozess- und Benutzerinformationen.",
        "read": "Laufende Prozesse, installierte Software und Benutzernamen sind verwertbare Enumeration.",
    },
    "ldapsearch": {
        "what": "Fragt LDAP/Active-Directory-Verzeichnisse ab.",
        "why": "Direkter Zugriff auf AD-Objekte (Benutzer, Gruppen, Attribute) – auch anonym manchmal möglich.",
        "read": "Attribute wie 'description' enthalten gelegentlich Passwörter; 'servicePrincipalName' weist auf kerberoastbare Konten hin.",
    },
    "dig-axfr": {
        "what": "Versucht einen DNS-Zonentransfer (AXFR).",
        "why": "Ein erlaubter Zonentransfer gibt die komplette interne DNS-Struktur preis.",
        "read": "Erfolgreicher AXFR = Fehlkonfiguration; die gelisteten Hostnamen erweitern die Zielkarte.",
    },
    "subfinder": {
        "what": "Findet passiv Subdomains einer Domäne über öffentliche Quellen.",
        "why": "Externe Recon: mehr Subdomains = mehr Angriffsfläche.",
        "read": "Ungewöhnliche/vergessene Subdomains (dev, staging, vpn) sind oft die schwächsten Punkte.",
    },
    "nxc-smb": {
        "what": "NetExec über SMB: prüft Credentials gegen Hosts, listet Shares/Benutzer, erkennt Admin-Zugriff.",
        "why": "Validiert gefundene Zugangsdaten und zeigt, wo sie administrativen Zugriff geben.",
        "read": "'(Pwn3d!)' = administrativer Zugriff auf dem Host. 'signing:False' und 'Null Auth:True' sind eigenständige Schwachstellen.",
    },
    "nxc-winrm": {
        "what": "NetExec über WinRM: prüft Credentials für Remote-PowerShell-Zugriff.",
        "why": "WinRM-Zugriff mit gültigen Credentials bedeutet oft direkte Code-Ausführung.",
        "read": "'(Pwn3d!)' = ausführbarer Remote-Zugriff; Ansatzpunkt für Post-Exploitation.",
    },
    "hydra": {
        "what": "Online-Bruteforce/Password-Spraying gegen Netzwerkdienste (SSH, FTP, HTTP …).",
        "why": "Wenn nur ein Dienst, aber keine Credentials vorliegen, können schwache Passwörter den Einstieg liefern.",
        "read": "Eine 'login found'-Zeile liefert gültige Zugangsdaten – sofort als Loot sichern und Zugriff verifizieren.",
    },
    "medusa": {
        "what": "Paralleler Login-Bruteforcer, funktional ähnlich zu hydra.",
        "why": "Alternative für Online-Passwortangriffe je nach Dienst/Performance.",
        "read": "Erfolgreiche Logins erscheinen als Treffer-Zeile; Lockout-Policies beachten, um Konten nicht zu sperren.",
    },
    "kerbrute": {
        "what": "Enumeriert gültige AD-Benutzernamen über Kerberos und kann Passwort-Spraying durchführen.",
        "why": "Liefert valide Benutzernamen, ohne Logins auszulösen – Grundlage für gezieltes Spraying.",
        "read": "Als valide markierte Benutzer sind echte Konten; daraus Spraying-Listen bauen (mit Bedacht auf Lockout).",
    },
    "sqlmap": {
        "what": "Automatisiert das Auffinden und Ausnutzen von SQL-Injection.",
        "why": "SQL-Injection kann Datenbankinhalte, Credentials oder Code-Ausführung preisgeben.",
        "read": "Bestätigte Injection-Punkte und extrahierte Daten/Hashes sind direkte Funde; Hashes danach offline cracken.",
    },
    "searchsploit": {
        "what": "Durchsucht die lokale Exploit-DB nach bekannten Exploits für eine Software/Version.",
        "why": "Verbindet die in der Recon gefundenen Versionen mit verfügbaren Exploits.",
        "read": "Treffer auf die exakte Version sind am wertvollsten; Exploit-Code vor Einsatz prüfen.",
    },
    "john": {
        "what": "Offline-Passwortcracker für Hashes.",
        "why": "Gefundene Hashes (aus DBs, NTDS, Shares) zu Klartext-Passwörtern wandeln.",
        "read": "Geknackte Passwörter als Loot sichern; oft werden sie auf anderen Diensten wiederverwendet.",
    },
}

# ── Finding-Muster: didaktische Einordnung (Titel-Substring -> Erklärung) ──────
# Jede Erklärung: why (warum Problem), exploit (wie ausnutzbar), fix (Behebung).
FINDING_KNOWLEDGE: list[dict[str, str]] = [
    {
        "match": "null-session",
        "why": "Eine SMB-Null-Session erlaubt anonymen Zugriff (Benutzer und Passwort leer). Damit lassen sich oft Benutzer, Gruppen und Freigaben auslesen, ohne Zugangsdaten zu besitzen.",
        "exploit": "Ein Angreifer enumeriert anonym die Domäne (Benutzerlisten, Passwort-Policy) und nutzt das für gezieltes Password-Spraying.",
        "fix": "Anonyme/Null-Session-Zugriffe per Gruppenrichtlinie und Registry (RestrictAnonymous, RestrictAnonymousSAM) unterbinden.",
    },
    {
        "match": "signing nicht erzwungen",
        "why": "Wird SMB-Signing nicht erzwungen, lassen sich SMB-Sitzungen manipulieren.",
        "exploit": "NTLM-Relay: Ein Angreifer leitet abgefangene Authentifizierung an einen anderen Host weiter und erlangt dort Zugriff.",
        "fix": "SMB-Signing per GPO erzwingen ('Microsoft network server: Digitally sign communications (always)').",
    },
    {
        "match": "anonym lesbar",
        "why": "Eine ohne Authentifizierung les-/auflistbare Freigabe kann sensible Dateien (Konfigurationen, Backups, Schlüssel) offenlegen.",
        "exploit": "Der Angreifer durchsucht den Share direkt nach Zugangsdaten oder verwertbaren Informationen.",
        "fix": "Zugriffsrechte der Freigabe prüfen, anonymen Zugriff entfernen, Need-to-know-Prinzip anwenden.",
    },
    {
        "match": "domänen-enumeration",
        "why": "Ist die Konto- und Gruppenliste der Domäne auslesbar, kennt ein Angreifer alle Benutzer und privilegierten Gruppen. Das sichtbare Konto 'krbtgt' weist zudem auf Kerberos-Angriffsfläche hin.",
        "exploit": "Aus der Benutzerliste werden Spraying-Ziele; kerberoastbare Konten (mit SPN) erlauben das Offline-Cracken von Service-Passwörtern (Kerberoasting), AS-REP-fähige Konten den AS-REP-Roast.",
        "fix": "Anonyme/niedrigprivilegierte Enumeration einschränken; starke, lange Passwörter für Service-Konten; Tiering privilegierter Gruppen.",
    },
    {
        "match": "pwn3d",
        "why": "Administrativer Zugriff auf einem Host bedeutet vollständige Kontrolle über dieses System.",
        "exploit": "Code-Ausführung, Auslesen von Passwort-Hashes (SAM/LSASS), laterale Bewegung zu weiteren Hosts.",
        "fix": "Lokale Admin-Rechte minimieren (LAPS für eindeutige lokale Passwörter), Credential-Wiederverwendung verhindern, Tiering.",
    },
    {
        "match": "ftp-anon",
        "why": "Anonymer FTP-Zugriff erlaubt das Lesen (und teils Schreiben) von Dateien ohne Anmeldung.",
        "exploit": "Sensible Dateien herunterladen oder per Upload Schadcode platzieren.",
        "fix": "Anonymes FTP deaktivieren oder strikt auf einen isolierten, nicht-sensiblen Bereich beschränken.",
    },
    {
        "match": "telnet",
        "why": "Telnet überträgt Daten – inklusive Zugangsdaten – unverschlüsselt.",
        "exploit": "Mitlesen des Datenverkehrs (Sniffing) liefert Klartext-Credentials.",
        "fix": "Telnet abschalten und durch SSH ersetzen.",
    },
    {
        "match": "unverschlüsselt",
        "why": "Unverschlüsselte Dienste (z.B. HTTP) übertragen Daten im Klartext.",
        "exploit": "Man-in-the-Middle/Sniffing kann übertragene Daten und Sitzungen abgreifen.",
        "fix": "TLS erzwingen (HTTPS), unverschlüsselte Varianten deaktivieren oder umleiten.",
    },
]

# Methodik-Phase je Tool-Kategorie (für die Report-Gliederung)
PHASE_BY_CATEGORY: dict[str, str] = {
    "recon": "Reconnaissance",
    "web": "Enumeration (Web)",
    "smb": "Enumeration (SMB/AD)",
    "ldap": "Enumeration (LDAP/AD)",
    "snmp": "Enumeration (SNMP)",
    "dns": "Enumeration (DNS)",
    "vuln": "Schwachstellen-Scan",
    "bruteforce": "Credential-Angriffe",
    "exploit": "Exploitation",
    "cracking": "Offline-Cracking",
}


def tool_info(tool: str) -> dict[str, str] | None:
    """Erklärung zu einem Tool (oder None, wenn nicht in der Wissensbasis)."""
    return TOOL_KNOWLEDGE.get(tool)


def finding_info(title: str) -> dict[str, str] | None:
    """Didaktische Einordnung zu einem Finding anhand von Titel-Mustern."""
    low = (title or "").lower()
    for entry in FINDING_KNOWLEDGE:
        if entry["match"] in low:
            return entry
    return None


# ── Vorbefüllte Finding-Templates (abgeleitet aus FINDING_KNOWLEDGE) ───────────
# Severity/Kategorie/CVSS sind geprüfte Startwerte und im Projekt frei editierbar.
_TEMPLATE_META: dict[str, dict] = {
    "null-session": {
        "title": "SMB Null-Session erlaubt",
        "severity": "Medium", "category": "Misconfiguration",
        "cvss_score": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "signing nicht erzwungen": {
        "title": "SMB-Signing nicht erzwungen",
        "severity": "Medium", "category": "Misconfiguration",
        "cvss_score": 5.9, "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "anonym lesbar": {
        "title": "Anonym lesbarer SMB-Share",
        "severity": "Medium", "category": "Exposure",
        "cvss_score": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "domänen-enumeration": {
        "title": "Domänen-Enumeration möglich",
        "severity": "Medium", "category": "Information Disclosure",
        "cvss_score": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "pwn3d": {
        "title": "Administrativer Zugriff auf Host",
        "severity": "High", "category": "Credential",
        "cvss_score": 8.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    },
    "ftp-anon": {
        "title": "Anonymer FTP-Zugriff",
        "severity": "Medium", "category": "Misconfiguration",
        "cvss_score": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "telnet": {
        "title": "Telnet-Dienst (unverschlüsselt)",
        "severity": "Medium", "category": "Misconfiguration",
        "cvss_score": 5.9, "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "unverschlüsselt": {
        "title": "Unverschlüsselter Dienst",
        "severity": "Medium", "category": "Misconfiguration",
        "cvss_score": 5.9, "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
}


def builtin_templates() -> list:
    """Erzeugt FindingTemplate-Objekte aus der kuratierten Wissensbasis.

    Beschreibung = 'Warum Problem' + 'Wie ausnutzbar', Remediation = 'Wie beheben'.
    Import lokal, um Zirkularität (models <-> knowledge) zu vermeiden.
    """
    from .models import FindingCategory, FindingTemplate, Severity

    sev = {"Info": Severity.INFO, "Low": Severity.LOW, "Medium": Severity.MEDIUM,
           "High": Severity.HIGH, "Critical": Severity.CRITICAL}
    cat = {c.value: c for c in FindingCategory}

    out = []
    for entry in FINDING_KNOWLEDGE:
        meta = _TEMPLATE_META.get(entry["match"])
        if not meta:
            continue
        out.append(FindingTemplate(
            key=entry["match"],
            title=meta["title"],
            severity=sev[meta["severity"]],
            category=cat.get(meta["category"], FindingCategory.OTHER),
            description=f"{entry['why']}\n\nAusnutzbarkeit: {entry['exploit']}",
            remediation=entry["fix"],
            cvss_score=meta["cvss_score"],
            cvss_vector=meta["cvss_vector"],
            builtin=True,
        ))
    return out
