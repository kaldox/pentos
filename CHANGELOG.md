# Changelog

Alle nennenswerten Änderungen an PentOS werden hier festgehalten.

Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/),
die Versionierung an [Semantic Versioning](https://semver.org/lang/de/).

## [2.22.0] – 2026-06-27
### Hinzugefügt
- **Interaktives Web-Dashboard:** Finding-Status direkt im Browser ändern
  (Dropdown je Finding, optimistisches UI mit Speicher-Feedback) und Notizen
  über ein Formular anlegen.
- Schreib-Endpoints im Backend: `POST /api/project/{name}/finding/{id}/status`,
  `POST /api/project/{name}/notes`, sowie `GET /api/meta` (Status-Liste).
### Sicherheit
- **Origin-Prüfung** auf allen Schreibzugriffen: Fremde Websites können das
  lokale Dashboard nicht per Drive-By (CSRF/DNS-Rebinding) verändern.

## [2.21.0] – 2026-06-26
### Hinzugefügt
- **MCP-Server** (`pentos mcp`): Macht den Workspace für MCP-Clients wie
  Claude Code/Cursor abfragbar. Tools: `pentos_list_projects`, `pentos_summary`,
  `pentos_findings`, `pentos_hosts`, `pentos_loot`, `pentos_notes`,
  `pentos_knowledge`. Optionales Extra `[mcp]`.
### Geändert
- Alle MCP-Tools sind ausschliesslich **lesend/analysierend** – kein Tool führt
  Scans oder Angriffe aus (Kern-Leitplanke).

## [2.20.0] – 2026-06-26
### Hinzugefügt
- **Web-Dashboard** (`pentos serve`): lokales Lagebild im Browser mit
  Severity-Donut, Findings, Hosts/Diensten, Loot und Notizen. FastAPI-Backend +
  eigenständiges Frontend (offline, kein CDN). Optionales Extra `[web]`.
- Bindet standardmässig nur an `127.0.0.1` (keine offene Angriffsfläche).

## [2.19.0] – 2026-06-26
### Hinzugefügt
- **KI-Advisor:** `pentos ai analyze` (Scan/Log/Output deuten + nächste Schritte,
  auch per stdin) und `pentos ai next` (Vorschläge zum Projektstand).
- Advisor-Schalter (`ai config --advisor/--no-advisor`).
### Sicherheit
- Datenschutz-Nachfrage vor dem Senden an die KI; bei Cloud-Anbietern deutliche
  Warnung, dass Daten den Rechner verlassen (lokales Ollama bleibt privat).

## [2.18.0] – 2026-06-25
### Hinzugefügt
- **Evidence/Screenshots in Reports:** Einem Finding zugeordnete Belege werden
  in HTML (base64-inline), PDF (reportlab) und Markdown eingebettet.

## [2.17.0] – 2026-06-18
### Geändert
- **nuclei-Parser** neu geschrieben: nur Low+ werden Findings (sauberer Titel),
  Info-Treffer als eine Sammelnotiz statt vieler Rausch-Findings.
### Hinzugefügt
- `pentos note show <id>` (Notiz-Inhalt anzeigen).
- `--severity` als Alias für `--sev` bei `finding add`.

## [2.16.0] – 2026-06-18
### Hinzugefügt
- **Scanner-Import** (`pentos scan import-scanner`): Nessus, OpenVAS/Greenbone und
  Burp Suite (Auto-Erkennung oder `--format`), inkl. Host-/Finding-Dedup, CVSS
  und Remediation.

## [2.15.0] – 2026-06-17
### Hinzugefügt
- **Finding-Template-Bibliothek** (`pentos template ...`): wiederverwendbare
  Vorlagen mit CVSS und Remediation, vorbefüllt aus der Wissensbasis und
  erweiterbar; CVSS/Remediation erscheinen in Reports.

## [2.14.0] – 2026-06-16
### Hinzugefügt
- **HTML- und PDF-Reports** (`pentos report --html` / `--pdf`), Branding optional
  über die Konfiguration. PDF via optionalem Extra `[pdf]` (reportlab).

## [2.13.0] – 2026-06-16
### Hinzugefügt
- **Lern-Report** (`pentos report --explain`): didaktischer Report aus der
  kuratierten Wissensbasis (keine KI-Generierung).

## [2.12.0] – 2026-06-16
### Geändert
- **enum4linux-Parser** an echten Domänencontroller-Daten gehärtet
  (Gruppen-Zählung, Domain-SID, krbtgt/Kerberoast-Erkennung).

## [2.11.0 und früher] – 2026-06-09 bis 2026-06-16
### Hinzugefügt
- Grundgerüst: Pentest-Workspace pro Projekt, Journal, Aufgaben, Findings, Loot,
  Evidence, Wissensdatenbank.
- Empfehlungs-Engine und geführte Recon-/Enum-Kette (`sweep`).
- Opt-in Runner-Layer (Tool-Ausführung auf Wunsch, kein Shell-Eval, Scope-Guard).
- Methodik-/Playbook-Bibliothek (Web/AD/Linux-/Windows-PrivEsc).
- Attack-Path-Graph (Mermaid/DOT), Obsidian-Export.
- nmap-XML-Import, lokaler KI-Mentor (Ollama) mit Offline-Fallback, RAG über die
  eigenen Projektdaten.

[2.22.0]: https://github.com/kaldox/pentos/releases
[2.21.0]: https://github.com/kaldox/pentos/releases
[2.20.0]: https://github.com/kaldox/pentos/releases
[2.19.0]: https://github.com/kaldox/pentos/releases
[2.18.0]: https://github.com/kaldox/pentos/releases
