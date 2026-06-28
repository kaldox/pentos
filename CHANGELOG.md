# Changelog

Alle nennenswerten Änderungen an PentOS werden hier festgehalten.

Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/),
die Versionierung an [Semantic Versioning](https://semver.org/lang/de/).

> English version: [`CHANGELOG.en.md`](CHANGELOG.en.md)

## [2.27.0] – 2026-06-28
### Hinzugefügt
- **KI-Ausgabesprache:** wählbar (Deutsch, English, Español, Français, 中文, हिन्दी,
  العربية, Português, Русский, 日本語 oder Freitext). Beim ersten KI-Aufruf einmalige
  Abfrage, danach in der Config; pro Aufruf via `--lang` überschreibbar. Fachbegriffe,
  CVE-IDs sowie Tool-/Befehlsnamen bleiben optional im Original (`keep_terms`).
- **Automatische Modellwahl je Aufgabe** (`ai config --auto-model`): pro Task
  (analyze/next/explain/enum/ask/vision) wird das beste installierte Modell aus einer
  Präferenzliste gewählt. Explizite Zuordnung via `--model-for analyze=deepseek-r1:14b`.
- **Fallback-Kette:** schlägt ein Modell fehl oder fehlt, wird automatisch das nächste
  aus der Kandidatenliste versucht.
- **Persona / anpassbarer Prompt** (`ai config --persona "..."`), zusätzlich im
  Dashboard setzbar.
- **Streaming-Ausgabe** in der CLI (`--stream` bei analyze/next/ask) mit Live-Filter
  für `<think>`-Reasoning-Blöcke (deepseek-r1 & Co.).
- **Temperatur & Verbosity** konfigurierbar (`--temperature`, `--verbosity concise|normal|detailed`).
- **Vision:** `pentos ai analyze-image <bild>` wertet Screenshots mit einem
  Vision-Modell aus (z.B. qwen3-vl); `--vision-model` bzw. Auto-Wahl.
- **KI im Dashboard:** neuer Reiter „KI" mit „Frag dein Projekt" (RAG) und einem
  Einstellungs-Panel für Sprache, Verbosity, Temperatur, Auto-Modell und Persona.
- Neue API-Endpoints: `GET/POST /api/ai/config` und `POST /api/project/{name}/ai/ask`.

### Geändert
- Der gesamte KI-Chat-Pfad läuft jetzt zentral über eine Methode (Modellwahl,
  Sprache, Persona, Temperatur, Streaming, Vision an einer Stelle).

## [2.26.0] – 2026-06-28
### Hinzugefügt
- **Status-Historie / Retest-Tracking:** Jeder Statuswechsel eines Findings wird
  mit Zeitstempel und optionaler Notiz festgehalten (auch der Ersteintrag bei der
  Erstellung). Neuer Befehl `pentos finding history <id>` zeigt die Zeitleiste;
  `pentos finding status <id> <status> --note "..."` hält die Begründung fest. Der
  Status-Verlauf erscheint zusätzlich im Markdown-Report. Statuswechsel über TUI
  und Web-Dashboard fliessen automatisch in die Historie ein.
- **Dashboard-Detailansicht:** Klick auf einen Finding-Titel öffnet einen Drawer
  mit Beschreibung, Remediation, CVSS, Belegen und der vollen Status-Zeitleiste;
  Statuswechsel direkt dort inklusive Notiz-Feld.
- **Angriffspfad visuell:** Neuer Reiter „Angriffspfad" im Web-Dashboard rendert
  Hosts → Dienste → Findings als SVG-Graph (Findings in Severity-Farbe, anklickbar
  für die Detailansicht). Offline, ohne CDN.
- Neue API-Endpoints: `GET /api/project/{name}/finding/{id}` (Detail inkl.
  Historie und Belegen) und `GET /api/project/{name}/graph` (Graph-Daten). Der
  Status-Endpoint nimmt jetzt ein optionales `note`-Feld.

## [2.25.2] – 2026-06-28
### Geändert
- `template apply --host` akzeptiert jetzt sowohl die Host-ID als auch die
  Host-Adresse (vorher nur Adresse) - konsistent zu `finding add --host`, das die
  ID nimmt. Damit funktioniert `--host 1` wie `--host 10.10.10.5`.
### Hinzugefügt
- `--category` als Alias für `--cat` bei `note add` und `finding add`.

## [2.25.1] – 2026-06-28
### Geändert
- **Dokumentation internationalisiert:** Die englische Seite ist jetzt vollständig
  und eigenständig - README, CHANGELOG, ROADMAP und COMMANDS gibt es auf Englisch
  (`*.en.md`), aus der englischen README verlinkt. Die englische README wurde auf
  Feature-Parität zur deutschen gebracht (u.a. KI-Konfiguration und Installation
  aus dem Repo ergänzt).
### Entfernt
- Baseldütsch-README (`README.bl.md`) entfernt; PentOS wird ab jetzt auf Deutsch
  und Englisch gepflegt.
### Behoben
- `pentos graph mermaid` und `graph dot` stürzten bei der Ausgabe auf stdout ab,
  wenn Loot-/Knoten-Labels Klammern enthielten (die Mermaid-Form `[/"…"/]` wurde
  als Rich-Markup fehlinterpretiert). Die Ausgabe erfolgt jetzt ohne Markup.

## [2.25.0] – 2026-06-28
### Hinzugefügt
- **Terminal-UI (TUI):** `pentos tui` öffnet ein tastaturgesteuertes Lagebild
  des aktiven Projekts (Textual). Tabs für Übersicht, Hosts, Dienste, Findings,
  Tasks, Loot und Journal; Navigation per Pfeiltasten/Tab. Finding- und
  Task-Status lassen sich direkt per Taste `s` durchschalten (schreibt ins
  Projekt), `r` aktualisiert, `q` beendet. Reine Ansicht und Status-Pflege - es
  wird nichts ausgeführt. Neues Extra: `pip install -e ".[tui]"` (Textual).
### Geändert
- Die Datenschicht der TUI (`pentos/tui/data.py`) ist bewusst von der Oberfläche
  getrennt und ohne laufendes Terminal testbar.

## [2.24.0] – 2026-06-28
### Hinzugefügt
- **Scan-Diff:** `pentos scan diff <nmap.xml>` vergleicht einen frischen
  nmap-Scan mit dem aktuellen Projektstand und zeigt neue Hosts, neue Dienste,
  Versionswechsel und was im neuen Scan fehlt. Rein lesend - es wird nichts
  importiert oder verändert.
- **Loot-/Credential-Matching:** `pentos loot match [loot-id]` schlägt vor,
  gegen welche Dienste im Projekt sich ein gefundenes Passwort, ein Hash
  (Pass-the-Hash), ein SSH-Key oder ein API-Key/Cookie wiederverwenden lässt -
  inklusive fertiger Befehls-Kopiervorlagen und passendem Runner-Tool. Ohne
  Argument werden alle passenden Loot-Einträge ausgewertet. Reiner Vorschlag,
  keine Ausführung.
- **Projektweite Folge-Tool-Vorschläge:** `pentos recommend` ohne Service-ID
  zeigt jetzt eine projektweite Übersicht der ausführbaren Run-Shortcuts über
  alle Dienste. Dieselbe Übersicht erscheint zusätzlich automatisch am Ende von
  `scan import-nmap`, damit nach dem Import sofort klar ist, was als Nächstes
  läuft (nur installierte Tools = „bereit").
- **Shell-Completion:** `pentos --install-completion` bzw. `--show-completion`
  für Bash/Zsh/Fish.
### Behoben
- `pentos runs` öffnete das Repository versehentlich zweimal; der überflüssige
  Aufruf wurde entfernt.

## [2.23.0] – 2026-06-27
### Hinzugefügt
- **Live-Fortschritt beim Runner:** `pentos run` und `sweep` zeigen während ein
  Tool läuft einen mitlaufenden Timer (verstrichene Zeit plus verbleibende Zeit
  bis zum Timeout) sowie die letzten Ausgabe-Zeilen des Tools, statt still bis
  zum Ende zu blockieren. Die vollständige Ausgabe wird weiterhin erfasst und an
  die Parser übergeben. In nicht-interaktiven Umgebungen (Pipes, Tests) bleibt
  das schlichte Verhalten erhalten.

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
### Geändert
- CLI-Hilfe in Kategorien gruppiert (`pentos --help` zeigt Workspace,
  Recon & Import, Befunde & Doku, Reporting & Übersicht, KI & Integration).
- Dokumentation verschlankt: zentrale Befehls-Referenz (`COMMANDS.md`),
  READMEs auf den Kern-Ablauf gekürzt, Roadmap in `ROADMAP.md` ausgelagert.

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
