# Changelog

Alle nennenswerten Änderungen an PentOS werden hier festgehalten.

Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/),
die Versionierung an [Semantic Versioning](https://semver.org/lang/de/).

> English version: [`CHANGELOG.en.md`](CHANGELOG.en.md)

## [2.35.0] – 2026-08-16
### Hinzugefügt
- **Wordlists-Katalog (`pentos wordlists catalog`/`add`):** baut auf
  `wordlists setup` auf — statt nur den zwei festen Dateien jetzt ein
  kuratierter Katalog mit 12 weiteren SecLists-Listen über vier Kategorien
  (Usernames, Passwörter in mehreren Grössen, Verzeichnisse, Subdomains),
  einzeln per Namen durchsuchbar (`--category`/`--filter`) und ins Projekt
  ladbar. Alle URLs echte `raw.githubusercontent.com`-SecLists-Pfade.
- **gitleaks-Integration:** neuer Runner-Eintrag `gitleaks` für Secret-Scans
  gegen einen lokalen Git-Repo-Dump (`pentos run gitleaks <pfad>`,
  target = lokaler Pfad, kein Netzwerkziel). Thematischer Anschluss an den
  bestehenden `.git`-Exposure-Detector, dessen Finding-Text jetzt auf diesen
  Folgeschritt verweist. Schema verifiziert gegen den echten
  `report.Finding`-Struct im gitleaks/gitleaks-Repo. Treffer werden Findings
  (Tracking, mit maskierter Secret-Vorschau) und Loot (voller Wert, Typ per
  RuleID-Heuristik).

### Notiert (nicht umgesetzt)
- **AzureHound-Unterstützung recherchiert, aber zurückgestellt:** Schema ist
  deutlich grösser/komplexer als SharpHound (folgt dem vollen
  Microsoft-Graph-API-Objektmodell) und liess sich nicht mit derselben
  Sicherheit verifizieren wie die anderen Importer/Parser dieser Session.
  Details und bereits gesicherte Erkenntnisse in ROADMAP.md.

## [2.34.0] – 2026-08-16
### Hinzugefügt
- **testssl.sh-Parser:** Neuer Runner-Eintrag `testssl` (`testssl.sh
  --jsonfile {outfile} --quiet {target}`) plus strukturierter Parser für
  TLS/SSL-Findings (Protokolle, schwache Cipher, Zertifikatskette,
  Heartbleed/ROBOT/POODLE & Co.). Schema verifiziert gegen die offizielle
  `fileout_json_finding()`-Funktion im testssl/testssl.sh-Repo. Severity
  kommt direkt vom Tool, keine eigene Heuristik nötig.
- **ProjectDiscovery-Parser httpx/naabu/dnsx:** Drei neue Runner-Einträge für
  natives JSON statt Textformat. Reine Recon-/Enumeration-Tools (kein
  Schwachstellen-Scan) — Treffer landen wie bei subfinder als strukturierte
  Sammelnotiz je Ziel, nicht als Findings.
- **EPSS-Anreicherung (`pentos finding epss`):** Neues Modul `pentos/epss.py`
  extrahiert CVE-IDs aus Finding-Titel/-Beschreibung und fragt den
  Exploit-Prediction-Score bei der kostenlosen FIRST.org-API ab (gebatcht).
  Opt-in wie bei Cloud-KI-Aufrufen — fragt vor dem Senden explizit nach.
  Anzeige neben CVSS in `finding show` sowie in allen drei Reportformaten.
- **Proxychains-Unterstützung (`pentos run <tool> <ziel> --proxy "proxychains4
  -q"`):** stellt eine Proxy-Chain vor den Tool-Aufruf, für den Pivot-Fall
  nach einem Foothold ins interne Netz. Bewusst kein Tor-Support (siehe
  ROADMAP.md, „Bewusst nicht geplant").
- **Standard-Wordlists (`pentos wordlists setup`):** Generische
  Username-Liste (352 Einträge, reine Muster/Namen) wird direkt mit PentOS
  ausgeliefert. Passwort-Liste ist bewusst NICHT im Repo gebündelt (stammt
  aus einem echten Datenleck von 2009), sondern wird opt-in von der
  offiziellen SecLists-Quelle geladen (`rockyou-75.txt`, kuratierte
  75-Einträge-Kurzliste).
- **`ai next --act`:** Der Advisor formuliert schon länger konkrete `pentos
  run …`-Vorschläge im Antworttext — neu werden diese jetzt herausgefiltert,
  als Auswahl angezeigt und erst nach zwei expliziten Bestätigungen über
  denselben Runner-Pfad wie `pentos run` gestartet (inkl. Scope-Check). Ohne
  `--act` bleibt `ai next` reine Textausgabe wie bisher — verletzt das
  Prinzip „KI führt nie selbst aus" nicht, jeder Lauf bleibt eine bewusste
  menschliche Aktion.

### Behoben
- **`pentos recommend`: hydra/medusa-Shortcuts liefen ins Leere.** Beide
  wurden unter „Bereit (installiert)" mit einem blanken `pentos run hydra
  <ziel>` gelistet — ohne `-L`/`-P`/Protokoll-Modul tut das nichts
  Sinnvolles. Zeigt jetzt eine Befehlsvorlage mit `--args`, die auf die
  Pfade zeigt, die `pentos wordlists setup` anlegt.

## [2.33.0] – 2026-08-15
### Hinzugefügt
- **BloodHound-Angriffspfad im Dashboard-Graphen:** Der SharpHound-Import
  (`scan import-bloodhound`) landet jetzt zusätzlich zu Findings/Notiz auch
  strukturiert in der Projekt-DB (neue Tabelle `bloodhound_imports`) und wird
  im Web-Dashboard als eigener Graph-Abschnitt neben Hosts/Services/Findings
  gerendert: Domain → Domain Admins / kerberoastbare Accounts / AS-REP-roastbare
  Accounts / uneingeschränkte Delegation → betroffene Mitglieder. `GET
  /api/project/{name}/graph` liefert dafür ein zusätzliches `ad`-Feld
  (`null` ohne Import).
- **Risk-Score mit Chart:** Neues Modul `pentos/risk.py` berechnet einen
  transparenten, dokumentierten Risk-Score aus den aktuell offenen Findings
  (Gewichtung je Severity: Critical=10/High=6/Medium=3/Low=1/Info=0,
  aufsummiert; Geschlossen/False-Positive zählen bewusst nicht mit — reine
  Arithmetik über Projektdaten, kein KI-/Cloud-Aufruf). Erscheint jetzt in
  der Zusammenfassung aller drei Reportformate (Markdown-Zeile, HTML mit
  inline-SVG-Donut-Chart, PDF mit nativem reportlab-Pie-Chart) sowie oben im
  Web-Dashboard-Lagebild.
- **Engagement-Zeitplan (`pentos timeline add/list/rm`):** Meilensteine,
  Testzeitfenster und Blackout-Zeiten pro Projekt festhalten (Titel, Art,
  Start/Ende, Notiz — z. B. Eskalationskontakt). Erscheint als eigener
  Abschnitt in Markdown-, HTML- und PDF-Report, sofern Einträge vorhanden
  sind.

## [2.32.0] – 2026-08-15
### Hinzugefügt
- **Status-Historie auch im HTML-/PDF-Report:** Der Status-Verlauf eines
  Findings (Retest-Tracking, bisher nur im Markdown-Report) erscheint jetzt
  auch in `pentos report --html` und `--pdf` — jeder echte Statuswechsel mit
  Zeitstempel, altem/neuem Status und optionaler Notiz, direkt unter der
  Finding-Beschreibung. Der reine Ersteintrag beim Anlegen wird wie im
  Markdown-Report nicht extra ausgegeben; ohne Statuswechsel bleibt der
  Abschnitt ganz weg. Datensammlung einmalig in `export._collect()`
  (`history_by_finding`), von HTML und PDF gemeinsam genutzt. 3 neue Tests
  in `tests/test_status_history.py`.

## [2.31.1] – 2026-08-15
### Behoben
Systematischer Bug-Hunt über den gesamten Code (Multi-Agent-Review, 6
Finder-Durchläufe + eigene Nachverifikation gegen echten Code/Fixtures). Alle
zehn Funde mit Regressionstest abgesichert, 173/173 Tests grün.

- **[Kritisch] Zip-Slip beim Projekt-Import (`pentos/archive.py`):**
  `pentos project import <datei.zip>` ohne `--name` übernahm den Zielordner
  aus dem **ungeprüften** `project`-Feld im ZIP-Manifest. Ein präpariertes
  Archiv mit `"project": "../../../../fremder/pfad"` (oder einem absoluten
  Pfad) konnte damit die komplette Zip-Slip-Prüfung aushebeln und Dateien
  ausserhalb des Workspace schreiben — genau das Szenario „Export mit
  jemandem teilen" macht das ausnutzbar. Der Projektname wird jetzt validiert
  (keine Pfadtrenner, kein `..`, kein absoluter Pfad), zusätzlich wird der
  fertige Zielpfad noch einmal gegen `projects_dir()` geprüft.
- **KI-Cloud-Zustimmung fehlte bei zwei Befehlen:** `ai explain-finding` und
  `ai enum` sendeten Finding-/Service-Daten direkt an die KI, ohne die für
  alle anderen KI-Befehle geltende Rückfrage/Warnung vor dem Senden an einen
  Cloud-Anbieter (`_confirm_ai_send`). Beide Befehle laufen jetzt über
  dieselbe Zustimmungsabfrage wie `ai analyze`/`ai next`/`ai analyze-image`.
- **SMB-Share-Erkennung bei Backslash-escapten Namen (`ADMIN\$`, `IPC\$`):**
  Die Share-Header-Regex im enum4linux-ng-Parser kannte keinen Backslash, wie
  ihn echte enum4linux-ng-Ausgabe für Default-Shares schreibt. Dadurch blieb
  der Share-„Typ" immer bei `?`, und der Ausschluss von `IPC$` aus dem
  „anonym lesbarer Share"-Finding griff nie (False-Positive-Finding für den
  völlig normalen IPC$-Null-Session-Zugriff). Namen werden jetzt normalisiert.
- **Offene SQLite-Transaktion nach Dubletten-Insert:** `add_host()`/
  `add_service()` fingen `IntegrityError` bei Dubletten ab, riefen aber nie
  `rollback()` auf — die Transaktion blieb offen und konnte eine zweite,
  gleichzeitig laufende Verbindung (z.B. `pentos serve`/TUI neben einem
  `scan import-nmap`) mit „database is locked" blockieren.
- **`pentos scan import-bloodhound` stürzte bei fremden JSON-Dateien ab:**
  Eine `*.json`-Datei mit Top-Level-Array/Skalar im Export-Ordner liess den
  Import mit `AttributeError` abstürzen statt sie zu überspringen, wie es die
  eigene Modul-Doku verspricht.
- **`pentos finding add --host/--service` mit ungültiger ID:** stürzte mit
  einem rohen `sqlite3.IntegrityError`-Traceback ab (Foreign-Key-Verletzung)
  statt einer sauberen Fehlermeldung; die DB-Verbindung wurde dabei nicht
  geschlossen. Wird jetzt vorab geprüft, analog zu `template apply --host`.
- **`pentos report --html --out <pfad>` ignorierte den Pfad stillschweigend**,
  wenn die Endung nicht exakt `.html` war, und schrieb stattdessen nach
  `reports/report.html` — ohne jede Warnung. `--out` wird jetzt wie bei
  `--pdf` immer respektiert.
- **CVSS-Score 0.0 beim Nessus-Import:** `cvss = v3 or v2` behandelte einen
  gültigen CVSSv3-Score von `0.0` als falsy und ersetzte ihn fälschlich durch
  den (höheren) CVSSv2-Score.
- **Command Palette (Strg+K) verlor kurze Subtitle-Treffer:** der additive
  Abschlag für Subtitle-Treffer (`- 2`) konnte einen echten, aber kurzen
  Treffer (z.B. Suche nach `w` bei Subtitle „Ansicht wechseln") unter 0
  drücken und aus der Trefferliste werfen. Jetzt ein multiplikativer Abschlag
  (`× 0.5`), der einen positiven Score nie negativ macht.

## [2.31.0] – 2026-08-15
### Hinzugefügt
- **BloodHound-Datenimport** (`pentos scan import-bloodhound <export>`,
  BloodHound CE / on-prem AD): liest einen SharpHound-Export (ZIP-Archiv,
  wie SharpHound es erzeugt, oder ein bereits entpackter Ordner) und leitet
  daraus Findings ab — Kerberoastable Accounts (SPN gesetzt), AS-REP-
  roastbare Accounts (Kerberos-Preauth deaktiviert), uneingeschränkte
  Delegation (Nutzer und Computer) sowie Domain-Admin-Mitgliedschaft
  (erkannt über die well-known RID `-512`, unabhängig von Domänenname/
  Sprache). `--host` verknüpft Findings/Notiz optional mit einem Host (z.B.
  dem Domain Controller). PentOS baut damit **keinen Graphen nach** — das
  bleibt BloodHounds Job; für die volle Angriffspfad-Analyse wird auf die
  echte BloodHound-Oberfläche verwiesen. Neues Modul
  `pentos/importers/bloodhound.py`. Schema (data/meta-Wrapper je Datei,
  lowercase-Properties wie `hasspn`/`dontreqpreauth`/`enabled`,
  `Members`-Array je Gruppe) gegen die offizielle SharpHound-Dokumentation
  und mehrere unabhängige Quellen verifiziert, nicht geraten. Nur SharpHound
  (on-prem AD) wird unterstützt — AzureHound (Entra ID) hat ein anderes
  Schema und ist als offener Roadmap-Punkt vermerkt. 16 neue Tests
  (`tests/test_bloodhound_importer.py`, `tests/test_cli_bloodhound.py`) mit
  handgebauter, aber schema-treuer Fixture unter `tests/fixtures/sharphound/`.

## [2.30.0] – 2026-08-15
### Hinzugefügt
- **Strukturierter nikto-Parser:** `nikto` läuft jetzt mit `-o {outfile}
  -Format xml` statt reinem Capture. Der neue Parser (`_parse_nikto` in
  `pentos/runners/parsers.py`) liest die `<item>`-Elemente des XML-Reports
  (Schema aus dem offiziellen `nikto_report_xml.plugin`, robust gegen
  beliebige Verschachtelungstiefe via `root.iter()` sowie gegen bekannte
  nikto-XML-Eigenheiten bei fehlerhaften Dokumenten). Häufiges
  Header-Rauschen (fehlende `X-Frame-Options`, `X-Content-Type-Options`
  usw.) wird gesammelt als eine Notiz abgelegt statt Findings zu spammen —
  wie beim nuclei-Parser. Alles andere wird ein Finding mit heuristisch
  abgeleiteter Severity (nikto liefert selbst kein CVSS): CVE-Referenzen,
  SQLi/XSS/Command-Injection & Co. → High, RCE-Hinweise → Critical,
  veraltete Software/Directory-Listing/phpinfo/Backup-Dateien → Medium,
  Rest → Low. Neue Test-Fixture `tests/fixtures/nikto_scan.xml` (nach dem
  bestätigten nikto-XML-Schema nachgebaut) und `tests/test_nikto_parser.py`
  (6 Tests: Parsing, Rausch-Filter, Severity-Heuristik, Pfad/Referenzen in
  der Beschreibung, keine Duplikate bei erneutem Lauf).

## [2.29.0] – 2026-08-14
### Hinzugefügt
- **Projekt-Export/-Import:** `pentos project export [name]` packt den
  kompletten Workspace (Datenbank + alle Unterordner: scans/, screenshots/,
  evidence/, notes/, loot/, findings/, reports/, ...) als eine einzelne
  ZIP-Datei — zum Sichern, Umziehen auf einen anderen Rechner oder Teilen
  eines Projekts. `pentos project import <datei.zip>` spielt eine solche
  Datei wieder als (neues) Projekt ein, mit `--name` für einen abweichenden
  Zielnamen und `--force` zum Überschreiben eines gleichnamigen Projekts;
  `--no-activate` verhindert das automatische Aktivsetzen nach dem Import.
  Neues Modul `pentos/archive.py`: Export schreibt zunächst in eine temporäre
  Datei (verhindert, dass ein Zielpfad innerhalb des Projektordners sich
  selbst mit einpackt), Import prüft vor jeder Extraktion auf Zip-Slip
  (Pfade, die aus dem Zielordner ausbrechen) und lehnt Archive ohne
  `database/pentos.db` als ungültig ab. Hinweis: Evidence-Dateien ausserhalb
  des Projektordners werden nicht mitverpackt. 14 neue Tests in
  `tests/test_archive.py` (Modul- und CLI-Ebene).
- **Command Palette (Strg+K) im Web-Dashboard:** globale Fuzzy-Suche über
  Hosts, Findings und Notizen des aktiven Projekts plus Schnellaktionen
  (aktuell „Neue Notiz anlegen"), wie bei Linear/Vercel/Raycast üblich —
  Pendant zur bereits tastaturorientierten TUI. Öffnen per `Strg+K`/`Cmd+K`
  oder Klick auf den neuen „Springe zu …"-Button in der Topbar; Navigation
  mit Pfeiltasten, Auswahl mit Enter, Schliessen mit Escape oder Klick
  ausserhalb. Ergebnisse aus Ansichten (Lagebild/Findings/Hosts/…), Findings
  (springt in die Finding-Detailansicht), Hosts (springt in die
  Host-Detailansicht) und Notizen; Daten werden bei jedem Öffnen frisch
  geladen. Reines Frontend (`pentos/web/static/{index.html,app.js,style.css}`),
  keine neuen Backend-Endpoints — nutzt die bestehenden `findings`/`hosts`/
  `notes`-Routen. Funktional gegen einen echten Browser verifiziert (Fuzzy-
  Suche über alle Eintragstypen, Tastaturnavigation, alle drei Öffnen-/
  Schliessen-Wege, keine Konsolenfehler); da es im Projekt keinen
  JS-Testrunner gibt, prüft der neue Test
  `test_command_palette_markup_and_wiring_served` zumindest, dass Markup und
  Kernfunktionen ausgeliefert werden.

## [2.28.1] – 2026-08-14
### Behoben
- **Absturz auf nicht-UTF-8-Windows-Konsolen:** `pentos project list`
  markierte das aktive Projekt mit „●" (U+25CF). Lief stdout in einer
  nicht-UTF-8-Codepage (z. B. cp1252, der Windows-Standard – oder wenn
  `pentos`/`python -m pentos` als Subprozess ohne `PYTHONUTF8=1`/
  `PYTHONIOENCODING=utf-8` läuft), schrieb Rich das Zeichen roh in den
  Stream und ein `UnicodeEncodeError` liess den Befehl abstürzen statt die
  Tabelle zu zeigen. Alle Unicode-only-Marker in `pentos/cli/app.py`
  (●/→/▶/✓/✗/⚠/█/░ sowie drei Emoji-Icons in der Playbook-Legende) sowie die
  analogen Stellen in `pentos/runners/base.py` (Live-Spinner, ⏱, ✓) und
  `pentos/tui/app.py` (●, ⚠, →, █/░) durch ASCII-Ersatzzeichen ersetzt (`*`,
  `->`, `>>`, `x`, `!`, `#`/`-`, …). Neuer Test `tests/test_cli_encoding.py`:
  reproduziert die cp1252-Konsole gezielt (schlug vor dem Fix mit demselben
  `UnicodeEncodeError` fehl wie im Bugreport) und ein statischer Wächter
  gegen künftige Nicht-ASCII-Marker in den drei Dateien.

## [2.28.0] – 2026-08-14
### Hinzugefügt
- **Strukturierter Web-Pfad-Parser** (`gobuster`/`ffuf`/`feroxbuster`): Treffer
  wurden bisher nur als Rohnotiz abgelegt. Jetzt erkennt PentOS
  sicherheitsrelevante Pfade – exponierte `.git`/`.svn`/`.hg`-Verzeichnisse,
  `.env`/`.htpasswd`/private SSH-Schlüssel, Backup-/Altdateien
  (`.sql`/`.bak`/`.zip`/…), `web.config` sowie Admin-/DB-Verwaltungsinterfaces
  (phpMyAdmin, Adminer, wp-admin, …) – und legt dafür automatisch Findings mit
  passender Severity/Kategorie an (nur bei erreichbaren Status-Codes
  200/204/301/302/401/403; Duplikate werden übersprungen). Vorbild: die
  bestehenden nuclei-/enum4linux-ng-Parser. Neuer Test
  `tests/test_gobuster_parser.py`.
- **Host-Detailansicht im Web-Dashboard:** Klick auf eine Host-Adresse in
  „Hosts & Dienste" öffnet einen Drawer (analog zur bestehenden
  Finding-Detailansicht) mit allen Diensten, verknüpften Findings (direkt am
  Host sowie über dessen Dienste), Notizen und Loot des Hosts. Neuer
  API-Endpoint `GET /api/project/{name}/host/{hid}` in
  `pentos/web/server.py`; Findings innerhalb des Drawers sind wiederum
  anklickbar und öffnen die volle Finding-Detailansicht. Drei neue Tests in
  `tests/test_web_dashboard.py`.

## [2.27.2] – 2026-08-14
### Behoben
- **MCP-Server mit aktuellem SDK:** `mcp.server.fastmcp.FastMCP` wurde im
  MCP-SDK 2.0 entfernt; da `pyproject.toml` `mcp>=1.0` erlaubte, wurde 2.x
  installiert und `pentos mcp` brach mit „MCP-SDK fehlt" ab. Abhängigkeit auf
  `mcp>=1.0,<2.0` eingegrenzt, bis auf die 2.x-API migriert ist.
### Hinzugefügt
- **CI-Workflow** (`.github/workflows/ci.yml`): Matrix-Build gegen Python 3.10,
  3.11 und 3.12 mit `compileall` (Syntax-Guard) und `pytest`.

## [2.27.1] – 2026-07-13
### Behoben
- **Report-Export unter Python 3.10/3.11:** Ein verschachtelter f-string mit
  maskierten Anführungszeichen in `export.py` ist erst ab Python 3.12 gültig
  und führte auf 3.10/3.11 zu einem `SyntaxError` – das gesamte `export`-Modul
  ließ sich nicht importieren (HTML-/PDF-Report defekt). Der Ausdruck wird nun
  vorab in einer Variablen aufgebaut; damit ist der Export wieder mit der in
  `pyproject.toml` deklarierten Mindestversion (3.10) lauffähig.

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
