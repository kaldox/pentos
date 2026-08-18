# Roadmap

Diese Roadmap zeigt, wohin PentOS sich entwickelt. Sie ist bewusst ehrlich:
Was erledigt ist, steht im [Changelog](CHANGELOG.md); hier geht es um das, was
noch kommt. Reihenfolge und Umfang können sich ändern. PentOS ist ein
Hobby-Projekt, kein Produkt mit Liefertermin.

> English version: [`ROADMAP.en.md`](ROADMAP.en.md)

## Kürzlich umgesetzt

Zur Einordnung, was zuletzt dazugekommen ist (Details im Changelog):

- Scanner-Import (Nessus / OpenVAS / Burp) mit Dedup, CVSS und Remediation
- Evidence und Screenshots direkt in den Reports (HTML, PDF, Markdown)
- KI-Advisor: Scans und Logs deuten, nächste Schritte vorschlagen
- Web-Dashboard mit lokalem Lagebild (`pentos serve`)
- Interaktives Dashboard: Finding-Status ändern und Notizen anlegen im Browser
- MCP-Server: den Workspace aus Claude Code oder Cursor abfragen (nur lesend)
- Scan-Diff: einen nmap-Scan gegen den Projektstand vergleichen (`scan diff`)
- Loot-/Credential-Matching: Loot gegen passende Dienste vorschlagen (`loot match`)
- Projektweite Folge-Tool-Vorschläge nach Import und via `recommend` ohne Argument
- Terminal-UI (`pentos tui`): tastaturgesteuertes Lagebild mit Status-Pflege
- Status-Historie / Retest-Tracking für Findings (`finding history`, `--note`)
- Dashboard-Detailansicht pro Finding mit Status-Zeitleiste
- Attack-Path-Graph visuell im Web-Dashboard (Reiter „Angriffspfad")
- KI-Ausbau: Ausgabesprache, Auto-Modellwahl/Fallback, Persona, Streaming, Temperatur/Verbosity, Vision (analyze-image) und KI-Panel im Dashboard
- Strukturierte Web-Parser für gobuster/ffuf/feroxbuster: sicherheitsrelevante
  Pfade (VCS-Verzeichnisse, Secrets, Backups, Admin-Interfaces) werden
  automatisch zu Findings statt nur als Rohnotiz abgelegt
- Host-Detailansicht im Dashboard (Drawer mit Diensten, Findings, Notizen, Loot)
- Projekt-Export/-Import (`project export`/`project import`): kompletter
  Workspace als eine ZIP-Datei, zum Sichern, Umziehen oder Teilen
- Command Palette (Strg+K) im Web-Dashboard: globale Fuzzy-Suche über
  Hosts/Findings/Notizen plus Schnellaktionen
- Strukturierter nikto-Parser (XML-Report): sicherheitsrelevante Treffer
  werden automatisch zu Findings mit heuristischer Severity, Header-Rauschen
  landet gesammelt als Notiz statt Findings zu spammen
- BloodHound-Datenimport (`scan import-bloodhound`): SharpHound-Export (ZIP
  oder Ordner) einlesen, daraus Findings für Kerberoastable/AS-REP-roastbare
  Accounts, uneingeschränkte Delegation und Domain-Admin-Mitgliedschaft bauen
- Status-Historie auch im HTML-/PDF-Report (bisher nur im Markdown-Report)
- BloodHound-Angriffspfad im Dashboard-Graphen: Domain Admins, kerberoastbare
  und AS-REP-roastbare Accounts sowie uneingeschränkte Delegation als eigener
  Graph-Abschnitt neben Hosts/Services/Findings
- Risk-Score mit transparenter Formel (Severity-gewichtete Summe, geschlossene
  Findings zählen nicht mit) plus Chart in Dashboard, Markdown-, HTML- und
  PDF-Report
- Engagement-Zeitplan (`pentos timeline add/list/rm`): Meilensteine,
  Testzeitfenster und Blackout-Zeiten pro Projekt festhalten, erscheint in
  allen drei Report-Formaten
- **testssl.sh-Parser**: strukturierter TLS/SSL-Check (Protokolle, schwache
  Cipher, Zertifikatskette, Heartbleed/ROBOT/POODLE & Co.) direkt aus dem
  nativen JSON-Report - Severity kommt vom Tool selbst, keine eigene Heuristik
  nötig
- **ProjectDiscovery-Parser** (`httpx`/`naabu`/`dnsx`): natives JSON statt
  Textformat, `httpx` inkl. Tech-Detection - landen als strukturierte
  Recon-Notiz (kein Schwachstellen-Scan, also keine Findings)
- **EPSS-Anreicherung für Findings** (`finding epss`): CVE-Referenzen aus
  Titel/Beschreibung werden bei der FIRST-API abgefragt - CVSS sagt, wie
  schlimm eine Lücke wäre, EPSS sagt, wie wahrscheinlich sie in den nächsten
  30 Tagen tatsächlich ausgenutzt wird. Opt-in wie bei Cloud-KI-Aufrufen.
- **Proxychains-Unterstützung im Runner** (`pentos run <tool> <ziel> --proxy
  "proxychains4 -q"`): für den echten Pivot-Fall nach einem Foothold ins
  interne Netz - bewusst kein Tor-/Anonymisierungs-Support, siehe „Bewusst
  nicht geplant"
- **Standard-Wordlists** (`pentos wordlists setup`): generische Username-Liste
  direkt mitgeliefert, Passwort-Kurzliste (SecLists `rockyou-75.txt`) opt-in
  von der offiziellen Quelle geladen statt im Repo gebündelt - `hydra`/
  `medusa`-Vorschläge in `recommend` zeigen jetzt auf diese Pfade
- **KI schlägt vor, du bestätigst** (`ai next --act`): die Advisor-Antwort
  wird nach ausführbaren `pentos run …`-Vorschlägen durchsucht, die du
  auswählst und einzeln bestätigst - beschleunigt die manuelle Arbeit, ohne
  dass die KI selbst etwas startet
- **Wordlists-Katalog** (`pentos wordlists catalog`/`add`): kuratierter
  Katalog mit 12 weiteren SecLists-Listen über vier Kategorien (Usernames,
  Passwörter in mehreren Grössen, Verzeichnisse, Subdomains), einzeln per
  Namen durchsuchbar und ins Projekt ladbar
- **gitleaks-Integration**: Secret-Scan gegen einen lokalen Repo-Dump
  (`pentos run gitleaks <pfad>`), thematischer Anschluss an den
  `.git`-Exposure-Detector - Treffer werden Findings (mit maskierter
  Secret-Vorschau) und Loot (mit vollem Wert)
- **MITRE-ATT&CK-Mapping** (`pentos finding attack <id> <technique>`):
  optionales Technique-Tag pro Finding, rein manuell/kuratiert (PentOS prüft
  nur das ID-Format, nicht gegen die echte Matrix - kein Drift-Risiko bei
  ATT&CK-Revisionen). Export als offizielles Navigator-Layer-JSON
  (`report --attack-navigator`), direkt in der echten ATT&CK-Navigator-
  Anwendung ladbar.
- **Engagement-Policy für Bug-Bounty-Programme** (`pentos policy setup`):
  Programm-Regeln pro Projekt festlegen (Brute-Force/aktive Exploitation/
  Offline-Cracking/automatisierte Tools erlaubt?) - durchsetzbare Antworten
  sperren die passende Runner-Kategorie in `run`/`sweep --run` (Override wie
  beim Scope-Guard via `--force`), nicht durchsetzbare (DoS-Tests, Social
  Engineering, Produktiv-only, Rate-Limits) landen als Beleg im Report.
  Gedächtnisstütze/Selbstschutz, keine Compliance-Garantie.
- **Vereinfachte Brute-Force-Wordlists** (`pentos run --userlist/--passlist/
  --proto`): tool-übergreifende Kurzform für hydra/medusa/nxc-smb/nxc-winrm
  statt händisch zusammengebautem `--args`, mit automatischem Rückgriff auf
  die Projekt-Wordlists und klarer Fehlermeldung, wenn die fehlen - behebt
  einen aus echtem Praxistest bekannten kaputten `recommend`-Vorschlag
  (hartkodierter relativer Pfad).

## Als Nächstes

Aktuell nichts konkret Neues eingeplant - die Punkte hier waren zuletzt alle
in „Kürzlich umgesetzt" gelandet. Vorschläge gerne über die
[Issues](https://github.com/kaldox/pentos/issues).

## Später

Größere Brocken, die einen frischen Kopf verdienen:

- **KI-Lernkarten und Notiz-Zusammenfassungen**, ausschließlich aus den eigenen
  Projektdaten, ohne Halluzination. Lernen aus dem, was man selbst gefunden hat.
- **Reicheres Screenshot-Handling**, etwa automatisierte Screenshots über
  `gowitness` (Headless-Chrome-Screenshot-Tool, passt ins Runner/Parser-Muster)
  statt nur manuell angehängter Dateien.
- **AzureHound-Unterstützung** für den BloodHound-Import (Entra ID hat ein
  anderes Schema als SharpHound, bisher nicht abgedeckt). Rechercheversuch
  am 2026-08-16: Schema deutlich grösser/komplexer als SharpHound (folgt
  dem vollen Microsoft-Graph-API-Objektmodell, ein einzelner User-Knoten
  hat 60+ Felder), offizielle Doku enthält kein konkretes Beispiel-JSON.
  Bestätigt bisher nur: `IngestRequest{Meta{Type,Version,Count}, Data}`-
  Wrapper existiert, Global-Admin-Erkennung läuft über eine `roleTemplateId`.
  Für eine saubere Umsetzung braucht es entweder echten Testtenant-Zugriff
  oder ein veröffentlichtes Beispiel-Export zum Gegenprüfen - bewusst nicht
  auf Verdacht gebaut, um den „Schema verifiziert, nicht geraten"-Standard
  der anderen Importer/Parser nicht zu brechen.
- **Mehr strukturierte Parser** für weitere Tools, damit deren Ausgabe
  automatisch zu Hosts, Diensten und Findings wird.

## Bewusst nicht geplant

Das ist kein Versehen, sondern Absicht und Teil der Idee von PentOS:

- **Keine autonome Ausführung von Angriffen.** Die KI analysiert und schlägt
  vor; gestartet wird nur, was der Mensch selbst auslöst. `ai next --act`
  bleibt dabei: es zeigt Vorschläge, ausgeführt wird erst nach expliziter
  Bestätigung pro Schritt. Ein echter „Auto-Hack"-Modus (Ketten ohne
  Bestätigung) kommt nicht.
- **Kein Tor-/Anonymisierungs-Support gegenüber dem Ziel.** Proxychains wird
  unterstützt, aber nur für den legitimen Pivot-Fall (SOCKS durch einen
  Foothold ins interne Netz). Traffic gegenüber einem autorisierten Testziel
  bewusst zu anonymisieren, widerspricht der Nachvollziehbarkeit, die eine
  Rules-of-Engagement eigentlich sicherstellen soll - und ist für echtes
  Scanning technisch ohnehin ungeeignet (Latenz, geblockte Exit-Nodes).
- **Kein Cloud-Zwang.** PentOS bleibt lokal-first und lauffähig ohne externe
  Dienste; eine Cloud-Anbindung wird nie Voraussetzung.
- **Kein Ersatz für eigenes Verständnis.** Die Lern-Reports und der Advisor
  erklären, sie nehmen einem das Nachdenken nicht ab.

---

Eine Idee, die hier fehlt? Vorschläge gerne über die
[Issues](https://github.com/kaldox/pentos/issues).
