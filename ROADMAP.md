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

## Als Nächstes

Konkret geplant, baut auf Bestehendem auf:

- **Strukturierter nikto-Parser**, damit dessen Treffer ebenfalls automatisch
  zu Findings werden statt nur als Capture (Vorbild: der neue gobuster-/ffuf-/
  feroxbuster-Parser).
- **Status-Historie auch im HTML-/PDF-Report** (aktuell im Markdown-Report).
- **Command Palette (Strg+K) im Web-Dashboard**: globale Fuzzy-Suche über
  Hosts/Findings/Notizen plus Schnellaktionen (Status setzen, Notiz anlegen),
  wie bei Linear/Vercel/Raycast üblich. Passt zur bereits tastaturorientierten
  TUI – das wäre das Pendant fürs Web.
- **ProjectDiscovery-Parser** (`httpx`/`naabu`/`dnsx`): alle drei können nativ
  JSON ausgeben, das macht die Parser robuster als das gobuster-Textformat.
  `httpx` liefert Tech-Detection direkt mit, `naabu` ist eine sehr schnelle
  Port-Discovery, `dnsx` löst auf.
- **EPSS-Anreicherung für Findings**: Findings mit CVE/CVSS bekommen
  zusätzlich einen EPSS-Score (kostenlose FIRST-API) – CVSS sagt, wie schlimm
  eine Lücke wäre, EPSS sagt, wie wahrscheinlich sie in den nächsten 30 Tagen
  tatsächlich ausgenutzt wird. Wie bei Cloud-KI-Aufrufen mit explizitem
  Hinweis, dass dafür eine Anfrage nach aussen geht (opt-in).

## Später

Größere Brocken, die einen frischen Kopf verdienen:

- **KI-Lernkarten und Notiz-Zusammenfassungen**, ausschließlich aus den eigenen
  Projektdaten, ohne Halluzination. Lernen aus dem, was man selbst gefunden hat.
- **Reicheres Screenshot-Handling**, etwa automatisierte Screenshots über
  `gowitness` (Headless-Chrome-Screenshot-Tool, passt ins Runner/Parser-Muster)
  statt nur manuell angehängter Dateien.
- **gitleaks-Integration**: Secret-Scanning als eigene Findings-Quelle –
  thematischer Anschluss an den `.git`-Exposure-Detector aus 2.28.0: wird ein
  offenes `.git` gefunden, `gitleaks` gegen einen Dump vorschlagen und dessen
  Treffer zu Credential-/Info-Disclosure-Findings machen.
- **BloodHound-Datenimport**: SharpHound-/AzureHound-JSON einlesen und daraus
  Findings ("Kerberoastable Accounts", Domain-Admin-Anzahl, AS-REP-Roasting
  möglich) plus Link zur echten BloodHound-Ansicht bauen – PentOS wertet aus,
  statt BloodHound nachzubauen.
- **Engagement-Zeitplan/Timeline**: Der Workspace legt pro Projekt schon einen
  `timelines/`-Ordner an, der aber noch von keinem Feature genutzt wird –
  Rules-of-Engagement-Eckdaten (Zeitfenster, Blackout-Zeiten, Eskalationspfad)
  und Projekt-Meilensteine dort strukturiert festhalten.
- **Mehr strukturierte Parser** für weitere Tools, damit deren Ausgabe
  automatisch zu Hosts, Diensten und Findings wird.

## Bewusst nicht geplant

Das ist kein Versehen, sondern Absicht und Teil der Idee von PentOS:

- **Keine autonome Ausführung von Angriffen.** Die KI analysiert und schlägt
  vor; gestartet wird nur, was der Mensch selbst auslöst. Ein „Auto-Hack"-Modus
  kommt nicht.
- **Kein Cloud-Zwang.** PentOS bleibt lokal-first und lauffähig ohne externe
  Dienste; eine Cloud-Anbindung wird nie Voraussetzung.
- **Kein Ersatz für eigenes Verständnis.** Die Lern-Reports und der Advisor
  erklären, sie nehmen einem das Nachdenken nicht ab.

---

Eine Idee, die hier fehlt? Vorschläge gerne über die
[Issues](https://github.com/kaldox/pentos/issues).
