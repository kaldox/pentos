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

## Als Nächstes

Konkret geplant, baut auf Bestehendem auf:

- **Strukturierte Web-Parser** (gobuster/ffuf/feroxbuster/nikto), damit deren
  Ausgabe automatisch zu Findings/Pfaden wird statt nur als Capture.
- **Detailansicht pro Host** im Dashboard, analog zur Finding-Detailansicht, mit
  Verlinkung zu Diensten, Findings und Notizen.
- **Status-Historie auch im HTML-/PDF-Report** (aktuell im Markdown-Report).

## Später

Größere Brocken, die einen frischen Kopf verdienen:

- **KI-Lernkarten und Notiz-Zusammenfassungen**, ausschließlich aus den eigenen
  Projektdaten, ohne Halluzination. Lernen aus dem, was man selbst gefunden hat.
- **Reicheres Screenshot-Handling**, etwa direkte Aufnahme oder Annotation statt
  nur Dateien anhängen.
- **Projekt-Export und -Import** als eine Datei, zum Sichern, Umziehen oder
  Teilen eines kompletten Workspace.
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
