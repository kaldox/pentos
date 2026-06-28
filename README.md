# PentOS

**🇩🇪 Deutsch** · [🇬🇧 English](README.en.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Version](https://img.shields.io/badge/version-2.26.0-informational)

**Knowledge-Driven Offensive Security Workspace**

PentOS ist **keine Scanner-Sammlung**, sondern ein vollständiges Pentest-*Workspace*-System:
Erkenntnisse, Angriffspfade, Notizen, Beweise, Wissen und Dokumentation stehen im
Mittelpunkt. Lokal-first, kein Cloud-Zwang, deutschsprachige Ausgabe. Die KI ist reiner
Lern- und Analyseassistent. **Sie führt niemals selbst Angriffe oder Befehle aus.**

> Gedacht für autorisiertes Testing: CTF, TryHackMe und freigegebene Engagements.

---

## Was PentOS kann

| Funktion | Status |
|---|---|
| Pentest-Workspace (vollständige Ordnerstruktur pro Projekt) | ✅ |
| Automatische Notizen (z.B. `notes/nmap.md` beim Import) | ✅ |
| Pentest-Journal (jede Aktion mit Zeitstempel) | ✅ |
| Aufgabensystem (auto-generiert je Service, Offen/In Bearbeitung/Erledigt) | ✅ |
| Intelligente nächste Schritte (Empfehlungen, **keine Ausführung**) | ✅ |
| **Scan-Diff** (`scan diff`: nmap-Scan gegen Projektstand, nur lesend) | ✅ |
| **Loot-/Credential-Matching** (`loot match`: Spray/Pass-the-Hash/Key-Login vorschlagen) | ✅ |
| **Projektweite Folge-Tool-Vorschläge** (`recommend` ohne Argument + nach Import) | ✅ |
| Geführte Recon-/Enum-Kette (`sweep`, regelbasiert, Rückfrage je Schritt) | ✅ |
| Opt-in Runner-Layer (23 Tools, kein Shell-Eval, Scope-Guard, Timeout) | ✅ |
| Methodik-/Playbook-Bibliothek (Web/AD/Linux-/Windows-PrivEsc) | ✅ |
| Automatische Findings (regelbasiert) + strukturierte Parser (enum4linux-ng, nuclei) | ✅ |
| Attack-Path-Graph (Mermaid + Graphviz-DOT) | ✅ |
| Obsidian-Integration (Vault mit `[[Wikilinks]]`) | ✅ |
| Loot-Management (Credentials/Hashes/Tokens/…) | ✅ |
| Evidence-Management (Dateien/Screenshots/Outputs einem Finding zuordnen) | ✅ |
| **Evidence/Screenshots in Reports eingebettet** (HTML inline, PDF, Markdown) | ✅ |
| Finding-Template-Bibliothek (wiederverwendbar, CVSS, vorbefüllt + erweiterbar) | ✅ |
| CTF/THM-Wissensdatenbank (getaggte Einträge) | ✅ |
| „Frag dein Projekt" (RAG über eigene Projektdaten, lokale Embeddings) | ✅ |
| KI-Mentor + **Advisor-Modus** (Scan/Log analysieren, nächste Schritte; fragt vor dem Senden; Offline-Fallback) | ✅ |
| Reporting: Markdown, **gebrandetes HTML & PDF**, didaktischer Lern-Report | ✅ |
| **Web-Dashboard interaktiv** (Lagebild + Finding-Status ändern, Notizen anlegen im Browser) | ✅ |
| **Finding-Detailansicht + Angriffspfad-Graph** im Dashboard (SVG, anklickbar) | ✅ |
| **Status-Historie / Retest-Tracking** (`finding history`, Zeitleiste im Report) | ✅ |
| **MCP-Server** (Workspace aus Claude Code/Cursor abfragen, nur lesend) | ✅ |
| **Terminal-UI** (`pentos tui`: tastaturgesteuertes Lagebild, Status-Pflege) | ✅ |
| Import: nmap-XML **+ Scanner-Import (Nessus/OpenVAS/Burp)** | ✅ |
| **Shell-Completion** (`--install-completion`, Bash/Zsh/Fish) | ✅ |

**Roadmap (offen):**
- KI-Lernkarten & Notizen-Zusammenfassungen (nur aus eigenen Daten, ohne Halluzination)
- Strukturierte Web-Parser (gobuster/ffuf/feroxbuster/nikto) zu Findings
- Reicheres Screenshot-Handling (z.B. direkte Aufnahme/Annotation)

Die vollständige Roadmap mit Begründungen und bewussten Nicht-Zielen steht in [`ROADMAP.md`](ROADMAP.md).

---

## Installation

```bash
cd pentos
pip install -r requirements.txt
# optional als Befehl 'pentos' installieren:
pip install -e .
```

Ohne Installation läuft alles via `python -m pentos ...`.

Beim ersten Start wird `~/.config/pentos/config.yaml` automatisch angelegt
(siehe `config.example.yaml`). Eigener Pfad via `export PENTOS_CONFIG=/pfad/config.yaml`.

---

## Quickstart

```bash
# 1) Projekt anlegen (wird automatisch aktiv)
pentos project new THM_Alfred

# 2) Scan importieren  (nmap -sC -sV -oX scan.xml <ziel>)
pentos scan import-nmap scan.xml          # oder import-scanner für Nessus/OpenVAS/Burp
#   -> Hosts + Services + Auto-Aufgaben + Auto-Findings + Auto-Notiz

# 3) Überblick & nächste Schritte
pentos dashboard                          # kompakte Projekt-Übersicht
pentos recommend 4                        # Vorschläge für einen Service (keine Ausführung)

# 4) Arbeiten dokumentieren
pentos finding status 4 confirmed
pentos loot add "admin:Passw0rd" --type cred --host 1 --source smb
pentos evidence add ./shot.png --kind screenshot --finding 4   # erscheint im Report

# 5) Report erzeugen
pentos report --html                      # gebrandetes HTML (auch --pdf, --explain)
```

Das ist der Kern-Ablauf. Alle Befehle nach Bereich gruppiert in der
**[Befehls-Referenz (COMMANDS.md)](COMMANDS.md)**, oder live über `pentos --help`
und `pentos <gruppe> --help` (z.B. `pentos finding --help`).

Der **Advisor-Modus** (Standard an) macht die KI proaktiv: konkrete nächste Schritte
mit Begründung und vorgeschlagenen Befehlen, die du prüfst und selbst startest. Die KI
**führt nie selbst etwas aus**. Vor jedem Senden fragt PentOS nach; geht es an einen
Cloud-Anbieter, warnt es ausdrücklich, dass Daten den Rechner verlassen (lokales Ollama
bleibt dagegen privat). Umschalten: `pentos ai config --advisor / --no-advisor`.

---

## Runner-Layer (opt-in)

PentOS kann Tools auch **selbst ausführen**, aber nur, wenn du sie explizit
startest (`pentos run <tool> <ziel>`). Die Rohausgabe landet in `scans/`, wird
geparst und automatisch in Findings/Tasks/Evidence/Notizen überführt und im
Journal protokolliert. Einige Tools werten ihre Ausgabe direkt aus: `nmap` baut
die volle Host/Service/Finding-Pipeline, `nuclei` erzeugt Findings, `hydra`/`nxc`
schreiben gefundene Logins als Loot, `enum4linux-ng` legt eine strukturierte Notiz
plus SMB-Findings an.

> **Shell-Modus (`--shell`)**: Standardmäßig laufen Tools ohne Shell (festes `argv`,
> kein Metazeichen-Eval, Injection-Schutz). Manche Tools brauchen aber eine echte
> Shell (z.B. `smbclient -c '...'`); `--shell` aktiviert das bewusst. Der Scope-Guard
> bleibt aktiv. **Nur mit vertrauenswürdiger Eingabe verwenden.**

**Geführte Kette (`sweep`)** nimmt ein Ziel, startet die Basis-Recon und schlägt pro
Dienst die nächsten Tools vor. Regelbasiert, **kein autonomer Agent**: sichere
Recon/Enum-Tools können automatisch laufen (mit Rückfrage je Schritt),
Brute-Force/Exploits werden **nie** automatisch ausgeführt, nur vorgeschlagen.

**Playbooks** sind abhakbare Checklisten (Web, AD, Linux-/Windows-PrivEsc) für
strukturiertes Vorgehen; der Fortschritt wird pro Projekt gespeichert. Eigene als
YAML unter `~/.config/pentos/playbooks/`.

**„Frag dein Projekt" (RAG)** beantwortet Fragen über die eigenen Projektdaten mit
Quellenangabe, ausschließlich aus dem Projektkontext, ohne Halluzination (lokale
Embeddings über das KI-Backend).

**Scope-Guard:** Für echte Engagements legst du erlaubte Ziele fest, damit nichts
außerhalb des Auftrags läuft; ohne Scope läuft der Runner uneingeschränkt (CTF-Modus).
Ausführung erfolgt immer ohne Shell und mit Timeout je Tool. PentOS führt nichts von
selbst aus und kettet keine Angriffe automatisch.

Die konkreten Befehle (Tools, Profile, `sweep`, Playbooks, RAG, Scope) stehen in der
**[Befehls-Referenz (COMMANDS.md)](COMMANDS.md)**.

---

## KI konfigurieren

Ohne Backend läuft alles im Offline-Fallback. Für echte Antworten ein Backend
anbinden, am einfachsten per CLI:

```bash
pentos ai config --provider ollama --base-url http://127.0.0.1:11434 --model llama3.1
pentos ai status          # prüft Erreichbarkeit + listet Modelle
```

Provider: `ollama` | `lmstudio` | `openai` | `none`. Reasoning-Modelle (z.B.
`deepseek-r1`) werden unterstützt; ihre internen `<think>…</think>`-Blöcke filtert
PentOS aus der Antwort.

**Ollama aus einer VM erreichen:** Ollama auf dem Hauptrechner im Netz lauschen
lassen (`OLLAMA_HOST=0.0.0.0:11434 ollama serve`), Port 11434 in der Firewall
freigeben und in der VM `--base-url http://<hauptrechner-ip>:11434` setzen.
Bridged- oder Host-only-Netz funktioniert direkt; bei reinem NAT ggf.
Port-Forwarding.

---

## Architektur

```
pentos/
├── models.py          # Pydantic-Modelle + Enums (Severity, Status, ...)
├── config.py          # YAML-Config, Pfade, aktives Projekt
├── workspace.py       # Workspace-Ordnerstruktur
├── db.py              # SQLite-Schema (eine DB pro Projekt)
├── repository.py      # CRUD + automatisches Journal-Logging
├── recommend.py       # Regel-Engine: Service -> Empfehlungen + Auto-Tasks
├── findings_rules.py  # Auto-Finding-Detektoren (inkl. NSE-Output)
├── importers/nmap.py  # nmap-XML-Parser
├── runners/           # Opt-in Tool-Ausführung
│   ├── base.py        #   sichere Ausführung (kein Shell, Timeout) + ToolSpec
│   ├── registry.py    #   deklarative Tool-Definitionen
│   └── parsers.py     #   Ingest: Ausgabe -> Findings/Tasks/Evidence/Notizen
├── graph.py           # Attack-Path -> Mermaid / Graphviz-DOT
├── obsidian.py        # Vault-Export mit Wikilinks
├── report.py          # Markdown-Report
├── ai.py              # KI-Mentor (Ollama/LM Studio/OpenAI + Offline-Fallback)
└── cli/app.py         # Typer-CLI (Rich-Ausgabe, deutsch)
```

Datenmodell: pro Projekt eine eigene SQLite-DB unter `<projekt>/database/pentos.db`.

---

## Sicherheit / Scope

PentOS orchestriert und dokumentiert. Es führt **keine** Scans oder Exploits selbst aus.
Empfehlungen sind Vorschläge, die KI analysiert ausschliesslich. Einsatz nur in
autorisierten Umgebungen (eigene Labs, CTF/THM, freigegebene Tests).

---

## Installation (aus diesem Repo)

```bash
git clone https://github.com/kaldox/pentos.git
cd pentos
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[pdf,web,mcp,tui]"  # alle Extras: PDF + Web-Dashboard + MCP-Server + TUI; minimal: pip install -e .
pentos --help
```

Erste Schritte:
```bash
pentos project new demo
pentos scope add 10.10.10.0/24       # CIDR oder Hostname (z.B. box.thm)
pentos sweep 10.10.10.5 --run        # geführte Recon/Enumeration
pentos template seed                 # Finding-Vorlagen vorbefüllen
pentos report --pdf                  # gebrandeter Report (Branding optional via config)
```

Konfiguration: Beim ersten Start wird `~/.config/pentos/config.yaml` aus den Defaults
erzeugt. Eine kommentierte Vorlage liegt in [`config.example.yaml`](config.example.yaml).
Ein optionaler OpenAI-Key wird **nie** in der Config gespeichert, sondern nur über die in
`api_key_env` genannte Umgebungsvariable gelesen (Default-KI ist lokales Ollama).

---

## Tests

```bash
pip install pytest
pytest -q
```

---

## ⚠️ Haftungsausschluss / Authorized Use Only

PentOS ist ausschliesslich für **autorisierte** Sicherheitstests gedacht: eigene Labore,
CTF-Plattformen wie TryHackMe/Hack The Box sowie Engagements mit **schriftlicher
Genehmigung** des Zielinhabers. Der Einsatz gegen Systeme ohne ausdrückliche Erlaubnis ist
in den meisten Rechtsordnungen strafbar.

Die Autorinnen und Autoren übernehmen **keine Haftung** für Missbrauch oder Schäden. Die
Nutzung erfolgt auf eigene Verantwortung. Das Tool **führt selbst keine Angriffe aus** und
die integrierte KI **analysiert ausschliesslich**. Die Verantwortung für jede ausgeführte
Aktion liegt bei der nutzenden Person.

---

## Lizenz

Veröffentlicht unter der [MIT-Lizenz](LICENSE).

---

## Web-Dashboard (optional)

Ein lokales Lagebild deines Workspace im Browser: Severity-Verteilung, Findings,
Hosts/Dienste, Loot und Notizen auf einen Blick.

```bash
pip install -e ".[web]"          # FastAPI + uvicorn
pentos serve                     # startet http://127.0.0.1:8787
pentos serve --port 9000 --project meinprojekt
```

Im Dashboard kannst du den **Status von Findings ändern** und **Notizen anlegen**;
die Änderungen landen direkt im Projekt. Es bindet standardmässig nur an `127.0.0.1`
(**keine offene Angriffsfläche**); Schreibzugriffe sind zusätzlich per Origin-Prüfung
gegen Drive-By-Zugriffe fremder Websites geschützt.

---

## MCP-Server (optional)

Macht den PentOS-Workspace für MCP-Clients wie **Claude Code** oder **Cursor**
abfragbar – du sprichst dein Projekt in natürlicher Sprache an („zeig die
High-Findings", „was steht in den Notizen zu SMB"). Alle MCP-Tools sind
**ausschliesslich lesend/analysierend** – kein Tool führt Scans oder Angriffe
aus. Das grosse Reasoning übernimmt der Client, die Kontrolle bleibt bei dir.

```bash
pip install -e ".[mcp]"
```

Client-Konfiguration (Beispiel, z.B. in der MCP-Settings-Datei des Clients):
```json
{ "mcpServers": { "pentos": { "command": "pentos", "args": ["mcp"] } } }
```

Bereitgestellte Tools: `pentos_list_projects`, `pentos_summary`, `pentos_findings`,
`pentos_hosts`, `pentos_loot`, `pentos_notes`, `pentos_knowledge`.

---

## TUI – Terminal-Oberfläche (optional)

`pentos tui` öffnet ein tastaturgesteuertes Lagebild des aktiven Projekts direkt
im Terminal. Tabs für Übersicht, Hosts, Dienste, Findings, Tasks, Loot und
Journal; Navigation mit Pfeiltasten und Tab. Mit `s` schaltest du den Status des
markierten Findings oder Tasks weiter (das wird ins Projekt geschrieben), `r`
aktualisiert, `q` beendet. Reine Ansicht und Status-Pflege, es wird nichts
ausgeführt.

```bash
pip install -e ".[tui]"
pentos tui                 # oder: pentos tui --project meinprojekt
```

---

## Changelog

Alle Versionen und Änderungen sind in [`CHANGELOG.md`](CHANGELOG.md) dokumentiert.
Aktuelle Version: **2.26.0**.
