# PentOS

**🇩🇪 Deutsch** · [🇬🇧 English](README.en.md) · [🐻 Baseldütsch](README.bl.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Version](https://img.shields.io/badge/version-2.22.0%2Brunner-informational)

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
| **MCP-Server** (Workspace aus Claude Code/Cursor abfragen, nur lesend) | ✅ |
| Import: nmap-XML **+ Scanner-Import (Nessus/OpenVAS/Burp)** | ✅ |

**Roadmap (offen):**
- KI-Lernkarten & Notizen-Zusammenfassungen (nur aus eigenen Daten, ohne Halluzination)
- Remediation-/Status-Historie für Findings (Retest-Tracking)
- Attack-Path-Graph visuell im Dashboard
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
# 1) Projekt-Workspace anlegen (wird automatisch aktiv)
pentos project new THM_Alfred

# 2) nmap-Scan importieren  (empfohlen: nmap -sC -sV -oX scan.xml <ziel>)
pentos scan import-nmap scan.xml
pentos scan import-scanner report.nessus          # Nessus/OpenVAS/Burp (Auto-Erkennung)
pentos scan import-scanner gvm.xml --format openvas   # Format erzwingen (nessus|openvas|burp)
#   -> Hosts + Services + Auto-Aufgaben + Auto-Findings + Auto-Notiz

# 3) Überblick
pentos dashboard                   # Projekt-Übersicht auf einen Blick
pentos finding list
pentos task list
pentos service list

# 4) Nächste Schritte für einen Service (nur Vorschlag)
pentos recommend 4                 # optional: --create-tasks

# 5) Arbeiten dokumentieren
pentos task start 12
pentos task done 12
pentos finding status 4 confirmed
pentos loot add "admin:Passw0rd" --type cred --host 1 --source smb
pentos evidence add ./screenshots/smb_share.png --kind screenshot --finding 4
#   -> einem Finding zugeordnete Screenshots/Outputs erscheinen automatisch im Report (HTML/PDF/Markdown)
pentos note show <id>                 # vollständigen Notiz-Inhalt anzeigen
pentos knowledge add Jenkins "Script Console RCE" --body "Groovy unter /script"

# 5b) Finding-Template-Bibliothek (wiederverwendbare, geprüfte Vorlagen, pro Projekt)
pentos template seed                           # aus der Wissensbasis vorbefüllen (8 Vorlagen, idempotent)
pentos template list                           # Vorlagen anzeigen
pentos template show pwn3d                      # Detail (Beschreibung, Remediation, CVSS)
pentos template add open-redis --title "Offener Redis ohne Auth" \
    --severity high --cat exposure --cvss 7.5 \
    --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" \
    --desc "Redis ohne Authentifizierung." --fix "requirepass setzen."
pentos template apply pwn3d --host 192.168.56.10 --suffix "(192.168.56.10)"  # Vorlage -> Finding

# 6) Visualisieren & exportieren
pentos graph mermaid --out attack_paths/ap.mmd
pentos graph dot --out attack_paths/ap.dot     # dot -Tpng ap.dot -o ap.png
pentos obsidian                                # Vault unter <projekt>/obsidian
pentos report                                  # Markdown-Report unter <projekt>/reports
pentos report --html                           # gebrandeter HTML-Report (im Browser druck-/PDF-fähig)
pentos report --pdf                            # gebrandetes PDF (benötigt reportlab: pip install reportlab)
pentos report --explain                        # Lern-Report: erklärt jeden Schritt didaktisch

# 7) KI-Mentor (lokal; ohne Modell -> Offline-Fallback)
pentos ai explain-finding 4
pentos ai enum 4
pentos ai analyze scan.txt --as nmap          # Scan/Log/Output deuten lassen + nächste Schritte
cat nikto.txt | pentos ai analyze --as nikto   # auch per Pipe (stdin)
pentos ai next                                 # KI schlägt nächste Schritte zum Projektstand vor
```

Der **Advisor-Modus** (Standard an) macht die KI proaktiv: konkrete nächste Schritte
mit Begründung und vorgeschlagenen Befehlen, die du prüfst und selbst startest. Die KI
**führt nie selbst etwas aus**. Vor jedem Senden fragt PentOS nach; geht es an einen
Cloud-Anbieter, warnt es ausdrücklich, dass Daten den Rechner verlassen (lokales Ollama
bleibt dagegen privat). Umschalten: `pentos ai config --advisor / --no-advisor`.

---

## Runner-Layer (opt-in)

PentOS kann Tools auch **selbst ausführen**, aber nur, wenn du sie explizit
startest. Die Rohausgabe landet in `scans/`, wird geparst und automatisch in
Findings/Tasks/Evidence/Notizen überführt und im Journal protokolliert.

```bash
pentos tools                         # verfügbare Tools + Installations-Check
pentos run nmap 10.10.10.10          # voller Cascade: Hosts/Services/Tasks/Findings
pentos run nuclei http://10.10.10.10 # Treffer -> Findings (Severity aus Output)
pentos run whatweb http://10.10.10.10
pentos run feroxbuster http://10.10.10.10 --wordlist /usr/share/wordlists/dirb/common.txt
pentos run nmap 10.10.10.10 --profile full     # basic | standard | full | custom
pentos run nmap 10.10.10.10 --args "-p- -T4"   # zusätzliche Argumente durchreichen
pentos run nmap 10.10.10.10 --dry-run          # nur das Kommando zeigen
pentos run smbclient 10.10.10.10 --shell \
  --args "//10.10.10.10/anonymous -N -c 'get log.txt'"   # interaktive Tools (Shell-Modus)
pentos runs                          # Historie aller Läufe
```

> **Shell-Modus (`--shell`)**: Standardmäßig laufen Tools ohne Shell (festes `argv`,
> kein Metazeichen-Eval – Injection-Schutz). Manche Tools brauchen jedoch eine
> echte Shell (z.B. `smbclient -c '...'`). `--shell` aktiviert das bewusst: der
> Befehl aus `--args` wird durch die Shell interpretiert. Der Scope-Guard bleibt
> aktiv. **Nur mit vertrauenswürdiger Eingabe verwenden** – Shell-Metazeichen
> werden ausgeführt.

Aufräumen und Status pflegen:

```bash
pentos finding rm 7 --yes            # Finding löschen (auch loot/note/evidence rm)
pentos finding status 6 exploited    # unverified|confirmed|exploited|fp|closed
```

`finding list` zeigt Host/Port je Finding, sodass gleichnamige Findings auf
verschiedenen Hosts unterscheidbar sind. Auto-Findings deduplizieren pro Dienst
bzw. pro Host (kein Doppeln bei Re-Scans).

### Sweep – geführte Recon-/Enum-Kette

`sweep` nimmt ein Ziel, startet die Basis-Recon (nmap) und schlägt dann pro
gefundenem Dienst die nächsten Tools vor. Regelbasiert und nachvollziehbar – **kein
autonomer Agent**: sichere Recon/Enum-Tools können automatisch laufen (mit Rückfrage
je Schritt), Brute-Force/Exploits werden **nie** automatisch ausgeführt, nur vorgeschlagen.

```bash
pentos sweep 10.10.10.10                 # Vorschau: Kette als fertige Kommandos
pentos sweep 10.10.10.10 --run           # sichere Enum-Tools ausführen (je Schritt Rückfrage)
pentos sweep 10.10.10.10 --run --yes     # ohne Rückfragen durchlaufen
```

- **Auto (sicher):** nmap, whatweb, feroxbuster, nuclei, enum4linux-ng, smbclient, smbmap, snmpwalk, ldapsearch, dig-axfr
- **Nur Vorschlag (nie automatisch):** hydra/medusa/nxc (Brute-Force), sqlmap/searchsploit (Exploit), gobuster/ffuf/nikto (Alternativen). GUI-/Spezialtools (Burp, ZAP, BloodHound, wpscan) über die Playbooks.

### Playbooks / Methodik

Abhakbare Checklisten für strukturiertes Vorgehen (Web, AD, Linux-/Windows-PrivEsc).
Jeder Schritt ist 🔧 ein PentOS-Tool (mit fertigem Kommando), 🌐 ein externes/GUI-Tool
(Burp, ZAP, wpscan, impacket, LinPEAS …) oder 📝 ein manueller Prüfschritt. Der
Fortschritt wird pro Projekt gespeichert.

```bash
pentos playbook list                       # verfügbare Playbooks
pentos playbook show web --target 10.10.10.10   # Checkliste, Kommandos mit Ziel
pentos playbook check web ports            # Schritt abhaken (--note "...", --skip)
pentos playbook uncheck web ports          # Markierung entfernen
pentos playbook status                     # Fortschritt aller Playbooks
```

Eigene Playbooks als YAML unter `~/.config/pentos/playbooks/` ablegen – gleiche
Namen überschreiben die mitgelieferten.

### „Frag dein Projekt" (RAG)

Stellt Fragen über die **eigenen** Projektdaten (Findings, Notizen, Wissen, Loot,
Hosts/Services). PentOS baut lokale Embeddings (über das KI-Backend), legt sie als
Vektor-Index in der Projekt-DB ab und beantwortet Fragen mit Quellenangabe –
ausschließlich aus dem Projektkontext, ohne Halluzination.

```bash
ollama pull nomic-embed-text                 # Embedding-Modell (einmalig)
pentos ai config --embed-model nomic-embed-text
pentos ai index                              # Index über das aktive Projekt bauen
pentos ai ask "Wo finde ich den SSH-Key von kenobi?"
```

Die Antwort nennt die genutzten Quellen als `[Typ #id]`. Sprache folgt
`config.language` (de/en). Nach neuen Findings/Notizen `pentos ai index` erneut
ausführen, um den Index zu aktualisieren.

`pentos recommend <service-id>` zeigt zu jedem Vorschlag direkt die passenden,
**installierten** `pentos run …`-Kommandos (copy-paste-fertig).

**Enumeration/Recon:** `nmap` (volle Pipeline, mit Profilen), `nuclei` (Findings),
`whatweb`, `nikto`, `feroxbuster`, `gobuster`, `ffuf`, `enum4linux-ng`, `smbclient`,
`smbmap`, `ldapsearch`, `snmpwalk`, `dig-axfr`.

**Brute-Force / Exploitation / Cracking** (für autorisiertes Training wie TryHackMe):
`hydra`, `medusa`, `nxc-smb`, `nxc-winrm` (NetExec), `sqlmap`, `searchsploit` (offline),
`john` (offline). Diese Tools sind Wrapper um die Standard-Kali-Binaries – die
spezifischen Parameter kommen über `--args`:

```bash
pentos run hydra 10.10.10.10 --args "-l admin -P /usr/share/wordlists/rockyou.txt ssh"
pentos run hydra 10.10.10.10 --args "-L users.txt -P pass.txt ftp"
pentos run nxc-smb 10.10.10.10 --args "-u users.txt -p pass.txt"
pentos run sqlmap "http://10.10.10.10/page?id=1" --args "--dbs --batch"
pentos run searchsploit "apache 2.4.49"          # offline, kein Scope nötig
pentos run john ./hashes.txt --wordlist /usr/share/wordlists/rockyou.txt
```

`hydra`/`medusa` parsen gefundene Logins automatisch in **Loot** (`pentos loot list`).
Weitere Tools lassen sich als `ToolSpec` in `pentos/runners/registry.py` ergänzen.

### Automatische Auswertung der Ausgabe

Statt nur die Rohausgabe abzulegen, überführen einige Tools ihr Ergebnis direkt
in den Workspace:

- `nmap` → Hosts/Services/Auto-Tasks/Auto-Findings (volle Pipeline)
- `nuclei` → Findings (Severity aus der Ausgabe)
- `ffuf` (JSON) / `gobuster` / `feroxbuster` → gefundene Pfade als Notiz (Status, URL, Größe)
- `hydra` / `medusa` → gefundene Credentials als Loot
- `nxc-smb` / `nxc-winrm` → Credentials als Loot, `(Pwn3d!)` zusätzlich als High-Finding
- `enum4linux-ng` → strukturierte Notiz (OS/Workgroup/Computer/Dialekte/User/Shares) plus
  Findings: Null-Session, SMB-Signing nicht erzwungen, anonym lesbare Shares

Alle übrigen Tools legen die Ausgabe als Notiz + Evidence ab.

### Scope-Guard

Für echte Engagements: erlaubte Ziele festlegen, damit nichts ausserhalb des
Auftrags läuft. Ohne Scope läuft der Runner uneingeschränkt (CTF-Modus).
Offline-Tools (`searchsploit`, `john`) haben kein Netzwerk-Ziel und umgehen die Prüfung.

```bash
pentos scope add 10.10.10.0/24       # z.B. die THM-VPN-Range
pentos scope add target.example.com  # einzelner Host
pentos scope list
pentos run hydra 1.2.3.4 --args "..." # -> blockiert, wenn nicht im Scope
pentos run hydra 1.2.3.4 --args "..." --force   # bewusst überschreiben
```

Ausführung erfolgt ohne Shell (festes argv, kein String-Eval), mit Timeout je Tool.
PentOS führt nichts von selbst aus und kettet keine Angriffe automatisch.



## KI konfigurieren

Ohne Backend läuft alles im Offline-Fallback. Für echte Antworten ein Backend
anbinden – am einfachsten per CLI, ohne YAML zu editieren:

```bash
pentos ai config --provider ollama --base-url http://192.168.1.20:11434 --model llama3.1
pentos ai status          # prüft Erreichbarkeit + listet verfügbare Modelle
```

`ai config` schreibt die Werte in `config.yaml` und prüft danach direkt die
Verbindung. Provider: `ollama` | `lmstudio` | `openai` | `none`.
Reasoning-Modelle (z.B. `deepseek-r1`) werden unterstützt – ihre internen
`<think>…</think>`-Blöcke filtert PentOS aus der Antwort.

### Lokales Ollama aus einer VM erreichen (gleiches Netz)

Läuft PentOS in einer VM und Ollama auf dem Hauptrechner:

1. **Auf dem Hauptrechner** Ollama im Netz lauschen lassen (nicht nur localhost):
   ```bash
   # Linux/macOS:
   OLLAMA_HOST=0.0.0.0:11434 ollama serve
   # systemd: 'systemctl edit ollama' -> [Service] Environment="OLLAMA_HOST=0.0.0.0:11434"
   # Windows: Umgebungsvariable OLLAMA_HOST=0.0.0.0:11434 setzen, Ollama neu starten
   ollama pull llama3.1
   ```
2. **IP des Hauptrechners** ermitteln (`ip a` / `ipconfig`) und **Port 11434** in der
   Firewall freigeben.
3. **In der VM** aus PentOS heraus konfigurieren und testen:
   ```bash
   curl http://<hauptrechner-ip>:11434/api/tags         # Vorab-Check der Route
   pentos ai config --provider ollama --base-url http://<hauptrechner-ip>:11434 --model llama3.1
   pentos ai status
   pentos ai explain-finding 1
   ```

VM-Netzwerk: **Bridged** oder **Host-only** mit Route zum Host funktioniert direkt;
bei reinem NAT ggf. Port-Forwarding/Host-IP nötig.

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
pip install -e ".[pdf,web,mcp]"  # alle Extras: PDF + Web-Dashboard + MCP-Server; minimal: pip install -e .
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

## Changelog

Alle Versionen und Änderungen sind in [`CHANGELOG.md`](CHANGELOG.md) dokumentiert.
Aktuelle Version: **2.22.0**.
