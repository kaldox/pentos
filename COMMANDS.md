# PentOS Befehls-Referenz

Vollständige Übersicht aller Befehle, gruppiert wie in `pentos --help`. Die
Befehle sind in jeder Sprachversion identisch.

> English version: [`COMMANDS.en.md`](COMMANDS.en.md)

> Die lebende Referenz ist die CLI selbst: `pentos --help` zeigt alle Gruppen,
> `pentos <gruppe> --help` (z.B. `pentos finding --help`) zeigt die Unterbefehle
> samt Optionen.

## Workspace

```bash
pentos project new <name>            # Projekt-Workspace anlegen (wird aktiv)
pentos project list                  # alle Projekte
pentos project use <name>            # aktives Projekt wechseln
pentos scope add 10.10.10.0/24       # erlaubtes Ziel (CIDR oder Hostname)
pentos scope list                    # Scope anzeigen
pentos host list                     # Hosts
pentos service list                  # Dienste
```

## Recon & Import

```bash
# Import
pentos scan import-nmap scan.xml                 # nmap-XML (-oX) importieren
pentos scan import-scanner report.nessus         # Nessus/OpenVAS/Burp (auto-erkannt)
pentos scan import-scanner gvm.xml --format openvas   # Format erzwingen
pentos scan diff rescan.xml                       # nmap-Scan gegen Projektstand (nur lesend)

# Empfehlungen (nur Vorschlag, keine Ausführung)
pentos recommend                     # projektweite Run-Shortcuts über alle Dienste
pentos recommend 4                   # nächste Schritte für Service 4  (--create-tasks)

# Tools ausführen (opt-in)
pentos tools                         # verfügbare Tools + Installations-Check
pentos run nmap 10.10.10.10          # Tool laufen lassen, Ausgabe wird übernommen
pentos run nmap 10.10.10.10 --profile full     # basic | standard | full | custom
pentos run nmap 10.10.10.10 --args "-p- -T4"   # zusätzliche Argumente durchreichen
pentos run nmap 10.10.10.10 --dry-run          # nur das Kommando zeigen
pentos run nmap 10.10.10.10 --shell            # Shell-Modus (nur mit vertrauenswürdiger Eingabe!)
pentos runs                          # Historie aller Läufe

# Geführte Recon-/Enum-Kette
pentos sweep 10.10.10.10             # Vorschau: Kette als fertige Kommandos
pentos sweep 10.10.10.10 --run       # sichere Enum-Tools laufen lassen (Rückfrage je Schritt)
pentos sweep 10.10.10.10 --run --yes # ohne Rückfragen durchlaufen

# Methodik-Playbooks (Checklisten)
pentos playbook list                 # verfügbare Playbooks
pentos playbook show web --target 10.10.10.10   # Checkliste, Kommandos mit Ziel
pentos playbook check web ports      # Schritt abhaken (--note "...", --skip)
pentos playbook uncheck web ports    # Häkchen entfernen
pentos playbook status               # Fortschritt über alle Playbooks
```

> **Sichere Tools** können bei `sweep --run` automatisch laufen (mit Rückfrage),
> **Brute-Force/Exploits nie** automatisch, nur als Vorschlag. Tools laufen ohne
> Shell (festes `argv`, kein Metazeichen-Eval). `--shell` schaltet eine echte
> Shell bewusst frei und ist nur mit vertrauenswürdiger Eingabe zu nutzen.

## Befunde & Doku

```bash
# Findings
pentos finding list
pentos finding status 4 confirmed    # Status setzen
pentos finding rm 4

# Finding-Vorlagen (wiederverwendbar, pro Projekt)
pentos template seed                 # aus der Wissensbasis vorbefüllen (idempotent)
pentos template list
pentos template show pwn3d           # Detail (Beschreibung, Remediation, CVSS)
pentos template apply pwn3d --host 10.10.10.5 --suffix "(10.10.10.5)"  # Vorlage -> Finding
pentos template add ...              # eigene Vorlage anlegen

# Loot, Evidence, Notizen, Wissen
pentos loot add "admin:Passw0rd" --type cred --host 1 --source smb
pentos loot list
pentos loot match                    # alle Loot-Einträge gegen passende Dienste vorschlagen
pentos loot match 1                  # nur Loot #1 (Spray / Pass-the-Hash / Key-Login)
pentos evidence add ./shot.png --kind screenshot --finding 4
pentos note show <id>                # Notiz-Inhalt anzeigen
pentos knowledge add Jenkins "Script Console RCE" --body "Groovy unter /script"

# Aufgaben
pentos task list
pentos task start 12
pentos task done 12
```

## Reporting & Übersicht

```bash
pentos dashboard                     # kompakte CLI-Übersicht des Projekts
pentos tui                           # interaktives Terminal-Lagebild (Textual); s=Status, r=neu, q=Ende
pentos report                        # Markdown-Report unter <projekt>/reports
pentos report --html                 # gebrandetes HTML (im Browser druckbar)
pentos report --pdf                  # gebrandetes PDF (braucht reportlab)
pentos report --explain              # Lern-Report: erklärt jeden Schritt didaktisch
pentos graph mermaid --out attack_paths/ap.mmd
pentos graph dot --out attack_paths/ap.dot       # dot -Tpng ap.dot -o ap.png
pentos obsidian                      # Obsidian-Vault unter <projekt>/obsidian
```

## KI & Integration

```bash
# KI-Mentor & Advisor (lokal; ohne Modell -> Offline-Fallback)
pentos ai status                     # Backend-Status
pentos ai config --provider ollama --base-url http://127.0.0.1:11434 --model llama3.1
pentos ai explain-finding 4
pentos ai enum 4
pentos ai analyze scan.txt --as nmap # Scan/Log deuten (--text, stdin, --save)
pentos ai next                       # Vorschläge zum Projektstand

# "Frag dein Projekt" (RAG über eigene Daten)
pentos ai config --embed-model nomic-embed-text
pentos ai index                      # Index über das aktive Projekt bauen
pentos ai ask "Wo finde ich den SSH-Key von kenobi?"

# Web-Dashboard
pentos serve                         # http://127.0.0.1:8787
pentos serve --port 9000 --project meinprojekt

# MCP-Server (für Claude Code / Cursor)
pentos mcp                           # stdio-Server (read-only)
```

---

Shell-Completion einrichten (Bash/Zsh/Fish):

```bash
pentos --install-completion          # Completion für die aktuelle Shell installieren
pentos --show-completion             # Completion-Skript nur ausgeben (zum Kopieren)
```

---

Tipp: Jede Gruppe hat eine eigene Hilfe, z.B. `pentos ai --help` oder
`pentos run --help`, mit allen Optionen und Defaults.
