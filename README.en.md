# PentOS

[🇩🇪 Deutsch](README.md) · **🇬🇧 English** · [🐻 Baseldütsch](README.bl.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Version](https://img.shields.io/badge/version-2.22.0%2Brunner-informational)

**Knowledge-Driven Offensive Security Workspace**

PentOS is **not a scanner collection**. It is a full pentest *workspace* system:
findings, attack paths, notes, evidence, knowledge and documentation are what it
revolves around. Local-first, no forced cloud, German-language output by default.
The AI is purely a learning and analysis assistant. **It never runs attacks or
commands itself**.

> Built for authorized testing: CTF, TryHackMe and signed-off engagements.

---

## What Phase 1 already does

| Spec requirement | Status |
|---|---|
| Pentest workspace (full folder structure per project) | ✅ |
| Automatic notes (e.g. `notes/nmap.md` on import) | ✅ |
| Pentest journal (every action timestamped) | ✅ |
| Task system (auto-generated per service, Open/In progress/Done) | ✅ |
| Intelligent next steps (recommendations, **no execution**) | ✅ |
| Automatic findings (rule-based, parses NSE output) | ✅ |
| Attack-path graph (Mermaid + Graphviz DOT) | ✅ |
| Obsidian integration (vault with `[[wikilinks]]`) | ✅ |
| Loot management (credentials/hashes/tokens/…) | ✅ |
| Evidence management (attach files/screenshots/outputs to a finding) | ✅ |
| CTF/THM knowledge base (tagged entries) | ✅ |
| AI mentor (explain findings, enumeration ideas; offline fallback) | ✅ |
| Reporting (Markdown from findings/journal/tasks/attack path) | ✅ |
| nmap XML import (hosts/services/scripts) | ✅ |

**Roadmap (next phases):**
- **Opt-in runner layer:** ✅ shipped. Tools run on request, output is parsed and
  ingested into the workspace (scope guard included).
- **Phase 2:** methodology/playbook library (web/AD/Linux/Windows/cloud/API/mobile as
  checklists), richer screenshot handling, knowledge-base expansion.
- **Phase 3:** AI flashcards & note summaries, Nuclei template management,
  structured parsers for more tools (enum4linux-ng/ffuf JSON → users/shares/paths),
  HTML/PDF report.

---

## Installation

```bash
cd pentos
pip install -r requirements.txt
# optionally install as the 'pentos' command:
pip install -e .
```

Without installation, everything runs via `python -m pentos ...`.

On first start, `~/.config/pentos/config.yaml` is created automatically
(see `config.example.yaml`). Custom path via `export PENTOS_CONFIG=/path/config.yaml`.

---

## Quickstart

```bash
# 1) Create a project workspace (becomes active automatically)
pentos project new THM_Alfred

# 2) Import an nmap scan  (recommended: nmap -sC -sV -oX scan.xml <target>)
pentos scan import-nmap scan.xml
pentos scan import-scanner report.nessus          # Nessus/OpenVAS/Burp (auto-detect)
pentos scan import-scanner gvm.xml --format openvas   # force format (nessus|openvas|burp)
#   -> hosts + services + auto-tasks + auto-findings + auto-note

# 3) Overview
pentos dashboard                   # project overview at a glance
pentos finding list
pentos task list
pentos service list

# 4) Next steps for a service (suggestion only)
pentos recommend 4                 # optional: --create-tasks

# 5) Document your work
pentos task start 12
pentos task done 12
pentos finding status 4 confirmed
pentos loot add "admin:Passw0rd" --type cred --host 1 --source smb
pentos evidence add ./screenshots/smb_share.png --kind screenshot --finding 4
pentos note show <id>                 # show full note content
pentos knowledge add Jenkins "Script Console RCE" --body "Groovy under /script"

# 5b) Finding template library (reusable, vetted templates, per project)
pentos template seed                           # pre-fill from the knowledge base (8 templates, idempotent)
pentos template list                           # show templates
pentos template show pwn3d                      # detail (description, remediation, CVSS)
pentos template apply pwn3d --host 192.168.56.10 --suffix "(192.168.56.10)"  # template -> finding

# 6) Visualize & export
pentos graph mermaid --out attack_paths/ap.mmd
pentos graph dot --out attack_paths/ap.dot     # dot -Tpng ap.dot -o ap.png
pentos obsidian                                # vault under <project>/obsidian
pentos report                                  # Markdown report under <project>/reports
pentos report --html                           # branded HTML report (printable/PDF in browser)
pentos report --pdf                            # branded PDF (needs reportlab: pip install reportlab)
pentos report --explain                        # learning report: explains each step didactically

# 7) AI mentor (local; without a model -> offline fallback)
pentos ai explain-finding 4
pentos ai enum 4
```

---

## Runner layer (opt-in)

PentOS can also **run tools itself**, but only when you explicitly start them.
The raw output lands in `scans/`, gets parsed and is automatically ingested into
findings/tasks/evidence/notes and logged in the journal.

```bash
pentos tools                         # available tools + install check
pentos run nmap 10.10.10.10          # full cascade: hosts/services/tasks/findings
pentos run nuclei http://10.10.10.10 # hits -> findings (severity from output)
pentos run nmap 10.10.10.10 --profile full     # basic | standard | full | custom
pentos run nmap 10.10.10.10 --args "-p- -T4"   # pass through extra arguments
pentos run nmap 10.10.10.10 --dry-run          # only show the command
pentos runs                          # history of all runs
```

> **Shell mode (`--shell`)**: By default, tools run without a shell (fixed `argv`,
> no metacharacter eval, injection protection). Some tools need a real shell
> though (e.g. `smbclient -c '...'`). `--shell` enables that deliberately: the
> command from `--args` is interpreted by the shell. The scope guard stays active.
> **Only use with trusted input.** Shell metacharacters will be executed.

### Sweep: guided recon/enum chain

`sweep` takes a target, runs base recon (nmap) and then suggests the next tools per
discovered service. Rule-based and traceable, **not an autonomous agent**: safe
recon/enum tools can run automatically (with a prompt per step), brute-force/exploits
are **never** run automatically, only suggested.

```bash
pentos sweep 10.10.10.10                 # preview: chain as ready-to-run commands
pentos sweep 10.10.10.10 --run           # run safe enum tools (prompt per step)
pentos sweep 10.10.10.10 --run --yes     # run through without prompts
```

### Playbooks / methodology

Checkable checklists for a structured approach (web, AD, Linux/Windows privesc).
Each step is 🔧 a PentOS tool (with a ready command), 🌐 an external/GUI tool
(Burp, ZAP, wpscan, impacket, LinPEAS …) or 📝 a manual check. Progress is saved
per project.

```bash
pentos playbook list                       # available playbooks
pentos playbook show web --target 10.10.10.10   # checklist, commands with target
pentos playbook check web ports            # check off a step (--note "...", --skip)
pentos playbook status                     # progress across all playbooks
```

### "Ask your project" (RAG)

Ask questions about your **own** project data (findings, notes, knowledge, loot,
hosts/services). PentOS builds local embeddings (via the AI backend), stores them as
a vector index in the project DB and answers with source attribution, exclusively
from the project context, no hallucination.

```bash
ollama pull nomic-embed-text                 # embedding model (once)
pentos ai config --embed-model nomic-embed-text
pentos ai index                              # build the index over the active project
pentos ai ask "Where do I find kenobi's SSH key?"
```

---

## Architecture

```
pentos/
├── models.py          # Pydantic models + enums (Severity, Status, ...)
├── config.py          # YAML config, paths, active project
├── workspace.py       # workspace folder structure
├── db.py              # SQLite schema (one DB per project)
├── repository.py      # CRUD + automatic journal logging
├── recommend.py       # rule engine: service -> recommendations + auto-tasks
├── findings_rules.py  # auto-finding detectors (incl. NSE output)
├── importers/nmap.py  # nmap XML parser
├── runners/           # opt-in tool execution
│   ├── base.py        #   safe execution (no shell, timeout) + ToolSpec
│   ├── registry.py    #   declarative tool definitions
│   └── parsers.py     #   ingest: output -> findings/tasks/evidence/notes
├── graph.py           # attack path -> Mermaid / Graphviz DOT
├── obsidian.py        # vault export with wikilinks
├── report.py          # Markdown report
├── ai.py              # AI mentor (Ollama/LM Studio/OpenAI + offline fallback)
└── cli/app.py         # Typer CLI (Rich output)
```

Data model: one SQLite DB per project under `<project>/database/pentos.db`.

---

## Security / scope

PentOS orchestrates and documents. It runs **no** scans or exploits itself.
Recommendations are suggestions, the AI analyzes only. Use only in authorized
environments (your own labs, CTF/THM, signed-off tests).

---

## Tests

```bash
pip install pytest
pytest -q
```

---

## ⚠️ Disclaimer / Authorized Use Only

PentOS is intended solely for **authorized** security testing: your own labs,
CTF platforms like TryHackMe/Hack The Box, and engagements with **written
permission** from the target owner. Use against systems without explicit permission
is a criminal offense in most jurisdictions.

The authors accept **no liability** for misuse or damage. Use at your own risk. The
tool **runs no attacks itself** and the integrated AI **only analyzes**; responsibility
for every executed action lies with the user.

---

## License

Released under the [MIT License](LICENSE).
