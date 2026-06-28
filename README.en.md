# PentOS

[🇩🇪 Deutsch](README.md) · **🇬🇧 English**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Version](https://img.shields.io/badge/version-2.25.1-informational)

**Knowledge-Driven Offensive Security Workspace**

PentOS is **not a scanner collection**. It is a full pentest *workspace* system:
findings, attack paths, notes, evidence, knowledge and documentation are what it
revolves around. Local-first, no forced cloud, German-language output by default.
The AI is purely a learning and analysis assistant. **It never runs attacks or
commands itself**.

> Built for authorized testing: CTF, TryHackMe and signed-off engagements.

---

## What PentOS can do

| Feature | Status |
|---|---|
| Pentest workspace (full folder structure per project) | ✅ |
| Automatic notes (e.g. `notes/nmap.md` on import) | ✅ |
| Pentest journal (every action timestamped) | ✅ |
| Task system (auto-generated per service, Open/In progress/Done) | ✅ |
| Intelligent next steps (recommendations, **no execution**) | ✅ |
| **Scan diff** (`scan diff`: nmap scan vs. project state, read-only) | ✅ |
| **Loot/credential matching** (`loot match`: suggest spray/pass-the-hash/key login) | ✅ |
| **Project-wide follow-up tool suggestions** (`recommend` with no argument + after import) | ✅ |
| Guided recon/enum chain (`sweep`, rule-based, prompts per step) | ✅ |
| Opt-in runner layer (23 tools, no shell eval, scope guard, timeout) | ✅ |
| Methodology / playbook library (web/AD/Linux/Windows privesc) | ✅ |
| Automatic findings (rule-based) + structured parsers (enum4linux-ng, nuclei) | ✅ |
| Attack-path graph (Mermaid + Graphviz DOT) | ✅ |
| Obsidian integration (vault with `[[wikilinks]]`) | ✅ |
| Loot management (credentials/hashes/tokens/…) | ✅ |
| Evidence management (attach files/screenshots/outputs to a finding) | ✅ |
| **Evidence/screenshots embedded in reports** (HTML inline, PDF, Markdown) | ✅ |
| Finding-template library (reusable, with CVSS, pre-filled + extendable) | ✅ |
| CTF/THM knowledge base (tagged entries) | ✅ |
| "Ask your project" (RAG over your own project data, local embeddings) | ✅ |
| AI mentor + **advisor mode** (analyze a scan/log, suggest next steps; asks before sending; offline fallback) | ✅ |
| Reporting: Markdown, **branded HTML & PDF**, didactic learning report | ✅ |
| **Interactive web dashboard** (overview + change finding status, add notes in the browser) | ✅ |
| **MCP server** (query your workspace from Claude Code/Cursor, read-only) | ✅ |
| **Terminal UI** (`pentos tui`: keyboard-driven dashboard, status editing) | ✅ |
| Import: nmap XML **+ scanner import (Nessus/OpenVAS/Burp)** | ✅ |
| **Shell completion** (`--install-completion`, Bash/Zsh/Fish) | ✅ |

**Roadmap (open):**
- AI flashcards & note summaries (from your own data only, no hallucination)
- Remediation/status history for findings (retest tracking)
- Attack-path graph rendered visually in the dashboard
- Richer screenshot handling (e.g. direct capture/annotation)

The full roadmap, with rationale and deliberate non-goals, lives in [`ROADMAP.en.md`](ROADMAP.en.md).

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
# 1) Create a project (becomes active automatically)
pentos project new THM_Alfred

# 2) Import a scan  (nmap -sC -sV -oX scan.xml <target>)
pentos scan import-nmap scan.xml          # or import-scanner for Nessus/OpenVAS/Burp
#   -> hosts + services + auto-tasks + auto-findings + auto-note

# 3) Overview & next steps
pentos dashboard                          # compact project overview
pentos recommend                          # project-wide run shortcuts across all services
pentos recommend 4                        # suggestions for a service (no execution)

# 4) Document your work
pentos finding status 4 confirmed
pentos loot add "admin:Passw0rd" --type cred --host 1 --source smb
pentos evidence add ./shot.png --kind screenshot --finding 4   # shows up in the report

# 5) Generate a report
pentos report --html                      # branded HTML (also --pdf, --explain)
```

That is the core flow. All commands grouped by area in the
**[command reference (COMMANDS.en.md)](COMMANDS.en.md)**, or live via `pentos --help`
and `pentos <group> --help` (e.g. `pentos finding --help`).

---

## Runner layer (opt-in)

PentOS can also **run tools itself**, but only when you explicitly start them
(`pentos run <tool> <target>`). The raw output lands in `scans/`, gets parsed and
is automatically ingested into findings/tasks/evidence/notes and logged in the
journal. Some tools ingest their output directly: `nmap` builds the full
host/service/finding pipeline, `nuclei` creates findings, `hydra`/`nxc` write found
logins as loot, `enum4linux-ng` adds a structured note plus SMB findings.

> **Shell mode (`--shell`)**: By default tools run without a shell (fixed `argv`,
> no metacharacter eval, injection protection). Some tools need a real shell though
> (e.g. `smbclient -c '...'`); `--shell` enables that deliberately. The scope guard
> stays active. **Only use with trusted input.**

**Guided chain (`sweep`)** takes a target, runs base recon and then suggests the
next tools per discovered service. Rule-based, **not an autonomous agent**: safe
recon/enum tools can run automatically (with a prompt per step), brute-force/exploits
are **never** run automatically, only suggested.

**Playbooks** are checkable checklists (web, AD, Linux/Windows privesc) for a
structured approach; progress is saved per project. Add your own as YAML under
`~/.config/pentos/playbooks/`.

**"Ask your project" (RAG)** answers questions about your own project data with
source attribution, exclusively from the project context, no hallucination (local
embeddings via the AI backend).

**Scope guard:** for real engagements you define allowed targets so nothing runs
outside the engagement; without a scope the runner runs unrestricted (CTF mode).
Execution is always without a shell and with a per-tool timeout. PentOS runs nothing
on its own and chains no attacks automatically.

The concrete commands (tools, profiles, `sweep`, playbooks, RAG, scope) are in the
**[command reference (COMMANDS.en.md)](COMMANDS.en.md)**.

---

## AI configuration

Without a backend, everything runs in offline fallback. For real answers, connect
a backend, most easily via the CLI:

```bash
pentos ai config --provider ollama --base-url http://127.0.0.1:11434 --model llama3.1
pentos ai status          # checks reachability + lists models
```

Providers: `ollama` | `lmstudio` | `openai` | `none`. Reasoning models (e.g.
`deepseek-r1`) are supported; PentOS strips their internal `<think>…</think>`
blocks from the answer.

**Reaching Ollama from a VM:** have Ollama listen on the network on the host
(`OLLAMA_HOST=0.0.0.0:11434 ollama serve`), open port 11434 in the firewall, and
set `--base-url http://<host-ip>:11434` inside the VM. Bridged or host-only
networking works directly; with plain NAT you may need port forwarding.

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

## Installation (from this repo)

```bash
git clone https://github.com/kaldox/pentos.git
cd pentos
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[pdf,web,mcp,tui]"  # all extras: PDF + web dashboard + MCP server + TUI; minimal: pip install -e .
pentos --help
```

First steps:
```bash
pentos project new demo
pentos scope add 10.10.10.0/24       # CIDR or hostname (e.g. box.thm)
pentos sweep 10.10.10.5 --run        # guided recon/enumeration
pentos template seed                 # pre-fill finding templates
pentos report --pdf                  # branded report (branding optional via config)
```

Configuration: on first start, `~/.config/pentos/config.yaml` is created from the
defaults. A commented template lives in [`config.example.yaml`](config.example.yaml).
An optional OpenAI key is **never** stored in the config; it is only read from the
environment variable named in `api_key_env` (the default AI is local Ollama).

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

---

## Web dashboard (optional)

A local situational overview of your workspace in the browser: severity distribution,
findings, hosts/services, loot and notes at a glance.

```bash
pip install -e ".[web]"          # FastAPI + uvicorn
pentos serve                     # starts http://127.0.0.1:8787
pentos serve --port 9000 --project myproject
```

In the dashboard you can **change a finding's status** and **add notes**; the changes
go straight into the project. It binds to `127.0.0.1` only (**no open attack surface**),
and write requests are additionally guarded by an origin check against drive-by access
from other websites.

---

## MCP server (optional)

Makes the PentOS workspace queryable from MCP clients like **Claude Code** or **Cursor**.
You talk to your project in natural language ("show the high findings", "what is in the
SMB notes"). All MCP tools are **strictly read-only/analytical**; no tool runs scans or
attacks. The heavy reasoning happens in the client, control stays with you.

```bash
pip install -e ".[mcp]"
```

Client configuration (example, e.g. in the client's MCP settings file):

```json
{ "mcpServers": { "pentos": { "command": "pentos", "args": ["mcp"] } } }
```

Provided tools: `pentos_list_projects`, `pentos_summary`, `pentos_findings`,
`pentos_hosts`, `pentos_loot`, `pentos_notes`, `pentos_knowledge`.

---

## TUI – terminal interface (optional)

`pentos tui` opens a keyboard-driven dashboard of the active project right in the
terminal. Tabs for overview, hosts, services, findings, tasks, loot and journal;
navigate with arrow keys and Tab. Press `s` to cycle the status of the selected
finding or task (written back to the project), `r` refreshes, `q` quits. View and
status editing only, nothing is executed.

```bash
pip install -e ".[tui]"
pentos tui                 # or: pentos tui --project myproject
```

---

## Changelog

All versions and changes are documented in [`CHANGELOG.en.md`](CHANGELOG.en.md).
Current version: **2.25.1**.
