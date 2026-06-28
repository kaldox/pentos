# Changelog

All notable changes to PentOS are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the versioning follows [Semantic Versioning](https://semver.org/).

> German version: [`CHANGELOG.md`](CHANGELOG.md)

## [2.25.1] – 2026-06-28
### Changed
- **Documentation internationalized:** the English side is now complete and
  self-contained - README, CHANGELOG, ROADMAP and COMMANDS are available in
  English (`*.en.md`), linked from the English README. The English README was
  brought to feature parity with the German one (AI configuration and install
  from the repo added, among others).
### Removed
- Baseldütsch README (`README.bl.md`) removed; PentOS is now maintained in German
  and English.
### Fixed
- `pentos graph mermaid` and `graph dot` crashed when printing to stdout if
  loot/node labels contained brackets (the Mermaid shape `[/"…"/]` was
  misinterpreted as Rich markup). Output is now printed without markup.

## [2.25.0] – 2026-06-28
### Added
- **Terminal UI (TUI):** `pentos tui` opens a keyboard-driven dashboard of the
  active project (Textual). Tabs for overview, hosts, services, findings, tasks,
  loot and journal; navigate with arrow keys/Tab. Finding and task status can be
  cycled directly with the `s` key (written to the project), `r` refreshes, `q`
  quits. View and status editing only - nothing is executed. New extra:
  `pip install -e ".[tui]"` (Textual).
### Changed
- The TUI data layer (`pentos/tui/data.py`) is deliberately separated from the
  interface and testable without a running terminal.

## [2.24.0] – 2026-06-28
### Added
- **Scan diff:** `pentos scan diff <nmap.xml>` compares a fresh nmap scan against
  the current project state and shows new hosts, new services, version changes
  and what is missing from the new scan. Read-only - nothing is imported or
  modified.
- **Loot/credential matching:** `pentos loot match [loot-id]` suggests which
  services in the project a found password, hash (pass-the-hash), SSH key or
  API key/cookie could be reused against - including ready-to-copy command
  templates and the matching runner tool. Without an argument, all matching loot
  entries are evaluated. Suggestion only, no execution.
- **Project-wide follow-up tool suggestions:** `pentos recommend` without a
  service ID now shows a project-wide overview of the runnable run shortcuts
  across all services. The same overview also appears automatically at the end of
  `scan import-nmap`, so right after an import it is clear what runs next (only
  installed tools = "ready").
- **Shell completion:** `pentos --install-completion` / `--show-completion` for
  Bash/Zsh/Fish.
### Fixed
- `pentos runs` accidentally opened the repository twice; the redundant call was
  removed.

## [2.23.0] – 2026-06-27
### Added
- **Live progress in the runner:** `pentos run` and `sweep` show a running timer
  while a tool runs (elapsed time plus remaining time until timeout) and the
  tool's last output lines, instead of blocking silently until the end. The full
  output is still captured and passed to the parsers. In non-interactive
  environments (pipes, tests) the plain behaviour is kept.

## [2.22.0] – 2026-06-27
### Added
- **Interactive web dashboard:** change finding status directly in the browser
  (per-finding dropdown, optimistic UI with save feedback) and create notes via a
  form.
- Write endpoints in the backend: `POST /api/project/{name}/finding/{id}/status`,
  `POST /api/project/{name}/notes`, and `GET /api/meta` (status list).
### Security
- **Origin check** on all write accesses: foreign websites cannot modify the local
  dashboard via drive-by (CSRF/DNS rebinding).
### Changed
- CLI help grouped into categories (`pentos --help` shows Workspace,
  Recon & Import, Findings & Docs, Reporting & Overview, AI & Integration).
- Documentation slimmed down: central command reference (`COMMANDS.md`), READMEs
  shortened to the core workflow, roadmap moved to `ROADMAP.md`.

## [2.21.0] – 2026-06-26
### Added
- **MCP server** (`pentos mcp`): makes the workspace queryable for MCP clients
  like Claude Code/Cursor. Tools: `pentos_list_projects`, `pentos_summary`,
  `pentos_findings`, `pentos_hosts`, `pentos_loot`, `pentos_notes`,
  `pentos_knowledge`. Optional extra `[mcp]`.
### Changed
- All MCP tools are strictly **read-only/analytical** - no tool runs scans or
  attacks (core guardrail).

## [2.20.0] – 2026-06-26
### Added
- **Web dashboard** (`pentos serve`): local situation overview in the browser with
  a severity donut, findings, hosts/services, loot and notes. FastAPI backend +
  self-contained frontend (offline, no CDN). Optional extra `[web]`.
- Binds to `127.0.0.1` only by default (no open attack surface).

## [2.19.0] – 2026-06-26
### Added
- **AI advisor:** `pentos ai analyze` (interpret a scan/log/output + next steps,
  also via stdin) and `pentos ai next` (suggestions based on project state).
- Advisor toggle (`ai config --advisor/--no-advisor`).
### Security
- Privacy prompt before sending to the AI; with cloud providers a clear warning
  that data leaves the machine (local Ollama stays private).

## [2.18.0] – 2026-06-25
### Added
- **Evidence/screenshots in reports:** evidence attached to a finding is embedded
  in HTML (base64 inline), PDF (reportlab) and Markdown.

## [2.17.0] – 2026-06-18
### Changed
- **nuclei parser** rewritten: only Low+ become findings (clean title), Info hits
  as a single summary note instead of many noise findings.
### Added
- `pentos note show <id>` (show note content).
- `--severity` as an alias for `--sev` on `finding add`.

## [2.16.0] – 2026-06-18
### Added
- **Scanner import** (`pentos scan import-scanner`): Nessus, OpenVAS/Greenbone and
  Burp Suite (auto-detection or `--format`), incl. host/finding dedup, CVSS and
  remediation.

## [2.15.0] – 2026-06-17
### Added
- **Finding template library** (`pentos template ...`): reusable templates with
  CVSS and remediation, pre-filled from the knowledge base and extensible;
  CVSS/remediation appear in reports.

## [2.14.0] – 2026-06-16
### Added
- **HTML and PDF reports** (`pentos report --html` / `--pdf`), branding optional
  via the configuration. PDF via the optional extra `[pdf]` (reportlab).

## [2.13.0] – 2026-06-16
### Added
- **Learning report** (`pentos report --explain`): didactic report from the
  curated knowledge base (no AI generation).

## [2.12.0] – 2026-06-16
### Changed
- **enum4linux parser** hardened against real domain controller data (group
  counting, domain SID, krbtgt/Kerberoast detection).

## [2.11.0 and earlier] – 2026-06-09 to 2026-06-16
### Added
- Foundation: per-project pentest workspace, journal, tasks, findings, loot,
  evidence, knowledge base.
- Recommendation engine and guided recon/enum chain (`sweep`).
- Opt-in runner layer (tool execution on demand, no shell eval, scope guard).
- Methodology/playbook library (Web/AD/Linux/Windows privesc).
- Attack-path graph (Mermaid/DOT), Obsidian export.
- nmap XML import, local AI mentor (Ollama) with offline fallback, RAG over your
  own project data.

[2.22.0]: https://github.com/kaldox/pentos/releases
[2.21.0]: https://github.com/kaldox/pentos/releases
[2.20.0]: https://github.com/kaldox/pentos/releases
[2.19.0]: https://github.com/kaldox/pentos/releases
[2.18.0]: https://github.com/kaldox/pentos/releases
