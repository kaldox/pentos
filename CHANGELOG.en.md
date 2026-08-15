# Changelog

All notable changes to PentOS are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and the versioning follows [Semantic Versioning](https://semver.org/).

> German version: [`CHANGELOG.md`](CHANGELOG.md)

## [2.33.0] – 2026-08-15
### Added
- **BloodHound attack path in the dashboard graph:** the SharpHound import
  (`scan import-bloodhound`) now also lands in the project DB in structured
  form (new `bloodhound_imports` table) in addition to findings/notes, and
  renders as its own graph section in the web dashboard next to
  hosts/services/findings: domain → Domain Admins / kerberoastable accounts /
  AS-REP-roastable accounts / unconstrained delegation → affected members.
  `GET /api/project/{name}/graph` now returns an extra `ad` field (`null`
  without an import).
- **Risk score with chart:** new module `pentos/risk.py` computes a
  transparent, documented risk score from the currently open findings
  (severity weighting: Critical=10/High=6/Medium=3/Low=1/Info=0, summed;
  closed/false-positive findings deliberately don't count — plain arithmetic
  over project data, no AI/cloud call). Now shown in the summary of all three
  report formats (Markdown line, HTML with an inline SVG donut chart, PDF
  with a native reportlab pie chart) and at the top of the web dashboard
  overview.
- **Engagement timeline (`pentos timeline add/list/rm`):** track milestones,
  test windows and blackout periods per project (title, kind, start/end,
  note — e.g. an escalation contact). Shown as its own section in the
  Markdown, HTML and PDF report whenever entries exist.

## [2.32.0] – 2026-08-15
### Added
- **Status history in the HTML/PDF report too:** a finding's status history
  (retest tracking, previously only in the Markdown report) now also shows
  up in `pentos report --html` and `--pdf` — every real status change with
  timestamp, old/new status and an optional note, right under the finding's
  description. The initial "created" entry is omitted just like in the
  Markdown report; the section is skipped entirely when there are no status
  changes. Data is collected once in `export._collect()`
  (`history_by_finding`), shared by both HTML and PDF. 3 new tests in
  `tests/test_status_history.py`.

## [2.31.1] – 2026-08-15
### Fixed
Systematic bug hunt across the whole codebase (multi-agent review, 6 finder
passes + independent re-verification against real code/fixtures). All ten
findings covered with a regression test, 173/173 tests green.

- **[Critical] Zip-slip on project import (`pentos/archive.py`):**
  `pentos project import <file.zip>` without `--name` took the destination
  folder from the **unvalidated** `project` field in the ZIP manifest. A
  crafted archive with `"project": "../../../../someone/elses/path"` (or an
  absolute path) could bypass the entire zip-slip check and write files
  outside the workspace — exactly the "share an export with someone"
  scenario makes this exploitable. The project name is now validated (no
  path separators, no `..`, no absolute path), and the resulting destination
  is additionally re-checked against `projects_dir()`.
- **AI cloud consent missing on two commands:** `ai explain-finding` and
  `ai enum` sent finding/service data straight to the AI without the
  confirm-before-sending-to-cloud prompt (`_confirm_ai_send`) every other AI
  command goes through. Both commands now use the same consent gate as
  `ai analyze`/`ai next`/`ai analyze-image`.
- **SMB share detection broke on backslash-escaped names (`ADMIN\$`,
  `IPC\$`):** the share-header regex in the enum4linux-ng parser didn't
  allow a backslash, which real enum4linux-ng output uses for default
  shares. Share "type" stayed `?` forever, and the exclusion of `IPC$` from
  the "anonymously readable share" finding never fired (a false-positive
  finding for perfectly normal IPC$ null-session access). Names are now
  normalized.
- **Open SQLite transaction after a duplicate insert:** `add_host()`/
  `add_service()` caught `IntegrityError` on duplicates but never called
  `rollback()` — the transaction stayed open and could block a second,
  concurrently running connection (e.g. `pentos serve`/TUI next to a
  `scan import-nmap`) with "database is locked".
- **`pentos scan import-bloodhound` crashed on stray JSON files:** a
  `*.json` file with a top-level array/scalar in the export folder made the
  import crash with `AttributeError` instead of being skipped, as the
  module's own docstring promises.
- **`pentos finding add --host/--service` with an invalid ID:** crashed
  with a raw `sqlite3.IntegrityError` traceback (foreign-key violation)
  instead of a clean error message, and the DB connection wasn't closed.
  Now validated upfront, matching `template apply --host`.
- **`pentos report --html --out <path>` silently ignored the path** when
  the extension wasn't exactly `.html`, writing to `reports/report.html`
  instead with no warning. `--out` is now always honored, like `--pdf`.
- **CVSS score 0.0 on Nessus import:** `cvss = v3 or v2` treated a valid
  CVSSv3 score of `0.0` as falsy and wrongly replaced it with the (higher)
  CVSSv2 score.
- **Command palette (Ctrl+K) lost short subtitle matches:** the additive
  penalty for subtitle matches (`- 2`) could push a genuine but short match
  (e.g. searching `w` against the subtitle "switch view") below zero and
  drop it from the results. Now a multiplicative penalty (`× 0.5`) that can
  never turn a positive score negative.

## [2.31.0] – 2026-08-15
### Added
- **BloodHound data import** (`pentos scan import-bloodhound <export>`,
  BloodHound CE / on-prem AD): reads a SharpHound export (a ZIP archive, the
  way SharpHound produces it, or an already-unpacked folder) and turns it
  into findings — kerberoastable accounts (SPN set), AS-REP-roastable
  accounts (Kerberos preauth disabled), unconstrained delegation (users and
  computers), and Domain Admins membership (detected via the well-known RID
  `-512`, independent of domain name/locale). `--host` optionally links
  findings/note to a host (e.g. the domain controller). PentOS does **not**
  rebuild a graph — that stays BloodHound's job; for full attack-path
  analysis it points to the real BloodHound UI. New module
  `pentos/importers/bloodhound.py`. Schema (data/meta wrapper per file,
  lowercase properties like `hasspn`/`dontreqpreauth`/`enabled`, a
  `Members` array per group) verified against the official SharpHound
  documentation and multiple independent sources, not guessed. Only
  SharpHound (on-prem AD) is supported — AzureHound (Entra ID) has a
  different schema and is noted as an open roadmap item. 16 new tests
  (`tests/test_bloodhound_importer.py`, `tests/test_cli_bloodhound.py`)
  with a hand-built but schema-accurate fixture under
  `tests/fixtures/sharphound/`.

## [2.30.0] – 2026-08-15
### Added
- **Structured nikto parser:** `nikto` now runs with `-o {outfile} -Format
  xml` instead of plain capture. The new parser (`_parse_nikto` in
  `pentos/runners/parsers.py`) reads the XML report's `<item>` elements
  (schema taken from the official `nikto_report_xml.plugin`, robust against
  arbitrary nesting depth via `root.iter()` and against known nikto XML
  quirks on malformed documents). Common header noise (missing
  `X-Frame-Options`, `X-Content-Type-Options`, etc.) is collected into a
  single note instead of spamming findings — same as the nuclei parser.
  Everything else becomes a finding with a heuristically derived severity
  (nikto itself provides no CVSS): CVE references, SQLi/XSS/command
  injection etc. → High, RCE hints → Critical, outdated software/directory
  listing/phpinfo/backup files → Medium, everything else → Low. New test
  fixture `tests/fixtures/nikto_scan.xml` (built to match the confirmed
  nikto XML schema) and `tests/test_nikto_parser.py` (6 tests: parsing,
  noise filtering, severity heuristics, path/references in the
  description, no duplicates on a second run).

## [2.29.0] – 2026-08-14
### Added
- **Project export/import:** `pentos project export [name]` packs the whole
  workspace (database + all subfolders: scans/, screenshots/, evidence/,
  notes/, loot/, findings/, reports/, ...) into a single ZIP file — for
  backup, moving to another machine, or sharing a project. `pentos project
  import <file.zip>` restores such a file as a (new) project, with `--name`
  for a different target name and `--force` to overwrite a project of the
  same name; `--no-activate` skips setting it active after import. New
  module `pentos/archive.py`: export writes to a temporary file first
  (prevents a destination path inside the project folder from packing
  itself), import checks every entry for zip-slip (paths that escape the
  destination folder) before extracting anything, and rejects archives
  without `database/pentos.db` as invalid. Note: evidence files outside the
  project folder are not included. 14 new tests in `tests/test_archive.py`
  (module and CLI level).
- **Command palette (Ctrl+K) in the web dashboard:** global fuzzy search over
  the active project's hosts, findings and notes plus quick actions
  (currently "add a new note"), the way Linear/Vercel/Raycast do it — the
  web counterpart to the already keyboard-driven TUI. Open with
  `Ctrl+K`/`Cmd+K` or by clicking the new "Jump to …" button in the topbar;
  navigate with arrow keys, select with Enter, close with Escape or a click
  outside. Results cover views (overview/findings/hosts/…), findings (jumps
  to the finding detail view), hosts (jumps to the host detail view) and
  notes; data is reloaded fresh every time it opens. Frontend-only
  (`pentos/web/static/{index.html,app.js,style.css}`), no new backend
  endpoints — reuses the existing `findings`/`hosts`/`notes` routes.
  Functionally verified against a real browser (fuzzy search across every
  entry type, keyboard navigation, all three open/close paths, no console
  errors); since the project has no JS test runner, the new test
  `test_command_palette_markup_and_wiring_served` at least checks that the
  markup and core functions are actually served.

## [2.28.1] – 2026-08-14
### Fixed
- **Crash on non-UTF-8 Windows consoles:** `pentos project list` marked the
  active project with "●" (U+25CF). When stdout runs under a non-UTF-8
  codepage (e.g. cp1252, the Windows default – or when `pentos`/
  `python -m pentos` is invoked as a subprocess without `PYTHONUTF8=1`/
  `PYTHONIOENCODING=utf-8`), Rich wrote the character raw to the stream and
  a `UnicodeEncodeError` made the command crash instead of showing the
  table. Replaced every Unicode-only marker in `pentos/cli/app.py`
  (●/→/▶/✓/✗/⚠/█/░ plus three emoji icons in the playbook legend) and the
  equivalent spots in `pentos/runners/base.py` (live spinner, ⏱, ✓) and
  `pentos/tui/app.py` (●, ⚠, →, █/░) with ASCII substitutes (`*`, `->`,
  `>>`, `x`, `!`, `#`/`-`, …). New test `tests/test_cli_encoding.py`:
  reproduces the cp1252 console directly (failed with the same
  `UnicodeEncodeError` as the bug report before the fix) plus a static
  guard against future non-ASCII markers in the three files.

## [2.28.0] – 2026-08-14
### Added
- **Structured web-path parser** (`gobuster`/`ffuf`/`feroxbuster`): hits used
  to be stored only as a raw note. PentOS now recognizes security-relevant
  paths – exposed `.git`/`.svn`/`.hg` directories, `.env`/`.htpasswd`/private
  SSH keys, backup/legacy files (`.sql`/`.bak`/`.zip`/…), `web.config`, and
  admin/DB management interfaces (phpMyAdmin, Adminer, wp-admin, …) – and
  automatically creates findings with matching severity/category for them
  (only for reachable status codes 200/204/301/302/401/403; duplicates are
  skipped). Modeled after the existing nuclei/enum4linux-ng parsers. New test
  `tests/test_gobuster_parser.py`.
- **Host detail view in the web dashboard:** clicking a host address under
  "Hosts & Services" opens a drawer (following the existing finding detail
  view) with all its services, linked findings (directly on the host as well
  as via its services), notes and loot. New API endpoint
  `GET /api/project/{name}/host/{hid}` in `pentos/web/server.py`; findings
  inside the drawer are themselves clickable and open the full finding
  detail view. Three new tests in `tests/test_web_dashboard.py`.

## [2.27.2] – 2026-08-14
### Fixed
- **MCP server with the current SDK:** `mcp.server.fastmcp.FastMCP` was removed in
  MCP SDK 2.0; since `pyproject.toml` allowed `mcp>=1.0`, 2.x got installed and
  `pentos mcp` aborted with "MCP-SDK fehlt". Constrained the dependency to
  `mcp>=1.0,<2.0` until the code is migrated to the 2.x API.
### Added
- **CI workflow** (`.github/workflows/ci.yml`): matrix build against Python 3.10,
  3.11 and 3.12 with `compileall` (syntax guard) and `pytest`.

## [2.27.1] – 2026-07-13
### Fixed
- **Report export on Python 3.10/3.11:** a nested f-string with escaped quotes in
  `export.py` is only valid from Python 3.12 onwards and raised a `SyntaxError` on
  3.10/3.11 – the whole `export` module failed to import (HTML/PDF report broken).
  The expression is now built into a variable beforehand, so export works again
  with the minimum version declared in `pyproject.toml` (3.10).

## [2.27.0] – 2026-06-28
### Added
- **AI output language:** selectable (Deutsch, English, Español, Français, 中文, हिन्दी,
  العربية, Português, Русский, 日本語 or free text). Asked once on first AI use, then
  stored in the config; overridable per call via `--lang`. Technical terms, CVE IDs and
  tool/command names optionally stay in the original (`keep_terms`).
- **Automatic per-task model selection** (`ai config --auto-model`): for each task
  (analyze/next/explain/enum/ask/vision) the best installed model is picked from a
  preference list. Explicit mapping via `--model-for analyze=deepseek-r1:14b`.
- **Fallback chain:** if a model fails or is missing, the next candidate is tried.
- **Persona / customizable prompt** (`ai config --persona "..."`), also settable in the
  dashboard.
- **Streaming output** in the CLI (`--stream` on analyze/next/ask) with a live filter
  for `<think>` reasoning blocks (deepseek-r1 et al.).
- **Temperature & verbosity** configurable (`--temperature`, `--verbosity concise|normal|detailed`).
- **Vision:** `pentos ai analyze-image <image>` analyses screenshots with a vision model
  (e.g. qwen3-vl); `--vision-model` or auto-selection.
- **AI in the dashboard:** new "AI" tab with "Ask your project" (RAG) and a settings
  panel for language, verbosity, temperature, auto-model and persona.
- New API endpoints: `GET/POST /api/ai/config` and `POST /api/project/{name}/ai/ask`.

### Changed
- The whole AI chat path now runs through one central method (model selection,
  language, persona, temperature, streaming, vision in one place).

## [2.26.0] – 2026-06-28
### Added
- **Status history / retest tracking:** every status change of a finding is
  recorded with a timestamp and an optional note (including the initial entry at
  creation). New command `pentos finding history <id>` shows the timeline;
  `pentos finding status <id> <status> --note "..."` records the rationale. The
  status history also appears in the Markdown report. Status changes via the TUI
  and the web dashboard feed into the history automatically.
- **Dashboard detail view:** clicking a finding title opens a drawer with
  description, remediation, CVSS, evidence and the full status timeline; status
  changes can be made right there, including a note field.
- **Attack path, visual:** new "Attack path" tab in the web dashboard renders
  hosts → services → findings as an SVG graph (findings in their severity colour,
  clickable for the detail view). Offline, no CDN.
- New API endpoints: `GET /api/project/{name}/finding/{id}` (detail incl. history
  and evidence) and `GET /api/project/{name}/graph` (graph data). The status
  endpoint now accepts an optional `note` field.

## [2.25.2] – 2026-06-28
### Changed
- `template apply --host` now accepts both the host ID and the host address
  (previously address only) - consistent with `finding add --host`, which takes
  the ID. So `--host 1` works just like `--host 10.10.10.5`.
### Added
- `--category` as an alias for `--cat` on `note add` and `finding add`.

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
