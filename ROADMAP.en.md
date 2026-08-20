# Roadmap

This roadmap shows where PentOS is heading. It is deliberately honest: what is
done lives in the [changelog](CHANGELOG.en.md); this is about what is still to
come. Order and scope may change. PentOS is a hobby project, not a product with a
delivery date.

> German version: [`ROADMAP.md`](ROADMAP.md)

## Recently shipped

For context, what was added most recently (details in the changelog):

- Scanner import (Nessus / OpenVAS / Burp) with dedup, CVSS and remediation
- Evidence and screenshots directly in the reports (HTML, PDF, Markdown)
- AI advisor: interpret scans and logs, suggest next steps
- Web dashboard with a local situation overview (`pentos serve`)
- Interactive dashboard: change finding status and create notes in the browser
- MCP server: query the workspace from Claude Code or Cursor (read-only)
- Scan diff: compare an nmap scan against the project state (`scan diff`)
- Loot/credential matching: suggest loot against matching services (`loot match`)
- Project-wide follow-up tool suggestions after import and via `recommend` without an argument
- Status history / retest tracking for findings (`finding history`, `--note`)
- Dashboard detail view per finding with a status timeline
- Attack-path graph rendered visually in the web dashboard ("Attack path" tab)
- AI overhaul: output language, auto model-per-task/fallback, persona, streaming, temperature/verbosity and an AI panel in the dashboard
- Structured web parsers for gobuster/ffuf/feroxbuster: security-relevant paths
  (VCS directories, secrets, backups, admin interfaces) automatically become
  findings instead of just a raw note
- Host detail view in the dashboard (drawer with services, findings, notes, loot)
- Project export/import (`project export`/`project import`): whole workspace
  as a single ZIP file, for backup, migration or sharing
- Command palette (Ctrl+K) in the web dashboard: global fuzzy search over
  hosts/findings/notes plus quick actions
- Structured nikto parser (XML report): security-relevant hits automatically
  become findings with a heuristic severity, header noise gets collected into
  a note instead of spamming findings
- BloodHound data import (`scan import-bloodhound`): read a SharpHound export
  (ZIP or folder) and turn it into findings for kerberoastable/AS-REP-roastable
  accounts, unconstrained delegation and Domain Admins membership
- Status history in the HTML/PDF report too (previously only in the Markdown report)
- BloodHound attack path in the dashboard graph: Domain Admins, kerberoastable
  and AS-REP-roastable accounts, and unconstrained delegation as their own
  graph section next to hosts/services/findings
- Risk score with a transparent formula (severity-weighted sum, closed
  findings don't count) plus a chart in the dashboard, Markdown, HTML and PDF
  report
- Engagement timeline (`pentos timeline add/list/rm`): track milestones, test
  windows and blackout periods per project, shown in all three report formats
- **testssl.sh parser**: structured TLS/SSL checks (protocols, weak ciphers,
  certificate chain, Heartbleed/ROBOT/POODLE etc.) straight from the native
  JSON report - severity comes from the tool itself, no heuristic needed
- **ProjectDiscovery parsers** (`httpx`/`naabu`/`dnsx`): native JSON instead
  of text format, `httpx` includes tech detection - land as a structured
  recon note (not a vulnerability scan, so no findings)
- **EPSS enrichment for findings** (`finding epss`): CVE references found in
  title/description get looked up against the FIRST API - CVSS says how bad
  a flaw could be, EPSS says how likely it actually gets exploited in the
  next 30 days. Opt-in like cloud AI calls.
- **Proxychains support in the runner** (`pentos run <tool> <target> --proxy
  "proxychains4 -q"`): for the real pivot case after a foothold into an
  internal network - deliberately no Tor/anonymization support, see
  "Deliberately not planned"
- **Default wordlists** (`pentos wordlists setup`): a generic username list
  ships with the package, a short password list (SecLists `rockyou-75.txt`)
  is fetched opt-in from the official source instead of being bundled in the
  repo - `hydra`/`medusa` suggestions in `recommend` now point at these paths
- **AI proposes, you confirm** (`ai next --act`): the advisor's answer gets
  scanned for executable `pentos run …` suggestions, which you pick from and
  confirm individually - speeds up manual work without the AI ever starting
  anything itself
- **gitleaks integration**: secret scanning against a local repo dump
  (`pentos run gitleaks <path>`), a thematic follow-up to the `.git`
  exposure detector - hits become findings (with a masked secret preview)
  and loot (with the full value)
- **MITRE ATT&CK mapping** (`pentos finding attack <id> <technique>`): an
  optional technique tag per finding, purely manual/curated (PentOS only
  checks the ID format, not against the real matrix - no drift risk on
  ATT&CK revisions). Export as an official Navigator layer JSON
  (`report --attack-navigator`), loadable straight into the real ATT&CK
  Navigator app.
- **Engagement policy for bug bounty programs** (`pentos policy setup`):
  set per-project program rules (brute-force/active exploitation/offline
  cracking/automated tools allowed?) - enforceable answers block the
  matching runner category in `run`/`sweep --run` (override like the scope
  guard, via `--force`), non-enforceable ones (DoS testing, social
  engineering, production-only, rate limits) land as documentation in the
  report. A memory aid/self-protection, not a compliance guarantee.
- **Simplified brute-force wordlists** (`pentos run --userlist/--passlist/
  --proto`): a tool-agnostic shorthand for hydra/medusa/nxc-smb/nxc-winrm
  instead of hand-assembling `--args`, with automatic fallback to the
  project's wordlists and a clear error when those are missing - fixes a
  broken `recommend` suggestion (hardcoded relative path) found during
  real-world testing.
- **`--proto-extra` for hydra web forms** (`pentos run hydra ... --proto
  http-post-form --proto-extra "..."`): module extra parameters for
  `http-post-form`/`http-get-form`, combinable with `--userlist`/
  `--passlist`/`--proto` instead of having to fall back to `--args` entirely.
- **Deliberate downsizing after a critical architecture audit:** removed the
  TUI, Obsidian export, vision/image analysis, the knowledge base as its own
  CRUD subsystem (duplicated `note add`), and the wordlist catalog
  downloader - none of them carried the actual core (Scope → Recon → Finding
  → Evidence → Retest → Report), each was extra upkeep without proportional
  value. Goal: less surface area, so the core gets better instead of
  everything staying merely "fine".

## Next

Nothing concrete newly planned right now - the items that used to live here
all landed in "Recently shipped". Suggestions welcome via the
[issues](https://github.com/kaldox/pentos/issues).

## Later

Larger chunks that deserve a fresh head:

- **AI flashcards and note summaries**, exclusively from your own project data,
  without hallucination. Learning from what you found yourself.
- **Richer screenshot handling**, e.g. automated screenshots via `gowitness`
  (headless-Chrome screenshot tool, fits the runner/parser pattern) instead of
  only manually attached files.
- **AzureHound support** for the BloodHound import (Entra ID has a different
  schema than SharpHound, not covered yet). Research attempt on 2026-08-16:
  the schema is substantially bigger/more complex than SharpHound's (follows
  the full Microsoft Graph API object model, a single User node has 60+
  fields), and the official docs don't include a concrete example JSON.
  Confirmed so far: an `IngestRequest{Meta{Type,Version,Count}, Data}`
  wrapper exists, Global Admin detection goes through a `roleTemplateId`.
  A clean implementation needs either real test-tenant access or a
  published sample export to verify against - deliberately not built on a
  guess, to keep the "schema verified, not guessed" standard the other
  importers/parsers hold to.
- **More structured parsers** for additional tools, so their output automatically
  becomes hosts, services and findings.

## Deliberately not planned

This is not an oversight but intent and part of the idea of PentOS:

- **No autonomous execution of attacks.** The AI analyzes and suggests; only what
  the human triggers is started. `ai next --act` still fits this: it shows
  suggestions, execution only ever happens after an explicit per-step
  confirmation. A real "auto-hack" mode (chaining without confirmation) is
  not coming.
- **No Tor/anonymization support against the target.** Proxychains is
  supported, but only for the legitimate pivot case (SOCKS through a
  foothold into an internal network). Deliberately anonymizing traffic
  against an authorized test target undermines the accountability a rules-
  of-engagement is meant to guarantee - and it's technically unsuited for
  real scanning anyway (latency, blocked exit nodes).
- **No cloud requirement.** PentOS stays local-first and runnable without external
  services; a cloud connection will never be a prerequisite.
- **No replacement for your own understanding.** The learning reports and the
  advisor explain; they do not do the thinking for you.

---

An idea missing here? Suggestions are welcome via the
[issues](https://github.com/kaldox/pentos/issues).
