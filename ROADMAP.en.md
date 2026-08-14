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
- Terminal UI (`pentos tui`): keyboard-driven dashboard with status editing
- Status history / retest tracking for findings (`finding history`, `--note`)
- Dashboard detail view per finding with a status timeline
- Attack-path graph rendered visually in the web dashboard ("Attack path" tab)
- AI overhaul: output language, auto model-per-task/fallback, persona, streaming, temperature/verbosity, vision (analyze-image) and an AI panel in the dashboard
- Structured web parsers for gobuster/ffuf/feroxbuster: security-relevant paths
  (VCS directories, secrets, backups, admin interfaces) automatically become
  findings instead of just a raw note
- Host detail view in the dashboard (drawer with services, findings, notes, loot)
- Project export/import (`project export`/`project import`): whole workspace
  as a single ZIP file, for backup, migration or sharing
- Command palette (Ctrl+K) in the web dashboard: global fuzzy search over
  hosts/findings/notes plus quick actions

## Next

Concretely planned, building on what exists:

- **Structured nikto parser**, so its hits also automatically become findings
  instead of just a capture (following the new gobuster/ffuf/feroxbuster parser).
- **Status history in the HTML/PDF report too** (currently in the Markdown report).
- **ProjectDiscovery parsers** (`httpx`/`naabu`/`dnsx`): all three can output
  native JSON, which makes for more robust parsers than gobuster's text
  format. `httpx` includes tech detection, `naabu` is very fast port
  discovery, `dnsx` resolves DNS.
- **EPSS enrichment for findings**: findings with a CVE/CVSS also get an EPSS
  score (free FIRST API) – CVSS says how bad a flaw could be, EPSS says how
  likely it actually gets exploited in the next 30 days. Like cloud AI calls,
  with an explicit notice that a request leaves the machine (opt-in).

## Later

Larger chunks that deserve a fresh head:

- **AI flashcards and note summaries**, exclusively from your own project data,
  without hallucination. Learning from what you found yourself.
- **Richer screenshot handling**, e.g. automated screenshots via `gowitness`
  (headless-Chrome screenshot tool, fits the runner/parser pattern) instead of
  only manually attached files.
- **gitleaks integration**: secret scanning as its own findings source –
  a thematic follow-up to the `.git` exposure detector from 2.28.0: when an
  open `.git` is found, suggest running `gitleaks` against a dump and turn its
  hits into credential/info-disclosure findings.
- **BloodHound data import**: ingest SharpHound/AzureHound JSON and turn it
  into findings ("kerberoastable accounts", domain admin count, AS-REP
  roasting possible) plus a link to the real BloodHound view – PentOS
  interprets the data instead of rebuilding BloodHound.
- **Engagement timeline**: every project workspace already gets a
  `timelines/` folder that no feature uses yet – capture rules-of-engagement
  basics (time windows, blackout periods, escalation path) and project
  milestones there in a structured way.
- **More structured parsers** for additional tools, so their output automatically
  becomes hosts, services and findings.

## Deliberately not planned

This is not an oversight but intent and part of the idea of PentOS:

- **No autonomous execution of attacks.** The AI analyzes and suggests; only what
  the human triggers is started. An "auto-hack" mode is not coming.
- **No cloud requirement.** PentOS stays local-first and runnable without external
  services; a cloud connection will never be a prerequisite.
- **No replacement for your own understanding.** The learning reports and the
  advisor explain; they do not do the thinking for you.

---

An idea missing here? Suggestions are welcome via the
[issues](https://github.com/kaldox/pentos/issues).
