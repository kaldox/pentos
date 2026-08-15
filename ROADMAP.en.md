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

## Next

Concretely planned, building on what exists:

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
- **AzureHound support** for the BloodHound import (Entra ID has a different
  schema than SharpHound, not covered yet).
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
