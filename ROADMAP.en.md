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

## Next

Concretely planned, building on what exists:

- **Structured web parsers** (gobuster/ffuf/feroxbuster/nikto), so their output
  automatically becomes findings/paths instead of just a capture.
- **Per-host detail view** in the dashboard, analogous to the finding detail view,
  with links to services, findings and notes.
- **Status history in the HTML/PDF report too** (currently in the Markdown report).

## Later

Larger chunks that deserve a fresh head:

- **AI flashcards and note summaries**, exclusively from your own project data,
  without hallucination. Learning from what you found yourself.
- **Richer screenshot handling**, e.g. direct capture or annotation instead of
  just attaching files.
- **Project export and import** as a single file, for backup, migration or
  sharing a complete workspace.
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
