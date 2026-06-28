# PentOS command reference

Complete overview of all commands, grouped as in `pentos --help`. The commands are
identical in every language version.

> German version: [`COMMANDS.md`](COMMANDS.md)

> The living reference is the CLI itself: `pentos --help` shows all groups,
> `pentos <group> --help` (e.g. `pentos finding --help`) shows the subcommands
> with their options.

## Workspace

```bash
pentos project new <name>            # create a project workspace (becomes active)
pentos project list                  # all projects
pentos project use <name>            # switch the active project
pentos scope add 10.10.10.0/24       # allowed target (CIDR or hostname)
pentos scope list                    # show scope
pentos host list                     # hosts
pentos service list                  # services
```

## Recon & Import

```bash
# Import
pentos scan import-nmap scan.xml                 # import nmap XML (-oX)
pentos scan import-scanner report.nessus         # Nessus/OpenVAS/Burp (auto-detected)
pentos scan import-scanner gvm.xml --format openvas   # force the format
pentos scan diff rescan.xml                       # nmap scan vs. project state (read-only)

# Recommendations (suggestion only, no execution)
pentos recommend                     # project-wide run shortcuts across all services
pentos recommend 4                   # next steps for service 4  (--create-tasks)

# Run tools (opt-in)
pentos tools                         # available tools + install check
pentos run nmap 10.10.10.10          # run a tool, output is ingested
pentos run nmap 10.10.10.10 --profile full     # basic | standard | full | custom
pentos run nmap 10.10.10.10 --args "-p- -T4"   # pass extra arguments through
pentos run nmap 10.10.10.10 --dry-run          # only show the command
pentos run nmap 10.10.10.10 --shell            # shell mode (only with trusted input!)
pentos runs                          # history of all runs

# Guided recon/enum chain
pentos sweep 10.10.10.10             # preview: the chain as ready commands
pentos sweep 10.10.10.10 --run       # run safe enum tools (prompt per step)
pentos sweep 10.10.10.10 --run --yes # run through without prompts

# Methodology playbooks (checklists)
pentos playbook list                 # available playbooks
pentos playbook show web --target 10.10.10.10   # checklist, commands with target
pentos playbook check web ports      # check off a step (--note "...", --skip)
pentos playbook uncheck web ports    # remove the check
pentos playbook status               # progress across all playbooks
```

> **Safe tools** can run automatically on `sweep --run` (with a prompt),
> **brute-force/exploits never** automatically, only as a suggestion. Tools run
> without a shell (fixed `argv`, no metacharacter eval). `--shell` deliberately
> enables a real shell and is only to be used with trusted input.

## Findings & Docs

```bash
# Findings
pentos finding list
pentos finding status 4 confirmed    # set status
pentos finding status 4 closed --note "retest ok, fixed"    # with rationale
pentos finding history 4             # status timeline (retest tracking)
pentos finding rm 4

# Finding templates (reusable, per project)
pentos template seed                 # pre-fill from the knowledge base (idempotent)
pentos template list
pentos template show pwn3d           # detail (description, remediation, CVSS)
pentos template apply pwn3d --host 10.10.10.5 --suffix "(10.10.10.5)"  # template -> finding
pentos template add ...              # add your own template

# Loot, evidence, notes, knowledge
pentos loot add "admin:Passw0rd" --type cred --host 1 --source smb
pentos loot list
pentos loot match                    # suggest all loot entries against matching services
pentos loot match 1                  # only loot #1 (spray / pass-the-hash / key login)
pentos evidence add ./shot.png --kind screenshot --finding 4
pentos note show <id>                # show note content
pentos knowledge add Jenkins "Script Console RCE" --body "Groovy under /script"

# Tasks
pentos task list
pentos task start 12
pentos task done 12
```

## Reporting & Overview

```bash
pentos dashboard                     # compact CLI overview of the project
pentos tui                           # interactive terminal dashboard (Textual); s=status, r=refresh, q=quit
pentos report                        # Markdown report under <project>/reports
pentos report --html                 # branded HTML (printable in the browser)
pentos report --pdf                  # branded PDF (needs reportlab)
pentos report --explain              # learning report: explains each step didactically
pentos graph mermaid --out attack_paths/ap.mmd
pentos graph dot --out attack_paths/ap.dot       # dot -Tpng ap.dot -o ap.png
pentos obsidian                      # Obsidian vault under <project>/obsidian
```

## AI & Integration

```bash
# AI mentor & advisor (local; without a model -> offline fallback)
pentos ai status                     # backend status
pentos ai config --provider ollama --base-url http://127.0.0.1:11434 --model llama3.1
pentos ai explain-finding 4
pentos ai enum 4
pentos ai analyze scan.txt --as nmap # interpret a scan/log (--text, stdin, --save)
pentos ai next                       # suggestions based on project state

# "Ask your project" (RAG over your own data)
pentos ai config --embed-model nomic-embed-text
pentos ai index                      # build the index over the active project
pentos ai ask "Where is the SSH key for kenobi?"

# Web dashboard
pentos serve                         # http://127.0.0.1:8787
pentos serve --port 9000 --project myproject

# MCP server (for Claude Code / Cursor)
pentos mcp                           # stdio server (read-only)
```

---

Set up shell completion (Bash/Zsh/Fish):

```bash
pentos --install-completion          # install completion for the current shell
pentos --show-completion             # only print the completion script (to copy)
```

---

Tip: each group has its own help, e.g. `pentos ai --help` or `pentos run --help`,
with all options and defaults.
