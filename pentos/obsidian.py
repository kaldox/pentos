"""
Obsidian-Export für PentOS.

Erzeugt aus der DB einen Obsidian-Vault mit interner Verlinkung ([[...]]).
Struktur: Hosts/, Services/, Findings/, Credentials/, Notes/, Attack Paths/.

"""
from __future__ import annotations

from pathlib import Path

from . import graph
from .repository import Repository


def _safe(name: str) -> str:
    bad = '<>:"/\\|?*'
    out = "".join("_" if c in bad else c for c in name)
    return out.strip() or "unbenannt"


def export_vault(repo: Repository, vault_dir: Path, project: str) -> Path:
    vault_dir.mkdir(parents=True, exist_ok=True)
    for sub in ["Hosts", "Services", "Findings", "Credentials", "Notes", "Attack Paths"]:
        (vault_dir / sub).mkdir(parents=True, exist_ok=True)

    hosts = {h.id: h for h in repo.list_hosts()}
    services = repo.list_services()
    findings = repo.list_findings()
    loot = repo.list_loot()
    notes = repo.list_notes()

    # Hosts
    for h in hosts.values():
        title = h.hostname or h.address
        host_services = [s for s in services if s.host_id == h.id]
        host_findings = [f for f in findings if f.host_id == h.id]
        body = [
            f"# {title}",
            "",
            f"- **Adresse:** {h.address}",
            f"- **Hostname:** {h.hostname or '-'}",
            f"- **OS:** {h.os_guess or '-'}",
            f"- **Status:** {h.status}",
            "",
            "## Services",
        ]
        for s in host_services:
            body.append(f"- [[{_safe(f'{s.port}-{s.protocol}-{title}')}|{s.port}/{s.protocol} {s.name or ''}]]")
        body.append("")
        body.append("## Findings")
        for f in host_findings:
            body.append(f"- [[{_safe(f.title)}]] ({f.severity.value})")
        body.append("")
        body.append("#host")
        (vault_dir / "Hosts" / f"{_safe(title)}.md").write_text("\n".join(body), encoding="utf-8")

    # Services
    for s in services:
        h = hosts.get(s.host_id)
        htitle = (h.hostname or h.address) if h else f"host-{s.host_id}"
        fname = _safe(f"{s.port}-{s.protocol}-{htitle}")
        body = [
            f"# {s.port}/{s.protocol} – {s.name or 'unbekannt'}",
            "",
            f"- **Host:** [[{_safe(htitle)}]]",
            f"- **Produkt:** {s.product or '-'}",
            f"- **Version:** {s.version or '-'}",
            f"- **Tunnel:** {s.tunnel or '-'}",
            "",
        ]
        if s.extra:
            body += ["## Script-Output", "```", s.extra, "```", ""]
        body.append("#service")
        (vault_dir / "Services" / f"{fname}.md").write_text("\n".join(body), encoding="utf-8")

    # Findings
    for f in findings:
        body = [
            f"# {f.title}",
            "",
            f"- **Severity:** {f.severity.value}",
            f"- **Kategorie:** {f.category.value}",
            f"- **Status:** {f.status.value}",
            f"- **Automatisch erkannt:** {'ja' if f.auto else 'nein'}",
            "",
            "## Beschreibung",
            f.description or "_keine_",
            "",
            "#finding",
        ]
        (vault_dir / "Findings" / f"{_safe(f.title)}.md").write_text("\n".join(body), encoding="utf-8")

    # Credentials / Loot
    for l in loot:
        body = [
            f"# {l.label}",
            "",
            f"- **Typ:** {l.type.value}",
            f"- **Wert:** {l.value or '-'}",
            f"- **Quelle:** {l.source or '-'}",
            "",
            "#credential",
        ]
        (vault_dir / "Credentials" / f"{_safe(l.label)}.md").write_text("\n".join(body), encoding="utf-8")

    # Notes
    for n in notes:
        body = [f"# {n.title}", "", n.body or "", "", f"_Kategorie: {n.category or '-'}_", "", "#note"]
        (vault_dir / "Notes" / f"{_safe(n.title)}.md").write_text("\n".join(body), encoding="utf-8")

    # Attack Path (Mermaid)
    mermaid = graph.to_mermaid(repo)
    ap = [f"# Attack Path – {project}", "", "```mermaid", mermaid, "```", "", "#attackpath"]
    (vault_dir / "Attack Paths" / "Attack Path.md").write_text("\n".join(ap), encoding="utf-8")

    # Index
    index = [
        f"# {project} – Vault Index",
        "",
        f"- Hosts: {len(hosts)}",
        f"- Services: {len(services)}",
        f"- Findings: {len(findings)}",
        f"- Credentials/Loot: {len(loot)}",
        f"- Notes: {len(notes)}",
        "",
        "Erzeugt von PentOS.",
    ]
    (vault_dir / "Index.md").write_text("\n".join(index), encoding="utf-8")

    repo.log("Obsidian-Vault exportiert", str(vault_dir))
    return vault_dir
