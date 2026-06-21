"""
Attack-Path-Graph für PentOS.

Erzeugt aus den DB-Beziehungen (Host -> Service -> Finding / Loot) Diagramme
in Mermaid und Graphviz-DOT. Keine externen Tools nötig (nur Textausgabe).

"""
from __future__ import annotations

from .models import SEVERITY_ORDER, Severity
from .repository import Repository


def _mm_id(prefix: str, n: int) -> str:
    return f"{prefix}{n}"


def _esc(text: str) -> str:
    text = (text or "").replace("\n", " ")
    # Zeichen entfernen/ersetzen, die Mermaid-Node-Labels brechen können
    for ch in ['"', "[", "]", "{", "}", "|", "<", ">", "(", ")"]:
        text = text.replace(ch, " ")
    return " ".join(text.split())


def to_mermaid(repo: Repository) -> str:
    lines = ["graph TD"]
    hosts = repo.list_hosts()
    services = repo.list_services()
    findings = repo.list_findings()
    loot = repo.list_loot()

    for h in hosts:
        label = h.hostname or h.address
        lines.append(f'    {_mm_id("H", h.id)}["🖥️ {_esc(label)}<br/>{_esc(h.address)}"]')

    for s in services:
        svc_label = f"{s.port}/{s.protocol} {s.name or ''}".strip()
        lines.append(f'    {_mm_id("S", s.id)}(["🔌 {_esc(svc_label)}"])')
        lines.append(f'    {_mm_id("H", s.host_id)} --> {_mm_id("S", s.id)}')

    for f in findings:
        lines.append(f'    {_mm_id("F", f.id)}{{"⚠️ {_esc(f.title)}<br/>[{f.severity.value}]"}}')
        if f.service_id:
            lines.append(f'    {_mm_id("S", f.service_id)} --> {_mm_id("F", f.id)}')
        elif f.host_id:
            lines.append(f'    {_mm_id("H", f.host_id)} --> {_mm_id("F", f.id)}')

    for l in loot:
        lines.append(f'    {_mm_id("L", l.id)}[/"🔑 {_esc(l.label)}"/]')
        if l.host_id:
            lines.append(f'    {_mm_id("H", l.host_id)} --> {_mm_id("L", l.id)}')

    return "\n".join(lines)


def to_dot(repo: Repository) -> str:
    lines = ["digraph attack_path {", '    rankdir=TB;', '    node [fontname="Helvetica"];']
    hosts = repo.list_hosts()
    services = repo.list_services()
    findings = repo.list_findings()
    loot = repo.list_loot()

    sev_color = {
        Severity.CRITICAL: "#c0392b",
        Severity.HIGH: "#e67e22",
        Severity.MEDIUM: "#f1c40f",
        Severity.LOW: "#3498db",
        Severity.INFO: "#95a5a6",
    }

    for h in hosts:
        label = _esc(h.hostname or h.address)
        lines.append(f'    H{h.id} [shape=box, style=filled, fillcolor="#d6eaf8", label="{label}\\n{_esc(h.address)}"];')
    for s in services:
        svc_label = _esc(f"{s.port}/{s.protocol} {s.name or ''}".strip())
        lines.append(f'    S{s.id} [shape=ellipse, label="{svc_label}"];')
        lines.append(f"    H{s.host_id} -> S{s.id};")
    for f in findings:
        color = sev_color.get(f.severity, "#bdc3c7")
        lines.append(f'    F{f.id} [shape=diamond, style=filled, fillcolor="{color}", label="{_esc(f.title)}"];')
        if f.service_id:
            lines.append(f"    S{f.service_id} -> F{f.id};")
        elif f.host_id:
            lines.append(f"    H{f.host_id} -> F{f.id};")
    for l in loot:
        lines.append(f'    L{l.id} [shape=note, style=filled, fillcolor="#fcf3cf", label="{_esc(l.label)}"];')
        if l.host_id:
            lines.append(f"    H{l.host_id} -> L{l.id};")

    lines.append("}")
    return "\n".join(lines)
