"""
Workspace-Verwaltung: legt die Ordnerstruktur eines Projekts an.

"""
from __future__ import annotations

from pathlib import Path

from . import config


def create_workspace(name: str) -> Path:
    """Legt den vollständigen Workspace für ein Projekt an und gibt den Pfad zurück."""
    root = config.project_path(name)
    root.mkdir(parents=True, exist_ok=True)
    for sub in config.WORKSPACE_DIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    # README im Projekt für den Menschen
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(
            f"# Pentest-Workspace: {name}\n\n"
            "Automatisch angelegt von PentOS.\n\n"
            "Struktur:\n"
            + "\n".join(f"- `{d}/`" for d in config.WORKSPACE_DIRS)
            + "\n",
            encoding="utf-8",
        )
    return root


def list_projects() -> list[str]:
    base = config.projects_dir()
    return sorted(
        p.name
        for p in base.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )
