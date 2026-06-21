"""
Konfiguration und Pfadverwaltung für PentOS.

- Config liegt unter ~/.config/pentos/config.yaml (override via PENTOS_CONFIG).
- Projekte liegen standardmässig unter ~/pentos/projects.
- Das aktive Projekt wird in <projects_dir>/.active gespeichert.

"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml

# Unterordner, die jeder Projekt-Workspace bekommt
WORKSPACE_DIRS = [
    "scans",
    "screenshots",
    "evidence",
    "notes",
    "loot",
    "credentials",
    "findings",
    "reports",
    "exports",
    "attack_paths",
    "timelines",
    "tasks",
    "knowledge",
    "obsidian",
    "database",
]

DEFAULT_CONFIG = {
    "projects_dir": str(Path.home() / "pentos" / "projects"),
    "language": "de",
    "ai": {
        # provider: ollama | lmstudio | openai | none
        "provider": "ollama",
        "base_url": "http://localhost:11434",
        "model": "llama3.1",
        "embed_model": "nomic-embed-text",
        "api_key_env": "OPENAI_API_KEY",
        "timeout": 60,
    },
    "report": {
        # Branding für HTML-/PDF-Reports
        "company": "",
        "color": "#0f766e",
        "author": "",
    },
}


def config_path() -> Path:
    env = os.environ.get("PENTOS_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".config" / "pentos" / "config.yaml"


def config_dir() -> Path:
    """Verzeichnis der Config (für Nutzer-eigene Playbooks/Erweiterungen)."""
    return config_path().parent


def load_config() -> dict:
    """Lädt die Config, legt bei Bedarf eine Default-Config an."""
    path = config_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(DEFAULT_CONFIG, fh, allow_unicode=True, sort_keys=False)
        return dict(DEFAULT_CONFIG)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    # mit Defaults auffüllen (vorwärtskompatibel)
    merged = {**DEFAULT_CONFIG, **data}
    merged["ai"] = {**DEFAULT_CONFIG["ai"], **(data.get("ai") or {})}
    merged["report"] = {**DEFAULT_CONFIG["report"], **(data.get("report") or {})}
    return merged


def save_config(cfg: dict) -> Path:
    """Schreibt die Konfiguration nach config_path() zurück."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, allow_unicode=True, sort_keys=False)
    return path


def projects_dir() -> Path:
    p = Path(load_config()["projects_dir"]).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _active_marker() -> Path:
    return projects_dir() / ".active"


def set_active_project(name: str) -> None:
    _active_marker().write_text(name, encoding="utf-8")


def get_active_project() -> Optional[str]:
    marker = _active_marker()
    if marker.exists():
        name = marker.read_text(encoding="utf-8").strip()
        if name and (projects_dir() / name).exists():
            return name
    return None


def project_path(name: str) -> Path:
    return projects_dir() / name


def db_path(name: str) -> Path:
    return project_path(name) / "database" / "pentos.db"
