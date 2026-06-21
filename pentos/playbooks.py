"""
Playbook-Modul für PentOS.

Playbooks sind methodische Checklisten (Web, AD, Linux-/Windows-PrivEsc …).
Ein Schritt ist einer von drei Typen:

- ``pentos``   – Schritt mit fertigem ``pentos run …``-Kommando
- ``external`` – externes/GUI-Tool (Burp, ZAP, wpscan …) mit Hinweis/Kommando
- ``manual``   – manuelle Prüfung / Denkschritt

Definitionen liegen als YAML im Paket (``pentos/playbooks/*.yaml``) und optional
unter ``~/.config/pentos/playbooks/*.yaml`` (Nutzer-eigene überschreiben gleiche Namen).
Der Fortschritt wird pro Projekt in der DB gehalten (Tabelle ``playbook_progress``).

"""
from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel

from .config import config_dir

StepKind = Literal["pentos", "external", "manual"]


class PlaybookStep(BaseModel):
    id: str
    title: str
    kind: StepKind = "manual"
    why: Optional[str] = None          # warum dieser Schritt
    command: Optional[str] = None      # fertiges Kommando ({target} wird ersetzt)
    tool: Optional[str] = None         # Name des (externen) Tools
    when: Optional[str] = None         # Bedingungs-Hinweis (z.B. "wordpress")


class Playbook(BaseModel):
    name: str
    title: str
    description: Optional[str] = None
    steps: list[PlaybookStep] = []


def _user_dir() -> Path:
    return config_dir() / "playbooks"


def _load_file(text: str) -> Optional[Playbook]:
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and data.get("name"):
            return Playbook(**data)
    except Exception:
        return None
    return None


def load_all() -> dict[str, Playbook]:
    """Lädt gebündelte + nutzereigene Playbooks (Nutzer überschreibt gleichen Namen)."""
    out: dict[str, Playbook] = {}
    # Gebündelte Definitionen aus dem Paket
    try:
        pkg = resources.files("pentos") / "playbooks"
        for entry in pkg.iterdir():
            if entry.name.endswith((".yaml", ".yml")):
                pb = _load_file(entry.read_text(encoding="utf-8"))
                if pb:
                    out[pb.name] = pb
    except Exception:
        pass
    # Nutzer-eigene Definitionen
    udir = _user_dir()
    if udir.is_dir():
        for f in sorted(udir.glob("*.y*ml")):
            pb = _load_file(f.read_text(encoding="utf-8"))
            if pb:
                out[pb.name] = pb
    return out


def get(name: str) -> Optional[Playbook]:
    return load_all().get(name)


def render_command(cmd: Optional[str], target: Optional[str]) -> Optional[str]:
    if not cmd:
        return None
    return cmd.replace("{target}", target) if target else cmd
