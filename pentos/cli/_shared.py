"""
Gemeinsame Infrastruktur für die CLI-Befehlsmodule.

Bewusst ohne Abhängigkeit auf `pentos.cli.app` (das Haupt-`app`-Objekt) --
die einzelnen Befehlsgruppen-Module (workspace.py, findings.py, ...)
importieren nur von hier, `app.py` importiert wiederum die fertigen
Typer-Sub-Apps aus diesen Modulen. Keine Zirkelbezüge in beide Richtungen.
"""
from __future__ import annotations

import typer
from rich.console import Console

from .. import config
from ..repository import Repository

console = Console()

# Auf Windows läuft stdout gerne in einer nicht-UTF-8-Codepage (z.B. cp1252 als
# Konsolen-Default, oder wenn `pentos`/`python -m pentos` als Subprozess ohne
# PYTHONUTF8=1 / PYTHONIOENCODING=utf-8 aufgerufen wird). Rich schreibt in dem
# Fall roh in den Stream, und ein UnicodeEncodeError für Zeichen wie ●, →, ✓
# oder ⚠ lässt den Befehl abstürzen statt die Ausgabe zu zeigen. Deshalb hier
# durchgängig ASCII-Ersatzzeichen für Marker/Status-Symbole in Rich-Ausgaben.
SYM_BULLET = "*"     # aktives Projekt / Prioritäts-Bullet
SYM_ARROW = "->"     # Statuswechsel / Wertübergänge
SYM_NEXT = ">>"      # "Nächste Schritte"-Panels
SYM_WARN = "!"       # Warnhinweis
SYM_OK = "x"         # erledigt / installiert (grün)
SYM_MISSING = "-"    # fehlt / nicht installiert (rot)
SYM_SKIP = ">"       # übersprungen (gelb)
SYM_PENDING = "."    # offen / ausstehend (dim)
BAR_FULL = "#"       # Fortschrittsbalken: gefüllt
BAR_EMPTY = "-"      # Fortschrittsbalken: leer


def _active_or_exit() -> str:
    name = config.get_active_project()
    if not name:
        console.print("[red]Kein aktives Projekt.[/red] Lege eines an: "
                      "[cyan]pentos project new <name>[/cyan]")
        raise typer.Exit(1)
    return name


def _repo() -> tuple[Repository, str]:
    name = _active_or_exit()
    return Repository(config.db_path(name)), name
