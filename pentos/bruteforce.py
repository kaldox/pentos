"""
Vereinfachte Wordlist-/Protokoll-Argumente für Brute-Force-Tools.

hydra, medusa und netexec (smb/winrm) haben je eigene Flag-Syntax für
Username-/Passwort-Listen -- ein blindes "pentos run hydra <ziel>" ohne
diese Angaben würde nur hängen bzw. nichts Sinnvolles tun. --userlist/
--passlist/--proto (siehe cli/app.py::run_cmd) bilden das pro Tool auf die
richtige argv-Syntax ab, mit automatischem Rückgriff auf die Projekt-
Wordlists (siehe wordlists.py::setup) statt eines hartkodierten relativen
Pfads.

Bewusst NICHT hier: kerbrute -- reine User-Enumeration ohne Passwort-Liste,
nutzt bereits den generischen --wordlist-Mechanismus (needs_wordlist=True
in der Tool-Registry).
"""
from __future__ import annotations

from typing import Optional

# Tools, die --userlist/--passlist/--proto verstehen (Reihenfolge = Anzeige
# z.B. in Fehlermeldungen).
SUPPORTED_TOOLS = ["hydra", "medusa", "nxc-smb", "nxc-winrm"]

# Tools, die zusätzlich ein Protokoll-Modul brauchen (hydra: trailing
# Positional-Argument, medusa: -M). nxc-smb/nxc-winrm brauchen KEIN --proto --
# das Protokoll steckt schon im Tool-Namen (netexec smb bzw. netexec winrm).
_PROTO_REQUIRED = {"hydra", "medusa"}


def is_supported(tool: str) -> bool:
    """True, wenn --userlist/--passlist/--proto für dieses Tool gilt."""
    return tool in SUPPORTED_TOOLS


def needs_proto(tool: str) -> bool:
    """True, wenn das Tool zwingend ein Protokoll-Modul braucht (--proto)."""
    return tool in _PROTO_REQUIRED


def build_args(tool: str, userlist: str, passlist: str, proto: Optional[str]) -> list[str]:
    """Baut die tool-spezifischen argv-Tokens für User-/Passwort-Liste (+ Protokoll).

    Wirft ValueError bei fehlendem proto (wenn needs_proto(tool) True ist) oder
    einem nicht unterstützten Tool -- Aufrufer sollten vorher is_supported()/
    needs_proto() prüfen, das ist hier nur ein zusätzliches Sicherheitsnetz.
    """
    if tool == "hydra":
        if not proto:
            raise ValueError("hydra braucht --proto (z.B. ssh, ftp, http-get).")
        return ["-L", userlist, "-P", passlist, proto]
    if tool == "medusa":
        if not proto:
            raise ValueError("medusa braucht --proto (z.B. ssh, ftp, http).")
        return ["-U", userlist, "-P", passlist, "-M", proto]
    if tool in ("nxc-smb", "nxc-winrm"):
        return ["-u", userlist, "-p", passlist]
    raise ValueError(f"'{tool}' unterstützt --userlist/--passlist/--proto nicht.")
