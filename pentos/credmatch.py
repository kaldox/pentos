"""
Loot-/Credential-Matching für PentOS.

Nimmt ein Loot-Objekt (Passwort, Hash, SSH-Key, ...) und schlägt vor, gegen
welche Dienste im Projekt es sich wiederverwenden liesse - inklusive eines
konkreten Befehls-Hinweises und, wo passend, eines Runner-Tools.

Strikt nur Vorschlag: Es wird NICHTS ausgefuehrt. Die Befehls-Hinweise sind
Kopiervorlagen für den Menschen, kein Auto-Spray. Gedacht für autorisierte
Labs / CTF, nicht für breites Credential-Stuffing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import Loot, LootType, Service


@dataclass
class CredMatch:
    host: str
    port: int
    protocol: str
    service: Optional[str]
    method: str            # menschenlesbar, z.B. "Password-Spray via SMB"
    tool: Optional[str]    # Registry-Name für Run-Shortcut (oder None)
    hint: str              # konkreter Befehls-Vorschlag (Kopiervorlage)


# Protokoll-Klassen, gegen die sich Passwörter testen lassen.
# port-Set ODER keyword im Service-Namen → Treffer.
# tool = Runner-Registry-Name (None = kein Runner, nur manueller Hinweis).
_PASSWORD_TARGETS: list[dict] = [
    {"label": "SMB", "ports": {139, 445}, "keywords": ["smb", "microsoft-ds", "netbios"],
     "tool": "nxc-smb", "hint": "nxc smb {host} -u {user} -p {pass}"},
    {"label": "WinRM", "ports": {5985, 5986}, "keywords": ["winrm", "wsman"],
     "tool": "nxc-winrm", "hint": "nxc winrm {host} -u {user} -p {pass}"},
    {"label": "SSH", "ports": {22}, "keywords": ["ssh"],
     "tool": "hydra", "hint": "ssh {user}@{host}   # bzw. hydra -l {user} -p {pass} ssh://{host}"},
    {"label": "FTP", "ports": {21}, "keywords": ["ftp"],
     "tool": "hydra", "hint": "hydra -l {user} -p {pass} ftp://{host}"},
    {"label": "RDP", "ports": {3389}, "keywords": ["ms-wbt-server", "rdp"],
     "tool": "nxc-smb", "hint": "xfreerdp /u:{user} /p:{pass} /v:{host}"},
    {"label": "MSSQL", "ports": {1433}, "keywords": ["ms-sql", "mssql"],
     "tool": "hydra", "hint": "impacket-mssqlclient {user}:{pass}@{host}"},
    {"label": "MySQL", "ports": {3306}, "keywords": ["mysql", "mariadb"],
     "tool": "hydra", "hint": "mysql -h {host} -u {user} -p{pass}"},
    {"label": "PostgreSQL", "ports": {5432}, "keywords": ["postgres"],
     "tool": "hydra", "hint": "psql 'host={host} user={user} password={pass}'"},
    {"label": "LDAP", "ports": {389, 636, 3268, 3269}, "keywords": ["ldap"],
     "tool": "ldapsearch", "hint": "ldapsearch -x -H ldap://{host} -D {user} -w {pass} -b ''"},
    {"label": "Telnet", "ports": {23}, "keywords": ["telnet"],
     "tool": "hydra", "hint": "hydra -l {user} -p {pass} telnet://{host}"},
]

# Pass-the-Hash: NTLM-Hashes gegen SMB/WinRM.
_HASH_TARGETS: list[dict] = [
    {"label": "SMB (PtH)", "ports": {139, 445}, "keywords": ["smb", "microsoft-ds", "netbios"],
     "tool": "nxc-smb", "hint": "nxc smb {host} -u {user} -H {hash}"},
    {"label": "WinRM (PtH)", "ports": {5985, 5986}, "keywords": ["winrm", "wsman"],
     "tool": "nxc-winrm", "hint": "nxc winrm {host} -u {user} -H {hash}"},
]

_WEB_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}


def _svc_matches(target: dict, svc: Service) -> bool:
    if svc.port in target["ports"]:
        return True
    name = (svc.name or "").lower()
    return any(kw in name for kw in target["keywords"])


def _split_cred(value: Optional[str], label: str) -> tuple[str, str]:
    """Zerlegt 'user:pass' grob; sonst Platzhalter aus dem Label."""
    if value and ":" in value:
        user, _, pw = value.partition(":")
        return (user or "<user>"), (pw or "<pass>")
    # value könnte nur Passwort oder nur User sein - wir bleiben generisch.
    return "<user>", (value or "<pass>")


def _is_web(svc: Service) -> bool:
    name = (svc.name or "").lower()
    return "http" in name or svc.port in _WEB_PORTS


def matches_for(loot: Loot, host_services: list[tuple[str, Service]]) -> list[CredMatch]:
    """Schlaegt Wiederverwendungs-Ziele für ein Loot-Objekt vor.

    `host_services` ist eine Liste aus (Host-Adresse, Service). So bleibt die
    Funktion unabhängig vom Repository und gut testbar.
    """
    out: list[CredMatch] = []

    if loot.type in (LootType.CREDENTIAL, LootType.TOKEN):
        user, pw = _split_cred(loot.value, loot.label)
        for addr, svc in host_services:
            for tgt in _PASSWORD_TARGETS:
                if _svc_matches(tgt, svc):
                    out.append(CredMatch(
                        host=addr, port=svc.port, protocol=svc.protocol, service=svc.name,
                        method=f"Password-Spray via {tgt['label']}", tool=tgt["tool"],
                        hint=tgt["hint"].format(host=addr, user=user, **{"pass": pw}),
                    ))
                    break  # pro Service nur die erste passende Klasse

    elif loot.type == LootType.HASH:
        user, _ = _split_cred(loot.value, loot.label)
        hash_val = (loot.value or "<hash>")
        if ":" in hash_val and hash_val.count(":") == 1 and not hash_val.lower().startswith("$"):
            # sieht nach user:hash aus
            user, hash_val = hash_val.split(":", 1)
        for addr, svc in host_services:
            for tgt in _HASH_TARGETS:
                if _svc_matches(tgt, svc):
                    out.append(CredMatch(
                        host=addr, port=svc.port, protocol=svc.protocol, service=svc.name,
                        method=f"Pass-the-Hash via {tgt['label']}", tool=tgt["tool"],
                        hint=tgt["hint"].format(host=addr, user=user or "<user>", **{"hash": hash_val}),
                    ))
                    break
        # zusaetzlich immer der Cracking-Hinweis (kein Service noetig)
        out.append(CredMatch(
            host="-", port=0, protocol="-", service=None,
            method="Hash offline knacken", tool="john",
            hint="pentos run john <hashfile>   # bzw. hashcat -m <mode> <hashfile> <wordlist>",
        ))

    elif loot.type == LootType.SSH_KEY:
        for addr, svc in host_services:
            if svc.port == 22 or "ssh" in (svc.name or "").lower():
                out.append(CredMatch(
                    host=addr, port=svc.port, protocol=svc.protocol, service=svc.name,
                    method="Login mit SSH-Key", tool=None,
                    hint=f"ssh -i <keyfile> <user>@{addr}",
                ))

    elif loot.type in (LootType.COOKIE, LootType.API_KEY):
        for addr, svc in host_services:
            if _is_web(svc):
                kind = "Cookie" if loot.type == LootType.COOKIE else "API-Key"
                out.append(CredMatch(
                    host=addr, port=svc.port, protocol=svc.protocol, service=svc.name,
                    method=f"{kind} im Web-Request setzen", tool=None,
                    hint=f"curl http://{addr}:{svc.port}/ -H 'Authorization/Cookie: {loot.label}'",
                ))

    return out
