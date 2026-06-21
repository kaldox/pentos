"""
Tool-Registry für PentOS.

Deklarative Spezifikationen gängiger Enumeration-/Recon-Tools. Neue Tools werden
einfach als ToolSpec ergänzt – optional mit eigenem Parser (siehe parsers.py).
Bewusst keine aggressiven Brute-Force-/Exploit-Tools im Default-Set; bei Bedarf
projektspezifisch ergänzbar.

"""
from __future__ import annotations

from .base import ToolSpec

# Standard-Wordlist auf Kali (per --wordlist überschreibbar)
_WL = "/usr/share/wordlists/dirb/common.txt"

REGISTRY: dict[str, ToolSpec] = {
    "nmap": ToolSpec(
        name="nmap", binary="nmap", category="recon",
        argv=["nmap", "-sC", "-sV", "-oX", "{outfile}", "{target}"],
        produces_outfile=True, outfile_ext="xml", timeout=900,
        description="Service-/Versions-Scan (-sC -sV). Profile: basic|standard|full|custom",
        parser="nmap",
        profiles={
            "basic":    ["nmap", "-oX", "{outfile}", "{target}"],
            "standard": ["nmap", "-sC", "-sV", "-oX", "{outfile}", "{target}"],
            "full":     ["nmap", "-p-", "-sC", "-sV", "-oX", "{outfile}", "{target}"],
            "custom":   ["nmap", "-oX", "{outfile}", "{target}"],   # Rest via --args
        },
    ),
    "whatweb": ToolSpec(
        name="whatweb", binary="whatweb", category="web",
        argv=["whatweb", "--no-errors", "-a", "3", "{target}"],
        timeout=180, description="Web-Technologie-Erkennung",
        parser="capture",
    ),
    "nikto": ToolSpec(
        name="nikto", binary="nikto", category="web",
        argv=["nikto", "-h", "{target}"],
        timeout=900, description="Web-Schwachstellen-Scan",
        parser="capture",
    ),
    "feroxbuster": ToolSpec(
        name="feroxbuster", binary="feroxbuster", category="web",
        argv=["feroxbuster", "-u", "{target}", "-w", "{wordlist}", "-q", "-o", "{outfile}"],
        produces_outfile=True, needs_wordlist=True, default_wordlist=_WL, timeout=600,
        description="Verzeichnis-/Datei-Enumeration (rekursiv)",
        parser="ferox_text",
    ),
    "gobuster": ToolSpec(
        name="gobuster", binary="gobuster", category="web",
        argv=["gobuster", "dir", "-u", "{target}", "-w", "{wordlist}", "-q", "-o", "{outfile}"],
        produces_outfile=True, needs_wordlist=True, default_wordlist=_WL, timeout=600,
        description="Verzeichnis-/Datei-Enumeration",
        parser="dir_text",
    ),
    "ffuf": ToolSpec(
        name="ffuf", binary="ffuf", category="web",
        argv=["ffuf", "-u", "{target}/FUZZ", "-w", "{wordlist}", "-of", "json", "-o", "{outfile}"],
        produces_outfile=True, outfile_ext="json", needs_wordlist=True, default_wordlist=_WL,
        timeout=600, description="Fuzzing (FUZZ-Marker an die URL anhängen)",
        parser="ffuf_json",
    ),
    "enum4linux-ng": ToolSpec(
        name="enum4linux-ng", binary="enum4linux-ng", category="smb",
        argv=["enum4linux-ng", "-A", "{target}"],
        timeout=300, description="SMB/AD-Enumeration (Shares, User, Gruppen)",
        parser="enum4linux",
    ),
    "smbclient": ToolSpec(
        name="smbclient", binary="smbclient", category="smb",
        argv=["smbclient", "-L", "{target}", "-N"],
        timeout=120, description="SMB-Shares anonym auflisten",
        parser="capture",
    ),
    "smbmap": ToolSpec(
        name="smbmap", binary="smbmap", category="smb",
        argv=["smbmap", "-H", "{target}"],
        timeout=180, description="SMB-Shares + Zugriffsrechte. --args z.B. \"-u guest -p ''\"",
        parser="capture",
    ),
    "ldapsearch": ToolSpec(
        name="ldapsearch", binary="ldapsearch", category="ldap",
        argv=["ldapsearch", "-x", "-H", "ldap://{target}"],
        timeout=180, description="LDAP-Abfrage. --args z.B. \"-b 'dc=example,dc=com'\"",
        parser="capture",
    ),
    "snmpwalk": ToolSpec(
        name="snmpwalk", binary="snmpwalk", category="snmp",
        argv=["snmpwalk", "-v2c", "-c", "public", "{target}"],
        timeout=180, description="SNMP-Walk mit Community 'public'",
        parser="capture",
    ),
    "dig-axfr": ToolSpec(
        name="dig-axfr", binary="dig", category="dns",
        argv=["dig", "axfr", "{target}"],
        timeout=60, description="DNS-Zonentransfer (AXFR) testen (target = Domain)",
        parser="capture",
    ),
    "nuclei": ToolSpec(
        name="nuclei", binary="nuclei", category="vuln",
        argv=["nuclei", "-u", "{target}", "-silent", "-o", "{outfile}"],
        produces_outfile=True, timeout=900,
        description="Template-basierter Schwachstellen-Scan",
        parser="nuclei",
    ),

    # ── Brute-Force / Auth (THM-Training; opt-in, scope-gated) ───────────────
    "hydra": ToolSpec(
        name="hydra", binary="hydra", category="bruteforce",
        argv=["hydra", "{target}"], timeout=1800,
        description="Login-Brute-Force. Rest via --args, z.B. \"-l admin -P <wl> ssh\"",
        parser="creds",
    ),
    "medusa": ToolSpec(
        name="medusa", binary="medusa", category="bruteforce",
        argv=["medusa", "-h", "{target}"], timeout=1800,
        description="Login-Brute-Force. --args z.B. \"-u admin -P <wl> -M ssh\"",
        parser="creds",
    ),
    "nxc-smb": ToolSpec(
        name="nxc-smb", binary="netexec", category="bruteforce",
        argv=["netexec", "smb", "{target}"], timeout=1200,
        description="NetExec SMB (Spray/Auth). --args z.B. \"-u users.txt -p <wl>\"",
        parser="nxc",
    ),
    "nxc-winrm": ToolSpec(
        name="nxc-winrm", binary="netexec", category="bruteforce",
        argv=["netexec", "winrm", "{target}"], timeout=1200,
        description="NetExec WinRM (Auth/Exec). --args z.B. \"-u admin -p <pw>\"",
        parser="nxc",
    ),

    # ── Exploitation (THM-Training; opt-in, scope-gated) ─────────────────────
    "sqlmap": ToolSpec(
        name="sqlmap", binary="sqlmap", category="exploit",
        argv=["sqlmap", "-u", "{target}", "--batch"], timeout=1800,
        description="SQL-Injection. --args z.B. \"--dbs --level 3 --risk 2\"",
        parser="capture",
    ),
    "searchsploit": ToolSpec(
        name="searchsploit", binary="searchsploit", category="exploit",
        argv=["searchsploit", "{target}"], timeout=120, network=False,
        description="Offline Exploit-DB-Suche (target = Suchbegriff)",
        parser="capture",
    ),

    # ── Offline Hash-Cracking (kein Netzwerk-Ziel; Scope entfällt) ───────────
    "john": ToolSpec(
        name="john", binary="john", category="cracking",
        argv=["john", "--wordlist={wordlist}", "{target}"], timeout=3600,
        needs_wordlist=True, default_wordlist="/usr/share/wordlists/rockyou.txt",
        network=False, description="John the Ripper (target = Hash-Datei)",
        parser="capture",
    ),

    # ── Schnelle Port-Discovery / OSINT / AD-User-Enum ───────────────────────
    "rustscan": ToolSpec(
        name="rustscan", binary="rustscan", category="recon",
        argv=["rustscan", "-a", "{target}", "--ulimit", "5000", "--no-config"],
        timeout=300, description="Sehr schnelle Port-Discovery (Alternative/Vorstufe zu nmap)",
        parser="capture",
    ),
    "subfinder": ToolSpec(
        name="subfinder", binary="subfinder", category="dns",
        argv=["subfinder", "-d", "{target}", "-silent"],
        timeout=300, description="Passive Subdomain-Enumeration (target = Domain)",
        parser="lines_note",
    ),
    "kerbrute": ToolSpec(
        name="kerbrute", binary="kerbrute", category="bruteforce",
        argv=["kerbrute", "userenum", "--dc", "{target}", "{wordlist}"],
        needs_wordlist=True, timeout=600,
        description="AD-User-Enumeration via Kerberos (zusätzlich -d <domain> via --args)",
        parser="capture",
    ),
}


def get(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def names() -> list[str]:
    return list(REGISTRY.keys())
