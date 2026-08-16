"""
Standard-Wordlists für PentOS.

Löst ein reales Reibungsproblem: frisch installiert (egal ob Kali, Debian,
Ubuntu, macOS) hat ein Projekt keine einzige Wordlist -- `pentos run hydra
<ziel>` liefe ins Leere, weil weder Userliste noch Passwortliste existieren.

Zwei bewusst unterschiedliche Wege, je nach Datenart:
- Usernames: reine Muster/generische Namen, kein Bezug zu echten Breach-
  Daten -- wird direkt als Paket-Ressource mitgeliefert (data/wordlists/).
- Passwords: Top-Passwort-Listen (rockyou & Derivate) stammen aus einem
  echten Datenleck von 2009. Statt das selbst dauerhaft im Repo zu bündeln,
  wird die kuratierte Kurzliste rockyou-75.txt (SecLists, ca. 40% Abdeckung
  mit nur 75 Einträgen -- fürs schnelle Durchprobieren gedacht) opt-in von
  der offiziellen Quelle heruntergeladen (siehe cli/app.py::wordlists_setup).

Darüber hinaus ein kleiner, kuratierter Katalog (CATALOG) mit weiteren
SecLists-Listen (Usernames, Passwörter in mehreren Grössen, Verzeichnisse,
Subdomains) -- jede einzeln per Namen ins Projekt ladbar (`wordlists add
<name>`), ebenfalls opt-in von der offiziellen Quelle, nichts davon im Repo
gebündelt.

"""
from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Optional

import requests
from pydantic import BaseModel

PASSWORD_LIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Passwords/Leaked-Databases/rockyou-75.txt"
)

_SECLISTS_RAW = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"


class WordlistCatalogEntry(BaseModel):
    name: str            # kurzer Handle für 'wordlists add <name>'
    category: str        # usernames | passwords | directories | subdomains
    description: str
    url: str


# Kuratierte Auswahl -- bewusst klein und mit Bedacht zusammengestellt statt
# der komplette SecLists-Baum. Reihenfolge = Anzeige-Reihenfolge je Kategorie.
CATALOG: dict[str, WordlistCatalogEntry] = {
    "usernames-shortlist": WordlistCatalogEntry(
        name="usernames-shortlist", category="usernames",
        description="Kurzliste gängiger Usernames (root, admin, ec2-user, vagrant, …)",
        url=_SECLISTS_RAW + "Usernames/top-usernames-shortlist.txt",
    ),
    "names": WordlistCatalogEntry(
        name="names", category="usernames",
        description="Vornamen-Liste, geeignet für firstname/firstname.lastname-Muster",
        url=_SECLISTS_RAW + "Usernames/Names/names.txt",
    ),
    "rockyou-10": WordlistCatalogEntry(
        name="rockyou-10", category="passwords",
        description="Kuratierte 10-Einträge-Kurzliste (schnellster Smoke-Test)",
        url=_SECLISTS_RAW + "Passwords/Leaked-Databases/rockyou-10.txt",
    ),
    "rockyou-15": WordlistCatalogEntry(
        name="rockyou-15", category="passwords",
        description="Kuratierte 15-Einträge-Kurzliste",
        url=_SECLISTS_RAW + "Passwords/Leaked-Databases/rockyou-15.txt",
    ),
    "rockyou-20": WordlistCatalogEntry(
        name="rockyou-20", category="passwords",
        description="Kuratierte 20-Einträge-Kurzliste",
        url=_SECLISTS_RAW + "Passwords/Leaked-Databases/rockyou-20.txt",
    ),
    "rockyou-25": WordlistCatalogEntry(
        name="rockyou-25", category="passwords",
        description="Kuratierte 25-Einträge-Kurzliste",
        url=_SECLISTS_RAW + "Passwords/Leaked-Databases/rockyou-25.txt",
    ),
    "rockyou-75": WordlistCatalogEntry(
        name="rockyou-75", category="passwords",
        description="Kuratierte 75-Einträge-Kurzliste, ~40% Abdeckung (Default in 'wordlists setup')",
        url=PASSWORD_LIST_URL,
    ),
    "dir-common": WordlistCatalogEntry(
        name="dir-common", category="directories",
        description="Kleine, breit einsetzbare Verzeichnis-/Datei-Wordlist (~4,7k Einträge)",
        url=_SECLISTS_RAW + "Discovery/Web-Content/common.txt",
    ),
    "dir-quickhits": WordlistCatalogEntry(
        name="dir-quickhits", category="directories",
        description="Sehr kleine Liste besonders ergiebiger Treffer -- guter erster Durchlauf",
        url=_SECLISTS_RAW + "Discovery/Web-Content/quickhits.txt",
    ),
    "dir-raft-medium": WordlistCatalogEntry(
        name="dir-raft-medium", category="directories",
        description="Grössere, aus echten Webseiten abgeleitete Verzeichnis-Wordlist",
        url=_SECLISTS_RAW + "Discovery/Web-Content/raft-medium-directories.txt",
    ),
    "dir-big": WordlistCatalogEntry(
        name="dir-big", category="directories",
        description="Sehr grosse Verzeichnis-/Datei-Wordlist (langer Lauf, hohe Abdeckung)",
        url=_SECLISTS_RAW + "Discovery/Web-Content/big.txt",
    ),
    "subdomains-5k": WordlistCatalogEntry(
        name="subdomains-5k", category="subdomains",
        description="Top 5.000 Subdomains (aus DNS-Zonentransfers abgeleitet)",
        url=_SECLISTS_RAW + "Discovery/DNS/subdomains-top1million-5000.txt",
    ),
    "subdomains-20k": WordlistCatalogEntry(
        name="subdomains-20k", category="subdomains",
        description="Top 20.000 Subdomains -- gründlicher, entsprechend länger",
        url=_SECLISTS_RAW + "Discovery/DNS/subdomains-top1million-20000.txt",
    ),
}


def catalog_list(category: Optional[str] = None, query: Optional[str] = None) -> list[WordlistCatalogEntry]:
    """Katalog durchsuchen/filtern -- Basis für 'wordlists catalog'."""
    items = list(CATALOG.values())
    if category:
        items = [i for i in items if i.category == category]
    if query:
        q = query.lower()
        items = [i for i in items if q in i.name.lower() or q in i.description.lower()]
    return sorted(items, key=lambda i: (i.category, i.name))


def catalog_get(name: str) -> Optional[WordlistCatalogEntry]:
    return CATALOG.get(name)


def fetch_catalog_entry(entry: WordlistCatalogEntry, timeout: int = 30) -> str:
    """Lädt eine einzelne Katalog-Liste von der offiziellen SecLists-Quelle.

    Wirft WordlistError bei Netzwerk-/HTTP-Problemen oder leerer Antwort --
    kein stiller Fehlschlag.
    """
    try:
        resp = requests.get(entry.url, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise WordlistError(f"'{entry.name}' nicht erreichbar: {exc}") from exc
    text = resp.text
    if not text.strip():
        raise WordlistError(f"'{entry.name}' war leer -- Quelle prüfen.")
    return text


class WordlistError(Exception):
    """Fehler beim Einrichten der Standard-Wordlists (Download/Dateizugriff)."""


def bundled_usernames_text() -> str:
    """Liest die im Paket mitgelieferte generische Username-Liste."""
    res = resources.files("pentos") / "data" / "wordlists" / "usernames.txt"
    return res.read_text(encoding="utf-8")


def fetch_password_list(timeout: int = 15) -> str:
    """Lädt die kuratierte rockyou-75.txt-Kurzliste von SecLists (GitHub).

    Wirft WordlistError bei Netzwerk-/HTTP-Problemen -- kein stiller
    Fehlschlag, damit der Aufrufer den Nutzer klar informieren kann.
    """
    try:
        resp = requests.get(PASSWORD_LIST_URL, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise WordlistError(f"Passwort-Liste nicht erreichbar: {exc}") from exc
    text = resp.text
    if not text.strip():
        raise WordlistError("Passwort-Liste war leer -- Quelle prüfen.")
    return text


def setup(project_wordlists_dir: Path, download_passwords: bool = True) -> dict:
    """Richtet die Standard-Wordlists im Projekt ein.

    - usernames.txt: immer aus der Paket-Ressource kopiert (kein Netzwerk).
    - passwords.txt: nur wenn download_passwords=True und noch nicht
      vorhanden -- ein bestehender passwords.txt wird NICHT überschrieben
      (könnte eine bewusst grössere/eigene Liste sein).

    Gibt {"usernames_path", "passwords_path" (oder None), "passwords_downloaded"} zurück.
    """
    project_wordlists_dir.mkdir(parents=True, exist_ok=True)
    users_path = project_wordlists_dir / "usernames.txt"
    users_path.write_text(bundled_usernames_text(), encoding="utf-8")

    result = {"usernames_path": users_path, "passwords_path": None, "passwords_downloaded": False}
    pw_path = project_wordlists_dir / "passwords.txt"
    if download_passwords:
        if pw_path.exists():
            result["passwords_path"] = pw_path
        else:
            pw_path.write_text(fetch_password_list(), encoding="utf-8")
            result["passwords_path"] = pw_path
            result["passwords_downloaded"] = True
    return result
