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

"""
from __future__ import annotations

from importlib import resources
from pathlib import Path

import requests

PASSWORD_LIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Passwords/Leaked-Databases/rockyou-75.txt"
)


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
