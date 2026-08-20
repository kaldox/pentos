"""
Projekt-Export/-Import für PentOS.

Packt einen kompletten Projekt-Workspace (Datenbank + alle Unterordner:
scans/, screenshots/, evidence/, notes/, loot/, findings/, reports/, ...) als
eine einzelne ZIP-Datei – zum Sichern, Umziehen auf einen anderen Rechner
oder Teilen eines Projekts. Import entpackt eine solche Datei wieder als
vollständigen Workspace.

Hinweis zur Portabilität: Nur Dateien, die tatsächlich im Projektordner
liegen, landen im Export. Evidence-Einträge, deren Pfad auf eine Datei
ausserhalb des Projekts zeigt (z.B. `pentos evidence add /anderer/pfad.png`),
werden nicht mitverpackt – für volle Portabilität Evidence-Dateien im
Workspace ablegen (z.B. unter `evidence/`).
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import config

MANIFEST_NAME = "pentos-export.json"
EXPORT_FORMAT_VERSION = 1


class ArchiveError(Exception):
    """Export/Import ist fehlgeschlagen (ungültiges Archiv, Namenskonflikt, ...)."""


def export_project(name: str, output: Path) -> Path:
    """Packt den Workspace von Projekt `name` als ZIP nach `output`.

    Schreibt zunächst in eine temporäre Datei und verschiebt erst danach ans
    Ziel – verhindert, dass ein Zielpfad innerhalb des Projektordners (z.B.
    `exports/`) sich während des Packens selbst mit einliest.
    """
    root = config.project_path(name)
    if not root.exists():
        raise ArchiveError(f"Projekt '{name}' existiert nicht.")

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    manifest = {
        "pentos_export_version": EXPORT_FORMAT_VERSION,
        "project": name,
        "exported_at": datetime.now().replace(microsecond=0).isoformat(sep=" "),
    }

    fd, tmp_name = tempfile.mkstemp(suffix=".zip", dir=str(output.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2, ensure_ascii=False))
            for path in sorted(root.rglob("*")):
                if path.is_dir():
                    continue
                if path.resolve() == output.resolve():
                    continue  # Ziel läge selbst im Projektordner -> nicht mit einpacken
                zf.write(path, arcname=str(path.relative_to(root)).replace("\\", "/"))
        shutil.move(str(tmp_path), str(output))
    finally:
        tmp_path.unlink(missing_ok=True)
    return output


def read_manifest(archive: Path) -> Optional[dict]:
    """Liest das Manifest aus einem Export-Archiv (None, wenn keins vorhanden)."""
    try:
        with zipfile.ZipFile(archive) as zf:
            if MANIFEST_NAME not in zf.namelist():
                return None
            return json.loads(zf.read(MANIFEST_NAME).decode("utf-8"))
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"'{archive}' ist keine gültige ZIP-Datei.") from exc


def _safe_project_name(name: str) -> str:
    """Validiert einen Projektnamen, bevor er als Zielordner-Komponente
    verwendet wird -- der Name kann aus dem ZIP-Manifest stammen (nicht
    vertrauenswürdig!), also muss er selbst geprüft werden, nicht erst die
    einzelnen Archiv-Einträge relativ dazu (siehe _safe_members). Ein
    Manifest mit z.B. "project": "../../../etc" oder einem absoluten Pfad
    würde sonst den Zielordner selbst aus projects_dir() heraushebeln und
    die Zip-Slip-Prüfung wirkungslos machen."""
    name = (name or "").strip()
    if not name:
        raise ArchiveError("Ungültiger (leerer) Projektname im Archiv.")
    if name in (".", "..") or "/" in name or "\\" in name or Path(name).is_absolute():
        raise ArchiveError(
            f"Unsicherer Projektname im Archiv-Manifest: '{name}'. "
            "Ziel mit --name explizit setzen."
        )
    return name


def _safe_members(zf: zipfile.ZipFile, dest: Path) -> list[str]:
    """Prüft alle Archiv-Einträge auf Zip-Slip (Pfade, die aus `dest` ausbrechen)."""
    dest_resolved = dest.resolve()
    members = []
    for member in zf.namelist():
        if member == MANIFEST_NAME or member.endswith("/"):
            continue
        target = (dest / member).resolve()
        if target != dest_resolved and dest_resolved not in target.parents:
            raise ArchiveError(f"Unsichere Pfadangabe im Archiv: '{member}'")
        members.append(member)
    return members


def import_project(archive: Path, name: Optional[str] = None, force: bool = False) -> str:
    """Entpackt ein Export-Archiv als (neuen) Workspace.

    `name` überschreibt den im Manifest gespeicherten Projektnamen. Existiert
    ein Projekt mit diesem Namen bereits, muss `force=True` gesetzt werden,
    sonst wird ein ArchiveError geworfen. Gibt den Namen des importierten
    Projekts zurück.
    """
    archive = Path(archive)
    if not archive.exists():
        raise ArchiveError(f"Datei nicht gefunden: {archive}")

    try:
        with zipfile.ZipFile(archive) as zf:
            names = zf.namelist()
            if not any(n == "database/pentos.db" for n in names):
                raise ArchiveError(
                    f"'{archive}' sieht nicht wie ein PentOS-Projekt-Export aus "
                    "(database/pentos.db fehlt im Archiv)."
                )
            manifest = read_manifest(archive)
            target_name = _safe_project_name(name or (manifest or {}).get("project") or archive.stem)
            dest = config.project_path(target_name)
            # Doppelt genäht: selbst wenn _safe_project_name je eine Lücke hätte,
            # muss dest am Ende trotzdem innerhalb von projects_dir() landen.
            projects_root = config.projects_dir().resolve()
            if projects_root != dest.resolve() and projects_root not in dest.resolve().parents:
                raise ArchiveError(f"Unsicherer Zielpfad: '{dest}' liegt ausserhalb von {projects_root}.")
            if dest.exists() and not force:
                raise ArchiveError(
                    f"Projekt '{target_name}' existiert bereits. Anderen Namen mit "
                    "--name wählen oder --force zum Überschreiben."
                )
            members = _safe_members(zf, dest)  # wirft ArchiveError bei Zip-Slip, VOR jeder Extraktion
            if dest.exists() and force:
                shutil.rmtree(dest)
            dest.mkdir(parents=True, exist_ok=True)
            config.harden(dest, 0o700)  # enthält importiertes Loot/Credentials, siehe workspace.py
            for member in members:
                zf.extract(member, path=dest)
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"'{archive}' ist keine gültige ZIP-Datei.") from exc
    return target_name
