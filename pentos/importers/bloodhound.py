"""
BloodHound-CE-Datenimport für PentOS (SharpHound-JSON, on-prem Active Directory).

Liest einen SharpHound-Collection-Export (ZIP-Archiv wie es SharpHound
erzeugt, oder ein bereits entpackter Ordner mit *_users.json/*_groups.json/
*_computers.json/...) und leitet daraus konkrete Findings ab:

- Kerberoastable Accounts (SPN gesetzt)
- AS-REP-roastbare Accounts (Kerberos-Preauth deaktiviert)
- Uneingeschränkte Delegation (Nutzer und Computer)
- Domain-Admin-Mitgliedschaft

PentOS baut damit **keinen Graphen nach** – das bleibt BloodHounds Job. Es
wertet die Rohdaten aus und macht die wichtigsten Ergebnisse als Findings im
Workspace sichtbar, mit Verweis auf die echte BloodHound-Oberfläche für die
volle Angriffspfad-Analyse.

Schema verifiziert gegen die SharpHound-Dokumentation und mehrere
unabhängige Quellen (data/meta-Wrapper je Datei; Properties-Objekt pro
Knoten mit lowercase-Keys wie hasspn/dontreqpreauth/enabled/admincount;
Members-Array pro Gruppe mit MemberId/MemberType). Nur SharpHound (on-prem
AD) wird unterstützt – AzureHound (Entra ID) hat ein anderes Schema und ist
(noch) nicht abgedeckt.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Iterator, Optional

# Well-known RID der Domain-Admins-Gruppe: SID endet immer auf -512,
# unabhängig von Domänenname/Sprache – robuster als ein Namensvergleich.
_DOMAIN_ADMINS_RID_SUFFIX = "-512"


class BloodHoundImportError(Exception):
    """Der Export konnte nicht gelesen werden (kein ZIP/Ordner, keine JSON-Dateien)."""


def _iter_json_members(path: Path) -> Iterator[tuple[str, dict]]:
    """Liefert (Dateiname, geparstes JSON) für jede *.json in einem Ordner
    oder innerhalb eines ZIP-Archivs. Fehlerhafte Einzeldateien werden
    übersprungen statt den ganzen Import abzubrechen."""
    if path.is_dir():
        found = False
        for p in sorted(path.glob("*.json")):
            found = True
            try:
                yield p.name, json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            except (json.JSONDecodeError, OSError):
                continue
        if not found:
            raise BloodHoundImportError(f"Keine .json-Dateien in '{path}' gefunden.")
        return

    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise BloodHoundImportError(f"'{path}' ist weder ein Ordner noch eine gültige ZIP-Datei.") from exc
    with zf:
        names = [n for n in zf.namelist() if n.lower().endswith(".json")]
        if not names:
            raise BloodHoundImportError(f"Keine .json-Dateien im Archiv '{path}' gefunden.")
        for name in sorted(names):
            try:
                yield name, json.loads(zf.read(name).decode("utf-8", errors="ignore"))
            except (json.JSONDecodeError, KeyError):
                continue


def _data_type(name: str, doc: dict) -> str:
    """Ermittelt den SharpHound-Dateityp: bevorzugt aus meta.dataType/type,
    sonst aus dem Dateinamen (z.B. '20260101_users.json')."""
    meta = doc.get("meta") or {}
    dt = str(meta.get("dataType") or meta.get("type") or "").lower()
    if dt:
        return dt
    lname = name.lower()
    for cand in ("users", "groups", "computers", "domains", "gpos", "ous", "containers"):
        if cand in lname:
            return cand
    return ""


def parse_sharphound(path: Path) -> dict:
    """Parst einen SharpHound-Export (ZIP oder Ordner) in eine strukturierte
    Zusammenfassung. Liest defensiv: fehlende/unerwartete Felder führen nicht
    zum Absturz, sondern werden schlicht nicht gezählt."""
    path = Path(path)
    if not path.exists():
        raise BloodHoundImportError(f"Datei/Ordner nicht gefunden: {path}")

    objects_by_sid: dict[str, dict] = {}   # SID -> Properties, für Namensauflösung
    users: list[dict] = []
    groups: list[dict] = []
    computers: list[dict] = []
    domain_name: Optional[str] = None
    seen_any = False

    for name, doc in _iter_json_members(path):
        if not isinstance(doc, dict):
            continue  # z.B. eine fremde *.json mit Top-Level-Array/Skalar -> überspringen statt abzustürzen
        items = doc.get("data")
        if not isinstance(items, list):
            continue
        dtype = _data_type(name, doc)
        for obj in items:
            if not isinstance(obj, dict):
                continue
            seen_any = True
            sid = obj.get("ObjectIdentifier") or ""
            props = obj.get("Properties") or {}
            if sid:
                objects_by_sid[sid] = props
            if dtype == "users":
                users.append(obj)
            elif dtype == "groups":
                groups.append(obj)
            elif dtype == "computers":
                computers.append(obj)
            elif dtype == "domains" and not domain_name:
                domain_name = props.get("name") or props.get("domain")

    if not seen_any:
        raise BloodHoundImportError(
            f"'{path}' enthält keine erkennbaren SharpHound-Objekte "
            "(erwartet: *_users.json/*_groups.json/*_computers.json mit data/meta-Struktur)."
        )

    def _name_of(sid: str) -> str:
        return (objects_by_sid.get(sid, {}) or {}).get("name") or sid

    kerberoastable: list[str] = []
    asrep_roastable: list[str] = []
    unconstrained_delegation: list[str] = []

    for u in users:
        props = u.get("Properties") or {}
        uname = str(props.get("name") or u.get("ObjectIdentifier", "?"))
        if uname.lower().startswith("krbtgt"):
            continue  # krbtgt hat immer ein SPN -- kein echter Kerberoasting-Kandidat
        if props.get("enabled") is False:
            continue
        if props.get("hasspn"):
            kerberoastable.append(uname)
        if props.get("dontreqpreauth"):
            asrep_roastable.append(uname)
        if props.get("unconstraineddelegation"):
            unconstrained_delegation.append(uname)

    for c in computers:
        props = c.get("Properties") or {}
        if props.get("unconstraineddelegation"):
            cname = str(props.get("name") or c.get("ObjectIdentifier", "?"))
            unconstrained_delegation.append(cname)

    domain_admins: list[str] = []
    for g in groups:
        props = g.get("Properties") or {}
        sid = str(g.get("ObjectIdentifier") or "")
        gname = str(props.get("name") or "")
        if sid.endswith(_DOMAIN_ADMINS_RID_SUFFIX) or gname.upper().startswith("DOMAIN ADMINS@"):
            for m in g.get("Members") or []:
                mid = m.get("MemberId") or m.get("ObjectIdentifier")
                if mid:
                    domain_admins.append(_name_of(mid))

    return {
        "domain": domain_name,
        "user_count": len(users),
        "computer_count": len(computers),
        "group_count": len(groups),
        "kerberoastable": sorted(set(kerberoastable)),
        "asrep_roastable": sorted(set(asrep_roastable)),
        "unconstrained_delegation": sorted(set(unconstrained_delegation)),
        "domain_admins": sorted(set(domain_admins)),
    }
