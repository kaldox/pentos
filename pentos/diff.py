"""
Scan-Diff für PentOS.

Vergleicht einen frisch geparsten nmap-Scan mit dem aktuellen Projektstand und
meldet, was sich geaendert hat: neue Hosts, neue Dienste, Versionswechsel und
was im neuen Scan fehlt. Rein regelbasiert, keine Persistenz, keine Ausführung
- es werden nur Unterschiede berechnet und zurückgegeben.

Die Kernfunktion arbeitet auf normalisierten Maps, damit sie ohne Repository
und ohne nmap-Datei testbar ist. Bauhelfer wandeln Repository-Objekte bzw. das
Parser-Ergebnis in diese Maps um.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .models import Host, Service


# ── Datentypen ───────────────────────────────────────────────────────────────
@dataclass
class ServiceRef:
    """Ein Dienst als flache Referenz (für Anzeige)."""
    host: str
    port: int
    protocol: str
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None

    def banner(self) -> str:
        parts = [p for p in (self.name, self.product, self.version) if p]
        return " ".join(parts) if parts else "-"


@dataclass
class ServiceChange:
    """Ein Dienst, der schon bekannt war, aber jetzt andere Produkt-/Versionsinfo hat."""
    host: str
    port: int
    protocol: str
    before: str
    after: str


@dataclass
class ScanDiff:
    new_hosts: list[str] = field(default_factory=list)
    new_services: list[ServiceRef] = field(default_factory=list)
    changed_services: list[ServiceChange] = field(default_factory=list)
    missing_hosts: list[str] = field(default_factory=list)
    missing_services: list[ServiceRef] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_hosts
            or self.new_services
            or self.changed_services
            or self.missing_hosts
            or self.missing_services
        )


# Normalisierte Map: { address: { (port, protocol): {"name","product","version"} } }
ScanMap = dict[str, dict[tuple[int, str], dict[str, Optional[str]]]]


# ── Bauhelfer ────────────────────────────────────────────────────────────────
def _svc_dict(svc: Service) -> dict[str, Optional[str]]:
    return {"name": svc.name, "product": svc.product, "version": svc.version}


def index_parsed(parsed: Iterable[tuple[Host, list[Service]]]) -> ScanMap:
    """Wandelt das nmap-Parser-Ergebnis in eine normalisierte Map um."""
    out: ScanMap = {}
    for host, services in parsed:
        bucket = out.setdefault(host.address, {})
        for svc in services:
            bucket[(svc.port, svc.protocol)] = _svc_dict(svc)
    return out


def index_repo(hosts: Iterable[Host], services: Iterable[Service]) -> ScanMap:
    """Wandelt Repository-Hosts und -Services in eine normalisierte Map um.

    `services` darf alle Services des Projekts enthalten; die Zuordnung erfolgt
    ueber host_id.
    """
    by_id: dict[int, str] = {h.id: h.address for h in hosts if h.id is not None}
    out: ScanMap = {addr: {} for addr in by_id.values()}
    for svc in services:
        addr = by_id.get(svc.host_id)
        if addr is None:
            continue
        out.setdefault(addr, {})[(svc.port, svc.protocol)] = _svc_dict(svc)
    return out


def _banner(d: dict[str, Optional[str]]) -> str:
    parts = [d.get("product"), d.get("version")]
    parts = [p for p in parts if p]
    return " ".join(parts) if parts else (d.get("name") or "-")


def _has_versioninfo(d: dict[str, Optional[str]]) -> bool:
    return bool(d.get("product") or d.get("version"))


# ── Kern ─────────────────────────────────────────────────────────────────────
def diff_maps(existing: ScanMap, scanned: ScanMap) -> ScanDiff:
    """Berechnet den Unterschied zwischen Projektstand und neuem Scan."""
    result = ScanDiff()

    for addr, svcs in scanned.items():
        if addr not in existing:
            result.new_hosts.append(addr)
            for (port, proto), d in sorted(svcs.items()):
                result.new_services.append(
                    ServiceRef(addr, port, proto, d.get("name"), d.get("product"), d.get("version"))
                )
            continue

        old_svcs = existing[addr]
        for (port, proto), d in sorted(svcs.items()):
            key = (port, proto)
            if key not in old_svcs:
                result.new_services.append(
                    ServiceRef(addr, port, proto, d.get("name"), d.get("product"), d.get("version"))
                )
                continue
            old = old_svcs[key]
            # Versionswechsel nur melden, wenn beide Seiten Produkt-/Versionsinfo
            # tragen und sie sich unterscheidet. Reines Anreichern (vorher leer)
            # wird ebenfalls gemeldet, damit man neue Banner sieht.
            before, after = _banner(old), _banner(d)
            if _has_versioninfo(d) and before != after:
                result.changed_services.append(ServiceChange(addr, port, proto, before, after))
            else:
                result.unchanged += 1

    # Was im Projekt war, aber im neuen Scan fehlt (z.B. Dienst weg / Host down).
    for addr, svcs in existing.items():
        if addr not in scanned:
            result.missing_hosts.append(addr)
            continue
        new_svcs = scanned[addr]
        for (port, proto), d in sorted(svcs.items()):
            if (port, proto) not in new_svcs:
                result.missing_services.append(
                    ServiceRef(addr, port, proto, d.get("name"), d.get("product"), d.get("version"))
                )

    result.new_hosts.sort()
    result.missing_hosts.sort()
    return result


def diff_parsed_against_repo(
    parsed: Iterable[tuple[Host, list[Service]]],
    hosts: Iterable[Host],
    services: Iterable[Service],
) -> ScanDiff:
    """Bequemer Einstieg: nmap-Parser-Ergebnis gegen Repository-Stand diffen."""
    return diff_maps(index_repo(hosts, services), index_parsed(parsed))
