"""
nmap-XML-Importer für PentOS.

Parst die Ausgabe von `nmap -oX` (inkl. NSE-Script-Output) in Host- und
Service-Objekte. Empfohlen: `nmap -sC -sV -oX scan.xml <ziel>`.

"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Host, Service


def parse_nmap_xml(path: Path) -> list[tuple[Host, list[Service]]]:
    tree = ET.parse(str(path))
    root = tree.getroot()
    result: list[tuple[Host, list[Service]]] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") == "down":
            continue

        # Adresse (IPv4 bevorzugt, sonst erste verfügbare)
        address = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                address = addr_el.get("addr")
                break
        if not address:
            any_addr = host_el.find("address")
            address = any_addr.get("addr") if any_addr is not None else None
        if not address:
            continue

        hostname = None
        hn_el = host_el.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name")

        os_guess = None
        osmatch = host_el.find("os/osmatch")
        if osmatch is not None:
            os_guess = osmatch.get("name")

        host = Host(address=address, hostname=hostname, os_guess=os_guess, status="up")

        services: list[Service] = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue
            portid = port_el.get("portid")
            protocol = port_el.get("protocol", "tcp")
            if portid is None:
                continue

            svc_el = port_el.find("service")
            name = product = version = tunnel = None
            if svc_el is not None:
                name = svc_el.get("name")
                product = svc_el.get("product")
                version = svc_el.get("version")
                tunnel = svc_el.get("tunnel")

            # NSE-Script-Output sammeln (wird für Auto-Findings genutzt)
            script_parts = []
            for script_el in port_el.findall("script"):
                sid = script_el.get("id", "")
                out = (script_el.get("output", "") or "").strip()
                if out:
                    script_parts.append(f"[{sid}] {out}")
            extra = "\n".join(script_parts) if script_parts else None

            services.append(
                Service(
                    host_id=0,  # wird beim Persistieren gesetzt
                    port=int(portid),
                    protocol=protocol,
                    name=name,
                    product=product,
                    version=version,
                    extra=extra,
                    tunnel=tunnel,
                )
            )

        result.append((host, services))

    return result
