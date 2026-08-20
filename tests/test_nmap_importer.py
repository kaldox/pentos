"""Tests für den nmap-XML-Importer (pentos.importers.nmap).

Bisher ohne eigene Testdatei -- ergänzt hier im Zuge der defusedxml-
Migration (SECURITY.md): ein Regressionstest für den Normalfall plus einen
für die eigentliche Sicherheitseigenschaft (Entity-Expansion-DoS wird
abgelehnt statt stillschweigend expandiert).
"""
import defusedxml.common
import pytest

from pentos.importers.nmap import parse_nmap_xml

_BASIC_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="target.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

_BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<nmaprun>&lol1;</nmaprun>"""


def test_parse_nmap_xml_extracts_host_and_service(tmp_path):
    p = tmp_path / "scan.xml"
    p.write_text(_BASIC_NMAP_XML, encoding="utf-8")
    result = parse_nmap_xml(p)
    assert len(result) == 1
    host, services = result[0]
    assert host.address == "10.0.0.5"
    assert host.hostname == "target.local"
    assert len(services) == 1
    assert services[0].port == 22
    assert services[0].product == "OpenSSH"


def test_parse_nmap_xml_rejects_entity_expansion(tmp_path):
    """Eine praeparierte 'nmap-XML'-Datei (z.B. aus einer geteilten Scan-
    Ergebnisdatei) darf nicht stillschweigend expandiert werden -- ein
    klarer Fehler ist hier das gewuenschte Verhalten (siehe defusedxml-
    Migration, SECURITY.md)."""
    p = tmp_path / "evil.xml"
    p.write_text(_BILLION_LAUGHS, encoding="utf-8")
    with pytest.raises(defusedxml.common.EntitiesForbidden):
        parse_nmap_xml(p)
