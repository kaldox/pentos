"""Tests für den Scanner-Import (Nessus, OpenVAS, Burp)."""
import pathlib

from pentos.importers import scanners
from pentos.models import Severity

FIX = pathlib.Path(__file__).parent / "fixtures"


def test_detect_formats():
    assert scanners.detect_format(FIX / "scan_nessus.nessus") == "nessus"
    assert scanners.detect_format(FIX / "scan_openvas.xml") == "openvas"
    assert scanners.detect_format(FIX / "scan_burp.xml") == "burp"


def test_nessus_parsing():
    fmt, targets = scanners.parse(FIX / "scan_nessus.nessus")
    assert fmt == "nessus"
    assert len(targets) == 1
    pt = targets[0]
    assert pt.host.address == "192.168.56.10"
    assert pt.host.os_guess == "Windows Server 2019"
    # Info-Item (severity 0) wird NICHT als Finding übernommen
    assert len(pt.findings) == 1
    f = pt.findings[0]
    assert f.severity == Severity.HIGH
    assert f.cvss_score == 5.9          # CVSS v3 bevorzugt
    assert f.cvss_vector and f.cvss_vector.startswith("CVSS:3")
    assert "CVE-2016-2118" in (f.description or "")
    assert "signing" in (f.remediation or "").lower()
    # Service aus Port abgeleitet
    assert any(s.port == 445 for s in pt.services)


def test_openvas_parsing():
    fmt, targets = scanners.parse(FIX / "scan_openvas.xml")
    assert fmt == "openvas"
    pt = targets[0]
    assert pt.host.address == "192.168.56.20"
    # Log-Eintrag übersprungen, nur das High-Finding bleibt
    assert len(pt.findings) == 1
    f = pt.findings[0]
    assert f.severity == Severity.HIGH
    assert f.cvss_score == 7.5
    assert "weak ciphers" in (f.remediation or "").lower()


def test_burp_parsing_strips_html():
    fmt, targets = scanners.parse(FIX / "scan_burp.xml")
    assert fmt == "burp"
    pt = targets[0]
    # Information-Issue übersprungen
    assert len(pt.findings) == 1
    f = pt.findings[0]
    assert f.severity == Severity.HIGH
    assert "(/search)" in f.title
    # HTML-Tags müssen entfernt sein
    assert "<b>" not in (f.description or "")
    assert "<p>" not in (f.remediation or "")
    assert "echoed" in (f.description or "")


def test_forced_format_overrides_detection():
    # Burp-Datei, aber als nessus erzwungen -> Parser liefert keine Treffer/keine Exception
    fmt, targets = scanners.parse(FIX / "scan_burp.xml", fmt="nessus")
    assert fmt == "nessus"
    assert targets == []  # kein ReportHost im Burp-XML


def test_unknown_format_raises():
    import pytest
    p = FIX / "scan_unknown.xml"
    p.write_text("<foo><bar/></foo>", encoding="utf-8")
    try:
        with pytest.raises(ValueError, match="Format"):
            scanners.parse(p, fmt="definitely-not-real")
    finally:
        p.unlink(missing_ok=True)
