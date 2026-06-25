"""Tests für Evidence-Einbettung in Reports (Markdown/HTML/PDF)."""
import os
import struct
import tempfile
import zlib

import pytest


def _png(path, w=20, h=10, rgb=(15, 118, 110)):
    raw = b""
    for _ in range(h):
        raw += b"\x00" + bytes(rgb) * w

    def chunk(t, d):
        c = t + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

    data = (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))
    with open(path, "wb") as fh:
        fh.write(data)


def _project_with_evidence():
    tmp = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(tmp, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {tmp}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    from pentos.models import (Host, Finding, Severity, FindingCategory,
                               FindingStatus, Evidence)
    config.project_path("ev").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("ev"))
    repo = Repository(config.db_path("ev"))
    h = repo.add_host(Host(address="10.10.10.5", hostname="target01"))
    f = repo.add_finding(Finding(title="Upload ausnutzbar", severity=Severity.HIGH,
                                 category=FindingCategory.VULN,
                                 status=FindingStatus.CONFIRMED,
                                 description="RCE via Upload.", host_id=h.id))
    img = os.path.join(tmp, "proof.png")
    _png(img)
    repo.add_evidence(Evidence(kind="screenshot", path=img,
                               description="Shell als www-data", finding_id=f.id))
    repo.add_evidence(Evidence(kind="output", path=os.path.join(tmp, "nc.txt"),
                               description="Listener-Log", finding_id=f.id))
    return repo, "ev", config, tmp


def test_markdown_embeds_image_and_lists_file():
    from pentos import report
    repo, name, _config, _tmp = _project_with_evidence()
    md = report.build_markdown(repo, name)
    assert "**Belege:**" in md
    assert "![Shell als www-data]" in md       # Bild als Markdown-Bild
    assert "[output]" in md                     # Text-Beleg als Referenz
    assert "Listener-Log" in md


def test_html_inlines_image_base64():
    from pentos import export
    repo, name, config, _tmp = _project_with_evidence()
    html = export.build_html(repo, name, cfg=config.load_config())
    assert "Belege:" in html
    assert "data:image/png;base64," in html     # Bild base64-inline (self-contained)
    assert "Shell als www-data" in html
    assert "Listener-Log" in html               # Text-Beleg gelistet


def test_pdf_with_evidence_builds():
    pytest.importorskip("reportlab")
    from pentos import export
    repo, name, config, tmp = _project_with_evidence()
    out = os.path.join(tmp, "report.pdf")
    export.build_pdf(repo, name, out, cfg=config.load_config())
    assert os.path.exists(out)
    with open(out, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_evidence_without_finding_not_embedded():
    """Evidence ohne finding_id darf NICHT unter Findings auftauchen."""
    from pentos import report
    from pentos.models import Evidence
    repo, name, _config, tmp = _project_with_evidence()
    repo.add_evidence(Evidence(kind="output", path=os.path.join(tmp, "lose.txt"),
                               description="loser Beleg", finding_id=None))
    md = report.build_markdown(repo, name)
    assert "loser Beleg" not in md
