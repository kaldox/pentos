"""Regressionstest für den nikto-Parser (XML-Report, strukturierte Findings).

Vorbild ist der nuclei-Parser: Header-Rauschen (fehlende Security-Header)
wird gesammelt statt Findings zu spammen, alles andere wird ein Finding mit
heuristisch abgeleiteter Severity (nikto liefert selbst kein CVSS).

Fixture tests/fixtures/nikto_scan.xml folgt dem Schema aus dem offiziellen
nikto_report_xml.plugin (sullo/nikto): <item id=".." method="..">-Elemente
mit description/uri/namelink/iplink/references-Kindelementen.
"""
import os
import pathlib
import tempfile

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _repo_with_host():
    cfg = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(cfg, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    from pentos import db as db_mod
    from pentos.repository import Repository
    from pentos.models import Host
    config.project_path("n").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("n"))
    repo = Repository(config.db_path("n"))
    h = repo.add_host(Host(address="10.10.10.5", status="up"))
    return repo, h


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class _FakeSpec:
    name = "nikto"
    category = "web"


def test_parse_nikto_xml_extracts_all_items():
    from pentos.runners.parsers import _parse_nikto_xml
    hits = _parse_nikto_xml(_load("nikto_scan.xml"))
    assert len(hits) == 6
    assert hits[0]["uri"] == "/"
    assert "X-Frame-Options" in hits[0]["description"]
    assert hits[4]["references"] == "CVE-2021-41773"


def test_parse_nikto_xml_handles_garbage():
    from pentos.runners.parsers import _parse_nikto_xml
    assert _parse_nikto_xml("not xml at all") == []
    assert _parse_nikto_xml("") == []


def test_parse_nikto_xml_rejects_entity_expansion_gracefully():
    """defusedxml lehnt Entity-Expansion (billion laughs) ab -- wie bei
    kaputtem/leerem XML gibt es dafuer [] statt eines Crashs/Hangs (siehe
    defusedxml-Migration, SECURITY.md)."""
    from pentos.runners.parsers import _parse_nikto_xml
    evil = ('<?xml version="1.0"?>'
            '<!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
            '<niktoscan>&lol1;</niktoscan>')
    assert _parse_nikto_xml(evil) == []


def test_nikto_header_noise_becomes_info_not_findings():
    from pentos.runners.parsers import _parse_nikto
    repo, h = _repo_with_host()
    find_n, info = _parse_nikto(repo, _FakeSpec(), "10.10.10.5", _load("nikto_scan.xml"), h.id)
    # 6 Treffer insgesamt, 2 sind reines Header-Rauschen (X-Frame-Options, X-Content-Type-Options)
    assert find_n == 4
    assert len(info) == 2
    assert any("X-Frame-Options" in ln for ln in info)


def test_nikto_severity_heuristik():
    from pentos.runners.parsers import _parse_nikto
    from pentos.models import Severity
    repo, h = _repo_with_host()
    _parse_nikto(repo, _FakeSpec(), "10.10.10.5", _load("nikto_scan.xml"), h.id)
    sev_by_snippet = {}
    for f in repo.list_findings():
        for key in ("phpinfo", "Directory indexing", "remote command execution", "outdated"):
            if key.lower() in f.title.lower() or key.lower() in (f.description or "").lower():
                sev_by_snippet[key] = f.severity
    assert sev_by_snippet["remote command execution"] == Severity.CRITICAL
    assert sev_by_snippet["phpinfo"] == Severity.MEDIUM
    assert sev_by_snippet["Directory indexing"] == Severity.MEDIUM
    assert sev_by_snippet["outdated"] == Severity.MEDIUM


def test_nikto_finding_has_path_and_references_in_description():
    from pentos.runners.parsers import _parse_nikto
    repo, h = _repo_with_host()
    _parse_nikto(repo, _FakeSpec(), "10.10.10.5", _load("nikto_scan.xml"), h.id)
    rce = next(f for f in repo.list_findings() if "remote command execution" in f.description.lower())
    assert "Pfad: /cgi-bin" in rce.description
    assert "CVE-2021-41773" in rce.description


def test_nikto_no_duplicate_findings_on_second_run():
    from pentos.runners.parsers import _parse_nikto
    repo, h = _repo_with_host()
    text = _load("nikto_scan.xml")
    n1, _ = _parse_nikto(repo, _FakeSpec(), "10.10.10.5", text, h.id)
    n2, _ = _parse_nikto(repo, _FakeSpec(), "10.10.10.5", text, h.id)
    assert n1 == 4
    assert n2 == 0
