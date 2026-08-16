"""Regressionstest für den testssl.sh-Parser (JSON-Report, strukturierte Findings).

Vorbild ist der nikto-Parser: Rauschen (hier: OK/DEBUG) wird verworfen,
Kontext-/Scan-Probleme (INFO/WARN/FATAL) werden gesammelt statt Findings zu
spammen, LOW+ wird ein Finding. Anders als bei nikto liefert testssl.sh die
Severity direkt selbst mit -- keine eigene Heuristik nötig.

Fixture tests/fixtures/testssl_scan.json folgt dem Schema aus der offiziellen
fileout_json_finding()-Funktion (testssl/testssl.sh, ab Version 3.2): ein
flaches Array von {"id","ip","port","severity","cve","cwe","finding"}.
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
    config.project_path("ts").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("ts"))
    repo = Repository(config.db_path("ts"))
    h = repo.add_host(Host(address="10.10.10.7", status="up"))
    return repo, h


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class _FakeSpec:
    name = "testssl"
    category = "web"


def test_parse_testssl_json_extracts_all_items():
    from pentos.runners.parsers import _parse_testssl_json
    hits = _parse_testssl_json(_load("testssl_scan.json"))
    assert len(hits) == 15
    assert hits[0]["id"] == "SSLv2"
    assert hits[6]["cve"] == "CVE-2014-0160"


def test_parse_testssl_json_handles_garbage():
    from pentos.runners.parsers import _parse_testssl_json
    assert _parse_testssl_json("not json at all") == []
    assert _parse_testssl_json("") == []
    assert _parse_testssl_json("null") == []
    assert _parse_testssl_json("42") == []


def test_parse_testssl_json_accepts_pretty_wrapper():
    from pentos.runners.parsers import _parse_testssl_json
    import json
    flat = json.loads(_load("testssl_scan.json"))
    pretty = json.dumps({"Invocation": "testssl.sh --jsonfile-pretty x 10.10.10.7",
                         "scanResult": flat, "scanTime": 42})
    hits = _parse_testssl_json(pretty)
    assert len(hits) == 15


def test_testssl_ok_and_debug_are_discarded_not_findings_or_notes():
    from pentos.runners.parsers import _parse_testssl
    repo, h = _repo_with_host()
    find_n, info = _parse_testssl(repo, _FakeSpec(), "10.10.10.7", _load("testssl_scan.json"), h.id)
    # 15 Treffer: 5 OK + 1 DEBUG verworfen, 2 WARN + 1 INFO als Notiz, 6 als Findings
    assert find_n == 6
    assert len(info) == 3
    assert not any("not offered" in ln for ln in info)  # OK-Treffer nie in der Notiz
    assert not any("internal debug" in ln for ln in info)  # DEBUG-Treffer nie in der Notiz


def test_testssl_warn_and_info_become_note_not_findings():
    from pentos.runners.parsers import _parse_testssl
    repo, h = _repo_with_host()
    _find_n, info = _parse_testssl(repo, _FakeSpec(), "10.10.10.7", _load("testssl_scan.json"), h.id)
    assert any("SNI" in ln for ln in info)
    assert any("example.local" in ln for ln in info)


def test_testssl_severity_comes_directly_from_tool():
    from pentos.runners.parsers import _parse_testssl
    from pentos.models import Severity
    repo, h = _repo_with_host()
    _parse_testssl(repo, _FakeSpec(), "10.10.10.7", _load("testssl_scan.json"), h.id)
    by_id = {}
    for f in repo.list_findings():
        for key in ("TLS1:", "TLS1_1:", "heartbleed:", "ROBOT:", "cert_expirationStatus:", "cipherlist_3DES_IDEA:"):
            if f.title.startswith(key):
                by_id[key] = f.severity
    assert by_id["TLS1:"] == Severity.LOW
    assert by_id["TLS1_1:"] == Severity.LOW
    assert by_id["heartbleed:"] == Severity.HIGH
    assert by_id["ROBOT:"] == Severity.CRITICAL
    assert by_id["cert_expirationStatus:"] == Severity.MEDIUM
    assert by_id["cipherlist_3DES_IDEA:"] == Severity.MEDIUM


def test_testssl_finding_category_vuln_when_cve_present():
    from pentos.runners.parsers import _parse_testssl
    from pentos.models import FindingCategory
    repo, h = _repo_with_host()
    _parse_testssl(repo, _FakeSpec(), "10.10.10.7", _load("testssl_scan.json"), h.id)
    heartbleed = next(f for f in repo.list_findings() if f.title.startswith("heartbleed:"))
    cipher = next(f for f in repo.list_findings() if f.title.startswith("cipherlist_3DES_IDEA:"))
    assert heartbleed.category == FindingCategory.VULN
    assert "CVE-2014-0160" in heartbleed.description
    assert cipher.category == FindingCategory.MISCONFIG  # kein CVE -> Konfigurationsproblem


def test_testssl_no_duplicate_findings_on_second_run():
    from pentos.runners.parsers import _parse_testssl
    repo, h = _repo_with_host()
    text = _load("testssl_scan.json")
    n1, _ = _parse_testssl(repo, _FakeSpec(), "10.10.10.7", text, h.id)
    n2, _ = _parse_testssl(repo, _FakeSpec(), "10.10.10.7", text, h.id)
    assert n1 == 6
    assert n2 == 0


def test_testssl_unknown_severity_value_is_ignored_safely():
    from pentos.runners.parsers import _parse_testssl
    repo, h = _repo_with_host()
    text = '[{"id": "weird", "port": "443", "severity": "BOGUS", "cve": "", "cwe": "", "finding": "??"}]'
    find_n, info = _parse_testssl(repo, _FakeSpec(), "10.10.10.7", text, h.id)
    assert find_n == 0
    assert info == []
