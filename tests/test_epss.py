"""Tests für die EPSS-Anreicherung (pentos/epss.py): CVE-Extraktion aus
Finding-Text, Abfrage bei der FIRST.org-API (gemockt, kein echter Netzwerk-
Zugriff in Tests) und Persistenz über das Repository."""
import os
import tempfile

import pytest


def _finding(title="", description=""):
    from pentos.models import Finding
    return Finding(title=title, description=description)


# ── extract_cves ──────────────────────────────────────────────────────────────
def test_extract_cves_finds_single_cve_in_description():
    from pentos.epss import extract_cves
    f = _finding(description="Verwundbar für CVE-2014-0160 (Heartbleed).")
    assert extract_cves(f) == ["CVE-2014-0160"]


def test_extract_cves_finds_multiple_and_dedups_preserving_order():
    from pentos.epss import extract_cves
    f = _finding(title="cve-2021-41773", description="Auch CVE-2021-42013, nochmal CVE-2021-41773")
    assert extract_cves(f) == ["CVE-2021-41773", "CVE-2021-42013"]


def test_extract_cves_normalizes_case():
    from pentos.epss import extract_cves
    f = _finding(description="cve-2017-13099")
    assert extract_cves(f) == ["CVE-2017-13099"]


def test_extract_cves_empty_when_none_present():
    from pentos.epss import extract_cves
    f = _finding(title="Schwaches Cipher", description="RC4 wird angeboten, kein CVE-Bezug.")
    assert extract_cves(f) == []


# ── fetch_epss (requests gemockt) ────────────────────────────────────────────
class _FakeResponse:
    def __init__(self, payload, status_ok=True):
        self._payload = payload
        self._status_ok = status_ok

    def raise_for_status(self):
        if not self._status_ok:
            import requests
            raise requests.HTTPError("500 Server Error")

    def json(self):
        return self._payload


def test_fetch_epss_parses_data_list(monkeypatch):
    from pentos import epss as epss_mod

    def fake_get(url, params=None, timeout=None):
        assert "CVE-2014-0160" in params["cve"]
        return _FakeResponse({"data": [
            {"cve": "CVE-2014-0160", "epss": "0.94123", "percentile": "0.99001"},
        ]})

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    result = epss_mod.fetch_epss(["CVE-2014-0160"])
    assert result["CVE-2014-0160"]["epss"] == pytest.approx(0.94123)
    assert result["CVE-2014-0160"]["percentile"] == pytest.approx(0.99001)


def test_fetch_epss_skips_cves_without_entry(monkeypatch):
    """CVEs, die die API nicht kennt, fehlen einfach im Ergebnis (kein Fehler)."""
    from pentos import epss as epss_mod

    def fake_get(url, params=None, timeout=None):
        return _FakeResponse({"data": []})

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    result = epss_mod.fetch_epss(["CVE-9999-99999"])
    assert result == {}


def test_fetch_epss_batches_large_cve_lists(monkeypatch):
    from pentos import epss as epss_mod
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params["cve"].split(","))
        return _FakeResponse({"data": []})

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    cves = [f"CVE-2020-{1000 + i}" for i in range(85)]  # > 2 Batches à 40
    epss_mod.fetch_epss(cves)
    assert len(calls) == 3
    assert len(calls[0]) == 40 and len(calls[1]) == 40 and len(calls[2]) == 5


def test_fetch_epss_dedups_case_insensitively(monkeypatch):
    from pentos import epss as epss_mod
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params["cve"])
        return _FakeResponse({"data": []})

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    epss_mod.fetch_epss(["cve-2014-0160", "CVE-2014-0160"])
    assert len(calls) == 1
    assert calls[0] == "CVE-2014-0160"


def test_fetch_epss_raises_epss_error_on_request_exception(monkeypatch):
    from pentos import epss as epss_mod
    import requests

    def fake_get(url, params=None, timeout=None):
        raise requests.ConnectionError("boom")

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    with pytest.raises(epss_mod.EpssError):
        epss_mod.fetch_epss(["CVE-2014-0160"])


def test_fetch_epss_raises_epss_error_on_http_error(monkeypatch):
    from pentos import epss as epss_mod

    def fake_get(url, params=None, timeout=None):
        return _FakeResponse({}, status_ok=False)

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    with pytest.raises(epss_mod.EpssError):
        epss_mod.fetch_epss(["CVE-2014-0160"])


def test_fetch_epss_raises_epss_error_on_bad_json(monkeypatch):
    from pentos import epss as epss_mod

    class _BadJson(_FakeResponse):
        def json(self):
            raise ValueError("not json")

    def fake_get(url, params=None, timeout=None):
        return _BadJson({})

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    with pytest.raises(epss_mod.EpssError):
        epss_mod.fetch_epss(["CVE-2014-0160"])


def test_fetch_epss_ignores_malformed_items_gracefully(monkeypatch):
    from pentos import epss as epss_mod

    def fake_get(url, params=None, timeout=None):
        return _FakeResponse({"data": [
            {"cve": "CVE-2014-0160"},              # fehlende epss/percentile
            {"epss": "0.5", "percentile": "0.5"},  # fehlende cve
            "not a dict",
            {"cve": "CVE-2021-1234", "epss": "0.1", "percentile": "0.2"},
        ]})

    monkeypatch.setattr(epss_mod.requests, "get", fake_get)
    result = epss_mod.fetch_epss(["CVE-2014-0160", "CVE-2021-1234"])
    assert list(result.keys()) == ["CVE-2021-1234"]


# ── Persistenz über das Repository ───────────────────────────────────────────
def _repo():
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
    config.project_path("epss").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("epss"))
    return Repository(config.db_path("epss"))


def test_set_finding_epss_persists_and_round_trips():
    from pentos.models import Finding
    repo = _repo()
    f = repo.add_finding(Finding(title="Heartbleed", description="CVE-2014-0160"))
    assert f.epss_score is None  # noch nicht angereichert
    ok = repo.set_finding_epss(f.id, 0.94123, 0.99001)
    repo.close()
    assert ok


def test_set_finding_epss_reflected_in_get_and_list_finding():
    from pentos.models import Finding
    repo = _repo()
    f = repo.add_finding(Finding(title="Heartbleed", description="CVE-2014-0160"))
    repo.set_finding_epss(f.id, 0.94123, 0.99001)
    got = repo.get_finding(f.id)
    listed = {x.id: x for x in repo.list_findings()}[f.id]
    repo.close()
    assert got.epss_score == pytest.approx(0.94123)
    assert got.epss_percentile == pytest.approx(0.99001)
    assert listed.epss_score == pytest.approx(0.94123)


def test_set_finding_epss_returns_false_for_unknown_id():
    repo = _repo()
    ok = repo.set_finding_epss(999999, 0.5, 0.5)
    repo.close()
    assert ok is False
