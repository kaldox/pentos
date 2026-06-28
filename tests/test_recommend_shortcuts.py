"""Tests für die Run-Shortcut-Helfer (pentos.recommend)."""
import shutil

from pentos import recommend
from pentos.models import Service


def _svc(port, name=None, proto="tcp", tunnel=None):
    return Service(host_id=1, port=port, name=name, protocol=proto, tunnel=tunnel)


def test_target_url_http_and_https():
    assert recommend.target_url(_svc(80, "http"), "10.0.0.1") == "http://10.0.0.1"
    assert recommend.target_url(_svc(443, "https"), "10.0.0.1") == "https://10.0.0.1"
    assert recommend.target_url(_svc(8080, "http"), "10.0.0.1") == "http://10.0.0.1:8080"
    assert recommend.target_url(_svc(8443, "http", tunnel="ssl"), "x") == "https://x:8443"


def test_run_shortcuts_split_installed_missing(monkeypatch):
    # nur whatweb gilt als installiert
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/whatweb" if b == "whatweb" else None)
    svc = _svc(80, "http")
    ready, missing = recommend.run_shortcuts_for(svc, "10.0.0.1")
    ready_tools = {t for t, _cmd in ready}
    assert "whatweb" in ready_tools
    assert "whatweb" not in missing
    assert "nikto" in missing  # web-tool, hier nicht installiert
    # Web-Tools bekommen die URL als Ziel
    assert any("http://10.0.0.1" in cmd for _t, cmd in ready)


def test_run_shortcuts_no_addr():
    ready, missing = recommend.run_shortcuts_for(_svc(80, "http"), None)
    assert ready == [] and missing == []


def test_project_shortcuts_dedup(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/" + b)  # alles installiert
    svcs = [(_svc(80, "http"), "10.0.0.1"), (_svc(445, "smb"), "10.0.0.1")]
    ready, missing = recommend.project_shortcuts(svcs)
    # keine Duplikate
    assert len(ready) == len(set(ready))
    assert any("pentos run whatweb" in c for c in ready)
    assert any("pentos run enum4linux-ng" in c for c in ready)
