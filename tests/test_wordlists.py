"""Tests für pentos/wordlists.py: gebündelte Username-Liste + opt-in
Passwort-Download (SecLists rockyou-75.txt, gemockt -- kein echter
Netzwerk-Zugriff in Tests)."""
import tempfile
from pathlib import Path

import pytest

from pentos import wordlists as wl_mod


def test_bundled_usernames_text_has_entries_no_duplicates():
    text = wl_mod.bundled_usernames_text()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert len(lines) > 50
    assert len(lines) == len(set(lines))
    assert "admin" in lines


class _FakeResponse:
    def __init__(self, text, status_ok=True):
        self.text = text
        self._status_ok = status_ok

    def raise_for_status(self):
        if not self._status_ok:
            import requests
            raise requests.HTTPError("404 Not Found")


def test_fetch_password_list_returns_text(monkeypatch):
    monkeypatch.setattr(wl_mod.requests, "get",
                        lambda url, timeout=None: _FakeResponse("123456\npassword\n"))
    text = wl_mod.fetch_password_list()
    assert "123456" in text


def test_fetch_password_list_raises_on_http_error(monkeypatch):
    monkeypatch.setattr(wl_mod.requests, "get",
                        lambda url, timeout=None: _FakeResponse("", status_ok=False))
    with pytest.raises(wl_mod.WordlistError):
        wl_mod.fetch_password_list()


def test_fetch_password_list_raises_on_empty_body(monkeypatch):
    monkeypatch.setattr(wl_mod.requests, "get",
                        lambda url, timeout=None: _FakeResponse("   \n  "))
    with pytest.raises(wl_mod.WordlistError):
        wl_mod.fetch_password_list()


def test_fetch_password_list_raises_on_connection_error(monkeypatch):
    import requests

    def fake_get(url, timeout=None):
        raise requests.ConnectionError("boom")

    monkeypatch.setattr(wl_mod.requests, "get", fake_get)
    with pytest.raises(wl_mod.WordlistError):
        wl_mod.fetch_password_list()


def test_setup_without_download_only_writes_usernames():
    d = Path(tempfile.mkdtemp()) / "wordlists"
    result = wl_mod.setup(d, download_passwords=False)
    assert result["usernames_path"].exists()
    assert result["passwords_path"] is None
    assert result["passwords_downloaded"] is False
    assert not (d / "passwords.txt").exists()


def test_setup_with_download_writes_both(monkeypatch):
    monkeypatch.setattr(wl_mod.requests, "get",
                        lambda url, timeout=None: _FakeResponse("123456\n"))
    d = Path(tempfile.mkdtemp()) / "wordlists"
    result = wl_mod.setup(d, download_passwords=True)
    assert result["usernames_path"].exists()
    assert result["passwords_path"].exists()
    assert result["passwords_downloaded"] is True
    assert "123456" in result["passwords_path"].read_text(encoding="utf-8")


def test_setup_does_not_overwrite_existing_passwords_file(monkeypatch):
    called = {"n": 0}

    def fake_get(url, timeout=None):
        called["n"] += 1
        return _FakeResponse("fresh-download\n")

    monkeypatch.setattr(wl_mod.requests, "get", fake_get)
    d = Path(tempfile.mkdtemp()) / "wordlists"
    d.mkdir(parents=True)
    (d / "passwords.txt").write_text("my-own-custom-list\n", encoding="utf-8")

    result = wl_mod.setup(d, download_passwords=True)
    assert result["passwords_downloaded"] is False
    assert called["n"] == 0  # kein Download ausgelöst, Datei existierte schon
    assert (d / "passwords.txt").read_text(encoding="utf-8") == "my-own-custom-list\n"


def test_setup_re_run_refreshes_usernames_but_not_passwords(monkeypatch):
    """usernames.txt darf bei jedem Setup aktualisiert werden (kommt aus dem
    Paket, keine Nutzerdaten drin) -- passwords.txt bleibt stabil."""
    monkeypatch.setattr(wl_mod.requests, "get",
                        lambda url, timeout=None: _FakeResponse("first\n"))
    d = Path(tempfile.mkdtemp()) / "wordlists"
    wl_mod.setup(d, download_passwords=True)
    (d / "usernames.txt").write_text("tampered\n", encoding="utf-8")
    result = wl_mod.setup(d, download_passwords=True)
    assert result["usernames_path"].read_text(encoding="utf-8") != "tampered\n"
    assert result["passwords_downloaded"] is False
