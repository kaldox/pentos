"""CLI-Tests für 'pentos wordlists setup'."""
import os
import tempfile

from typer.testing import CliRunner


def _project():
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
    config.project_path("w").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("w"))
    Repository(config.db_path("w")).close()
    config.set_active_project("w")
    import importlib as il
    from pentos.cli import app as app_mod
    il.reload(app_mod)
    return app_mod


def test_wordlists_setup_no_passwords_flag_skips_download():
    app_mod = _project()
    r = CliRunner().invoke(app_mod.app, ["wordlists", "setup", "--no-passwords"])
    assert r.exit_code == 0, r.output
    assert "Usernames:" in r.output
    assert "Keine Passwort-Liste eingerichtet" in r.output

    from pentos import config
    wl_dir = config.project_path("w") / "wordlists"
    assert (wl_dir / "usernames.txt").exists()
    assert not (wl_dir / "passwords.txt").exists()


def test_wordlists_setup_yes_flag_downloads_without_prompt(monkeypatch):
    app_mod = _project()

    def fake_get(url, timeout=None):
        class R:
            text = "123456\npassword\n"

            def raise_for_status(self):
                pass
        return R()

    monkeypatch.setattr(app_mod.wordlists_mod.requests, "get", fake_get)
    r = CliRunner().invoke(app_mod.app, ["wordlists", "setup", "--yes"])
    assert r.exit_code == 0, r.output
    assert "Passwords:" in r.output
    # "heruntergeladen" statt der vollen Phrase pruefen: Rich umbricht die
    # Konsolenausgabe je nach erkannter Terminalbreite (schmal z.B. bei
    # nicht-interaktivem CliRunner/SSH), "neu heruntergeladen" kann dabei
    # auf zwei Zeilen landen -- das einzelne Wort bleibt stabil.
    assert "heruntergeladen" in r.output

    from pentos import config
    wl_dir = config.project_path("w") / "wordlists"
    assert (wl_dir / "passwords.txt").read_text(encoding="utf-8") == "123456\npassword\n"


def test_wordlists_setup_without_yes_asks_and_respects_no(monkeypatch):
    app_mod = _project()
    called = {"n": 0}

    def fake_get(url, timeout=None):
        called["n"] += 1
        class R:
            text = "x\n"
            def raise_for_status(self):
                pass
        return R()

    monkeypatch.setattr(app_mod.wordlists_mod.requests, "get", fake_get)
    r = CliRunner().invoke(app_mod.app, ["wordlists", "setup"], input="n\n")
    assert r.exit_code == 0, r.output
    assert called["n"] == 0
    assert "Keine Passwort-Liste eingerichtet" in r.output


def test_wordlists_setup_handles_download_error_gracefully(monkeypatch):
    app_mod = _project()

    def fake_get(url, timeout=None):
        raise app_mod.wordlists_mod.WordlistError("Passwort-Liste nicht erreichbar: timeout")

    monkeypatch.setattr(app_mod.wordlists_mod, "fetch_password_list",
                        lambda timeout=15: (_ for _ in ()).throw(
                            app_mod.wordlists_mod.WordlistError("Passwort-Liste nicht erreichbar: timeout")))
    r = CliRunner().invoke(app_mod.app, ["wordlists", "setup", "--yes"])
    assert r.exit_code == 1
    assert "nicht erreichbar" in r.output


def test_wordlists_setup_shows_hydra_example_command():
    app_mod = _project()
    r = CliRunner().invoke(app_mod.app, ["wordlists", "setup", "--no-passwords"])
    assert r.exit_code == 0, r.output
    assert "pentos run hydra" in r.output
    assert "-L " in r.output and "-P " in r.output


# ── wordlists catalog / wordlists add ────────────────────────────────────────
def test_wordlists_catalog_lists_all_by_default():
    app_mod = _project()
    r = CliRunner().invoke(app_mod.app, ["wordlists", "catalog"])
    assert r.exit_code == 0, r.output
    assert "rockyou-10" in r.output
    assert "subdomains-5k" in r.output


def test_wordlists_catalog_filters_by_category():
    app_mod = _project()
    r = CliRunner().invoke(app_mod.app, ["wordlists", "catalog", "--category", "subdomains"])
    assert r.exit_code == 0, r.output
    assert "subdomains-5k" in r.output
    assert "rockyou-10" not in r.output


def test_wordlists_catalog_filters_by_query():
    app_mod = _project()
    r = CliRunner().invoke(app_mod.app, ["wordlists", "catalog", "--filter", "rockyou-75"])
    assert r.exit_code == 0, r.output
    assert "rockyou-75" in r.output
    assert "rockyou-10" not in r.output


def test_wordlists_add_unknown_name_fails_cleanly():
    app_mod = _project()
    r = CliRunner().invoke(app_mod.app, ["wordlists", "add", "totally-made-up"])
    assert r.exit_code == 1
    assert "Unbekannter Katalog-Eintrag" in r.output


def test_wordlists_add_downloads_named_entry_with_yes(monkeypatch):
    app_mod = _project()

    def fake_get(url, timeout=None):
        class R:
            text = "admin\nroot\n"
            def raise_for_status(self):
                pass
        return R()

    monkeypatch.setattr(app_mod.wordlists_mod.requests, "get", fake_get)
    r = CliRunner().invoke(app_mod.app, ["wordlists", "add", "usernames-shortlist", "--yes"])
    assert r.exit_code == 0, r.output
    assert "usernames-shortlist" in r.output

    from pentos import config
    out = config.project_path("w") / "wordlists" / "usernames-shortlist.txt"
    assert out.read_text(encoding="utf-8") == "admin\nroot\n"


def test_wordlists_add_without_yes_respects_decline(monkeypatch):
    app_mod = _project()
    called = {"n": 0}

    def fake_get(url, timeout=None):
        called["n"] += 1
        class R:
            text = "x\n"
            def raise_for_status(self):
                pass
        return R()

    monkeypatch.setattr(app_mod.wordlists_mod.requests, "get", fake_get)
    r = CliRunner().invoke(app_mod.app, ["wordlists", "add", "dir-common"], input="n\n")
    assert r.exit_code == 0, r.output
    assert called["n"] == 0
    assert "Abgebrochen" in r.output


def test_wordlists_add_handles_download_error(monkeypatch):
    app_mod = _project()

    def fake_fetch(entry, timeout=30):
        raise app_mod.wordlists_mod.WordlistError(f"'{entry.name}' nicht erreichbar: timeout")

    monkeypatch.setattr(app_mod.wordlists_mod, "fetch_catalog_entry", fake_fetch)
    r = CliRunner().invoke(app_mod.app, ["wordlists", "add", "dir-big", "--yes"])
    assert r.exit_code == 1
    assert "nicht erreichbar" in r.output
