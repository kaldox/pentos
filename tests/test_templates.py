"""Tests für die Finding-Template-Bibliothek und die DB-Migration."""
import os
import sqlite3
import tempfile

import pytest


def _fresh_repo():
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
    config.project_path("t").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("t"))
    return Repository(config.db_path("t")), config


def test_seed_is_idempotent():
    repo, _ = _fresh_repo()
    n1 = repo.seed_builtin_templates()
    assert n1 == 8                      # 8 Muster aus der Wissensbasis
    n2 = repo.seed_builtin_templates()
    assert n2 == 0                      # nichts doppelt
    assert len(repo.list_templates()) == 8


def test_builtin_templates_have_cvss_and_remediation():
    repo, _ = _fresh_repo()
    repo.seed_builtin_templates()
    pwn = repo.get_template("pwn3d")
    assert pwn is not None
    assert pwn.severity.value == "High"
    assert pwn.cvss_score == 8.8
    assert pwn.cvss_vector and pwn.cvss_vector.startswith("CVSS:3.1")
    assert "LAPS" in pwn.remediation
    assert pwn.builtin is True


def test_lookup_by_id_and_key():
    repo, _ = _fresh_repo()
    repo.seed_builtin_templates()
    by_key = repo.get_template("null-session")
    by_id = repo.get_template(by_key.id)
    assert by_id is not None and by_id.key == "null-session"


def test_add_custom_and_apply_creates_finding():
    repo, _ = _fresh_repo()
    from pentos.models import FindingTemplate, FindingCategory, Severity
    repo.add_template(FindingTemplate(
        key="open-redis", title="Offener Redis", severity=Severity.HIGH,
        category=FindingCategory.EXPOSURE, description="Redis ohne Auth.",
        remediation="requirepass setzen.", cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    ))
    f = repo.instantiate_template("open-redis", title_suffix="(10.0.0.1)")
    assert f is not None
    assert f.title == "Offener Redis (10.0.0.1)"
    assert f.cvss_score == 7.5
    assert f.severity.value == "High"
    assert f.remediation == "requirepass setzen."
    # Finding ist auch wirklich persistiert
    assert any(x.cvss_score == 7.5 for x in repo.list_findings())


def test_delete_template():
    repo, _ = _fresh_repo()
    repo.seed_builtin_templates()
    assert repo.delete_template("telnet") is True
    assert repo.get_template("telnet") is None
    assert repo.delete_template("telnet") is False


def test_migration_adds_columns_to_old_findings_table():
    """Eine alte findings-Tabelle ohne cvss-Spalten muss migriert werden."""
    cfg = tempfile.mkdtemp()
    os.environ["PENTOS_CONFIG"] = os.path.join(cfg, "config.yaml")
    open(os.environ["PENTOS_CONFIG"], "w").write(
        f"projects_dir: {cfg}/projects\nlanguage: de\n"
        'ai: {provider: none, base_url: "", model: "", embed_model: x, api_key_env: X, timeout: 5}\n'
    )
    import importlib
    from pentos import config
    importlib.reload(config)
    db_file = config.db_path("old")
    db_file.parent.mkdir(parents=True, exist_ok=True)
    # Alte findings-Tabelle OHNE cvss/remediation simulieren
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, title TEXT NOT NULL, "
                 "category TEXT, severity TEXT, status TEXT, description TEXT, "
                 "host_id INTEGER, service_id INTEGER, auto INTEGER, created_at TEXT NOT NULL)")
    conn.commit(); conn.close()
    # init_db muss die Spalten ergänzen
    from pentos import db as db_mod
    db_mod.init_db(db_file)
    conn = sqlite3.connect(str(db_file))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
    conn.close()
    assert {"remediation", "cvss_score", "cvss_vector"} <= cols
