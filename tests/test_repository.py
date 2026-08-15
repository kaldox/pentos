"""Regression: add_host()/add_service() müssen die Transaktion sauber
zurückrollen, wenn der UNIQUE-Constraint anspricht (Dublette) -- sonst
bleibt die SQLite-Transaktion offen und blockiert eine zweite, gleichzeitig
laufende Verbindung auf derselben Projekt-DB (z.B. `pentos serve`/TUI neben
einem laufenden `pentos scan import-nmap`).
"""
import os
import sqlite3
import tempfile


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
    config.project_path("r").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("r"))
    return Repository(config.db_path("r")), config.db_path("r")


def test_add_host_duplicate_rolls_back_and_returns_existing():
    from pentos.models import Host
    repo, _dbpath = _fresh_repo()
    h1 = repo.add_host(Host(address="10.10.10.5", hostname="first"))
    h2 = repo.add_host(Host(address="10.10.10.5", hostname="second"))  # Dublette
    assert h2.id == h1.id  # bestehender Host zurückgegeben, kein Crash
    repo.close()


def test_add_host_duplicate_does_not_leave_transaction_open():
    """Reproduziert den Bug direkt: nach einer abgefangenen IntegrityError
    darf conn.in_transaction nicht mehr True sein, sonst blockiert eine
    zweite Verbindung mit 'database is locked'."""
    from pentos.models import Host
    repo, dbpath = _fresh_repo()
    repo.add_host(Host(address="10.10.10.5"))
    repo.add_host(Host(address="10.10.10.5"))  # löst den IntegrityError-Pfad aus
    assert repo.conn.in_transaction is False

    # Harter Beweis: eine zweite, unabhängige Verbindung muss sofort schreiben können.
    second = sqlite3.connect(str(dbpath), timeout=0.5)
    second.execute("INSERT INTO hosts (address, status, created_at) VALUES (?, 'up', 'x')",
                   ("10.10.10.6",))
    second.commit()
    second.close()
    repo.close()


def test_add_service_duplicate_rolls_back_and_returns_existing():
    from pentos.models import Host, Service
    repo, _dbpath = _fresh_repo()
    h = repo.add_host(Host(address="10.10.10.5"))
    s1 = repo.add_service(Service(host_id=h.id, port=80, protocol="tcp", name="http"))
    s2 = repo.add_service(Service(host_id=h.id, port=80, protocol="tcp", name="http-again"))
    assert s2.id == s1.id
    assert repo.conn.in_transaction is False
    repo.close()
