"""Regressionstest für den gobuster/ffuf/feroxbuster-Web-Pfad-Parser.

Bisher landete die Ausgabe nur als Rohnotiz im Projekt. Jetzt werden
sicherheitsrelevante Pfade (VCS-Verzeichnisse, Secrets, Backups,
Admin-Interfaces) zusätzlich als strukturierte Findings angelegt –
analog zum nuclei-/enum4linux-ng-Parser.
"""
import os
import tempfile


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
    h = repo.add_host(Host(address="10.82.148.95", status="up"))
    return repo, h


GOBUSTER_SAMPLE = """===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 301) [Size: 178]
/.git                 (Status: 200) [Size: 45]
/backup.zip           (Status: 200) [Size: 10240]
/index.html           (Status: 200) [Size: 512]
/secret               (Status: 404) [Size: 0]
===============================================================
"""


class _FakeSpec:
    name = "gobuster"
    category = "web"


def test_gobuster_lines_parsed():
    from pentos.runners.parsers import _parse_gobuster
    hits = _parse_gobuster(GOBUSTER_SAMPLE)
    # 404 wird von gobuster (mit -q, Statuscode-Filter) i.d.R. nicht ausgegeben,
    # ist hier aber absichtlich in der Fixture, um zu prüfen, dass der reine
    # Zeilen-Parser trotzdem alles matched, was wie eine gobuster-Zeile aussieht.
    assert len(hits) == 5
    assert ("/admin", 301, 178) in hits
    assert ("/.git", 200, 45) in hits


def test_paths_findings_created_for_sensitive_hits():
    from pentos.runners.parsers import _parse_gobuster, _paths_findings
    from pentos.models import Severity, FindingCategory
    repo, h = _repo_with_host()
    hits = _parse_gobuster(GOBUSTER_SAMPLE)
    find_n = _paths_findings(repo, _FakeSpec(), "http://10.82.148.95", h.id, hits)
    # .git (HIGH) + backup.zip (MEDIUM) sind sicherheitsrelevant; /admin (301) auch.
    # /index.html und /secret (404, nicht erreichbar) sind es nicht.
    assert find_n == 3
    titles = {f.title: f for f in repo.list_findings()}
    assert "Exponiertes .git-Verzeichnis (http://10.82.148.95)" in titles
    assert "Backup-/Altdatei erreichbar (http://10.82.148.95)" in titles
    assert "Admin-Interface erreichbar (http://10.82.148.95)" in titles
    assert titles["Exponiertes .git-Verzeichnis (http://10.82.148.95)"].severity == Severity.HIGH
    assert titles["Exponiertes .git-Verzeichnis (http://10.82.148.95)"].category == FindingCategory.EXPOSURE
    assert "index.html" not in str(titles)


def test_paths_findings_no_duplicates_on_second_run():
    from pentos.runners.parsers import _parse_gobuster, _paths_findings
    repo, h = _repo_with_host()
    hits = _parse_gobuster(GOBUSTER_SAMPLE)
    n1 = _paths_findings(repo, _FakeSpec(), "http://10.82.148.95", h.id, hits)
    n2 = _paths_findings(repo, _FakeSpec(), "http://10.82.148.95", h.id, hits)
    assert n1 == 3
    assert n2 == 0  # zweiter Lauf: bereits vorhandene Findings nicht doppelt anlegen


def test_paths_findings_none_when_nothing_sensitive():
    from pentos.runners.parsers import _paths_findings
    repo, h = _repo_with_host()
    hits = [("/index.html", 200, 512), ("/robots.txt", 200, 30)]
    find_n = _paths_findings(repo, _FakeSpec(), "http://10.82.148.95", h.id, hits)
    assert find_n == 0
