"""Regressionstest für den nuclei-Parser (strukturiert, Info-Rauschen gefiltert).

Schützt gegen die alte Schwäche: früher wurde aus JEDER Ausgabezeile ein Finding
mit rohem Titel (massenhaft Info-Rauschen). Jetzt: nur Low+ werden Findings mit
sauberem Titel (= Template-ID), Info-Treffer werden gesammelt zurückgegeben.
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


SAMPLE = """[tech-detect:apache] [http] [info] http://10.82.148.95 [Apache]
[http-missing-security-headers] [http] [info] http://10.82.148.95 ["x-frame-options"]
[ssh-server-enumeration] [javascript] [info] 10.82.148.95:22 [SSH-2.0-OpenSSH_8.2p1]
[php-session-id] [http] [info] http://10.82.148.95 [PHPSESSID; path=/]
[CVE-2021-41773] [http] [critical] http://10.82.148.95/cgi-bin/.%2e/
[xss-reflected] [http] [medium] http://10.82.148.95/search?q=
Configuration { dieser Muell darf KEIN Finding werden }
"""


def test_nuclei_only_low_plus_become_findings():
    from pentos.runners.parsers import _parse_nuclei
    repo, h = _repo_with_host()
    find_n, info = _parse_nuclei(repo, None, "10.82.148.95", SAMPLE, h.id)
    assert find_n == 2                  # nur critical + medium
    assert len(info) == 4              # vier Info-Treffer gesammelt
    titles = [f.title for f in repo.list_findings()]
    # Saubere Titel = Template-ID, KEIN roher Zeilen-Müll
    assert "CVE-2021-41773 (10.82.148.95)" in titles
    assert "xss-reflected (10.82.148.95)" in titles
    # Config-Zeile darf kein Finding sein
    assert not any("Configuration" in t for t in titles)


def test_nuclei_severity_mapping():
    from pentos.runners.parsers import _parse_nuclei
    from pentos.models import Severity
    repo, h = _repo_with_host()
    _parse_nuclei(repo, None, "10.82.148.95", SAMPLE, h.id)
    sev = {f.title.split(" (")[0]: f.severity for f in repo.list_findings()}
    assert sev["CVE-2021-41773"] == Severity.CRITICAL
    assert sev["xss-reflected"] == Severity.MEDIUM


def test_nuclei_garbage_lines_ignored():
    from pentos.runners.parsers import _parse_nuclei
    repo, h = _repo_with_host()
    junk = "irgendwas\n\n[unvollständig\nbanner text ohne klammern\n"
    find_n, info = _parse_nuclei(repo, None, "10.82.148.95", junk, h.id)
    assert find_n == 0
    assert info == []
