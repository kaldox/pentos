"""Regressionstest für den enum4linux-ng-Parser gegen echte DC-Ausgabe (GOAD-Light).

Fixture stammt aus einem authentifizierten Lauf gegen einen echten Domain
Controller (enum4linux-ng v1.3.10). Schützt die Parser-Logik dauerhaft gegen
Regressionen am realen Ausgabeformat.
"""
import os
import pathlib

from pentos.runners.parsers import _parse_enum4linux_data

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_authenticated_dc_users_and_groups():
    d = _parse_enum4linux_data(_load("enum4linux_auth_dc_full.txt"))
    # Anzahl muss aus der "... total"-Zeile kommen, nicht aus Teilzahlen
    assert d["user_count"] == 4
    assert d["group_count"] == 48
    # Usernamen inkl. krbtgt
    assert {"Administrator", "Guest", "krbtgt", "vagrant"} <= set(d["users"])
    assert d["krbtgt_visible"] is True
    # Gruppennamen mit Leerzeichen müssen vollständig erkannt werden
    assert "Domain Admins" in d["groups"]
    assert "Enterprise Admins" in d["priv_groups"]


def test_domain_sid_and_signing():
    d = _parse_enum4linux_data(_load("enum4linux_auth_dc_full.txt"))
    assert d["domain_sid"] == "S-1-5-21-310869615-4264155859-1587050713"
    assert d["smb_signing_required"] is True
    assert d["null_session"] is True


def test_shares_access_parsing():
    d = _parse_enum4linux_data(_load("enum4linux_auth_dc_full.txt"))
    shares = {s["name"]: s for s in d["shares"]}
    assert shares  # nicht leer
    # IPC$ darf NICHT als anonym lesbar gewertet werden (Listing NOT SUPPORTED)
    ipc = next((s for s in d["shares"] if "IPC" in s["name"]), None)
    assert ipc is not None
    assert "not supported" in ipc["access"].lower()


def test_share_names_normalized_without_backslash_escaping():
    """Regression: enum4linux-ng schreibt Default-Shares Backslash-escaped
    ('ADMIN\\$:', 'IPC\\$:'). Die alte Header-Regex kannte keinen Backslash,
    liess 'cur' dadurch None und liess 'type' fuer diese Shares immer bei
    '?' stehen -- ausserdem verglich der IPC$-Ausschluss unten gegen den
    sauberen String 'IPC$', der wegen des Backslashs nie zutraf."""
    d = _parse_enum4linux_data(_load("enum4linux_auth_dc_full.txt"))
    shares = {s["name"]: s for s in d["shares"]}
    # Namen sind normalisiert (kein Backslash mehr im Namen selbst)
    assert "ADMIN$" in shares
    assert "IPC$" in shares
    assert not any("\\" in name for name in shares)
    # Typ wird jetzt korrekt aus dem Definitionsblock uebernommen, nicht '?'
    assert shares["ADMIN$"]["type"] == "Disk"
    assert shares["IPC$"]["type"] == "IPC"


_IPC_READABLE_SAMPLE = """[+] Got domain/workgroup name: CORP
[+] NetBIOS computer name: DC01
[+] FQDN: dc01.corp.local
OS: Windows Server 2019
Server type string: Windows Server 2019
[+] Attempting to authenticate via username '' and password ''
ADMIN\\$:
  type: Disk
IPC\\$:
  type: IPC
[*] Testing share ADMIN\\$
[+] Mapping: OK, Listing: OK
[*] Testing share IPC\\$
[+] Mapping: OK, Listing: OK
"""


def test_ipc_share_excluded_from_anonymous_readable_finding():
    """Regression: der IPC$-Ausschluss in _ingest_enum4linux griff nie, weil
    s['name'] wegen des Backslash-Bugs 'IPC\\$' statt 'IPC$' war. IPC$-
    Nullsession-Listing ist normales SMB-Verhalten, keine echte Schwachstelle
    -- anders als bei ADMIN$, das hier bewusst als echtes Finding auftauchen soll."""
    import tempfile
    from pentos.runners.parsers import _ingest_enum4linux

    class _FakeSpec:
        name = "enum4linux-ng"
        category = "smb"

    cfg = tempfile.mkdtemp()
    import os
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
    config.project_path("e").mkdir(parents=True, exist_ok=True)
    db_mod.init_db(config.db_path("e"))
    repo = Repository(config.db_path("e"))
    h = repo.add_host(Host(address="10.10.10.5"))

    _ingest_enum4linux(repo, _FakeSpec(), "10.10.10.5", _IPC_READABLE_SAMPLE, h.id)
    titles = [f.title for f in repo.list_findings()]
    assert not any("IPC$" in t and "Anonym lesbarer SMB-Share" in t for t in titles)
    assert any("ADMIN$" in t and "Anonym lesbarer SMB-Share" in t for t in titles)
    repo.close()
