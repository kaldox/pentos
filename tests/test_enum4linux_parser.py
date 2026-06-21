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
