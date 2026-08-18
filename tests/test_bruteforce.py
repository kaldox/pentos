"""Tests für die Brute-Force-Argument-Zuordnung (pentos.bruteforce).

Regressionsschutz für den ursprünglichen Bug: 'pentos run hydra <ziel>'
brauchte zwingend -L/-P + Protokoll als händisch (und korrekt) zusammen-
gebautes --args -- inkl. eines hartkodierten, nie zuverlässig aufgelösten
relativen Pfads. Diese Zuordnung ist jetzt hier zentral getestet.
"""
import pytest

from pentos import bruteforce


def test_supported_tools_list():
    assert bruteforce.is_supported("hydra")
    assert bruteforce.is_supported("medusa")
    assert bruteforce.is_supported("nxc-smb")
    assert bruteforce.is_supported("nxc-winrm")


def test_kerbrute_and_unknown_tools_not_supported():
    # kerbrute: reine User-Enumeration, nutzt bereits den generischen
    # --wordlist-Mechanismus -- bewusst NICHT Teil dieser Kurzform.
    assert not bruteforce.is_supported("kerbrute")
    assert not bruteforce.is_supported("nmap")
    assert not bruteforce.is_supported("does-not-exist")


def test_needs_proto_hydra_and_medusa_only():
    assert bruteforce.needs_proto("hydra")
    assert bruteforce.needs_proto("medusa")
    assert not bruteforce.needs_proto("nxc-smb")
    assert not bruteforce.needs_proto("nxc-winrm")


def test_build_args_hydra_uses_capital_l_p_plus_trailing_proto():
    argv = bruteforce.build_args("hydra", "/p/users.txt", "/p/pass.txt", "ssh")
    assert argv == ["-L", "/p/users.txt", "-P", "/p/pass.txt", "ssh"]


def test_build_args_medusa_uses_dash_m_module():
    argv = bruteforce.build_args("medusa", "/p/users.txt", "/p/pass.txt", "ssh")
    assert argv == ["-U", "/p/users.txt", "-P", "/p/pass.txt", "-M", "ssh"]


def test_build_args_nxc_smb_and_winrm_no_proto_token():
    argv_smb = bruteforce.build_args("nxc-smb", "/p/users.txt", "/p/pass.txt", None)
    argv_winrm = bruteforce.build_args("nxc-winrm", "/p/users.txt", "/p/pass.txt", None)
    assert argv_smb == ["-u", "/p/users.txt", "-p", "/p/pass.txt"]
    assert argv_winrm == ["-u", "/p/users.txt", "-p", "/p/pass.txt"]


def test_build_args_hydra_without_proto_raises():
    with pytest.raises(ValueError, match="proto"):
        bruteforce.build_args("hydra", "/p/users.txt", "/p/pass.txt", None)


def test_build_args_medusa_without_proto_raises():
    with pytest.raises(ValueError, match="proto"):
        bruteforce.build_args("medusa", "/p/users.txt", "/p/pass.txt", None)


def test_build_args_unsupported_tool_raises():
    with pytest.raises(ValueError, match="unterst"):
        bruteforce.build_args("kerbrute", "/p/users.txt", "/p/pass.txt", None)
