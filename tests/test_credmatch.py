"""Tests für das Loot-/Credential-Matching (pentos.credmatch)."""
from pentos.credmatch import matches_for
from pentos.models import Loot, LootType, Service


def _svc(port, name=None, proto="tcp"):
    return Service(host_id=1, port=port, name=name, protocol=proto)


def test_credential_matches_smb_and_ssh():
    loot = Loot(type=LootType.CREDENTIAL, label="admin", value="admin:Lab-Passw0rd!")
    hs = [("10.0.0.1", _svc(445, "microsoft-ds")), ("10.0.0.1", _svc(22, "ssh"))]
    ms = matches_for(loot, hs)
    methods = {m.method for m in ms}
    assert any("SMB" in m for m in methods)
    assert any("SSH" in m for m in methods)
    # User/Pass werden in den Hint eingesetzt
    smb = next(m for m in ms if "SMB" in m.method)
    assert "admin" in smb.hint and "Lab-Passw0rd!" in smb.hint
    assert smb.tool == "nxc-smb"


def test_credential_ignores_unrelated_service():
    loot = Loot(type=LootType.CREDENTIAL, label="x", value="u:p")
    hs = [("10.0.0.1", _svc(9999, "unknown"))]
    assert matches_for(loot, hs) == []


def test_hash_pass_the_hash_and_crack_hint():
    loot = Loot(type=LootType.HASH, label="ntlm", value="aad3b...:31d6cfe0d16ae931b73c59d7e0c089c0")
    hs = [("10.0.0.1", _svc(445, "smb")), ("10.0.0.1", _svc(5985, "winrm"))]
    ms = matches_for(loot, hs)
    assert any("Pass-the-Hash" in m.method and "SMB" in m.method for m in ms)
    assert any("Pass-the-Hash" in m.method and "WinRM" in m.method for m in ms)
    # Cracking-Hinweis ist immer dabei (offline, ohne Service)
    crack = [m for m in ms if m.method == "Hash offline knacken"]
    assert len(crack) == 1
    assert crack[0].host == "-"


def test_ssh_key_only_ssh():
    loot = Loot(type=LootType.SSH_KEY, label="id_rsa")
    hs = [("10.0.0.1", _svc(22, "ssh")), ("10.0.0.1", _svc(445, "smb"))]
    ms = matches_for(loot, hs)
    assert len(ms) == 1
    assert ms[0].port == 22
    assert ms[0].tool is None


def test_apikey_targets_web():
    loot = Loot(type=LootType.API_KEY, label="X-Api-Key: abc")
    hs = [("10.0.0.1", _svc(8080, "http-proxy")), ("10.0.0.1", _svc(22, "ssh"))]
    ms = matches_for(loot, hs)
    assert len(ms) == 1
    assert ms[0].port == 8080


def test_password_only_value_uses_placeholder_user():
    loot = Loot(type=LootType.CREDENTIAL, label="found-pw", value="Lab-Passw0rd!")
    hs = [("10.0.0.1", _svc(445, "smb"))]
    ms = matches_for(loot, hs)
    assert "<user>" in ms[0].hint
    assert "Lab-Passw0rd!" in ms[0].hint
