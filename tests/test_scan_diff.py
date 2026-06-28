"""Tests für den Scan-Diff (pentos.diff)."""
from pentos.diff import diff_maps, index_parsed, diff_parsed_against_repo
from pentos.models import Host, Service


def _svc(port, name=None, product=None, version=None, proto="tcp"):
    return {"name": name, "product": product, "version": version}


def test_new_host_and_services():
    existing = {"10.0.0.1": {(22, "tcp"): _svc(22, "ssh")}}
    scanned = {
        "10.0.0.1": {(22, "tcp"): _svc(22, "ssh")},
        "10.0.0.2": {(80, "tcp"): _svc(80, "http")},
    }
    d = diff_maps(existing, scanned)
    assert d.new_hosts == ["10.0.0.2"]
    assert len(d.new_services) == 1
    assert d.new_services[0].host == "10.0.0.2"
    assert d.new_services[0].port == 80
    assert d.unchanged == 1
    assert d.has_changes


def test_new_service_on_known_host():
    existing = {"10.0.0.1": {(22, "tcp"): _svc(22, "ssh")}}
    scanned = {"10.0.0.1": {(22, "tcp"): _svc(22, "ssh"), (445, "tcp"): _svc(445, "smb")}}
    d = diff_maps(existing, scanned)
    assert d.new_hosts == []
    assert [s.port for s in d.new_services] == [445]
    assert d.unchanged == 1


def test_version_change_detected():
    existing = {"10.0.0.1": {(80, "tcp"): _svc(80, "http", "Apache", "2.4.41")}}
    scanned = {"10.0.0.1": {(80, "tcp"): _svc(80, "http", "Apache", "2.4.52")}}
    d = diff_maps(existing, scanned)
    assert len(d.changed_services) == 1
    c = d.changed_services[0]
    assert c.before == "Apache 2.4.41"
    assert c.after == "Apache 2.4.52"
    assert d.unchanged == 0


def test_identical_no_change():
    existing = {"10.0.0.1": {(80, "tcp"): _svc(80, "http", "Apache", "2.4.41")}}
    d = diff_maps(existing, dict(existing))
    assert not d.has_changes
    assert d.unchanged == 1


def test_missing_host_and_service():
    existing = {
        "10.0.0.1": {(22, "tcp"): _svc(22, "ssh")},
        "10.0.0.9": {(23, "tcp"): _svc(23, "telnet")},
    }
    scanned = {"10.0.0.1": {}}
    d = diff_maps(existing, scanned)
    assert d.missing_hosts == ["10.0.0.9"]
    assert [s.port for s in d.missing_services] == [22]


def test_index_parsed_roundtrip():
    h = Host(id=1, address="10.0.0.5")
    s = Service(id=1, host_id=1, port=445, name="smb")
    m = index_parsed([(h, [s])])
    assert m == {"10.0.0.5": {(445, "tcp"): {"name": "smb", "product": None, "version": None}}}


def test_diff_parsed_against_repo():
    # Repo kennt nur den SSH-Host, der Scan bringt zusätzlich SMB.
    hosts = [Host(id=1, address="10.0.0.1")]
    services = [Service(id=1, host_id=1, port=22, name="ssh")]
    parsed = [(Host(address="10.0.0.1"),
               [Service(host_id=0, port=22, name="ssh"),
                Service(host_id=0, port=445, name="smb")])]
    d = diff_parsed_against_repo(parsed, hosts, services)
    assert [s.port for s in d.new_services] == [445]
    assert d.new_hosts == []
