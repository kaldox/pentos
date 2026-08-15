"""Tests für den BloodHound-CE-Datenimport (SharpHound-JSON, on-prem AD).

Fixture tests/fixtures/sharphound/ folgt dem verifizierten SharpHound-Schema
(data/meta-Wrapper je Datei, Properties-Objekt mit lowercase-Keys wie
hasspn/dontreqpreauth/enabled, Members-Array mit MemberId pro Gruppe).

Testdaten-Übersicht (5 Benutzer, 2 Computer, 2 Gruppen):
- SVC-SQL:    hasspn=true, enabled          -> kerberoastable
- JDOE:       dontreqpreauth=true, enabled  -> AS-REP-roastbar
- OLDACCOUNT: hasspn+dontreqpreauth=true, ABER enabled=false -> wird NICHT gezählt
- KRBTGT:     hasspn=true (immer so)        -> explizit ausgeschlossen
- ADMIN.BOB:  unconstraineddelegation=true, Mitglied Domain Admins (RID 512)
- FILESRV01 (Computer): unconstraineddelegation=true
- Domain Admins (RID 512): ADMIN.BOB + eine nicht auflösbare SID (RID 500,
  kein zugehöriges Benutzerobjekt in der Fixture -> Fallback auf rohe SID)
"""
import pathlib
import tempfile
import zipfile

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "sharphound"


def test_parse_sharphound_from_directory():
    from pentos.importers.bloodhound import parse_sharphound
    summary = parse_sharphound(FIXTURES)
    assert summary["domain"] == "CORP.LOCAL"
    assert summary["user_count"] == 5
    assert summary["computer_count"] == 2
    assert summary["group_count"] == 2


def test_kerberoastable_excludes_disabled_and_krbtgt():
    from pentos.importers.bloodhound import parse_sharphound
    summary = parse_sharphound(FIXTURES)
    assert summary["kerberoastable"] == ["SVC-SQL@CORP.LOCAL"]


def test_asrep_roastable_excludes_disabled():
    from pentos.importers.bloodhound import parse_sharphound
    summary = parse_sharphound(FIXTURES)
    assert summary["asrep_roastable"] == ["JDOE@CORP.LOCAL"]


def test_unconstrained_delegation_users_and_computers():
    from pentos.importers.bloodhound import parse_sharphound
    summary = parse_sharphound(FIXTURES)
    assert set(summary["unconstrained_delegation"]) == {
        "ADMIN.BOB@CORP.LOCAL", "FILESRV01.CORP.LOCAL",
    }


def test_domain_admins_resolved_by_well_known_rid():
    from pentos.importers.bloodhound import parse_sharphound
    summary = parse_sharphound(FIXTURES)
    das = summary["domain_admins"]
    assert "ADMIN.BOB@CORP.LOCAL" in das
    # Mitglied ohne zugehöriges Benutzerobjekt in der Fixture -> Fallback auf die rohe SID
    assert any(sid.endswith("-500") for sid in das)


def test_parse_sharphound_from_zip():
    """Deckt den zweiten unterstützten Eingabeweg ab: ein ZIP-Archiv, wie
    SharpHound es tatsächlich erzeugt (Drag-and-drop in die BloodHound-GUI)."""
    from pentos.importers.bloodhound import parse_sharphound
    with tempfile.TemporaryDirectory() as tmp:
        zpath = pathlib.Path(tmp) / "sharphound_export.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            for f in FIXTURES.glob("*.json"):
                zf.write(f, arcname=f.name)
        summary = parse_sharphound(zpath)
        assert summary["domain"] == "CORP.LOCAL"
        assert summary["kerberoastable"] == ["SVC-SQL@CORP.LOCAL"]


def test_missing_path_raises():
    from pentos.importers.bloodhound import parse_sharphound, BloodHoundImportError
    with pytest.raises(BloodHoundImportError):
        parse_sharphound(pathlib.Path("/does/not/exist.zip"))


def test_empty_directory_raises():
    from pentos.importers.bloodhound import parse_sharphound, BloodHoundImportError
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(BloodHoundImportError):
            parse_sharphound(pathlib.Path(tmp))


def test_invalid_zip_raises():
    from pentos.importers.bloodhound import parse_sharphound, BloodHoundImportError
    with tempfile.TemporaryDirectory() as tmp:
        bogus = pathlib.Path(tmp) / "bogus.zip"
        bogus.write_text("not a zip", encoding="utf-8")
        with pytest.raises(BloodHoundImportError):
            parse_sharphound(bogus)


def test_unrecognized_json_raises():
    """JSON-Dateien ohne SharpHound-data/meta-Struktur -> klare Fehlermeldung
    statt stillschweigend eine leere Zusammenfassung zurückzugeben."""
    from pentos.importers.bloodhound import parse_sharphound, BloodHoundImportError
    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp) / "irgendwas.json"
        p.write_text('{"foo": "bar"}', encoding="utf-8")
        with pytest.raises(BloodHoundImportError):
            parse_sharphound(pathlib.Path(tmp))
