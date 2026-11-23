"""Scanner provenance is captured once and stored with each scan report."""
from pathlib import Path
from types import SimpleNamespace

from virelith import cli


def test_scanner_versions_parse_clamav_database_number(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="ClamAV 1.4.6/28173/Tue Nov 3 2026",
            stderr="",
        )
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli, "package_version", lambda name: "1.20.0")
    assert cli.scanner_versions("clamscan") == {
        "clamav": {"engine": "1.4.6", "signature_database": "28173"},
        "yara_x": "1.20.0",
    }


def test_scanner_versions_fail_closed_to_unknown(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("clamscan missing")
    monkeypatch.setattr(cli.subprocess, "run", missing)
    monkeypatch.setattr(cli, "package_version", lambda name: "1.20.0")
    result = cli.scanner_versions("missing-clamscan")
    assert result["clamav"] == {
        "engine": "unknown", "signature_database": "unknown"
    }
    assert result["yara_x"] == "1.20.0"


def test_report_payload_keeps_version_provenance():
    args = SimpleNamespace(created_utc="2026-11-23T08:00:00+00:00",
                           target=Path("/tmp/sample.exe"))
    engines = {
        "clamav": {"engine": "1.4.6", "signature_database": "28173"},
        "yara_x": "1.20.0",
    }
    report = cli.report_payload(args, [], {"source": "signed_store", "version": "2.0.0"},
                                engine_metadata=engines)
    assert report["engines"] == engines
    assert report["yara_rules"]["version"] == "2.0.0"
