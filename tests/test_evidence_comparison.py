"""Compare historic evidence only when SHA-256 identifies the same sample."""
import pytest

from virelith.evidence_comparison import compare_file_history, matching_scans
from virelith.scan_history import save_scan

A = "a" * 64


def report(when, verdict, yara_status, matches=(), rule_version=None):
    return {
        "created_utc": when, "target": "/tmp/demo.exe",
        "complete": True,
        "yara_rules": {"version": rule_version} if rule_version else {},
        "files": [{"path": "/tmp/demo.exe", "sha256": A, "verdict": verdict,
                   "clamav": {"status": "no_detection"},
                   "yara": {"status": yara_status, "matches": list(matches)},
                   "insight": [{"id": "api_process_memory"}]}],
    }


def test_matching_and_change_detection(tmp_path):
    db = tmp_path / "hist.sqlite"
    save_scan(db, report("2026-01-01", "no_detection", "no_detection", rule_version="1.0.0"))
    save_scan(db, report("2026-01-02", "detection", "detected", ["Demo"], "1.1.0"))
    outcome = compare_file_history(db, A)
    assert outcome["status"] == "compared"
    changes = outcome["comparison"]["changes"]
    assert changes["verdict"]["before"] == "no_detection"
    assert changes["verdict"]["after"] == "detection"
    assert changes["yara_matches"]["after"] == ["Demo"]
    assert changes["rule_version"]["after"] == "1.1.0"
    assert outcome["comparison"]["same_hash"] is True


def test_no_cross_file_comparisons(tmp_path):
    db = tmp_path / "hist.sqlite"
    save_scan(db, report("2026-01-01", "no_detection", "no_detection"))
    other = report("2026-01-02", "detection", "detected")
    other["files"][0]["sha256"] = "b" * 64
    save_scan(db, other)
    assert compare_file_history(db, A)["status"] == "insufficient_history"


def test_identical_scans_do_not_invent_differences(tmp_path):
    db = tmp_path / "hist.sqlite"
    save_scan(db, report("1", "no_detection", "no_detection"))
    save_scan(db, report("2", "no_detection", "no_detection"))
    assert compare_file_history(db, A)["comparison"]["changes"] == {}


def test_invalid_digest_rejected(tmp_path):
    with pytest.raises(ValueError):
        matching_scans(tmp_path / "hist.sqlite", "not-a-hash")


def test_no_history(tmp_path):
    assert compare_file_history(tmp_path / "missing.db", A)["count"] == 0
