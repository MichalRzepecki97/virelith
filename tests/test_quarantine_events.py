import hashlib
from pathlib import Path

import pytest

from virelith.scan_history import save_scan
from virelith.quarantine_events import (
    list_quarantine_events, linked_scan_id, match_scan_file, record_quarantine_event,
)


def setup_history(tmp_path):
    file = tmp_path / "sample.txt"
    file.write_text("test-data")
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    db = tmp_path / "history.sqlite3"
    scan_id = save_scan(db, {
        "created_utc": "2026-10-27T00:00:00Z",
        "target": str(file),
        "files": [{"path": str(file), "sha256": digest, "verdict": "detection"}],
    })
    return db, scan_id, file, digest


def test_match_requires_path_and_hash(tmp_path):
    db, scan, file, digest = setup_history(tmp_path)
    assert match_scan_file(db, scan, file, digest)
    assert not match_scan_file(db, scan, file, "0" * 64)
    assert not match_scan_file(db, scan, tmp_path / "other.txt", digest)


def test_record_and_read_events(tmp_path):
    db, scan, file, digest = setup_history(tmp_path)
    record_quarantine_event(db, scan_id=scan, quarantine_id="abc",
                            action="quarantined", path=str(file), sha256=digest)
    assert linked_scan_id(db, "abc") == scan
    assert list_quarantine_events(db, scan_id=scan)[0]["action"] == "quarantined"
    record_quarantine_event(db, scan_id=scan, quarantine_id="abc",
                            action="restored", path=str(file), sha256=digest)
    assert [e["action"] for e in list_quarantine_events(db)] == [
        "restored", "quarantined"
    ]


def test_reject_unknown_scan(tmp_path):
    db, _, file, _ = setup_history(tmp_path)
    with pytest.raises(ValueError, match="unknown scan"):
        record_quarantine_event(db, scan_id="missing", quarantine_id="abc",
                                action="quarantined", path=str(file))


def test_reject_unknown_action(tmp_path):
    db, _, file, _ = setup_history(tmp_path)
    with pytest.raises(ValueError, match="invalid audit action"):
        record_quarantine_event(db, scan_id=None, quarantine_id="abc",
                                action="deleted", path=str(file))


def test_missing_history(tmp_path):
    db = tmp_path / "missing.sqlite3"
    assert list_quarantine_events(db) == []
    assert linked_scan_id(db, "abc") is None
