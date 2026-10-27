from virelith.scan_history import save_scan, recent_scans, get_scan

def test_history_roundtrip(tmp_path):
    db = tmp_path / "history.sqlite3"
    report = {"created_utc": "2026-10-27T00:00:00+00:00",
              "target": "demo", "files": [{"verdict": "detection"}, {"verdict": "no_detection"}]}
    scan_id = save_scan(db, report)
    rows = recent_scans(db)
    assert len(rows) == 1
    assert rows[0]["detections"] == 1
    assert get_scan(db, scan_id) == report

def test_empty_history(tmp_path):
    assert recent_scans(tmp_path / "missing.sqlite3") == []

def test_invalid_report(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        save_scan(tmp_path / "history.sqlite3", {"files": None})

def test_limit_validation(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        recent_scans(tmp_path / "history.sqlite3", 0)

def test_missing_scan(tmp_path):
    assert get_scan(tmp_path / "missing.sqlite3", "missing") is None
