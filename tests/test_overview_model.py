from virelith.overview_model import overview_snapshot
from virelith.scan_history import save_scan


def test_overview_without_history(tmp_path):
    result = overview_snapshot(tmp_path / "missing.sqlite3", "not-a-real-clam-command")
    assert result["last_scan"] is None
    assert result["detection_count"] == 0
    assert "no real-time protection" in result["scope"]


def test_overview_uses_actual_history(tmp_path):
    db = tmp_path / "scans.sqlite3"
    save_scan(db, {"target": "sample.txt", "created_utc": "2026-10-28T08:00:00Z",
                   "files": [{"verdict": "detection"}]})
    result = overview_snapshot(db, "not-a-real-clam-command")
    assert result["last_scan"]["target"] == "sample.txt"
    assert result["detection_count"] == 1


def test_rule_store_is_not_claimed_verified(tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    result = overview_snapshot(tmp_path / "missing.db", "", str(store))
    assert "not verified" in result["yara"]
