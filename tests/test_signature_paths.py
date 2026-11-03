"""Platform-aware ClamAV discovery should not invent databases or updaters."""
from pathlib import Path
from unittest.mock import patch

from virelith.signature_paths import (
    database_candidates, choose_database_dir, find_freshclam,
)
from virelith.signature_management import signature_snapshot


def test_windows_database_candidates(tmp_path):
    env = {"PROGRAMDATA": str(tmp_path / "pd"),
           "ProgramFiles": str(tmp_path / "pf")}
    candidates = database_candidates(platform="win32", environ=env)
    assert Path(env["PROGRAMDATA"]) / "ClamAV" / "database" in candidates
    assert Path(env["ProgramFiles"]) / "ClamAV" / "database" in candidates


def test_discovery_prefers_existing_signatures(tmp_path):
    empty = tmp_path / "empty"
    good = tmp_path / "db"
    empty.mkdir()
    good.mkdir()
    (good / "daily.cld").write_bytes(b"test database marker, not a real database")
    path, found = choose_database_dir(candidates=[empty, good])
    assert path == good
    assert found is True


def test_missing_database_returns_unknown():
    path, found = choose_database_dir(candidates=[])
    assert path is None and found is False


def test_discovery_does_not_follow_directory_symlink(tmp_path):
    database = tmp_path / "database"
    database.mkdir()
    (database / "main.cvd").write_bytes(b"demo")
    alias = tmp_path / "alias"
    alias.symlink_to(database, target_is_directory=True)
    path, found = choose_database_dir(candidates=[alias])
    assert path is None and found is False


def test_updater_found_next_to_configured_windows_scanner(tmp_path):
    scanner = tmp_path / "clamscan.exe"
    updater = tmp_path / "freshclam.exe"
    scanner.touch()
    updater.touch()
    with patch("virelith.signature_paths.shutil.which", return_value=None):
        assert find_freshclam(str(scanner), platform="win32") == str(updater)


def test_snapshot_reports_no_database_without_claiming_freshness():
    with patch("virelith.signature_management.choose_database_dir", return_value=(None, False)), \
         patch("virelith.signature_management.clamav_status", return_value={
             "status": "database_missing", "databases": [], "engine_version": "ClamAV demo"
         }), \
         patch("virelith.signature_management.find_freshclam", return_value=None):
        state = signature_snapshot()
    assert state["database_path"] == "Not discovered"
    assert state["database_discovered"] is False
    assert state["freshclam_available"] is False
    assert "not verified" in state["notice"]
