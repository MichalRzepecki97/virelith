"""Safe integration test: scan metadata -> quarantine -> restore audit."""
import hashlib
import json
import sys

from virelith.quarantine_cli import main
from virelith.scan_history import save_scan
from virelith.quarantine_events import list_quarantine_events
from virelith.quarantine import list_quarantine


def test_manual_quarantine_tracks_scan_and_restore(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("benign fixture")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    db = tmp_path / "history.sqlite3"
    scan_id = save_scan(db, {"created_utc": "2026-10-27T00:00:00Z",
        "target": str(sample), "files": [{"path": str(sample),
        "sha256": digest, "verdict": "detection"}]})
    store = tmp_path / "quarantine"
    monkeypatch.setattr(sys, "argv", ["virelith-quarantine",
        "--store", str(store), "--history-db", str(db),
        "add", str(sample), "--scan-id", scan_id, "--confirm"])
    assert main() == 0
    add = json.loads(capsys.readouterr().out)
    assert add["status"] == "quarantined"
    assert not sample.exists()

    monkeypatch.setattr(sys, "argv", ["virelith-quarantine",
        "--store", str(store), "--history-db", str(db),
        "restore", add["id"], "--confirm"])
    assert main() == 0
    assert sample.read_text() == "benign fixture"
    assert [event["action"] for event in list_quarantine_events(db, scan_id=scan_id)] == [
        "restored", "quarantined"]
    assert list_quarantine(store)[0]["state"] == "restored"


def test_refuses_mismatched_scan(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("different")
    db = tmp_path / "history.sqlite3"
    scan_id = save_scan(db, {"created_utc": "2026-10-27T00:00:00Z",
        "target": str(sample), "files": [{"path": str(sample),
        "sha256": "0" * 64, "verdict": "detection"}]})
    monkeypatch.setattr(sys, "argv", ["virelith-quarantine",
        "--store", str(tmp_path / "store"), "--history-db", str(db),
        "add", str(sample), "--scan-id", scan_id, "--confirm"])
    assert main() == 2
    assert sample.exists()
    assert list_quarantine_events(db, scan_id=scan_id) == []
