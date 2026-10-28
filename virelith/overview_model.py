"""Read-only overview data; never claim system-wide protection."""
from __future__ import annotations
from pathlib import Path
import shutil
import sqlite3
from .scan_history import recent_scans


def overview_snapshot(db_path: Path, clam_executable: str, rule_store: str = "") -> dict:
    executable = (shutil.which(clam_executable) if clam_executable else None)
    if not executable and clam_executable:
        path = Path(clam_executable).expanduser()
        executable = str(path) if path.is_file() else None
    rules_path = Path(rule_store).expanduser() if rule_store.strip() else None
    if rules_path:
        rules_status = ("Configured · not verified" if rules_path.is_dir()
                        else "Configured path missing")
    else:
        rules_status = "Bundled test rules · not a production signature set"
    try:
        recent = recent_scans(db_path, limit=5)
        history_error = None
    except (sqlite3.Error, OSError, ValueError) as exc:
        recent, history_error = [], str(exc)[:180]
    return {
        "clamav": "Executable found" if executable else "Executable not found",
        "yara": rules_status,
        "history": recent,
        "history_error": history_error,
        "last_scan": recent[0] if recent else None,
        "detection_count": sum(row["detections"] for row in recent),
        "scope": "On-demand scans only · no real-time protection",
    }
