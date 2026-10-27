"""Audit trail linking manual quarantine operations to prior scan records.

Audit is best-effort and does not provide an atomic transaction across the
quarantine database, filesystem and scan-history database.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import uuid

from .scan_history import get_scan


def _ensure_events(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS quarantine_events (
        event_id TEXT PRIMARY KEY,
        created_utc TEXT NOT NULL,
        scan_id TEXT,
        quarantine_id TEXT NOT NULL,
        action TEXT NOT NULL CHECK(action IN ('quarantined','restored')),
        path TEXT NOT NULL,
        sha256 TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )""")


def match_scan_file(db_path: Path, scan_id: str, file_path: Path, digest: str) -> bool:
    """Match both absolute path and SHA-256 to a prior scan.

    Existing reports may contain relative paths, so resolve relative to the
    current working directory. Only use reports made in the same workspace.
    """
    report = get_scan(db_path, scan_id)
    if report is None:
        return False
    candidate = file_path.absolute()
    return any(
        isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and Path(item["path"]).absolute() == candidate
        and item.get("sha256") == digest
        for item in report.get("files", [])
    )


def record_quarantine_event(
    db_path: Path, *, scan_id: str | None, quarantine_id: str,
    action: str, path: str, sha256: str | None = None,
) -> str:
    """Append a validated audit event. Never modify a previous event."""
    if action not in ("quarantined", "restored"):
        raise ValueError("invalid audit action")
    if not db_path.exists():
        raise ValueError("scan-history database missing")
    event_id = uuid.uuid4().hex
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA foreign_keys=ON")
        _ensure_events(db)
        if scan_id is not None:
            exists = db.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if exists is None:
                raise ValueError("unknown scan id")
        db.execute("INSERT INTO quarantine_events VALUES (?,?,?,?,?,?,?)", (
            event_id, datetime.now(timezone.utc).isoformat(), scan_id,
            quarantine_id, action, path, sha256,
        ))
    return event_id


def linked_scan_id(db_path: Path, quarantine_id: str) -> str | None:
    """Find scan associated with the latest quarantine-add event."""
    if not db_path.exists():
        return None
    with sqlite3.connect(db_path) as db:
        _ensure_events(db)
        row = db.execute(
            "SELECT scan_id FROM quarantine_events WHERE quarantine_id = ? "
            "AND action = 'quarantined' ORDER BY rowid DESC LIMIT 1",
            (quarantine_id,),
        ).fetchone()
    return row[0] if row else None


def list_quarantine_events(db_path: Path, *, scan_id: str | None = None) -> list[dict]:
    if not db_path.exists():
        return []
    with sqlite3.connect(db_path) as db:
        _ensure_events(db)
        if scan_id is None:
            rows = db.execute(
                "SELECT event_id, created_utc, scan_id, quarantine_id, action, path "
                "FROM quarantine_events ORDER BY rowid DESC"
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT event_id, created_utc, scan_id, quarantine_id, action, path "
                "FROM quarantine_events WHERE scan_id = ? ORDER BY rowid DESC",
                (scan_id,),
            ).fetchall()
    keys = ("event_id", "created_utc", "scan_id", "quarantine_id", "action", "path")
    return [dict(zip(keys, row)) for row in rows]
