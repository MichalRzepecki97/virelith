"""SQLite scan history. Stores metadata, not raw scanned file contents."""
from __future__ import annotations
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

def save_scan(db_path: Path, report: dict) -> str:
    if not isinstance(report, dict) or not isinstance(report.get("files"), list):
        raise ValueError("invalid scan report")
    scan_id = uuid4().hex
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, created_utc TEXT NOT NULL,
            target TEXT NOT NULL, file_count INTEGER NOT NULL,
            detections INTEGER NOT NULL, report_json TEXT NOT NULL)""")
        db.execute("""INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)""", (
            scan_id, str(report.get("created_utc", "")),
            str(report.get("target", "")), len(report["files"]),
            sum(1 for f in report["files"] if isinstance(f, dict)
                and f.get("verdict") == "detection"),
            json.dumps(report, ensure_ascii=False)))
    return scan_id

def recent_scans(db_path: Path, limit: int = 20) -> list[dict]:
    if not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not db_path.exists():
        return []
    with sqlite3.connect(db_path) as db:
        rows = db.execute(
            "SELECT id, created_utc, target, file_count, detections FROM scans "
            "ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
    return [dict(zip(("id", "created_utc", "target", "file_count", "detections"), row))
            for row in rows]

def get_scan(db_path: Path, scan_id: str) -> dict | None:
    if not db_path.exists():
        return None
    with sqlite3.connect(db_path) as db:
        row = db.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row[0]) if row else None
