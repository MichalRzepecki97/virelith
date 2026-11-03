"""Compare stored scan evidence for identical file SHA-256, without rescanning.

Comparisons are limited to stored evidence; a change in signatures or results
is not proof of new malware. SQLite database is local and not tamper-proof.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_MAX_REPORTS = 500


def _file_evidence(report: dict, digest: str) -> dict | None:
    files = report.get("files", [])
    if not isinstance(files, list):
        return None
    for item in files:
        if (isinstance(item, dict)
                and str(item.get("sha256") or "").lower() == digest):
            return item
    return None


def matching_scans(db_path: Path, sha256: str, limit: int = 10) -> list[dict]:
    """Search most recent bounded history, newest first; never open files."""
    if not _SHA256.fullmatch(sha256):
        raise ValueError("valid SHA-256 required for history comparison")
    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    if not db_path.is_file():
        return []
    matched = []
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT created_utc, report_json FROM scans ORDER BY rowid DESC LIMIT ?",
            (_MAX_REPORTS,),
        )
        for timestamp, source in rows:
            try:
                report = json.loads(source)
                if not isinstance(report, dict):
                    continue
                item = _file_evidence(report, sha256.lower())
            except (ValueError, TypeError):
                continue
            if item is not None:
                matched.append({
                    "timestamp": str(timestamp),
                    "file": item,
                    "rules": report.get("yara_rules") or {},
                    "complete": report.get("complete", True),
                })
                if len(matched) >= limit:
                    break
    return matched


def _engine_status(file: dict, name: str) -> str:
    engine = file.get(name)
    return str(engine.get("status", "unknown")) if isinstance(engine, dict) else "unknown"


def _matches(file: dict) -> list[str]:
    yara = file.get("yara") or {}
    values = yara.get("matches", []) if isinstance(yara, dict) else []
    return sorted({str(value) for value in values if isinstance(value, str)}) if isinstance(values, list) else []


def _insights(file: dict) -> list[str]:
    values = file.get("insight") or []
    return sorted({str(x["id"]) for x in values
                   if isinstance(x, dict) and isinstance(x.get("id"), str)}) if isinstance(values, list) else []


def compare_two(older: dict, newer: dict) -> dict:
    """Explain changes only; caller determines which snapshot is older."""
    a, b = older["file"], newer["file"]
    fields = {
        "verdict": (str(a.get("verdict", "unknown")), str(b.get("verdict", "unknown"))),
        "clamav_status": (_engine_status(a, "clamav"), _engine_status(b, "clamav")),
        "yara_status": (_engine_status(a, "yara"), _engine_status(b, "yara")),
        "yara_matches": (_matches(a), _matches(b)),
        "insight_ids": (_insights(a), _insights(b)),
        "rule_version": (str((older.get("rules") or {}).get("version", "unknown")),
                         str((newer.get("rules") or {}).get("version", "unknown"))),
        "scan_complete": (bool(older.get("complete", True)),
                          bool(newer.get("complete", True))),
    }
    return {
        "older": older["timestamp"], "newer": newer["timestamp"],
        "changes": {k: {"before": x, "after": y} for k, (x, y) in fields.items() if x != y},
        "same_hash": a.get("sha256", "").lower() == b.get("sha256", "").lower(),
        "notice": "Local historical comparison only; no new scan or malware verdict.",
    }


def compare_file_history(db_path: Path, sha256: str) -> dict:
    records = matching_scans(db_path, sha256, limit=2)
    if len(records) < 2:
        return {"status": "insufficient_history", "count": len(records)}
    return {"status": "compared", "count": 2,
            "comparison": compare_two(records[1], records[0])}
