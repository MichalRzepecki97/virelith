"""Explicit manual quarantine commands for trusted test files only."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from .quarantine import list_quarantine, quarantine_file, restore_file
from .quarantine_events import (
    linked_scan_id, list_quarantine_events, match_scan_file, record_quarantine_event,
)


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Virelith experimental manual quarantine")
    parser.add_argument("--store", type=Path, required=True, help="restricted local quarantine directory")
    parser.add_argument("--history-db", type=Path, help="scan history used for append-only events")
    commands = parser.add_subparsers(dest="action", required=True)
    add = commands.add_parser("add", help="move regular file to quarantine")
    add.add_argument("path", type=Path)
    add.add_argument("--scan-id", help="link to a prior scan of the identical file")
    add.add_argument("--confirm", action="store_true", required=True)
    commands.add_parser("list", help="show entries")
    events = commands.add_parser("events", help="show quarantine audit events")
    events.add_argument("--scan-id", help="filter by scan")
    restore = commands.add_parser("restore", help="restore an entry")
    restore.add_argument("id")
    restore.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args()

    if args.action == "events":
        if args.history_db is None:
            parser.error("events requires --history-db")
        result = {"status": "ok", "events": list_quarantine_events(
            args.history_db, scan_id=args.scan_id)}
    elif args.action == "list":
        result = {"status": "ok", "entries": list_quarantine(args.store)}
    elif args.action == "add":
        if args.scan_id and args.history_db is None:
            parser.error("--scan-id requires --history-db")
        path = args.path.absolute()
        try:
            digest = _digest(path)
            if args.scan_id and not match_scan_file(
                args.history_db, args.scan_id, path, digest
            ):
                result = {"status": "error", "detail": "file does not match prior scan"}
            else:
                result = quarantine_file(path, args.store, confirmed=args.confirm)
        except OSError as exc:
            result = {"status": "error", "detail": str(exc)}
        if result["status"] == "quarantined" and args.history_db is not None:
            try:
                result["event_id"] = record_quarantine_event(
                    args.history_db, scan_id=args.scan_id, quarantine_id=result["id"],
                    action="quarantined", path=str(path), sha256=result["sha256"])
            except (OSError, ValueError, __import__("sqlite3").Error) as exc:
                result["audit_warning"] = str(exc)
                print(f"AUDIT FAILURE: {exc}", file=sys.stderr)
                print(json.dumps(result, indent=2))
                return 2
    else:
        entry = next((e for e in list_quarantine(args.store)
                      if e["id"] == args.id and e["state"] == "quarantined"), None)
        result = restore_file(args.id, args.store, confirmed=args.confirm)
        if result["status"] == "restored" and args.history_db is not None:
            try:
                scan_id = linked_scan_id(args.history_db, args.id)
                result["event_id"] = record_quarantine_event(
                    args.history_db, scan_id=scan_id, quarantine_id=args.id,
                    action="restored", path=result["path"],
                    sha256=entry["sha256"] if entry else None)
            except (OSError, ValueError, __import__("sqlite3").Error) as exc:
                result["audit_warning"] = str(exc)
                print(f"AUDIT FAILURE: {exc}", file=sys.stderr)
                print(json.dumps(result, indent=2))
                return 2
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"ok", "quarantined", "restored"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
