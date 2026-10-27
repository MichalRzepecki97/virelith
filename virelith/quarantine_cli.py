"""Explicit manual quarantine commands for trusted test files only."""
import argparse
import json
from pathlib import Path

from .quarantine import list_quarantine, quarantine_file, restore_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Virelith experimental manual quarantine")
    parser.add_argument("--store", type=Path, required=True, help="restricted local quarantine directory")
    commands = parser.add_subparsers(dest="action", required=True)
    add = commands.add_parser("add", help="move regular file to quarantine")
    add.add_argument("path", type=Path)
    add.add_argument("--confirm", action="store_true", required=True)
    commands.add_parser("list", help="show entries")
    restore = commands.add_parser("restore", help="restore an entry")
    restore.add_argument("id")
    restore.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args()
    if args.action == "add":
        result = quarantine_file(args.path, args.store, confirmed=args.confirm)
    elif args.action == "restore":
        result = restore_file(args.id, args.store, confirmed=args.confirm)
    else:
        result = {"status": "ok", "entries": list_quarantine(args.store)}
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"ok", "quarantined", "restored"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
