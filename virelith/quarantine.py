"""Opt-in local quarantine prototype; no automatic isolation.

Security boundary: intended for trusted directories and benign test files.
No protection against hostile concurrent filesystem mutations yet.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import uuid
from datetime import datetime, timezone


def _hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _connect(store: Path) -> sqlite3.Connection:
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    if store.is_symlink():
        raise ValueError("symlink store is not allowed")
    os.chmod(store, 0o700)
    db = sqlite3.connect(store / "quarantine.sqlite3")
    db.execute("""CREATE TABLE IF NOT EXISTS quarantine (
        id TEXT PRIMARY KEY, original TEXT NOT NULL, digest TEXT NOT NULL,
        state TEXT NOT NULL, created_utc TEXT NOT NULL)""")
    return db


def quarantine_file(source: Path, store: Path, *, confirmed: bool = False) -> dict:
    """Manually move a regular file into a same-filesystem restricted store."""
    if not confirmed:
        return {"status": "confirmation_required"}
    try:
        source = source.absolute()
        store = store.absolute()
        source_stat = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("only regular non-symlink files are supported")
        if source_stat.st_nlink != 1:
            raise ValueError("hard-linked files cannot be safely quarantined")
        if any(parent.is_symlink() for parent in source.parents if parent.exists()):
            raise ValueError("source parent symlink rejected")
        if source == store or store in source.parents or source in store.parents:
            raise ValueError("source and store must be separate")
        if any(parent.is_symlink() for parent in (store, *store.parents) if parent.exists()):
            raise ValueError("store parent symlink rejected")
        if source.stat().st_dev != store.parent.stat().st_dev:
            raise ValueError("store must be on the same filesystem")
        digest = _hash(source)
        item_id = uuid.uuid4().hex
        with _connect(store) as db:
            target = store / (item_id + ".bin")
            if target.exists():
                raise ValueError("quarantine entry collision")
            # Atomic on same filesystem, but TOCTOU hardening is still needed.
            os.replace(source, target)
            try:
                os.chmod(target, 0o600)
                db.execute("INSERT INTO quarantine VALUES (?,?,?,?,?)", (
                    item_id, str(source), digest, "quarantined",
                    datetime.now(timezone.utc).isoformat()))
                db.commit()
            except Exception:
                os.replace(target, source)
                raise
        return {"status": "quarantined", "id": item_id, "sha256": digest}
    except (OSError, ValueError, sqlite3.Error) as exc:
        return {"status": "error", "detail": str(exc)[:300]}


def list_quarantine(store: Path) -> list[dict]:
    if not (store / "quarantine.sqlite3").exists():
        return []
    with _connect(store) as db:
        rows = db.execute(
            "SELECT id, original, digest, state, created_utc FROM quarantine ORDER BY created_utc DESC"
        ).fetchall()
    return [dict(zip(("id", "original", "sha256", "state", "created_utc"), row)) for row in rows]


def restore_file(item_id: str, store: Path, *, confirmed: bool = False) -> dict:
    """Restore only to the original path, never overwrite an existing file."""
    if not confirmed:
        return {"status": "confirmation_required"}
    try:
        if len(item_id) != 32 or any(c not in "0123456789abcdef" for c in item_id):
            raise ValueError("invalid quarantine id")
        with _connect(store) as db:
            row = db.execute("SELECT original, digest, state FROM quarantine WHERE id = ?",
                             (item_id,)).fetchone()
            if not row or row[2] != "quarantined":
                raise ValueError("entry missing or not quarantined")
            original, digest, _ = row
            source = store / (item_id + ".bin")
            target = Path(original)
            source_stat = source.lstat()
            if source.is_symlink() or not stat.S_ISREG(source_stat.st_mode):
                raise ValueError("invalid stored file")
            if source_stat.st_nlink != 1:
                raise ValueError("hard-linked quarantine entry rejected")
            if any(parent.is_symlink() for parent in target.parents if parent.exists()):
                raise ValueError("restore parent symlink rejected")
            if _hash(source) != digest:
                raise ValueError("stored file checksum mismatch")
            if target.exists() or target.is_symlink():
                raise ValueError("destination already exists")
            if not target.parent.is_dir():
                raise ValueError("original directory missing")
            if source.stat().st_dev != target.parent.stat().st_dev:
                raise ValueError("cross-device restore not supported")
            # Hard link creation is exclusive: fails if a target appears.
            os.link(source, target, follow_symlinks=False)
            try:
                db.execute("UPDATE quarantine SET state = 'restored' WHERE id = ?", (item_id,))
                db.commit()
            except Exception:
                target.unlink()
                raise
            source.unlink()
        return {"status": "restored", "path": str(target)}
    except (OSError, ValueError, sqlite3.Error) as exc:
        return {"status": "error", "detail": str(exc)[:300]}
