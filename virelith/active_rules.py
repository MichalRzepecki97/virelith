"""Resolve and verify locally activated YARA rules before scanning."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

_FILENAME = re.compile(r"^rules-[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{16}\.yar$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_BYTES = 4 * 1024 * 1024


def load_active_rules(store_dir: Path) -> tuple[str, dict]:
    """Return verified rule source and metadata; raise ValueError on fail-closed errors.

    Intended for a trusted local store, not a directory writable by an attacker.
    """
    state_file = store_dir / "current.json"
    if store_dir.is_symlink() or state_file.is_symlink():
        raise ValueError("symlink update store rejected")
    try:
        if state_file.stat().st_size > 16384:
            raise ValueError("active metadata too large")
        state = json.loads(state_file.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise ValueError("invalid active state")
        version, filename, digest = (state.get(k) for k in ("version", "file", "sha256"))
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError("invalid active version")
        if not isinstance(filename, str) or not _FILENAME.fullmatch(filename):
            raise ValueError("invalid rule filename")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError("invalid active digest")
        if filename != f"rules-{version}-{digest[:16]}.yar":
            raise ValueError("active filename mismatch")
        file_path = store_dir / filename
        if file_path.is_symlink():
            raise ValueError("symlink rule file rejected")
        if file_path.stat().st_size > _MAX_BYTES:
            raise ValueError("active rules too large")
        contents = file_path.read_bytes()
        if hashlib.sha256(contents).hexdigest() != digest:
            raise ValueError("active rules checksum mismatch")
        return contents.decode("utf-8"), {
            "source": "signed_store", "version": version, "sha256": digest,
            "path": str(file_path),
        }
    except (OSError, UnicodeError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load active YARA rules: {exc}") from exc
