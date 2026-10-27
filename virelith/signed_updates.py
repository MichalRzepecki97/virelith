"""Offline signed YARA bundle activation (v0.5 prototype).

Do not treat this as a network updater. Trust root must be provisioned
independently; this API assumes a single local administrator.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_MAX_RULE_BYTES = 4 * 1024 * 1024
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def _version(text: str) -> tuple[int, int, int]:
    if not isinstance(text, str) or not _SEMVER.fullmatch(text) or len(text) > 64:
        raise ValueError("version must be numeric major.minor.patch")
    return tuple(int(x) for x in text.split("."))


def _atomic_json(path: Path, data: dict) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".virelith-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def activate_signed_rules(
    rules_path: Path,
    manifest_path: Path,
    signature_path: Path,
    trusted_public_key_path: Path,
    store_dir: Path,
) -> dict:
    """Verify Ed25519 signature over EXACT manifest bytes, then compile & activate.

    Manifest JSON: {"version":"1.0.0","sha256":"<hex>"}.
    Signature and public key are raw byte files (64 and 32 bytes respectively).
    Do not take the public key from the update package.
    """
    import yara_x

    try:
        for path in (rules_path, manifest_path, signature_path, trusted_public_key_path):
            if path.is_symlink():
                raise ValueError("symlink input forbidden")
        if store_dir.is_symlink():
            raise ValueError("symlink store forbidden")
        manifest_bytes = manifest_path.read_bytes()
        if len(manifest_bytes) > 4096:
            raise ValueError("manifest too large")
        pub = trusted_public_key_path.read_bytes()
        sig = signature_path.read_bytes()
        if len(pub) != 32 or len(sig) != 64:
            raise ValueError("invalid key or signature size")
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, manifest_bytes)
        metadata = json.loads(manifest_bytes)
        if not isinstance(metadata, dict) or set(metadata) != {"version", "sha256"}:
            raise ValueError("unexpected manifest fields")
        version = metadata["version"]
        parsed = _version(version)
        digest = metadata["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid digest")
        if rules_path.stat().st_size > _MAX_RULE_BYTES:
            raise ValueError("rules too large")
        rules = rules_path.read_bytes()
        if hashlib.sha256(rules).hexdigest() != digest:
            raise ValueError("digest mismatch")
        yara_x.compile(rules.decode("utf-8"))

        store_dir.mkdir(parents=True, exist_ok=True)
        current_path = store_dir / "current.json"
        if current_path.is_symlink():
            raise ValueError("symlink state forbidden")
        current = json.loads(current_path.read_text()) if current_path.exists() else None
        if current is not None:
            if not isinstance(current, dict) or "version" not in current:
                raise ValueError("invalid active state")
            if parsed <= _version(current["version"]):
                raise ValueError("version downgrade or replay rejected")

        filename = f"rules-{version}-{digest[:16]}.yar"
        destination = store_dir / filename
        # Immutable version files; never overwrite an existing file.
        with destination.open("xb") as stream:
            stream.write(rules)
            stream.flush()
            os.fsync(stream.fileno())
        new_state = {
            "version": version,
            "file": filename,
            "sha256": digest,
            "previous": current,
        }
        _atomic_json(current_path, new_state)
        return {"status": "activated", "version": version, "path": str(destination)}
    except (OSError, ValueError, UnicodeError, InvalidSignature, TypeError) as exc:
        return {"status": "error", "detail": str(exc)[:300] or type(exc).__name__}
    except Exception as exc:
        return {"status": "error", "detail": f"validation failed: {type(exc).__name__}"}


def rollback_rules(store_dir: Path) -> dict:
    """Operator-initiated rollback to the previous *local* version.

    Explicit rollback is allowed even though signed automatic updates must be
    monotonically increasing. Call only when scanner is stopped.
    """
    try:
        state_file = store_dir / "current.json"
        if state_file.is_symlink() or store_dir.is_symlink():
            raise ValueError("symlink state forbidden")
        state = json.loads(state_file.read_text(encoding="utf-8"))
        previous = state.get("previous")
        if not isinstance(previous, dict):
            raise ValueError("no previous version")
        filename = previous.get("file")
        digest = previous.get("sha256")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ValueError("invalid previous file")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid previous hash")
        content = (store_dir / filename).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("previous rules corrupted")
        _atomic_json(state_file, previous)
        return {"status": "rolled_back", "version": previous["version"]}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return {"status": "error", "detail": str(exc)[:300]}
