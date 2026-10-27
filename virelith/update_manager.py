"""Read-only ClamAV health checks and offline, integrity-checked YARA rule staging.

This module intentionally does not download or execute untrusted updates.
SHA-256 proves integrity against a trusted manifest, not publisher identity.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess

_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_RULE_BYTES = 4 * 1024 * 1024


def clamav_status(
    *,
    clam_exe: str = "clamscan",
    database_dir: Path = Path("/var/lib/clamav"),
) -> dict:
    """Report scanner version and local database metadata without running updates."""
    try:
        result = subprocess.run(
            [clam_exe, "--version"], capture_output=True, text=True,
            timeout=10, errors="replace", check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "detail": str(exc)[:500]}

    if result.returncode != 0:
        return {"status": "error", "detail": (result.stderr or result.stdout)[:500]}

    databases = []
    try:
        if database_dir.is_dir():
            for path in sorted(database_dir.iterdir()):
                if path.is_file() and path.suffix.lower() in {".cvd", ".cld"}:
                    stat = path.stat()
                    databases.append({
                        "name": path.name,
                        "bytes": stat.st_size,
                        "modified_utc_epoch": int(stat.st_mtime),
                    })
    except OSError as exc:
        return {"status": "error", "detail": str(exc)[:500]}

    return {
        "status": "ok" if databases else "database_missing",
        "engine_version": result.stdout.strip()[:300],
        "databases": databases,
        "note": "Database file timestamps do not prove freshness or signature authenticity.",
    }


def stage_yara_rules(
    rules_path: Path,
    manifest_path: Path,
    destination_dir: Path,
) -> dict:
    """Stage vetted rules supplied by an operator; never fetch remote data.

    The manifest must contain: version, sha256. For now the manifest MUST be
    acquired from a trusted channel independently of the candidate rules.
    A cryptographic signature check is required before enabling remote updates.
    """
    import yara_x

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be an object")
        version = manifest.get("version")
        digest = manifest.get("sha256")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ValueError("invalid version")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("invalid sha256")
        if rules_path.is_symlink() or destination_dir.is_symlink():
            raise ValueError("symlink paths are not supported")
        size = rules_path.stat().st_size
        if size > _MAX_RULE_BYTES:
            raise ValueError("rules exceed 4 MiB")
        contents = rules_path.read_bytes()
        if hashlib.sha256(contents).hexdigest() != digest:
            raise ValueError("SHA-256 mismatch")
        yara_x.compile(contents.decode("utf-8"))
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / f"rules-{version}.yar"
        if destination.exists():
            raise ValueError("version already staged")
        # Exclusive creation prevents accidental replacement.
        with destination.open("xb") as output:
            output.write(contents)
        return {"status": "staged", "version": version, "path": str(destination)}
    except (OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return {"status": "error", "detail": str(exc)[:500]}
    except Exception as exc:
        return {"status": "error", "detail": f"rule validation failed: {type(exc).__name__}"}
