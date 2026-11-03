"""Opt-in ClamAV signature maintenance; never downloads without an explicit call.

Uses the installed freshclam binary and its own configured trusted mirrors.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .update_manager import clamav_status


def signature_snapshot(clam_exe: str = "clamscan", database_dir: Path = Path("/var/lib/clamav")) -> dict:
    result = clamav_status(clam_exe=clam_exe, database_dir=database_dir)
    return {
        "clamav": result,
        "freshclam_available": shutil.which("freshclam") is not None,
        "database_path": str(database_dir),
        "notice": "File timestamps and scanner versions do not prove signature authenticity or freshness.",
    }


def update_clamav(*, freshclam_exe: str = "freshclam", timeout: int = 240) -> dict:
    """Explicit update through installed FreshClam. No shell or arbitrary user arguments.

    Privileges, database locks and mirror configuration are managed by FreshClam.
    A successful exit means the utility completed, not that new signatures exist.
    """
    if not 10 <= timeout <= 900:
        raise ValueError("timeout must be 10–900 seconds")
    try:
        done = subprocess.run(
            [freshclam_exe, "--stdout"], capture_output=True, text=True,
            timeout=timeout, errors="replace", check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "detail": "FreshClam exceeded time limit"}
    except OSError as exc:
        return {"status": "error", "detail": str(exc)[:500]}
    return {
        "status": "completed" if done.returncode == 0 else "error",
        "exit_code": done.returncode,
        "detail": (done.stdout + "\n" + done.stderr).strip()[-3000:],
        "notice": "Check database state afterwards; this operation does not guarantee a new database.",
    }


def yara_store_snapshot(rule_store: str) -> dict:
    """Report only the validated active rules; never claim publisher identity.

    The signed-rule activation workflow establishes publisher trust upstream.
    This read-only check validates current store consistency (hash/version).
    """
    if not rule_store.strip():
        return {
            "status": "bundled_test_rules",
            "detail": "No active signed rule store configured. Bundled rules are for testing only.",
        }
    from .active_rules import load_active_rules
    try:
        _source, metadata = load_active_rules(Path(rule_store).expanduser())
        return {
            "status": "active",
            "version": metadata["version"],
            "sha256": metadata["sha256"],
            "path": metadata["path"],
            "detail": "Active rules integrity verified locally. This does not revalidate publisher signature.",
        }
    except (ValueError, OSError) as exc:
        return {"status": "invalid", "detail": str(exc)[:350]}
