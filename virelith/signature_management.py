"""Opt-in ClamAV signature maintenance; never downloads without an explicit call.

Uses the installed freshclam binary and its own configured trusted mirrors.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .update_manager import clamav_status
from .signature_paths import choose_database_dir, find_freshclam


def signature_snapshot(clam_exe: str = "clamscan",
                       database_dir: Path | None = None) -> dict:
    """Report detected local databases, distinguishing discovery from certainty."""
    discovered = False
    if database_dir is None:
        database_dir, discovered = choose_database_dir()
    if database_dir is None:
        # No plausible database directory was found. Still check the scanner.
        result = clamav_status(clam_exe=clam_exe, database_dir=Path("__missing_clamav_db__"))
    else:
        result = clamav_status(clam_exe=clam_exe, database_dir=database_dir)
    updater = find_freshclam(clam_exe)
    return {
        "clamav": result,
        "freshclam_available": updater is not None,
        "freshclam_executable": updater,
        "database_path": str(database_dir) if database_dir is not None else "Not discovered",
        "database_discovered": discovered if database_dir is not None else False,
        "notice": ("Database location is inferred from common paths, not verified "
                   "against the active ClamAV configuration. File timestamps "
                   "do not establish signature freshness or authenticity."),
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

def freshclam_service_status() -> dict:
    """Best-effort systemd service check. Never change system services."""
    if not sys.platform.startswith("linux") or shutil.which("systemctl") is None:
        return {"status": "unavailable", "detail": "System service status unavailable."}
    try:
        done = subprocess.run(
            ["systemctl", "is-active", "clamav-freshclam.service"],
            capture_output=True, text=True, timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unavailable", "detail": str(exc)[:250]}
    if done.returncode == 0 and done.stdout.strip() == "active":
        return {"status": "active", "detail": "ClamAV FreshClam service is running."}
    return {"status": "inactive", "detail": "FreshClam system service is not active or not installed."}
