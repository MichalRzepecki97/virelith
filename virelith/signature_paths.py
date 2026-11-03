"""Conservative cross-platform discovery of local ClamAV installations.

No filesystem writes, downloads, privilege escalation or signature trust claims.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys


def database_candidates(*, platform: str | None = None, environ=None) -> list[Path]:
    """Common candidate paths; these do not imply ClamAV uses any of them."""
    platform = sys.platform if platform is None else platform
    env = os.environ if environ is None else environ
    if platform == "win32":
        roots = [env.get("PROGRAMDATA"), env.get("ProgramFiles"),
                 env.get("ProgramFiles(x86)")]
        candidates = []
        for root in roots:
            if root:
                base = Path(root) / "ClamAV"
                candidates.extend((base / "database", base / "db"))
        return list(dict.fromkeys(candidates))
    return [Path("/var/lib/clamav"), Path("/usr/local/share/clamav"),
            Path("/opt/clamav/share/clamav")]


def choose_database_dir(*, platform: str | None = None,
                        environ=None, candidates=None) -> tuple[Path | None, bool]:
    """Prefer a directory containing real .cvd/.cld files; else unknown.

    Return (best candidate, verified_db_files_found). A candidate is not proof
    it is the scanner's configured database directory.
    """
    paths = database_candidates(platform=platform, environ=environ) if candidates is None else candidates
    first_existing = None
    for path in paths:
        try:
            if not path.is_dir() or path.is_symlink():
                continue
            if first_existing is None:
                first_existing = path
            if any(entry.is_file() and not entry.is_symlink()
                   and entry.suffix.lower() in {".cvd", ".cld"}
                   for entry in path.iterdir()):
                return path, True
        except OSError:
            continue
    return first_existing, False


def find_freshclam(clam_exe: str = "clamscan", *,
                   platform: str | None = None) -> str | None:
    """Use installed executable from PATH, then an adjacent scanner binary."""
    platform = sys.platform if platform is None else platform
    binary = "freshclam.exe" if platform == "win32" else "freshclam"
    located = shutil.which(binary)
    if located:
        return located
    source = shutil.which(clam_exe)
    if source is None and Path(clam_exe).is_file():
        source = clam_exe
    if source:
        candidate = Path(source).parent / binary
        if candidate.is_file() and not candidate.is_symlink():
            return str(candidate)
    return None
