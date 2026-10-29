# Quarantine UX — v0.9 stage 5

Read-only GUI for quarantine inventory with file name, status, timestamp,
search, status filters and metadata details. Summary counts come only from
the configured store's SQLite records.

The GUI DOES NOT implement move, restore, delete, or auto-quarantine.
Production malware containment requires more filesystem and permission
hardening on Windows and POSIX.

On Kali:
```bash
git fetch origin
git switch feature/desktop-quarantine-v09
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```
For existing benign test entries, configure Quarantine inventory directory
in Settings, e.g. `~/Projects/Virelith/local-quarantine`, then reopen Quarantine.
Test searching, filters and details without moving any files.
