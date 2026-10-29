# Virelith v0.9 — History UX

The History view now filters the latest 100 SQLite scans by filename/path
and by whether any detections were recorded. The user can double-click
a scan or select it and choose **Open selected scan in Results**.

Historical reports are opened read-only. No file is rescanned by opening
a report. No quarantine action is performed.

## Kali smoke test

```bash
git fetch origin
git switch feature/desktop-history-v09
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Check the History search, detection filter and navigation to Results.
Search is case-insensitive. The view deliberately limits the list to
the latest 100 saved scans. More advanced pagination is future work.

This branch is stacked on GUI PR #14 and its parent branches.
