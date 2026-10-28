# Precision 2.0 — Scan page

Second implementation stage after Overview. The new dark Scan page uses a
clear file-selection section, non-editable status hierarchy, analysis-module
summary and separate start/cancel actions. The underlying CLI workflow is
unchanged: user confirmation, one regular file up to 5 MiB, 90-second timeout,
no folder/drive scans and no automatic quarantine.

Smoke test on Kali:

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/precision-2-scan
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Check selection without auto-start, rejection of confirmation, successful
single-file result, Cancel, and that selection controls are disabled while a
scan runs. Design review is manual; no Windows validation yet.
