# Scan UX v0.9

The Scan page now communicates distinct states: ready, scanning, cancelling,
timed-out, cancelled, completed, and failed. The target field is disabled
while the scanner is running; selection never triggers scanning.

A scan requires an explicit Yes/No confirmation. The GUI preview is still
limited to one file of at most 5 MiB and a 90-second deadline.

When a process is cancelled or times out, the UI does **not** open a possibly
partial JSON report as a valid result. No automatic quarantine is performed.

## Kali smoke test

```bash
git fetch origin
git switch feature/desktop-scan-ux-v09
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Check three workflows using benign files:
1. Select a file, confirm, wait for Results.
2. Select a file and click Cancel; verify "Scan cancelled".
3. Select a file but reject confirmation; no process should run.

This is a UI change, not a guarantee that ClamAV cannot overload a small VM.
