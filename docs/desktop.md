# Virelith Precision – first desktop prototype

Qt Widgets / PySide6 desktop shell with fixed sidebar: Overview, Scan,
History, Quarantine, Settings. The first two views are functional.
Scan invokes the existing Virelith CLI in a child process (QProcess)
without freezing the interface. Reports and optional SQLite scan history
are written under the current user's `~/.virelith` directory.

## Kali local preview

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/desktop-shell-precision
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m virelith.desktop
```

Use a graphical desktop session. Some platforms and Python versions may lack
PySide6 wheels; Python 3.12/3.13 are recommended for reproducibility.

## Windows

Use Python 3.12 or 3.13 in a Windows virtual environment and install `.[desktop]`.
A working ClamAV `clamscan.exe` on PATH and readable YARA rule file are needed
for complete scan results. No service, realtime protection, or elevation is installed.

## Explicitly unfinished

History, Quarantine and Settings navigation pages are placeholders.
The desktop does not invoke quarantine or restore; those remain experimental
CLI-only actions for benign files. The scanner's default YARA rule is a
**test rule**, not a trusted production threat detection policy.
No packaging, signing, installer, progress cancellation, or test-backed
GUI compatibility claim is made in this PR.


## Stability safeguards after first Kali report

- Selecting a file does not trigger a scan; `Run scan` shows a second explicit
  Yes/No confirmation.
- The desktop preview accepts **regular single files of at most 5 MiB**. Folder
  scanning is disabled for the moment.
- A Cancel button and a 90-second deadline terminate the scan process.
  On POSIX where supported by Qt, the child starts in its own session and
  cancellation terminates its process group, including ClamAV.
- These are containment measures, not a promise of zero resource exhaustion.
  ClamAV itself can use significant memory even for small files.
- Please test only harmless files in a disposable VM and verify that no
  `clamscan` process remains after cancellation.

The initial report mentioned a VM hang, which is not yet conclusively
diagnosed. The scanner must be profiled under CPU and memory limits before
re-enabling folder scans or allowing larger files.
