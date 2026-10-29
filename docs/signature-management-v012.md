# Signature Management v0.12 — initial batch

The Settings screen can inspect local ClamAV database metadata and **explicitly**
invoke the locally installed `freshclam --stdout` tool without a shell. It never
downloads without a user action. The Qt process is asynchronous and limited to
240 seconds. Error messages, database locks and permissions are surfaced,
not silently hidden. The button's success only means FreshClam exited normally;
check local status afterwards.

Run a Kali smoke test from this branch:

```bash
git fetch origin
git switch feature/v012-signature-management
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

In Settings, select **Check signature status**. On a disposable VM with correctly
configured FreshClam mirrors and database permissions, use **Run FreshClam update**.
Do not run privileged GUI applications. FreshClam may fail due to daemon locks,
rate limits or permissions; it is not an indication Virelith is protected.
Current default database directory is /var/lib/clamav (Linux), not yet
auto-discovered on Windows. Signature authentication and update provenance
must be delegated to verified FreshClam configuration and trusted sources.

**Known follow-ups:** Windows database path discovery, signed YARA rule
store UI and tests, non-blocking signature status checks, structured
signature version display, and a safe fallback for background freshclam.
This work is a preview, not release-ready.
