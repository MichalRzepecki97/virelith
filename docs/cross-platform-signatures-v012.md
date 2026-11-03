# Virelith v0.12 — Cross-platform Signature Discovery

## Scope

- Detects a FreshClam executable from PATH or beside the configured clamscan binary.
- Looks for ClamAV databases at common Linux/Windows installation directories.
- Only reports discovered .cvd/.cld files and clearly states the directory is inferred.
- When none is found, reports **database_location_unknown**, not a fabricated path.
- The manual updater stays disabled until ClamAV status is checked and a
  FreshClam executable has been located.
- Still blocks a competing update if the Linux systemd service is active.
- No privilege escalation, no automatic download, no claim of trusted or current signatures.

## Kali smoke test

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/v012-crossplatform-signatures
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Open **Settings → Check ClamAV status**, inspect **Technical details**.
FreshClam may not be callable by a desktop user if logs/databases are owned
by a service account. Do not run the entire desktop as root.

## Windows validation (still required)

On Windows 11, install ClamAV separately and set the scanner executable in
Local Configuration. Check whether FreshClam is found in PATH or beside the
scanner. Check the inferred database directory against the actual FreshClam
configuration — Windows installation layouts vary.

Known limitations:
- Discovery does not parse custom FreshClam configuration; a discovered
  directory need not be the active scanner database directory.
- We do not manage Windows services or elevated updates.
- ClamAV version checks are currently synchronous (up to 10 seconds).
- Windows executable availability and GUI behavior must be smoke-tested
  before release. Do not call the scanner production-ready.
