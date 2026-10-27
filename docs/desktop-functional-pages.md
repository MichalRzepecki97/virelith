# GUI functional pages (development preview)

Adds real SQLite history browsing, a **read-only** quarantine inventory and
persistent desktop settings (QSettings). The scanner still requires explicit
confirmation, scans one file <=5 MiB and supports cancellation.

## Kali

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/desktop-functional-pages
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m virelith.desktop
```

1. Open **Settings**. Verify ClamAV command (default `clamscan`), history
   database (default `~/.virelith/history.sqlite3`), optional signed YARA
   rule store, and quarantine inventory path. Save.
2. In **Scan**, choose one small harmless file, click **Run scan** and confirm.
   Result displays whether the matching SQLite history entry exists.
3. Open **History**. The newest entry should appear. Click it to inspect JSON.
4. Open **Quarantine**. Empty is normal if no files have been manually moved
   into the configured quarantine store. The default path does not magically
   import older stores such as `./local-quarantine`; select that exact location
   in Settings if needed. No modification actions are exposed.

## Limitations

GUI is a prototype and has not been smoke-tested in Kali/Windows through
this change. ClamAV may exhaust VM resources in some cases; do not test
unknown malicious samples. Quarantine is not hardened for production.
Existing audit-logging PR #9 is separate. A JSON report can exist even if
history writing fails, so the UI separately indicates DB record presence.
