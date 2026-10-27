# Virelith v0.7 – manual quarantine prototype

Manual opt-in quarantine for **benign test files only**. Never automatically
quarantine files because YARA matches (including test-only rules).

## Commands

```bash
cd ~/Projects/Virelith
echo "QUARANTINE_DEMO" > demo-quarantine.txt
./.venv/bin/python -m virelith.quarantine_cli --store ./local-quarantine add ./demo-quarantine.txt --confirm
./.venv/bin/python -m virelith.quarantine_cli --store ./local-quarantine list
./.venv/bin/python -m virelith.quarantine_cli --store ./local-quarantine restore <id-from-list> --confirm
```

The quarantine directory must be a separate directory on the same filesystem.
Do not version-control it or put it inside a directory routinely scanned by
the prototype.

## Not safe for production

This prototype is NOT an antivirus-grade containment mechanism. The local
file operations are not hardened against concurrent filesystem modifications,
hardlinks, hostile source directories, elevated privilege boundaries, crashes
between database and file operations, or cross-platform ACL semantics.
The source file's previous hardlinks are not invalidated. No secure deletion,
encryption, threat assessment, or automatic isolation is provided.
Only use disposable, non-executable files for tests. On Windows, additional
ACL and file-lock controls are required before the feature can be considered
safe for real malware.
