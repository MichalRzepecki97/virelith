# Virelith scan-linked quarantine events

Optional audit events link a manual quarantine operation to a prior scan.
The original file SHA-256 and absolute path must match the selected scan
record before movement. Restoration is logged as a separate event.

This remains a **benign-fixture-only prototype**. Events are not tamper-proof,
and filesystem moves and history database commits are not one transaction:
a move can succeed even if audit logging fails (CLI exits with code 2 and
prints AUDIT FAILURE). Do not use to contain real malware.

Example from an existing workspace with a saved scan ID:

```bash
python -m virelith.quarantine_cli --store ./local-quarantine \
  --history-db ./local-history.sqlite3 \
  add ./demo-quarantine.txt --scan-id YOUR_SCAN_ID --confirm
python -m virelith.quarantine_cli --store ./local-quarantine \
  --history-db ./local-history.sqlite3 events --scan-id YOUR_SCAN_ID
python -m virelith.quarantine_cli --store ./local-quarantine \
  --history-db ./local-history.sqlite3 restore YOUR_QUARANTINE_ID --confirm
```

Do not put SQLite data or quarantined files in Git. This phase does not
implement automatic quarantine, crash recovery, authorization roles or
Windows-specific security containment.
