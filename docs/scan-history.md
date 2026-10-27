# Scan history v0.8

Opt-in SQLite history for scan reports. No raw scanned file bytes are stored.
Reports may contain sensitive local paths and detection details; keep the database private.

```bash
python -m virelith.cli ./hello.exe --report ./reports/test.json --history-db ./local-history.sqlite3
python - <<'PY'
from pathlib import Path
from virelith.scan_history import recent_scans
print(recent_scans(Path("local-history.sqlite3")))
PY
```

This phase stores scan reports but **does not yet associate quarantine actions**.
It does not change the scanner verdicts or quarantine files.
Avoid committing local-history.sqlite3 to source control.
