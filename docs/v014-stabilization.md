# Virelith v0.14 — stabilization and reproducible evidence

This branch is a feature-freeze preparation batch. It does not add resident
protection, automatic quarantine or network rule downloads.

## Scan provenance

Each new report stores:
- ClamAV engine version, read from `clamscan --version`;
- ClamAV signature database version when the installed output exposes it;
- YARA-X package version;
- the already recorded YARA rule-store version and digest.

Version probing runs once per scan, with a short timeout. Missing tools or
unparseable output are recorded as `unknown`; a scan is not blocked. Old
reports remain readable and display unknown provenance where fields did not
exist.

The report records tool-reported versions, not proof of database freshness,
authenticity or exact active configuration. It does not capture a complete
reproducible environment.

## Historical comparison

Same-SHA-256 comparison now includes ClamAV engine/database version and
YARA-X package version. It reads only local SQLite history, scans a bounded
number of recent records and skips individual report JSON blobs above 16 MiB.
It does not re-open or execute the sample. Local SQLite history is not
cryptographically authenticated; an attacker able to edit it can alter
historical evidence.

## Cross-platform GUI checks

The new `Desktop runtime smoke` workflow installs the optional PySide6
dependency and constructs Settings, Results and History widgets using Qt's
offscreen platform on Ubuntu and Windows. This catches import, constructor
and basic widget wiring errors. It is not a substitute for interactive
Windows 10/11 testing, screen-reader/accessibility checks, installer testing
or a real ClamAV integration test.

## Kali test

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/v014-stabilization-provenance
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

For a provenance test, scan the same harmless file twice. Export both reports
and compare their top-level `engines` values and YARA metadata. If the engine
or database version changes between scans, Results → Compare previous scans
should list that change. If the system uses an old ClamAV build whose version
output has no database number, the value remains `unknown`.

## Remaining release gates

- Run all tests and both desktop CI workflows successfully.
- Validate the new Results comparison and Settings YARA import manually on Kali.
- Test on a real Windows 11 installation with ClamAV installed.
- Review file-system race conditions in scanning and signed-store activation.
- Review quarantine limitations; keep it clearly experimental.
- Test installer upgrade/uninstall, data paths and permissions before beta.
