# Desktop Precision 2.0 — release candidate review gates

This document is the acceptance checklist for desktop UX and code consolidation.
The interface language remains English.

## UX review (Kali and Windows)

- [ ] Overview displays actual SQLite history, engine availability, and no claim of real-time protection.
- [ ] Selecting a file never starts a scan; only pressing **Start scan** starts it.
- [ ] The 5 MiB and single-file restrictions are communicated and enforced.
- [ ] Cancel and timeout do not show a partial report as successful.
- [ ] Results distinguishes no-detection, detection, error and incomplete; test signatures are not called proof of malware.
- [ ] History search/filter and navigation to Results work without rescanning.
- [ ] Quarantine is explicitly read-only; missing/empty stores have appropriate messages.
- [ ] Settings persist between restarts; invalid configuration has actionable errors.
- [ ] All six pages remain legible on 1280x720, high-DPI scaling and keyboard navigation.
- [ ] No clipped labels, unreadable dark text, fake activity graphs, or misleading readiness claims.

## Technical gates

- [ ] All pytest checks and desktop syntax parsing pass.
- [ ] Kali desktop smoke test including cancellation passes.
- [ ] Windows 11 PySide6 launch and clamscan integration are verified.
- [ ] File and process resource behavior is checked on constrained VM.
- [ ] Packaging, release version, README and screenshot documentation are reviewed.
- [ ] No production malware containment claim; optional backend audit PR #9 reviewed separately.

**Do not merge or tag a release while critical gates are unchecked.**
