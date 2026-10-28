# Virelith Desktop v0.9 — staged plan

1. Results: structured per-file verdict, ClamAV/YARA-X, PE and heuristics; scan opens Results after report creation.
2. Overview: real engine readiness and last-scan information, no invented protection score.
3. Scan UX: completion/failure states, no fake progress, cancellation and resource testing.
4. History: filterable scan records opening Results, not raw JSON only.
5. Quarantine: understandable read-only metadata until file isolation is production hardened.
6. Visual refinement: typography, spacing, visual states, branding.
7. Windows tests: dependencies, installation, path handling and safe local smoke testing.

## Try current Results prototype (Kali)

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/desktop-results-v09
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Choose a harmless test file no larger than 5 MiB; confirm the scan. A
successful report opens the new Results tab. Matching a YARA test rule does
not prove malware. Other GUI phases are not implemented by this PR.
This branch depends on GUI PR #11, itself based on PR #10; merge in order.
