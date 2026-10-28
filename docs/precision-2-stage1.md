# Virelith Precision 2.0 — implementation, stage 1

Approved direction: dark navy-charcoal surfaces, restrained emerald status
accents, denser operational hierarchy. **English UI only**.

This first implementation stage introduces the shared dark QSS theme and
rebuilds Overview with a principal scan action, engine availability, actual
SQLite recent activity and five most recent scan entries.

The design reference image is a **concept**: none of its invented scores,
charts, engine versions, malware labels, or unsupported scan features are
part of this implementation. GUI only exposes the existing safe single-file
scan flow; no folder/drive scan or real-malware quarantine actions.

## Kali smoke test

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/precision-2-desktop
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Review Overview, navigation and contrast. Scan, Results, History, Quarantine
and Settings still need individual dark-theme layout passes. Qt widget
stylesheet overrides in those pages may differ in contrast until then.

This is a **stacked PR** based on visual-polish PR #17, not main. Do not
merge out of sequence. No Windows compatibility claim yet.
