# Precision 2.0 — unified desktop UI review

This single integration branch contains Scan 2.0 (inherited), the dark
Results presentation, consistent History/Quarantine/Settings layout and
shared theme. The original explicit **Start scan** button remains the
only action that starts a scan; the extra Yes/No confirmation dialog
has been removed. Browsing a file never starts a scan.

Safety constraints remain: GUI scans one regular file <= 5 MiB, with
90-second timeout, cancel support and no automatic quarantine.
Quarantine is read-only and not ready to contain real malware.
English-only GUI. Values come from the scanner and local SQLite;
no invented detection claims or engine health guarantees.

## Kali verification

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/precision-2-complete-ui
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Test browsing without auto-start, explicit Start scan, cancellation,
History opening a Results report, empty Quarantine, and Settings persistence.

This is one **review PR for the remaining desktop work**. The branch is
based on feature/precision-2-scan (PR #19), which is based on PR #18,
itself based on earlier stacked PRs. Do not merge to main out of order.

Before calling the dark GUI production-ready: manual desktop review,
screen scaling, contrast, navigation, VM resource testing and Windows
validation are necessary. Qt Widgets dark theme and layout is not a
pixel-perfect reproduction of the conceptual mockup.
