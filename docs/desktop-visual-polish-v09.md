# Virelith v0.9 — Visual polish, iteration 1

The interface stays **English only**. Precision + Operator remains the design language.

## Scope
- Shared Qt stylesheet covering typography, surfaces, side navigation, focus states,
  table headers, text fields, selection and scrollbars.
- More consistent spacing, borders and button emphasis.
- Results: disable technical-analysis control until a result is selected;
  alternating rows for multi-file results.

No scanning or quarantine logic was changed intentionally. This is the **first**
visual refinement iteration, not the final branded release.

## Kali preview

```bash
cd ~/Projects/Virelith
git fetch origin
git switch feature/desktop-visual-polish-v09
./.venv/bin/python -m pip install -e '.[desktop]'
./.venv/bin/python -m pytest -q
./.venv/bin/python -m virelith.desktop
```

Review: Overview, Scan, Results (empty and populated), History (with filters),
Quarantine (empty and populated with benign test entries), Settings, and
keyboard focus. Send screenshots of visual defects; avoid testing unknown
samples. This branch is stacked on PR #16 and its parent GUI branches.

## Remaining before v0.9 completion
- Replace generic text-only empty states with designed content.
- Review responsive behavior on Windows display scaling and smaller resolutions.
- Polish layout/column widths and accessible contrast.
- Add Virelith-specific app icon and distribution assets.
- Windows validation and packaging.
