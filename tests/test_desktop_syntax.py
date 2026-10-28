"""Ensure optional desktop modules have valid syntax in headless CI."""
import ast
from pathlib import Path

def test_desktop_modules_parse():
    root = Path(__file__).resolve().parents[1] / "virelith"
    for module in ("desktop.py", "desktop_views.py", "results_view.py",
                   "overview_view.py", "desktop_theme.py"):
        ast.parse((root / module).read_text(encoding="utf-8"), filename=module)
