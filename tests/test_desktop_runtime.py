"""Runtime smoke tests for core Qt pages on headless Linux and Windows CI."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from virelith.desktop_views import HistoryView
from virelith.results_view import ResultsView
from virelith.scan_history import save_scan

_HASH = "a" * 64


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance()
    return instance or QApplication([])


def sample_report():
    return {
        "created_utc": "2026-11-23T08:00:00+00:00",
        "target": "/tmp/sample.exe",
        "complete": True,
        "files": [{
            "path": "/tmp/sample.exe",
            "sha256": _HASH,
            "verdict": "no_detection",
            "clamav": {"status": "no_detection"},
            "yara": {"status": "no_detection", "matches": []},
            "pe_analysis": {"status": "not_pe"},
            "heuristics": {"status": "not_applicable"},
            "insight": [],
        }],
    }


def test_results_page_constructs_and_enables_same_hash_comparison(app, tmp_path):
    db = tmp_path / "history.sqlite3"
    save_scan(db, sample_report())
    view = ResultsView()
    view.history_db_path = db
    view.set_report(sample_report())
    try:
        assert view.compare_button.isEnabled()
        view.compare_history()
        assert "Fewer than two saved analyses" in view.comparison_details.toPlainText()
    finally:
        view.close()
        view.deleteLater()


def test_history_page_loads_saved_report(app, tmp_path):
    db = tmp_path / "history.sqlite3"
    save_scan(db, sample_report())
    view = HistoryView(db)
    try:
        assert view.table.rowCount() == 1
        assert view.open_button.isEnabled() is False
    finally:
        view.close()
        view.deleteLater()
