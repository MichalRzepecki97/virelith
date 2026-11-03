"""Smoke-test optional desktop construction without a display server.

Qt is optional for CLI installations; pytest skips this test when PySide6
is not installed. A real QApplication is constructed with the offscreen
platform so runtime NameError / missing widgets are caught.
"""
import os
import pytest


def test_settings_constructs_offscreen(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6.QtWidgets")
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication
    from virelith.desktop_views import SettingsView

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    panel = SettingsView(settings)
    try:
        assert panel.signature_status is not None
        assert panel.yara_status is not None
        assert panel.update_button.text() == "Run FreshClam update"
    finally:
        panel.close()
        panel.deleteLater()
