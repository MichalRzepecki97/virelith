"""Virelith Precision desktop shell (optional PySide6 dependency).

Prototype UI: launches the existing CLI in a child process. No automatic
quarantine, no background resident monitoring, no safety guarantees.
"""
from __future__ import annotations

import json
import os
import signal
from pathlib import Path
import sys
from uuid import uuid4

from PySide6.QtCore import QProcess, Qt, QTimer, QSettings
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPushButton, QStackedWidget, QVBoxLayout, QWidget,
)

from .desktop_views import HistoryView, QuarantineView, SettingsView
from .scan_history import recent_scans
from .results_view import ResultsView
from .overview_view import OverviewView

from .desktop_theme import STYLE


def panel() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(22, 20, 22, 20)
    layout.setSpacing(13)
    return frame, layout


def page(title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(42, 36, 42, 36)
    layout.setSpacing(22)
    heading = QLabel(title)
    heading.setObjectName("h1")
    layout.addWidget(heading)
    info = QLabel(subtitle)
    info.setObjectName("muted")
    info.setWordWrap(True)
    layout.addWidget(info)
    return widget, layout


class Desktop(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Virelith · Local Threat Analysis")
        self.resize(1100, 730)
        self.setMinimumSize(820, 560)
        self.proc: QProcess | None = None
        self.scan_cancelled = False
        self.scan_timed_out = False
        self.settings = QSettings("Virelith", "VirelithDesktop")
        self.scan_timer = QTimer(self)
        self.scan_timer.setSingleShot(True)
        self.scan_timer.timeout.connect(self.timeout_scan)

        root = QWidget()
        row = QHBoxLayout(root)
        row.setSpacing(0)
        row.setContentsMargins(0, 0, 0, 0)
        self.setCentralWidget(root)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(228)
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(12, 28, 12, 18)
        nav.setSpacing(5)
        brand = QLabel("◈  V I R E L I T H")
        brand.setStyleSheet("font-size: 16px; font-weight: 700; letter-spacing: 2px;")
        nav.addWidget(brand)
        subtitle = QLabel("LOCAL THREAT ANALYSIS")
        subtitle.setStyleSheet("font-size: 10px; color: #9BABAD;")
        nav.addWidget(subtitle)
        nav.addSpacing(32)
        self.stack = QStackedWidget()
        self.nav_buttons = []
        for index, label in enumerate(("Overview", "Scan", "Results", "History", "Quarantine", "Settings")):
            button = QPushButton(label)
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, i=index: self.change_page(i))
            self.nav_buttons.append(button)
            nav.addWidget(button)
        nav.addStretch()
        nav.addWidget(QLabel("EXPERIMENTAL BUILD"))
        row.addWidget(sidebar)
        row.addWidget(self.stack, 1)

        self.overview_view = OverviewView(
            self.history_path(), str(self.settings.value('clam', 'clamscan')),
            str(self.settings.value('rule_store', '')),
            lambda: self.change_page(1), lambda: self.change_page(3))
        self.stack.addWidget(self.overview_view)
        self.stack.addWidget(self.scan_page())
        self.results_view = ResultsView()
        self.stack.addWidget(self.results_view)
        self.history_view = HistoryView(self.history_path())
        self.history_view.report_selected.connect(self.open_history_report)
        self.quarantine_view = QuarantineView(self.quarantine_path())
        self.stack.addWidget(self.history_view)
        self.stack.addWidget(self.quarantine_view)
        self.stack.addWidget(SettingsView(self.settings))
        self.change_page(0)

    def open_history_report(self, report: dict) -> None:
        self.results_view.set_report(report)
        self.change_page(2)

    def history_path(self) -> Path:
        return Path(str(self.settings.value('history_db', Path.home() / '.virelith' / 'history.sqlite3'))).expanduser()

    def quarantine_path(self) -> Path:
        return Path(str(self.settings.value('quarantine_store', Path.home() / '.virelith' / 'quarantine'))).expanduser()

    def change_page(self, index: int) -> None:
        if index == 0:
            self.overview_view.history_path = self.history_path()
            self.overview_view.clam_command = str(self.settings.value('clam', 'clamscan'))
            self.overview_view.rule_store = str(self.settings.value('rule_store', ''))
            self.overview_view.refresh()
        if index == 3:
            self.history_view.db_path = self.history_path()
            self.history_view.refresh()
        elif index == 4:
            self.quarantine_view.store = self.quarantine_path()
            self.quarantine_view.refresh()
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons):
            button.setChecked(i == index)

    def overview_page(self) -> QWidget:
        widget, layout = page("Overview", "A focused workspace for local, on-demand threat analysis.")
        card, inner = panel()
        inner.addWidget(QLabel("SCANNER"))
        main = QLabel("Ready for a manual scan")
        main.setStyleSheet("font-size: 22px; font-weight: 600;")
        inner.addWidget(main)
        hint = QLabel("ClamAV + YARA-X · PE inspection · Conservative heuristics")
        hint.setObjectName("muted")
        inner.addWidget(hint)
        start = QPushButton("Start new scan")
        start.setObjectName("primary")
        start.clicked.connect(lambda: self.change_page(1))
        inner.addWidget(start, alignment=Qt.AlignLeft)
        layout.addWidget(card)
        layout.addStretch()
        return widget

    def scan_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(34, 32, 34, 32)
        layout.setSpacing(18)
        breadcrumb = QLabel("VIRELITH  /  SCAN")
        breadcrumb.setStyleSheet("color:#9DB9BB; font-size:11px; letter-spacing:1px;")
        layout.addWidget(breadcrumb)
        heading = QLabel("Scan files")
        heading.setStyleSheet("font-size:28px; font-weight:700;")
        layout.addWidget(heading)
        subtitle = QLabel("Inspect a local file using ClamAV, YARA-X and static analysis.")
        subtitle.setStyleSheet("color:#A4B8BD;")
        layout.addWidget(subtitle)

        card, inner = panel()
        inner.addWidget(QLabel("FILE SELECTION"))
        hint = QLabel("File: up to 5 MiB · Folder: up to 500 files / 256 MiB / 8 levels · No automatic quarantine")
        hint.setStyleSheet("color:#9CB6BA; font-size:12px;")
        inner.addWidget(hint)
        target_row = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("No file selected")
        target_row.addWidget(self.target_input, 1)
        choose_file = QPushButton("Browse files")
        choose_file.setObjectName("secondary")
        choose_file.clicked.connect(self.pick_file)
        target_row.addWidget(choose_file)
        folder_button = QPushButton("Browse folder")
        folder_button.setObjectName("secondary")
        folder_button.clicked.connect(self.pick_folder)
        target_row.addWidget(folder_button)
        inner.addLayout(target_row)
        self.choose_folder_button = folder_button
        self.choose_file_button = choose_file
        self.target_input.textChanged.connect(self.target_changed)
        layout.addWidget(card)

        engines, engine_layout = panel()
        engine_layout.addWidget(QLabel("ANALYSIS MODULES"))
        engine_hint = QLabel("ClamAV  ·  YARA-X  ·  PE inspection  ·  Conservative heuristics")
        engine_hint.setWordWrap(True)
        engine_hint.setStyleSheet("color:#ABC5C4;")
        engine_layout.addWidget(engine_hint)
        limitations = QLabel("Folder scans have resource limits; drive-wide scans remain unavailable.")
        limitations.setStyleSheet("color:#93ADB4; font-size:12px;")
        engine_layout.addWidget(limitations)
        layout.addWidget(engines)

        actions = QHBoxLayout()
        self.run_button = QPushButton("Start scan")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.run_scan)
        self.run_button.setEnabled(False)
        actions.addWidget(self.run_button)
        self.cancel_button = QPushButton("Cancel scan")
        self.cancel_button.setObjectName("secondary")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        actions.addWidget(self.cancel_button)
        actions.addStretch()
        layout.addLayout(actions)
        status_card, status_layout = panel()
        status_layout.addWidget(QLabel("SCAN ACTIVITY"))
        self.status = QLabel("Ready · Select a file to begin")
        self.status.setStyleSheet("font-size:15px; font-weight:600;")
        status_layout.addWidget(self.status)
        self.output = QLabel("The scan runs in a separate process. Results appear in Results.")
        self.output.setWordWrap(True)
        self.output.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.output.setStyleSheet("color:#AAC2C5;")
        status_layout.addWidget(self.output)
        layout.addWidget(status_card)
        layout.addStretch()
        return widget

    def information_page(self, title: str, message: str) -> QWidget:
        widget, layout = page(title, message)
        layout.addStretch()
        return widget

    def pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path:
            self.target_input.setText(path)

    def pick_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select folder")
        if path:
            self.target_input.setText(path)

    def target_changed(self) -> None:
        path = Path(self.target_input.text().strip())
        self.run_button.setEnabled(self.proc is None and bool(self.target_input.text().strip()) and not path.is_symlink() and (path.is_file() or path.is_dir()))
        if self.proc is None:
            self.status.setText("Ready · Press Start scan to begin." if self.target_input.text().strip() else "Ready · Select a file to begin")

    def run_scan(self) -> None:
        path = Path(self.target_input.text().strip())
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            QMessageBox.warning(self, "Invalid target", "Select a regular file or folder, not a symlink.")
            return
        if path.is_file() and path.stat().st_size > 5 * 1024 * 1024:
            QMessageBox.warning(self, "File too large", "GUI preview limits scans to 5 MiB to protect the VM.")
            return
        if self.proc is not None:
            return
        reports = Path.home() / ".virelith" / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        report = reports / f"desktop-{uuid4().hex}.json"
        history = self.history_path()
        history.parent.mkdir(parents=True, exist_ok=True)
        self.scan_cancelled = False
        self.scan_timed_out = False
        self._progress_buffer = ""
        self.proc = QProcess(self)
        # On POSIX, create a separate process group so cancelling also stops ClamAV.
        if os.name == 'posix' and hasattr(self.proc, 'setChildProcessModifier'):
            self.proc.setChildProcessModifier(os.setsid)
        self.proc.setProgram(sys.executable)
        arguments = ["-m", "virelith.cli", str(path.absolute()),
                     "--report", str(report), "--history-db", str(history),
                     "--clam", str(self.settings.value("clam", "clamscan"))]
        rule_store = str(self.settings.value("rule_store", "")).strip()
        if rule_store:
            arguments.extend(["--rule-store", str(Path(rule_store).expanduser())])
        self.proc.setArguments(arguments)
        self.proc.finished.connect(lambda code, _status: self.scan_finished(code, report))
        self.proc.readyReadStandardOutput.connect(self.read_scan_progress)
        self.proc.errorOccurred.connect(self.process_error)
        self.run_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.choose_file_button.setEnabled(False)
        self.choose_folder_button.setEnabled(False)
        self.status.setText("Scanning · Processing selected target (up to 90 seconds)")
        self.scan_timer.start(90_000)
        self.output.setText("Scan in progress. You can cancel this operation.\nNo automatic quarantine.")
        self.proc.start()

    def read_scan_progress(self) -> None:
        if self.proc is None:
            return
        self._progress_buffer = getattr(self, "_progress_buffer", "") + bytes(
            self.proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        lines = self._progress_buffer.split("\n")
        self._progress_buffer = lines.pop()
        for line in lines:
            if line.startswith("VIRELITH_PROGRESS "):
                try:
                    progress = json.loads(line[len("VIRELITH_PROGRESS "):])
                    self.status.setText(
                        f"Scanning · {int(progress['processed'])} files processed · "
                        f"{int(progress['detections'])} detections"
                    )
                except (ValueError, KeyError, TypeError):
                    pass

    def timeout_scan(self) -> None:
        if self.proc is not None:
            self.scan_timed_out = True
            self.cancel_scan()

    def cancel_scan(self) -> None:
        if self.proc is None:
            return
        self.scan_cancelled = True
        self.scan_timer.stop()
        self.cancel_button.setEnabled(False)
        self.status.setText("Time limit reached · Stopping scan" if self.scan_timed_out else "Cancelling scan…")
        if os.name == 'posix' and hasattr(self.proc, 'setChildProcessModifier') and self.proc.processId():
            try:
                os.killpg(int(self.proc.processId()), signal.SIGKILL)
                return
            except ProcessLookupError:
                return
            except OSError:
                pass
        self.proc.kill()

    def process_error(self, _error) -> None:
        if self.proc is not None and self.proc.state() == QProcess.NotRunning:
            message = self.proc.errorString()
            self.status.setText("Unable to start scanner")
            self.output.setText(message)
            self.scan_timer.stop()
            self.cancel_button.setEnabled(False)
            self.target_input.setEnabled(True)
            self.choose_file_button.setEnabled(True)
            self.choose_folder_button.setEnabled(True)
            self.target_changed()
            self.proc.deleteLater()
            self.proc = None

    def scan_finished(self, code: int, report: Path) -> None:
        assert self.proc is not None
        stderr = bytes(self.proc.readAllStandardError()).decode(errors="replace")
        self.scan_timer.stop()
        self.cancel_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.choose_file_button.setEnabled(True)
        self.choose_folder_button.setEnabled(True)
        self.target_changed()
        if self.scan_cancelled:
            self.status.setText("Time limit exceeded" if self.scan_timed_out else "Scan cancelled")
            self.output.setText("Scan was interrupted; results may be incomplete. No report has been trusted.")
            self.proc.deleteLater()
            self.proc = None
            return
        self.status.setText("Scan report created" if report.exists() else "Scan failed · No report")
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            files = data.get("files", [])
            detections = sum(f.get("verdict") == "detection" for f in files)
            try:
                saved = any(row["created_utc"] == data.get("created_utc")
                            and row["target"] == data.get("target")
                            for row in recent_scans(self.history_path(), limit=100))
                history_note = "Saved in history" if saved else "WARNING: history record missing"
            except Exception as exc:
                history_note = f"WARNING: cannot read history: {exc}"
            self.results_view.set_report(data)
            if not data.get("complete", True):
                self.status.setText("Incomplete scan · Directory limit reached")
            self.output.setText(f"Files analyzed: {len(files)}   ·   Detections: {detections}\n"
                                f"Report: {report}\nHistory: {history_note}\nExit code: {code}\n"
                                + (f"Details: {stderr[-1200:]}" if stderr else ""))
        except (OSError, ValueError):
            self.output.setText(f"No valid scan report produced. Exit code: {code}\n{stderr[-1200:]}")
        if report.exists() and not self.scan_cancelled:
            self.history_view.db_path = self.history_path()
            self.history_view.refresh()
            self.output.setText(self.output.text() + "\nOpen Results to inspect this scan.")
            self.change_page(2)
        self.proc.deleteLater()
        self.proc = None


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    window = Desktop()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
