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

STYLE = """
QWidget { background: #F7F8F7; color: #24313B; font-family: 'Segoe UI'; font-size: 13px; }
QFrame#sidebar { background: #202B35; border: none; }
QFrame#sidebar QLabel { background: transparent; color: #F2F5F3; }
QFrame#sidebar QPushButton {
  background: transparent; color: #C1CBCB; border: none;
  padding: 12px 16px; text-align: left; border-radius: 5px;
}
QFrame#sidebar QPushButton:hover { background: #34414C; }
QFrame#sidebar QPushButton:checked { background: #344D49; color: #FFFFFF; }
QLabel#h1 { font-size: 26px; font-weight: 650; }
QLabel#muted { color: #63747D; }
QFrame#panel { background: #FFFFFF; border: 1px solid #DDE3E1; border-radius: 7px; }
QFrame#panel QLabel { background: transparent; }
QPushButton#primary { background: #286958; color: white; padding: 11px 18px; border: none; border-radius: 5px; font-weight: 600; }
QPushButton#primary:hover { background: #205C4D; }
QPushButton#primary:disabled { background: #9EAFA9; }
QLineEdit { background: white; border: 1px solid #CAD5D0; border-radius: 4px; padding: 9px; }
QPushButton#secondary { background: #E9EEEB; padding: 9px 12px; border: 1px solid #CFD9D3; border-radius: 4px; }
"""


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
        sidebar.setFixedWidth(225)
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(12, 28, 12, 18)
        nav.setSpacing(5)
        brand = QLabel("◈  V I R E L I T H")
        brand.setStyleSheet("font-size: 15px; font-weight: 700;")
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
        self.quarantine_view = QuarantineView(self.quarantine_path())
        self.stack.addWidget(self.history_view)
        self.stack.addWidget(self.quarantine_view)
        self.stack.addWidget(SettingsView(self.settings))
        self.change_page(0)

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
        widget, layout = page("New scan", "Choose one local file, then explicitly confirm the scan.")
        card, inner = panel()
        inner.addWidget(QLabel("SCAN TARGET"))
        target_row = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Choose one file (maximum 5 MiB)…")
        target_row.addWidget(self.target_input, 1)
        choose_file = QPushButton("File")
        choose_file.setObjectName("secondary")
        choose_file.clicked.connect(self.pick_file)
        target_row.addWidget(choose_file)
        # Directory scans intentionally disabled until resource limits and cancellation are hardened.
        inner.addLayout(target_row)
        self.run_button = QPushButton("Run scan")
        self.run_button.setObjectName("primary")
        self.run_button.clicked.connect(self.run_scan)
        self.run_button.setEnabled(False)
        self.target_input.textChanged.connect(self.target_changed)
        actions = QHBoxLayout()
        actions.addWidget(self.run_button)
        self.cancel_button = QPushButton("Cancel scan")
        self.cancel_button.setObjectName("secondary")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_scan)
        actions.addWidget(self.cancel_button)
        actions.addStretch()
        inner.addLayout(actions)
        self.status = QLabel("Ready · Select a file to begin")
        self.status.setObjectName("muted")
        inner.addWidget(self.status)
        self.output = QLabel("Results will appear here after the scan completes.")
        self.output.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.output.setWordWrap(True)
        inner.addWidget(self.output)
        layout.addWidget(card)
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

    def target_changed(self) -> None:
        self.run_button.setEnabled(self.proc is None and Path(self.target_input.text().strip()).is_file())
        if self.proc is None:
            self.status.setText("Ready · Press Run scan to confirm." if self.target_input.text().strip() else "Ready · Select a file to begin")

    def run_scan(self) -> None:
        path = Path(self.target_input.text().strip())
        if not path.is_file() or path.is_symlink():
            QMessageBox.warning(self, "Invalid target", "Select a regular file, not a folder or symlink.")
            return
        if path.stat().st_size > 5 * 1024 * 1024:
            QMessageBox.warning(self, "File too large", "GUI preview limits scans to 5 MiB to protect the VM.")
            return
        if QMessageBox.question(self, "Confirm scan",
                f"Scan this file?\\n{path}\\n\\nNo file will be quarantined automatically.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
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
        self.proc.readyReadStandardOutput.connect(lambda: self.proc.readAllStandardOutput() if self.proc else None)
        self.proc.errorOccurred.connect(self.process_error)
        self.run_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.target_input.setEnabled(False)
        self.status.setText("Scanning · Processing file (up to 90 seconds)")
        self.scan_timer.start(90_000)
        self.output.setText("Scan in progress. You can cancel this operation.\nNo automatic quarantine.")
        self.proc.start()

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
            self.run_button.setEnabled(Path(self.target_input.text().strip()).is_file())
            self.proc.deleteLater()
            self.proc = None

    def scan_finished(self, code: int, report: Path) -> None:
        assert self.proc is not None
        stderr = bytes(self.proc.readAllStandardError()).decode(errors="replace")
        self.scan_timer.stop()
        self.cancel_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.run_button.setEnabled(Path(self.target_input.text().strip()).is_file())
        if self.scan_cancelled:
            self.status.setText("Time limit exceeded" if self.scan_timed_out else "Scan cancelled")
            self.output.setText("Scan was interrupted; results may be incomplete. No report has been trusted.")
            self.proc.deleteLater()
            self.proc = None
            return
        self.status.setText("Scan completed" if report.exists() else "Scan failed · No report")
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
