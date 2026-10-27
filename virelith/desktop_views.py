"""Functional Qt views for local history, quarantine inventory and settings."""
from pathlib import Path

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import (
    QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)
from .scan_history import recent_scans, get_scan
from .quarantine import list_quarantine


class HistoryView(QWidget):
    def __init__(self, db_path):
        super().__init__()
        self.db_path = db_path
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("History — previous scans"))
        self.note = QLabel("Local SQLite scan history. Select a row to inspect its report.")
        layout.addWidget(self.note)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Date (UTC)", "Target", "Files", "Detections", "Scan ID"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a scan to view engine results.")
        layout.addWidget(self.details)
        refresh = QPushButton("Refresh history")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        self.table.itemSelectionChanged.connect(self.show_selected)
        self.refresh()

    def refresh(self):
        try:
            scans = recent_scans(self.db_path, limit=100)
            self.table.setRowCount(len(scans))
            for i, scan in enumerate(scans):
                for j, value in enumerate((scan["created_utc"], scan["target"],
                                            scan["file_count"], scan["detections"], scan["id"])):
                    self.table.setItem(i, j, QTableWidgetItem(str(value)))
            self.note.setText(f"History database: {self.db_path} — {len(scans)} scans")
        except Exception as exc:
            self.note.setText(f"Cannot read history: {exc}")

    def show_selected(self):
        row = self.table.currentRow()
        if row < 0 or self.table.item(row, 4) is None:
            return
        scan_id = self.table.item(row, 4).text()
        try:
            report = get_scan(self.db_path, scan_id)
            if report is None:
                self.details.setPlainText("Record not found")
                return
            import json
            self.details.setPlainText(json.dumps(report, indent=2, ensure_ascii=False))
        except Exception as exc:
            self.details.setPlainText(f"Cannot open report: {exc}")


class QuarantineView(QWidget):
    """Read-only intentionally: real malicious samples are not safely handled yet."""
    def __init__(self, store):
        super().__init__()
        self.store = store
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Quarantine — inventory (read-only prototype)"))
        self.note = QLabel("No restore / delete actions in the desktop until containment is hardened.")
        self.note.setWordWrap(True)
        layout.addWidget(self.note)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Original path", "SHA-256", "State", "Date"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)
        refresh = QPushButton("Refresh quarantine")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        self.refresh()

    def refresh(self):
        try:
            entries = list_quarantine(self.store)
            self.table.setRowCount(len(entries))
            for i, entry in enumerate(entries):
                for j, key in enumerate(("id", "original", "sha256", "state", "created_utc")):
                    self.table.setItem(i, j, QTableWidgetItem(str(entry[key])))
            self.note.setText(f"Read-only inventory: {self.store} — {len(entries)} entries")
        except Exception as exc:
            self.note.setText(f"Cannot read quarantine inventory: {exc}")


class SettingsView(QWidget):
    def __init__(self, settings: QSettings):
        super().__init__()
        self.settings = settings
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Settings — local scanner configuration"))
        form = QFormLayout()
        self.clam = QLineEdit(str(settings.value("clam", "clamscan")))
        self.rules = QLineEdit(str(settings.value("rule_store", "")))
        self.history = QLineEdit(str(settings.value("history_db", Path.home() / ".virelith" / "history.sqlite3")))
        self.store = QLineEdit(str(settings.value("quarantine_store", Path.home() / ".virelith" / "quarantine")))
        form.addRow("ClamAV executable", self.clam)
        form.addRow("Signed rule store (optional)", self.rules)
        form.addRow("History SQLite database", self.history)
        form.addRow("Quarantine inventory directory", self.store)
        layout.addLayout(form)
        self.status = QLabel("Paths are not automatically validated. Only trusted rule stores should be used.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        save = QPushButton("Save settings")
        save.clicked.connect(self.save)
        layout.addWidget(save)
        layout.addStretch()

    def save(self):
        for key, edit in (("clam", self.clam), ("rule_store", self.rules),
                          ("history_db", self.history), ("quarantine_store", self.store)):
            self.settings.setValue(key, edit.text().strip())
        self.settings.sync()
        self.status.setText("Settings saved. They apply to the next scan; refresh other tabs to read new paths.")
