"""Functional Qt views for local history, quarantine inventory and settings."""
from pathlib import Path

from PySide6.QtCore import QSettings, Signal
from PySide6.QtWidgets import (
    QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QComboBox,
)
from .scan_history import recent_scans, get_scan
from .quarantine import list_quarantine
from .history_filters import filter_scans
from .quarantine_viewmodel import summarize_quarantine, filter_quarantine, quarantine_row


class HistoryView(QWidget):
    report_selected = Signal(dict)

    def __init__(self, db_path):
        super().__init__()
        self.db_path = db_path
        self.scans = []
        layout = QVBoxLayout(self)
        title = QLabel("Scan history")
        title.setStyleSheet("font-size: 25px; font-weight: 600;")
        layout.addWidget(title)
        self.note = QLabel("Search saved scans and open a report in Results.")
        layout.addWidget(self.note)
        controls = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search file or path…")
        self.search.textChanged.connect(self.apply_filters)
        controls.addWidget(self.search, 1)
        self.verdict_filter = QComboBox()
        self.verdict_filter.addItem("All scans", "all")
        self.verdict_filter.addItem("With detections", "detections")
        self.verdict_filter.addItem("No detections", "no_detections")
        self.verdict_filter.currentIndexChanged.connect(self.apply_filters)
        controls.addWidget(self.verdict_filter)
        layout.addLayout(controls)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Date (UTC)", "Target", "Files", "Detections"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemDoubleClicked.connect(lambda _item: self.open_selected())
        layout.addWidget(self.table)
        self.open_button = QPushButton("Open selected scan in Results")
        self.open_button.setEnabled(False)
        self.open_button.clicked.connect(self.open_selected)
        self.table.itemSelectionChanged.connect(
            lambda: self.open_button.setEnabled(self.table.currentRow() >= 0))
        layout.addWidget(self.open_button)
        refresh = QPushButton("Refresh history")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        self.refresh()

    def refresh(self):
        try:
            self.scans = recent_scans(self.db_path, limit=100)
            self.apply_filters()
        except Exception as exc:
            self.scans = []
            self.apply_filters()
            self.note.setText(f"Cannot read history: {exc}")

    def apply_filters(self, *_args):
        rows = filter_scans(self.scans, self.search.text(),
                            self.verdict_filter.currentData())
        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        for i, scan in enumerate(rows):
            for j, value in enumerate((scan["created_utc"], scan["target"],
                                        scan["file_count"], scan["detections"])):
                cell = QTableWidgetItem(str(value))
                if j == 0:
                    cell.setData(256, scan["id"])
                self.table.setItem(i, j, cell)
        self.open_button.setEnabled(False)
        self.note.setText(
            f"{len(rows)} of {len(self.scans)} saved scans · Last 100 records · "
            "Double-click to inspect."
        )

    def open_selected(self):
        row = self.table.currentRow()
        cell = self.table.item(row, 0) if row >= 0 else None
        if cell is None:
            return
        scan_id = cell.data(256)
        try:
            report = get_scan(self.db_path, scan_id)
            if report is None:
                self.note.setText("Selected record is no longer available.")
                return
            self.report_selected.emit(report)
        except Exception as exc:
            self.note.setText(f"Cannot open scan: {exc}")


class QuarantineView(QWidget):
    """Read-only inventory. Never move, restore or execute quarantined files."""
    def __init__(self, store):
        super().__init__()
        self.store = store
        self.entries = []
        layout = QVBoxLayout(self)
        heading = QLabel("Quarantine")
        heading.setStyleSheet("font-size: 25px; font-weight: 600;")
        layout.addWidget(heading)
        self.note = QLabel("Local inventory only · no automatic isolation or restore actions.")
        self.note.setWordWrap(True)
        layout.addWidget(self.note)
        self.summary = QLabel("No stored records")
        layout.addWidget(self.summary)
        controls = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search file name or entry ID…")
        self.search.textChanged.connect(self.apply_filters)
        controls.addWidget(self.search, 1)
        self.state_filter = QComboBox()
        self.state_filter.addItem("All entries", "all")
        self.state_filter.addItem("Quarantined", "quarantined")
        self.state_filter.addItem("Restored", "restored")
        self.state_filter.currentIndexChanged.connect(self.apply_filters)
        controls.addWidget(self.state_filter)
        layout.addLayout(controls)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["File", "State", "Date (UTC)"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(135)
        self.details.setPlaceholderText("Select an entry to inspect metadata.")
        self.table.itemSelectionChanged.connect(self.show_selected)
        layout.addWidget(self.details)
        refresh = QPushButton("Refresh inventory")
        refresh.clicked.connect(self.refresh)
        layout.addWidget(refresh)
        layout.addWidget(QLabel("Experimental quarantine: do not use for real malware containment."))
        self.refresh()

    def refresh(self):
        try:
            self.entries = list_quarantine(self.store)
            totals = summarize_quarantine(self.entries)
            self.summary.setText(
                f"{totals['quarantined']} quarantined · {totals['restored']} restored · "
                f"{totals['total']} total records")
            self.note.setText(f"Read-only local inventory: {self.store}")
        except Exception as exc:
            self.entries = []
            self.note.setText(f"Cannot read quarantine inventory: {exc}")
            self.summary.setText("Inventory unavailable")
        self.apply_filters()

    def apply_filters(self, *_args):
        self.visible_entries = filter_quarantine(
            self.entries, self.search.text(), self.state_filter.currentData())
        self.table.setRowCount(0)
        self.table.setRowCount(len(self.visible_entries))
        for i, entry in enumerate(self.visible_entries):
            for j, value in enumerate(quarantine_row(entry)):
                self.table.setItem(i, j, QTableWidgetItem(value))
        self.details.clear()
        if not self.visible_entries:
            self.details.setPlaceholderText(
                "No matching entries. Empty quarantine is normal if no files were manually isolated.")

    def show_selected(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.visible_entries):
            return
        entry = self.visible_entries[row]
        self.details.setPlainText(
            f"Original path: {entry.get('original', '—')}\n"
            f"Entry ID: {entry.get('id', '—')}\n"
            f"SHA-256: {entry.get('sha256', '—')}\n"
            f"State: {entry.get('state', '—')}"
        )


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
