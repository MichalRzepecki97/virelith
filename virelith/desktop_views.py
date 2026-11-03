"""Functional Qt views for local history, quarantine inventory and settings."""
from pathlib import Path

from PySide6.QtCore import Qt, QSettings, Signal, QProcess, QTimer
from PySide6.QtWidgets import (
    QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QComboBox,
    QScrollArea, QFrame,
)
from .scan_history import recent_scans, get_scan
from .quarantine import list_quarantine
from .history_filters import filter_scans
from .quarantine_viewmodel import summarize_quarantine, filter_quarantine, quarantine_row
from .signature_management import signature_snapshot, yara_store_snapshot


class HistoryView(QWidget):
    report_selected = Signal(dict)

    def __init__(self, db_path):
        super().__init__()
        self.db_path = db_path
        self.scans = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(15)
        layout.addWidget(QLabel("VIRELITH  /  HISTORY"))
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
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(15)
        layout.addWidget(QLabel("VIRELITH  /  QUARANTINE"))
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
    """Scrollable, operator-friendly settings and signature maintenance."""

    def __init__(self, settings: QSettings):
        super().__init__()
        self.settings = settings
        self.update_proc = None
        self.update_expired = False
        self.update_timer = QTimer(self)
        self.update_timer.setSingleShot(True)
        self.update_timer.timeout.connect(self.signature_update_timeout)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(32, 27, 32, 30)
        layout.setSpacing(15)

        eyebrow = QLabel("VIRELITH  /  SETTINGS")
        eyebrow.setStyleSheet("font-size:11px; color:#8FADB4;")
        layout.addWidget(eyebrow)
        heading = QLabel("Signature management")
        heading.setStyleSheet("font-size:27px; font-weight:700;")
        layout.addWidget(heading)
        intro = QLabel(
            "Local engine status, trusted rule-store inventory and explicit updates. "
            "Virelith does not provide real-time protection."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#A6BDC3;")
        layout.addWidget(intro)

        clam_panel, clam_layout = self._panel("CLAMAV / SIGNATURE DATABASES")
        self.signature_status = QLabel("Not checked. Inspect local database files to see their state.")
        self.signature_status.setWordWrap(True)
        self.signature_status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        clam_layout.addWidget(self.signature_status)
        actions = QHBoxLayout()
        status_button = QPushButton("Check ClamAV status")
        status_button.setObjectName("secondary")
        status_button.clicked.connect(self.check_signatures)
        actions.addWidget(status_button)
        self.update_button = QPushButton("Run FreshClam update")
        self.update_button.setObjectName("primary")
        self.update_button.clicked.connect(self.start_signature_update)
        actions.addWidget(self.update_button)
        actions.addStretch()
        clam_layout.addLayout(actions)
        layout.addWidget(clam_panel)

        yara_panel, yara_layout = self._panel("YARA-X / ACTIVE RULE STORE")
        self.yara_status = QLabel("Not checked. Rules must be activated in a trusted local store.")
        self.yara_status.setWordWrap(True)
        self.yara_status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        yara_layout.addWidget(self.yara_status)
        check_yara = QPushButton("Verify active YARA rules")
        check_yara.setObjectName("secondary")
        check_yara.clicked.connect(self.check_yara)
        yara_layout.addWidget(check_yara, 0)
        layout.addWidget(yara_panel)

        settings_panel, settings_layout = self._panel("LOCAL CONFIGURATION")
        form = QFormLayout()
        self.clam = QLineEdit(str(settings.value("clam", "clamscan")))
        self.rules = QLineEdit(str(settings.value("rule_store", "")))
        self.history = QLineEdit(str(settings.value(
            "history_db", Path.home() / ".virelith" / "history.sqlite3")))
        self.store = QLineEdit(str(settings.value(
            "quarantine_store", Path.home() / ".virelith" / "quarantine")))
        for title, field in (
            ("ClamAV executable", self.clam),
            ("Signed rule store", self.rules),
            ("History database", self.history),
            ("Quarantine inventory", self.store),
        ):
            form.addRow(title, field)
        settings_layout.addLayout(form)
        self.status = QLabel("Configuration paths are not automatically trusted.")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color:#A5BBC0;")
        settings_layout.addWidget(self.status)
        save_button = QPushButton("Save configuration")
        save_button.setObjectName("secondary")
        save_button.clicked.connect(self.save)
        settings_layout.addWidget(save_button)
        layout.addWidget(settings_panel)
        layout.addStretch()

    @staticmethod
    def _panel(title):
        panel = QFrame()
        panel.setObjectName("panel")
        inner = QVBoxLayout(panel)
        inner.setContentsMargins(20, 18, 20, 18)
        inner.setSpacing(12)
        heading = QLabel(title)
        heading.setStyleSheet("color:#80D9B8; font-size:12px; font-weight:650; background:transparent;")
        inner.addWidget(heading)
        return panel, inner

    def check_yara(self):
        state = yara_store_snapshot(self.rules.text().strip())
        detail = state.get("detail", "")
        if state["status"] == "active":
            self.yara_status.setText(
                f"ACTIVE · Version {state['version']}\n"
                f"SHA-256: {state['sha256']}\n"
                f"Source: {state['path']}\n{detail}"
            )
        else:
            self.yara_status.setText(f"{state['status'].upper()} · {detail}")

    def save(self):
        for key, edit in (("clam", self.clam), ("rule_store", self.rules),
                          ("history_db", self.history), ("quarantine_store", self.store)):
            self.settings.setValue(key, edit.text().strip())
        self.settings.sync()
        self.status.setText("Settings saved. They apply to the next scan; refresh other tabs to read new paths.")

    def check_signatures(self):
        snapshot = signature_snapshot(str(self.clam.text().strip() or "clamscan"))
        clam = snapshot["clamav"]
        databases = clam.get("databases", [])
        lines = [
            f"Engine: {clam.get('engine_version', 'Unavailable')}",
            f"Database status: {clam['status']}",
            f"FreshClam installed: {'yes' if snapshot['freshclam_available'] else 'no'}",
            f"Database directory: {snapshot['database_path']}",
        ]
        if databases:
            from datetime import datetime, timezone
            for database in databases:
                stamp = datetime.fromtimestamp(
                    database["modified_utc_epoch"], tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
                lines.append(f"{database['name']} · {database['bytes']} bytes · modified {stamp}")
        else:
            lines.append("No recognized .cvd/.cld database files were found at this path.")
        if clam.get("detail"):
            lines.append(str(clam["detail"]))
        lines.append(snapshot["notice"])
        self.signature_status.setText("\n".join(lines))

    def start_signature_update(self):
        if self.update_proc is not None:
            return
        self.update_expired = False
        self.update_proc = QProcess(self)
        self.update_proc.setProgram("freshclam")
        self.update_proc.setArguments(["--stdout"])
        self.update_proc.finished.connect(self.signature_update_finished)
        self.update_proc.errorOccurred.connect(self.signature_update_error)
        self.update_button.setEnabled(False)
        self.signature_status.setText(
            "FreshClam running. Database locks, mirror access and permissions "
            "are managed by FreshClam. No update is guaranteed."
        )
        self.update_proc.start()
        self.update_timer.start(240_000)

    def signature_update_timeout(self):
        if self.update_proc is not None:
            self.update_expired = True
            self.update_proc.kill()

    def signature_update_error(self, error):
        if self.update_proc is None:
            return
        if error == QProcess.FailedToStart:
            self.signature_status.setText(
                "Could not start FreshClam: " + self.update_proc.errorString()
            )
            self.finish_signature_process()

    def signature_update_finished(self, exit_code, _status):
        if self.update_proc is None:
            return
        output = bytes(self.update_proc.readAllStandardOutput()).decode(errors="replace")
        errors = bytes(self.update_proc.readAllStandardError()).decode(errors="replace")
        self.signature_status.setText(
            ("FreshClam timed out after 240 seconds; update not verified.\n"
             if self.update_expired else
             "FreshClam completed. Check signature status to verify databases.\n"
             if exit_code == 0 else f"FreshClam failed (exit {exit_code}).\n")
            + (output + "\n" + errors).strip()[-1500:]
        )
        self.finish_signature_process()

    def finish_signature_process(self):
        self.update_timer.stop()
        if self.update_proc is not None:
            self.update_proc.deleteLater()
            self.update_proc = None
        self.update_button.setEnabled(True)
