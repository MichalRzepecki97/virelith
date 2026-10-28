"""Results view for structured per-file scanner output."""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QTextEdit,
)
from .report_viewmodel import describe_file, summarize_report


class ResultsView(QWidget):
    def __init__(self):
        super().__init__()
        self.report = None
        layout = QVBoxLayout(self)
        self.heading = QLabel("Results")
        self.heading.setStyleSheet("font-size: 25px; font-weight: 600;")
        layout.addWidget(self.heading)
        self.summary = QLabel("Run a scan or select a report from History.")
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["File", "Verdict", "SHA-256"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.show_selected)
        layout.addWidget(self.table)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a file to review individual engine findings.")
        layout.addWidget(self.details)

    def set_report(self, report: dict):
        self.report = report
        summary = summarize_report(report)
        self.summary.setText(
            f"{summary['status']}  ·  {summary['total']} files  ·  "
            f"{summary['counts']['detection']} detections. "
            "No detection does not guarantee a file is safe."
        )
        self.table.setRowCount(summary["total"])
        for index, item in enumerate(report["files"]):
            for column, value in enumerate((
                item.get("path", ""), item.get("verdict", "unknown"), item.get("sha256") or "—"
            )):
                self.table.setItem(index, column, QTableWidgetItem(str(value)))
        self.details.clear()
        if summary["total"]:
            self.table.selectRow(0)

    def show_selected(self):
        index = self.table.currentRow()
        if self.report and 0 <= index < len(self.report.get("files", [])):
            self.details.setPlainText(describe_file(self.report["files"][index]))
