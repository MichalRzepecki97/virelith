"""Precision Results: decision first, technical evidence on demand."""
from pathlib import Path
import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from .report_viewmodel import summarize_report


def text_label(text, size=13, muted=False):
    label = QLabel(str(text))
    label.setWordWrap(True)
    label.setStyleSheet(
        f"font-size: {size}px; color: {'#9AB6BE' if muted else '#E5F2F1'}; background: transparent;"
    )
    return label


def card():
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(9)
    return frame, layout


def engine_status(item, engine):
    result = item.get(engine) or {}
    status = result.get("status", "unavailable")
    suffix = ""
    if engine == "pe_analysis" and result.get("section_count") is not None:
        suffix = f" · {result['section_count']} sections"
    if engine == "heuristics":
        if result.get("review_recommended"):
            suffix = " · Review recommended"
        elif status == "evaluated":
            suffix = " · No review flagged"
    return str(status).replace("_", " ").title() + suffix


class ResultsView(QWidget):
    def __init__(self):
        super().__init__()
        self.report = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(30, 24, 30, 20)
        outer.setSpacing(0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(0, 0, 12, 0)
        layout.setSpacing(15)

        layout.addWidget(text_label("VIRELITH  /  ANALYSIS REPORT", 11, True))
        heading = text_label("Scan results", 27)
        heading.setStyleSheet("font-size: 27px; font-weight: 650;")
        layout.addWidget(heading)

        summary_card, summary_layout = card()
        self.verdict = text_label("No scan selected", 22)
        self.verdict.setStyleSheet("font-size: 22px; font-weight: 650;")
        summary_layout.addWidget(self.verdict)
        self.summary = text_label("Complete a scan to review the results.", 13, True)
        summary_layout.addWidget(self.summary)
        self.disclaimer = text_label(
            "No detection is not proof a file is safe. Detection rules may include test signatures.",
            11, True,
        )
        summary_layout.addWidget(self.disclaimer)
        layout.addWidget(summary_card)

        self.files_heading = text_label("Files", 15)
        self.files_heading.setStyleSheet("font-size: 15px; font-weight: 600;")
        layout.addWidget(self.files_heading)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["File", "Verdict"])
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setMaximumHeight(175)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(88)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.show_selected)
        layout.addWidget(self.table)

        self.selected_name = text_label("Select a file to inspect", 18)
        self.selected_name.setStyleSheet("font-size: 18px; font-weight: 600;")
        layout.addWidget(self.selected_name)

        grid = QHBoxLayout()
        grid.setSpacing(12)
        self.engine_labels = {}
        for key, name in (("clamav", "ClamAV"), ("yara", "YARA-X"),
                          ("pe_analysis", "PE Analyzer"), ("heuristics", "Heuristics")):
            frame, inner = card()
            title = text_label(name, 13)
            title.setStyleSheet("font-size: 13px; font-weight: 600;")
            inner.addWidget(title)
            status = text_label("—", 12, True)
            inner.addWidget(status)
            self.engine_labels[key] = status
            grid.addWidget(frame, 1)
        layout.addLayout(grid)

        details_card, details_layout = card()
        details_layout.addWidget(text_label("FILE INFORMATION", 11, True))
        self.file_path = text_label("—", 12)
        self.file_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        details_layout.addWidget(self.file_path)
        digest_row = QHBoxLayout()
        self.digest = text_label("SHA-256: —", 12, True)
        self.digest.setTextInteractionFlags(Qt.TextSelectableByMouse)
        digest_row.addWidget(self.digest, 1)
        copy = QPushButton("Copy SHA-256")
        copy.clicked.connect(self.copy_digest)
        digest_row.addWidget(copy)
        details_layout.addLayout(digest_row)
        layout.addWidget(details_card)

        self.advanced_button = QPushButton("Show technical analysis")
        self.advanced_button.setEnabled(False)
        self.advanced_button.setObjectName("secondary")
        self.advanced_button.setCheckable(True)
        self.advanced_button.toggled.connect(self.toggle_advanced)
        layout.addWidget(self.advanced_button, alignment=Qt.AlignLeft)
        self.advanced = QTextEdit()
        self.advanced.setReadOnly(True)
        self.advanced.setMinimumHeight(190)
        self.advanced.hide()
        layout.addWidget(self.advanced)
        layout.addStretch()

    def toggle_advanced(self, checked):
        self.advanced.setVisible(checked)
        self.advanced_button.setText(
            "Hide technical analysis" if checked else "Show technical analysis"
        )

    def set_report(self, report: dict):
        self.report = report
        result = summarize_report(report)
        counts = result["counts"]
        self.verdict.setText(result["status"])
        self.summary.setText(
            f"{result['total']} analyzed · {counts['detection']} detections · "
            f"{counts['incomplete'] + counts['error']} incomplete/errors"
        )
        files = report.get("files", [])
        self.table.setRowCount(len(files))
        for i, file in enumerate(files):
            file = file if isinstance(file, dict) else {}
            self.table.setItem(i, 0, QTableWidgetItem(Path(str(file.get("path", ""))).name))
            self.table.setItem(i, 1, QTableWidgetItem(str(file.get("verdict", "incomplete")).replace("_", " ").title()))
        self.files_heading.setVisible(len(files) > 1)
        self.table.setVisible(len(files) > 1)
        if files:
            if len(files) > 1:
                self.table.selectRow(0)
            else:
                self.show_file(files[0])
        else:
            self.show_file({})

    def show_selected(self):
        i = self.table.currentRow()
        if self.report and 0 <= i < len(self.report.get("files", [])):
            self.show_file(self.report["files"][i])

    def show_file(self, item):
        item = item if isinstance(item, dict) else {}
        path = str(item.get("path", ""))
        self.selected_name.setText(Path(path).name if path else "No file selected")
        self.file_path.setText("Path: " + (path or "—"))
        digest = item.get("sha256") or ""
        self.digest.setText("SHA-256: " + (digest or "—"))
        for engine, label in self.engine_labels.items():
            label.setText(engine_status(item, engine))
        self.advanced.setPlainText(json.dumps({
            "clamav": item.get("clamav"), "yara": item.get("yara"),
            "pe_analysis": item.get("pe_analysis"),
            "heuristics": item.get("heuristics"),
            "insight": item.get("insight", []),
        }, indent=2, ensure_ascii=False))
        self.advanced_button.setChecked(False)
        self.advanced_button.setEnabled(bool(item))

    def copy_digest(self):
        if self.report:
            digest = self.digest.text().removeprefix("SHA-256: ").strip()
            if len(digest) == 64 and all(c in "0123456789abcdefABCDEF" for c in digest):
                QApplication.clipboard().setText(digest)
