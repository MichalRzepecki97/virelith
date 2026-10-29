"""Precision Results: decision first, technical evidence on demand."""
from pathlib import Path
import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QMessageBox, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from .report_viewmodel import summarize_report
from .report_export import analysis_payload, export_report_html, export_report_json


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
        self.selected_item = {}
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
        insight_card, insight_layout = card()
        insight_layout.addWidget(text_label("SECURITY INSIGHTS / STATIC OBSERVATIONS", 12, True))
        self.insights_summary = text_label("No analysis selected.", 12, True)
        insight_layout.addWidget(self.insights_summary)
        self.insights_container = QVBoxLayout()
        insight_layout.addLayout(self.insights_container)
        insight_layout.addWidget(text_label("An import is not proof of execution; an observation is not a malware verdict.", 11, True))
        layout.addWidget(insight_card)

        self.advanced_button = QPushButton("Show technical analysis")
        self.advanced_button.setEnabled(False)
        self.advanced_button.setObjectName("secondary")
        self.advanced_button.setCheckable(True)
        self.advanced_button.toggled.connect(self.toggle_advanced)
        analysis_actions = QHBoxLayout()
        analysis_actions.addWidget(self.advanced_button)
        self.copy_analysis_button = QPushButton("Copy analysis JSON")
        self.copy_analysis_button.setObjectName("secondary")
        self.copy_analysis_button.setEnabled(False)
        self.copy_analysis_button.clicked.connect(self.copy_analysis)
        analysis_actions.addWidget(self.copy_analysis_button)
        self.export_json_button = QPushButton("Export JSON")
        self.export_html_button = QPushButton("Export HTML")
        for button in (self.export_json_button, self.export_html_button):
            button.setObjectName("secondary")
            button.setEnabled(False)
            analysis_actions.addWidget(button)
        self.export_json_button.clicked.connect(lambda: self.export_report("json"))
        self.export_html_button.clicked.connect(lambda: self.export_report("html"))
        analysis_actions.addStretch()
        layout.addLayout(analysis_actions)
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
        self.export_json_button.setEnabled(True)
        self.export_html_button.setEnabled(True)
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
        self.selected_item = item
        self.copy_analysis_button.setEnabled(bool(item))
        path = str(item.get("path", ""))
        self.selected_name.setText(Path(path).name if path else "No file selected")
        self.file_path.setText("Path: " + (path or "—"))
        digest = item.get("sha256") or ""
        self.digest.setText("SHA-256: " + (digest or "—"))
        for engine, label in self.engine_labels.items():
            label.setText(engine_status(item, engine))
        self.advanced.setPlainText(json.dumps(analysis_payload(item), indent=2, ensure_ascii=False))
        while self.insights_container.count():
            child = self.insights_container.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
        insights = item.get("insight") or []
        if not isinstance(insights, list):
            insights = []
        self.insights_summary.setText(
            f"{len(insights)} documented observation(s)" if insights
            else "No explanatory observations for this file."
        )
        for observation in insights[:32]:
            if not isinstance(observation, dict):
                continue
            frame, inner = card()
            inner.addWidget(text_label(str(observation.get("title", "Observation"))[:130], 15))
            imports = observation.get("matched_imports") or []
            if isinstance(imports, list) and imports:
                inner.addWidget(text_label("Matched imports: " + ", ".join(str(i) for i in imports[:20]), 12, True))
            if observation.get("section"):
                inner.addWidget(text_label("Section: " + str(observation["section"]), 12, True))
            inner.addWidget(text_label(str(observation.get("meaning", ""))[:1100], 12))
            inner.addWidget(text_label("Next step: " + str(observation.get("next_step", ""))[:800], 12, True))
            self.insights_container.addWidget(frame)
        self.advanced_button.setChecked(False)
        self.advanced_button.setEnabled(bool(item))

    def export_report(self, format_name):
        if not self.report:
            return
        extension = ".html" if format_name == "html" else ".json"
        output, _ = QFileDialog.getSaveFileName(
            self, "Export scan report", "virelith-report" + extension,
            "HTML report (*.html)" if format_name == "html" else "JSON report (*.json)"
        )
        if not output:
            return
        path = Path(output)
        if path.suffix.lower() != extension:
            path = path.with_suffix(extension)
        try:
            data = export_report_html(self.report) if format_name == "html" else export_report_json(self.report)
            path.write_text(data, encoding="utf-8")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))

    def copy_analysis(self):
        if self.selected_item:
            QApplication.clipboard().setText(self.advanced.toPlainText())

    def copy_digest(self):
        if self.report:
            digest = self.digest.text().removeprefix("SHA-256: ").strip()
            if len(digest) == 64 and all(c in "0123456789abcdefABCDEF" for c in digest):
                QApplication.clipboard().setText(digest)
