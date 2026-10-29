"""Precision 2.0 Overview — local facts, never a fabricated protection score."""
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)
from .overview_model import overview_snapshot


def caption(text):
    lbl = QLabel(text)
    lbl.setObjectName("overviewCaption")
    lbl.setStyleSheet("background:transparent; color:#9FB8BB; font-size:11px; letter-spacing:1px;")
    return lbl


def txt(text, size=14, color="#E4F0F0", weight=400):
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(
        f"background:transparent; color:{color}; font-size:{size}px; font-weight:{weight};"
    )
    return lbl


def block():
    frame = QFrame()
    frame.setObjectName("panel")
    box = QVBoxLayout(frame)
    box.setContentsMargins(21, 20, 21, 20)
    box.setSpacing(12)
    return frame, box


class OverviewView(QWidget):
    def __init__(self, history_path, clam_command, rule_store, open_scan, open_history):
        super().__init__()
        self.history_path = history_path
        self.clam_command = clam_command
        self.rule_store = rule_store
        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        shell.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        main = QVBoxLayout(body)
        main.setContentsMargins(30, 28, 30, 28)
        main.setSpacing(18)

        main.addWidget(caption("VIRELITH  /  OVERVIEW"))
        header = txt("Local threat analysis", 29, weight=700)
        main.addWidget(header)
        main.addWidget(txt("On-demand scanning. Full control. Transparent results.",
                           13, "#9EB5BE"))

        hero, hero_box = block()
        row = QHBoxLayout()
        icon = txt("◈", 53, "#55CE9D", 700)
        icon.setFixedWidth(84)
        row.addWidget(icon, 0, Qt.AlignVCenter)
        headline_col = QVBoxLayout()
        headline_col.addWidget(caption("SCANNER STATUS"))
        headline_col.addWidget(txt("Ready for on-demand analysis", 22, weight=650))
        self.scope = txt("No real-time protection", 12, "#A9C0C4")
        headline_col.addWidget(self.scope)
        row.addLayout(headline_col, 1)
        scan = QPushButton("Scan a file")
        scan.setObjectName("primary")
        scan.clicked.connect(open_scan)
        row.addWidget(scan, 0, Qt.AlignVCenter)
        hero_box.addLayout(row)
        main.addWidget(hero)

        grid = QHBoxLayout()
        grid.setSpacing(14)
        engine, engine_layout = block()
        engine_layout.addWidget(caption("ENGINE AVAILABILITY"))
        self.clam = txt("ClamAV · Checking…")
        self.yara = txt("YARA · Checking…")
        engine_layout.addWidget(self.clam)
        engine_layout.addWidget(self.yara)
        engine_layout.addWidget(txt(
            "Executable and configuration checks only — signature validity is not verified.",
            11, "#90ADB3"))
        grid.addWidget(engine, 1)

        activity, activity_layout = block()
        activity_layout.addWidget(caption("RECENT ACTIVITY"))
        self.counts = txt("No recent scans", 18, weight=650)
        self.last_scan = txt("No saved reports yet", 12, "#ACC1C7")
        activity_layout.addWidget(self.counts)
        activity_layout.addWidget(self.last_scan)
        history_btn = QPushButton("View history")
        history_btn.setObjectName("secondary")
        history_btn.clicked.connect(open_history)
        activity_layout.addWidget(history_btn, 0, Qt.AlignLeft)
        grid.addWidget(activity, 1)
        main.addLayout(grid)

        timeline, timeline_box = block()
        timeline_box.addWidget(caption("LATEST SCANS"))
        self.scan_rows = []
        for _ in range(5):
            entry = txt("", 13)
            entry.setVisible(False)
            self.scan_rows.append(entry)
            timeline_box.addWidget(entry)
        self.empty = txt("No scans saved in the selected history database.", 13, "#ACC1C7")
        timeline_box.addWidget(self.empty)
        main.addWidget(timeline)
        self.note = txt(
            "Virelith scans on demand; it is not a replacement for real-time endpoint protection.",
            11, "#91AAB2")
        main.addWidget(self.note)
        main.addStretch()
        self.refresh()

    def refresh(self):
        data = overview_snapshot(self.history_path, self.clam_command, self.rule_store)
        self.scope.setText(data["scope"])
        self.clam.setText("ClamAV  ·  " + data["clamav"])
        self.yara.setText("YARA-X  ·  " + data["yara"])
        scans = data["history"]
        self.counts.setText(f"{len(scans)} recent scans  /  {data['detection_count']} detections")
        last = data["last_scan"]
        self.last_scan.setText(
            "Latest: " + Path(str(last["target"])).name + " · " + str(last["created_utc"])
            if last else "No previous scan"
        )
        self.empty.setVisible(not scans)
        for label, entry in zip(self.scan_rows, scans):
            label.setText(
                f"{Path(str(entry['target'])).name}   ·   "
                f"{entry['detections']} detection(s)   ·   {entry['created_utc']}"
            )
        for i, label in enumerate(self.scan_rows):
            label.setVisible(i < len(scans))
        self.note.setText(
            ("History unavailable: " + data["history_error"]) if data["history_error"]
            else "Availability checks do not establish trusted signatures or real-time protection."
        )
