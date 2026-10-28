"""Precision Overview — grounded local state, not a protection score."""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget
from .overview_model import overview_snapshot


def label(text, size=13, muted=False):
    node = QLabel(str(text))
    node.setWordWrap(True)
    node.setStyleSheet(f"font-size:{size}px; color:{'#657680' if muted else '#24313B'}; background:transparent;")
    return node


def card():
    frame = QFrame()
    frame.setObjectName("panel")
    box = QVBoxLayout(frame)
    box.setContentsMargins(20, 18, 20, 18)
    box.setSpacing(10)
    return frame, box


class OverviewView(QWidget):
    def __init__(self, history_path, clam_command, rule_store, open_scan, open_history):
        super().__init__()
        self.history_path = history_path
        self.clam_command = clam_command
        self.rule_store = rule_store
        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 30, 35, 30)
        layout.setSpacing(17)
        layout.addWidget(label("VIRELITH  /  OVERVIEW", 11, True))
        title = label("Security overview", 27)
        title.setStyleSheet("font-size:27px; font-weight:650;")
        layout.addWidget(title)
        main, main_layout = card()
        headline = label("Local on-demand scanner", 20)
        headline.setStyleSheet("font-size:20px; font-weight:650; background:transparent;")
        main_layout.addWidget(headline)
        self.scope = label("On-demand scans only · no real-time protection", 12, True)
        main_layout.addWidget(self.scope)
        scan = QPushButton("New scan")
        scan.setObjectName("primary")
        scan.clicked.connect(open_scan)
        main_layout.addWidget(scan, alignment=Qt.AlignLeft)
        layout.addWidget(main)

        engine_card, engine_layout = card()
        engine_layout.addWidget(label("ENGINE STATUS", 11, True))
        self.clam = label("ClamAV — checking")
        self.yara = label("YARA rules — checking")
        engine_layout.addWidget(self.clam)
        engine_layout.addWidget(self.yara)
        layout.addWidget(engine_card)

        history_card, history_layout = card()
        history_layout.addWidget(label("RECENT SCANS", 11, True))
        self.last_scan = label("No saved scans yet")
        self.counts = label("0 recent detections", 12, True)
        history_layout.addWidget(self.last_scan)
        history_layout.addWidget(self.counts)
        history_button = QPushButton("View history")
        history_button.setObjectName("secondary")
        history_button.clicked.connect(open_history)
        history_layout.addWidget(history_button, alignment=Qt.AlignLeft)
        layout.addWidget(history_card)
        self.note = label("Status reflects local availability, not a guarantee of protection.", 11, True)
        layout.addWidget(self.note)
        layout.addStretch()
        self.refresh()

    def refresh(self):
        data = overview_snapshot(self.history_path, self.clam_command, self.rule_store)
        self.scope.setText(data["scope"])
        self.clam.setText("ClamAV · " + data["clamav"])
        self.yara.setText("YARA · " + data["yara"])
        last = data["last_scan"]
        self.last_scan.setText(
            f"Last scan: {last['target']} · {last['created_utc']}"
            if last else "No scans recorded in the selected history database."
        )
        self.counts.setText(
            f"{len(data['history'])} recent scans · "
            f"{data['detection_count']} detections across the last five scans"
        )
        self.note.setText(
            "History unavailable: " + data["history_error"] if data["history_error"]
            else "Availability checks do not confirm ClamAV signatures are current or rules are trusted."
        )
