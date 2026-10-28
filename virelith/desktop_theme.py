"""Shared visual language for Virelith Precision + Operator."""
STYLE = """
QWidget { background: #F5F7F6; color: #22313A; font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 13px; }
QFrame#sidebar { background: #1D2933; border: none; }
QFrame#sidebar QLabel { color: #E9F0EF; background: transparent; }
QFrame#sidebar QPushButton {
 background: transparent; color: #B9C7C8; border: none; padding: 12px 16px;
 border-left: 3px solid transparent; text-align: left; border-radius: 3px;
}
QFrame#sidebar QPushButton:hover { background: #2B3942; color: #FFFFFF; }
QFrame#sidebar QPushButton:checked {
 background: #2A423F; color: #FFFFFF; border-left: 3px solid #77B6A3; font-weight: 600;
}
QLabel#h1 { font-size: 27px; font-weight: 700; color: #1F3038; }
QLabel#muted { color: #63747E; }
QFrame#panel { background: #FFFFFF; border: 1px solid #DCE4E0; border-radius: 8px; }
QFrame#panel QLabel { background: transparent; }
QPushButton { min-height: 28px; padding: 5px 12px; border-radius: 5px; }
QPushButton#primary {
 background: #276B58; color: white; padding: 10px 18px; border: 1px solid #276B58;
 font-weight: 600;
}
QPushButton#primary:hover { background: #215946; }
QPushButton#primary:disabled { background: #A9B8B2; border-color: #A9B8B2; }
QPushButton#secondary {
 background: #FFFFFF; color: #263B43; border: 1px solid #CBD8D3;
}
QPushButton#secondary:hover { background: #EFF4F1; }
QLineEdit, QComboBox {
 background: #FFFFFF; border: 1px solid #CAD6D2; border-radius: 5px;
 padding: 8px; selection-background-color: #357969;
}
QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QTableWidget:focus { border: 1px solid #458C76; }
QTableWidget {
 background: #FFFFFF; alternate-background-color: #F7FAF8; border: 1px solid #DEE6E1;
 border-radius: 6px; gridline-color: #ECF1ED; selection-background-color: #DFEEE7;
 selection-color: #1F3730;
}
QTableWidget::item { padding: 8px; }
QHeaderView::section {
 background: #EDF2EF; color: #465960; font-weight: 600; padding: 9px 10px;
 border: none; border-bottom: 1px solid #D8E2DC;
}
QTextEdit {
 background: #FFFFFF; border: 1px solid #DEE6E1; border-radius: 6px;
 padding: 10px; selection-background-color: #D7E9DF;
}
QScrollArea { background: transparent; border: none; }
QScrollBar:vertical { background: #EFF3F0; width: 10px; }
QScrollBar::handle:vertical { background: #BFCFC7; border-radius: 4px; min-height: 25px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""
