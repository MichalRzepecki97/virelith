"""Virelith Precision 2.0 — dark desktop theme.

Use only neutral dark surfaces and restrained emerald status/action accents.
"""
STYLE = """
QWidget { background: #0B151B; color: #E8F0F2; font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 13px; }
QMainWindow, QStackedWidget { background: #0B151B; }
QFrame#sidebar { background: #101E26; border-right: 1px solid #243740; }
QFrame#sidebar QLabel { background: transparent; color: #EDF5F6; }
QFrame#sidebar QPushButton {
 background: transparent; color: #AEBDC5; border: none; border-left: 3px solid transparent;
 padding: 13px 17px; text-align: left; border-radius: 0;
}
QFrame#sidebar QPushButton:hover { background: #1D3238; color: #FFFFFF; }
QFrame#sidebar QPushButton:checked {
 background: #163A35; color: #F1FFFA; border-left: 3px solid #46C995; font-weight: 650;
}
QLabel#h1 { font-size: 27px; font-weight: 700; color: #F3F8F9; }
QLabel#muted { color: #9DADB6; }
QFrame#panel { background: #13232B; border: 1px solid #28404A; border-radius: 8px; }
QFrame#panel QLabel { background: transparent; }
QPushButton { min-height: 28px; padding: 6px 14px; border-radius: 5px; }
QPushButton#primary { background: #23A77A; color: #061D19; border: 1px solid #34B98A; font-weight: 700; padding: 11px 19px; }
QPushButton#primary:hover { background: #48CDA1; }
QPushButton#primary:disabled { background: #38594F; color: #8FB4A5; border-color: #38594F; }
QPushButton#secondary { background: #152931; color: #D5E8E7; border: 1px solid #34515A; }
QPushButton#secondary:hover { background: #234047; }
QLineEdit, QComboBox { background: #11242C; color: #F1F6F5; border: 1px solid #35515B; border-radius: 5px; padding: 9px; selection-background-color: #26735C; }
QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QTableWidget:focus { border: 1px solid #3AA982; }
QTableWidget { background: #11222B; alternate-background-color: #172A32; color: #DCE9EA;
 border: 1px solid #29404A; border-radius: 6px; gridline-color: #263943;
 selection-background-color: #225847; selection-color: #FFFFFF; }
QTableWidget::item { padding: 8px; }
QHeaderView::section { background: #1B3038; color: #C3D4D8; font-weight: 600; padding: 9px;
 border: none; border-bottom: 1px solid #36505B; }
QTextEdit { background: #10232B; color: #DCEAE9; border: 1px solid #314850; border-radius: 6px; padding: 10px; }
QScrollArea { background: transparent; border: none; }
QScrollBar:vertical { background: #11242C; width: 10px; }
QScrollBar::handle:vertical { background: #3C5961; border-radius: 4px; min-height: 25px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""
