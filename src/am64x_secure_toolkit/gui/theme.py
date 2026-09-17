from __future__ import annotations

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

STYLE_SHEET = r"""
QMainWindow, QWidget { background: #f4f6f8; color: #20242a; }
QLabel { background: transparent; }
QFrame#contextBar, QFrame#boundaryPanel, QFrame#statusCard, QFrame#infoCard, QFrame#wizardStepBar, QFrame#taskCard {
    background: #ffffff;
    border: 1px solid #d7dce2;
    border-radius: 8px;
}
QFrame#statusCard { min-height: 66px; }
QFrame#taskCard { min-height: 96px; }
QFrame#safetyNote {
    background: #f8fafc;
    border: 1px solid #dce2e8;
    border-radius: 7px;
}
QFrame#choiceCard {
    background: #ffffff;
    border: 1px solid #d7dce2;
    border-radius: 8px;
}
QFrame#choiceCard[selected="true"] {
    background: #eef5fc;
    border: 2px solid #4b6f9f;
}
QRadioButton {
    background: transparent;
    spacing: 8px;
    font-weight: 650;
}
QRadioButton::indicator { width: 16px; height: 16px; }
QLabel#pageTitle { font-size: 22px; font-weight: 650; padding: 4px 0 2px 0; }
QLabel#sectionTitle { font-size: 16px; font-weight: 650; padding-top: 2px; }
QLabel#mutedText, QLabel#taskCardBody { color: #59636e; background: transparent; }
QLabel#cardText { color: #303740; background: transparent; }
QLabel#statusCardTitle { color: #303740; font-size: 13px; font-weight: 650; background: transparent; }
QLabel#statusCardValue { color: #59636e; background: transparent; }
QLabel#projectCountValue { color: #234f80; font-size: 22px; font-weight: 700; background: transparent; }
QLabel#safetyText { color: #59636e; background: transparent; }
QLabel#contextChip, QLabel#contextChipInfo, QLabel#contextChipMuted {
    border-radius: 11px;
    padding: 4px 9px;
    font-size: 12px;
    font-weight: 600;
}
QLabel#contextChip { color: #303740; background: #f1f4f7; border: 1px solid #d9dfe5; }
QLabel#contextChipInfo { color: #2e4e73; background: #eaf1f8; border: 1px solid #c8d7e8; }
QLabel#contextChipMuted { color: #59636e; background: #f6f7f8; border: 1px solid #dfe3e7; }
QLabel#statusPass { color: #17633a; background: #e7f4ec; border: 1px solid #b9dec7; border-radius: 12px; padding: 5px 10px; font-weight: 650; }
QLabel#statusWarn { color: #7a4b00; background: #fff4d8; border: 1px solid #eed28d; border-radius: 12px; padding: 5px 10px; font-weight: 650; }
QLabel#statusFail { color: #9f2727; background: #fde8e8; border: 1px solid #efbcbc; border-radius: 12px; padding: 5px 10px; font-weight: 650; }
QLabel#statusInfo { color: #2e4e73; background: #e9f0f8; border: 1px solid #bfd0e3; border-radius: 12px; padding: 5px 10px; font-weight: 650; }
QLabel#wizardStepActive { color: #234f80; font-weight: 700; padding: 5px 8px; background: #e9f0f8; border-radius: 8px; }
QLabel#wizardStepDone { color: #17633a; font-weight: 650; padding: 5px 8px; }
QLabel#wizardStepIdle { color: #6f7882; padding: 5px 8px; }
QPushButton {
    min-height: 32px;
    padding: 6px 12px;
    background: #ffffff;
    border: 1px solid #c8ced6;
    border-radius: 6px;
}
QPushButton:hover { background: #eef2f6; border-color: #aeb7c2; }
QPushButton:focus { border: 2px solid #4b6f9f; }
QPushButton:disabled { color: #8b939c; background: #eef0f2; }
QPushButton#primaryAction { background: #315f91; color: #ffffff; border-color: #315f91; font-weight: 650; }
QPushButton#primaryAction:hover { background: #284f79; }
QPushButton#primaryAction:disabled {
    color: #8b939c;
    background: #eef0f2;
    border-color: #d4d9df;
    font-weight: 650;
}
QPushButton#dangerAction { background: #fff8f8; color: #8b2929; border-color: #d9aaaa; }
QPushButton#taskCardAction {
    min-height: 26px;
    padding: 1px 0;
    text-align: left;
    background: transparent;
    border: 0;
    color: #234f80;
    font-weight: 650;
}
QPushButton#taskCardAction:hover { background: transparent; color: #173d67; text-decoration: underline; }
QPushButton#taskCardAction:focus { border: 1px solid #4b6f9f; border-radius: 4px; }
QPushButton#taskCardPrimary {
    min-height: 30px;
    padding: 5px 9px;
    text-align: left;
    background: #315f91;
    color: #ffffff;
    border: 1px solid #315f91;
    border-radius: 6px;
    font-weight: 650;
}
QPushButton#taskCardPrimary:hover { background: #284f79; }
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QListWidget, QTreeWidget, QTableWidget, QSpinBox {
    background: #ffffff;
    border: 1px solid #c8ced6;
    border-radius: 5px;
    padding: 5px;
    selection-background-color: #dce8f8;
    selection-color: #20242a;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QListWidget:focus, QTreeWidget:focus, QTableWidget:focus, QSpinBox:focus {
    border: 2px solid #4b6f9f;
}
QLineEdit[invalid="true"], QComboBox[invalid="true"] { border: 2px solid #b54141; background: #fffafa; }
QListWidget#mainNavigation { padding: 6px; background: #ffffff; border: 1px solid #d7dce2; border-radius: 8px; }
QListWidget#mainNavigation::item { min-height: 25px; padding: 7px 9px; margin: 1px 0; border-radius: 5px; }
QListWidget#mainNavigation::item:hover { background: #f1f4f7; }
QListWidget#mainNavigation::item:selected { background: #e4edf8; color: #1f3f63; font-weight: 650; }
QTabWidget::pane { border: 1px solid #d7dce2; border-radius: 6px; background: #ffffff; }
QTabBar::tab { padding: 7px 11px; margin-right: 2px; }
QTabBar::tab:selected { background: #ffffff; font-weight: 650; }
QHeaderView::section { background: #f2f4f6; padding: 6px; border: 0; border-bottom: 1px solid #d7dce2; font-weight: 650; }
QToolTip { background: #ffffff; color: #20242a; border: 1px solid #aeb7c2; padding: 4px; }
"""


def apply_application_theme(app: QApplication) -> None:
    """Apply a readable, high-DPI-friendly theme without overriding platform font family."""
    font = QFont(app.font())
    if font.pointSizeF() > 0 and font.pointSizeF() < 10.0:
        font.setPointSizeF(10.0)
    app.setFont(font)

    palette = QPalette(app.palette())
    palette.setColor(QPalette.Window, QColor("#f4f6f8"))
    palette.setColor(QPalette.Base, QColor("#ffffff"))
    palette.setColor(QPalette.AlternateBase, QColor("#f7f8fa"))
    palette.setColor(QPalette.Text, QColor("#20242a"))
    palette.setColor(QPalette.WindowText, QColor("#20242a"))
    palette.setColor(QPalette.Highlight, QColor("#dce8f8"))
    palette.setColor(QPalette.HighlightedText, QColor("#20242a"))
    app.setPalette(palette)
    app.setStyleSheet(STYLE_SHEET)
