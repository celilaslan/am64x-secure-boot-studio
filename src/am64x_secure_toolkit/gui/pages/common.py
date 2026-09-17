from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QWidget

from ...services.presentation import error_guidance


def file_field(parent: QWidget, title: str, *, save: bool = False, directory: bool = False, secret: bool = False):
    edit = QLineEdit()
    edit.setAccessibleName(title)
    if secret:
        edit.setEchoMode(QLineEdit.PasswordEchoOnEdit)
    button = QPushButton("Seç")
    button.setAccessibleName(f"{title}: dosya seç")

    def choose() -> None:
        if directory:
            path = QFileDialog.getExistingDirectory(parent, title)
        elif save:
            path, _ = QFileDialog.getSaveFileName(parent, title)
        else:
            path, _ = QFileDialog.getOpenFileName(parent, title)
        if path:
            edit.setText(path)
            set_field_invalid(edit, False)

    button.clicked.connect(choose)
    row = QHBoxLayout(); row.addWidget(edit); row.addWidget(button)
    box = QWidget(); box.setLayout(row)
    return edit, box


def set_json(widget: QPlainTextEdit, data) -> None:
    widget.setPlainText(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False))


def parse_optional_int(text: str) -> int | None:
    value = text.strip()
    if not value:
        return None
    return int(value, 0)


def require_text(value: str, label: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{label} boş bırakılamaz")
    return value


def set_field_invalid(widget, invalid: bool = True) -> None:
    widget.setProperty("invalid", invalid)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def require_field(widget: QLineEdit, label: str) -> str:
    value = widget.text().strip()
    set_field_invalid(widget, not bool(value))
    if not value:
        widget.setFocus()
        raise ValueError(f"{label} boş bırakılamaz")
    return value


def show_guided_error(parent: QWidget, exc: BaseException, *, context: str | None = None) -> None:
    guide = error_guidance(exc)
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Critical)
    box.setWindowTitle(context or guide["title"])
    box.setText(guide["title"])
    box.setInformativeText(
        f"Ne oldu?\n{guide['what']}\n\n"
        f"Neden olabilir?\n{guide['why']}\n\n"
        f"Ne yapabilirsiniz?\n{guide['action']}"
    )
    box.setDetailedText(guide["technical"])
    box.exec()


def save_text_dialog(parent: QWidget, title: str, writer: Callable[[Path], None], suffix: str = "") -> Path | None:
    path, _ = QFileDialog.getSaveFileName(parent, title)
    if not path:
        return None
    p = Path(path)
    if suffix and not p.suffix:
        p = p.with_suffix(suffix)
    writer(p)
    return p
