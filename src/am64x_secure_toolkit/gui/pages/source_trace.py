from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QListWidget, QPlainTextEdit, QVBoxLayout, QWidget

from ...services.source_registry import list_sources, source_card


class SourceTracePage(QWidget):
    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("Source Trace — Bu bilgi nereden geliyor?"); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel("Source priority: installed SDK source/Makefile/build → same-release SDK/TISCI → silicon errata → TRM/datasheet. Exact değer source-backed değilse Studio 'doğrulanmadı' yaklaşımını korur.")
        note.setWordWrap(True); layout.addWidget(note)
        body = QHBoxLayout(); layout.addLayout(body, 1)
        self.list = QListWidget(); body.addWidget(self.list, 0)
        self.detail = QPlainTextEdit(); self.detail.setReadOnly(True); body.addWidget(self.detail, 1)
        self.rows = list_sources()
        for row in self.rows:
            self.list.addItem(f"P{row['priority']}  {row['id']} — {row['title']}")
        self.list.currentRowChanged.connect(self.show_source)
        if self.rows: self.list.setCurrentRow(0)

    def show_source(self, index: int) -> None:
        if 0 <= index < len(self.rows):
            self.detail.setPlainText(source_card(self.rows[index]["id"]))
