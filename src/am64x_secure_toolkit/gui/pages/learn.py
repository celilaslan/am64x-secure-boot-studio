from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QListWidget, QPlainTextEdit, QVBoxLayout, QWidget

from ...services.explanations import list_learning_cards
from ...services.source_registry import source_card


class LearnPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("Öğren — kısa AM64x Secure Boot kartları"); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel("Her kart 30–90 saniyelik bir kavram özeti verir. Normal workflow'larda teknik ayrıntı gerektiğinde Source Trace ile aynı source registry kullanılır.")
        note.setWordWrap(True); layout.addWidget(note)
        body = QHBoxLayout(); layout.addLayout(body, 1)
        self.list = QListWidget(); body.addWidget(self.list, 0)
        self.detail = QPlainTextEdit(); self.detail.setReadOnly(True); body.addWidget(self.detail, 1)
        self.cards = list_learning_cards()
        for card in self.cards: self.list.addItem(card["title"])
        self.list.currentRowChanged.connect(self.show_card)
        if self.cards: self.list.setCurrentRow(0)

    def show_card(self, index: int) -> None:
        if not 0 <= index < len(self.cards): return
        card = self.cards[index]
        source_text = "\n\n".join(source_card(s) for s in card["sources"])
        self.detail.setPlainText(f"{card['title']}\n\n{card['short']}\n\n{card['body']}\n\n--- Kaynaklar ---\n{source_text}")
