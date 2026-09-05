from __future__ import annotations
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

class PlaceholderPage(QWidget):
    def __init__(self,title:str,detail:str):
        super().__init__(); layout=QVBoxLayout(self); h=QLabel(title); h.setObjectName("pageTitle"); layout.addWidget(h); d=QLabel(detail); d.setWordWrap(True); layout.addWidget(d); layout.addStretch(1)
