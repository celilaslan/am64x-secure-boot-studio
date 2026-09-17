from __future__ import annotations

import json

from PySide6.QtWidgets import QLabel, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from ...services.demo import create_demo_workspace
from .common import file_field, show_guided_error


class DemoPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("5 Dakikalık Demo Workspace"); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel("Synthetic/non-production key set + küçük payload üretir; certificate signature ile payload integrity'nin bağımsız olduğunu gösterir. Exact Load Extension değeri uydurulmadığı için eğitim artifact'ı kasıtlı olarak NOT_TARGET_READY'dir. Hardware/OTP işlemi yoktur.")
        note.setWordWrap(True); layout.addWidget(note)
        self.dir_edit, field = file_field(self, "Boş demo klasörü seçin", directory=True); layout.addWidget(field)
        btn = QPushButton("Demo Workspace Oluştur ve Çalıştır"); btn.clicked.connect(self.run_demo); layout.addWidget(btn)
        self.out = QPlainTextEdit(); self.out.setReadOnly(True); layout.addWidget(self.out, 1)

    def run_demo(self) -> None:
        try:
            if not self.dir_edit.text().strip(): raise ValueError("Boş bir demo klasörü seçin")
            result = create_demo_workspace(self.dir_edit.text())
            self.state.set_last_result(result)
            self.out.setPlainText(json.dumps(result, indent=2, ensure_ascii=False))
        except Exception as exc:
            show_guided_error(self, exc, context="Demo başarısız")
