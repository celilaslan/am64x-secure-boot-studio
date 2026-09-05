from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QCheckBox, QComboBox, QFormLayout, QLabel, QPushButton, QPlainTextEdit, QVBoxLayout, QWidget

from ...services.guidance import recommend_workflow


class GuidePage(QWidget):
    navigate = Signal(str)

    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("Emin Değilim — Bana Yol Göster"); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel("CLI komutu/OID/tool seçmek yerine birkaç basit soruya cevap verin. Studio en uygun güvenli host-side workflow'u önerir.")
        note.setWordWrap(True); layout.addWidget(note)
        form = QFormLayout(); layout.addLayout(form)
        self.has_image = QComboBox(); self.has_image.addItems(["Hayır", "Evet"]); form.addRow("Elinizde hazır image/certificate var mı?", self.has_image)
        self.goal = QComboBox(); self.goal.addItem("Secure application oluşturmak", "application"); self.goal.addItem("Hazır dosyanın ne olduğunu anlamak", "what-is-this"); self.goal.addItem("Hazır dosyayı doğrulamak", "verify"); self.goal.addItem("Certificate/OID'leri anlamak", "certificate"); self.goal.addItem("Negative test yapmak", "negative"); self.goal.addItem("ROM combined image ile çalışmak", "rom"); self.goal.addItem("Key üretmek/kontrol etmek", "keys"); form.addRow("Ana hedefiniz", self.goal)
        self.conf = QCheckBox("Firmware içeriğinin gizlenmesini de istiyorum"); form.addRow("Confidentiality", self.conf)
        self.prov = QCheckBox("HS-FS→HS-SE / customer key provisioning mimarisini araştırıyorum"); form.addRow("Provisioning", self.prov)
        btn = QPushButton("Workflow Öner"); btn.clicked.connect(self.recommend); layout.addWidget(btn)
        self.output = QPlainTextEdit(); self.output.setReadOnly(True); layout.addWidget(self.output, 1)
        self.go = QPushButton("Önerilen Ekrana Git"); self.go.setEnabled(False); self.go.clicked.connect(self.open_workflow); layout.addWidget(self.go)
        self.current: dict | None = None

    def recommend(self) -> None:
        self.current = recommend_workflow(has_image=self.has_image.currentText()=="Evet", goal=self.goal.currentData(), wants_confidentiality=self.conf.isChecked(), provisioning_interest=self.prov.isChecked())
        r = self.current
        self.output.setPlainText(f"Öneri: {r['title']}\n\nNeden?\n{r['rationale']}\n\nGüvenlik sınırı\n{r['safety_note']}")
        self.go.setEnabled(True)

    def open_workflow(self) -> None:
        if self.current: self.navigate.emit(self.current["workflow"])
