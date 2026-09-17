from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget

from ...workflows.inspect import inspect_and_verify
from ..widgets import HumanResultView, ImageAnatomyWidget
from .common import require_field, show_guided_error


class InspectorPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        self.setAcceptDrops(True)
        layout = QVBoxLayout(self)
        title = QLabel("Image / Certificate İnceleme")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        hint = QLabel(
            "Dosyayı seçebilir veya bu sayfaya sürükleyip bırakabilirsiniz. Drop sonrası yalnız read-only inspect çalışır; "
            "kriptografik ve yapısal doğrulama ayrıca seçilir."
        )
        hint.setWordWrap(True); hint.setObjectName("mutedText"); layout.addWidget(hint)

        row = QHBoxLayout()
        self.path = QLineEdit(); self.path.setPlaceholderText("Secure image veya DER certificate")
        row.addWidget(self.path, 1)
        pick = QPushButton("Seç"); pick.clicked.connect(self.choose); row.addWidget(pick)
        layout.addLayout(row)
        actions = QHBoxLayout()
        inspect_btn = QPushButton("Yalnız İncele"); inspect_btn.clicked.connect(lambda: self.run(False))
        verify_btn = QPushButton("İncele + Doğrula"); verify_btn.setObjectName("primaryAction"); verify_btn.clicked.connect(lambda: self.run(True))
        actions.addWidget(inspect_btn); actions.addWidget(verify_btn); actions.addStretch(1); layout.addLayout(actions)

        self.tabs = QTabWidget()
        self.result_view = HumanResultView(show_boundary=True)
        self.tabs.addTab(self.result_view, "Sonuç")
        anatomy_page = QWidget(); anatomy_layout = QVBoxLayout(anatomy_page)
        anatomy_note = QLabel(
            "Bu görünüm yalnız dosyadan parse edilen byte boyutlarını kullanır. Eksik load address, offset, host/core ID veya target davranışı tahmin edilmez."
        )
        anatomy_note.setWordWrap(True); anatomy_note.setObjectName("mutedText"); anatomy_layout.addWidget(anatomy_note)
        self.anatomy = ImageAnatomyWidget(); anatomy_layout.addWidget(self.anatomy, 1)
        self.anatomy_meta = QLabel("Henüz image seçilmedi."); self.anatomy_meta.setWordWrap(True); anatomy_layout.addWidget(self.anatomy_meta)
        self.tabs.addTab(anatomy_page, "Image Anatomy")
        layout.addWidget(self.tabs, 1)

    def choose(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Image/certificate seç")
        if path:
            self.path.setText(path)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if any(url.isLocalFile() and Path(url.toLocalFile()).is_file() for url in urls):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile() and Path(url.toLocalFile()).is_file():
                self.path.setText(url.toLocalFile())
                event.acceptProposedAction()
                self.run(False)
                return
        event.ignore()

    def run(self, verify: bool) -> None:
        try:
            path = require_field(self.path, "Image/certificate")
            result = inspect_and_verify(path, verify=verify).to_dict()
            self.state.set_last_result(result)
            self.result_view.set_result(result)
            inspection = (result.get("safe_details") or {}).get("inspection") or {}
            self.anatomy.set_inspection(inspection)
            decoded = inspection.get("decoded") or {}
            extensions = inspection.get("extensions") or []
            semantics = inspection.get("tisci_request_semantics") or "not_determined"
            self.anatomy_meta.setText(
                f"Sınıflandırma: {inspection.get('classification', 'unknown')}  ·  "
                f"Certificate: {inspection.get('certificate_size', 0)} B  ·  "
                f"Appended: {inspection.get('appended_size', 0)} B  ·  "
                f"TI-SCI semantics: {semantics}  ·  Extensions: {len(extensions)}  ·  Decoded groups: {len(decoded)}"
            )
            self.tabs.setCurrentIndex(0)
        except Exception as exc:
            show_guided_error(self, exc, context="Image inceleme tamamlanamadı")
