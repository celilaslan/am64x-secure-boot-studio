from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QComboBox, QFormLayout, QHBoxLayout, QLabel, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget

from ...negative import create_negative_variant, run_negative_suite
from ...services.claim_boundary import attach_claims
from ...services.project import suggest_project_output
from ..widgets import HumanResultView, ResultBoundaryPanel
from .common import file_field, show_guided_error


class NegativePage(QWidget):
    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("Negatif Testler — kontrollü kopya"); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel(
            "Original dosya değiştirilmez. Mutasyon yalnız ayrı test kopyasında uygulanır; beklenen failure davranışı host-side doğrulamayla kontrol edilir."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)
        tabs = QTabWidget(); tabs.addTab(self._single_tab(), "Tek Kontrollü Değişiklik"); tabs.addTab(self._suite_tab(), "Otomatik Test Suite"); layout.addWidget(tabs, 2)
        self.boundary = ResultBoundaryPanel(); layout.addWidget(self.boundary, 1)
        state.changed.connect(self.refresh_project_hints)
        self.source.textChanged.connect(lambda _=None: self.refresh_project_hints())
        self.suite_source.textChanged.connect(lambda _=None: self.refresh_project_hints())
        self.kind.currentTextChanged.connect(lambda _=None: self.refresh_project_hints())
        self.refresh_project_hints()

    def _single_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.source, box = file_field(page, "Kaynak image seç"); form.addRow("Kaynak image", box)
        self.kind = QComboBox(); self.kind.addItems(["signature", "tbs", "payload", "ciphertext", "component"]); self.kind.currentTextChanged.connect(self._kind_changed); form.addRow("Controlled change", self.kind)
        self.component = QSpinBox(); self.component.setRange(1, 64); form.addRow("ROM component index", self.component)
        self.output, box = file_field(page, "Test kopyası", save=True); form.addRow("Test kopyası", box)
        layout.addLayout(form)
        single_project = QHBoxLayout()
        self.single_project_hint = QLabel("Project aktif değil — test kopyası manuel seçilir."); self.single_project_hint.setWordWrap(True); self.single_project_hint.setObjectName("mutedText")
        self.single_project_button = QPushButton("Project Negative-Test Yolu Kullan"); self.single_project_button.clicked.connect(self.use_project_single)
        single_project.addWidget(self.single_project_hint, 1); single_project.addWidget(self.single_project_button); layout.addLayout(single_project)
        run = QPushButton("Test Kopyası Oluştur ve Doğrula"); run.setObjectName("primaryAction"); run.clicked.connect(self.run_single); layout.addWidget(run)
        self.result = HumanResultView(show_boundary=False); layout.addWidget(self.result, 1)
        self._kind_changed(self.kind.currentText())
        return page

    def _suite_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.suite_source, box = file_field(page, "Kaynak image seç"); form.addRow("Kaynak image", box)
        self.suite_dir, box = file_field(page, "Boş output dizini seç", directory=True); form.addRow("Output dizini", box)
        layout.addLayout(form)
        suite_project = QHBoxLayout()
        self.suite_project_hint = QLabel("Project aktif değil — suite dizini manuel seçilir."); self.suite_project_hint.setWordWrap(True); self.suite_project_hint.setObjectName("mutedText")
        self.suite_project_button = QPushButton("Project Negative-Test Dizini Kullan"); self.suite_project_button.clicked.connect(self.use_project_suite)
        suite_project.addWidget(self.suite_project_hint, 1); suite_project.addWidget(self.suite_project_button); layout.addLayout(suite_project)
        run = QPushButton("Image Türüne Uygun Negative Suite Çalıştır"); run.setObjectName("primaryAction"); run.clicked.connect(self.run_suite); layout.addWidget(run)
        self.suite_result = HumanResultView(show_boundary=False); layout.addWidget(self.suite_result, 1)
        return page

    def _project_negative_base(self, source: str) -> Path | None:
        if self.state.project is None:
            return None
        return suggest_project_output(self.state.project, workflow="negative", source=source or None)

    def refresh_project_hints(self) -> None:
        project = self.state.project
        if not hasattr(self, "single_project_hint"):
            return
        enabled = project is not None
        self.single_project_button.setEnabled(enabled); self.suite_project_button.setEnabled(enabled)
        if not enabled:
            self.single_project_hint.setText("Project aktif değil — test kopyası manuel seçilir.")
            self.suite_project_hint.setText("Project aktif değil — suite dizini manuel seçilir.")
            return
        single_base = self._project_negative_base(self.source.text().strip())
        suite_base = self._project_negative_base(self.suite_source.text().strip())
        kind = self.kind.currentText()
        single_name = f"{single_base.name}_{kind}.bin" if single_base else "negative.bin"
        self.single_project_hint.setText(f"Project önerisi: negative-tests/{single_name}")
        self.suite_project_hint.setText(f"Project önerisi: negative-tests/{suite_base.name if suite_base else 'negative-suite'}")

    def use_project_single(self) -> None:
        base = self._project_negative_base(self.source.text().strip())
        if base is None:
            return
        self.output.setText(str(base.parent / f"{base.name}_{self.kind.currentText()}.bin"))

    def use_project_suite(self) -> None:
        base = self._project_negative_base(self.suite_source.text().strip())
        if base is not None:
            self.suite_dir.setText(str(base))

    def _kind_changed(self, kind: str) -> None:
        self.component.setEnabled(kind == "component")

    def _single_model(self, data: dict) -> dict:
        status = data.get("negative_test_result") or "PARTIAL"
        result = {
            **data,
            "operation": "negative_test",
            "status": status,
            "summary": data.get("reason") or "Kontrollü negatif test tamamlandı.",
            "checks": [
                {"check": "source_image_unchanged", "status": "PASS" if data.get("source_unchanged") else "FAIL", "detail": "Original source korunur"},
                {"check": f"expected_{data.get('test', 'mutation')}_failure_detected", "status": status, "detail": data.get("reason")},
            ],
            "outputs": [{"type": "negative_test_copy", "path": data.get("output")}],
        }
        return attach_claims(result, "negative_test", status)

    def _suite_model(self, data: dict) -> dict:
        status = data.get("suite_result") or "PARTIAL"
        checks = [{"check": "source_image_unchanged", "status": "PASS" if data.get("source_unchanged") else "FAIL", "detail": "Tüm case'lerde original source korunur"}]
        for case in data.get("cases", []):
            checks.append({
                "check": f"negative_{case.get('test', 'case')}",
                "status": case.get("negative_test_result") or "PARTIAL",
                "detail": case.get("reason") or "—",
            })
        result = {
            **data,
            "operation": "negative_test",
            "status": status,
            "summary": f"{len(data.get('cases', []))} kontrollü negative case çalıştırıldı.",
            "checks": checks,
            "outputs": [{"type": "negative_test_report", "path": data.get("report")}],
        }
        return attach_claims(result, "negative_test", status)

    def _publish(self, result: dict, widget: HumanResultView) -> None:
        self.state.set_last_result(result)
        widget.set_result(result)
        self.boundary.set_result(result)

    def run_single(self):
        try:
            kind = self.kind.currentText()
            kwargs = {"component_index": self.component.value()} if kind == "component" else {}
            data = create_negative_variant(self.source.text(), kind, self.output.text(), **kwargs)
            self._publish(self._single_model(data), self.result)
        except Exception as exc:
            show_guided_error(self, exc, context="Negatif test tamamlanamadı")

    def run_suite(self):
        try:
            data = run_negative_suite(self.suite_source.text(), self.suite_dir.text())
            self._publish(self._suite_model(data), self.suite_result)
        except Exception as exc:
            show_guided_error(self, exc, context="Negatif test suite tamamlanamadı")
