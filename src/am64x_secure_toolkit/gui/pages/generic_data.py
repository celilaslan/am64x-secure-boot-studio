from __future__ import annotations

from PySide6.QtWidgets import QFormLayout, QHBoxLayout, QLabel, QPushButton, QTabWidget, QVBoxLayout, QWidget

from ...generic_data import (
    build_generic_data,
    save_generic_data_profile,
    template_generic_data_profile,
    validate_generic_data_profile,
    verify_generic_data,
)
from ...services.claim_boundary import attach_claims
from ...services.workflow_visuals import generic_data_visual_model
from ..widgets import FlowDiagramWidget, HumanResultView
from .common import file_field, save_text_dialog, show_guided_error


class GenericDataPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("Generic Data Assistant — TISCI Generalized Authentication")
        title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel(
            "Generic binary için signed veya encrypted+signed package üretir. Processor Boot Extension eklemez. "
            "TISCI_MSG_PROC_AUTH_BOOT target çağrısı ve hardware acceptance bu Studio tarafından çalıştırılmaz."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)
        tabs = QTabWidget(); tabs.addTab(self._build_tab(), "Profile / Build"); tabs.addTab(self._verify_tab(), "Verify"); layout.addWidget(tabs, 1)

    def _build_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.profile, box = file_field(page, "Generic data YAML seç"); form.addRow("Profile", box)
        self.key, box = file_field(page, "RSA-4096 signing private key seç", secret=True); form.addRow("Signing key", box)
        self.mek, box = file_field(page, "MEK seç", secret=True); form.addRow("MEK (encryption enabled ise)", box)
        self.output, box = file_field(page, "Generic data output", save=True); form.addRow("Package output", box)
        self.cert_output, box = file_field(page, "Certificate output", save=True); form.addRow("Certificate output (optional)", box)
        layout.addLayout(form)
        actions = QHBoxLayout()
        new = QPushButton("Profile Şablonu"); new.clicked.connect(self.create_template)
        val = QPushButton("Profile Doğrula"); val.clicked.connect(self.validate)
        build = QPushButton("Build + Host Verify"); build.setObjectName("primaryAction"); build.clicked.connect(self.build)
        actions.addWidget(new); actions.addWidget(val); actions.addWidget(build); actions.addStretch(1); layout.addLayout(actions)
        self.build_flow = FlowDiagramWidget(); layout.addWidget(self.build_flow)
        self.build_result = HumanResultView(show_boundary=True); layout.addWidget(self.build_result, 1)
        return page

    def _verify_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.package, box = file_field(page, "Generic secure package seç"); form.addRow("Package", box)
        self.verify_mek, box = file_field(page, "MEK seç", secret=True); form.addRow("MEK (optional)", box)
        self.original, box = file_field(page, "Original data seç"); form.addRow("Original data (optional)", box)
        layout.addLayout(form)
        run = QPushButton("Host-side Verify"); run.setObjectName("primaryAction"); run.clicked.connect(self.verify); layout.addWidget(run)
        self.verify_flow = FlowDiagramWidget(); layout.addWidget(self.verify_flow)
        self.verify_result = HumanResultView(show_boundary=True); layout.addWidget(self.verify_result, 1)
        return page

    def create_template(self) -> None:
        try:
            path = save_text_dialog(self, "Generic data profile kaydet", lambda p: save_generic_data_profile(template_generic_data_profile(), p), ".yaml")
            if path: self.profile.setText(str(path))
        except Exception as exc:
            show_guided_error(self, exc, context="Profile oluşturulamadı")

    def validate(self) -> None:
        try:
            result = validate_generic_data_profile(self.profile.text())
            issues = [str(x) for x in result.get("issues", [])]
            warnings = [str(x) for x in result.get("warnings", [])]
            checks = [{
                "check": "generic_data_profile_schema",
                "status": "PASS" if not issues else "FAIL",
                "detail": "Profile gerekli generalized-authentication alanlarını içeriyor." if not issues else "; ".join(issues),
            }]
            if warnings:
                checks.append({"check": "generic_data_profile_source_warnings", "status": "PARTIAL", "detail": " | ".join(warnings)})
            result["operation"] = "generic_data_profile"
            result["summary"] = "Generic data profile doğrulandı." if not issues else "Generic data profile düzeltme gerektiriyor."
            result["checks"] = checks
            result = attach_claims(result, "generic_data", result.get("status", "PARTIAL"))
            self.state.set_last_result(result)
            self.build_flow.set_model(generic_data_visual_model(result))
            self.build_result.set_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Profile validation başarısız")

    def build(self) -> None:
        try:
            result = build_generic_data(
                self.profile.text(), self.key.text(), self.output.text(),
                certificate_output=self.cert_output.text().strip() or None,
                mek=self.mek.text().strip() or None,
            )
            result = attach_claims(result, "generic_data_build", result.get("status", "PARTIAL"), encrypted=result.get("mode") == "encrypted+signed")
            self.state.set_last_result(result)
            self.build_flow.set_model(generic_data_visual_model(result))
            self.build_result.set_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Generic data build başarısız")

    def verify(self) -> None:
        try:
            result = verify_generic_data(
                self.package.text(),
                mek=self.verify_mek.text().strip() or None,
                original=self.original.text().strip() or None,
            )
            result = attach_claims(result, "generic_data", result.get("status", "PARTIAL"), encrypted=result.get("mode") == "encrypted+signed")
            self.state.set_last_result(result)
            self.verify_flow.set_model(generic_data_visual_model(result))
            self.verify_result.set_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Generic data verify başarısız")
