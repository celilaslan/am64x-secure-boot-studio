from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QTabWidget, QVBoxLayout, QWidget

from ...sdk_diff import compare_sdk_security
from ...sdk_lint import lint_sdk_security
from ...services.claim_boundary import attach_claims
from ...services.environment import resolve_environment
from ...services.ui_contract import SDK_INTENT_OPTIONS
from ...services.workflow_visuals import sdk_consumer_chain_model
from ..widgets import FlowDiagramWidget, HumanResultView, SdkDiffResultView
from .common import file_field, show_guided_error


def _source_field(parent, title: str):
    return file_field(parent, title)


class SdkPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self); title = QLabel("SDK Inspector / Upgrade Compare"); title.setObjectName("pageTitle"); layout.addWidget(title)
        tabs = QTabWidget(); tabs.addTab(self._lint_tab(), "Inspector"); tabs.addTab(self._diff_tab(), "SDK Compare"); layout.addWidget(tabs, 1)

    def _lint_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.sdk_root, box = file_field(page, "SDK root seç", directory=True); form.addRow("SDK root", box)
        self.app_make, box = file_field(page, "Application Makefile seç"); form.addRow("Application Makefile", box)
        self.sbl_make, box = file_field(page, "SBL Makefile seç"); form.addRow("SBL Makefile", box)
        self.intent = QComboBox();
        for label, value in SDK_INTENT_OPTIONS: self.intent.addItem(label, value)
        form.addRow("Intent", self.intent); layout.addLayout(form)
        note = QLabel("devconfig.mak ve signing tool'lar SDK root'tan çözümlenir. Makefile girdileri verilirse ENC_ENABLED / ENC_SBL_ENABLED consumer chain'i de kontrol edilir."); note.setWordWrap(True); layout.addWidget(note)
        run = QPushButton("Read-only SDK Security Inspector Çalıştır"); run.clicked.connect(self.run_lint); layout.addWidget(run)
        self.chain = FlowDiagramWidget(); layout.addWidget(self.chain)
        self.lint_result = HumanResultView(); layout.addWidget(self.lint_result, 1); return page

    def _diff_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.old_dev, box = _source_field(page, "Old devconfig.mak"); form.addRow("Old devconfig", box)
        self.new_dev, box = _source_field(page, "New devconfig.mak"); form.addRow("New devconfig", box)
        self.old_app_tool, box = _source_field(page, "Old app signer"); form.addRow("Old app signer", box)
        self.new_app_tool, box = _source_field(page, "New app signer"); form.addRow("New app signer", box)
        self.old_rom_tool, box = _source_field(page, "Old ROM signer"); form.addRow("Old ROM signer", box)
        self.new_rom_tool, box = _source_field(page, "New ROM signer"); form.addRow("New ROM signer", box)
        self.old_app_make, box = _source_field(page, "Old application Makefile"); form.addRow("Old app Makefile", box)
        self.new_app_make, box = _source_field(page, "New application Makefile"); form.addRow("New app Makefile", box)
        self.old_sbl_make, box = _source_field(page, "Old SBL Makefile"); form.addRow("Old SBL Makefile", box)
        self.new_sbl_make, box = _source_field(page, "New SBL Makefile"); form.addRow("New SBL Makefile", box)
        layout.addLayout(form); run = QPushButton("Security-Relevant Semantic Diff"); run.setObjectName("primaryAction"); run.clicked.connect(self.run_diff); layout.addWidget(run)
        note = QLabel("Karşılaştırma source text'i değil, mapped security semantics'i yan yana gösterir. Secret literal/path görünmez; mapped olmayan content değişikliği de otomatik olarak güvenli sayılmaz."); note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)
        self.diff_view = SdkDiffResultView(); layout.addWidget(self.diff_view, 1); return page

    def run_lint(self) -> None:
        try:
            env = self.state.environment or resolve_environment(self.sdk_root.text().strip() or None)
            if self.sdk_root.text().strip(): env = resolve_environment(self.sdk_root.text().strip())
            self.state.set_environment(env)
            result = lint_sdk_security(
                devconfig=env.devconfig,
                app_makefile=Path(self.app_make.text()) if self.app_make.text().strip() else None,
                sbl_makefile=Path(self.sbl_make.text()) if self.sbl_make.text().strip() else None,
                app_tool=env.app_signing_tool,
                rom_tool=env.rom_signing_tool,
                intent=str(self.intent.currentData()),
            )
            result = attach_claims(result, "sdk_lint", result.get("status", "PARTIAL"))
            self.state.set_last_result(result)
            self.chain.set_model(sdk_consumer_chain_model(result))
            self.lint_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="SDK Inspector başarısız")

    def run_diff(self) -> None:
        try:
            kw = {}
            mapping = {
                "old_devconfig": self.old_dev, "new_devconfig": self.new_dev,
                "old_app_tool": self.old_app_tool, "new_app_tool": self.new_app_tool,
                "old_rom_tool": self.old_rom_tool, "new_rom_tool": self.new_rom_tool,
                "old_app_makefile": self.old_app_make, "new_app_makefile": self.new_app_make,
                "old_sbl_makefile": self.old_sbl_make, "new_sbl_makefile": self.new_sbl_make,
            }
            for name, edit in mapping.items():
                if edit.text().strip(): kw[name] = Path(edit.text())
            if not kw: raise ValueError("Karşılaştırmak için en az bir old/new source pair girin")
            result = compare_sdk_security(**kw)
            result["summary_text"] = "SDK security-relevant semantic comparison tamamlandı; mapped değişiklikler source review gereksinimine göre sınıflandırıldı."
            result = attach_claims(result, "sdk_diff", result.get("status", "PARTIAL")); self.state.set_last_result(result); self.diff_view.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="SDK Compare başarısız")
