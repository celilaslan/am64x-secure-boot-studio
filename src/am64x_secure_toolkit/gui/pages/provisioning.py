from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import QFormLayout, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit, QVBoxLayout, QWidget

from ...provision import provision_preflight, save_provision_profile, template_provision_profile
from ...services.claim_boundary import attach_claims
from ...services.workflow_visuals import provisioning_visual_model
from ..widgets import FlowDiagramWidget, HumanResultView
from .common import file_field, save_text_dialog, show_guided_error


class ProvisioningPage(QWidget):
    def __init__(self,state)->None:
        super().__init__(); self.state=state
        l=QVBoxLayout(self); t=QLabel("Provisioning Preparation — OFFLINE ONLY"); t.setObjectName("pageTitle"); l.addWidget(t)
        n=QLabel("HS-FS → HS-SE için customer key set / KEYCNT / KEYREV girdilerini yalnız host üzerinde kontrol eder. OTP/eFuse write, Keywriter firmware execution veya lifecycle transition bu GUI'de yoktur."); n.setWordWrap(True); l.addWidget(n)
        f=QFormLayout(); self.profile,box=file_field(self,"Provisioning profile YAML seç"); f.addRow("Profile",box); self.smek,box=file_field(self,"SMEK seç",secret=True); f.addRow("SMEK (optional secret)",box); self.bmek,box=file_field(self,"BMEK seç",secret=True); f.addRow("BMEK (optional secret)",box); l.addLayout(f)
        a=QHBoxLayout(); new=QPushButton("Boş Profile Şablonu Oluştur"); new.clicked.connect(self.create_template); run=QPushButton("Offline Preflight"); run.clicked.connect(self.run); a.addWidget(new); a.addWidget(run); a.addStretch(1); l.addLayout(a)
        self.diagram=FlowDiagramWidget(); l.addWidget(self.diagram)
        self.result_view=HumanResultView(); l.addWidget(self.result_view,1)
    def create_template(self):
        try:
            p=save_text_dialog(self,"Provisioning profile kaydet",lambda p: save_provision_profile(template_provision_profile(),p),".yaml")
            if p:self.profile.setText(str(p))
        except Exception as exc: Qshow_guided_error(self, exc, context="Profile oluşturulamadı")
    def run(self):
        try:
            result=provision_preflight(self.profile.text(),smek=Path(self.smek.text()) if self.smek.text().strip() else None,bmek=Path(self.bmek.text()) if self.bmek.text().strip() else None)
            result=attach_claims(result,"provision_preflight",result.get("status","PARTIAL"))
            self.state.set_last_result(result)
            self.diagram.set_model(provisioning_visual_model(result))
            self.result_view.set_result(result)
        except Exception as exc: Qshow_guided_error(self, exc, context="Provisioning preflight başarısız")
