from __future__ import annotations

from PySide6.QtWidgets import QFormLayout, QLabel, QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget

from ...boardcfg import check_boardcfg_profile, evaluate_revision_writer, save_boardcfg_profile, template_boardcfg_profile
from ...services.claim_boundary import attach_claims
from ...services.workflow_visuals import boardcfg_policy_visual_model, writer_authorization_visual_model
from ..widgets import FlowDiagramWidget, HumanResultView
from .common import file_field, save_text_dialog, show_guided_error


class BoardCfgPage(QWidget):
    def __init__(self,state)->None:
        super().__init__(); self.state=state; l=QVBoxLayout(self); t=QLabel("Security BoardCfg — Offline Policy Inspector"); t.setObjectName("pageTitle"); l.addWidget(t)
        n=QLabel("Security Board Configuration target'a gönderilmez. Bu ekran profile/policy alanlarını ve authorization ilişkilerini host üzerinde değerlendirir."); n.setWordWrap(True); l.addWidget(n)
        tabs=QTabWidget(); tabs.addTab(self._check_tab(),"Profile Check"); tabs.addTab(self._writer_tab(),"Revision Writer"); l.addWidget(tabs,1)
    def _check_tab(self):
        p=QWidget(); l=QVBoxLayout(p); f=QFormLayout(); self.profile,box=file_field(p,"Security BoardCfg YAML seç"); f.addRow("BoardCfg profile",box); l.addLayout(f); new=QPushButton("Profile Şablonu Oluştur"); new.clicked.connect(self.create_template); run=QPushButton("Policy Kontrol Et"); run.clicked.connect(self.run_check); l.addWidget(new); l.addWidget(run); self.policy_diagram=FlowDiagramWidget(); l.addWidget(self.policy_diagram)
        self.policy_result=HumanResultView(); l.addWidget(self.policy_result,1); return p
    def _writer_tab(self):
        p=QWidget(); l=QVBoxLayout(p); f=QFormLayout(); self.writer_profile,box=file_field(p,"Security BoardCfg YAML seç"); f.addRow("BoardCfg profile",box); self.host=QSpinBox(); self.host.setRange(0,255); f.addRow("Requester Host ID",self.host); l.addLayout(f); run=QPushButton("SWREV/KEYREV Writer Authorization Değerlendir"); run.clicked.connect(self.run_writer); l.addWidget(run); self.writer_diagram=FlowDiagramWidget(); l.addWidget(self.writer_diagram)
        self.writer_result=HumanResultView(); l.addWidget(self.writer_result,1); return p
    def create_template(self):
        try:
            path=save_text_dialog(self,"Security BoardCfg profile kaydet",lambda p: save_boardcfg_profile(template_boardcfg_profile(),p),".yaml")
            if path:self.profile.setText(str(path))
        except Exception as exc: show_guided_error(self, exc, context="Profile oluşturulamadı")
    def run_check(self):
        try:
            result=check_boardcfg_profile(self.profile.text())
            result=attach_claims(result,"boardcfg",result.get("status","PARTIAL"))
            self.state.set_last_result(result)
            self.policy_diagram.set_model(boardcfg_policy_visual_model(result))
            self.policy_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="BoardCfg check başarısız")
    def run_writer(self):
        try:
            result=evaluate_revision_writer(self.writer_profile.text(),self.host.value())
            result=attach_claims(result,"boardcfg",result.get("status","PASS"))
            self.state.set_last_result(result)
            self.writer_diagram.set_model(writer_authorization_visual_model(result))
            self.writer_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="Writer policy başarısız")
