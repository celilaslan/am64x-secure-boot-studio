from __future__ import annotations

import json

from PySide6.QtWidgets import QComboBox, QFormLayout, QLabel, QLineEdit, QPushButton, QPlainTextEdit, QSpinBox, QTabWidget, QVBoxLayout, QWidget

from ...revision import key_revision_matrix, simulate_key_revision, simulate_swrev, swrev_field_info
from ...services.claim_boundary import attach_claims
from ...services.ui_contract import SWREV_CONTEXT_OPTIONS
from ...services.workflow_visuals import key_revision_visual_model, swrev_visual_model
from ..widgets import FlowDiagramWidget, HumanResultView
from .common import parse_optional_int, show_guided_error


class RevisionPage(QWidget):
    def __init__(self,state)->None:
        super().__init__(); self.state=state; l=QVBoxLayout(self); t=QLabel("KEYREV / SWREV Simulator — No Target Write"); t.setObjectName("pageTitle"); l.addWidget(t); tabs=QTabWidget(); tabs.addTab(self._key_tab(),"KEYREV"); tabs.addTab(self._sw_tab(),"SWREV"); l.addWidget(tabs,1)
    def _key_tab(self):
        p=QWidget(); l=QVBoxLayout(p); f=QFormLayout(); self.key_count=QSpinBox(); self.key_count.setRange(0,2); f.addRow("KEYCNT",self.key_count); self.key_rev=QLineEdit(); self.key_rev.setPlaceholderText("boş / 0 / 1 / 2"); f.addRow("Current KEYREV",self.key_rev); self.target_rev=QLineEdit(); self.target_rev.setPlaceholderText("optional proposed value"); f.addRow("Proposed KEYREV",self.target_rev); l.addLayout(f); b=QPushButton("Simüle Et"); b.clicked.connect(self.run_key); m=QPushButton("Geçerli Durum Matrisi"); m.clicked.connect(self.show_matrix); l.addWidget(b); l.addWidget(m); self.key_diagram=FlowDiagramWidget(); l.addWidget(self.key_diagram)
        self.key_result=HumanResultView(); l.addWidget(self.key_result,1); return p
    def _sw_tab(self):
        p=QWidget(); l=QVBoxLayout(p); f=QFormLayout(); self.context=QComboBox()
        for label,value in SWREV_CONTEXT_OPTIONS: self.context.addItem(label,value)
        f.addRow("Context",self.context); self.reference=QSpinBox(); self.reference.setRange(0,2**31-1); f.addRow("Reference/eFuse revision",self.reference); self.cert_rev=QSpinBox(); self.cert_rev.setRange(0,2**31-1); f.addRow("Certificate revision",self.cert_rev); l.addLayout(f); b=QPushButton("SWREV Karşılaştır"); b.clicked.connect(self.run_sw); info=QPushButton("SWREV Field Bilgisi"); info.clicked.connect(self.show_info); l.addWidget(b); l.addWidget(info); self.sw_diagram=FlowDiagramWidget(); l.addWidget(self.sw_diagram)
        self.sw_result=HumanResultView(); l.addWidget(self.sw_result,1); return p
    def run_key(self):
        try:
            result=simulate_key_revision(self.key_count.value(),parse_optional_int(self.key_rev.text()),parse_optional_int(self.target_rev.text()))
            result=attach_claims(result,"revision",result.get("status","PASS"))
            self.state.set_last_result(result)
            self.key_diagram.set_model(key_revision_visual_model(result))
            self.key_result.set_result(result)
        except Exception as exc: Qshow_guided_error(self, exc, context="KEYREV simulation başarısız")
    def show_matrix(self):
        result=key_revision_matrix(); result=attach_claims(result,"revision",result.get("status","PASS")); self.state.set_last_result(result); self.key_result.set_result(result)
    def run_sw(self):
        try:
            result=simulate_swrev(str(self.context.currentData()),self.reference.value(),self.cert_rev.value())
            result=attach_claims(result,"revision",result.get("status","PASS"))
            self.state.set_last_result(result)
            self.sw_diagram.set_model(swrev_visual_model(result))
            self.sw_result.set_result(result)
        except Exception as exc: Qshow_guided_error(self, exc, context="SWREV simulation başarısız")
    def show_info(self):
        result=swrev_field_info(); result=attach_claims(result,"revision",result.get("status","PASS")); self.state.set_last_result(result); self.sw_result.set_result(result)
