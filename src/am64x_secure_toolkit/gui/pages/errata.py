from __future__ import annotations

import json

from PySide6.QtWidgets import QComboBox, QFormLayout, QLabel, QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget

from ...errata import check_errata, list_errata
from ...services.claim_boundary import attach_claims
from ...services.ui_contract import (
    BOOT_MODE_OPTIONS,
    ERRATA_CATEGORY_OPTIONS,
    ERRATA_CERT_INFO_OPTIONS,
    ERRATA_EMULATOR_OPTIONS,
    ERRATA_FLOW_OPTIONS,
    ERRATA_OUTER_RSA_OPTIONS,
    ERRATA_REDUNDANT_OPTIONS,
)
from .common import show_guided_error


def _combo(options):
    c=QComboBox()
    for label,value in options:c.addItem(label,value)
    return c


class ErrataPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self); title = QLabel("Errata Advisor — AM64x/AM243x Rev. J"); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel("Silicon revision, lifecycle ve boot-flow bağlamına göre yalnız documented advisory değerlendirmesi yapar. Target davranışı çalıştırılmaz veya tahmin edilmez."); note.setWordWrap(True); layout.addWidget(note)
        tabs = QTabWidget(); tabs.addTab(self._list_tab(), "Advisory List"); tabs.addTab(self._check_tab(), "Context Check"); layout.addWidget(tabs, 1)

    def _revision(self):
        c = QComboBox(); c.addItems(["SR1.0", "SR2.0"]); c.setCurrentText(self.state.silicon_revision); return c

    def _list_tab(self):
        p=QWidget(); l=QVBoxLayout(p); f=QFormLayout(); self.list_rev=self._revision(); f.addRow("Silicon revision",self.list_rev); self.category=_combo(ERRATA_CATEGORY_OPTIONS); f.addRow("Category",self.category); self.boot_mode=_combo(BOOT_MODE_OPTIONS); f.addRow("Boot mode",self.boot_mode); l.addLayout(f); b=QPushButton("İlgili Errata'yı Listele"); b.clicked.connect(self.run_list); l.addWidget(b); self.list_out=QPlainTextEdit(); self.list_out.setReadOnly(True); l.addWidget(self.list_out,1); return p

    def _check_tab(self):
        p=QWidget(); l=QVBoxLayout(p); f=QFormLayout(); self.check_rev=self._revision(); f.addRow("Silicon revision",self.check_rev)
        self.device_state=QComboBox(); self.device_state.addItem("HS-FS","hs-fs"); self.device_state.addItem("HS-SE","hs-se"); self.device_state.addItem("GP","gp"); self.device_state.addItem("Bilinmiyor","unknown")
        wanted={"HS-FS":"hs-fs","HS-SE":"hs-se","GP":"gp"}.get(self.state.lifecycle,"unknown"); idx=self.device_state.findData(wanted); self.device_state.setCurrentIndex(max(0,idx)); f.addRow("Device state",self.device_state)
        self.flow=_combo(ERRATA_FLOW_OPTIONS); f.addRow("Flow",self.flow); self.primary=_combo(BOOT_MODE_OPTIONS); f.addRow("Primary boot",self.primary); self.backup=_combo(BOOT_MODE_OPTIONS); f.addRow("Backup boot",self.backup); self.outer_rsa=_combo(ERRATA_OUTER_RSA_OPTIONS); f.addRow("Outer RSA",self.outer_rsa); self.cert_info=_combo(ERRATA_CERT_INFO_OPTIONS); f.addRow("Certificate info",self.cert_info); self.redundant=_combo(ERRATA_REDUNDANT_OPTIONS); f.addRow("Redundant image content",self.redundant); self.emulator=_combo(ERRATA_EMULATOR_OPTIONS); f.addRow("External emulator",self.emulator)
        l.addLayout(f); b=QPushButton("Offline Errata Context Check"); b.clicked.connect(self.run_check); l.addWidget(b); self.check_out=QPlainTextEdit(); self.check_out.setReadOnly(True); l.addWidget(self.check_out,1); return p

    def run_list(self):
        try:
            result=list_errata(revision=self.list_rev.currentText(),category=str(self.category.currentData()),boot_mode=str(self.boot_mode.currentData())); result=attach_claims(result,"errata",result.get("status","PASS")); self.state.set_last_result(result); self.list_out.setPlainText(json.dumps(result,indent=2,ensure_ascii=False))
        except Exception as exc: show_guided_error(self, exc, context="Errata list başarısız")

    def run_check(self):
        try:
            result=check_errata(revision=self.check_rev.currentText(),device_state=str(self.device_state.currentData()),flow=str(self.flow.currentData()),primary_boot=str(self.primary.currentData()),backup_boot=str(self.backup.currentData()),outer_rsa=str(self.outer_rsa.currentData()),certificate_info=str(self.cert_info.currentData()),redundant_content=str(self.redundant.currentData()),external_emulator=str(self.emulator.currentData())); result=attach_claims(result,"errata",result.get("status","PARTIAL")); self.state.set_last_result(result); self.check_out.setPlainText(json.dumps(result,indent=2,ensure_ascii=False))
        except Exception as exc: show_guided_error(self, exc, context="Errata check başarısız")
