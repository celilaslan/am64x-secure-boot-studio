from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QFormLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget

from ...boardcfg import evaluate_debug_policy
from ...services.claim_boundary import attach_claims
from ...services.ui_contract import JTAG_EFUSE_OPTIONS, SECURE_DEBUG_TRANSPORT_OPTIONS
from ...services.workflow_visuals import secure_debug_visual_model
from ..widgets import FlowDiagramWidget, HumanResultView
from .common import file_field, show_guided_error


class SecureDebugPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("Secure Debug Assistant — Offline Policy Evaluation")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        note = QLabel(
            "Secure Debug certificate, secure-boot certificate'ından ayrıdır. Bu ekran certificate + Security BoardCfg + user-supplied target context ilişkisini değerlendirir; "
            "JTAG unlock göndermez, debug port açmaz ve eFuse değiştirmez."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)

        form = QFormLayout()
        self.profile, box = file_field(self, "Security BoardCfg YAML seç"); form.addRow("BoardCfg profile", box)
        self.cert, box = file_field(self, "Secure Debug certificate seç"); form.addRow("Debug certificate", box)
        self.transport = QComboBox()
        for label, value in SECURE_DEBUG_TRANSPORT_OPTIONS:
            self.transport.addItem(label, value)
        self.transport.currentIndexChanged.connect(self._sync_transport)
        form.addRow("Certificate delivery context", self.transport)
        self.host = QLineEdit(); self.host.setPlaceholderText("TISCI için optional requester Host ID")
        form.addRow("Host ID", self.host)
        self.uid = QLineEdit(); self.uid.setPlaceholderText("Optional 256-bit SOC UID hex; secret değildir fakat cihaz kimliğidir")
        form.addRow("SOC UID", self.uid)
        self.jtag = QComboBox()
        for label, value in JTAG_EFUSE_OPTIONS:
            self.jtag.addItem(label, value)
        form.addRow("JTAG connectivity eFuse", self.jtag)
        layout.addLayout(form)

        run = QPushButton("Offline Debug Policy Değerlendir")
        run.setObjectName("primaryAction")
        run.clicked.connect(self.run)
        layout.addWidget(run)

        self.flow = FlowDiagramWidget(); layout.addWidget(self.flow)
        self.result = HumanResultView(show_boundary=True); layout.addWidget(self.result, 1)
        self._sync_transport()

    def _sync_transport(self) -> None:
        is_tisci = self.transport.currentData() == "tisci"
        self.host.setEnabled(is_tisci)
        self.host.setToolTip("jtag_unlock_hosts policy yalnız TISCI requester için değerlendirilir." if is_tisci else "Sec-AP context'te TISCI requester Host ID uygulanmaz.")

    def run(self) -> None:
        try:
            host = int(self.host.text(), 0) if self.host.isEnabled() and self.host.text().strip() else None
            result = evaluate_debug_policy(
                self.profile.text(),
                self.cert.text(),
                transport=str(self.transport.currentData()),
                host_id=host,
                soc_uid=self.uid.text().strip() or None,
                jtag_efuse=str(self.jtag.currentData()),
            )
            decision = str(result.get("policy_decision") or "INDETERMINATE")
            result["summary"] = {
                "POLICY_ALLOWS_REQUEST": "Verilen offline policy girdileri debug request'e izin veriyor; target acceptance ve unlock çalıştırılmadı.",
                "REJECT_BY_POLICY": "Verilen offline policy girdilerinden en az biri debug request'i reddediyor.",
                "INDETERMINATE": "Policy sonucu için SOC UID, JTAG eFuse durumu veya TISCI Host ID gibi target context eksik.",
                "INVALID_DEBUG_CERTIFICATE": "Debug certificate gerekli Secure Debug certificate yapısını sağlamıyor.",
                "INVALID_BOARDCFG_PROFILE": "Security BoardCfg profile doğrulanamadı.",
            }.get(decision, f"Offline debug policy sonucu: {decision}")
            result = attach_claims(result, "secure_debug", result.get("status", "PARTIAL"))
            self.state.set_last_result(result)
            self.flow.set_model(secure_debug_visual_model(result))
            self.result.set_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Secure Debug policy değerlendirilemedi")
