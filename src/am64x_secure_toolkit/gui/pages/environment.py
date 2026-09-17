from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...services.environment import resolve_environment
from ...services.network_policy import runtime_network_policy
from .common import show_guided_error


class EnvironmentPage(QWidget):
    """Beginner-first environment discovery page.

    The default view answers one question first: "Is this host ready for the supported
    build workflows?"  Exact paths, hashes and machine-readable discovery output stay
    available under Technical Details instead of dominating the main UI.
    """

    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 8)
        layout.setSpacing(10)

        title = QLabel("Environment Setup")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        note = QLabel(
            "Studio runtime'da internet, telemetry veya otomatik SDK indirme kullanmaz. "
            "SDK bulunamazsa inceleme, öğrenme ve mevcut artifact raporlama gibi SDK gerektirmeyen işler kullanılabilir."
        )
        note.setObjectName("mutedText")
        note.setWordWrap(True)
        layout.addWidget(note)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.sdk = QLineEdit()
        self.sdk.setAccessibleName("MCU+ SDK root")
        self.sdk.setPlaceholderText("MCU+ SDK root (boş bırakırsanız yerel adaylar otomatik aranır)")
        row.addWidget(self.sdk, 1)
        browse = QPushButton("Seç")
        browse.setAccessibleName("MCU+ SDK klasörü seç")
        browse.clicked.connect(self.choose)
        row.addWidget(browse)
        layout.addLayout(row)

        self.discovered_sdk = QLabel("")
        self.discovered_sdk.setObjectName("mutedText")
        self.discovered_sdk.setWordWrap(True)
        self.discovered_sdk.setVisible(False)
        self.discovered_sdk.setAccessibleName("Otomatik bulunan MCU+ SDK")
        layout.addWidget(self.discovered_sdk)

        check = QPushButton("Environment Kontrol Et")
        check.setObjectName("primaryAction")
        check.setAccessibleName("Environment kontrollerini çalıştır")
        check.clicked.connect(self.run_check)
        layout.addWidget(check)

        self.summary = QLabel("Henüz environment kontrol edilmedi.")
        self.summary.setWordWrap(True)
        self.summary.setAccessibleName("Environment özeti")
        self.summary.setObjectName("statusInfo")
        layout.addWidget(self.summary)

        self.tabs = QTabWidget()
        self.tabs.setAccessibleName("Environment sonuçları")
        layout.addWidget(self.tabs, 1)

        # Human-readable overview is the default tab.
        overview = QWidget()
        overview_layout = QVBoxLayout(overview)
        overview_layout.setContentsMargins(12, 12, 12, 12)
        overview_layout.setSpacing(10)

        self.empty_state = QFrame()
        self.empty_state.setObjectName("infoCard")
        empty_layout = QVBoxLayout(self.empty_state)
        empty_layout.setContentsMargins(14, 14, 14, 14)
        empty_title = QLabel("Henüz kontrol yapılmadı")
        empty_title.setObjectName("sectionTitle")
        empty_layout.addWidget(empty_title)
        empty_body = QLabel(
            "SDK yolunu seçebilir veya alanı boş bırakıp yerel SDK adaylarının otomatik aranmasını sağlayabilirsiniz."
        )
        empty_body.setWordWrap(True)
        empty_body.setObjectName("mutedText")
        empty_layout.addWidget(empty_body)
        overview_layout.addWidget(self.empty_state)

        self.cards = QGridLayout()
        self.cards.setHorizontalSpacing(10)
        self.cards.setVerticalSpacing(10)
        self.card_widgets: dict[str, tuple[QFrame, QLabel, QLabel, QLabel]] = {}
        specs = [
            ("sdk", "MCU+ SDK"),
            ("python", "Python"),
            ("openssl", "OpenSSL"),
            ("app_signer", "Application signer"),
            ("rom_signer", "ROM signer"),
            ("devconfig", "devconfig.mak"),
        ]
        for index, (key, label) in enumerate(specs):
            card = self._result_card(label)
            self.card_widgets[key] = card
            self.cards.addWidget(card[0], index // 3, index % 3)
            card[0].setVisible(False)
        for col in range(3):
            self.cards.setColumnStretch(col, 1)
        overview_layout.addLayout(self.cards)

        self.readiness_note = QFrame()
        self.readiness_note.setObjectName("safetyNote")
        rn_layout = QVBoxLayout(self.readiness_note)
        rn_layout.setContentsMargins(12, 9, 12, 9)
        self.readiness_text = QLabel("")
        self.readiness_text.setWordWrap(True)
        self.readiness_text.setObjectName("safetyText")
        rn_layout.addWidget(self.readiness_text)
        self.readiness_note.setVisible(False)
        overview_layout.addWidget(self.readiness_note)
        overview_layout.addStretch(1)
        self.tabs.addTab(overview, "Özet")

        # Full machine-readable output remains available for advanced inspection.
        technical = QWidget()
        technical_layout = QVBoxLayout(technical)
        technical_layout.setContentsMargins(8, 8, 8, 8)
        technical_note = QLabel(
            "Path, SHA-256 ve discovery metadata'sı burada gösterilir. <HOME> dışındaki path'ler yalnız gerekli olduğunda görünür."
        )
        technical_note.setWordWrap(True)
        technical_note.setObjectName("mutedText")
        technical_layout.addWidget(technical_note)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setAccessibleName("Environment teknik ayrıntıları")
        self.output.setPlaceholderText("Environment kontrolü çalıştırıldığında teknik ayrıntılar burada görünecek.")
        technical_layout.addWidget(self.output, 1)
        self.tabs.addTab(technical, "Teknik Ayrıntılar")
        self.tabs.setCurrentIndex(0)

        if self.state.environment and self.state.environment.sdk_root:
            env = self.state.environment
            self.sdk.setText(str(env.sdk_root))
            self.discovered_sdk.setText(f"Otomatik/hatırlanan SDK: {env.sdk_root}")
            self.discovered_sdk.setVisible(True)
            self.summary.setText(
                f"SDK otomatik bulundu: {env.sdk_version or env.sdk_root.name}. "
                "Yolu yeniden seçmeniz gerekmez; isterseniz kontrolleri yenileyebilirsiniz."
            )
            self.summary.setObjectName("statusPass" if env.ready else "statusWarn")

    def _result_card(self, title: str) -> tuple[QFrame, QLabel, QLabel, QLabel]:
        frame = QFrame()
        frame.setObjectName("statusCard")
        box = QVBoxLayout(frame)
        box.setContentsMargins(12, 10, 12, 10)
        box.setSpacing(4)

        heading = QLabel(title)
        heading.setObjectName("statusCardTitle")
        box.addWidget(heading)

        value = QLabel("—")
        value.setWordWrap(True)
        value.setObjectName("sectionTitle")
        box.addWidget(value)

        detail = QLabel("")
        detail.setWordWrap(True)
        detail.setObjectName("mutedText")
        box.addWidget(detail)

        status = QLabel("Bekliyor")
        status.setObjectName("statusInfo")
        status.setMaximumWidth(140)
        box.addWidget(status)
        return frame, value, detail, status

    @staticmethod
    def _filename(value: str | None, fallback: str) -> str:
        if not value:
            return fallback
        return Path(value).name or fallback

    @staticmethod
    def _openssl_short(version: str | None) -> str:
        if not version:
            return "Bulunamadı"
        parts = version.split()
        if len(parts) >= 2 and parts[0].lower() == "openssl":
            return parts[1]
        return version

    def _set_card(self, key: str, *, value: str, detail: str, status: str) -> None:
        frame, value_label, detail_label, status_label = self.card_widgets[key]
        frame.setVisible(True)
        value_label.setText(value)
        detail_label.setText(detail)
        object_name = {
            "PASS": "statusPass",
            "PARTIAL": "statusWarn",
            "WARN": "statusWarn",
            "FAIL": "statusFail",
        }.get(status, "statusInfo")
        status_label.setObjectName(object_name)
        status_label.setText({"PASS": "✓ Hazır", "PARTIAL": "◐ İnceleme gerekli", "WARN": "! Uyarı", "FAIL": "✕ Bulunamadı"}.get(status, status))
        status_label.style().unpolish(status_label)
        status_label.style().polish(status_label)

    def choose(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "MCU+ SDK root seç")
        if path:
            self.sdk.setText(path)

    def run_check(self) -> None:
        try:
            env = resolve_environment(self.sdk.text().strip() or None)
            self.state.set_environment(env)
            data = env.to_dict()
            data["network_policy"] = runtime_network_policy().to_dict()
            self.state.set_last_result(data)

            self.empty_state.setVisible(False)
            if data.get("sdk_root"):
                self.discovered_sdk.setText(f"Otomatik/aktif SDK: {data['sdk_root']}")
                self.discovered_sdk.setVisible(True)
            else:
                self.discovered_sdk.setVisible(False)

            if env.ready and env.compatibility == "VALIDATED_BASELINE":
                self.summary.setObjectName("statusPass")
                text = (
                    "Environment hazır — MCU+ SDK, signing araçları ve OpenSSL bulundu. "
                    "SDK sürümü doğrulanan 12.00.00.27 baseline'ı ile eşleşiyor."
                )
                readiness = "Build environment hazır. Host-side build workflow'larına geçebilirsiniz."
            elif env.ready:
                self.summary.setObjectName("statusWarn")
                text = (
                    f"Environment kısmen hazır — gerekli araçlar bulundu ancak SDK compatibility={env.compatibility}. "
                    "Security-relevant source farkları doğrulanmadan validated baseline ile eşdeğer kabul etmeyin."
                )
                readiness = "Build araçları bulundu; SDK sürüm/source farklarını incelemeden security equivalence claim yapmayın."
            else:
                self.summary.setObjectName("statusFail")
                text = (
                    "SDK build workflow'ları hazır değil — Studio internetten SDK indirmez. "
                    "SDK gerektirmeyen Image Inspector, Learn, Demo ve mevcut artifact raporlama özellikleri kullanılabilir."
                )
                readiness = "Build workflow'ları için eksik bileşenleri giderin; SDK gerektirmeyen araçlar kullanılabilir."
            self.summary.setText(text)
            self.summary.style().unpolish(self.summary)
            self.summary.style().polish(self.summary)

            sdk_status = "PASS" if env.sdk_root and env.compatibility == "VALIDATED_BASELINE" else ("PARTIAL" if env.sdk_root else "FAIL")
            sdk_detail = (
                "Validated 12.00.00.27 baseline ile eşleşiyor."
                if env.compatibility == "VALIDATED_BASELINE"
                else f"Compatibility: {env.compatibility}"
            )
            self._set_card("sdk", value=env.sdk_version or "Sürüm bilinmiyor", detail=sdk_detail, status=sdk_status)
            self._set_card("python", value=data.get("checks", [])[-1].get("detail", "Hazır") if data.get("checks") else "Hazır", detail="Studio'nun aktif Python runtime'ı.", status="PASS")
            self._set_card("openssl", value=self._openssl_short(env.openssl_version), detail="Signing ve encryption tooling dependency.", status="PASS" if env.openssl_path else "FAIL")
            self._set_card("app_signer", value="appimage_x509_cert_gen.py", detail="Application secure-image signer bulundu.", status="PASS" if env.app_signing_tool else "FAIL")
            self._set_card("rom_signer", value="rom_image_gen.py", detail="ROM/SBL combined-image signer bulundu.", status="PASS" if env.rom_signing_tool else "FAIL")
            self._set_card("devconfig", value="devconfig.mak", detail="SDK security configuration girdisi bulundu." if env.devconfig else "Dosya bulunamadı; build configuration kontrolü gerekli.", status="PASS" if env.devconfig else "WARN")

            self.readiness_text.setText(readiness)
            self.readiness_note.setVisible(True)
            self.output.setPlainText(json.dumps(data, indent=2, ensure_ascii=False))
            self.tabs.setCurrentIndex(0)
        except Exception as exc:
            show_guided_error(self, exc, context="Environment kontrolü tamamlanamadı")
