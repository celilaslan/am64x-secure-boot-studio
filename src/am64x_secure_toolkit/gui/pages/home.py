from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from ...services.onboarding import onboarding_model
from ...services.presentation import result_presentation


class HomePage(QWidget):
    """Beginner-first dashboard.

    Home intentionally exposes only the six primary tasks. Advanced tools remain available
    from the left navigation in Expert Mode instead of turning the dashboard into a command
    catalogue.
    """

    navigate = Signal(str)

    def __init__(self, state) -> None:
        super().__init__()
        self.state = state

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 8)
        layout.setSpacing(12)

        title = QLabel("AM64x Secure Boot Studio")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        self.subtitle = QLabel()
        self.subtitle.setWordWrap(True)
        self.subtitle.setObjectName("mutedText")
        layout.addWidget(self.subtitle)

        # Status comes first: the user can see whether the host is ready before choosing a task.
        status_row = QHBoxLayout()
        status_row.setSpacing(10)
        self.env_card = self._status_card("Environment", "Henüz kontrol edilmedi")
        self.project_card = self._status_card("Project", "Workspace seçilmedi")
        self.last_card = self._status_card("Son İşlem", "Henüz işlem yok")
        status_row.addWidget(self.env_card[0], 1)
        status_row.addWidget(self.project_card[0], 1)
        status_row.addWidget(self.last_card[0], 1)
        layout.addLayout(status_row)

        # Compact quick-start card. The primary action is deliberately not a full-width banner.
        self.quick_start = QFrame()
        self.quick_start.setObjectName("infoCard")
        quick_layout = QVBoxLayout(self.quick_start)
        quick_layout.setContentsMargins(12, 10, 12, 10)
        quick_layout.setSpacing(5)
        quick_title = QLabel("Hızlı Başlangıç")
        quick_title.setObjectName("sectionTitle")
        quick_layout.addWidget(quick_title)
        self.quick_summary = QLabel()
        self.quick_summary.setWordWrap(True)
        self.quick_summary.setObjectName("cardText")
        quick_layout.addWidget(self.quick_summary)
        self.quick_steps = QLabel()
        self.quick_steps.setWordWrap(True)
        self.quick_steps.setObjectName("mutedText")
        quick_layout.addWidget(self.quick_steps)
        self.quick_action = QPushButton()
        self.quick_action.setObjectName("primaryAction")
        self.quick_action.setMaximumWidth(300)
        self.quick_action.clicked.connect(self._open_recommended)
        quick_layout.addWidget(self.quick_action, 0, Qt.AlignLeft)
        layout.addWidget(self.quick_start)

        section = QLabel("Ne yapmak istiyorsunuz?")
        section.setObjectName("sectionTitle")
        layout.addWidget(section)

        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(10)
        self.grid.setVerticalSpacing(10)
        primary_tasks = [
            ("Emin Değilim — Bana Yol Göster", "Birkaç basit soruyla doğru işleme yönlendirir.", "guide", True),
            ("CCS / Secure Application", "CCS build çıktısını bulun, hazır HS-FS image'ı doğrulayın veya gerektiğinde yeni image hazırlayın.", "application", False),
            ("Image Doğrula / İncele", "Image veya certificate yapısını okuyun ve host-side kontrolleri çalıştırın.", "inspector", False),
            ("Key Hazırla / Kontrol Et", "Development key set oluşturun veya mevcut key material'i kontrol edin.", "keys", False),
            ("Environment Kontrolü", "SDK, Python/OpenSSL ve TI signer durumunu kontrol edin.", "environment", False),
            ("Proje Aç / Oluştur", "Çıktıları ve raporları düzenli tutmak için bir Project Workspace kullanın.", "project", False),
        ]
        self.task_cards: list[QFrame] = []
        for index, (title_text, description, key, primary) in enumerate(primary_tasks):
            card = self._task_card(title_text, description, key, primary=primary)
            self.task_cards.append(card)
            self.grid.addWidget(card, index // 3, index % 3)
        for col in range(3):
            self.grid.setColumnStretch(col, 1)
        layout.addLayout(self.grid)

        self.mode_hint = QLabel()
        self.mode_hint.setWordWrap(True)
        self.mode_hint.setObjectName("mutedText")
        layout.addWidget(self.mode_hint)

        safety = QFrame()
        safety.setObjectName("safetyNote")
        safety_layout = QHBoxLayout(safety)
        safety_layout.setContentsMargins(10, 7, 10, 7)
        safety_text = QLabel(
            "Güvenlik sınırı: Studio OTP/eFuse yazma, HS-FS → HS-SE transition veya kalıcı debug/security değişikliği çalıştırmaz."
        )
        safety_text.setWordWrap(True)
        safety_text.setObjectName("safetyText")
        safety_layout.addWidget(safety_text)
        layout.addWidget(safety)
        layout.addStretch(1)

        state.mode_changed.connect(self.refresh_mode)
        state.changed.connect(self.refresh_status)
        state.result_changed.connect(lambda _: self.refresh_status())
        self.refresh_mode(state.mode)
        self.refresh_status()

    def _status_card(self, title: str, text: str):
        frame = QFrame()
        frame.setObjectName("statusCard")
        card_layout = QVBoxLayout(frame)
        card_layout.setContentsMargins(12, 9, 12, 9)
        card_layout.setSpacing(4)
        heading = QLabel(title)
        heading.setObjectName("statusCardTitle")
        card_layout.addWidget(heading)
        value = QLabel(text)
        value.setWordWrap(True)
        value.setObjectName("statusCardValue")
        card_layout.addWidget(value)
        return frame, value

    def _task_card(self, title: str, description: str, key: str, *, primary: bool = False) -> QFrame:
        frame = QFrame()
        frame.setObjectName("taskCard")
        card_layout = QVBoxLayout(frame)
        card_layout.setContentsMargins(12, 10, 12, 10)
        card_layout.setSpacing(5)

        button = QPushButton(title)
        button.setObjectName("taskCardPrimary" if primary else "taskCardAction")
        button.setAccessibleName(title)
        button.clicked.connect(lambda _=False, k=key: self.navigate.emit(k))
        card_layout.addWidget(button)

        body = QLabel(description)
        body.setWordWrap(True)
        body.setObjectName("taskCardBody")
        card_layout.addWidget(body)
        card_layout.addStretch(1)
        return frame

    def _open_recommended(self) -> None:
        env = self.state.environment
        model = onboarding_model(
            environment_checked=env is not None,
            environment_ready=bool(env and env.ready),
            project_active=self.state.project is not None,
            has_result=self.state.last_result is not None,
        )
        self.navigate.emit(model.recommended_page)

    def _refresh_quick_start(self) -> None:
        env = self.state.environment
        model = onboarding_model(
            environment_checked=env is not None,
            environment_ready=bool(env and env.ready),
            project_active=self.state.project is not None,
            has_result=self.state.last_result is not None,
        )
        marker = {"DONE": "✓", "CURRENT": "→", "PENDING": "·", "OPTIONAL": "○"}
        self.quick_summary.setText(model.summary)
        self.quick_steps.setText("   ".join(f"{marker.get(step.state, '·')} {step.title}" for step in model.steps))
        self.quick_action.setText(model.recommended_title)

    def refresh_status(self) -> None:
        self._refresh_quick_start()
        if self.state.environment:
            env = self.state.environment
            sdk = env.sdk_version or "sürüm bilinmiyor"
            self.env_card[1].setText(f"SDK {sdk} · {'Hazır' if env.ready else 'Kontrol gerekli'}")
        else:
            self.env_card[1].setText("Henüz kontrol edilmedi")

        if self.state.project:
            self.project_card[1].setText(f"{self.state.project.name} · {self.state.device} · {self.state.lifecycle}")
        else:
            self.project_card[1].setText("Workspace seçilmedi")

        if self.state.last_result:
            model = result_presentation(self.state.last_result)
            self.last_card[1].setText(f"{model.title} · {model.status_text}")
            self.last_card[1].setToolTip(model.summary)
        else:
            self.last_card[1].setText("Henüz işlem yok")
            self.last_card[1].setToolTip("")

    def refresh_mode(self, mode: str) -> None:
        if mode == "guided":
            self.subtitle.setText(
                "Rehberli Mod günlük işleri öne çıkarır; OID, tool adı veya CLI komutu bilmeniz gerekmez."
            )
            self.mode_hint.setText("Daha ileri araçlara ihtiyaç duyarsanız sağ üstten Uzman Modu'na geçebilirsiniz.")
        else:
            self.subtitle.setText(
                "Uzman Modu bütün host-side/offline araçları açar. Exact source olmayan target değerleri yine tahmin edilmez."
            )
            self.mode_hint.setText("ROM, SDK, provisioning, revision, BoardCfg ve Secure Debug araçları sol menüde yer alır.")
