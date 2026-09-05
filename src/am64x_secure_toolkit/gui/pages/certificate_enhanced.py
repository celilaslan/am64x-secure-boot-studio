from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)

from ...keycheck import preflight_signing_key
from ...services.project import path_is_within_project
from ...workflows.keys import generate_keys_workflow
from .certificate import CertificatePage as _BaseCertificatePage
from .common import file_field, show_guided_error


class CertificatePage(_BaseCertificatePage):
    """Certificate Center with the current guided Signing Key step.

    The alpha26 base page remains the regression baseline. This subclass keeps the
    fast-moving guided Step 3 isolated while reusing the same certificate/profile
    engine and all existing management tabs.
    """

    def __init__(self, state) -> None:
        super().__init__(state)
        self._upgrade_signing_key_step()
        self._install_guided_application_route()

    def _install_guided_application_route(self) -> None:
        """Keep raw TI application-certificate fields out of the normal CCS path."""
        create_page = self.tabs.widget(1)
        create_layout = create_page.layout()
        self._create_progress = create_layout.itemAt(1).widget()

        self._create_application_route = QFrame()
        self._create_application_route.setObjectName("infoCard")
        route_layout = QVBoxLayout(self._create_application_route)
        route_title = QLabel("Application için standart yol: CCS / MCU+ SDK build")
        route_title.setObjectName("sectionTitle")
        route_text = QLabel(
            "Normal kullanımda application certificate'ını elle oluşturmanız veya Destination Address, Host ID ve "
            "processor flag alanlarını doldurmanız gerekmez. CCS/MCU+ SDK secure build sırasında gerekli X.509 yapısını "
            "TI signer ile image'a ekler. Secure Application ekranı hazır .appimage.hs_fs çıktısını doğrudan doğrular; "
            "yalnız custom/standalone signing gerektiğinde unsigned .appimage/.mcelf ve seçilen key ile yeni image üretir. "
            "Bu ham certificate formu yalnız Uzman Modu'ndaki özel entegrasyon çalışmaları içindir."
        )
        route_text.setWordWrap(True)
        route_text.setObjectName("mutedText")
        route_button = QPushButton("CCS / Secure Application Akışını Aç")
        route_button.setObjectName("primaryAction")
        route_button.clicked.connect(lambda: self.navigate.emit("application"))
        route_layout.addWidget(route_title)
        route_layout.addWidget(route_text)
        route_layout.addWidget(route_button)
        route_layout.addStretch(1)
        create_layout.insertWidget(1, self._create_application_route, 1)
        self._sync_guided_application_route()

    def _sync_guided_application_route(self) -> None:
        if not hasattr(self, "_create_application_route"):
            return
        guided_application = self.state.mode != "expert" and self.create_kind.currentData() == "application"
        self._create_application_route.setVisible(guided_application)
        if self._create_progress is not None:
            self._create_progress.setVisible(not guided_application)
        self.create_wizard_scroll.setVisible(not guided_application)
        self.create_nav.setVisible(not guided_application)

    def _refresh_mode_ui(self, *_args) -> None:
        super()._refresh_mode_ui(*_args)
        self._sync_guided_application_route()

    @staticmethod
    def _clear_layout(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            child_layout = item.layout()
            widget = item.widget()
            if child_layout is not None:
                CertificatePage._clear_layout(child_layout)
            if widget is not None:
                widget.deleteLater()

    def _upgrade_signing_key_step(self) -> None:
        signing = self.create_wizard.widget(2)
        outer = signing.layout()
        self._clear_layout(outer)

        sign_card = QFrame()
        sign_card.setObjectName("infoCard")
        layout = QVBoxLayout(sign_card)

        title = QLabel("3 · Signing Key")
        title.setObjectName("sectionTitle")
        note = QLabel(
            "Certificate RSA-4096 private signing key ile imzalanır. Mevcut bir private key kullanabilir veya "
            "bu wizard'dan çıkmadan synthetic development/test key oluşturabilirsiniz. Private key değeri ve "
            "secret path Project metadata'sına kaydedilmez."
        )
        note.setWordWrap(True)
        note.setObjectName("mutedText")
        layout.addWidget(title)
        layout.addWidget(note)

        mode_row = QHBoxLayout()
        self.create_key_mode_group = QButtonGroup(sign_card)
        self.create_existing_key_radio = QRadioButton("Mevcut RSA-4096 private key kullan")
        self.create_new_key_radio = QRadioButton("Yeni development/test RSA-4096 key oluştur")
        self.create_key_mode_group.addButton(self.create_existing_key_radio)
        self.create_key_mode_group.addButton(self.create_new_key_radio)
        self.create_existing_key_radio.setChecked(True)
        mode_row.addWidget(self.create_existing_key_radio)
        mode_row.addWidget(self.create_new_key_radio)
        mode_row.addStretch(1)
        layout.addLayout(mode_row)

        self.create_existing_key_panel = QFrame()
        existing = QGridLayout(self.create_existing_key_panel)
        self.create_key, keybox = file_field(
            self.create_existing_key_panel,
            "RSA-4096 private signing key seç",
            secret=True,
        )
        existing.addWidget(QLabel("Signing private key *"), 0, 0)
        existing.addWidget(keybox, 0, 1, 1, 3)
        existing_note = QLabel(
            "Devam etmeden önce Studio seçilen dosyanın private RSA key olduğunu ve target requirement için "
            "RSA-4096 olduğunu secret-safe preflight ile kontrol eder. Public key veya certificate tek başına imzalama için yeterli değildir."
        )
        existing_note.setWordWrap(True)
        existing_note.setObjectName("mutedText")
        existing.addWidget(existing_note, 1, 0, 1, 4)
        check_key = QPushButton("Key'i Kontrol Et")
        check_key.clicked.connect(self._check_create_signing_key)
        key_center = QPushButton("Key Center'ı Aç")
        key_center.clicked.connect(lambda: self.navigate.emit("keys"))
        existing.addWidget(check_key, 2, 2)
        existing.addWidget(key_center, 2, 3)
        layout.addWidget(self.create_existing_key_panel)

        self.create_new_key_panel = QFrame()
        generated = QGridLayout(self.create_new_key_panel)
        safety = QLabel(
            "Yeni key yalnız development/test / synthetic / non-production / unprovisioned / offline-only olarak üretilir. "
            "Production/customer key otomatik oluşturulmaz. Secret-generating output Project Workspace içinde olamaz."
        )
        safety.setWordWrap(True)
        safety.setObjectName("safetyText")
        generated.addWidget(safety, 0, 0, 1, 3)
        self.create_key_output_dir = QLineEdit()
        self.create_key_output_dir.setPlaceholderText("Project dışında korumalı bir key dizini seçin")
        choose_dir = QPushButton("Seç")
        choose_dir.clicked.connect(self._choose_create_key_output_dir)
        generated.addWidget(QLabel("Key output dizini *"), 1, 0)
        generated.addWidget(self.create_key_output_dir, 1, 1)
        generated.addWidget(choose_dir, 1, 2)
        generate = QPushButton("RSA-4096 development/test key oluştur ve kullan")
        generate.setObjectName("primaryAction")
        generate.clicked.connect(self._generate_create_signing_key)
        generated.addWidget(generate, 2, 1, 1, 2)
        self.create_key_generation_status = QLabel("Henüz yeni signing key üretilmedi.")
        self.create_key_generation_status.setWordWrap(True)
        self.create_key_generation_status.setObjectName("mutedText")
        generated.addWidget(self.create_key_generation_status, 3, 0, 1, 3)
        self.create_new_key_panel.setVisible(False)
        layout.addWidget(self.create_new_key_panel)

        self.create_key_preflight_status = QLabel(
            "Seçilen veya üretilen key, bu adımdan çıkarken secret-safe preflight ile doğrulanır."
        )
        self.create_key_preflight_status.setWordWrap(True)
        self.create_key_preflight_status.setObjectName("mutedText")
        layout.addWidget(self.create_key_preflight_status)

        self.create_new_key_radio.toggled.connect(self._on_create_key_mode_changed)
        self.create_key.textChanged.connect(self._update_create_navigation_state)
        outer.addWidget(sign_card)
        outer.addStretch(1)
        self._update_create_navigation_state()

    def _on_create_key_mode_changed(self, new_key_mode: bool) -> None:
        self.create_existing_key_panel.setVisible(not new_key_mode)
        self.create_new_key_panel.setVisible(new_key_mode)
        # Never carry a key selection silently between existing/generated modes.
        self.create_key.clear()
        self._set_key_status(
            self.create_key_preflight_status,
            "Seçilen veya üretilen key, bu adımdan çıkarken secret-safe preflight ile doğrulanır.",
            "mutedText",
        )
        if new_key_mode:
            self._set_key_status(self.create_key_generation_status, "Henüz yeni signing key üretilmedi.", "mutedText")
        self._update_create_navigation_state()

    @staticmethod
    def _set_key_status(label: QLabel, text: str, object_name: str) -> None:
        label.setText(text)
        label.setObjectName(object_name)
        label.style().unpolish(label)
        label.style().polish(label)

    def _choose_create_key_output_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Signing key output dizini seç")
        if path:
            self.create_key_output_dir.setText(path)

    def _key_purpose(self) -> str:
        return "debug" if self.create_kind.currentData() == "debug" else "application"

    def _preflight_selected_create_key(self) -> dict:
        key_text = self.create_key.text().strip()
        if not key_text:
            if self.create_new_key_radio.isChecked():
                raise ValueError("Önce development/test RSA-4096 signing key oluşturun")
            raise ValueError("RSA-4096 private signing key seçin")
        result = preflight_signing_key(Path(key_text), purpose=self._key_purpose())
        if result.get("input_class") != "private_key":
            raise ValueError(
                "Certificate imzalamak için private RSA signing key gerekir; public key/certificate yeterli değildir"
            )
        if result.get("status") != "PASS":
            raise ValueError("Signing key target requirement için RSA-4096 private-key preflight kontrolünü geçmedi")
        key = result.get("key") if isinstance(result.get("key"), dict) else {}
        self._set_key_status(
            self.create_key_preflight_status,
            f"✓ Private RSA-{key.get('rsa_bits', '—')} key doğrulandı · Public DER-SPKI SHA-256: {key.get('der_spki_sha256', '—')}",
            "statusPass",
        )
        return result

    def _check_create_signing_key(self) -> None:
        try:
            self._preflight_selected_create_key()
        except Exception as exc:
            show_guided_error(self, exc, context="Signing key preflight tamamlanamadı")

    def _generate_create_signing_key(self) -> None:
        try:
            output_dir = self.create_key_output_dir.text().strip()
            if not output_dir:
                raise ValueError("Yeni signing key için Project dışında bir output dizini seçin")
            if self.state.project is not None and path_is_within_project(self.state.project, output_dir):
                raise ValueError(
                    "Private signing key Project Workspace içine üretilemez. Project dışında ayrı korumalı bir dizin seçin."
                )
            role = self._key_purpose()
            workflow = generate_keys_workflow(output_dir, kind="signing", role=role)
            data = workflow.to_dict()
            details = data.get("safe_details") if isinstance(data.get("safe_details"), dict) else {}
            secret_files = details.get("secret_files_created") or []
            if len(secret_files) != 1:
                raise ValueError("Generated signing key output beklenen tek private-key dosyasını vermedi")
            private_name = str(secret_files[0])
            private_path = Path(output_dir).expanduser().resolve() / private_name
            self.create_key.setText(str(private_path))
            preflight = self._preflight_selected_create_key()
            public_files = details.get("public_files_created") or []
            public_name = str(public_files[0]) if public_files else "public DER-SPKI"
            fingerprint = (preflight.get("key") or {}).get("der_spki_sha256", "—")
            self._set_key_status(
                self.create_key_generation_status,
                "✓ Development/test signing key oluşturuldu ve bu certificate için seçildi. "
                f"Private dosya: {private_name} · Public dosya: {public_name} · DER-SPKI SHA-256: {fingerprint}",
                "statusPass",
            )
            self._update_create_navigation_state()
        except Exception as exc:
            show_guided_error(self, exc, context="Signing key üretilemedi")

    def _validate_create_step(self, step: int) -> None:
        if step == 2:
            self._preflight_selected_create_key()
            return
        super()._validate_create_step(step)

    def _update_create_context(self, *_args) -> None:
        super()._update_create_context(*_args)
        # A generated key is role-labeled (application/debug). If the certificate
        # context changes, require an explicit regeneration rather than silently reuse it.
        if hasattr(self, "create_new_key_radio") and self.create_new_key_radio.isChecked():
            self.create_key.clear()
            self._set_key_status(self.create_key_generation_status, "Certificate türü değişti; yeni role için key'i yeniden oluşturun.", "statusWarn")
            self._update_create_navigation_state()
        self._sync_guided_application_route()
