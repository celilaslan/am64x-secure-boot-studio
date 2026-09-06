from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThreadPool, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...keygen import generate_mek, generate_signing_key
from ...services.environment import resolve_environment
from ...services.secure_boot_package import build_secure_boot_package
from ...services.secure_boot_profile import assess_secure_boot_profile
from ...services.uart_flash import create_uart_flash_plan, execute_uart_flash_plan
from ..jobs import FunctionJob
from ..widgets import HumanResultView
from .common import show_guided_error


class SecureBootPage(QWidget):
    """Beginner-first end-to-end CCS → secure package → UART flash workflow."""

    navigate = Signal(str)

    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        self._active_job: FunctionJob | None = None
        self._package_result: dict | None = None
        self._flash_plan = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setObjectName("secureBootScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        root.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(8, 4, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Secure Boot Paketi Hazırla ve Karta Yükle")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        intro = QLabel(
            "CCS projelerini seçin; Studio HS-FS/HS-SE hedefini, key gereksinimini, TI make/signer zincirini "
            "ve karta yükleme planını yönetir. .mcelf, DEVICE_TYPE, certificate alanı veya flash offset'i bilmeniz gerekmez."
        )
        intro.setWordWrap(True)
        intro.setObjectName("mutedText")
        layout.addWidget(intro)

        layout.addWidget(self._target_card())
        layout.addWidget(self._projects_card())
        layout.addWidget(self._keys_card())
        layout.addWidget(self._build_card())
        layout.addWidget(self._flash_card())

        self.result_view = HumanResultView()
        self.result_view.setMinimumHeight(420)
        layout.addWidget(self.result_view)

        safety = QLabel(
            "Sınır: Studio OSPI yazmayı yalnız açık onayla çalıştırır; OTP/eFuse yazmaz, HS-FS → HS-SE geçişi yapmaz. "
            "CCS Debug/Run gerçek secure boot kanıtı değildir; boot sonucu OSPI boot + UART log ile doğrulanır."
        )
        safety.setWordWrap(True)
        safety.setObjectName("safetyNote")
        layout.addWidget(safety)

        self.physical.currentIndexChanged.connect(self._refresh_profile)
        self.target.currentIndexChanged.connect(self._target_changed)
        self.root_state.currentIndexChanged.connect(self._root_changed)
        self.scope.currentIndexChanged.connect(self._refresh_profile)
        self.encrypt.toggled.connect(self._refresh_profile)
        self.signing.textChanged.connect(self._refresh_profile)
        self.mek.textChanged.connect(self._refresh_profile)
        self.state.changed.connect(self._sync_state)
        self._sync_state()

    def _card(self, title: str, description: str) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setObjectName("infoCard")
        layout = QVBoxLayout(frame)
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        layout.addWidget(heading)
        detail = QLabel(description)
        detail.setWordWrap(True)
        detail.setObjectName("mutedText")
        layout.addWidget(detail)
        return frame, layout

    def _target_card(self) -> QFrame:
        frame, layout = self._card(
            "1 · Kart durumu ve üretim hedefi",
            "Kartın gerçek lifecycle'ı ile üretilecek dosyanın hedefi ayrı bilgilerdir. Studio yanlış lifecycle çıktısını karta yazmaz.",
        )
        form = QFormLayout()
        self.physical = QComboBox()
        self.physical.addItem("HS-FS geliştirme kartı", "HS-FS")
        self.physical.addItem("HS-SE provision edilmiş kart", "HS-SE")
        self.physical.addItem("GP kart", "GP")
        self.target = QComboBox()
        self.target.addItem("HS-FS · SDK development akışı", "HS-FS")
        self.target.addItem("HS-SE · Customer RoT akışı", "HS-SE")
        self.root_state = QComboBox()
        self.root_state.addItem("Doğrulanmadı / bilmiyorum", "unknown")
        self.root_state.addItem("Provision edilmedi", "not_provisioned")
        self.root_state.addItem("Provision edildiğini biliyorum", "provisioned")
        self.root_state.addItem("Donanım üzerinde doğrulandı", "hardware_verified")
        form.addRow("Fiziksel kart", self.physical)
        form.addRow("Üretim hedefi", self.target)
        form.addRow("Customer Root of Trust", self.root_state)
        layout.addLayout(form)
        self.profile_status = QLabel()
        self.profile_status.setWordWrap(True)
        layout.addWidget(self.profile_status)
        return frame

    def _path_row(self, title: str, *, directory: bool) -> tuple[QLineEdit, QWidget]:
        edit = QLineEdit()
        edit.setReadOnly(True)
        edit.setPlaceholderText("Henüz seçilmedi")
        row = QWidget()
        box = QHBoxLayout(row)
        box.setContentsMargins(0, 0, 0, 0)
        box.addWidget(edit, 1)
        choose = QPushButton("Seç")
        box.addWidget(choose)

        def pick() -> None:
            value = QFileDialog.getExistingDirectory(self, title) if directory else QFileDialog.getOpenFileName(self, title)[0]
            if value:
                edit.setText(value)
                self._flash_plan = None
                self.flash_button.setEnabled(False) if hasattr(self, "flash_button") else None

        choose.clicked.connect(pick)
        return edit, row

    def _projects_card(self) -> QFrame:
        frame, layout = self._card(
            "2 · CCS projeleri",
            "Application projesi zorunludur. Tam boot paketi isterseniz kullandığınız SBL (ör. sbl_ospi) CCS projesini de seçin.",
        )
        form = QFormLayout()
        self.scope = QComboBox()
        self.scope.addItem("Secure application · SDK hazır SBL ile yükle", "application_only")
        self.scope.addItem("Tam paket · application + kendi SBL/combined image", "full")
        self.app_project, app_row = self._path_row("Application CCS proje veya Debug/Release klasörünü seç", directory=True)
        self.sbl_project, sbl_row = self._path_row("SBL CCS proje veya Debug/Release klasörünü seç", directory=True)
        form.addRow("Paket kapsamı", self.scope)
        form.addRow("Application CCS projesi", app_row)
        form.addRow("SBL CCS projesi", sbl_row)
        layout.addLayout(form)
        self.sbl_hint = QLabel()
        self.sbl_hint.setWordWrap(True)
        self.sbl_hint.setObjectName("mutedText")
        layout.addWidget(self.sbl_hint)
        return frame

    def _keys_card(self) -> QFrame:
        frame, layout = self._card(
            "3 · Key ve koruma",
            "HS-FS için SDK development key otomatik kullanılabilir. HS-SE için karttaki Customer RoT ile eşleşen private key zorunludur.",
        )
        form = QFormLayout()
        self.signing, signing_row = self._path_row("Application/SBL private signing key seç", directory=False)
        self.encrypt = QCheckBox("Application ve SBL şifrele")
        self.mek, mek_row = self._path_row("256-bit application/SBL MEK seç", directory=False)
        form.addRow("Private signing key", signing_row)
        form.addRow("Koruma", self.encrypt)
        form.addRow("MEK", mek_row)
        layout.addLayout(form)
        actions = QHBoxLayout()
        new_key = QPushButton("Yeni development/test key oluştur")
        new_key.clicked.connect(self._generate_key)
        new_mek = QPushButton("Yeni development/test MEK oluştur")
        new_mek.clicked.connect(self._generate_mek)
        key_center = QPushButton("Gelişmiş Key Center")
        key_center.clicked.connect(lambda: self.navigate.emit("keys"))
        actions.addWidget(new_key)
        actions.addWidget(new_mek)
        actions.addWidget(key_center)
        actions.addStretch(1)
        layout.addLayout(actions)
        note = QLabel("Üretilen test key'leri production Customer RoT değildir; private key yolu proje/rapor geçmişine kaydedilmez.")
        note.setWordWrap(True)
        note.setObjectName("mutedText")
        layout.addWidget(note)
        return frame

    def _build_card(self) -> QFrame:
        frame, layout = self._card(
            "4 · Paketi üret",
            "Studio CCS make ve projenin kendi makefile_ccs_bootimage_gen tarifini arka planda çalıştırır; global devconfig.mak değiştirilmez.",
        )
        row = QHBoxLayout()
        self.build_status = QLabel("Hazır olduğunuzda paketi üretin.")
        self.build_status.setWordWrap(True)
        self.build_status.setObjectName("mutedText")
        row.addWidget(self.build_status, 1)
        self.build_button = QPushButton("Secure Boot Paketini Üret")
        self.build_button.setObjectName("primaryAction")
        self.build_button.clicked.connect(self._build)
        row.addWidget(self.build_button)
        layout.addLayout(row)
        return frame

    def _flash_card(self) -> QFrame:
        frame, layout = self._card(
            "5 · Karta yükle ve gerçek boot'u test et",
            "Kartı UART boot moduna alın. Studio SDK'nın lifecycle'a uygun UniFlash config'indeki doğrulanmış offset'leri kullanır; offset tahmin etmez.",
        )
        form = QFormLayout()
        self.port = QLineEdit("COM3")
        self.port.setMaximumWidth(160)
        self.flash_confirm = QCheckBox("OSPI içeriğinin değişeceğini anladım")
        form.addRow("UART portu", self.port)
        form.addRow("Yazma onayı", self.flash_confirm)
        layout.addLayout(form)
        row = QHBoxLayout()
        self.plan_button = QPushButton("Yükleme Planını Kontrol Et")
        self.plan_button.clicked.connect(self._prepare_flash)
        self.flash_button = QPushButton("UART ile OSPI'ye Yaz")
        self.flash_button.setObjectName("dangerAction")
        self.flash_button.setEnabled(False)
        self.flash_button.clicked.connect(self._flash)
        row.addWidget(self.plan_button)
        row.addWidget(self.flash_button)
        row.addStretch(1)
        layout.addLayout(row)
        self.flash_status = QLabel("Önce paket üretin; ardından yükleme planını kontrol edin.")
        self.flash_status.setWordWrap(True)
        self.flash_status.setObjectName("mutedText")
        layout.addWidget(self.flash_status)
        return frame

    def _combo_set(self, combo: QComboBox, value: str) -> None:
        index = combo.findData(value)
        if index >= 0 and combo.currentIndex() != index:
            combo.blockSignals(True)
            combo.setCurrentIndex(index)
            combo.blockSignals(False)

    def _sync_state(self) -> None:
        self._combo_set(self.physical, self.state.lifecycle)
        self._combo_set(self.target, getattr(self.state, "build_target_lifecycle", "HS-FS"))
        self._combo_set(self.root_state, getattr(self.state, "customer_root_state", "unknown"))
        self._refresh_profile()

    def _target_changed(self) -> None:
        target = str(self.target.currentData())
        if target:
            self.state.set_build_target_lifecycle(target)
        self._flash_plan = None
        self.flash_button.setEnabled(False)
        self._refresh_profile()

    def _root_changed(self) -> None:
        root_state = str(self.root_state.currentData())
        if root_state:
            self.state.set_customer_root_state(root_state)
        self._flash_plan = None
        self.flash_button.setEnabled(False)
        self._refresh_profile()

    def _profile(self):
        return assess_secure_boot_profile(
            physical_lifecycle=str(self.physical.currentData()),
            target_lifecycle=str(self.target.currentData()),
            customer_root_state=str(self.root_state.currentData()),
            has_customer_signing_key=bool(self.signing.text()),
            encrypted=self.encrypt.isChecked(),
            has_encryption_key=bool(self.mek.text()),
        )

    def _refresh_profile(self) -> None:
        if not hasattr(self, "profile_status"):
            return
        profile = self._profile()
        details = (
            f"Hedef {profile.target_lifecycle}: DEVICE_TYPE={profile.device_type}, çıktı ailesi *{profile.output_family}. "
            + ("SDK development key kullanılabilir." if profile.sdk_development_key_allowed else "Customer signing key zorunlu.")
        )
        messages = [*profile.blockers, *profile.warnings]
        self.profile_status.setText(details + ("\n" + "\n".join(f"• {x}" for x in messages) if messages else "\n✓ Build ve yükleme hedefleri tutarlı."))
        self.profile_status.setObjectName("statusWarn" if messages else "statusPass")
        self.profile_status.style().unpolish(self.profile_status)
        self.profile_status.style().polish(self.profile_status)
        full = self.scope.currentData() == "full"
        self.sbl_project.setEnabled(full)
        self.sbl_hint.setText(
            "Tam paket seçildi: SBL CCS projesi zorunlu." if full else
            "Application-only seçildi: karta yüklerken SDK'nın lifecycle'a uygun hazır SBL'i kullanılır."
        )
        self.mek.setEnabled(self.encrypt.isChecked())
        self.flash_button.setEnabled(self._flash_plan is not None and profile.flash_allowed)

    def _generate_key(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Development/test key için proje dışı korumalı klasör seç")
        if not directory:
            return
        try:
            result = generate_signing_key(directory, role="application")
            self.signing.setText(str(Path(directory).resolve() / result["secret_files_created"][0]))
            self.state.set_last_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Development/test signing key üretilemedi")

    def _generate_mek(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Development/test MEK için proje dışı korumalı klasör seç")
        if not directory:
            return
        try:
            result = generate_mek(directory, role="application")
            self.mek.setText(str(Path(directory).resolve() / result["secret_files_created"][0]))
            self.encrypt.setChecked(True)
            self.state.set_last_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Development/test MEK üretilemedi")

    def _environment(self):
        env = self.state.environment or resolve_environment()
        self.state.set_environment(env)
        if not env.ready or env.sdk_root is None:
            raise RuntimeError("Önce Environment ekranında MCU+ SDK ve signing araçlarını doğrulayın")
        return env

    def _build(self) -> None:
        try:
            env = self._environment()
            profile = self._profile()
            if profile.blockers:
                raise ValueError(" ".join(profile.blockers))
            app = self.app_project.text().strip()
            if not app:
                raise FileNotFoundError("Application CCS projesini seçin")
            full = self.scope.currentData() == "full"
            sbl = self.sbl_project.text().strip() if full else None
            if full and not sbl:
                raise FileNotFoundError("Tam paket için SBL CCS projesini seçin")
            args = dict(
                application_project=app, sdk_root=env.sdk_root,
                physical_lifecycle=str(self.physical.currentData()),
                target_lifecycle=str(self.target.currentData()),
                customer_root_state=str(self.root_state.currentData()),
                signing_key=self.signing.text().strip() or None,
                encryption_key=self.mek.text().strip() if self.encrypt.isChecked() else None,
                encrypt=self.encrypt.isChecked(),
                sbl_project=sbl,
            )
            self.build_button.setEnabled(False)
            self.build_status.setText("CCS/MCU+ SDK build çalışıyor; pencereyi kapatmayın…")
            job = FunctionJob(lambda: build_secure_boot_package(**args))
            self._active_job = job
            job.signals.finished.connect(self._build_finished)
            job.signals.failed.connect(self._job_failed)
            QThreadPool.globalInstance().start(job)
        except Exception as exc:
            show_guided_error(self, exc, context="Secure boot paketi başlatılamadı")

    def _build_finished(self, result: dict) -> None:
        self._active_job = None
        self._package_result = result
        self._flash_plan = None
        self.build_button.setEnabled(True)
        self.build_status.setText(result.get("summary", "Build tamamlandı."))
        self.state.set_last_result(result)
        self.result_view.set_result(result)
        self._refresh_profile()

    def _job_failed(self, detail: str) -> None:
        self._active_job = None
        self.build_button.setEnabled(True)
        self.flash_button.setEnabled(False)
        self.build_status.setText("İşlem tamamlanamadı.")
        show_guided_error(self, RuntimeError(detail), context="Secure boot işlemi tamamlanamadı")

    def _prepare_flash(self) -> None:
        try:
            if not self._package_result or self._package_result.get("status") != "PASS":
                raise RuntimeError("Önce başarılı bir secure boot paketi üretin")
            env = self._environment()
            app = (self._package_result.get("application_output") or {}).get("path")
            boot = (self._package_result.get("boot_output") or {}).get("path")
            self._flash_plan = create_uart_flash_plan(
                sdk_root=env.sdk_root, serial_port=self.port.text(),
                physical_lifecycle=str(self.physical.currentData()),
                target_lifecycle=str(self.target.currentData()),
                customer_root_state=str(self.root_state.currentData()),
                application_image=app, boot_image=boot,
            )
            self.flash_status.setText(
                f"Plan hazır: boot offset {self._flash_plan.boot_offset}, application offset "
                f"{self._flash_plan.application_offset}, port {self._flash_plan.serial_port}. "
                "Kart UART boot modunda olmalı. Yazmadan önce onay kutusunu işaretleyin."
            )
            self.flash_status.setObjectName("statusPass")
            self.flash_button.setEnabled(self._profile().flash_allowed)
        except Exception as exc:
            self._flash_plan = None
            self.flash_button.setEnabled(False)
            show_guided_error(self, exc, context="UART/OSPI yükleme planı hazırlanamadı")

    def _flash(self) -> None:
        try:
            if self._flash_plan is None:
                raise RuntimeError("Önce yükleme planını kontrol edin")
            if not self.flash_confirm.isChecked():
                raise PermissionError("OSPI yazma onay kutusunu işaretleyin")
            answer = QMessageBox.warning(
                self,
                "OSPI içeriği değişecek",
                f"{self._flash_plan.serial_port} üzerinden boot ve application image OSPI'ye yazılacak. "
                "Bu işlem OTP/eFuse'a dokunmaz. Devam edilsin mi?",
                QMessageBox.Yes | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if answer != QMessageBox.Yes:
                return
            self.flash_button.setEnabled(False)
            self.flash_status.setText("UART UniFlash çalışıyor; karta ve seri bağlantıya dokunmayın…")
            job = FunctionJob(lambda: execute_uart_flash_plan(self._flash_plan, confirm_hardware_write=True))
            self._active_job = job
            job.signals.finished.connect(self._flash_finished)
            job.signals.failed.connect(self._job_failed)
            QThreadPool.globalInstance().start(job)
        except Exception as exc:
            show_guided_error(self, exc, context="UART/OSPI yazma başlatılamadı")

    def _flash_finished(self, result: dict) -> None:
        self._active_job = None
        self.flash_status.setText(result.get("summary", "UART UniFlash tamamlandı."))
        self.state.set_last_result(result)
        self.result_view.set_result(result)
        self.flash_button.setEnabled(True)
