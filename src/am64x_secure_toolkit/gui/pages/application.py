from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QInputDialog,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ...services.environment import resolve_environment
from ...services.project import suggest_project_output
from ...workflows.application import application_build_workflow
from ..widgets import HumanResultView
from .common import file_field, require_field, set_field_invalid, show_guided_error


class ApplicationPage(QWidget):
    navigate = Signal(str)

    STEP_NAMES = ("Application", "Koruma", "Çıktı", "Kontrol", "Sonuç")

    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        root = QVBoxLayout(self)
        title = QLabel("Secure Application Oluştur")
        title.setObjectName("pageTitle")
        root.addWidget(title)
        intro = QLabel(
            "Adım adım ilerleyin. Studio gerekli ön kontrolleri yapar ve MCU+ SDK içindeki resmi "
            "appimage_x509_cert_gen.py aracını kullanır. Image üretim mantığını yeniden uygulamaz."
        )
        intro.setWordWrap(True)
        intro.setObjectName("mutedText")
        root.addWidget(intro)

        self.step_bar = QFrame()
        self.step_bar.setObjectName("wizardStepBar")
        step_layout = QHBoxLayout(self.step_bar)
        self.step_labels: list[QLabel] = []
        for i, name in enumerate(self.STEP_NAMES):
            label = QLabel(f"{i + 1}. {name}")
            label.setAlignment(QtAlignCenter)
            self.step_labels.append(label)
            step_layout.addWidget(label, 1)
        root.addWidget(self.step_bar)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._input_step())
        self.stack.addWidget(self._protection_step())
        self.stack.addWidget(self._output_step())
        self.stack.addWidget(self._review_step())
        self.stack.addWidget(self._result_step())
        # Keep every step usable when Studio is not maximized.
        self.stack_scroll = QScrollArea()
        self.stack_scroll.setObjectName("wizardScroll")
        self.stack_scroll.setWidgetResizable(True)
        self.stack_scroll.setFrameShape(QFrame.NoFrame)
        self.stack_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.stack_scroll.setWidget(self.stack)
        root.addWidget(self.stack_scroll, 1)

        nav = QHBoxLayout()
        self.back = QPushButton("← Geri")
        self.back.clicked.connect(self.go_back)
        self.next = QPushButton("Devam →")
        self.next.setObjectName("primaryAction")
        self.next.clicked.connect(self.go_next)
        self.start_over = QPushButton("Yeni İşlem")
        self.start_over.clicked.connect(self.reset_wizard)
        nav.addWidget(self.back)
        nav.addStretch(1)
        nav.addWidget(self.start_over)
        nav.addWidget(self.next)
        root.addLayout(nav)
        self._project_output_last: str | None = None
        self.input.textChanged.connect(lambda _=None: self._sync_project_output())
        self.input.textChanged.connect(lambda _=None: self._update_navigation_state())
        self.signing.textChanged.connect(lambda _=None: self._update_navigation_state())
        self.mek.textChanged.connect(lambda _=None: self._update_navigation_state())
        self.output.textChanged.connect(lambda _=None: self._update_navigation_state())
        self.encrypt.toggled.connect(lambda _=False: self._sync_project_output())
        self.encrypt.toggled.connect(lambda _=False: self._update_navigation_state())
        self.state.changed.connect(self._sync_project_output)
        self.state.changed.connect(self._refresh_sdk_ui)
        self.state.mode_changed.connect(lambda _mode: self._refresh_sdk_ui())
        self._set_step(0)
        self._sync_project_output()
        self._refresh_sdk_ui()
        self._update_navigation_state()

    def _card(self, title: str, body: str) -> QFrame:
        frame = QFrame(); frame.setObjectName("infoCard")
        layout = QVBoxLayout(frame)
        h = QLabel(title); h.setObjectName("sectionTitle"); layout.addWidget(h)
        text = QLabel(body); text.setWordWrap(True); text.setObjectName("mutedText"); layout.addWidget(text)
        return frame

    def _set_choice_card_selected(self, frame: QFrame, selected: bool) -> None:
        frame.setProperty("selected", bool(selected))
        frame.style().unpolish(frame)
        frame.style().polish(frame)

    def _protection_choice_card(self, radio: QRadioButton, body: str) -> QFrame:
        frame = QFrame()
        frame.setObjectName("choiceCard")
        layout = QVBoxLayout(frame)
        radio.setAccessibleName(radio.text())
        layout.addWidget(radio)
        detail = QLabel(body)
        detail.setWordWrap(True)
        detail.setObjectName("mutedText")
        layout.addWidget(detail)
        radio.toggled.connect(lambda checked, card=frame: self._set_choice_card_selected(card, checked))
        self._set_choice_card_selected(frame, radio.isChecked())
        return frame

    def _set_secret_status(self, label: QLabel, text: str, object_name: str) -> None:
        label.setText(text)
        label.setObjectName(object_name)
        label.style().unpolish(label)
        label.style().polish(label)

    def _refresh_secret_selector(
        self,
        edit: QLineEdit,
        status: QLabel,
        *,
        empty_text: str,
        show_basename: bool,
    ) -> None:
        value = edit.text().strip()
        if not value:
            self._set_secret_status(status, empty_text, "mutedText")
            return
        path = Path(value).expanduser()
        if not path.exists() or not path.is_file():
            self._set_secret_status(status, "Seçilen dosya artık bulunamıyor.", "statusFail")
            return
        if show_basename:
            self._set_secret_status(status, f"Seçildi: {path.name}", "statusInfo")
        else:
            self._set_secret_status(status, "MEK dosyası seçildi.", "statusInfo")

    def _secret_selector(
        self,
        parent: QWidget,
        *,
        title: str,
        empty_text: str,
        button_text: str,
        badge_text: str,
        show_basename: bool,
    ):
        # The real secret path stays in an internal widget for workflow execution.
        # Guided/Expert GUI surfaces show only a basename/status, never the full secret path.
        edit = QLineEdit(parent)
        edit.setVisible(False)
        edit.setAccessibleName(title)

        frame = QFrame()
        frame.setObjectName("infoCard")
        outer = QHBoxLayout(frame)
        texts = QVBoxLayout()
        heading_row = QHBoxLayout()
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        badge = QLabel(badge_text)
        badge.setObjectName("statusWarn")
        heading_row.addWidget(heading)
        heading_row.addWidget(badge)
        heading_row.addStretch(1)
        texts.addLayout(heading_row)
        status = QLabel(empty_text)
        status.setWordWrap(True)
        status.setObjectName("mutedText")
        texts.addWidget(status)
        outer.addLayout(texts, 1)
        choose = QPushButton(button_text)
        choose.setAccessibleName(f"{title}: dosya seç")
        outer.addWidget(choose, 0)

        def pick() -> None:
            path, _ = QFileDialog.getOpenFileName(parent, title)
            if path:
                edit.setText(path)

        choose.clicked.connect(pick)
        edit.textChanged.connect(
            lambda _=None: self._refresh_secret_selector(
                edit, status, empty_text=empty_text, show_basename=show_basename
            )
        )
        return edit, frame, status, choose

    def _secret_file_ready(self, edit: QLineEdit) -> bool:
        value = edit.text().strip()
        if not value:
            return False
        path = Path(value).expanduser()
        return path.exists() and path.is_file()

    def _input_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "1 · Application",
            "CCS/MCU+ SDK build sonrasında oluşan unsigned application çıktısını seçin veya build klasörünü taratın."
        ))
        form = QFormLayout()
        self.input, box = file_field(page, "Unsigned .mcelf veya .appimage dosyası seç")
        self.input.setPlaceholderText("Unsigned .mcelf/.appimage seçin veya Build Klasörünü Tara'yı kullanın")
        form.addRow("Application dosyası", box)
        layout.addLayout(form)

        discovery = QFrame()
        discovery.setObjectName("infoCard")
        discovery_layout = QHBoxLayout(discovery)
        discovery_text = QVBoxLayout()
        discovery_title = QLabel("CCS / MCU+ SDK build çıktısını bul")
        discovery_title.setObjectName("sectionTitle")
        discovery_note = QLabel(
            "Dosya adını veya yerini bilmeniz gerekmiyor. CCS'te proje build edildikten sonra proje ya da build "
            "klasörünü seçin; Studio unsigned .mcelf ve .appimage adaylarını tarayıp size gösterir. "
            "Yalnız .out varsa SDK boot-image/post-build aşaması henüz tamamlanmamıştır."
        )
        discovery_note.setWordWrap(True)
        discovery_note.setObjectName("mutedText")
        discovery_text.addWidget(discovery_title)
        discovery_text.addWidget(discovery_note)
        discovery_layout.addLayout(discovery_text, 1)
        discover_button = QPushButton("Build Klasörünü Tara")
        discover_button.clicked.connect(self._choose_application_build_dir)
        discovery_layout.addWidget(discover_button)
        layout.addWidget(discovery)
        self.discovery_status = QLabel("Henüz build klasörü taranmadı.")
        self.discovery_status.setWordWrap(True)
        self.discovery_status.setObjectName("mutedText")
        layout.addWidget(self.discovery_status)

        self.sdk_status_card = QFrame()
        self.sdk_status_card.setObjectName("infoCard")
        sdk_status_layout = QHBoxLayout(self.sdk_status_card)
        sdk_texts = QVBoxLayout()
        self.sdk_status_title = QLabel("SDK")
        self.sdk_status_title.setObjectName("sectionTitle")
        self.sdk_status_detail = QLabel()
        self.sdk_status_detail.setWordWrap(True)
        self.sdk_status_detail.setObjectName("mutedText")
        sdk_texts.addWidget(self.sdk_status_title)
        sdk_texts.addWidget(self.sdk_status_detail)
        sdk_status_layout.addLayout(sdk_texts, 1)
        self.environment_action = QPushButton("Environment'ı Kontrol Et")
        self.environment_action.clicked.connect(lambda: self.navigate.emit("environment"))
        sdk_status_layout.addWidget(self.environment_action, 0)
        layout.addWidget(self.sdk_status_card)

        self.sdk_expert_label = QLabel("MCU+ SDK root")
        self.sdk_expert_box = QWidget()
        sdk_expert_layout = QHBoxLayout(self.sdk_expert_box)
        sdk_expert_layout.setContentsMargins(0, 0, 0, 0)
        self.sdk = QLineEdit()
        self.sdk.setPlaceholderText("Optional SDK root — boşsa Environment / auto-discovery")
        sdk_expert_layout.addWidget(self.sdk, 1)
        expert_form = QFormLayout()
        expert_form.addRow(self.sdk_expert_label, self.sdk_expert_box)
        layout.addLayout(expert_form)

        layout.addStretch(1)
        return page

    def _choose_application_build_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self,
            "CCS / MCU+ SDK proje veya build klasörünü seç",
        )
        if not directory:
            return
        root = Path(directory)
        try:
            candidates: list[Path] = []
            for pattern in ("*.mcelf", "*.appimage"):
                candidates.extend(path for path in root.rglob(pattern) if path.is_file())
            unique = {str(path.resolve()).casefold(): path for path in candidates}
            candidates = sorted(
                unique.values(),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            if not candidates:
                signed = next(
                    (path for path in root.rglob("*.appimage.hs_fs") if path.is_file()),
                    None,
                )
                if signed is not None:
                    raise FileNotFoundError(
                        "Bu klasörde yalnız imzalı .appimage.hs_fs çıktısı bulundu. Bu dosya tekrar imzalanmaz; "
                        "doğrulamak için Image İnceleme ekranını kullanın. Yeni imza için unsigned .mcelf veya "
                        ".appimage çıktısının bulunduğu build klasörünü seçin."
                    )
                raise FileNotFoundError(
                    "Seçilen klasörde unsigned .mcelf veya .appimage bulunamadı. CCS build konsolunda boot-image/"
                    "post-build aşamasının başarıyla tamamlandığını kontrol edin; yalnız .out oluşması yeterli değildir."
                )

            labels = [str(path.relative_to(root)) for path in candidates]
            if len(candidates) == 1:
                selected = candidates[0]
            else:
                chosen, accepted = QInputDialog.getItem(
                    self,
                    "Application build çıktısını seç",
                    f"{len(candidates)} uygun unsigned çıktı bulundu:",
                    labels,
                    0,
                    False,
                )
                if not accepted:
                    return
                selected = candidates[labels.index(chosen)]

            self.input.setText(str(selected))
            self.discovery_status.setText(
                f"✓ {len(candidates)} uygun unsigned build çıktısı bulundu; seçilen dosya: {selected.name}"
            )
            self.discovery_status.setObjectName("statusPass")
            self.discovery_status.style().unpolish(self.discovery_status)
            self.discovery_status.style().polish(self.discovery_status)
        except Exception as exc:
            show_guided_error(self, exc, context="CCS / MCU+ SDK build çıktısı bulunamadı")

    def _protection_step(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "2 · İmzalama ve Şifreleme",
            "Her secure application imzalanır. Şifreleme seçerseniz ayrıca bir application MEK gerekir."
        ))

        self.signing, self.signing_card, self.signing_status, self.signing_choose = self._secret_selector(
            page,
            title="Signing key",
            empty_text="Henüz key seçilmedi.",
            button_text="Mevcut key'i seç",
            badge_text="Zorunlu",
            show_basename=True,
        )
        layout.addWidget(self.signing_card)

        key_help = QFrame()
        key_help.setObjectName("infoCard")
        key_help_layout = QHBoxLayout(key_help)
        help_text = QLabel("Development/test key'iniz yok mu? Synthetic, non-production bir test key set'i oluşturabilirsiniz.")
        help_text.setWordWrap(True)
        help_text.setObjectName("mutedText")
        key_help_layout.addWidget(help_text, 1)
        key_center = QPushButton("Test key set'i oluştur")
        key_center.clicked.connect(lambda: self.navigate.emit("keys"))
        key_help_layout.addWidget(key_center, 0)
        layout.addWidget(key_help)

        choice_title = QLabel("Application nasıl korunacak?")
        choice_title.setObjectName("sectionTitle")
        layout.addWidget(choice_title)

        self.protection_group = QButtonGroup(page)
        self.protection_group.setExclusive(True)
        self.sign_only = QRadioButton("Yalnız imzala")
        self.encrypt = QRadioButton("Şifrele + imzala")
        self.protection_group.addButton(self.sign_only)
        self.protection_group.addButton(self.encrypt)
        self.encrypt.toggled.connect(self._toggle_encryption)
        self.sign_only.setChecked(True)

        choices = QHBoxLayout()
        self.sign_only_card = self._protection_choice_card(
            self.sign_only,
            "Signed application oluşturur; certificate signature ve image-integrity kontrolleri bu akışın parçasıdır."
        )
        self.encrypt_card = self._protection_choice_card(
            self.encrypt,
            "Signing'e ek olarak application içeriğini şifreler. Bu seçenek için bir application MEK gerekir."
        )
        choices.addWidget(self.sign_only_card, 1)
        choices.addWidget(self.encrypt_card, 1)
        layout.addLayout(choices)

        self.mek, self.mek_card, self.mek_status, self.mek_choose = self._secret_selector(
            page,
            title="Application MEK",
            empty_text="Henüz MEK seçilmedi.",
            button_text="MEK seç",
            badge_text="Şifreleme için zorunlu",
            show_basename=False,
        )
        layout.addWidget(self.mek_card)

        layout.addWidget(self._card(
            "Güvenlik sınırı",
            "Bu adım yalnız host üzerinde image hazırlamak içindir. Key seçmek veya image üretmek customer Root of Trust "
            "provisioning'ini kanıtlamaz. Studio OTP/eFuse yazmaz ve HS-FS → HS-SE geçişi yapmaz."
        ))
        layout.addStretch(1)
        self._toggle_encryption(False)
        return page

    def _output_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "3 · Çıktı",
            "Üretilecek secure application image için ayrı bir çıktı dosyası seçin. Studio input dosyasını değiştirmez."
        ))
        form = QFormLayout()
        self.output, box = file_field(page, "Output image", save=True)
        self.output.setPlaceholderText("Çıktı dosyasını seçin")
        form.addRow("Çıktı dosyası", box)
        layout.addLayout(form)
        project_row = QHBoxLayout()
        self.project_output_hint = QLabel("Aktif bir Proje Çalışma Alanı yok. Çıktı dosyasını manuel seçin.")
        self.project_output_hint.setWordWrap(True); self.project_output_hint.setObjectName("mutedText")
        self.use_project_output = QPushButton("Proje Önerisini Kullan")
        self.use_project_output.clicked.connect(lambda: self._sync_project_output(force=True))
        project_row.addWidget(self.project_output_hint, 1); project_row.addWidget(self.use_project_output)
        layout.addLayout(project_row)
        layout.addWidget(self._card(
            "Çıktı politikası",
            "Aktif proje varsa Studio proje klasörü altında güvenli bir çıktı yolu önerir. Mevcut bir dosyanın üzerine "
            "sessizce yazmaz. Private key/MEK path proje metadata'sına kaydedilmez."
        ))
        layout.addStretch(1)
        return page

    def _review_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "4 · Çalıştırmadan Önce",
            "Aşağıdaki özet yalnız seçiminizi gösterir. Secret değerler veya secret hash'ler burada gösterilmez."
        ))
        self.review = QLabel()
        self.review.setWordWrap(True)
        self.review.setTextInteractionFlags(self.review.textInteractionFlags() | TextSelectable)
        layout.addWidget(self.review)
        boundary = QLabel(
            "Bu işlem host üzerinde TI signer'ı çalıştırabilir. OTP/eFuse değiştirmez, lifecycle transition yapmaz ve "
            "hardware/customer enforcement kanıtlamaz."
        )
        boundary.setWordWrap(True); boundary.setObjectName("mutedText"); layout.addWidget(boundary)
        actions = QHBoxLayout()
        dry = QPushButton("Dry Run")
        dry.clicked.connect(lambda: self.run(True))
        build = QPushButton("Build + Post Verify")
        build.setObjectName("primaryAction")
        build.clicked.connect(lambda: self.run(False))
        actions.addWidget(dry); actions.addWidget(build); actions.addStretch(1)
        layout.addLayout(actions)
        layout.addStretch(1)
        return page

    def _result_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        self.result_view = HumanResultView(show_boundary=True)
        layout.addWidget(self.result_view, 1)
        return page

    def _refresh_sdk_ui(self) -> None:
        if not hasattr(self, "sdk_status_detail"):
            return
        env = self.state.environment
        if env is None:
            self.sdk_status_detail.setText("SDK henüz kontrol edilmedi.")
            self.environment_action.setText("Environment'ı Kontrol Et")
        elif env.ready:
            version = env.sdk_version or "sürüm belirlenemedi"
            compatibility = " · doğrulanan baseline" if env.compatibility == "VALIDATED_BASELINE" else " · sürüm ayrıca gözden geçirilmeli"
            self.sdk_status_detail.setText(f"{version} ✓ Hazır{compatibility}")
            self.environment_action.setText("Environment Ayrıntıları")
        else:
            self.sdk_status_detail.setText("SDK/signing araçları hazır değil. Environment kontrolünü gözden geçirin.")
            self.environment_action.setText("Environment'ı Kontrol Et")

        expert = self.state.mode == "expert"
        self.sdk_expert_label.setVisible(expert)
        self.sdk_expert_box.setVisible(expert)

    def _application_input_ready(self) -> bool:
        value = self.input.text().strip()
        if not value:
            return False
        path = Path(value).expanduser()
        return path.exists() and path.is_file()

    def _output_path_ready(self) -> bool:
        value = self.output.text().strip()
        if not value:
            return False
        out_path = Path(value).expanduser()
        input_value = self.input.text().strip()
        try:
            if input_value and out_path.resolve() == Path(input_value).expanduser().resolve():
                return False
        except OSError:
            return False
        # Existing files/directories are deliberately rejected before the review step;
        # build.py enforces the same no-overwrite rule again at execution time.
        return not out_path.exists()

    def _step_ready(self, step: int) -> bool:
        if step == 0:
            return self._application_input_ready()
        if step == 1:
            if not self._secret_file_ready(self.signing):
                return False
            return not self.encrypt.isChecked() or self._secret_file_ready(self.mek)
        if step == 2:
            return self._output_path_ready()
        return True

    def _update_navigation_state(self) -> None:
        if not hasattr(self, "next"):
            return
        step = self.stack.currentIndex()
        ready = step < 3 and self._step_ready(step)
        self.next.setEnabled(ready)
        if step == 0 and not ready:
            value = self.input.text().strip()
            if not value:
                self.next.setToolTip("Devam etmek için bir application dosyası seçin.")
            else:
                self.next.setToolTip("Seçilen application dosyası bulunamadı veya normal bir dosya değil.")
        elif step == 1 and not ready:
            if not self._secret_file_ready(self.signing):
                self.next.setToolTip("Devam etmek için mevcut bir signing private key seçin.")
            elif self.encrypt.isChecked() and not self._secret_file_ready(self.mek):
                self.next.setToolTip("Şifreleme için mevcut bir application MEK seçin.")
        elif step == 2 and not ready:
            value = self.output.text().strip()
            if not value:
                self.next.setToolTip("Devam etmek için bir çıktı dosyası seçin.")
            elif Path(value).expanduser().exists():
                self.next.setToolTip("Bu çıktı zaten mevcut. Studio üzerine yazmaz; farklı bir çıktı seçin.")
            else:
                self.next.setToolTip("Çıktı application input ile aynı dosya olamaz.")
        else:
            self.next.setToolTip("")

    def _toggle_encryption(self, enabled: bool) -> None:
        self.mek_card.setVisible(enabled)
        if not enabled:
            self.mek.setProperty("invalid", False)
            self.mek.style().unpolish(self.mek)
            self.mek.style().polish(self.mek)

    def _validate_step(self, step: int) -> None:
        if step == 0:
            value = require_field(self.input, "Application dosyası")
            path = Path(value).expanduser()
            if not path.exists() or not path.is_file():
                set_field_invalid(self.input, True)
                self.input.setFocus()
                raise FileNotFoundError("Seçilen application dosyası bulunamadı veya normal bir dosya değil")
            set_field_invalid(self.input, False)
        elif step == 1:
            signing = Path(require_field(self.signing, "Signing private key")).expanduser()
            if not signing.exists() or not signing.is_file():
                raise FileNotFoundError("Seçilen signing private key bulunamadı veya normal bir dosya değil")
            if self.encrypt.isChecked():
                mek = Path(require_field(self.mek, "Application MEK")).expanduser()
                if not mek.exists() or not mek.is_file():
                    raise FileNotFoundError("Seçilen application MEK bulunamadı veya normal bir dosya değil")
        elif step == 2:
            output = require_field(self.output, "Çıktı dosyası")
            out_path = Path(output).expanduser()
            input_value = self.input.text().strip()
            if input_value and out_path.resolve() == Path(input_value).expanduser().resolve():
                raise ValueError("Çıktı dosyası application input ile aynı dosya olamaz")
            if out_path.exists():
                raise FileExistsError("Seçilen çıktı zaten mevcut. Studio mevcut dosyanın üzerine sessizce yazmaz; farklı bir çıktı seçin.")

    def _sync_project_output(self, force: bool = False) -> None:
        project = self.state.project
        if not hasattr(self, "project_output_hint"):
            return
        if project is None:
            self.project_output_hint.setText("Aktif bir Proje Çalışma Alanı yok. Çıktı dosyasını manuel seçin.")
            self.use_project_output.setEnabled(False)
            return
        suggested = str(suggest_project_output(
            project, workflow="application", source=self.input.text().strip() or None, encrypted=self.encrypt.isChecked()
        ))
        self.project_output_hint.setText(
            f"Proje önerisi: outputs/{Path(suggested).name} · İsterseniz farklı bir konum seçebilirsiniz."
        )
        self.use_project_output.setEnabled(True)
        current = self.output.text().strip()
        if force or not current or (self._project_output_last is not None and current == self._project_output_last):
            self.output.setText(suggested)
            self._project_output_last = suggested

    def _refresh_review(self) -> None:
        input_name = Path(self.input.text()).name or "—"
        output_name = Path(self.output.text()).name or "—"
        signing_name = "[secret dosya seçildi]" if self.signing.text().strip() else "[seçilmedi]"
        mek_name = "[secret dosya seçildi]" if self.encrypt.isChecked() and self.mek.text().strip() else "Kullanılmayacak"
        protection = "Encrypted + signed" if self.encrypt.isChecked() else "Signed-only"
        sdk_context = "Environment / auto-discovery" if not self.sdk.text().strip() else "Explicit SDK root seçildi"
        self.review.setText(
            f"Application       : {input_name}\n"
            f"Protection        : {protection}\n"
            f"Signing key       : {signing_name} (secret value gösterilmez)\n"
            f"Encryption key    : {mek_name} (secret value gösterilmez)\n"
            f"Output            : {output_name}\n"
            f"SDK               : {sdk_context}\n\n"
            "Build sonrası: certificate parse + host-side verification uygulanır."
        )

    def _set_step(self, index: int) -> None:
        index = max(0, min(index, self.stack.count() - 1))
        self.stack.setCurrentIndex(index)
        if index == 3:
            self._refresh_review()
        for i, label in enumerate(self.step_labels):
            if i < index:
                label.setObjectName("wizardStepDone")
                label.setText(f"✓ {i + 1}. {self.STEP_NAMES[i]}")
            elif i == index:
                label.setObjectName("wizardStepActive")
                label.setText(f"{i + 1}. {self.STEP_NAMES[i]}")
            else:
                label.setObjectName("wizardStepIdle")
                label.setText(f"{i + 1}. {self.STEP_NAMES[i]}")
            label.style().unpolish(label); label.style().polish(label)
        self.back.setEnabled(index > 0 and index < 4)
        self.next.setVisible(index < 3)
        self.next.setEnabled(index < 3 and self._step_ready(index))
        self.start_over.setVisible(index == 4)

    def go_next(self) -> None:
        step = self.stack.currentIndex()
        try:
            self._validate_step(step)
            self._set_step(step + 1)
        except Exception as exc:
            show_guided_error(self, exc, context="Bu adım tamamlanamadı")

    def go_back(self) -> None:
        self._set_step(self.stack.currentIndex() - 1)

    def reset_wizard(self) -> None:
        self.result_view.clear()
        self._set_step(0)

    def run(self, dry_run: bool) -> None:
        try:
            self._validate_step(0); self._validate_step(1); self._validate_step(2)
            env = self.state.environment or resolve_environment(self.sdk.text().strip() or None)
            if self.sdk.text().strip():
                env = resolve_environment(self.sdk.text().strip())
            self.state.set_environment(env)
            result = application_build_workflow(
                environment=env,
                input_image=self.input.text(),
                signing_key=self.signing.text(),
                output=self.output.text(),
                encryption_key=self.mek.text() if self.encrypt.isChecked() else None,
                dry_run=dry_run,
                post_verify=not dry_run,
            ).to_dict()
            self.state.set_last_result(result)
            self.result_view.set_result(result)
            self._set_step(4)
        except Exception as exc:
            show_guided_error(self, exc, context="Application workflow tamamlanamadı")


# Keep tiny aliases local to avoid importing broad Qt namespaces merely for two flags.
from PySide6.QtCore import Qt  # noqa: E402
QtAlignCenter = Qt.AlignCenter
TextSelectable = Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
