from __future__ import annotations

import json
import tempfile
from pathlib import Path

import yaml
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...certificate import build_certificate, render_openssl_config
from ...inspect import inspect_artifact
from ...profiles import save_profile, template_profile, validate_profile, validate_profile_file
from ...services.certificate_center import (
    AUTH_MODES,
    DEBUG_LEVELS,
    SUBJECT_FIELDS,
    add_certificate_to_library,
    certificate_metadata,
    compare_certificate_with_private_key,
    compare_certificates,
    export_certificate,
    export_public_key_der,
    list_certificate_library,
    profile_from_certificate,
    remove_certificate_from_library,
    save_cloned_profile,
)
from ...services.certificate_explorer import certificate_explorer_model
from ...services.claim_boundary import attach_claims
from ...verify import verify_artifact
from ..widgets import HumanResultView, ImageAnatomyWidget, ResultBoundaryPanel
from .common import file_field, save_text_dialog, show_guided_error


class CertificatePage(QWidget):
    """Certificate Center: create, inspect, verify, reissue, export and organize public certs."""

    navigate = Signal(str)

    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        self._last_library_rows: list[dict] = []

        layout = QVBoxLayout(self)
        title = QLabel("Certificate Center")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        help_text = QLabel(
            "AM64x certificate oluşturma ve yönetim işlemlerini burada yapabilirsiniz. "
            "Yeni certificate oluşturabilir, mevcut certificate'ları inceleyip doğrulayabilir, export edebilir ve yeni sürüm üretebilirsiniz."
        )
        help_text.setWordWrap(True)
        help_text.setObjectName("mutedText")
        layout.addWidget(help_text)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._start_tab(), "Başlangıç")
        self.tabs.addTab(self._create_tab(), "Yeni Certificate")
        self.tabs.addTab(self._explore_tab(), "Explorer / Doğrula")
        self.tabs.addTab(self._reissue_tab(), "Yeni Sürüm / Export")
        self.tabs.addTab(self._library_tab(), "Certificate Library")
        self.tabs.addTab(self._contexts_tab(), "ROM / Keywriter / Generic Data")
        self.tabs.addTab(self._profile_tab(), "Uzman Profile")
        self.tabs.addTab(self._compare_tab(), "Karşılaştır")
        layout.addWidget(self.tabs, 3)

        self.boundary = ResultBoundaryPanel()
        self.boundary.setVisible(False)
        layout.addWidget(self.boundary, 1)
        self.state.changed.connect(self._refresh_project_state)
        self.state.mode_changed.connect(self._refresh_mode_ui)
        self._refresh_project_state()
        self._refresh_mode_ui()

    # ---------- shared helpers ----------
    def _publish(self, result: dict, operation: str = "certificate_explore") -> dict:
        status = result.get("status") or result.get("host_side_verification") or "PASS"
        status = status if status in {"PASS", "FAIL", "PARTIAL", "NOT_CHECKED", "NOT_APPLICABLE"} else "PARTIAL"
        result = attach_claims(result, operation, status)
        self.state.set_last_result(result)
        self.boundary.set_result(result)
        self.boundary.setVisible(True)
        return result

    @staticmethod
    def _card(title: str, body: str, button_text: str | None = None, callback=None) -> QFrame:
        card = QFrame()
        card.setObjectName("taskCard")
        lay = QVBoxLayout(card)
        head = QLabel(title)
        head.setObjectName("sectionTitle")
        body_label = QLabel(body)
        body_label.setWordWrap(True)
        body_label.setObjectName("taskCardBody")
        lay.addWidget(head)
        lay.addWidget(body_label, 1)
        if button_text:
            btn = QPushButton(button_text)
            btn.setObjectName("taskCardAction")
            if callback:
                btn.clicked.connect(callback)
            lay.addWidget(btn)
        return card

    def _refresh_project_state(self) -> None:
        if hasattr(self, "library_project_note"):
            if self.state.project:
                self.library_project_note.setText(
                    f"Aktif Project: {self.state.project.name} · Library: public/certificates/"
                )
            else:
                self.library_project_note.setText("Certificate Library için önce bir Project Workspace açın.")
        if hasattr(self, "library_add"):
            self.library_add.setEnabled(self.state.project is not None)
            self.library_refresh.setEnabled(self.state.project is not None)
            self.library_remove.setEnabled(self.state.project is not None)
        if self.state.project and hasattr(self, "library_table"):
            self.refresh_library()


    def _refresh_mode_ui(self, *_args) -> None:
        # Guided mode keeps the first-use surface focused; the raw profile editor remains available in Expert Mode.
        self.tabs.setTabVisible(6, self.state.mode == "expert")

    # ---------- start ----------
    def _start_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        intro = QLabel(
            "Certificate oluşturabilir, mevcut certificate'ları açıp doğrulayabilir, key eşleşmesini kontrol edebilir, "
            "DER/PEM export yapabilir ve mevcut bir certificate'tan yeni sürüm oluşturabilirsiniz."
        )
        intro.setWordWrap(True)
        intro.setObjectName("mutedText")
        layout.addWidget(intro)

        first_use = QLabel(
            "İlk kez kullanıyorsanız Application veya Secure Debug ile başlayın. Studio gerekli alanları adım adım gösterir."
        )
        first_use.setWordWrap(True)
        first_use.setObjectName("mutedText")
        layout.addWidget(first_use)

        grid = QGridLayout()
        grid.addWidget(self._card(
            "Yeni Application Certificate",
            "Subject bilgilerini doldurun, signing key ve payload seçin; Studio gerekli TI alanlarını ve doğrulamaları yönetsin.",
            "Oluşturmaya başla",
            lambda: self._open_create("application"),
        ), 0, 0)
        grid.addWidget(self._card(
            "Yeni Secure Debug Certificate",
            "Subject, SOC UID, debug privilege ve core alanlarını kaynakta tanımlanan kurallarla hazırlayın.",
            "Oluşturmaya başla",
            lambda: self._open_create("debug"),
        ), 0, 1)
        grid.addWidget(self._card(
            "Mevcut Certificate'ı Aç ve İncele",
            "DER/PEM certificate veya certificate+payload image açın; X.509 ve TI alanlarını okuyun ve host-side doğrulayın.",
            "Aç ve incele",
            lambda: self.tabs.setCurrentIndex(2),
        ), 0, 2)
        grid.addWidget(self._card(
            "Yeni Sürüm Oluştur",
            "Mevcut certificate alanlarını yeni forma aktarın, gerekli değişiklikleri yapın ve yeni certificate'ı yeniden imzalayın.",
            "Mevcut certificate'tan başla",
            lambda: self.tabs.setCurrentIndex(3),
        ), 1, 0)
        grid.addWidget(self._card(
            "Certificate Library",
            "Project Workspace içindeki public certificate'ları context ve public fingerprint bilgileriyle düzenleyin.",
            "Library'yi aç",
            lambda: self.tabs.setCurrentIndex(4),
        ), 1, 1)
        grid.addWidget(self._card(
            "ROM / Keywriter / Generic Data",
            "Bu certificate bağlamlarını kendi TI üretim ve preflight akışlarıyla yönetin; generic editor ile karıştırmayın.",
            "Bağlamları göster",
            lambda: self.tabs.setCurrentIndex(5),
        ), 1, 2)
        layout.addLayout(grid)

        compare_row = QHBoxLayout()
        compare_note = QLabel(
            "İki certificate sürümünü Subject, public key, validity, signature ve TI extension alanları üzerinden karşılaştırabilirsiniz."
        )
        compare_note.setWordWrap(True)
        compare_note.setObjectName("mutedText")
        compare_btn = QPushButton("Certificate'ları Karşılaştır")
        compare_btn.clicked.connect(lambda: self.tabs.setCurrentIndex(7))
        compare_row.addWidget(compare_note, 1)
        compare_row.addWidget(compare_btn)
        layout.addLayout(compare_row)

        self.start_technical_toggle = QPushButton("Teknik sınırlar ve güvenlik notları ▸")
        self.start_technical_toggle.setCheckable(True)
        self.start_technical_toggle.setObjectName("secondaryButton")
        self.start_technical_toggle.setToolTip("AM64x certificate context ayrımları ve güvenlik sınırlarını göster")
        layout.addWidget(self.start_technical_toggle)

        self.start_technical_panel = QFrame()
        self.start_technical_panel.setObjectName("infoCard")
        technical_layout = QVBoxLayout(self.start_technical_panel)

        scope_title = QLabel("AM64x certificate kapsamı")
        scope_title.setObjectName("sectionTitle")
        scope_body = QLabel(
            "Studio version-locked AM64x Secure Boot / System Firmware certificate akışlarına odaklanır. "
            "ROM, Application, Secure Debug, Generic Data ve Keywriter context'leri ayrı tutulur. "
            "Genel kurumsal PKI özellikleri bu TI self-signed secure-image/debug akışının parçası olarak kaynaklarda tanımlanmadığında eklenmez."
        )
        scope_body.setWordWrap(True)
        scope_body.setObjectName("mutedText")
        technical_layout.addWidget(scope_title)
        technical_layout.addWidget(scope_body)

        rule_title = QLabel("Certificate yönetim kuralı")
        rule_title.setObjectName("sectionTitle")
        rule_body = QLabel(
            "Signed X.509 certificate doğrudan düzenlenmez. Değişiklik gerektiğinde yeni profile/certificate üretilir ve yeniden imzalanır. "
            "Keywriter certificate hazırlığı OTP/eFuse execution değildir; Secure Debug certificate üretmek JTAG unlock değildir. "
            "Subject bilgisi signing key veya Root of Trust değildir."
        )
        rule_body.setWordWrap(True)
        rule_body.setObjectName("safetyText")
        technical_layout.addWidget(rule_title)
        technical_layout.addWidget(rule_body)

        self.start_technical_panel.setVisible(False)
        self.start_technical_toggle.toggled.connect(self._toggle_start_technical_notes)
        layout.addWidget(self.start_technical_panel)
        layout.addStretch(1)
        return page

    def _toggle_start_technical_notes(self, checked: bool) -> None:
        self.start_technical_panel.setVisible(checked)
        self.start_technical_toggle.setText(
            "Teknik sınırlar ve güvenlik notları ▾" if checked else "Teknik sınırlar ve güvenlik notları ▸"
        )

    def _open_create(self, kind: str) -> None:
        self.tabs.setCurrentIndex(1)
        idx = self.create_kind.findData(kind)
        if idx >= 0:
            self.create_kind.setCurrentIndex(idx)
        self._update_create_context()
        self._set_create_step(0)

    # ---------- create ----------
    def _create_tab(self) -> QWidget:
        """Guided certificate creation wizard.

        Keep Subject, TI context, signing material and outputs in separate steps so
        first-time users do not have to reason about the whole X.509 profile at once.
        The underlying profile/build functions remain the same source-backed engine.
        """
        page = QWidget()
        root = QVBoxLayout(page)

        top = QFrame(); top.setObjectName("infoCard")
        tl = QHBoxLayout(top)
        self.create_kind = QComboBox()
        self.create_kind.addItem("Application", "application")
        self.create_kind.addItem("Secure Debug", "debug")
        self.create_kind.currentIndexChanged.connect(self._update_create_context)
        tl.addWidget(QLabel("Certificate türü"))
        tl.addWidget(self.create_kind)
        tl.addStretch(1)
        root.addWidget(top)

        # Compact progress bar. It is intentionally informational; navigation happens
        # with Geri/Devam so a user cannot silently skip mandatory fields.
        progress = QFrame(); progress.setObjectName("wizardStepBar")
        pl = QHBoxLayout(progress)
        self.create_step_labels: list[QLabel] = []
        for text in ("1. Kimlik", "2. TI Alanları", "3. Signing Key", "4. Çıktı", "5. Kontrol"):
            label = QLabel(text)
            label.setAlignment(Qt.AlignCenter)
            label.setObjectName("wizardStepIdle")
            self.create_step_labels.append(label)
            pl.addWidget(label, 1)
        root.addWidget(progress)

        self.create_wizard = QStackedWidget()

        # ----- Step 1: Subject / identity -----
        identity = QWidget(); il = QVBoxLayout(identity)
        subject_card = QFrame(); subject_card.setObjectName("infoCard")
        sl = QVBoxLayout(subject_card)
        sh = QLabel("1 · Subject / Kimlik"); sh.setObjectName("sectionTitle")
        sn = QLabel(
            "Certificate üzerinde görülecek X.509 kimlik bilgilerini girin. Yalnız Common Name (CN) zorunludur; "
            "diğer Subject alanları isteğe bağlıdır. Subject bilgisi signing key veya Root of Trust değildir."
        )
        sn.setWordWrap(True); sn.setObjectName("mutedText")
        sl.addWidget(sh); sl.addWidget(sn)
        form = QFormLayout()
        self.subject_edits: dict[str, QLineEdit] = {}
        placeholders = {
            "country": "örn. TR",
            "state": "örn. Ankara",
            "locality": "örn. Ankara",
            "organization": "örn. Company / Project",
            "organizational_unit": "örn. Embedded Software",
            "common_name": "örn. AM64x Secure Application",
            "email": "isteğe bağlı",
        }
        for key, label, _oid in SUBJECT_FIELDS:
            edit = QLineEdit(); edit.setPlaceholderText(placeholders[key])
            if key == "country": edit.setMaxLength(2)
            self.subject_edits[key] = edit
            row_label = label + (" *" if key == "common_name" else "")
            form.addRow(row_label, edit)
        sl.addLayout(form)
        il.addWidget(subject_card)

        common = QFrame(); common.setObjectName("infoCard")
        cl = QFormLayout(common)
        self.valid_days = QSpinBox(); self.valid_days.setRange(1, 36500); self.valid_days.setValue(3650)
        cl.addRow("Geçerlilik süresi (gün)", self.valid_days)
        common_note = QLabel(
            "Geçerlilik süresi host-side X.509 validity bilgisidir; tek başına target acceptance veya rollback enforcement kanıtı değildir."
        )
        common_note.setWordWrap(True); common_note.setObjectName("mutedText")
        cl.addRow("Not", common_note)
        il.addWidget(common)

        self.create_mechanics_toggle = QPushButton("Teknik certificate ayrıntıları ▸")
        self.create_mechanics_toggle.setCheckable(True)
        self.create_mechanics_toggle.setObjectName("secondaryButton")
        il.addWidget(self.create_mechanics_toggle)
        self.create_mechanics = QFrame(); self.create_mechanics.setObjectName("infoCard")
        ml = QFormLayout(self.create_mechanics)
        ml.addRow("Issuer", QLabel("Subject ile aynı (self-signed X.509)"))
        ml.addRow("Serial number", QLabel("Otomatik / cryptographic random"))
        ml.addRow("Public key", QLabel("Seçilen RSA-4096 signing key'in public tarafı"))
        ml.addRow("Certificate signature", QLabel("RSA + SHA-512"))
        ml.addRow("Basic Constraints", QLabel("CA=true · TI template davranışıyla uyumlu"))
        self.create_mechanics.setVisible(False)
        self.create_mechanics_toggle.toggled.connect(self._toggle_create_mechanics)
        il.addWidget(self.create_mechanics)
        il.addStretch(1)
        self.create_wizard.addWidget(identity)

        # ----- Step 2: TI context fields -----
        context = QWidget(); ctl = QVBoxLayout(context)
        ti_meta = QFrame(); ti_meta.setObjectName("infoCard")
        tml = QFormLayout(ti_meta)
        self.swrev = QSpinBox(); self.swrev.setRange(0, 0x7FFFFFFF); self.swrev.setValue(1)
        tml.addRow("Software Revision", self.swrev)
        swrev_note = QLabel(
            "Software Revision TI certificate metadata'sının parçasıdır. Subject/Kimlik alanı değildir; tek başına target rollback enforcement kanıtı değildir."
        )
        swrev_note.setWordWrap(True); swrev_note.setObjectName("mutedText")
        tml.addRow("Not", swrev_note)
        ctl.addWidget(ti_meta)
        self.create_stack = QStackedWidget()
        self.create_stack.addWidget(self._application_fields())
        self.create_stack.addWidget(self._debug_fields())
        ctl.addWidget(self.create_stack)
        ctl.addStretch(1)
        self.create_wizard.addWidget(context)

        # ----- Step 3: signing key -----
        signing = QWidget(); skl = QVBoxLayout(signing)
        sign_card = QFrame(); sign_card.setObjectName("infoCard")
        sg = QGridLayout(sign_card)
        sign_head = QLabel("3 · Signing Key"); sign_head.setObjectName("sectionTitle")
        sign_note = QLabel(
            "Certificate RSA-4096 private signing key ile imzalanır. Private key değeri ve secret path proje metadata'sına kaydedilmez. "
            "Yeni development/test key gerekiyorsa Key Center'dan oluşturabilirsiniz."
        )
        sign_note.setWordWrap(True); sign_note.setObjectName("mutedText")
        sg.addWidget(sign_head, 0, 0, 1, 3); sg.addWidget(sign_note, 1, 0, 1, 3)
        self.create_key, keybox = file_field(sign_card, "RSA-4096 private signing key seç", secret=True)
        sg.addWidget(QLabel("Signing private key *"), 2, 0); sg.addWidget(keybox, 2, 1, 1, 2)
        key_help = QPushButton("Key Center'ı Aç"); key_help.clicked.connect(lambda: self.navigate.emit("keys")); sg.addWidget(key_help, 3, 2)
        skl.addWidget(sign_card); skl.addStretch(1)
        self.create_wizard.addWidget(signing)

        # ----- Step 4: outputs -----
        outputs = QWidget(); ol = QVBoxLayout(outputs)
        out_card = QFrame(); out_card.setObjectName("infoCard")
        og = QGridLayout(out_card)
        out_head = QLabel("4 · Çıktı"); out_head.setObjectName("sectionTitle")
        out_note = QLabel(
            "Üretilecek DER certificate için ayrı bir output seçin. Studio mevcut dosyanın üzerine sessizce yazmaz. "
            "PEM/Profile/OpenSSL config gibi ek çıktılar isteğe bağlıdır."
        )
        out_note.setWordWrap(True); out_note.setObjectName("mutedText")
        og.addWidget(out_head, 0, 0, 1, 3); og.addWidget(out_note, 1, 0, 1, 3)
        self.create_der, derbox = file_field(out_card, "DER certificate output", save=True)
        og.addWidget(QLabel("DER certificate *"), 2, 0); og.addWidget(derbox, 2, 1, 1, 2)
        ol.addWidget(out_card)

        self.create_extra_outputs_toggle = QPushButton("İsteğe bağlı ek çıktılar ▸")
        self.create_extra_outputs_toggle.setCheckable(True)
        self.create_extra_outputs_toggle.setObjectName("secondaryButton")
        ol.addWidget(self.create_extra_outputs_toggle)
        self.create_extra_outputs = QFrame(); self.create_extra_outputs.setObjectName("infoCard")
        eg = QGridLayout(self.create_extra_outputs)
        self.create_pem, pembox = file_field(self.create_extra_outputs, "İsteğe bağlı PEM certificate output", save=True)
        eg.addWidget(QLabel("PEM export"), 0, 0); eg.addWidget(pembox, 0, 1, 1, 2)
        self.create_profile_output, pobox = file_field(self.create_extra_outputs, "İsteğe bağlı YAML profile output", save=True)
        eg.addWidget(QLabel("Profile export"), 1, 0); eg.addWidget(pobox, 1, 1, 1, 2)
        self.create_config_output, cobox = file_field(self.create_extra_outputs, "İsteğe bağlı OpenSSL config output", save=True)
        eg.addWidget(QLabel("OpenSSL config"), 2, 0); eg.addWidget(cobox, 2, 1, 1, 2)
        self.create_package, pkgbox = file_field(self.create_extra_outputs, "İsteğe bağlı certificate + plaintext payload package", save=True)
        self.create_package_label = QLabel("Application package")
        eg.addWidget(self.create_package_label, 3, 0); eg.addWidget(pkgbox, 3, 1, 1, 2)
        self.create_package_box = pkgbox
        self.create_extra_outputs.setVisible(False)
        self.create_extra_outputs_toggle.toggled.connect(self._toggle_create_extra_outputs)
        ol.addWidget(self.create_extra_outputs); ol.addStretch(1)
        self.create_wizard.addWidget(outputs)

        # ----- Step 5: review / build -----
        review = QWidget(); rl = QVBoxLayout(review)
        review_card = QFrame(); review_card.setObjectName("infoCard")
        rv = QVBoxLayout(review_card)
        review_head = QLabel("5 · Kontrol ve Üretim"); review_head.setObjectName("sectionTitle")
        review_note = QLabel(
            "Üretmeden önce seçimlerinizi kontrol edin. Certificate oluşturma host-side işlemdir; hardware/customer Root of Trust enforcement kanıtı değildir."
        )
        review_note.setWordWrap(True); review_note.setObjectName("mutedText")
        self.create_review = QLabel(); self.create_review.setWordWrap(True)
        rv.addWidget(review_head); rv.addWidget(review_note); rv.addWidget(self.create_review)
        rl.addWidget(review_card)

        action_row = QHBoxLayout()
        validate_btn = QPushButton("Formu Doğrula"); validate_btn.clicked.connect(self.validate_create_form)
        profile_btn = QPushButton("Profile Kaydet"); profile_btn.clicked.connect(self.save_create_profile)
        build_btn = QPushButton("Certificate Oluştur + Doğrula"); build_btn.setObjectName("primaryAction"); build_btn.clicked.connect(self.build_create_certificate)
        self.create_secure_boot_btn = QPushButton("Secure Boot'ta Kullan")
        self.create_secure_boot_btn.setEnabled(False)
        self.create_secure_boot_btn.clicked.connect(lambda: self.navigate.emit("secure_boot"))
        action_row.addWidget(validate_btn); action_row.addWidget(profile_btn); action_row.addStretch(1); action_row.addWidget(build_btn)
        action_row.addWidget(self.create_secure_boot_btn)
        rl.addLayout(action_row)
        self.create_result = HumanResultView(show_boundary=False)
        rl.addWidget(self.create_result, 1)
        self.create_wizard.addWidget(review)

        # Keep the active wizard step reachable at ordinary laptop/window sizes.
        # QStackedWidget otherwise advertises the tallest step and Qt compresses
        # line edits before offering any way to scroll.
        self.create_wizard_scroll = QScrollArea()
        self.create_wizard_scroll.setObjectName("wizardScroll")
        self.create_wizard_scroll.setWidgetResizable(True)
        self.create_wizard_scroll.setFrameShape(QFrame.NoFrame)
        self.create_wizard_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.create_wizard_scroll.setWidget(self.create_wizard)
        root.addWidget(self.create_wizard_scroll, 1)

        self.create_nav = QWidget()
        nav = QHBoxLayout(self.create_nav)
        nav.setContentsMargins(0, 0, 0, 0)
        self.create_back = QPushButton("← Geri"); self.create_back.clicked.connect(self._prev_create_step)
        self.create_next = QPushButton("Devam →"); self.create_next.setObjectName("primaryAction"); self.create_next.clicked.connect(self._next_create_step)
        nav.addWidget(self.create_back); nav.addStretch(1); nav.addWidget(self.create_next)
        root.addWidget(self.create_nav)

        # Live gating: required fields control Devam immediately instead of waiting
        # for a modal error after the user clicks.
        self.subject_edits["common_name"].textChanged.connect(self._update_create_navigation_state)
        self.app_input.textChanged.connect(self._update_create_navigation_state)
        self.app_dest.textChanged.connect(self._update_create_navigation_state)
        self.app_auth.currentIndexChanged.connect(self._update_create_navigation_state)
        self.app_host.textChanged.connect(self._update_create_navigation_state)
        self.debug_uid.textChanged.connect(self._update_create_navigation_state)
        self.debug_wildcard.toggled.connect(self._update_create_navigation_state)
        self.create_key.textChanged.connect(self._update_create_navigation_state)
        self.create_der.textChanged.connect(self._update_create_navigation_state)

        self._set_create_step(0)
        self._update_create_context()
        return page

    def _toggle_create_mechanics(self, checked: bool) -> None:
        self.create_mechanics.setVisible(bool(checked))
        self.create_mechanics_toggle.setText(
            "Certificate mechanics / teknik ayrıntılar ▾" if checked else "Teknik certificate ayrıntıları ▸"
        )

    def _toggle_create_extra_outputs(self, checked: bool) -> None:
        self.create_extra_outputs.setVisible(bool(checked))
        self.create_extra_outputs_toggle.setText(
            "İsteğe bağlı ek çıktılar ▾" if checked else "İsteğe bağlı ek çıktılar ▸"
        )

    def _set_create_step(self, index: int) -> None:
        if not hasattr(self, "create_wizard"):
            return
        index = max(0, min(index, self.create_wizard.count() - 1))
        self.create_wizard.setCurrentIndex(index)
        names = ("Kimlik", "TI Alanları", "Signing Key", "Çıktı", "Kontrol")
        for i, label in enumerate(self.create_step_labels):
            if i < index:
                label.setObjectName("wizardStepDone")
                label.setText(f"✓ {i + 1}. {names[i]}")
            elif i == index:
                label.setObjectName("wizardStepActive")
                label.setText(f"{i + 1}. {names[i]}")
            else:
                label.setObjectName("wizardStepIdle")
                label.setText(f"{i + 1}. {names[i]}")
            label.style().unpolish(label); label.style().polish(label)
        self.create_back.setEnabled(index > 0)
        self.create_next.setVisible(index < self.create_wizard.count() - 1)
        self._update_create_navigation_state()
        if index == self.create_wizard.count() - 1:
            self._refresh_create_review()

    def _create_step_readiness(self, step: int) -> tuple[bool, str]:
        """Return whether the current wizard step is complete enough to proceed.

        This is live UI gating only. Exact parsing/source-backed semantic validation
        still runs in _validate_create_step when the user proceeds.
        """
        if step == 0:
            if not self.subject_edits["common_name"].text().strip():
                return False, "Devam etmek için Common Name (CN) alanını doldurun."
            return True, ""

        if step == 1:
            kind = self.create_kind.currentData()
            if kind == "application":
                if not self.app_input.text().strip():
                    return False, "Devam etmek için Payload / application dosyasını seçin."
                if not self.app_dest.text().strip():
                    return False, "Devam etmek için source-verified Destination Address girin."
                if self.app_auth.currentData() is None:
                    return False, "Devam etmek için Yükleme davranışını seçin."
                if not self.app_host.text().strip():
                    return False, "Devam etmek için source-verified Destination Host ID girin."
                return True, ""
            if not self.debug_wildcard.isChecked() and not self.debug_uid.text().strip():
                return False, "Devam etmek için SOC UID girin veya Wildcard UID seçin."
            return True, ""

        if step == 2:
            if not self.create_key.text().strip():
                return False, "Devam etmek için RSA-4096 private signing key seçin."
            return True, ""

        if step == 3:
            if not self.create_der.text().strip():
                return False, "Devam etmek için DER certificate output seçin."
            return True, ""

        return True, ""

    def _update_create_navigation_state(self, *_args) -> None:
        if not hasattr(self, "create_wizard") or not hasattr(self, "create_next"):
            return
        step = self.create_wizard.currentIndex()
        if step >= self.create_wizard.count() - 1:
            return
        ready, reason = self._create_step_readiness(step)
        self.create_next.setEnabled(ready)
        self.create_next.setToolTip("" if ready else reason)

    def _prev_create_step(self) -> None:
        self._set_create_step(self.create_wizard.currentIndex() - 1)

    def _next_create_step(self) -> None:
        try:
            self._validate_create_step(self.create_wizard.currentIndex())
            self._set_create_step(self.create_wizard.currentIndex() + 1)
        except Exception as exc:
            show_guided_error(self, exc, context="Bu adım tamamlanamadı")

    def _validate_create_step(self, step: int) -> None:
        if step == 0:
            cn = self.subject_edits["common_name"].text().strip()
            if not cn:
                raise ValueError("Common Name (CN) alanını doldurun")
            country = self.subject_edits["country"].text().strip()
            if country and (len(country) != 2 or not country.isascii() or not country.isalpha()):
                raise ValueError("Country (C) girilecekse iki ASCII harf olmalıdır; örn. TR")
            email = self.subject_edits["email"].text().strip()
            if email and (not email.isascii() or "@" not in email or any(ch.isspace() for ch in email)):
                raise ValueError("Email girilecekse geçerli ASCII email biçimi kullanın")
            return
        if step == 1:
            kind = self.create_kind.currentData()
            if kind == "application":
                if not self.app_input.text().strip():
                    raise ValueError("Payload / application dosyasını seçin")
                if not self.app_dest.text().strip():
                    raise ValueError("Destination Address için source-verified değer girin")
                if self.app_auth.currentData() is None:
                    raise ValueError("Yükleme davranışını seçin")
                if not self.app_host.text().strip():
                    raise ValueError("Destination Host ID için source-verified değer girin")
            else:
                if not self.debug_wildcard.isChecked() and not self.debug_uid.text().strip():
                    raise ValueError("SOC UID girin veya açıkça Wildcard UID seçin")
            return
        if step == 2:
            if not self.create_key.text().strip():
                raise ValueError("RSA-4096 private signing key seçin")
            return
        if step == 3:
            if not self.create_der.text().strip():
                raise ValueError("DER certificate output seçin")

    def _refresh_create_review(self) -> None:
        kind = str(self.create_kind.currentData())
        subject = self.subject_edits["common_name"].text().strip() or "—"
        key_state = "seçildi" if self.create_key.text().strip() else "seçilmedi"
        der_name = Path(self.create_der.text()).name if self.create_der.text().strip() else "—"
        if kind == "application":
            payload = Path(self.app_input.text()).name if self.app_input.text().strip() else "—"
            auth = self.app_auth.currentText() if self.app_auth.currentData() is not None else "—"
            context_text = (
                f"Application: {payload}\n"
                f"Load mode: {auth}\n"
                f"Destination/Host ID: kullanıcı tarafından source-verified olarak girildi"
            )
        else:
            uid_mode = "Wildcard UID" if self.debug_wildcard.isChecked() else "Device-specific SOC UID"
            context_text = f"Secure Debug: {uid_mode}\nPrivilege: {self.debug_priv.currentText()}"
        self.create_review.setText(
            f"Certificate türü: {'Application' if kind == 'application' else 'Secure Debug'}\n"
            f"Common Name: {subject}\n"
            f"Software Revision: {self.swrev.value()}\n"
            f"Validity: {self.valid_days.value()} gün\n"
            f"{context_text}\n"
            f"Signing key: {key_state} (secret path gösterilmez)\n"
            f"DER output: {der_name}"
        )

    def _application_fields(self) -> QWidget:
        page = QFrame(); page.setObjectName("infoCard")
        layout = QVBoxLayout(page)
        head = QLabel("2 · Application / System Firmware Alanları"); head.setObjectName("sectionTitle"); layout.addWidget(head)
        note = QLabel(
            "Image Integrity SHA2-512 ve image size payload'dan otomatik hesaplanır. "
            "Studio, Yükleme davranışı ve Destination Host ID seçimlerini TI certificate formatındaki auth_type alanında otomatik birleştirir. "
            "Load/Boot değerleri target-specific'tir; Studio adres/core/flag tahmin etmez."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)
        enc_note = QFrame(); enc_note.setObjectName("safetyNote")
        enl = QHBoxLayout(enc_note)
        ent = QLabel("Şifreli application oluşturmak mı istiyorsunuz? Studio bu işlem için kurulu TI appimage_x509_cert_gen.py aracını kullanır.")
        ent.setWordWrap(True); ent.setObjectName("safetyText")
        enb = QPushButton("Şifreli Secure Application'a Git"); enb.clicked.connect(lambda: self.navigate.emit("application"))
        enl.addWidget(ent, 1); enl.addWidget(enb)
        layout.addWidget(enc_note)
        form = QFormLayout()
        self.app_input, box = file_field(page, "Application/generalized-auth payload dosyasını seç")
        form.addRow("Payload / application *", box)
        self.app_dest = QLineEdit(); self.app_dest.setPlaceholderText("örn. 0x... — exact source/build recipe ile doğrulanmış değer")
        form.addRow("Destination Address *", self.app_dest)
        self.app_auth = QComboBox(); self.app_auth.addItem("Seçin", None)
        mode_labels = {
            0: "Normal — payload Destination Address'e kopyalanır (0)",
            1: "In-place — payload bulunduğu yerde doğrulanır (1)",
            2: "In-place variant (2)",
        }
        for value, name, meaning in AUTH_MODES:
            self.app_auth.addItem(mode_labels.get(value, f"{name} ({value})"), value)
            self.app_auth.setItemData(self.app_auth.count() - 1, meaning, Qt.ToolTipRole)
        form.addRow("Yükleme davranışı *", self.app_auth)
        self.app_host = QLineEdit(); self.app_host.setPlaceholderText("0..255 — yalnız source-verified Host ID/context")
        form.addRow("Destination Host ID *", self.app_host)
        layout.addLayout(form)
        required_note = QLabel("* işaretli alanlar tamamlanmadan Devam etkinleşmez. Target-specific değerler yalnız source-verified bilgiyle girilmelidir.")
        required_note.setWordWrap(True)
        required_note.setObjectName("mutedText")
        layout.addWidget(required_note)

        self.app_auth_technical_toggle = QPushButton("Teknik auth_type ayrıntıları ▸")
        self.app_auth_technical_toggle.setCheckable(True)
        self.app_auth_technical_toggle.setObjectName("secondaryButton")
        layout.addWidget(self.app_auth_technical_toggle)
        self.app_auth_technical = QFrame(); self.app_auth_technical.setObjectName("infoCard")
        atl = QVBoxLayout(self.app_auth_technical)
        auth_detail = QLabel(
            "System Firmware Load Extension içindeki auth_type tek bir INTEGER'dır: "
            "auth_type[7:0] Yükleme davranışını (0/1/2), auth_type[15:8] Destination Host ID'yi taşır; "
            "üst bitler reserved'dır. Studio iki GUI seçimini certificate üretirken tek auth_type değerinde birleştirir."
        )
        auth_detail.setWordWrap(True); auth_detail.setObjectName("mutedText"); atl.addWidget(auth_detail)
        self.app_auth_technical.setVisible(False)
        self.app_auth_technical_toggle.toggled.connect(self._toggle_app_auth_technical)
        layout.addWidget(self.app_auth_technical)

        self.boot_enabled = QCheckBox("Processor boot bilgilerini ekle")
        self.boot_enabled.setToolTip("Yalnız bu certificate bir core'u boot etmek için kullanılacaksa gerekir.")
        self.boot_enabled.toggled.connect(self._toggle_boot_fields)
        layout.addWidget(self.boot_enabled)
        self.boot_box = QFrame(); self.boot_box.setObjectName("safetyNote")
        bf = QFormLayout(self.boot_box)
        self.boot_core = QLineEdit(); self.boot_core.setPlaceholderText("source-verified Processor ID")
        self.boot_set = QLineEdit(); self.boot_set.setPlaceholderText("source-verified configFlags_set")
        self.boot_clr = QLineEdit(); self.boot_clr.setPlaceholderText("source-verified configFlags_clr")
        self.boot_reset = QLineEdit(); self.boot_reset.setPlaceholderText("source-verified reset vector")
        self.boot_valid = QLineEdit(); self.boot_valid.setPlaceholderText("source-verified fieldValid")
        bf.addRow("bootCore", self.boot_core); bf.addRow("configFlags_set", self.boot_set); bf.addRow("configFlags_clr", self.boot_clr)
        bf.addRow("resetVec", self.boot_reset); bf.addRow("fieldValid", self.boot_valid)
        layout.addWidget(self.boot_box)
        self.boot_box.setVisible(False)
        return page

    def _debug_fields(self) -> QWidget:
        page = QFrame(); page.setObjectName("infoCard")
        layout = QVBoxLayout(page)
        head = QLabel("2 · Secure Debug Alanları"); head.setObjectName("sectionTitle"); layout.addWidget(head)
        note = QLabel(
            "System Firmware Debug Extension ve SWREV zorunludur. Certificate üretmek target JTAG unlock değildir. Processor ID'leri source'tan doğrulanmalıdır."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)
        form = QFormLayout()
        self.debug_uid = QLineEdit(); self.debug_uid.setPlaceholderText("64 hex karakter / 32-byte SOC UID")
        form.addRow("SOC UID", self.debug_uid)
        self.debug_wildcard = QCheckBox("Wildcard UID kullan (all-zero UID)")
        self.debug_wildcard.toggled.connect(self._toggle_wildcard)
        form.addRow("Wildcard", self.debug_wildcard)
        self.debug_priv = QComboBox()
        for value, name, meaning in DEBUG_LEVELS:
            self.debug_priv.addItem(f"{value} · {name}", value)
            self.debug_priv.setItemData(self.debug_priv.count() - 1, meaning, Qt.ToolTipRole)
        form.addRow("Debug privilege", self.debug_priv)
        self.debug_ns = QLineEdit(); self.debug_ns.setPlaceholderText("örn. 0x01,0x02 veya none → 0xFF")
        self.debug_sec = QLineEdit(); self.debug_sec.setPlaceholderText("örn. 0x20,0x21 veya none → 0xFF")
        form.addRow("Non-secure Processor IDs", self.debug_ns)
        form.addRow("Secure Processor IDs", self.debug_sec)
        layout.addLayout(form)
        warn = QLabel("Wildcard UID yalnız Security Board Configuration allow_wildcard_unlock politikasına izin veriyorsa anlamlıdır.")
        warn.setWordWrap(True); warn.setObjectName("safetyText"); layout.addWidget(warn)
        return page

    def _toggle_app_auth_technical(self, checked: bool) -> None:
        self.app_auth_technical.setVisible(bool(checked))
        self.app_auth_technical_toggle.setText(
            "Teknik auth_type ayrıntıları ▾" if checked else "Teknik auth_type ayrıntıları ▸"
        )

    def _toggle_boot_fields(self, enabled: bool) -> None:
        self.boot_box.setVisible(bool(enabled))

    def _toggle_wildcard(self, enabled: bool) -> None:
        if enabled:
            self.debug_uid.setText("00" * 32)
            self.debug_uid.setEnabled(False)
        else:
            self.debug_uid.setEnabled(True)
            if self.debug_uid.text() == "00" * 32:
                self.debug_uid.clear()

    def _update_create_context(self) -> None:
        if not hasattr(self, "create_stack"):
            return
        kind = self.create_kind.currentData()
        self.create_stack.setCurrentIndex(0 if kind == "application" else 1)
        app = kind == "application"
        self.create_package_label.setVisible(app)
        self.create_package_box.setVisible(app)
        if not app:
            self.create_package.clear()
        # Natural CN default only when user hasn't already entered a value.
        if not self.subject_edits["common_name"].text().strip():
            self.subject_edits["common_name"].setPlaceholderText(
                "AM64x Secure Application" if app else "AM64x Secure Debug Certificate"
            )
        self._update_create_navigation_state()

    @staticmethod
    def _parse_ids(text: str) -> list[int]:
        raw = text.strip()
        if not raw or raw.lower() in {"none", "no", "yok"}:
            return [255]
        values: list[int] = []
        for token in raw.replace(";", ",").split(","):
            token = token.strip()
            if not token:
                continue
            values.append(int(token, 0))
        return values or [255]

    def _profile_from_create_form(self) -> dict:
        subject = {key: edit.text().strip() for key, edit in self.subject_edits.items() if edit.text().strip()}
        kind = str(self.create_kind.currentData())
        if kind == "application":
            auth = self.app_auth.currentData()
            if auth is None:
                raise ValueError("Yükleme davranışını seçin; Studio bu target-specific değeri tahmin etmez")
            profile: dict = {
                "type": "application",
                "subject": subject,
                "input": self.app_input.text().strip(),
                "software_revision": self.swrev.value(),
                "load": {
                    "dest_addr": self.app_dest.text().strip(),
                    "auth_mode": int(auth),
                    "copy_as_host": self.app_host.text().strip(),
                },
                "boot": {"enabled": self.boot_enabled.isChecked()},
                "valid_days": self.valid_days.value(),
            }
            if self.boot_enabled.isChecked():
                profile["boot"].update({
                    "boot_core": self.boot_core.text().strip(),
                    "config_flags_set": self.boot_set.text().strip(),
                    "config_flags_clr": self.boot_clr.text().strip(),
                    "reset_vector": self.boot_reset.text().strip(),
                    "field_valid": self.boot_valid.text().strip(),
                })
            return profile
        return {
            "type": "debug",
            "subject": subject,
            "software_revision": self.swrev.value(),
            "debug": {
                "soc_uid": self.debug_uid.text().strip(),
                "wildcard_uid": self.debug_wildcard.isChecked(),
                "privilege": int(self.debug_priv.currentData()),
                "reserved": 0,
                "nonsecure_core_ids": self._parse_ids(self.debug_ns.text()),
                "secure_core_ids": self._parse_ids(self.debug_sec.text()),
            },
            "valid_days": self.valid_days.value(),
        }

    def validate_create_form(self) -> None:
        try:
            profile = self._profile_from_create_form()
            result = validate_profile(profile)
            result.update({"operation": "certificate_profile", "summary": "Certificate form alanları host-side doğrulandı."})
            result = self._publish(result, "certificate_profile")
            self.create_result.set_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Certificate form doğrulanamadı")

    def save_create_profile(self) -> None:
        try:
            profile = self._profile_from_create_form()
            check = validate_profile(profile)
            if check["status"] != "PASS":
                raise ValueError("profile doğrulaması başarısız: " + "; ".join(check["issues"]))
            path, _ = QFileDialog.getSaveFileName(self, "Certificate profile kaydet", filter="YAML (*.yaml *.yml)")
            if not path:
                return
            p = Path(path)
            if p.suffix.lower() not in {".yaml", ".yml"}:
                p = p.with_suffix(".yaml")
            save_profile(profile, p)
            result = self._publish({
                "status": "PASS", "operation": "certificate_profile", "summary": "Certificate profile kaydedildi.",
                "outputs": [{"type": "certificate_profile", "path": str(p)}],
            }, "certificate_profile")
            self.create_result.set_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Certificate profile kaydedilemedi")

    def build_create_certificate(self) -> None:
        temp_profile: Path | None = None
        try:
            profile = self._profile_from_create_form()
            validation = validate_profile(profile)
            if validation["status"] != "PASS":
                raise ValueError("profile doğrulaması başarısız: " + "; ".join(validation["issues"]))
            if not self.create_key.text().strip():
                raise ValueError("RSA-4096 private signing key seçin")
            if not self.create_der.text().strip():
                raise ValueError("DER certificate output seçin")
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", delete=False) as fh:
                yaml.safe_dump(profile, fh, sort_keys=False, allow_unicode=True)
                temp_profile = Path(fh.name)
            result = build_certificate(
                temp_profile,
                self.create_key.text(),
                self.create_der.text(),
                package=self.create_package.text().strip() or None,
            )
            outputs = [{"type": "certificate_der", "path": self.create_der.text()}]
            if self.create_pem.text().strip():
                pem_result = export_certificate(self.create_der.text(), self.create_pem.text(), encoding="pem")
                outputs.extend(pem_result.get("outputs", []))
            if self.create_profile_output.text().strip():
                save_profile(profile, self.create_profile_output.text())
                outputs.append({"type": "certificate_profile", "path": self.create_profile_output.text()})
            if self.create_config_output.text().strip():
                out = Path(self.create_config_output.text())
                if out.exists():
                    raise FileExistsError(f"OpenSSL config zaten mevcut: {out}")
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(render_openssl_config(temp_profile), encoding="utf-8")
                outputs.append({"type": "openssl_config", "path": str(out)})
            verification = verify_artifact(self.create_package.text().strip() or self.create_der.text())
            metadata = certificate_metadata(self.create_der.text())
            status = verification.get("overall_host_side_verification", "PARTIAL")
            result.update({
                "status": status if status in {"PASS", "FAIL", "PARTIAL"} else "PARTIAL",
                "operation": "certificate_build",
                "summary": "Certificate yeni Subject/TI extension değerleriyle üretildi ve host-side doğrulandı.",
                "verification": verification,
                "metadata": {
                    "subject": metadata["subject_rfc4514"],
                    "issuer": metadata["issuer_rfc4514"],
                    "serial_number": metadata["serial_number_hex"],
                    "valid_from": metadata["not_valid_before"],
                    "valid_until": metadata["not_valid_after"],
                    "validity_state": metadata["validity_state"],
                    "spki_sha256": metadata["spki_sha256"],
                    "signature_algorithm_oid": metadata["signature_algorithm_oid"],
                    "signature_hash_algorithm": metadata["signature_hash_algorithm"],
                    "basic_constraints": metadata["basic_constraints"],
                },
                "outputs": outputs,
            })
            if str(self.create_kind.currentData()) == "application":
                identity_match = compare_certificate_with_private_key(
                    self.create_der.text(), self.create_key.text()
                )
                if identity_match.get("status") != "PASS":
                    raise ValueError("Üretilen application certificate ile signing private key eşleşmedi")
                self.state.set_signing_identity(
                    certificate_path=self.create_der.text(),
                    private_key_path=self.create_key.text(),
                )
                result["secure_boot_handoff"] = {
                    "status": "PASS",
                    "certificate_name": Path(self.create_der.text()).name,
                    "spki_sha256": metadata["spki_sha256"],
                    "note": "Certificate kimliği ve eşleşen private key bu Studio oturumundaki Secure Boot akışına aktarıldı.",
                }
                result["summary"] += " Certificate kimliği Secure Boot akışına seçildi."
                self.create_secure_boot_btn.setEnabled(True)
            published = self._publish(result, "certificate_profile")
            self.create_result.set_result(published)
        except Exception as exc:
            show_guided_error(self, exc, context="Certificate üretilemedi")
        finally:
            if temp_profile is not None:
                try: temp_profile.unlink(missing_ok=True)
                except Exception: pass

    # ---------- explorer ----------
    def _explore_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        row = QHBoxLayout(); self.path = QLineEdit(); self.path.setPlaceholderText("DER/PEM certificate veya certificate+payload image")
        row.addWidget(self.path); pick = QPushButton("Seç"); pick.clicked.connect(self.choose); row.addWidget(pick); layout.addLayout(row)
        actions = QHBoxLayout()
        inspect_btn = QPushButton("Explorer Aç"); inspect_btn.clicked.connect(lambda: self.run(False))
        verify_btn = QPushButton("Explorer + Host Verify"); verify_btn.setObjectName("primaryAction"); verify_btn.clicked.connect(lambda: self.run(True))
        actions.addWidget(inspect_btn); actions.addWidget(verify_btn); actions.addStretch(1); layout.addLayout(actions)

        self.context = QLabel("Henüz certificate seçilmedi."); self.context.setWordWrap(True); self.context.setObjectName("mutedText"); layout.addWidget(self.context)
        anatomy_title = QLabel("Certificate ↔ Image Anatomy"); anatomy_title.setObjectName("sectionTitle"); layout.addWidget(anatomy_title)
        anatomy_note = QLabel("Tree'de bir alan seçildiğinde ilgili certificate/payload/ciphertext/component bölümü vurgulanır. Bu ilişki parsed artifact yapısından gelir; eksik offset/adres tahmin edilmez.")
        anatomy_note.setWordWrap(True); anatomy_note.setObjectName("mutedText"); layout.addWidget(anatomy_note)
        self.anatomy = ImageAnatomyWidget(); layout.addWidget(self.anatomy)
        split = QSplitter()
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["Certificate Alanı", "Değer"]); self.tree.setColumnWidth(0, 290)
        self.tree.currentItemChanged.connect(self._show_entry)
        self.detail = QPlainTextEdit(); self.detail.setReadOnly(True); self.detail.setPlaceholderText("Seçilen alanın anlamı, consumer'ı, claim sınırı ve source'u burada gösterilecek.")
        split.addWidget(self.tree); split.addWidget(self.detail); split.setSizes([430, 720]); layout.addWidget(split, 1)
        self.verify_result = HumanResultView(show_boundary=False); self.verify_result.setVisible(False); layout.addWidget(self.verify_result, 1)
        return page

    def choose(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Certificate/image seç")
        if p: self.path.setText(p)

    def _populate_tree(self, model: dict) -> None:
        self.tree.clear()
        identity = QTreeWidgetItem(["Identity", model.get("context", "")]); self.tree.addTopLevelItem(identity)
        crypto = QTreeWidgetItem(["Cryptography", model.get("consumer", "")]); self.tree.addTopLevelItem(crypto)
        extensions = QTreeWidgetItem(["TI Extensions", str(sum(1 for x in model.get("entries", []) if str(x.get("key", "")).startswith("ext:")))]); self.tree.addTopLevelItem(extensions)
        for entry in model.get("entries", []):
            key = str(entry.get("key") or "")
            parent = extensions if key.startswith("ext:") else (crypto if key in {"public_key", "signature"} else identity)
            value = str(entry.get("value") or "—")
            if len(value) > 72: value = value[:69] + "…"
            item = QTreeWidgetItem([str(entry.get("label") or key), value]); item.setData(0, Qt.UserRole, entry); parent.addChild(item)
        self.tree.expandAll()
        first = identity.child(0) if identity.childCount() else None
        if first: self.tree.setCurrentItem(first)

    def _show_entry(self, current, previous=None) -> None:
        if current is None: return
        entry = current.data(0, Qt.UserRole)
        if not isinstance(entry, dict):
            self.detail.setPlainText("Bir alt alan seçin."); self.anatomy.highlight_for_target(None); return
        self.anatomy.highlight_for_target(entry.get("anatomy_target"))
        decoded = entry.get("decoded")
        decoded_text = json.dumps(decoded, indent=2, ensure_ascii=False) if decoded is not None else str(entry.get("value") or "—")
        self.detail.setPlainText(
            f"{entry.get('official_name', entry.get('label', 'Alan'))}\n\n"
            f"OID\n{entry.get('oid') or 'Standard X.509 field'}\n\n"
            f"Certificate context\n{entry.get('context')}\n\n"
            f"Kim tüketir?\n{entry.get('consumer')}\n\n"
            f"Ne anlama gelir?\n{entry.get('meaning')}\n\n"
            f"Ne kanıtlamaz?\n{entry.get('does_not_prove')}\n\n"
            f"Decoded / observed value\n{decoded_text}\n\n"
            f"Kaynak\n{entry.get('source_title')}\nScope: {entry.get('source_scope')}"
        )

    def run(self, verify: bool) -> None:
        try:
            # PEM standalone cert is supported by metadata/export tools; image explorer currently uses DER parser.
            try:
                inspection = inspect_artifact(self.path.text())
            except Exception:
                meta = certificate_metadata(self.path.text())
                inspection = meta["inspection"]
                inspection.update({
                    "subject": meta["subject_rfc4514"], "issuer": meta["issuer_rfc4514"],
                    "spki_sha256": meta["spki_sha256"], "signature_algorithm_oid": meta["signature_algorithm_oid"],
                    "signature_hash_algorithm": meta["signature_hash_algorithm"],
                })
            model = certificate_explorer_model(inspection)
            if str(self.path.text()).lower().endswith((".der", ".bin", ".tiimage")):
                try: self.anatomy.set_inspection(inspection)
                except Exception: pass
            self.context.setText(
                f"Detected context: {model['context']} | Consumer: {model['consumer']} | TISCI semantics: {model['tisci_request_semantics']}"
            )
            self._populate_tree(model)
            result = {"status": "PASS", "operation": "certificate_explore", "summary": f"{model['context']} read-only olarak incelendi.", "inspection": inspection}
            if verify:
                verification = verify_artifact(self.path.text())
                result["verification"] = verification
                status = verification.get("overall_host_side_verification", "PARTIAL")
                result["status"] = status if status in {"PASS", "FAIL", "PARTIAL"} else "PARTIAL"
                published = self._publish(result)
                self.verify_result.set_result(published); self.verify_result.setVisible(True)
            else:
                self._publish(result); self.verify_result.setVisible(False)
        except Exception as exc:
            show_guided_error(self, exc, context="Certificate Explorer tamamlanamadı")

    # ---------- reissue/export ----------
    def _reissue_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        note = QLabel(
            "Signed certificate byte'larını doğrudan değiştirmek signature'ı bozar. Buradaki akış existing certificate alanlarını yeni forma/profile'a taşır ve yeni certificate üretmenizi sağlar."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)

        form = QFormLayout()
        self.reissue_cert, box = file_field(page, "Existing DER/PEM certificate veya certificate+payload image seç")
        form.addRow("Existing certificate", box)
        self.reissue_payload, box = file_field(page, "Application reissue için yeni/original payload seç")
        form.addRow("Payload (application için)", box)
        self.reissue_profile, box = file_field(page, "Yeni reissue YAML profile output", save=True)
        form.addRow("Reissue profile output", box)
        self.export_der, box = file_field(page, "DER export output", save=True)
        form.addRow("DER export", box)
        self.export_pem, box = file_field(page, "PEM export output", save=True)
        form.addRow("PEM export", box)
        self.export_spki, box = file_field(page, "Public DER-SPKI output", save=True)
        form.addRow("Public key DER", box)
        self.match_key, box = file_field(page, "Private signing key seç", secret=True)
        form.addRow("Key eşleşmesi", box)
        layout.addLayout(form)

        actions = QGridLayout()
        clone = QPushButton("Alanları Forma Aktar"); clone.setObjectName("primaryAction"); clone.clicked.connect(self.load_reissue_into_form)
        save = QPushButton("Reissue Profile Kaydet"); save.clicked.connect(self.save_reissue_profile)
        der = QPushButton("DER Export"); der.clicked.connect(lambda: self.export_cert("der"))
        pem = QPushButton("PEM Export"); pem.clicked.connect(lambda: self.export_cert("pem"))
        spki = QPushButton("Public Key Export"); spki.clicked.connect(self.export_spki_key)
        match_button = QPushButton("Certificate ↔ Private Key Eşleşmesini Kontrol Et"); match_button.clicked.connect(self.check_key_match)
        actions.addWidget(clone, 0, 0); actions.addWidget(save, 0, 1); actions.addWidget(der, 1, 0); actions.addWidget(pem, 1, 1); actions.addWidget(spki, 2, 0); actions.addWidget(match_button, 2, 1)
        layout.addLayout(actions)
        self.reissue_result = HumanResultView(show_boundary=False); layout.addWidget(self.reissue_result, 1)
        return page

    def load_reissue_into_form(self) -> None:
        try:
            profile, warnings = profile_from_certificate(self.reissue_cert.text(), payload_path=self.reissue_payload.text().strip() or None)
            self._load_profile_into_create_form(profile)
            self.tabs.setCurrentIndex(1)
            QMessageBox.information(self, "Yeni certificate formu hazır", "Existing certificate alanları forma aktarıldı.\n\n" + "\n".join(warnings))
        except Exception as exc:
            show_guided_error(self, exc, context="Certificate alanları forma aktarılamadı")

    def save_reissue_profile(self) -> None:
        try:
            if not self.reissue_profile.text().strip(): raise ValueError("Reissue profile output seçin")
            result = save_cloned_profile(self.reissue_cert.text(), self.reissue_profile.text(), payload_path=self.reissue_payload.text().strip() or None)
            result = self._publish(result, "certificate_profile"); self.reissue_result.set_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Reissue profile oluşturulamadı")

    def export_cert(self, encoding: str) -> None:
        try:
            output = self.export_der.text() if encoding == "der" else self.export_pem.text()
            if not output.strip(): raise ValueError(f"{encoding.upper()} output seçin")
            result = export_certificate(self.reissue_cert.text(), output, encoding=encoding)
            result = self._publish(result, "certificate_profile"); self.reissue_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="Certificate export tamamlanamadı")

    def export_spki_key(self) -> None:
        try:
            if not self.export_spki.text().strip(): raise ValueError("Public DER output seçin")
            result = export_public_key_der(self.reissue_cert.text(), self.export_spki.text())
            result = self._publish(result, "certificate_profile"); self.reissue_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="Public key export tamamlanamadı")

    def check_key_match(self) -> None:
        try:
            if not self.match_key.text().strip(): raise ValueError("Private signing key seçin")
            result = compare_certificate_with_private_key(self.reissue_cert.text(), self.match_key.text())
            result = self._publish(result, "certificate_profile"); self.reissue_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="Key eşleşmesi kontrol edilemedi")

    def _load_profile_into_create_form(self, profile: dict) -> None:
        kind = str(profile.get("type"))
        idx = self.create_kind.findData(kind)
        if idx < 0: raise ValueError("Forma yalnız application veya debug profile yüklenebilir")
        self.create_kind.setCurrentIndex(idx)
        subject = profile.get("subject") if isinstance(profile.get("subject"), dict) else {}
        for key, edit in self.subject_edits.items(): edit.setText(str(subject.get(key) or ""))
        self.swrev.setValue(int(profile.get("software_revision", 1)))
        self.valid_days.setValue(int(profile.get("valid_days", 3650)))
        if kind == "application":
            self.app_input.setText(str(profile.get("input") or ""))
            load = profile.get("load") if isinstance(profile.get("load"), dict) else {}
            self.app_dest.setText(str(load.get("dest_addr") or ""))
            ai = self.app_auth.findData(int(load.get("auth_mode", 1)))
            if ai >= 0: self.app_auth.setCurrentIndex(ai)
            self.app_host.setText(str(load.get("copy_as_host", "")))
            boot = profile.get("boot") if isinstance(profile.get("boot"), dict) else {"enabled": False}
            self.boot_enabled.setChecked(bool(boot.get("enabled", False)))
            self.boot_core.setText(str(boot.get("boot_core") or "")); self.boot_set.setText(str(boot.get("config_flags_set") or "")); self.boot_clr.setText(str(boot.get("config_flags_clr") or "")); self.boot_reset.setText(str(boot.get("reset_vector") or "")); self.boot_valid.setText(str(boot.get("field_valid") or ""))
        else:
            dbg = profile.get("debug") if isinstance(profile.get("debug"), dict) else {}
            self.debug_wildcard.setChecked(bool(dbg.get("wildcard_uid", False)))
            if not self.debug_wildcard.isChecked(): self.debug_uid.setText(str(dbg.get("soc_uid") or ""))
            di = self.debug_priv.findData(int(dbg.get("privilege", 0)))
            if di >= 0: self.debug_priv.setCurrentIndex(di)
            self.debug_ns.setText(",".join(hex(int(x)) for x in dbg.get("nonsecure_core_ids", [255])))
            self.debug_sec.setText(",".join(hex(int(x)) for x in dbg.get("secure_core_ids", [255])))

    # ---------- library ----------
    def _library_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        self.library_project_note = QLabel(); self.library_project_note.setObjectName("mutedText"); layout.addWidget(self.library_project_note)
        self.library_table = QTableWidget(0, 8)
        self.library_table.setHorizontalHeaderLabels(["Ad", "Context", "Subject", "Validity", "Bitiş", "Boyut", "Certificate SHA-256", "SPKI SHA-256"])
        self.library_table.setEditTriggers(QTableWidget.NoEditTriggers); self.library_table.setSelectionBehavior(QTableWidget.SelectRows); self.library_table.setSelectionMode(QTableWidget.SingleSelection)
        self.library_table.verticalHeader().setVisible(False)
        header = self.library_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents); header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch); header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents); header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch); header.setSectionResizeMode(7, QHeaderView.Stretch)
        layout.addWidget(self.library_table, 1)
        row = QHBoxLayout()
        self.library_add = QPushButton("Certificate Ekle"); self.library_add.setObjectName("primaryAction"); self.library_add.clicked.connect(self.add_library)
        self.library_refresh = QPushButton("Yenile"); self.library_refresh.clicked.connect(self.refresh_library)
        open_explorer = QPushButton("Seçileni Explorer'da Aç"); open_explorer.clicked.connect(self.open_library_in_explorer)
        self.library_remove = QPushButton("Seçileni Library'den Kaldır"); self.library_remove.clicked.connect(self.remove_library)
        row.addWidget(self.library_add); row.addWidget(self.library_refresh); row.addWidget(open_explorer); row.addStretch(1); row.addWidget(self.library_remove)
        layout.addLayout(row)
        note = QLabel("Library yalnız public certificate material saklar. Private key, MEK veya secret path bu alana kopyalanmaz.")
        note.setWordWrap(True); note.setObjectName("safetyText"); layout.addWidget(note)
        return page

    def refresh_library(self) -> None:
        if not self.state.project:
            self.library_table.setRowCount(0); self._last_library_rows = []; return
        try:
            rows = list_certificate_library(self.state.project.root); self._last_library_rows = rows
            self.library_table.setRowCount(len(rows))
            for r, item in enumerate(rows):
                vals = [item["name"], item["classification"], item["subject"], item.get("validity_state", "—"), item["not_valid_after"], str(item["size"]), str(item.get("certificate_sha256") or "—"), str(item.get("spki_sha256") or "—")]
                for c, val in enumerate(vals): self.library_table.setItem(r, c, QTableWidgetItem(val))
        except Exception as exc: show_guided_error(self, exc, context="Certificate Library okunamadı")

    def add_library(self) -> None:
        try:
            if not self.state.project: raise ValueError("Önce bir Project Workspace açın")
            path, _ = QFileDialog.getOpenFileName(self, "Library'ye eklenecek public certificate seç")
            if not path: return
            result = add_certificate_to_library(self.state.project.root, path)
            result = self._publish(result, "certificate_profile"); self.refresh_library()
        except Exception as exc: show_guided_error(self, exc, context="Certificate Library'ye eklenemedi")

    def _selected_library_row(self) -> dict:
        row = self.library_table.currentRow()
        if row < 0 or row >= len(self._last_library_rows): raise ValueError("Önce bir Library girdisi seçin")
        return self._last_library_rows[row]

    def open_library_in_explorer(self) -> None:
        try:
            if not self.state.project: raise ValueError("Aktif Project yok")
            item = self._selected_library_row()
            path = self.state.project.root / item["relative_path"]
            self.path.setText(str(path)); self.tabs.setCurrentIndex(2); self.run(False)
        except Exception as exc: show_guided_error(self, exc, context="Library certificate açılamadı")

    def remove_library(self) -> None:
        try:
            if not self.state.project: raise ValueError("Aktif Project yok")
            item = self._selected_library_row()
            if QMessageBox.question(self, "Library girdisini kaldır", f"{item['name']} Project Certificate Library'den kaldırılsın mı?\n\nOriginal external certificate etkilenmez.") != QMessageBox.Yes:
                return
            result = remove_certificate_from_library(self.state.project.root, item["relative_path"])
            self._publish(result, "certificate_profile"); self.refresh_library()
        except Exception as exc: show_guided_error(self, exc, context="Library girdisi kaldırılamadı")

    # ---------- contexts ----------
    def _contexts_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        grid = QGridLayout()
        grid.addWidget(self._card(
            "ROM / RBL Certificate",
            "ROM combined image outer certificate, application certificate ile aynı template değildir. SBL + SYSFW + inner certificate + BoardCfg akışı rom_image_gen.py üzerinden yürütülür.",
            "ROM Image workflow'a git",
            lambda: self.navigate.emit("rom"),
        ), 0, 0)
        grid.addWidget(self._card(
            "Keywriter / Provisioning Certificate",
            "Customer provisioning extension'ları AES ile korunur ve Keywriter package/FEK ile eşleşen resmi akış gerekir. Bu Studio shared kartta OTP/eFuse execution çalıştırmaz.",
            "Provisioning Hazırlığına git",
            lambda: self.navigate.emit("provisioning"),
        ), 0, 1)
        grid.addWidget(self._card(
            "Generic Data Certificate",
            "System Firmware Image Integrity + Load ve isteğe bağlı Encryption extension'larını Generic Data workflow yönetir.",
            "Generic Data workflow'a git",
            lambda: self.navigate.emit("generic_data"),
        ), 1, 0)
        grid.addWidget(self._card(
            "Secure Debug Runtime Policy",
            "Certificate tek başına unlock değildir. Active customer key, SOC UID, certificate revision ve Security BoardCfg policy ayrıca değerlendirilir.",
            "Secure Debug ekranına git",
            lambda: self.navigate.emit("secure_debug"),
        ), 1, 1)
        layout.addLayout(grid)
        source = QLabel(
            "Kaynak sınırı: Application/Generic authentication için System Firmware Integrity + Load zorunludur; Studio SWREV'i de profile dahil eder. "
            "Secure Debug certificate için Debug + SWREV zorunludur ve Distinguished Name alanları System Firmware güvenlik kararının kaynağı değildir. "
            "Encrypted application certificate, IV/randomString ve ciphertext binding için resmi TI appimage_x509_cert_gen.py akışına yönlendirilir. "
            "Keywriter fields provisioning context'idir ve application certificate ile karıştırılmaz."
        )
        source.setWordWrap(True); source.setObjectName("mutedText"); layout.addWidget(source)
        layout.addStretch(1)
        return page

    # ---------- compare ----------
    def _compare_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        note = QLabel(
            "İki public certificate'ı Subject/Issuer, serial, validity, public key fingerprint, signature algorithm ve TI extension seti üzerinden karşılaştırın. "
            "Bu karşılaştırma private key veya MEK gerektirmez."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)
        form = QFormLayout()
        self.compare_left, box = file_field(page, "İlk DER/PEM certificate veya certificate+payload image seç")
        form.addRow("Certificate A", box)
        self.compare_right, box = file_field(page, "İkinci DER/PEM certificate veya certificate+payload image seç")
        form.addRow("Certificate B", box)
        layout.addLayout(form)
        btn = QPushButton("Certificate'ları Karşılaştır"); btn.setObjectName("primaryAction"); btn.clicked.connect(self.compare_two_certificates)
        layout.addWidget(btn)
        self.compare_result = HumanResultView(show_boundary=False); layout.addWidget(self.compare_result, 1)
        return page

    def compare_two_certificates(self) -> None:
        try:
            if not self.compare_left.text().strip() or not self.compare_right.text().strip():
                raise ValueError("Karşılaştırmak için iki certificate seçin")
            result = compare_certificates(self.compare_left.text(), self.compare_right.text())
            result = self._publish(result, "certificate_profile")
            self.compare_result.set_result(result)
        except Exception as exc:
            show_guided_error(self, exc, context="Certificate karşılaştırması tamamlanamadı")

    # ---------- expert profile ----------
    def _profile_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.profile_kind = QComboBox(); self.profile_kind.addItems(["application", "debug", "rom", "keywriter"]); form.addRow("Yeni profile türü", self.profile_kind)
        self.profile_path, box = file_field(page, "Certificate profile YAML seç"); form.addRow("Profile", box)
        self.signing_key, box = file_field(page, "RSA-4096 private signing key seç", secret=True); form.addRow("Signing key", box)
        self.cert_output, box = file_field(page, "DER certificate output", save=True); form.addRow("DER output", box)
        self.package_output, box = file_field(page, "Optional application package output", save=True); form.addRow("Package output (optional)", box)
        self.config_output, box = file_field(page, "OpenSSL config output", save=True); form.addRow("Rendered OpenSSL config", box)
        layout.addLayout(form)
        actions = QHBoxLayout()
        new = QPushButton("Profile Şablonu Oluştur"); new.clicked.connect(self.create_profile)
        val = QPushButton("Profile Doğrula"); val.clicked.connect(self.validate_profile)
        render = QPushButton("OpenSSL Config Render"); render.clicked.connect(self.render_config)
        build = QPushButton("DER Certificate Build"); build.clicked.connect(self.build_profile)
        actions.addWidget(new); actions.addWidget(val); actions.addWidget(render); actions.addWidget(build); layout.addLayout(actions)
        self.profile_result = HumanResultView(show_boundary=False); layout.addWidget(self.profile_result, 1)
        return page

    def create_profile(self):
        try:
            p = save_text_dialog(self, "Certificate profile kaydet", lambda p: save_profile(template_profile(self.profile_kind.currentText()), p), ".yaml")
            if p:
                self.profile_path.setText(str(p))
                result = self._publish({"status": "PASS", "operation": "certificate_profile", "summary": "Profile şablonu oluşturuldu; secret içermez ve exact target değerleri tahmin edilmedi.", "outputs": [{"type": "profile", "path": str(p)}]}, "certificate_profile")
                self.profile_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="Profile oluşturulamadı")

    def validate_profile(self):
        try:
            result = validate_profile_file(self.profile_path.text()); result.setdefault("operation", "certificate_profile"); result.setdefault("summary", "Certificate profile host-side doğrulandı.")
            result = self._publish(result, "certificate_profile"); self.profile_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="Profile validation tamamlanamadı")

    def render_config(self):
        try:
            text = render_openssl_config(self.profile_path.text()); out = Path(self.config_output.text())
            if not str(out) or str(out) == ".": raise ValueError("OpenSSL config output seçin")
            if out.exists(): raise FileExistsError(f"çıktı zaten mevcut: {out}")
            out.parent.mkdir(parents=True, exist_ok=True); out.write_text(text, encoding="utf-8")
            result = self._publish({"status": "PASS", "operation": "certificate_profile", "summary": "OpenSSL config render edildi; bu host-side yardımcı çıktıdır.", "outputs": [{"type": "openssl_config", "path": str(out)}]}, "certificate_profile")
            self.profile_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="Config render tamamlanamadı")

    def build_profile(self):
        try:
            result = build_certificate(self.profile_path.text(), self.signing_key.text(), self.cert_output.text(), package=self.package_output.text().strip() or None)
            result["status"] = "PASS" if result.get("host_side_verification", "PASS") != "FAIL" else "FAIL"; result["operation"] = "certificate_profile"; result.setdefault("summary", "DER certificate host üzerinde üretildi.")
            result = self._publish(result, "certificate_profile"); self.profile_result.set_result(result)
        except Exception as exc: show_guided_error(self, exc, context="Certificate build tamamlanamadı")
