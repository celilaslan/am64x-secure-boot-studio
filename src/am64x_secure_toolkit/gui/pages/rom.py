from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ...services.environment import resolve_environment
from ...services.project import suggest_project_output
from ...workflows.rom import rom_build_workflow
from ..widgets import HumanResultView
from .common import file_field, require_field, show_guided_error


class RomPage(QWidget):
    navigate = Signal(str)
    STEP_NAMES = ("Bileşenler", "Güvenlik", "Target Değerleri", "Output", "Kontrol", "Sonuç")

    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        root = QVBoxLayout(self)
        title = QLabel("ROM Combined Image Oluştur")
        title.setObjectName("pageTitle")
        root.addWidget(title)
        intro = QLabel(
            "SBL + SYSFW + BoardCfg (+ HS için SYSFW inner certificate) zinciri installed TI "
            "rom_image_gen.py ile hazırlanır. Studio load address, debug option veya target ID tahmin etmez."
        )
        intro.setWordWrap(True); intro.setObjectName("mutedText"); root.addWidget(intro)

        self.step_bar = QFrame(); self.step_bar.setObjectName("wizardStepBar")
        step_layout = QHBoxLayout(self.step_bar)
        self.step_labels: list[QLabel] = []
        for i, name in enumerate(self.STEP_NAMES):
            label = QLabel(f"{i + 1}. {name}"); label.setAlignment(Qt.AlignCenter)
            self.step_labels.append(label); step_layout.addWidget(label, 1)
        root.addWidget(self.step_bar)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._components_step())
        self.stack.addWidget(self._security_step())
        self.stack.addWidget(self._target_step())
        self.stack.addWidget(self._output_step())
        self.stack.addWidget(self._review_step())
        self.stack.addWidget(self._result_step())
        root.addWidget(self.stack, 1)

        nav = QHBoxLayout()
        self.back = QPushButton("← Geri"); self.back.clicked.connect(self.go_back)
        self.next = QPushButton("Devam →"); self.next.setObjectName("primaryAction"); self.next.clicked.connect(self.go_next)
        self.start_over = QPushButton("Yeni İşlem"); self.start_over.clicked.connect(self.reset_wizard)
        nav.addWidget(self.back); nav.addStretch(1); nav.addWidget(self.start_over); nav.addWidget(self.next)
        root.addLayout(nav)
        self._project_output_last: str | None = None
        self.sbl.textChanged.connect(lambda _=None: self._sync_project_output())
        self.state.changed.connect(self._sync_project_output)
        self._set_step(0)
        self._sync_project_output()

    def _card(self, title: str, body: str) -> QFrame:
        frame = QFrame(); frame.setObjectName("infoCard")
        layout = QVBoxLayout(frame)
        h = QLabel(title); h.setObjectName("sectionTitle"); layout.addWidget(h)
        text = QLabel(body); text.setWordWrap(True); text.setObjectName("mutedText"); layout.addWidget(text)
        return frame

    def _components_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "1 · Combined image bileşenleri",
            "Bileşenleri ayrı ayrı seçin. HS flow kullanıyorsanız matching SYSFW inner certificate ekleyin; Studio bunu dosya adından zorla varsaymaz.",
        ))
        form = QFormLayout()
        self.sbl, box = file_field(page, "SBL binary seç"); form.addRow("SBL binary", box)
        self.sysfw, box = file_field(page, "SYSFW binary seç"); form.addRow("SYSFW", box)
        self.inner, box = file_field(page, "SYSFW inner certificate seç"); form.addRow("SYSFW inner cert (HS, optional)", box)
        self.boardcfg, box = file_field(page, "BoardCfg blob seç"); form.addRow("BoardCfg", box)
        self.sdk = QLineEdit(); self.sdk.setPlaceholderText("Optional SDK root — boşsa Environment / auto-discovery")
        form.addRow("MCU+ SDK root", self.sdk)
        layout.addLayout(form)
        env = QPushButton("Environment Kontrolüne Git"); env.clicked.connect(lambda: self.navigate.emit("environment")); layout.addWidget(env)
        layout.addStretch(1)
        return page

    def _security_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "2 · Signing, SWREV ve optional SBL encryption",
            "ROM signing private key zorunludur. SBL encryption seçilirse MEK gerekir. Debug option boşsa Studio herhangi bir debug enable değeri eklemez.",
        ))
        form = QFormLayout()
        self.key, box = file_field(page, "ROM signing private key seç", secret=True); form.addRow("Signing private key", box)
        self.enc_enabled = QCheckBox("SBL encryption kullan")
        self.enc_enabled.toggled.connect(self._toggle_encryption); form.addRow("SBL encryption", self.enc_enabled)
        self.mek, self.mek_box = file_field(page, "SBL encryption key seç", secret=True); form.addRow("Encryption key", self.mek_box)
        self.swrv = QSpinBox(); self.swrv.setRange(0, 2**31 - 1); self.swrv.setValue(1); form.addRow("SWRV", self.swrv)
        self.debug = QLineEdit(); self.debug.setPlaceholderText("Boş = debug option gönderme; exact SDK option girilebilir")
        form.addRow("Debug option", self.debug)
        layout.addLayout(form)
        layout.addWidget(self._card(
            "Debug uyarısı",
            "Development-oriented debug setting seçmek production secure state anlamına gelmez. Studio production için DBG_FULL_ENABLE benzeri bir değeri otomatik seçmez.",
        ))
        key_center = QPushButton("Key Center'a Git"); key_center.clicked.connect(lambda: self.navigate.emit("keys")); layout.addWidget(key_center)
        layout.addStretch(1); self._toggle_encryption(False)
        return page

    def _target_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "3 · Source-backed target değerleri",
            "Bu değerler ROM image formatının target-specific girdileridir. Exact SDK/build source'tan doğrulanmadan build başlatılmaz.",
        ))
        form = QFormLayout()
        self.sbl_addr = QLineEdit(); self.sbl_addr.setPlaceholderText("Exact source-derived value")
        self.sysfw_addr = QLineEdit(); self.sysfw_addr.setPlaceholderText("Exact source-derived value")
        self.bcfg_addr = QLineEdit(); self.bcfg_addr.setPlaceholderText("Exact source-derived value")
        form.addRow("SBL load address", self.sbl_addr)
        form.addRow("SYSFW load address", self.sysfw_addr)
        form.addRow("BoardCfg load address", self.bcfg_addr)
        layout.addLayout(form)
        source = QPushButton("Source Trace'e Git"); source.clicked.connect(lambda: self.navigate.emit("source_trace")); layout.addWidget(source)
        layout.addStretch(1)
        return page

    def _output_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "4 · Output",
            "Yeni ROM combined image için ayrı output seçin. Existing output'un üzerine sessizce yazılmaz; input bileşenler elle değiştirilmez.",
        ))
        form = QFormLayout()
        self.output, box = file_field(page, "ROM output image", save=True); form.addRow("Output", box)
        layout.addLayout(form)
        project_row = QHBoxLayout()
        self.project_output_hint = QLabel("Project Workspace aktif değil — output manuel seçilir.")
        self.project_output_hint.setWordWrap(True); self.project_output_hint.setObjectName("mutedText")
        self.use_project_output = QPushButton("Project Output Kullan")
        self.use_project_output.clicked.connect(lambda: self._sync_project_output(force=True))
        project_row.addWidget(self.project_output_hint, 1); project_row.addWidget(self.use_project_output)
        layout.addLayout(project_row)
        layout.addWidget(self._card(
            "Output politikası",
            "Project aktifse combined image için outputs/ altında project-relative yol önerilir. Existing output sessizce overwrite edilmez."
        ))
        layout.addStretch(1)
        return page

    def _review_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        layout.addWidget(self._card(
            "5 · Çalıştırmadan Önce",
            "Özet secret value/hash içermez. Dry Run komut planını gösterir; Build + Post Verify gerçek host-side generation ve doğrulama yapar.",
        ))
        self.review = QLabel(); self.review.setWordWrap(True)
        self.review.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        layout.addWidget(self.review)
        boundary = QLabel(
            "Bu workflow OTP/eFuse yazmaz, HS-FS → HS-SE transition yapmaz ve hardware/customer Root of Trust enforcement sonucu üretmez."
        )
        boundary.setWordWrap(True); boundary.setObjectName("mutedText"); layout.addWidget(boundary)
        actions = QHBoxLayout()
        dry = QPushButton("Dry Run"); dry.clicked.connect(lambda: self.run(True))
        build = QPushButton("Build + Post Verify"); build.setObjectName("primaryAction"); build.clicked.connect(lambda: self.run(False))
        actions.addWidget(dry); actions.addWidget(build); actions.addStretch(1); layout.addLayout(actions)
        layout.addStretch(1)
        return page

    def _result_step(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        self.result = HumanResultView(show_boundary=True); layout.addWidget(self.result, 1)
        return page

    def _toggle_encryption(self, enabled: bool) -> None:
        self.mek_box.setEnabled(enabled)
        if not enabled:
            self.mek.setProperty("invalid", False); self.mek.style().unpolish(self.mek); self.mek.style().polish(self.mek)

    def _validate_step(self, step: int) -> None:
        if step == 0:
            require_field(self.sbl, "SBL binary"); require_field(self.sysfw, "SYSFW"); require_field(self.boardcfg, "BoardCfg")
        elif step == 1:
            require_field(self.key, "Signing private key")
            if self.enc_enabled.isChecked(): require_field(self.mek, "Encryption key")
        elif step == 2:
            require_field(self.sbl_addr, "SBL load address"); require_field(self.sysfw_addr, "SYSFW load address"); require_field(self.bcfg_addr, "BoardCfg load address")
        elif step == 3:
            output = require_field(self.output, "Output")
            for source, label in ((self.sbl.text(), "SBL"), (self.sysfw.text(), "SYSFW"), (self.boardcfg.text(), "BoardCfg"), (self.inner.text(), "SYSFW inner cert")):
                if source.strip() and Path(output).expanduser().resolve() == Path(source.strip()).expanduser().resolve():
                    raise ValueError(f"Output image {label} input ile aynı dosya olamaz")

    def _sync_project_output(self, force: bool = False) -> None:
        project = self.state.project
        if not hasattr(self, "project_output_hint"):
            return
        if project is None:
            self.project_output_hint.setText("Project Workspace aktif değil — output manuel seçilir.")
            self.use_project_output.setEnabled(False)
            return
        suggested = str(suggest_project_output(project, workflow="rom", source=self.sbl.text().strip() or None))
        self.project_output_hint.setText(f"Project önerisi: outputs/{Path(suggested).name}")
        self.use_project_output.setEnabled(True)
        current = self.output.text().strip()
        if force or not current or (self._project_output_last is not None and current == self._project_output_last):
            self.output.setText(suggested)
            self._project_output_last = suggested

    def _refresh_review(self) -> None:
        files = {
            "SBL": Path(self.sbl.text()).name or "—",
            "SYSFW": Path(self.sysfw.text()).name or "—",
            "Inner cert": Path(self.inner.text()).name if self.inner.text().strip() else "Kullanılmayacak",
            "BoardCfg": Path(self.boardcfg.text()).name or "—",
        }
        debug = self.debug.text().strip() or "Gönderilmeyecek"
        encryption = "Enabled — secret key selected" if self.enc_enabled.isChecked() else "Disabled"
        sdk = "Explicit SDK root" if self.sdk.text().strip() else "Environment / auto-discovery"
        self.review.setText(
            f"SBL               : {files['SBL']}\n"
            f"SYSFW             : {files['SYSFW']}\n"
            f"SYSFW inner cert  : {files['Inner cert']}\n"
            f"BoardCfg          : {files['BoardCfg']}\n"
            f"Signing key       : [secret dosya seçildi]\n"
            f"SBL encryption    : {encryption}\n"
            f"SWRV              : {self.swrv.value()}\n"
            f"Debug option      : {debug}\n"
            f"SBL load address  : {self.sbl_addr.text().strip()}\n"
            f"SYSFW load address: {self.sysfw_addr.text().strip()}\n"
            f"BoardCfg address  : {self.bcfg_addr.text().strip()}\n"
            f"Output            : {Path(self.output.text()).name or '—'}\n"
            f"SDK               : {sdk}\n\n"
            "Build sonrası: certificate parse + ROM component/integrity post verification uygulanır."
        )

    def _set_step(self, index: int) -> None:
        index = max(0, min(index, self.stack.count() - 1)); self.stack.setCurrentIndex(index)
        if index == 4: self._refresh_review()
        for i, label in enumerate(self.step_labels):
            if i < index:
                label.setObjectName("wizardStepDone"); label.setText(f"✓ {i + 1}. {self.STEP_NAMES[i]}")
            elif i == index:
                label.setObjectName("wizardStepActive"); label.setText(f"{i + 1}. {self.STEP_NAMES[i]}")
            else:
                label.setObjectName("wizardStepIdle"); label.setText(f"{i + 1}. {self.STEP_NAMES[i]}")
            label.style().unpolish(label); label.style().polish(label)
        self.back.setEnabled(index > 0 and index < 5)
        self.next.setVisible(index < 4)
        self.start_over.setVisible(index == 5)

    def go_next(self) -> None:
        step = self.stack.currentIndex()
        try:
            self._validate_step(step); self._set_step(step + 1)
        except Exception as exc:
            show_guided_error(self, exc, context="Bu ROM adımı tamamlanamadı")

    def go_back(self) -> None:
        self._set_step(self.stack.currentIndex() - 1)

    def reset_wizard(self) -> None:
        self.result.clear(); self._set_step(0)

    def run(self, dry_run: bool) -> None:
        try:
            for step in range(4): self._validate_step(step)
            env = self.state.environment or resolve_environment(self.sdk.text().strip() or None)
            if self.sdk.text().strip(): env = resolve_environment(self.sdk.text().strip())
            self.state.set_environment(env)
            data = rom_build_workflow(
                environment=env,
                sbl_bin=self.sbl.text().strip(),
                sysfw_bin=self.sysfw.text().strip(),
                boardcfg_blob=self.boardcfg.text().strip(),
                sbl_loadaddr=self.sbl_addr.text().strip(),
                sysfw_loadaddr=self.sysfw_addr.text().strip(),
                bcfg_loadaddr=self.bcfg_addr.text().strip(),
                swrv=self.swrv.value(),
                signing_key=self.key.text().strip(),
                output=self.output.text().strip(),
                sysfw_inner_cert=self.inner.text().strip() or None,
                debug=self.debug.text().strip() or None,
                sbl_encryption_key=self.mek.text().strip() if self.enc_enabled.isChecked() else None,
                dry_run=dry_run,
                post_verify=not dry_run,
            ).to_dict()
            self.state.set_last_result(data); self.result.set_result(data); self._set_step(5)
        except Exception as exc:
            show_guided_error(self, exc, context="ROM workflow tamamlanamadı")
