from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
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

from ...keycheck import compare_key_material, preflight_mek, preflight_signing_key
from ...services.claim_boundary import attach_claims
from ...services.key_roles import list_key_roles
from ...services.project import path_is_within_project, suggest_project_output
from ...workflows.keys import generate_keys_workflow
from ..widgets import HumanResultView, ResultBoundaryPanel
from .common import file_field, show_guided_error


class KeysPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("Key Center"); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel(
            "Development/test key üretimi, existing key preflight ve public-material karşılaştırması aynı merkezde. "
            "Production/customer secret lifecycle veya OTP/eFuse provisioning yapılmaz."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)
        tabs = QTabWidget()
        tabs.addTab(self._roles_tab(), "Key Rolleri")
        tabs.addTab(self._generate_tab(), "Üret")
        tabs.addTab(self._check_tab(), "Existing Key Kontrol")
        tabs.addTab(self._compare_tab(), "Private/Public Eşleşme")
        layout.addWidget(tabs, 2)
        self.boundary = ResultBoundaryPanel(); layout.addWidget(self.boundary, 1)
        state.changed.connect(self.refresh_project_policy)
        self.check_path.textChanged.connect(lambda _=None: self.refresh_project_policy())
        self.refresh_project_policy()

    def _role_card(self, role: dict[str, str]) -> QFrame:
        card = QFrame(); card.setObjectName("infoCard")
        layout = QVBoxLayout(card)
        title = QLabel(role["title"]); title.setObjectName("sectionTitle"); layout.addWidget(title)
        alg = QLabel(role["algorithm"]); alg.setObjectName("statusInfo"); layout.addWidget(alg, 0)
        text = QLabel(
            f"{role['purpose']}\n\nKim kullanır? {role['consumer']}\n"
            f"Sınıf: {role['classification']}\n\n{role['warning']}"
        )
        text.setWordWrap(True); text.setObjectName("mutedText"); layout.addWidget(text)
        return card

    def _roles_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        intro = QLabel(
            "Aynı 'key' kelimesi farklı güvenlik rollerini ifade eder. Application key'leri ile provisioning Root of Trust key'lerini birbirine karıştırmayın."
        )
        intro.setWordWrap(True); layout.addWidget(intro)
        grid = QGridLayout()
        for i, role in enumerate(list_key_roles()):
            grid.addWidget(self._role_card(role), i // 2, i % 2)
        layout.addLayout(grid); layout.addStretch(1)
        return page

    def _generate_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.output_dir = QLineEdit(); pick = QPushButton("Seç"); pick.clicked.connect(self.choose)
        row = QHBoxLayout(); row.addWidget(self.output_dir); row.addWidget(pick); box = QWidget(); box.setLayout(row); form.addRow("Çıktı dizini", box)
        self.kind = QComboBox(); self.kind.addItems(["Development Set", "Signing Key", "MEK", "Provisioning Test Set"]); self.kind.currentTextChanged.connect(self._refresh_role); form.addRow("Üretim", self.kind)
        self.role = QComboBox(); self.role.currentTextChanged.connect(self._refresh_generation_help); form.addRow("Role", self.role)
        self.backup = QCheckBox("Backup set dahil (BMPK/BMEK)"); self.backup.toggled.connect(lambda _: self._refresh_generation_help()); form.addRow("", self.backup)
        layout.addLayout(form)
        self.generation_help = QLabel(); self.generation_help.setWordWrap(True); self.generation_help.setObjectName("mutedText"); layout.addWidget(self.generation_help)
        self.project_secret_warning = QLabel(
            "Secret-generating output için Project Workspace klasörlerini kullanmayın. Project paylaşılabilir output/report alanıdır; private key/MEK ayrı korumalı dizinde tutulmalıdır."
        )
        self.project_secret_warning.setWordWrap(True); self.project_secret_warning.setObjectName("statusWarn"); layout.addWidget(self.project_secret_warning)
        gen = QPushButton("Synthetic / Non-Production Key Üret"); gen.setObjectName("primaryAction"); gen.clicked.connect(self.generate); layout.addWidget(gen)
        self.output = HumanResultView(show_boundary=False); layout.addWidget(self.output, 1)
        self.identity = QPlainTextEdit(); self.identity.setReadOnly(True); self.identity.setMaximumHeight(150); self.identity.setPlaceholderText("Public identity metadata generation sonrası burada gösterilecek; secret value/hash gösterilmez.")
        layout.addWidget(self.identity)
        self._refresh_role(self.kind.currentText())
        return page

    def _check_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.check_path, box = file_field(page, "Key/MEK dosyası seç", secret=True); form.addRow("Input", box)
        self.check_type = QComboBox(); self.check_type.addItems(["Signing/Public/Certificate", "MEK"]); form.addRow("Kontrol türü", self.check_type)
        self.check_purpose = QComboBox(); self.check_purpose.addItems(["application", "debug", "smpk", "bmpk", "rom", "generic"]); form.addRow("Signing purpose", self.check_purpose)
        self.public_der, box = file_field(page, "Public DER output", save=True); form.addRow("Public DER export (optional)", box)
        layout.addLayout(form)
        public_row = QHBoxLayout()
        self.project_public_hint = QLabel("Project aktif değil — public DER export manuel seçilir."); self.project_public_hint.setWordWrap(True); self.project_public_hint.setObjectName("mutedText")
        self.project_public_button = QPushButton("Project Public DER Kullan"); self.project_public_button.clicked.connect(self.use_project_public_der)
        public_row.addWidget(self.project_public_hint, 1); public_row.addWidget(self.project_public_button); layout.addLayout(public_row)
        run = QPushButton("Secret-Safe Preflight"); run.clicked.connect(self.check_existing); layout.addWidget(run)
        self.check_output = HumanResultView(show_boundary=False); layout.addWidget(self.check_output, 1)
        return page

    def _compare_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); form = QFormLayout()
        self.private_key, box = file_field(page, "Private key seç", secret=True); form.addRow("Private key", box)
        self.reference_key, box = file_field(page, "Public key veya certificate seç"); form.addRow("Public/Certificate", box)
        layout.addLayout(form)
        run = QPushButton("Public DER-SPKI Üzerinden Karşılaştır"); run.clicked.connect(self.compare); layout.addWidget(run)
        self.compare_output = HumanResultView(show_boundary=False); layout.addWidget(self.compare_output, 1)
        return page

    def refresh_project_policy(self) -> None:
        project = self.state.project
        if not hasattr(self, "project_public_hint"):
            return
        self.project_public_button.setEnabled(project is not None)
        if project is None:
            self.project_public_hint.setText("Project aktif değil — public DER export manuel seçilir.")
            return
        suggested = suggest_project_output(project, workflow="public", source=self.check_path.text().strip() or "public-key")
        self.project_public_hint.setText(f"Public-only export önerisi: public/{suggested.name}")

    def use_project_public_der(self) -> None:
        project = self.state.project
        if project is None:
            return
        self.public_der.setText(str(suggest_project_output(project, workflow="public", source=self.check_path.text().strip() or "public-key")))

    def _refresh_role(self, label: str) -> None:
        self.role.clear()
        if label == "Signing Key": self.role.addItems(["application", "smpk", "bmpk", "debug"])
        elif label == "MEK": self.role.addItems(["application", "smek", "bmek"])
        else: self.role.addItem("profile tarafından belirlenir")
        self.role.setEnabled(label in {"Signing Key", "MEK"})
        self.backup.setEnabled(label == "Provisioning Test Set")
        self._refresh_generation_help()

    def _refresh_generation_help(self) -> None:
        label = self.kind.currentText()
        if label == "Development Set":
            text = "Application signing RSA-4096 + application MEK AES-256 üretilir. İkisi de synthetic/non-production olarak sınıflandırılır."
        elif label == "Provisioning Test Set":
            text = "Synthetic SMPK + SMEK hazırlanır" + ("; BMPK + BMEK de eklenir." if self.backup.isChecked() else ".") + " OTP/eFuse write veya lifecycle transition yapılmaz."
        elif label == "Signing Key":
            role = self.role.currentText(); text = f"RSA-4096 signing key role: {role}. Private material secret kalır; public DER-SPKI metadata raporlanabilir."
        else:
            role = self.role.currentText(); text = f"AES-256 symmetric key role: {role}. Secret value ve secret hash UI/report'a yazılmaz."
        self.generation_help.setText(text)

    def choose(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Key output dizini seç")
        if path: self.output_dir.setText(path)

    def _publish(self, data: dict, widget: HumanResultView) -> None:
        self.state.set_last_result(data); widget.set_result(data); self.boundary.set_result(data)

    def _show_public_identity(self, data: dict) -> None:
        details = data.get("safe_details") if isinstance(data.get("safe_details"), dict) else data
        role = details.get("role") or details.get("profile") or "—"
        key = details.get("key") if isinstance(details.get("key"), dict) else None
        pub = details.get("public_key_info") if isinstance(details.get("public_key_info"), dict) else None
        lines = [f"Role/Profile: {role}"]
        if key:
            lines += [
                f"Algorithm: {key.get('algorithm', '—')}",
                f"Bits: {key.get('bits', '—')}",
                f"Public exponent: {key.get('public_exponent', '—')}",
                f"DER-SPKI SHA-256: {key.get('public_der_spki_sha256', '—')}",
            ]
            if key.get("provisioning_public_der_sha512_candidate"):
                lines.append(f"Provisioning public DER SHA-512 candidate: {key['provisioning_public_der_sha512_candidate']}")
        elif pub:
            for name, info in pub.items():
                if isinstance(info, dict):
                    lines += [f"\n{name}", f"  {info.get('algorithm', 'RSA')} / {info.get('bits', '—')} bit", f"  DER-SPKI SHA-256: {info.get('public_der_spki_sha256', '—')}"]
                    if info.get("provisioning_public_der_sha512_candidate"):
                        lines.append(f"  Provisioning DER SHA-512 candidate: {info['provisioning_public_der_sha512_candidate']}")
        else:
            lines.append("Public identity yok (symmetric secret veya profile-specific output).")
        lines += ["", "Private/symmetric secret value veya secret hash burada gösterilmez."]
        self.identity.setPlainText("\n".join(lines))

    def generate(self) -> None:
        try:
            output_dir = self.output_dir.text().strip()
            if not output_dir:
                raise ValueError("Key output dizini boş bırakılamaz")
            if self.state.project is not None and path_is_within_project(self.state.project, output_dir):
                raise ValueError(
                    "Secret-generating key output dizini Project Workspace içinde olamaz. "
                    "Private key/MEK için project dışında ayrı korumalı bir dizin seçin; yalnız public DER export project/public altında tutulabilir."
                )
            label = self.kind.currentText()
            if label == "Development Set": result = generate_keys_workflow(output_dir, kind="set", profile="development")
            elif label == "Provisioning Test Set": result = generate_keys_workflow(output_dir, kind="set", profile="provisioning-test", backup=self.backup.isChecked())
            elif label == "Signing Key": result = generate_keys_workflow(output_dir, kind="signing", role=self.role.currentText())
            else: result = generate_keys_workflow(output_dir, kind="mek", role=self.role.currentText())
            data = result.to_dict(); self._publish(data, self.output); self._show_public_identity(data)
        except Exception as exc: show_guided_error(self, exc, context="Key generation tamamlanamadı")

    def check_existing(self) -> None:
        try:
            path = Path(self.check_path.text())
            if self.check_type.currentText() == "MEK": result = preflight_mek(path)
            else:
                out = Path(self.public_der.text()) if self.public_der.text().strip() else None
                result = preflight_signing_key(path, purpose=self.check_purpose.currentText(), public_der_output=out)
            result = attach_claims(result, "key_preflight", result.get("status", "PARTIAL")); result.setdefault("operation", "key_preflight"); result.setdefault("summary", "Selected key material host-side preflight ile değerlendirildi.")
            self._publish(result, self.check_output)
        except Exception as exc: show_guided_error(self, exc, context="Key preflight tamamlanamadı")

    def compare(self) -> None:
        try:
            result = compare_key_material(Path(self.private_key.text()), Path(self.reference_key.text()))
            result = attach_claims(result, "key_preflight", result.get("status", "PARTIAL")); result.setdefault("operation", "key_preflight"); result.setdefault("summary", "Private/public material DER-SPKI üzerinden karşılaştırıldı.")
            self._publish(result, self.compare_output)
        except Exception as exc: show_guided_error(self, exc, context="Key karşılaştırma tamamlanamadı")
