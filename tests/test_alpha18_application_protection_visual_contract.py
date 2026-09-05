from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "am64x_secure_toolkit" / "gui" / "pages" / "application.py"
THEME = ROOT / "src" / "am64x_secure_toolkit" / "gui" / "theme.py"


def _app() -> str:
    return APP.read_text(encoding="utf-8")


def test_alpha18_protection_step_uses_explicit_radio_choices_not_checkbox_mode():
    text = _app()
    assert 'self.sign_only = QRadioButton("Yalnız imzala")' in text
    assert 'self.encrypt = QRadioButton("Şifrele + imzala")' in text
    assert 'self.protection_group = QButtonGroup(page)' in text
    assert 'self.protection_group.setExclusive(True)' in text
    assert 'self.sign_only.setChecked(True)' in text
    assert 'choice_title = QLabel("Application nasıl korunacak?")' in text
    assert 'QCheckBox("Application payload' not in text
    assert 'form.addRow("Protection mode"' not in text


def test_alpha18_secret_paths_are_internal_and_gui_shows_only_safe_status():
    text = _app()
    assert 'edit.setVisible(False)' in text
    assert 'Guided/Expert GUI surfaces show only a basename/status, never the full secret path.' in text
    assert 'self._set_secret_status(status, f"Seçildi: {path.name}", "statusInfo")' in text
    assert 'self._set_secret_status(status, "MEK dosyası seçildi.", "statusInfo")' in text
    assert 'button_text="Mevcut key\'i seç"' in text
    assert 'button_text="MEK seç"' in text


def test_alpha18_mek_selector_is_conditional_and_existing_file_gated():
    text = _app()
    assert 'self.encrypt.toggled.connect(self._toggle_encryption)' in text
    assert 'self.mek_card.setVisible(enabled)' in text
    assert 'return not self.encrypt.isChecked() or self._secret_file_ready(self.mek)' in text
    assert 'return path.exists() and path.is_file()' in text
    assert 'Şifreleme için mevcut bir application MEK seçin.' in text


def test_alpha18_inline_key_help_and_safety_copy_are_beginner_facing():
    text = _app()
    assert 'Development/test key\'iniz yoksa' in text
    assert 'QPushButton("Yeni Test Signing Key Oluştur ve Kullan")' in text
    assert 'QPushButton("Bu Key ile CCS Secure Build Et")' in text
    assert 'Bu adım yalnız host üzerinde image hazırlamak içindir.' in text
    assert 'Studio OTP/eFuse yazmaz ve HS-FS → HS-SE geçişi yapmaz.' in text


def test_alpha18_choice_cards_have_distinct_selected_visual_state():
    text = THEME.read_text(encoding="utf-8")
    assert 'QFrame#choiceCard {' in text
    assert 'QFrame#choiceCard[selected="true"]' in text
    selected = text.split('QFrame#choiceCard[selected="true"]', 1)[1].split('}', 1)[0]
    assert 'background: #eef5fc' in selected
    assert 'border: 2px solid #4b6f9f' in selected
