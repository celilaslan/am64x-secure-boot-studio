from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "am64x_secure_toolkit" / "gui" / "pages" / "application.py"


def _text() -> str:
    return APP.read_text(encoding="utf-8")


def test_alpha16_application_step1_is_beginner_facing():
    text = _text()
    assert '"1 · CCS / MCU+ SDK Build"' in text
    assert 'QPushButton("CCS Proje / Build Klasörünü Seç")' in text
    assert 'QPushButton("Studio ile Secure Build Et")' in text
    assert '.mcelf dosyasını sizin bulmanız gerekmez' in text
    assert '"1 · Application ve SDK"' not in text
    assert 'form.addRow("Application input", box)' not in text


def test_alpha16_guided_mode_hides_manual_sdk_root_and_uses_status_card():
    text = _text()
    assert 'self.sdk_status_title = QLabel("SDK")' in text
    assert 'self.sdk_status_detail.setText("SDK henüz kontrol edilmedi.")' in text
    assert 'self.environment_action = QPushButton("Environment\'ı Kontrol Et")' in text
    assert 'expert = self.state.mode == "expert"' in text
    assert 'self.sdk_expert_label.setVisible(expert)' in text
    assert 'self.sdk_expert_box.setVisible(expert)' in text


def test_alpha16_next_is_disabled_until_current_step_is_ready():
    text = _text()
    assert 'def _step_ready(self, step: int) -> bool:' in text
    assert ('return bool(self.input.text().strip())' in text or 'return self._application_input_ready()' in text)
    assert 'self.next.setEnabled(index < 3 and self._step_ready(index))' in text
    assert 'self.input.textChanged.connect(lambda _=None: self._update_navigation_state())' in text


def test_alpha16_normal_ui_uses_cikti_not_output_in_step_bar():
    text = _text()
    assert 'STEP_NAMES = ("CCS Build", "Key ve Koruma", "Çıktı", "Kontrol", "Sonuç")' in text
    assert '"3 · Çıktı"' in text
    assert 'form.addRow("Çıktı dosyası", box)' in text
