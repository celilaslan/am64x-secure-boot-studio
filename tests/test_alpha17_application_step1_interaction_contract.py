from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "am64x_secure_toolkit" / "gui" / "pages" / "application.py"
THEME = ROOT / "src" / "am64x_secure_toolkit" / "gui" / "theme.py"


def test_alpha17_step1_requires_existing_regular_file():
    text = APP.read_text(encoding="utf-8")
    assert "def _application_input_ready(self) -> bool:" in text
    assert "return path.exists() and path.is_file()" in text
    assert "return self._application_input_ready()" in text
    assert 'raise FileNotFoundError("Seçilen application dosyası bulunamadı veya normal bir dosya değil")' in text


def test_alpha17_next_updates_immediately_and_explains_disabled_state():
    text = APP.read_text(encoding="utf-8")
    assert "self.input.textChanged.connect(lambda _=None: self._update_navigation_state())" in text
    assert "self.next.setEnabled(ready)" in text
    assert 'self.next.setToolTip("Devam etmek için bir application dosyası seçin.")' in text
    assert 'self.next.setToolTip("Seçilen application dosyası bulunamadı veya normal bir dosya değil.")' in text


def test_alpha17_primary_action_disabled_state_is_visually_distinct():
    text = THEME.read_text(encoding="utf-8")
    assert "QPushButton#primaryAction:disabled" in text
    disabled = text.split("QPushButton#primaryAction:disabled", 1)[1].split("}", 1)[0]
    assert "background: #eef0f2" in disabled
    assert "color: #8b939c" in disabled
