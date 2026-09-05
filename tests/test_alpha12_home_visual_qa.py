from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_home_dashboard_is_compact_and_beginner_first():
    home = (ROOT / "src/am64x_secure_toolkit/gui/pages/home.py").read_text(encoding="utf-8")
    # Real-Linux screenshot QA: keep the Home dashboard to six primary actions.
    assert home.count('self._task_card(') == 1  # one call in the task loop; definition is def _task_card
    assert 'primary_tasks = [' in home
    for label in (
        "Emin Değilim — Bana Yol Göster",
        "Secure Application Oluştur",
        "Image Doğrula / İncele",
        "Key Hazırla / Kontrol Et",
        "Environment Kontrolü",
        "Proje Aç / Oluştur",
    ):
        assert label in home
    # Advanced catalogue entries should not be duplicated as Home task cards.
    assert '("ROM Combined Image"' not in home
    assert '("Provisioning Hazırlığı"' not in home
    assert 'index // 3, index % 3' in home


def test_home_visual_patch_has_compact_context_and_transparent_card_text():
    widgets = (ROOT / "src/am64x_secure_toolkit/gui/widgets.py").read_text(encoding="utf-8")
    theme = (ROOT / "src/am64x_secure_toolkit/gui/theme.py").read_text(encoding="utf-8")
    main = (ROOT / "src/am64x_secure_toolkit/gui/main_window.py").read_text(encoding="utf-8")
    assert "context_chip" in widgets and "sdk_chip" in widgets
    assert "Customer RoT: Not assumed" in widgets
    assert "Hardware validation: Not executed" in widgets
    assert "QLabel { background: transparent; }" in theme
    assert "QPushButton#taskCardAction" in theme
    assert "QFrame#safetyNote" in theme
    assert 'showMessage(f"{model.title} · {model.status_text}", 8000)' in main
