from pathlib import Path


def _application_source() -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / "src/am64x_secure_toolkit/gui/pages/application.py").read_text(encoding="utf-8")


def _project_source() -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / "src/am64x_secure_toolkit/services/project.py").read_text(encoding="utf-8")


def test_alpha19_output_step_does_not_teach_appimage_hs_suffix():
    text = _application_source()
    assert 'setPlaceholderText("Çıktı dosyasını seçin")' in text
    assert 'Örn. application.appimage.hs' not in text
    assert 'Çıktı politikası' in text


def test_alpha19_no_project_copy_is_beginner_facing():
    text = _application_source()
    assert 'Aktif bir Proje Çalışma Alanı yok. Çıktı dosyasını manuel seçin.' in text
    assert 'Proje Önerisini Kullan' in text
    assert 'Proje önerisi: outputs/' in text


def test_alpha19_output_gating_rejects_existing_or_same_input_before_review():
    text = _application_source()
    assert 'def _output_path_ready' in text
    assert 'return not out_path.exists()' in text
    assert 'Çıktı dosyası application input ile aynı dosya olamaz' in text
    assert 'Studio mevcut dosyanın üzerine sessizce yazmaz' in text


def test_alpha19_project_application_suggestion_is_descriptive_not_official_suffix_claim():
    text = _project_source()
    assert 'encrypted_secure_application' in text
    assert 'signed_secure_application' in text
    assert '.encrypted.appimage.hs' not in text
    assert '.signed.appimage.hs' not in text
