from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_environment_default_view_is_human_readable_and_json_is_secondary():
    page = (ROOT / "src/am64x_secure_toolkit/gui/pages/environment.py").read_text(encoding="utf-8")
    assert 'self.tabs.addTab(overview, "Özet")' in page
    assert 'self.tabs.addTab(technical, "Teknik Ayrıntılar")' in page
    assert 'self.tabs.setCurrentIndex(0)' in page
    assert 'QPlainTextEdit' in page
    assert 'Environment hazır — MCU+ SDK, signing araçları ve OpenSSL bulundu.' in page
    for label in (
        '"MCU+ SDK"',
        '"Python"',
        '"OpenSSL"',
        '"Application signer"',
        '"ROM signer"',
        '"devconfig.mak"',
    ):
        assert label in page


def test_environment_has_empty_state_and_masked_discovery_hint():
    page = (ROOT / "src/am64x_secure_toolkit/gui/pages/environment.py").read_text(encoding="utf-8")
    assert "Henüz kontrol yapılmadı" in page
    assert "Otomatik/aktif SDK:" in page
    assert "Build environment hazır." in page
    assert "SDK build workflow'ları hazır değil" in page
