from pathlib import Path


def _page_source() -> str:
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit"
    return (root / "gui" / "pages" / "certificate.py").read_text(encoding="utf-8")


def test_alpha22_start_page_is_beginner_focused():
    page = _page_source()
    for token in [
        "Yeni Application Certificate",
        "Yeni Secure Debug Certificate",
        "Mevcut Certificate'ı Aç ve İncele",
        "Yeni Sürüm Oluştur",
        "Teknik sınırlar ve güvenlik notları ▸",
        "İlk kez kullanıyorsanız Application veya Secure Debug ile başlayın",
    ]:
        assert token in page
    assert "Yeniden Üret / Reissue" not in page
    assert "CSR, CA hierarchy, CRL veya OCSP" not in page


def test_alpha22_start_page_hides_empty_result_boundary_and_expert_profile_in_guided_mode():
    page = _page_source()
    assert "self.boundary.setVisible(False)" in page
    assert "self.boundary.setVisible(True)" in page
    assert 'self.tabs.setTabVisible(6, self.state.mode == "expert")' in page


def test_alpha22_technical_notes_are_collapsible():
    page = _page_source()
    assert "self.start_technical_panel.setVisible(False)" in page
    assert "self.start_technical_toggle.toggled.connect(self._toggle_start_technical_notes)" in page
    assert "Teknik sınırlar ve güvenlik notları ▾" in page
