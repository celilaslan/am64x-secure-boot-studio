from pathlib import Path


def _page_source() -> str:
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit"
    return (root / "gui" / "pages" / "certificate.py").read_text(encoding="utf-8")


def test_alpha25_guided_application_load_labels_hide_raw_auth_type_as_primary_language():
    page = _page_source()
    assert 'form.addRow("Yükleme davranışı *", self.app_auth)' in page
    assert 'form.addRow("Destination Host ID *", self.app_host)' in page
    assert 'form.addRow("Destination Address *", self.app_dest)' in page
    assert 'form.addRow("auth_type — copy mode", self.app_auth)' not in page
    assert 'form.addRow("auth_type — Host ID", self.app_host)' not in page


def test_alpha25_auth_type_exact_layout_remains_available_in_collapsed_technical_detail():
    page = _page_source()
    assert 'Teknik auth_type ayrıntıları ▸' in page
    assert 'auth_type[7:0]' in page
    assert 'auth_type[15:8]' in page
    assert 'tek auth_type değerinde birleştirir' in page
    assert 'self.app_auth_technical.setVisible(False)' in page


def test_alpha25_application_mode_choices_are_beginner_facing():
    page = _page_source()
    assert 'Normal — payload Destination Address\'e kopyalanır (0)' in page
    assert 'In-place — payload bulunduğu yerde doğrulanır (1)' in page
    assert 'In-place variant (2)' in page


def test_alpha25_encrypted_application_and_boot_copy_are_simplified_without_semantic_change():
    page = _page_source()
    assert 'Şifreli application oluşturmak mı istiyorsunuz?' in page
    assert 'TI appimage_x509_cert_gen.py aracını kullanır' in page
    assert 'Processor boot bilgilerini ekle' in page
    assert "Yalnız bu certificate bir core'u boot etmek için kullanılacaksa gerekir." in page
