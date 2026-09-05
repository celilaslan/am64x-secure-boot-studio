from pathlib import Path


def _page_source() -> str:
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit"
    return (root / "gui" / "pages" / "certificate.py").read_text(encoding="utf-8")


def test_alpha23_certificate_creation_is_five_step_guided_wizard():
    page = _page_source()
    for token in [
        "1. Kimlik",
        "2. TI Alanları",
        "3. Signing Key",
        "4. Çıktı",
        "5. Kontrol",
        "self.create_wizard = QStackedWidget()",
        "self.create_back",
        "self.create_next",
    ]:
        assert token in page


def test_alpha23_subject_explains_required_and_optional_fields():
    page = _page_source()
    assert "Yalnız Common Name (CN) zorunludur" in page
    assert 'row_label = label + (" *" if key == "common_name" else "")' in page
    assert "Subject bilgisi signing key veya Root of Trust değildir" in page


def test_alpha23_tisci_auth_type_is_not_misrepresented_as_two_extensions():
    page = _page_source()
    assert "auth_type tek bir INTEGER'dır" in page
    assert "auth_type[7:0]" in page
    assert "auth_type[15:8]" in page
    assert 'form.addRow("Yükleme davranışı *", self.app_auth)' in page
    assert 'form.addRow("Destination Host ID *", self.app_host)' in page


def test_alpha23_outputs_are_progressively_disclosed_and_der_is_required():
    page = _page_source()
    assert "İsteğe bağlı ek çıktılar ▸" in page
    assert "self.create_extra_outputs.setVisible(False)" in page
    assert 'QLabel("DER certificate *")' in page
    assert "Studio mevcut dosyanın üzerine sessizce yazmaz" in page


def test_alpha23_review_never_renders_private_key_path():
    page = _page_source()
    assert 'key_state = "seçildi" if self.create_key.text().strip() else "seçilmedi"' in page
    assert "secret path gösterilmez" in page
    review = page[page.index("def _refresh_create_review"):page.index("def _application_fields")]
    assert "Path(self.create_key.text())" not in review
    assert 'f"Signing key: {self.create_key.text()}' not in review
