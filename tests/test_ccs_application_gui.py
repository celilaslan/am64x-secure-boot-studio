from pathlib import Path


def _source(relative: str) -> str:
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit"
    return (root / relative).read_text(encoding="utf-8")


def test_ccs_application_is_the_primary_navigation_label():
    main = _source("gui/main_window.py")
    home = _source("gui/pages/home.py")
    assert '("application", "CCS / Secure Application"' in main
    assert '("CCS / Secure Application", "CCS build çıktısını bulun' in home


def test_application_scan_prefers_existing_signed_output_and_can_verify_it():
    page = _source("gui/pages/application.py")
    for token in [
        "scan_ccs_application_build(directory)",
        'state == "READY_SIGNED"',
        "Certificate/image zaten hazır; tekrar imzalama gerekmez.",
        "Hazır İmzalı Image'ı Doğrula",
        "inspect_and_verify(str(self._ready_signed_input), verify=True)",
    ]:
        assert token in page


def test_application_flow_keeps_unsigned_custom_signing_as_secondary_path():
    page = _source("gui/pages/application.py")
    for token in [
        "Gerekirse: unsigned girdiyi doğrudan seç",
        "Kendi Key'imle Yeni Image Hazırla",
        "Standalone/custom signing için unsigned girdi seçildi",
    ]:
        assert token in page


def test_application_flow_generates_signing_key_and_mek_inline():
    page = _source("gui/pages/application.py")
    for token in [
        "Yeni Test Signing Key Oluştur ve Kullan",
        'generate_keys_workflow(output_dir, kind="signing", role="application")',
        "Yeni Test MEK Oluştur ve Kullan",
        'generate_keys_workflow(output_dir, kind="mek", role="application")',
        "path_is_within_project(self.state.project, output_dir)",
    ]:
        assert token in page


def test_guided_certificate_center_explains_automatic_ccs_certificate():
    page = _source("gui/pages/certificate_enhanced.py")
    assert "application certificate'ını elle oluşturmanız" in page
    assert "hazır .appimage.hs_fs çıktısını doğrudan doğrular" in page
