from pathlib import Path


def _source(name: str) -> str:
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit" / "gui"
    return (root / name).read_text(encoding="utf-8")


def test_main_window_uses_current_certificate_center_page():
    main = _source("main_window.py")
    assert 'from .pages.certificate_enhanced import CertificatePage' in main


def test_certificate_step3_supports_existing_or_inline_generated_key():
    page = _source("pages/certificate_enhanced.py")
    for token in [
        'Mevcut RSA-4096 private key kullan',
        'Yeni development/test RSA-4096 key oluştur',
        'RSA-4096 development/test key oluştur ve kullan',
        'Production/customer key otomatik oluşturulmaz',
        'Secret-generating output Project Workspace içinde olamaz',
        "Key'i Kontrol Et",
    ]:
        assert token in page


def test_inline_key_generation_reuses_canonical_key_workflow_and_blocks_project_secret_output():
    page = _source("pages/certificate_enhanced.py")
    assert 'generate_keys_workflow(output_dir, kind="signing", role=role)' in page
    assert 'path_is_within_project(self.state.project, output_dir)' in page
    assert 'self.create_key.setText(str(private_path))' in page


def test_step3_preflight_requires_private_rsa4096_not_public_only_material():
    page = _source("pages/certificate_enhanced.py")
    assert 'preflight_signing_key(Path(key_text), purpose=self._key_purpose())' in page
    assert 'result.get("input_class") != "private_key"' in page
    assert 'result.get("status") != "PASS"' in page
    assert 'public key/certificate yeterli değildir' in page


def test_generated_key_status_is_share_safe():
    page = _source("pages/certificate_enhanced.py")
    assert 'Private dosya: {private_name}' in page
    assert 'Public dosya: {public_name}' in page
    assert 'DER-SPKI SHA-256: {fingerprint}' in page
    status_tail = page.split('"✓ Development/test signing key oluşturuldu', 1)[1].split('"statusPass"', 1)[0]
    assert 'private_path' not in status_tail


def test_certificate_and_application_wizards_are_scrollable():
    certificate = _source("pages/certificate.py")
    application = _source("pages/application.py")
    for source in (certificate, application):
        assert 'QScrollArea()' in source
        assert 'setWidgetResizable(True)' in source
        assert 'setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)' in source


def test_guided_application_certificate_routes_to_standard_ccs_workflow():
    page = _source("pages/certificate_enhanced.py")
    for token in [
        "Application için standart yol: CCS / MCU+ SDK build",
        "CCS / Secure Application Akışını Aç",
        'self.navigate.emit("application")',
        'self.state.mode != "expert"',
        "self.create_wizard_scroll.setVisible(not guided_application)",
        "self.create_nav.setVisible(not guided_application)",
    ]:
        assert token in page


def test_application_wizard_can_discover_unsigned_ccs_build_outputs():
    page = _source("pages/application.py")
    for token in [
        "CCS / MCU+ SDK build çıktısını bul",
        "Build Klasörünü Tara",
        'for pattern in ("*.mcelf", "*.appimage")',
        "QInputDialog.getItem",
        "yalnız imzalı .appimage.hs_fs çıktısı bulundu",
        "yalnız .out oluşması yeterli değildir",
        "Unsigned .mcelf/.appimage seçin veya Build Klasörünü Tara'yı kullanın",
    ]:
        assert token in page
