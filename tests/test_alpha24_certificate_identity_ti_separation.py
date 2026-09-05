from pathlib import Path


def _page_source() -> str:
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit"
    return (root / "gui" / "pages" / "certificate.py").read_text(encoding="utf-8")


def test_alpha24_software_revision_is_not_in_identity_step():
    page = _page_source()
    identity = page[page.index("# ----- Step 1: Subject / identity -----"):page.index("# ----- Step 2: TI context fields -----")]
    assert 'cl.addRow("Software Revision", self.swrev)' not in identity
    assert 'cl.addRow("Geçerlilik süresi (gün)", self.valid_days)' in identity


def test_alpha24_software_revision_is_in_ti_fields_step():
    page = _page_source()
    ti = page[page.index("# ----- Step 2: TI context fields -----"):page.index("# ----- Step 3: signing key -----")]
    assert 'tml.addRow("Software Revision", self.swrev)' in ti
    assert "Software Revision TI certificate metadata'sının parçasıdır" in ti
    assert "Subject/Kimlik alanı değildir" in ti
    assert "rollback enforcement kanıtı değildir" in ti
