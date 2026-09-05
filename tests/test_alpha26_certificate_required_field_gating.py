from pathlib import Path


def _page_source() -> str:
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit"
    return (root / "gui" / "pages" / "certificate.py").read_text(encoding="utf-8")


def test_alpha26_application_step2_marks_all_required_inputs():
    page = _page_source()
    assert 'form.addRow("Payload / application *", box)' in page
    assert 'form.addRow("Destination Address *", self.app_dest)' in page
    assert 'form.addRow("Yükleme davranışı *", self.app_auth)' in page
    assert 'form.addRow("Destination Host ID *", self.app_host)' in page
    assert '* işaretli alanlar tamamlanmadan Devam etkinleşmez' in page


def test_alpha26_live_navigation_gating_is_wired_to_step2_fields():
    page = _page_source()
    for token in [
        'self.app_input.textChanged.connect(self._update_create_navigation_state)',
        'self.app_dest.textChanged.connect(self._update_create_navigation_state)',
        'self.app_auth.currentIndexChanged.connect(self._update_create_navigation_state)',
        'self.app_host.textChanged.connect(self._update_create_navigation_state)',
        'self.create_next.setEnabled(ready)',
        'self.create_next.setToolTip("" if ready else reason)',
    ]:
        assert token in page


def test_alpha26_step2_fails_closed_until_all_application_fields_are_explicit():
    page = _page_source()
    start = page.index('def _create_step_readiness')
    end = page.index('def _update_create_navigation_state', start)
    body = page[start:end]
    for token in [
        'if not self.app_input.text().strip():',
        'if not self.app_dest.text().strip():',
        'if self.app_auth.currentData() is None:',
        'if not self.app_host.text().strip():',
        'return True, ""',
    ]:
        assert token in body


def test_alpha26_exact_transition_validation_remains_independent():
    page = _page_source()
    start = page.index('def _validate_create_step')
    body = page[start:page.index('def _refresh_create_review', start)]
    assert 'raise ValueError("Payload / application dosyasını seçin")' in body
    assert 'raise ValueError("Destination Address için source-verified değer girin")' in body
    assert 'raise ValueError("Yükleme davranışını seçin")' in body
    assert 'raise ValueError("Destination Host ID için source-verified değer girin")' in body


def test_alpha26_no_silent_target_default_for_address_or_host_id():
    page = _page_source()
    start = page.index('def _application_fields')
    end = page.index('def _debug_fields', start)
    application_constructor = page[start:end]
    assert 'self.app_dest.setText(' not in application_constructor
    assert 'self.app_host.setText(' not in application_constructor
