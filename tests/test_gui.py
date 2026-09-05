from am64x_secure_toolkit.gui import _result_text


def test_gui_result_text_is_utf8_friendly_json():
    text = _result_text({"status": "PASS", "açıklama": "doğrulama tamamlandı"})
    assert '"status": "PASS"' in text
    assert "açıklama" in text
    assert "doğrulama tamamlandı" in text
