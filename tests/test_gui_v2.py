from am64x_secure_toolkit.gui import _result_text, gui_available


def test_gui_facade_imports_without_pyside6():
    text = _result_text({"status": "PASS", "başlık": "Studio"})
    assert "Studio" in text
    assert isinstance(gui_available(), bool)
