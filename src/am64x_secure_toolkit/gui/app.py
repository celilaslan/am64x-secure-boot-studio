from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

from .main_window import MainWindow
from .theme import apply_application_theme


def run() -> int:
    # Qt 6 is high-DPI aware by default. PassThrough preserves fractional OS scale factors.
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("AM64x Secure Boot Studio")
    app.setApplicationDisplayName("AM64x Secure Boot Studio")
    app.setOrganizationName("AM64x Secure Boot Studio")
    app.setDesktopFileName("am64x-secure-boot-studio")
    apply_application_theme(app)
    window = MainWindow()
    window.show()
    if "--smoke-test" in sys.argv:
        # Automated launch/render smoke for packaged builds. This is runtime evidence only;
        # it does not replace human visual QA or clean-machine validation.
        app.processEvents()
        print("SECURESTUDIO_SMOKE=PASS")
        window.close()
        app.processEvents()
        return 0
    return app.exec()
