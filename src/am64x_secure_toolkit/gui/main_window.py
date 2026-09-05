from __future__ import annotations

from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QHBoxLayout, QListWidget, QListWidgetItem, QMainWindow, QStackedWidget, QVBoxLayout, QWidget

from ..services.ui_contract import page_visible
from ..services.presentation import result_presentation
from .pages.application import ApplicationPage
from .pages.boardcfg import BoardCfgPage
from .pages.certificate import CertificatePage
from .pages.environment import EnvironmentPage
from .pages.errata import ErrataPage
from .pages.generic_data import GenericDataPage
from .pages.guide import GuidePage
from .pages.learn import LearnPage
from .pages.demo import DemoPage
from .pages.diagnostics import DiagnosticsPage
from .pages.source_trace import SourceTracePage
from .pages.home import HomePage
from .pages.inspector import InspectorPage
from .pages.keys import KeysPage
from .pages.negative import NegativePage
from .pages.project import ProjectPage
from .pages.provisioning import ProvisioningPage
from .pages.reports import ReportsPage
from .pages.revision import RevisionPage
from .pages.rom import RomPage
from .pages.sdk import SdkPage
from .pages.secure_debug import SecureDebugPage
from .state import AppState
from .widgets import DeviceContextBar


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AM64x Secure Boot Studio")
        self.resize(1320, 860)
        self.setMinimumSize(1024, 700)
        self.setAccessibleName("AM64x Secure Boot Studio ana penceresi")
        self.state = AppState()
        self.statusBar().showMessage("Hazır · host-side / offline")
        self.state.result_changed.connect(self._show_result_status)

        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(10)
        outer.addWidget(DeviceContextBar(self.state))

        body = QHBoxLayout()
        body.setSpacing(10)
        outer.addLayout(body, 1)

        self.nav = QListWidget()
        self.nav.setObjectName("mainNavigation")
        self.nav.setAccessibleName("Ana gezinme")
        self.nav.setAccessibleDescription("Secure Boot Studio çalışma alanları arasında geçiş yapar")
        self.nav.setMaximumWidth(245)
        self.nav.setMinimumWidth(205)
        self.nav.setSpacing(2)
        self.nav.setUniformItemSizes(True)
        body.addWidget(self.nav)

        self.stack = QStackedWidget()
        self.stack.setAccessibleName("Çalışma alanı")
        body.addWidget(self.stack, 1)

        pages = [
            ("home", "Ana Sayfa", HomePage(self.state)),
            ("guide", "Bana Yol Göster", GuidePage(self.state)),
            ("environment", "Environment", EnvironmentPage(self.state)),
            ("project", "Proje", ProjectPage(self.state)),
            ("application", "Secure Application", ApplicationPage(self.state)),
            ("rom", "ROM Image", RomPage(self.state)),
            ("inspector", "Image İnceleme", InspectorPage(self.state)),
            ("certificate", "Certificate Center", CertificatePage(self.state)),
            ("keys", "Key Center", KeysPage(self.state)),
            ("negative", "Negatif Testler", NegativePage(self.state)),
            ("sdk", "SDK Inspector / Compare", SdkPage(self.state)),
            ("errata", "Errata Advisor", ErrataPage(self.state)),
            ("provisioning", "Provisioning Hazırlığı", ProvisioningPage(self.state)),
            ("revision", "KEYREV / SWREV", RevisionPage(self.state)),
            ("boardcfg", "Security BoardCfg", BoardCfgPage(self.state)),
            ("secure_debug", "Secure Debug", SecureDebugPage(self.state)),
            ("generic_data", "Generic Data", GenericDataPage(self.state)),
            ("reports", "Sonuçlar ve Raporlar", ReportsPage(self.state)),
            ("source_trace", "Source Trace", SourceTracePage(self.state)),
            ("learn", "Öğren", LearnPage(self.state)),
            ("demo", "5 Dakikalık Demo", DemoPage(self.state)),
            ("diagnostics", "Hakkında / Diagnostics", DiagnosticsPage(self.state)),
        ]
        self.index_by_key: dict[str, int] = {}
        self.item_by_key: dict[str, QListWidgetItem] = {}
        for idx, (key, label, page) in enumerate(pages):
            self.index_by_key[key] = idx
            item = QListWidgetItem(label)
            item.setToolTip(label)
            self.item_by_key[key] = item
            self.nav.addItem(item)
            self.stack.addWidget(page)
            if hasattr(page, "navigate"):
                page.navigate.connect(self.navigate)

        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.state.mode_changed.connect(self._apply_mode)
        self._apply_mode(self.state.mode)
        self.nav.setCurrentRow(self.index_by_key["home"])
        self._install_shortcuts()


    def _show_result_status(self, result: dict) -> None:
        model = result_presentation(result)
        self.statusBar().showMessage(f"{model.title} · {model.status_text}", 8000)

    def _install_shortcuts(self) -> None:
        shortcuts = {
            "Ctrl+1": "home",
            "Ctrl+2": "guide",
            "Ctrl+E": "environment",
            "Ctrl+I": "inspector",
            "Ctrl+K": "keys",
            "Ctrl+R": "reports",
            "F1": "learn",
            "Ctrl+D": "demo",
            "Ctrl+,": "diagnostics",
        }
        self._shortcuts: list[QShortcut] = []
        for sequence, key in shortcuts.items():
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.activated.connect(lambda k=key: self.navigate(k))
            self._shortcuts.append(shortcut)

    def _apply_mode(self, mode: str) -> None:
        current_key = next((k for k, i in self.index_by_key.items() if i == self.nav.currentRow()), "home")
        for key, item in self.item_by_key.items():
            item.setHidden(not page_visible(mode, key))
        if not page_visible(mode, current_key):
            self.navigate("home")

    def navigate(self, key: str) -> None:
        idx = self.index_by_key.get(key)
        if idx is None:
            return
        if not page_visible(self.state.mode, key):
            # Explicit navigation to an expert page is itself a clear user intent.
            self.state.set_mode("expert")
        self.nav.setCurrentRow(idx)
