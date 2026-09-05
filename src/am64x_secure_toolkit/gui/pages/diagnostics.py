from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from ...services.diagnostics import diagnostics_markdown, diagnostics_snapshot, write_diagnostics
from ...services.presentation import status_text
from .common import save_text_dialog, show_guided_error


class DiagnosticsPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        self.snapshot: dict | None = None
        layout = QVBoxLayout(self)
        title = QLabel("Hakkında / Diagnostics")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        note = QLabel(
            "Bu ekran share-safe teşhis özeti üretir. Secret value/hash/path, username, hostname veya full host path export edilmez. "
            "Beta readiness gerçek Qt/standalone testleri çalıştırılmadan PASS sayılmaz."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)

        actions = QHBoxLayout()
        refresh = QPushButton("Yenile"); refresh.clicked.connect(self.refresh_snapshot)
        export_json = QPushButton("JSON Export"); export_json.clicked.connect(self.export_json)
        export_md = QPushButton("Markdown Export"); export_md.clicked.connect(self.export_markdown)
        actions.addWidget(refresh); actions.addWidget(export_json); actions.addWidget(export_md); actions.addStretch(1)
        layout.addLayout(actions)

        self.summary = QLabel(); self.summary.setWordWrap(True); self.summary.setObjectName("statusCard")
        layout.addWidget(self.summary)

        self.checks = QTableWidget(0, 2)
        self.checks.setHorizontalHeaderLabels(["Kontrol", "Durum"])
        self.checks.verticalHeader().setVisible(False)
        self.checks.setEditTriggers(QTableWidget.NoEditTriggers)
        self.checks.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.checks)

        self.detail = QPlainTextEdit(); self.detail.setReadOnly(True); self.detail.setAccessibleName("Share-safe diagnostic JSON")
        layout.addWidget(self.detail, 1)
        state.changed.connect(self.refresh_snapshot)
        self.refresh_snapshot()

    def refresh_snapshot(self) -> None:
        try:
            self.snapshot = diagnostics_snapshot(environment=self.state.environment, project=self.state.project)
            beta = self.snapshot.get("beta_readiness", {})
            env = self.snapshot.get("environment", {})
            self.summary.setText(
                f"Toolkit {self.snapshot.get('toolkit', {}).get('version', '?')} · "
                f"Environment {'READY' if env.get('ready') else 'CHECK REQUIRED'} · "
                f"Beta readiness {status_text(str(beta.get('status') or 'PARTIAL'))}"
            )
            rows = [
                ("PySide6", "PASS" if self.snapshot.get("dependencies", {}).get("PySide6") else "NOT_CHECKED"),
                ("PyInstaller", "PASS" if self.snapshot.get("dependencies", {}).get("PyInstaller") else "NOT_CHECKED"),
                ("Real Qt render", str(beta.get("real_qt_render") or "NOT_EXECUTED")),
                ("Linux clean-machine", str(beta.get("linux_clean_machine") or "NOT_EXECUTED")),
                ("Windows clean-machine", str(beta.get("windows_clean_machine") or "NOT_EXECUTED")),
            ]
            self.checks.setRowCount(len(rows))
            for row, (name, status) in enumerate(rows):
                self.checks.setItem(row, 0, QTableWidgetItem(name))
                self.checks.setItem(row, 1, QTableWidgetItem(status_text(status)))
            self.checks.resizeColumnsToContents()
            self.detail.setPlainText(json.dumps(self.snapshot, indent=2, ensure_ascii=False))
        except Exception as exc:
            show_guided_error(self, exc, context="Diagnostics yenilenemedi")

    def export_json(self) -> None:
        if self.snapshot is None:
            self.refresh_snapshot()
        if self.snapshot is None:
            return
        try:
            save_text_dialog(
                self,
                "Share-safe diagnostics JSON kaydet",
                lambda p: write_diagnostics(self.snapshot or {}, p),
                ".json",
            )
        except Exception as exc:
            show_guided_error(self, exc, context="Diagnostic export başarısız")

    def export_markdown(self) -> None:
        if self.snapshot is None:
            self.refresh_snapshot()
        if self.snapshot is None:
            return
        try:
            def writer(path: Path) -> None:
                if path.exists():
                    raise FileExistsError(f"çıktı zaten mevcut: {path}")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(diagnostics_markdown(self.snapshot or {}), encoding="utf-8")
            save_text_dialog(self, "Share-safe diagnostics Markdown kaydet", writer, ".md")
        except Exception as exc:
            show_guided_error(self, exc, context="Diagnostic export başarısız")
