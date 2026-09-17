from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...reporting import write_batch_report, write_image_report
from ...services.explanations import explain_result
from ...services.presentation import humanize_identifier, result_presentation, status_text
from ...services.project import suggest_project_output
from ...services.secret_policy import sanitize_for_record
from ...services.source_registry import source_card
from ..widgets import HumanResultView
from .common import file_field, show_guided_error


class ReportsPage(QWidget):
    def __init__(self, state) -> None:
        super().__init__(); self.state = state
        layout = QVBoxLayout(self)
        title = QLabel("Sonuçlar ve Raporlar"); title.setObjectName("pageTitle"); layout.addWidget(title)
        note = QLabel(
            "Önce insan-okunur sonuç gösterilir; ham JSON Teknik Ayrıntı sekmesinde kalır. Session history yalnız share-safe alanları içerir."
        )
        note.setWordWrap(True); note.setObjectName("mutedText"); layout.addWidget(note)
        tabs = QTabWidget()
        tabs.addTab(self._current_tab(), "Current / Neden?")
        tabs.addTab(self._history_tab(), "Session History")
        tabs.addTab(self._project_history_tab(), "Project History")
        tabs.addTab(self._image_tab(), "Tek Image Raporu")
        tabs.addTab(self._batch_tab(), "Toplu Rapor")
        layout.addWidget(tabs, 1)
        state.result_changed.connect(self.show_result)
        state.history_changed.connect(self.refresh_history)
        state.history_changed.connect(self.refresh_project_history)
        state.changed.connect(self.refresh_project_output_hints)
        self.report_image.textChanged.connect(lambda _=None: self.refresh_project_output_hints())
        if state.last_result:
            self.show_result(state.last_result)
        self.refresh_history()
        self.refresh_project_history()
        self.refresh_project_output_hints()

    def _current_tab(self):
        page = QWidget(); l = QVBoxLayout(page)
        split = QSplitter()
        self.current_view = HumanResultView(show_boundary=True)
        split.addWidget(self.current_view)
        why_page = QWidget(); why_layout = QVBoxLayout(why_page)
        why_title = QLabel("Neden bu sonuç çıktı?"); why_title.setObjectName("sectionTitle"); why_layout.addWidget(why_title)
        self.why = QPlainTextEdit(); self.why.setReadOnly(True); why_layout.addWidget(self.why, 1)
        split.addWidget(why_page)
        split.setStretchFactor(0, 2); split.setStretchFactor(1, 1)
        l.addWidget(split, 1)
        save = QPushButton("Current Share-Safe JSON Kaydet"); save.clicked.connect(self.save_current); l.addWidget(save)
        return page

    def _history_tab(self):
        page = QWidget(); l = QVBoxLayout(page)
        n = QLabel("Son 50 in-memory session sonucu tutulur; uygulama kapanınca silinir. Secret değer/path history'ye yazılmaz.")
        n.setWordWrap(True); n.setObjectName("mutedText"); l.addWidget(n)
        self.history = QListWidget(); self.history.currentRowChanged.connect(self.show_history); l.addWidget(self.history, 1)
        self.history_detail = QPlainTextEdit(); self.history_detail.setReadOnly(True); l.addWidget(self.history_detail, 2)
        return page

    def _project_history_tab(self):
        page = QWidget(); l = QVBoxLayout(page)
        n = QLabel("Project Workspace aktifse share-safe workflow activity sessions/activity.jsonl içine kalıcı olarak yazılır. Secret value/path ve full host path kaydedilmez.")
        n.setWordWrap(True); n.setObjectName("mutedText"); l.addWidget(n)
        self.project_history = QListWidget(); self.project_history.currentRowChanged.connect(self.show_project_history); l.addWidget(self.project_history, 1)
        self.project_history_detail = QPlainTextEdit(); self.project_history_detail.setReadOnly(True); l.addWidget(self.project_history_detail, 2)
        return page

    def _image_tab(self):
        page = QWidget(); l = QVBoxLayout(page); f = QFormLayout()
        self.report_image, box = file_field(page, "Raporlanacak image/certificate seç"); f.addRow("Image", box)
        self.report_md, box = file_field(page, "Markdown rapor", save=True); f.addRow("Markdown output", box)
        self.report_json, box = file_field(page, "Optional JSON rapor", save=True); f.addRow("JSON output (optional)", box)
        l.addLayout(f)
        pr = QHBoxLayout()
        self.report_project_hint = QLabel("Project aktif değil — report output manuel seçilir."); self.report_project_hint.setWordWrap(True); self.report_project_hint.setObjectName("mutedText")
        self.report_project_button = QPushButton("Project Reports Kullan"); self.report_project_button.clicked.connect(self.use_project_report_paths)
        pr.addWidget(self.report_project_hint, 1); pr.addWidget(self.report_project_button); l.addLayout(pr)
        b = QPushButton("Host-Side Image Raporu Üret"); b.setObjectName("primaryAction"); b.clicked.connect(self.create_image_report); l.addWidget(b)
        self.report_out = QPlainTextEdit(); self.report_out.setReadOnly(True); l.addWidget(self.report_out, 1)
        return page

    def _batch_tab(self):
        page = QWidget(); l = QVBoxLayout(page)
        a = QHBoxLayout(); add = QPushButton("Image Dosyaları Ekle"); add.clicked.connect(self.add_batch_files)
        clear = QPushButton("Listeyi Temizle"); clear.clicked.connect(lambda: self.batch_files.clear())
        a.addWidget(add); a.addWidget(clear); a.addStretch(1); l.addLayout(a)
        self.batch_files = QListWidget(); l.addWidget(self.batch_files, 1)
        f = QFormLayout()
        self.batch_md, box = file_field(page, "Toplu Markdown rapor", save=True); f.addRow("Markdown output", box)
        self.batch_json, box = file_field(page, "Optional toplu JSON rapor", save=True); f.addRow("JSON output (optional)", box)
        l.addLayout(f)
        bpr = QHBoxLayout()
        self.batch_project_hint = QLabel("Project aktif değil — toplu rapor output manuel seçilir."); self.batch_project_hint.setWordWrap(True); self.batch_project_hint.setObjectName("mutedText")
        self.batch_project_button = QPushButton("Project Reports Kullan"); self.batch_project_button.clicked.connect(self.use_project_batch_paths)
        bpr.addWidget(self.batch_project_hint, 1); bpr.addWidget(self.batch_project_button); l.addLayout(bpr)
        b = QPushButton("Toplu Host-Side Rapor Üret"); b.setObjectName("primaryAction"); b.clicked.connect(self.create_batch_report); l.addWidget(b)
        self.batch_out = QPlainTextEdit(); self.batch_out.setReadOnly(True); l.addWidget(self.batch_out, 1)
        return page

    def refresh_project_output_hints(self) -> None:
        project = self.state.project
        if not hasattr(self, "report_project_hint"):
            return
        enabled = project is not None
        self.report_project_button.setEnabled(enabled); self.batch_project_button.setEnabled(enabled)
        if not enabled:
            self.report_project_hint.setText("Project aktif değil — report output manuel seçilir.")
            self.batch_project_hint.setText("Project aktif değil — toplu rapor output manuel seçilir.")
            return
        md = suggest_project_output(project, workflow="report", source=self.report_image.text().strip() or "image")
        self.report_project_hint.setText(f"Project önerisi: reports/{md.name}")
        self.batch_project_hint.setText("Project önerisi: reports/batch_host_report.md (+ optional JSON)")

    def use_project_report_paths(self) -> None:
        project = self.state.project
        if project is None:
            return
        source = self.report_image.text().strip() or "image"
        self.report_md.setText(str(suggest_project_output(project, workflow="report", source=source)))
        self.report_json.setText(str(suggest_project_output(project, workflow="report_json", source=source)))

    def use_project_batch_paths(self) -> None:
        project = self.state.project
        if project is None:
            return
        self.batch_md.setText(str(project.root / "reports" / "batch_host_report.md"))
        self.batch_json.setText(str(project.root / "reports" / "batch_host_report.json"))

    def show_result(self, result):
        safe = sanitize_for_record(result)
        self.current_view.set_result(safe)
        exp = explain_result(safe); parts = []
        for item in exp["items"]:
            parts.append(f"[{item.get('status', '?')}] {item['check']}\n{item['explanation']}")
            for sid in item.get("sources", []):
                try:
                    parts.append("  Kaynak: " + source_card(sid).replace("\n", " | "))
                except KeyError:
                    pass
        if exp.get("non_claims"):
            parts.append("Bu sonuçtan çıkarılmaması gerekenler:\n" + "\n".join("✗ " + x for x in exp["non_claims"]))
        self.why.setPlainText("\n\n".join(parts) if parts else "Bu sonuç için özel kısa açıklama yok. Teknik Ayrıntı ve Source Trace birlikte değerlendirilebilir.")

    def save_current(self):
        if not self.state.last_result:
            QMessageBox.information(self, "Rapor", "Henüz sonuç yok."); return
        p, _ = QFileDialog.getSaveFileName(self, "Share-safe JSON", "", "JSON (*.json)")
        if not p:
            return
        Path(p).write_text(json.dumps(sanitize_for_record(self.state.last_result), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def refresh_history(self):
        if not hasattr(self, "history"):
            return
        self.history.clear()
        for i, item in enumerate(self.state.result_history):
            model = result_presentation(item)
            self.history.addItem(f"{i + 1:02d}  [{model.status_text}]  {model.title}")
        if self.history.count():
            self.history.setCurrentRow(self.history.count() - 1)

    def show_history(self, row: int):
        if row < 0 or row >= len(self.state.result_history):
            self.history_detail.clear(); return
        model = result_presentation(self.state.result_history[row])
        lines = [f"{model.title} — {model.status_text}", model.summary, ""]
        if model.checks:
            lines.append("Kontroller:")
            lines.extend(f"  {x['status_text']}: {x['title']} — {x['detail']}" for x in model.checks)
        if model.claims:
            lines.extend(["", "Kanıtlar:", *[f"  ✓ {x}" for x in model.claims]])
        if model.non_claims:
            lines.extend(["", "Kanıtlamaz:", *[f"  ✗ {x}" for x in model.non_claims]])
        self.history_detail.setPlainText("\n".join(lines))

    def refresh_project_history(self):
        if not hasattr(self, "project_history"):
            return
        current = self.project_history.currentRow()
        self.project_history.clear()
        for event in self.state.project_history:
            stamp = str(event.get("timestamp_utc") or "")[:19].replace("T", " ")
            op = humanize_identifier(str(event.get("operation") or "result"))
            self.project_history.addItem(f"{stamp}  [{status_text(str(event.get('status') or 'INFO'))}]  {op}")
        if self.project_history.count():
            self.project_history.setCurrentRow(current if 0 <= current < self.project_history.count() else self.project_history.count() - 1)
        elif self.state.project is None:
            self.project_history_detail.setPlainText("Persistent history için önce Project Workspace açın.")
        if self.state.project_history_error:
            self.project_history_detail.setPlainText("Project activity log warning:\n" + self.state.project_history_error)

    def show_project_history(self, row: int):
        if row < 0 or row >= len(self.state.project_history):
            if self.state.project is not None:
                self.project_history_detail.clear()
            return
        event = self.state.project_history[row]
        lines = [
            f"{humanize_identifier(str(event.get('operation') or 'result'))} — {status_text(str(event.get('status') or 'INFO'))}",
            str(event.get("summary") or ""), ""
        ]
        checks = event.get("checks") if isinstance(event.get("checks"), list) else []
        if checks:
            lines.append("Kontroller:")
            lines.extend(f"  {status_text(str(x.get('status') or 'INFO'))}: {humanize_identifier(str(x.get('check') or 'check'))}" for x in checks)
        outputs = event.get("outputs") if isinstance(event.get("outputs"), list) else []
        if outputs:
            lines.extend(["", "Çıktılar:"])
            lines.extend(f"  {humanize_identifier(str(x.get('type') or 'output'))}: {x.get('name') or '—'}" for x in outputs)
        lines.extend(["", "Secret values stored: NO", "Secret paths stored: NO", "Full host paths stored: NO"])
        self.project_history_detail.setPlainText("\n".join(lines))

    def create_image_report(self):
        try:
            result = write_image_report(self.report_image.text(), self.report_md.text(), json_output=self.report_json.text().strip() or None)
            self.state.set_last_result(result)
            self.report_out.setPlainText("Rapor üretildi.\n\n" + json.dumps(sanitize_for_record(result), indent=2, ensure_ascii=False))
        except Exception as exc:
            show_guided_error(self, exc, context="Rapor üretilemedi")

    def add_batch_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Raporlanacak image/certificate dosyalarını seç")
        existing = {self.batch_files.item(i).text() for i in range(self.batch_files.count())}
        for p in paths:
            if p not in existing:
                self.batch_files.addItem(p); existing.add(p)

    def create_batch_report(self):
        try:
            paths = [self.batch_files.item(i).text() for i in range(self.batch_files.count())]
            if not paths:
                raise ValueError("En az bir image seçin")
            result = write_batch_report(paths, self.batch_md.text(), json_output=self.batch_json.text().strip() or None)
            self.state.set_last_result(result)
            self.batch_out.setPlainText("Toplu rapor üretildi.\n\n" + json.dumps(sanitize_for_record(result), indent=2, ensure_ascii=False))
        except Exception as exc:
            show_guided_error(self, exc, context="Toplu rapor üretilemedi")
