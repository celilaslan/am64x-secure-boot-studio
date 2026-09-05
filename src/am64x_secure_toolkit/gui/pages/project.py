from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog, QComboBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QPlainTextEdit, QPushButton, QStackedWidget,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ...services.presentation import humanize_identifier, status_text
from ...services.project import create_project, open_project, project_dashboard
from .common import show_guided_error


class ProjectPage(QWidget):
    """Beginner-first Project Workspace.

    Project creation/opening and the active-project dashboard are intentionally separate
    states. The active dashboard also has a compact empty state so a brand-new project
    does not expose large history/index tables before they contain useful information.
    """

    navigate = Signal(str)

    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        self._force_setup = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 8)
        layout.setSpacing(10)

        title = QLabel("Proje Çalışma Alanı")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        note = QLabel(
            "Proje; cihaz bilgilerini, üretilen dosyaları, raporları ve paylaşılabilir işlem geçmişini düzenli tutar. "
            "Private key ve symmetric key gibi secret bilgiler proje kayıtlarına kaydedilmez."
        )
        note.setWordWrap(True)
        note.setObjectName("mutedText")
        layout.addWidget(note)

        self.content = QStackedWidget()
        layout.addWidget(self.content, 1)
        self.setup_page = self._build_setup_page()
        self.dashboard_page = self._build_dashboard_page()
        self.content.addWidget(self.setup_page)
        self.content.addWidget(self.dashboard_page)

        state.changed.connect(self.refresh)
        state.history_changed.connect(self.refresh)
        self.refresh()

    # ------------------------------------------------------------------ setup
    def _build_setup_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        intro = QFrame()
        intro.setObjectName("infoCard")
        intro_layout = QVBoxLayout(intro)
        intro_layout.setContentsMargins(12, 10, 12, 10)
        intro_title = QLabel("Proje oluşturun veya mevcut projeyi açın")
        intro_title.setObjectName("sectionTitle")
        intro_layout.addWidget(intro_title)
        intro_text = QLabel(
            "Proje Çalışma Alanı; application/ROM çıktıları, negatif test kopyaları ve raporlar için düzenli bir çalışma alanı sağlar."
        )
        intro_text.setWordWrap(True)
        intro_text.setObjectName("mutedText")
        intro_layout.addWidget(intro_text)
        layout.addWidget(intro)

        form_frame = QFrame()
        form_frame.setObjectName("infoCard")
        form_box = QVBoxLayout(form_frame)
        form_box.setContentsMargins(12, 10, 12, 10)
        form_title = QLabel("Proje bilgileri")
        form_title.setObjectName("sectionTitle")
        form_box.addWidget(form_title)

        form = QFormLayout()
        self.root = QLineEdit()
        self.root.setPlaceholderText("Yeni proje için boş/uygun bir klasör veya mevcut proje klasörü")
        pick = QPushButton("Klasör seç")
        pick.clicked.connect(self.choose_root)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self.root)
        row.addWidget(pick)
        box = QWidget()
        box.setLayout(row)
        form.addRow("Proje klasörü", box)

        self.name = QLineEdit("AM6442 Secure Boot Project")
        form.addRow("Proje adı", self.name)
        self.device = QComboBox()
        self.device.addItems(["AM6442"])
        form.addRow("Device", self.device)
        self.silicon = QComboBox()
        self.silicon.addItems(["SR2.0", "SR1.0", "UNKNOWN"])
        form.addRow("Silicon revision", self.silicon)
        self.lifecycle = QComboBox()
        self.lifecycle.addItems(["HS-FS", "HS-SE", "GP"])
        form.addRow("Lifecycle", self.lifecycle)
        form_box.addLayout(form)

        actions = QHBoxLayout()
        self.create_btn = QPushButton("Yeni Proje Oluştur")
        self.create_btn.setObjectName("primaryAction")
        self.create_btn.clicked.connect(self.create)
        self.open_btn = QPushButton("Mevcut Projeyi Aç")
        self.open_btn.clicked.connect(self.open)
        self.return_btn = QPushButton("Aktif Projeye Dön")
        self.return_btn.clicked.connect(self.return_to_active_project)
        actions.addWidget(self.create_btn)
        actions.addWidget(self.open_btn)
        actions.addWidget(self.return_btn)
        actions.addStretch(1)
        form_box.addLayout(actions)
        layout.addWidget(form_frame)

        self.recent_frame = QFrame()
        self.recent_frame.setObjectName("infoCard")
        recent_layout = QVBoxLayout(self.recent_frame)
        recent_layout.setContentsMargins(12, 10, 12, 10)
        recent_title = QLabel("Son Projeler")
        recent_title.setObjectName("sectionTitle")
        recent_layout.addWidget(recent_title)
        recent_note = QLabel("Daha önce açtığınız projeler yalnız bu bilgisayardaki yerel ayarlarda tutulur.")
        recent_note.setWordWrap(True)
        recent_note.setObjectName("mutedText")
        recent_layout.addWidget(recent_note)
        self.recent_empty = QLabel("Henüz son proje yok. Açtığınız projeler burada listelenecek.")
        self.recent_empty.setObjectName("mutedText")
        recent_layout.addWidget(self.recent_empty)
        self.recent = QListWidget()
        self.recent.setMaximumHeight(140)
        self.recent.itemDoubleClicked.connect(lambda _item: self.open_recent())
        recent_layout.addWidget(self.recent)
        recent_actions = QHBoxLayout()
        self.open_recent_btn = QPushButton("Seçileni Aç")
        self.open_recent_btn.clicked.connect(self.open_recent)
        recent_actions.addWidget(self.open_recent_btn)
        recent_actions.addStretch(1)
        recent_layout.addLayout(recent_actions)
        layout.addWidget(self.recent_frame)
        layout.addStretch(1)
        return page

    # --------------------------------------------------------------- dashboard
    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.context_card = QFrame()
        self.context_card.setObjectName("statusCard")
        cc = QVBoxLayout(self.context_card)
        cc.setContentsMargins(12, 10, 12, 10)
        top = QHBoxLayout()
        self.project_name = QLabel("Aktif proje yok")
        self.project_name.setObjectName("sectionTitle")
        self.project_context = QLabel("—")
        self.project_context.setObjectName("mutedText")
        top.addWidget(self.project_name, 1)
        top.addWidget(self.project_context)
        cc.addLayout(top)
        policy = QLabel(
            "Üretilen public dosyalar ve raporlar proje klasörü altında düzenli tutulur. "
            "Secret bilgiler proje kayıtlarına yazılmaz."
        )
        policy.setWordWrap(True)
        policy.setObjectName("mutedText")
        cc.addWidget(policy)
        project_actions = QHBoxLayout()
        app_btn = QPushButton("Secure Application Oluştur")
        app_btn.setObjectName("primaryAction")
        app_btn.clicked.connect(lambda: self.navigate.emit("application"))
        inspect_btn = QPushButton("Image İncele")
        inspect_btn.clicked.connect(lambda: self.navigate.emit("inspector"))
        reports_btn = QPushButton("Raporları Aç")
        reports_btn.clicked.connect(lambda: self.navigate.emit("reports"))
        switch_btn = QPushButton("Başka Proje Aç / Oluştur")
        switch_btn.clicked.connect(self.show_setup)
        refresh_btn = QPushButton("Yenile")
        refresh_btn.clicked.connect(self.refresh)
        project_actions.addWidget(app_btn)
        project_actions.addWidget(inspect_btn)
        project_actions.addWidget(reports_btn)
        project_actions.addStretch(1)
        project_actions.addWidget(switch_btn)
        project_actions.addWidget(refresh_btn)
        cc.addLayout(project_actions)
        layout.addWidget(self.context_card)

        summary = QFrame()
        summary.setObjectName("infoCard")
        summary_box = QVBoxLayout(summary)
        summary_box.setContentsMargins(12, 10, 12, 10)
        summary_title = QLabel("Workspace Özeti")
        summary_title.setObjectName("sectionTitle")
        summary_box.addWidget(summary_title)
        summary_note = QLabel("Proje klasörlerindeki non-secret/public-generated dosya sayıları.")
        summary_note.setWordWrap(True)
        summary_note.setObjectName("mutedText")
        summary_box.addWidget(summary_note)
        summary_row = QHBoxLayout()
        summary_row.setSpacing(8)
        self.count_labels: dict[str, QLabel] = {}
        for key, label in (
            ("inputs", "Inputs"),
            ("outputs", "Outputs"),
            ("public", "Public files"),
            ("negative-tests", "Negatif Testler"),
            ("reports", "Raporlar"),
        ):
            card = QFrame()
            card.setObjectName("statusCard")
            card_box = QVBoxLayout(card)
            card_box.setContentsMargins(10, 8, 10, 8)
            title = QLabel(label)
            title.setObjectName("statusCardTitle")
            value = QLabel("0")
            value.setObjectName("projectCountValue")
            value.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            card_box.addWidget(title)
            card_box.addWidget(value)
            self.count_labels[key] = value
            summary_row.addWidget(card, 1)
        summary_box.addLayout(summary_row)
        layout.addWidget(summary)

        self.dashboard_content = QStackedWidget()
        self.dashboard_empty = self._build_dashboard_empty_state()
        self.dashboard_populated = self._build_dashboard_populated_state()
        self.dashboard_content.addWidget(self.dashboard_empty)
        self.dashboard_content.addWidget(self.dashboard_populated)
        layout.addWidget(self.dashboard_content, 1)
        return page

    def _build_dashboard_empty_state(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        empty = QFrame()
        empty.setObjectName("infoCard")
        box = QVBoxLayout(empty)
        box.setContentsMargins(14, 14, 14, 14)
        title = QLabel("Henüz işlem yapılmadı")
        title.setObjectName("sectionTitle")
        body = QLabel(
            "İlk secure application'ınızı oluşturabilir veya mevcut bir image'ı inceleyebilirsiniz. "
            "İşlem geçmişi ve üretilen dosyalar oluştuğunda burada gösterilecek."
        )
        body.setWordWrap(True)
        body.setObjectName("mutedText")
        box.addWidget(title)
        box.addWidget(body)
        layout.addWidget(empty)
        layout.addStretch(1)
        return page

    def _build_dashboard_populated_state(self) -> QWidget:
        page = QWidget()
        section = QHBoxLayout(page)
        section.setContentsMargins(0, 0, 0, 0)
        section.setSpacing(12)

        self.artifact_frame = QFrame()
        self.artifact_frame.setObjectName("infoCard")
        left = QVBoxLayout(self.artifact_frame)
        left.setContentsMargins(12, 10, 12, 10)
        artifact_title = QLabel("Üretilen Dosyalar")
        artifact_title.setObjectName("sectionTitle")
        left.addWidget(artifact_title)
        artifact_note = QLabel("Yalnız güvenli dosya referansları, boyut ve SHA-256 tutulur; secret path kaydedilmez.")
        artifact_note.setWordWrap(True)
        artifact_note.setObjectName("mutedText")
        left.addWidget(artifact_note)
        self.artifacts = QTableWidget(0, 4)
        self.artifacts.setHorizontalHeaderLabels(["Tür", "Referans", "Boyut", "SHA-256"])
        self.artifacts.verticalHeader().setVisible(False)
        self.artifacts.setEditTriggers(QTableWidget.NoEditTriggers)
        left.addWidget(self.artifacts, 1)

        self.history_frame = QFrame()
        self.history_frame.setObjectName("infoCard")
        right = QVBoxLayout(self.history_frame)
        right.setContentsMargins(12, 10, 12, 10)
        right_title = QLabel("İşlem Geçmişi")
        right_title.setObjectName("sectionTitle")
        right.addWidget(right_title)
        hist_note = QLabel("Son işlemler share-safe özet olarak tutulur; secret value/path ve full host path kaydedilmez.")
        hist_note.setWordWrap(True)
        hist_note.setObjectName("mutedText")
        right.addWidget(hist_note)
        self.activity = QListWidget()
        self.activity.currentRowChanged.connect(self.show_activity)
        right.addWidget(self.activity, 1)
        self.activity_detail = QPlainTextEdit()
        self.activity_detail.setReadOnly(True)
        self.activity_detail.setPlaceholderText("Bir işlem seçildiğinde kısa özeti burada gösterilir.")
        right.addWidget(self.activity_detail, 1)

        section.addWidget(self.artifact_frame, 1)
        section.addWidget(self.history_frame, 2)
        return page

    # ---------------------------------------------------------------- actions
    def choose_root(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Proje klasörü seç")
        if path:
            self.root.setText(path)

    def _root_or_choose(self, title: str) -> str | None:
        root = self.root.text().strip()
        if root:
            return root
        path = QFileDialog.getExistingDirectory(self, title)
        if not path:
            return None
        self.root.setText(path)
        return path

    def create(self) -> None:
        try:
            root = self._root_or_choose("Yeni proje klasörü seç")
            if not root:
                return
            project = create_project(
                root,
                name=self.name.text().strip() or "AM64x Project",
                device=self.device.currentText(),
                silicon_revision=self.silicon.currentText(),
                lifecycle=self.lifecycle.currentText(),
            )
            self._force_setup = False
            self.state.set_project(project)
            self.refresh()
        except Exception as exc:
            show_guided_error(self, exc, context="Proje oluşturulamadı")

    def open(self) -> None:
        try:
            root = self._root_or_choose("Mevcut proje klasörünü seç")
            if not root:
                return
            project = open_project(root)
            self._activate_project(project)
        except Exception as exc:
            show_guided_error(self, exc, context="Proje açılamadı")

    def open_recent(self) -> None:
        item = self.recent.currentItem()
        if item is None:
            return
        try:
            root = item.data(Qt.UserRole) or item.text()
            project = open_project(str(root))
            self.root.setText(str(project.root))
            self._activate_project(project)
        except Exception as exc:
            show_guided_error(self, exc, context="Son proje açılamadı")

    def _activate_project(self, project) -> None:
        self._force_setup = False
        self.state.set_project(project)
        self.name.setText(project.name)
        self.device.setCurrentText(project.device)
        self.silicon.setCurrentText(project.silicon_revision)
        self.lifecycle.setCurrentText(project.lifecycle)
        self.refresh()

    def show_setup(self) -> None:
        self._force_setup = True
        self.root.clear()
        if self.state.project is not None:
            self.device.setCurrentText(self.state.device)
            self.silicon.setCurrentText(self.state.silicon_revision)
            self.lifecycle.setCurrentText(self.state.lifecycle)
        self.refresh()

    def return_to_active_project(self) -> None:
        if self.state.project is None:
            return
        self._force_setup = False
        self.refresh()

    # ---------------------------------------------------------------- refresh
    def _refresh_recent(self) -> None:
        selected = self.recent.currentRow()
        self.recent.clear()
        for raw in self.state.preferences.recent_projects:
            p = Path(raw)
            # Do not display the full host path in the normal GUI. The local preference may
            # retain it for convenience, but the visible list uses only the project folder name.
            item = QListWidgetItem(p.name or "AM64x Project")
            item.setData(Qt.UserRole, raw)
            self.recent.addItem(item)
        has_recent = self.recent.count() > 0
        self.recent.setVisible(has_recent)
        self.open_recent_btn.setVisible(has_recent)
        self.recent_empty.setVisible(not has_recent)
        if has_recent:
            self.recent.setCurrentRow(selected if 0 <= selected < self.recent.count() else 0)

    def refresh(self) -> None:
        self._refresh_recent()
        project = self.state.project
        self.return_btn.setVisible(project is not None)

        if project is None or self._force_setup:
            self.content.setCurrentWidget(self.setup_page)
        else:
            self.content.setCurrentWidget(self.dashboard_page)

        if project is None:
            for label in self.count_labels.values():
                label.setText("0")
            self.artifacts.setRowCount(0)
            self.activity.clear()
            self.activity_detail.clear()
            self.dashboard_content.setCurrentWidget(self.dashboard_empty)
            return

        self.project_name.setText(project.name)
        self.project_context.setText(f"{project.device} · {project.silicon_revision} · {project.lifecycle}")
        try:
            model = project_dashboard(project)
        except Exception as exc:
            self.project_context.setText(self.project_context.text() + f" · Dashboard error: {type(exc).__name__}")
            return

        counts = model.get("workspace_counts", {})
        for key, label in self.count_labels.items():
            label.setText(str(int(counts.get(key, 0) or 0)))

        artifacts = list(self.state.project_artifacts)[-25:]
        self.artifacts.setRowCount(len(artifacts))
        for row, item in enumerate(artifacts):
            ref = item.get("reference") if isinstance(item.get("reference"), dict) else {}
            size = item.get("size")
            sha = str(item.get("sha256") or "—")
            self.artifacts.setItem(row, 0, QTableWidgetItem(humanize_identifier(str(item.get("type") or "output"))))
            self.artifacts.setItem(row, 1, QTableWidgetItem(str(ref.get("path") or "—")))
            self.artifacts.setItem(row, 2, QTableWidgetItem(str(size) if size is not None else "—"))
            self.artifacts.setItem(row, 3, QTableWidgetItem(sha[:16] + "…" if len(sha) > 16 else sha))
        self.artifacts.resizeColumnsToContents()

        current = self.activity.currentRow()
        self.activity.clear()
        for event in self.state.project_history:
            status = str(event.get("status") or "INFO")
            op = humanize_identifier(str(event.get("operation") or "result"))
            stamp = str(event.get("timestamp_utc") or "")[:19].replace("T", " ")
            self.activity.addItem(f"{stamp}  [{status_text(status)}]  {op}")
        if self.activity.count():
            self.activity.setCurrentRow(current if 0 <= current < self.activity.count() else self.activity.count() - 1)
        elif self.state.project_history_error:
            self.activity_detail.setPlainText("İşlem geçmişi uyarısı:\n" + self.state.project_history_error)
        else:
            self.activity_detail.clear()

        has_artifacts = bool(artifacts)
        has_history = bool(self.state.project_history) or bool(self.state.project_history_error)
        total_workspace_files = sum(int(counts.get(key, 0) or 0) for key in self.count_labels)
        is_empty = not has_artifacts and not has_history and total_workspace_files == 0
        self.dashboard_content.setCurrentWidget(self.dashboard_empty if is_empty else self.dashboard_populated)
        self.artifact_frame.setVisible(has_artifacts)
        self.history_frame.setVisible(has_history)

    def show_activity(self, row: int) -> None:
        if row < 0 or row >= len(self.state.project_history):
            if not self.state.project_history:
                self.activity_detail.clear()
            else:
                self.activity_detail.clear()
            return
        event = self.state.project_history[row]
        lines = [
            f"{humanize_identifier(str(event.get('operation') or 'result'))} — {status_text(str(event.get('status') or 'INFO'))}",
            str(event.get("summary") or ""),
            "",
        ]
        checks = event.get("checks") if isinstance(event.get("checks"), list) else []
        if checks:
            lines.append("Kontroller:")
            for check in checks:
                lines.append(f"  {status_text(str(check.get('status') or 'INFO'))}: {humanize_identifier(str(check.get('check') or 'check'))}")
        outputs = event.get("outputs") if isinstance(event.get("outputs"), list) else []
        if outputs:
            lines.extend(["", "Çıktılar:"])
            lines.extend(f"  {humanize_identifier(str(x.get('type') or 'output'))}: {x.get('name') or '—'}" for x in outputs)
        lines.extend(["", "Secret value kaydedildi: HAYIR", "Secret path kaydedildi: HAYIR", "Full host path kaydedildi: HAYIR"])
        self.activity_detail.setPlainText("\n".join(lines))
