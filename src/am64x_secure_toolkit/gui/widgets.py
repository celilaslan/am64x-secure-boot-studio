from __future__ import annotations

import json

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..services.presentation import image_anatomy_model, result_presentation


_STATUS_OBJECT = {
    "PASS": "statusPass",
    "FAIL": "statusFail",
    "ERROR": "statusFail",
    "PARTIAL": "statusWarn",
    "NOT_CHECKED": "statusWarn",
    "NOT_APPLICABLE": "statusInfo",
    "WARN": "statusWarn",
    "INFO": "statusInfo",
}

_STATUS_MARK = {
    "PASS": "✓",
    "FAIL": "✕",
    "ERROR": "!",
    "PARTIAL": "◐",
    "NOT_CHECKED": "○",
    "NOT_APPLICABLE": "—",
    "WARN": "!",
    "INFO": "i",
}


class DeviceContextBar(QFrame):
    def __init__(self, state) -> None:
        super().__init__()
        self.state = state
        self.setObjectName("contextBar")
        self.setAccessibleName("Device context")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(8)

        self.context_chip = QLabel()
        self.context_chip.setObjectName("contextChip")
        self.context_chip.setAccessibleName("Device ve lifecycle context")

        self.sdk_chip = QLabel()
        self.sdk_chip.setObjectName("contextChip")
        self.sdk_chip.setAccessibleName("SDK context")

        self.root_chip = QLabel("Customer RoT: Not assumed")
        self.root_chip.setObjectName("contextChipInfo")
        self.root_chip.setAccessibleName("Customer Root of Trust claim boundary")
        self.root_chip.setToolTip("Studio customer Root of Trust provisioning/enforcement durumunu hardware evidence olmadan varsaymaz.")

        self.hardware_chip = QLabel("Hardware validation: Not executed")
        self.hardware_chip.setObjectName("contextChipMuted")
        self.hardware_chip.setAccessibleName("Hardware validation state")

        self.mode = QComboBox()
        self.mode.addItem("Rehberli Mod", "guided")
        self.mode.addItem("Uzman Modu", "expert")
        self.mode.setAccessibleName("Kullanım modu")
        self.mode.setToolTip("Rehberli Mod temel workflow'ları gösterir; Uzman Modu bütün offline/host-side araçları açar.")
        self.mode.currentIndexChanged.connect(self._mode_changed)

        layout.addWidget(self.context_chip)
        layout.addWidget(self.sdk_chip)
        layout.addStretch(1)
        layout.addWidget(self.root_chip)
        layout.addWidget(self.hardware_chip)
        layout.addWidget(self.mode)

        state.changed.connect(self.refresh)
        state.mode_changed.connect(self._sync_mode)
        self.refresh()
        self._sync_mode(state.mode)

    def _mode_changed(self) -> None:
        mode = self.mode.currentData()
        if mode:
            self.state.set_mode(str(mode))

    def _sync_mode(self, mode: str) -> None:
        idx = self.mode.findData(mode)
        if idx >= 0 and idx != self.mode.currentIndex():
            self.mode.blockSignals(True)
            self.mode.setCurrentIndex(idx)
            self.mode.blockSignals(False)

    def refresh(self) -> None:
        sdk = self.state.environment.sdk_version if self.state.environment else None
        target = getattr(self.state, "build_target_lifecycle", self.state.lifecycle)
        self.context_chip.setText(
            f"{self.state.device} · {self.state.silicon_revision} · Kart: {self.state.lifecycle} · Hedef: {target}"
        )
        self.sdk_chip.setText(f"SDK {sdk}" if sdk else "SDK not checked")
        root_state = getattr(self.state, "customer_root_state", "unknown")
        root_labels = {
            "unknown": "Customer RoT: Doğrulanmadı",
            "not_provisioned": "Customer RoT: Provision edilmedi",
            "provisioned": "Customer RoT: Provision edildi (kullanıcı beyanı)",
            "hardware_verified": "Customer RoT: Donanımda doğrulandı (kullanıcı beyanı)",
        }
        self.root_chip.setText(root_labels.get(root_state, "Customer RoT: Doğrulanmadı"))


class StatusBadge(QLabel):
    def __init__(self, status: str = "INFO", text: str | None = None) -> None:
        super().__init__()
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumWidth(112)
        self.set_status(status, text)

    def set_status(self, status: str, text: str | None = None) -> None:
        status = status or "INFO"
        self.setObjectName(_STATUS_OBJECT.get(status, "statusInfo"))
        self.setText(f"{_STATUS_MARK.get(status, '•')} {text or status}")
        self.style().unpolish(self)
        self.style().polish(self)


class ResultBoundaryPanel(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("boundaryPanel")
        self.setAccessibleName("Result claim boundary")
        layout = QVBoxLayout(self)
        title = QLabel("Bu sonuç neyi kanıtlar / neyi kanıtlamaz?")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        self.claims = QLabel("Henüz sonuç yok.")
        self.claims.setWordWrap(True)
        self.claims.setTextInteractionFlags(Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self.claims.setAccessibleName("Kanıtlanan ve kanıtlanmayan sonuçlar")
        layout.addWidget(self.claims)

    def set_result(self, result: dict) -> None:
        claims = result.get("claims", [])
        non_claims = result.get("non_claims", [])
        text = "KANITLAR:\n" + ("\n".join(f"✓ {x}" for x in claims) or "-")
        text += "\n\nKANITLAMAZ:\n" + ("\n".join(f"✗ {x}" for x in non_claims) or "-")
        self.claims.setText(text)


class HumanResultView(QWidget):
    """Human-readable result view with technical JSON deliberately moved to a secondary tab."""

    def __init__(self, *, show_boundary: bool = True) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.summary_card = QFrame()
        self.summary_card.setObjectName("statusCard")
        summary_layout = QHBoxLayout(self.summary_card)
        text_col = QVBoxLayout()
        self.title = QLabel("Henüz sonuç yok")
        self.title.setObjectName("sectionTitle")
        self.summary = QLabel("Bir workflow çalıştırıldığında özet burada görünecek.")
        self.summary.setWordWrap(True)
        self.summary.setObjectName("mutedText")
        text_col.addWidget(self.title)
        text_col.addWidget(self.summary)
        summary_layout.addLayout(text_col, 1)
        self.badge = StatusBadge("INFO", "Bekliyor")
        summary_layout.addWidget(self.badge)
        layout.addWidget(self.summary_card)

        self.tabs = QTabWidget()
        checks_page = QWidget()
        checks_layout = QVBoxLayout(checks_page)
        self.checks = QTableWidget(0, 4)
        self.checks.setHorizontalHeaderLabels(["Durum", "Kontrol", "Açıklama", "Neden?"])
        self.checks.setEditTriggers(QTableWidget.NoEditTriggers)
        self.checks.setSelectionBehavior(QTableWidget.SelectRows)
        self.checks.setAlternatingRowColors(True)
        self.checks.verticalHeader().setVisible(False)
        header = self.checks.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        checks_layout.addWidget(self.checks)
        self.outputs = QLabel()
        self.outputs.setWordWrap(True)
        self.outputs.setObjectName("mutedText")
        checks_layout.addWidget(self.outputs)
        self.tabs.addTab(checks_page, "Kontroller")

        self.technical = QPlainTextEdit()
        self.technical.setReadOnly(True)
        self.technical.setAccessibleName("Teknik JSON ayrıntısı")
        self.tabs.addTab(self.technical, "Teknik Ayrıntı")
        layout.addWidget(self.tabs, 1)

        self.boundary = ResultBoundaryPanel() if show_boundary else None
        if self.boundary is not None:
            layout.addWidget(self.boundary)

    def clear(self) -> None:
        self.title.setText("Henüz sonuç yok")
        self.summary.setText("Bir workflow çalıştırıldığında özet burada görünecek.")
        self.badge.set_status("INFO", "Bekliyor")
        self.checks.setRowCount(0)
        self.outputs.clear()
        self.technical.clear()
        if self.boundary:
            self.boundary.set_result({})


    def _show_why(self, check: dict) -> None:
        sources = ", ".join(check.get("sources") or []) or "Özel source mapping yok; teknik sonuç/source trace birlikte değerlendirilir."
        QMessageBox.information(
            self,
            f"Neden? — {check.get('title', 'Kontrol')}",
            f"{check.get('why') or 'Bu kontrol için açıklama mevcut değil.'}\n\nKaynak: {sources}",
        )

    def set_result(self, result: dict) -> None:
        model = result_presentation(result)
        self.title.setText(model.title)
        self.summary.setText(model.summary)
        self.badge.set_status(model.status, model.status_text)
        self.checks.setRowCount(len(model.checks))
        for row, check in enumerate(model.checks):
            mark = _STATUS_MARK.get(check["status"], "•")
            status_item = QTableWidgetItem(f"{mark} {check['status_text']}")
            status_item.setTextAlignment(Qt.AlignCenter)
            self.checks.setItem(row, 0, status_item)
            self.checks.setItem(row, 1, QTableWidgetItem(check["title"]))
            self.checks.setItem(row, 2, QTableWidgetItem(check["detail"]))
            why = QPushButton("Neden?")
            why.setAccessibleName(f"{check['title']} kontrolünün açıklaması")
            why.setToolTip(check.get("why") or "Bu kontrolün neden gerekli olduğunu gösterir.")
            why.clicked.connect(lambda _checked=False, c=check: self._show_why(c))
            self.checks.setCellWidget(row, 3, why)
        if model.outputs:
            self.outputs.setText("Çıktılar: " + " · ".join(f"{x['type']}: {x['name']}" for x in model.outputs))
        else:
            self.outputs.setText("Çıktı dosyası raporlanmadı.")
        self.technical.setPlainText(json.dumps(model.technical, indent=2, ensure_ascii=False))
        if self.boundary:
            self.boundary.set_result({"claims": model.claims, "non_claims": model.non_claims})
        self.tabs.setCurrentIndex(0)


class ImageAnatomyWidget(QWidget):
    """Read-only visual map of certificate + appended payload/components.

    Geometry is proportional when possible, with a minimum block width for readability.
    No missing offset/address is inferred.
    """

    def __init__(self) -> None:
        super().__init__()
        self._model: dict = {"blocks": []}
        self._highlight_kinds: set[str] = set()
        self.setMinimumHeight(180)
        self.setAccessibleName("Image anatomy görseli")
        self.setToolTip("Parsed certificate ve appended payload/component boyutlarını görselleştirir; eksik adres/offset tahmin etmez.")

    def set_inspection(self, inspection: dict) -> None:
        self._model = image_anatomy_model(inspection)
        self.setAccessibleDescription(self._accessible_description())
        self.update()

    def clear(self) -> None:
        self._model = {"blocks": []}
        self._highlight_kinds = set()
        self.update()

    def highlight_kinds(self, *kinds: str) -> None:
        self._highlight_kinds = {str(x) for x in kinds if x}
        self.update()

    def highlight_for_target(self, target: str | None) -> None:
        mapping = {
            "certificate": {"certificate"},
            "payload": {"payload"},
            "ciphertext": {"ciphertext"},
            "payload_or_ciphertext": {"payload", "ciphertext"},
            "rom_components": {"rom_component"},
            "all": {"certificate", "payload", "ciphertext", "rom_component"},
        }
        self._highlight_kinds = mapping.get(str(target or ""), set())
        self.update()

    def _accessible_description(self) -> str:
        blocks = self._model.get("blocks", [])
        if not blocks:
            return "Henüz image anatomy yok."
        return "; ".join(f"{b['label']} {b['size']} byte" for b in blocks)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt API
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect().adjusted(12, 16, -12, -18)
        blocks = self._model.get("blocks", [])
        if not blocks:
            painter.setPen(QColor("#59636e"))
            painter.drawText(rect, Qt.AlignCenter, "Image seçildiğinde certificate / payload yapısı burada gösterilecek.")
            return

        title_h = 34
        painter.setPen(QColor("#20242a"))
        painter.drawText(QRectF(rect.x(), rect.y(), rect.width(), title_h), Qt.AlignLeft | Qt.AlignVCenter,
                         f"{self._model.get('classification', 'Image')} · {self._model.get('total_size', 0)} byte")
        y = rect.y() + title_h + 8
        h = max(62.0, rect.height() - title_h - 12)
        gap = 5.0
        available = max(1.0, rect.width() - gap * (len(blocks) - 1))
        min_w = min(112.0, available / max(1, len(blocks)))
        total_fraction = sum(max(float(b.get("fraction") or 0), 0.0) for b in blocks) or 1.0
        natural = [available * max(float(b.get("fraction") or 0), 0.0) / total_fraction for b in blocks]
        widths = [max(min_w, w) for w in natural]
        if sum(widths) > available:
            scale = available / sum(widths)
            widths = [max(44.0, w * scale) for w in widths]
        # A second normalization keeps all blocks inside the viewport.
        if sum(widths) > available:
            widths[-1] = max(30.0, widths[-1] - (sum(widths) - available))

        colors = {
            "certificate": QColor("#dce8f8"),
            "ciphertext": QColor("#e7e0f5"),
            "payload": QColor("#e2f0e8"),
            "rom_component": QColor("#f2eadb"),
        }
        x = float(rect.x())
        metrics = QFontMetrics(painter.font())
        for block, w in zip(blocks, widths):
            box = QRectF(x, y, w, h)
            kind = str(block.get("kind"))
            highlighted = kind in self._highlight_kinds
            painter.setPen(QPen(QColor("#315f9b") if highlighted else QColor("#aeb7c2"), 3.0 if highlighted else 1.0))
            painter.setBrush(colors.get(kind, QColor("#eef0f2")))
            painter.drawRoundedRect(box, 7.0, 7.0)
            painter.setPen(QColor("#20242a"))
            inner = box.adjusted(8, 8, -8, -8)
            label = str(block.get("label") or "Block")
            size = f"{block.get('size', 0)} B"
            max_text_w = max(10, int(inner.width()))
            label = metrics.elidedText(label, Qt.ElideRight, max_text_w)
            painter.drawText(QRectF(inner.x(), inner.y(), inner.width(), 22), Qt.AlignLeft | Qt.AlignVCenter, label)
            painter.setPen(QColor("#59636e"))
            painter.drawText(QRectF(inner.x(), inner.y() + 26, inner.width(), 20), Qt.AlignLeft | Qt.AlignVCenter, size)
            x += w + gap


class FlowDiagramWidget(QFrame):
    """Compact semantic flow renderer used by SDK/provisioning/revision/BoardCfg pages.

    The model is pure data from services.workflow_visuals. This widget never invents
    missing IDs/addresses and treats NOT_CHECKED explicitly instead of turning it into PASS.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("flowDiagram")
        self.setAccessibleName("Workflow diagram")
        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(8, 8, 8, 8)
        self._title = QLabel("Henüz diagram yok")
        self._title.setObjectName("sectionTitle")
        self._root.addWidget(self._title)
        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._root.addWidget(self._content)

    @staticmethod
    def _clear_layout(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            child = item.layout()
            if child is not None:
                FlowDiagramWidget._clear_layout(child)
            if widget is not None:
                widget.deleteLater()

    def clear(self) -> None:
        self._title.setText("Henüz diagram yok")
        self._clear_layout(self._content_layout)

    def set_model(self, model: dict) -> None:
        self._clear_layout(self._content_layout)
        self._title.setText(str(model.get("title") or "Workflow"))
        descriptions: list[str] = []
        for lane in model.get("lanes", []):
            lane_box = QFrame()
            lane_box.setObjectName("statusCard")
            lane_layout = QVBoxLayout(lane_box)
            lane_title = QLabel(str(lane.get("label") or "Akış"))
            lane_title.setObjectName("mutedText")
            lane_layout.addWidget(lane_title)
            nodes_row = QHBoxLayout()
            for index, node in enumerate(lane.get("nodes", [])):
                if index:
                    arrow = QLabel("→")
                    arrow.setAlignment(Qt.AlignCenter)
                    arrow.setObjectName("mutedText")
                    nodes_row.addWidget(arrow)
                card = QFrame()
                card.setObjectName("boundaryPanel")
                card_layout = QVBoxLayout(card)
                head = QHBoxLayout()
                name = QLabel(str(node.get("label") or "Adım"))
                name.setWordWrap(True)
                badge = StatusBadge(str(node.get("status") or "INFO"), str(node.get("status") or "INFO"))
                badge.setMinimumWidth(82)
                head.addWidget(name, 1)
                head.addWidget(badge)
                card_layout.addLayout(head)
                detail = QLabel(str(node.get("detail") or "—"))
                detail.setWordWrap(True)
                detail.setObjectName("mutedText")
                card_layout.addWidget(detail)
                nodes_row.addWidget(card, 1)
                descriptions.append(f"{node.get('label')}: {node.get('status')} — {node.get('detail')}")
            lane_layout.addLayout(nodes_row)
            self._content_layout.addWidget(lane_box)
        for callout in model.get("callouts", []):
            row = QHBoxLayout()
            badge = StatusBadge(str(callout.get("status") or "INFO"), str(callout.get("status") or "INFO"))
            text = QLabel(str(callout.get("text") or ""))
            text.setWordWrap(True)
            row.addWidget(badge)
            row.addWidget(text, 1)
            self._content_layout.addLayout(row)
            descriptions.append(str(callout.get("text") or ""))
        self.setAccessibleDescription("; ".join(descriptions))


class SdkDiffResultView(QWidget):
    """Side-by-side, semantic-only SDK security diff view.

    Full source text and private/encryption key paths are intentionally not rendered here.
    """

    def __init__(self) -> None:
        super().__init__()
        from ..services.sdk_compare import sdk_diff_view_model
        self._model_builder = sdk_diff_view_model
        self._model: dict = {"roles": []}
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        head = QFrame(); head.setObjectName("statusCard")
        hl = QHBoxLayout(head)
        self.head_title = QLabel("Henüz SDK karşılaştırması yok"); self.head_title.setObjectName("sectionTitle")
        self.head_note = QLabel("Old/new source pair'leri seçip semantic diff çalıştırın."); self.head_note.setObjectName("mutedText"); self.head_note.setWordWrap(True)
        text = QVBoxLayout(); text.addWidget(self.head_title); text.addWidget(self.head_note)
        hl.addLayout(text, 1); self.head_badge = StatusBadge("INFO", "Bekliyor"); hl.addWidget(self.head_badge)
        root.addWidget(head)

        tabs = QTabWidget(); root.addWidget(tabs, 1)
        semantic = QWidget(); sl = QHBoxLayout(semantic)
        self.roles = QTableWidget(0, 5)
        self.roles.setHorizontalHeaderLabels(["Rol", "Sınıf", "Review", "SHA", "Mapped fark"])
        self.roles.setEditTriggers(QTableWidget.NoEditTriggers); self.roles.setSelectionBehavior(QTableWidget.SelectRows); self.roles.verticalHeader().setVisible(False)
        rh = self.roles.horizontalHeader(); rh.setSectionResizeMode(0, QHeaderView.ResizeToContents); rh.setSectionResizeMode(1, QHeaderView.Stretch); rh.setSectionResizeMode(2, QHeaderView.ResizeToContents); rh.setSectionResizeMode(3, QHeaderView.ResizeToContents); rh.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.roles.currentCellChanged.connect(self._show_role)
        sl.addWidget(self.roles, 1)
        detail = QWidget(); dl = QVBoxLayout(detail)
        self.role_title = QLabel("Semantic changes"); self.role_title.setObjectName("sectionTitle"); dl.addWidget(self.role_title)
        self.changes = QTableWidget(0, 3); self.changes.setHorizontalHeaderLabels(["Alan", "Old", "New"]); self.changes.setEditTriggers(QTableWidget.NoEditTriggers); self.changes.verticalHeader().setVisible(False)
        ch = self.changes.horizontalHeader(); ch.setSectionResizeMode(0, QHeaderView.Stretch); ch.setSectionResizeMode(1, QHeaderView.Stretch); ch.setSectionResizeMode(2, QHeaderView.Stretch)
        dl.addWidget(self.changes, 1)
        self.review_note = QLabel(); self.review_note.setWordWrap(True); self.review_note.setObjectName("mutedText"); dl.addWidget(self.review_note)
        sl.addWidget(detail, 2)
        tabs.addTab(semantic, "Semantic Diff")
        self.technical = QPlainTextEdit(); self.technical.setReadOnly(True); tabs.addTab(self.technical, "Safe Technical Model")

    def set_result(self, result: dict) -> None:
        model = self._model_builder(result)
        self._model = model
        self.head_title.setText("SDK security semantic comparison")
        self.head_badge.set_status(str(model.get("status") or "INFO"), str(model.get("status") or "INFO"))
        required = len((model.get("summary") or {}).get("security_review_required", []))
        recommended = len((model.get("summary") or {}).get("manual_review_recommended", []))
        identical = len((model.get("summary") or {}).get("identical", []))
        self.head_note.setText(f"Required review: {required} · Recommended review: {recommended} · Identical: {identical}. {model.get('not_a_proof') or ''}")
        roles = model.get("roles", [])
        self.roles.setRowCount(len(roles))
        for row, item in enumerate(roles):
            self.roles.setItem(row, 0, QTableWidgetItem(str(item.get("label") or item.get("role") or "—")))
            self.roles.setItem(row, 1, QTableWidgetItem(str(item.get("classification_label") or "—")))
            self.roles.setItem(row, 2, QTableWidgetItem(str(item.get("review") or "—")))
            self.roles.setItem(row, 3, QTableWidgetItem("same" if item.get("same_sha256") else "changed"))
            count = QTableWidgetItem(str(len(item.get("changes") or []))); count.setTextAlignment(Qt.AlignCenter); self.roles.setItem(row, 4, count)
        self.technical.setPlainText(json.dumps(model, indent=2, ensure_ascii=False))
        if roles:
            self.roles.setCurrentCell(0, 0)
        else:
            self._show_role(-1, -1, -1, -1)

    def _show_role(self, row: int, _column: int, _prev_row: int, _prev_col: int) -> None:
        roles = self._model.get("roles", [])
        if row < 0 or row >= len(roles):
            self.role_title.setText("Semantic changes"); self.changes.setRowCount(0); self.review_note.clear(); return
        item = roles[row]
        self.role_title.setText(str(item.get("label") or "Semantic changes"))
        changes = item.get("changes") or []
        self.changes.setRowCount(len(changes))
        for r, change in enumerate(changes):
            self.changes.setItem(r, 0, QTableWidgetItem(str(change.get("field") or "—")))
            self.changes.setItem(r, 1, QTableWidgetItem(str(change.get("before"))))
            self.changes.setItem(r, 2, QTableWidgetItem(str(change.get("after"))))
        if not changes:
            self.review_note.setText("Mapped security semantic farkı yok. Byte-level content değiştiyse manuel review yine önerilebilir.")
        else:
            self.review_note.setText(f"{len(changes)} mapped security semantic farkı bulundu. Review: {item.get('review')}.")
