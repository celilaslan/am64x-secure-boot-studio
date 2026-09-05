from __future__ import annotations

from pathlib import Path


def _project_source() -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / "src/am64x_secure_toolkit/gui/pages/project.py").read_text(encoding="utf-8")


def test_alpha15_active_project_has_compact_empty_state():
    text = _project_source()
    assert "self.dashboard_content = QStackedWidget()" in text
    assert "self.dashboard_empty" in text
    assert "self.dashboard_populated" in text
    assert "Henüz işlem yapılmadı" in text
    assert "İlk secure application'ınızı oluşturabilir" in text
    assert "is_empty = not has_artifacts and not has_history and total_workspace_files == 0" in text


def test_alpha15_workspace_summary_uses_count_cards_not_count_table():
    text = _project_source()
    assert "self.count_labels" in text
    assert '("inputs", "Inputs")' in text
    assert '("outputs", "Outputs")' in text
    assert '("public", "Public files")' in text
    assert '("negative-tests", "Negatif Testler")' in text
    assert '("reports", "Raporlar")' in text
    assert "self.counts = QTableWidget(0, 2)" not in text


def test_alpha15_active_dashboard_copy_is_beginner_facing():
    text = _project_source()
    assert "Üretilen public dosyalar ve raporlar proje klasörü altında düzenli tutulur." in text
    assert "Project-relative public/generated output'lar" not in text
    assert "local preferences" not in text
    assert "yerel ayarlarda" in text


def test_alpha15_empty_dashboard_hides_large_empty_tables():
    text = _project_source()
    assert "self.artifact_frame.setVisible(has_artifacts)" in text
    assert "self.history_frame.setVisible(has_history)" in text
    assert "self.dashboard_content.setCurrentWidget(self.dashboard_empty if is_empty else self.dashboard_populated)" in text
