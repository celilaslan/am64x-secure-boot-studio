from __future__ import annotations

from pathlib import Path


def _project_source() -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / "src/am64x_secure_toolkit/gui/pages/project.py").read_text(encoding="utf-8")


def test_alpha14_project_setup_and_dashboard_are_separate_states():
    text = _project_source()
    assert "QStackedWidget" in text
    assert "self.setup_page" in text
    assert "self.dashboard_page" in text
    assert "project is None or self._force_setup" in text


def test_alpha14_project_beginner_copy_and_primary_action_contract():
    text = _project_source()
    assert "Proje Çalışma Alanı" in text
    assert "Proje klasörü" in text
    assert "Mevcut Projeyi Aç" in text
    assert 'self.create_btn.setObjectName("primaryAction")' in text
    assert "Persistent Activity History" not in text
    assert "Generated Artifact Index" not in text
    assert "sessions/activity.jsonl" not in text


def test_alpha14_recent_project_normal_display_avoids_full_host_path():
    text = _project_source()
    assert "p.parent" not in text
    assert "item.setToolTip(raw)" not in text
    assert "p.name or \"AM64x Project\"" in text


def test_alpha14_project_create_requires_explicit_folder_selection():
    text = _project_source()
    assert "_root_or_choose" in text
    assert 'QFileDialog.getExistingDirectory(self, title)' in text
    assert 'create_project(\n                root,' in text
