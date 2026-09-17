from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from am64x_secure_toolkit.cli import main
from am64x_secure_toolkit.services.beta_readiness import beta_readiness
from am64x_secure_toolkit.services.diagnostics import diagnostics_snapshot, write_diagnostics
from am64x_secure_toolkit.services.environment import resolve_environment
from am64x_secure_toolkit.services.preferences import (
    UserPreferences,
    load_preferences,
    save_preferences,
    with_context,
    with_mode,
    with_recent_project,
    with_sdk_root,
)
from am64x_secure_toolkit.services.project import create_project
from am64x_secure_toolkit.services.ui_contract import page_visible
from am64x_secure_toolkit.services.ux_audit import audit_gui_sources


def test_preferences_round_trip_is_local_only_and_restrictive(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AM64X_STUDIO_CONFIG_HOME", str(tmp_path / "cfg"))
    project = tmp_path / "My Project"
    pref = UserPreferences()
    pref = with_mode(pref, "expert")
    pref = with_context(pref, device="AM6442", silicon_revision="SR2.0", lifecycle="HS-FS")
    pref = with_recent_project(pref, project)
    pref = with_sdk_root(pref, tmp_path / "ti" / "mcu_plus_sdk_am64x_12_00_00_27")
    path = save_preferences(pref)
    loaded = load_preferences()
    assert loaded.mode == "expert"
    assert loaded.recent_projects[0] == str(project.resolve())
    assert loaded.sdk_root == str((tmp_path / "ti" / "mcu_plus_sdk_am64x_12_00_00_27").resolve())
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["local_only"] is True
    assert payload["secret_values_stored"] is False
    assert payload["secret_paths_stored"] is False
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_preferences_recent_projects_are_deduplicated_and_bounded(tmp_path: Path):
    pref = UserPreferences()
    for i in range(12):
        pref = with_recent_project(pref, tmp_path / f"p{i}")
    assert len(pref.recent_projects) == 8
    latest = str((tmp_path / "p11").resolve())
    assert pref.recent_projects[0] == latest
    pref = with_recent_project(pref, tmp_path / "p10")
    assert pref.recent_projects[0] == str((tmp_path / "p10").resolve())
    assert len(pref.recent_projects) == 8


def test_diagnostics_snapshot_excludes_host_paths_and_secret_material(tmp_path: Path):
    project = create_project(tmp_path / "host-specific" / "studio", name="Demo")
    env = resolve_environment(tmp_path / "missing-sdk")
    snap = diagnostics_snapshot(environment=env, project=project)
    text = json.dumps(snap, ensure_ascii=False)
    assert str(tmp_path) not in text
    assert "host-specific" not in text
    assert snap["privacy"]["secret_values_included"] is False
    assert snap["privacy"]["secret_paths_included"] is False
    assert snap["privacy"]["full_host_paths_included"] is False
    assert snap["project"]["project_root_included"] is False


def test_diagnostics_exports_json_and_markdown_without_overwrite(tmp_path: Path):
    snap = diagnostics_snapshot(environment=resolve_environment(tmp_path / "missing-sdk"))
    j = write_diagnostics(snap, tmp_path / "diag.json")
    m = write_diagnostics(snap, tmp_path / "diag.md")
    assert json.loads(j.read_text(encoding="utf-8"))["operation"] == "share_safe_diagnostics"
    md = m.read_text(encoding="utf-8")
    assert "Secret paths: **NOT INCLUDED**" in md
    assert "Full host paths" in md
    with pytest.raises(FileExistsError):
        write_diagnostics(snap, j)


def test_beta_readiness_does_not_promote_dependency_presence_to_execution(tmp_path: Path):
    root = Path(__file__).resolve().parents[1]
    out = beta_readiness(root)
    assert out["status"] in {"PARTIAL", "FAIL"}
    assert out["real_qt_render"] == "NOT_EXECUTED"
    assert out["linux_clean_machine"] == "NOT_EXECUTED"
    assert out["windows_clean_machine"] == "NOT_EXECUTED"
    assert out["project_final_completion"] == "NOT_DECLARED"
    assert any("Qt" in x or "PySide6" in x for x in out["release_blockers"])


def test_diagnostics_and_beta_readiness_cli_commands(tmp_path: Path, capsys):
    rc = main(["diagnostics", "--sdk-root", str(tmp_path / "no-sdk"), "--compact"])
    assert rc == 0
    captured = capsys.readouterr().out
    assert '"operation": "share_safe_diagnostics"' in captured
    rc2 = main(["beta-readiness", "--source-root", str(Path(__file__).resolve().parents[1]), "--compact"])
    assert rc2 in {2, 3}
    captured2 = capsys.readouterr().out
    assert '"real_qt_render": "NOT_EXECUTED"' in captured2


def test_diagnostics_page_is_visible_and_beta_ux_audit_covers_it():
    assert page_visible("guided", "diagnostics") is True
    assert page_visible("expert", "diagnostics") is True
    root = Path(__file__).resolve().parents[1]
    result = audit_gui_sources(root)
    assert result["status"] == "PASS"
    assert result["page_count"] == 22
    assert any(x["check"] == "share_safe_diagnostics" and x["status"] == "PASS" for x in result["checks"])


def test_qt_and_standalone_smoke_harnesses_exist_and_keep_human_review_separate():
    root = Path(__file__).resolve().parents[1]
    qt = (root / "tools" / "qt_visual_qa.py").read_text(encoding="utf-8")
    stand = (root / "tools" / "standalone_smoke.py").read_text(encoding="utf-8")
    app = (root / "src/am64x_secure_toolkit/gui/app.py").read_text(encoding="utf-8")
    assert "human_visual_review" in qt and "NOT_EXECUTED" in qt
    assert "clean_machine_claim" in stand and "NOT_ESTABLISHED" in stand
    assert '"--smoke-test"' in app and "SECURESTUDIO_SMOKE=PASS" in app
