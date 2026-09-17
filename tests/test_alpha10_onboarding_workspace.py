from __future__ import annotations

from pathlib import Path

from am64x_secure_toolkit.services.onboarding import onboarding_model
from am64x_secure_toolkit.services.project import (
    compact_project_artifacts,
    create_project,
    path_is_within_project,
    project_dashboard,
    project_safe_reference,
    read_project_artifacts,
    record_project_artifacts,
    suggest_project_output,
)
from am64x_secure_toolkit.services.ux_audit import audit_gui_sources


def test_onboarding_routes_beginner_through_environment_project_then_workflow():
    first = onboarding_model(environment_checked=False, environment_ready=False, project_active=False, has_result=False)
    assert first.recommended_page == "environment"
    assert first.steps[0].state == "CURRENT"

    second = onboarding_model(environment_checked=True, environment_ready=True, project_active=False, has_result=False)
    assert second.recommended_page == "project"
    assert [x.state for x in second.steps[:2]] == ["DONE", "CURRENT"]

    third = onboarding_model(environment_checked=True, environment_ready=True, project_active=True, has_result=False)
    assert third.recommended_page == "guide"
    assert third.ready_for_first_workflow is True


def test_project_output_suggestions_are_deterministic_and_project_relative(tmp_path: Path):
    project = create_project(tmp_path / "studio", name="Demo")
    app = suggest_project_output(project, workflow="application", source="hello world.mcelf", encrypted=True)
    rom = suggest_project_output(project, workflow="rom", source="sbl_uart.bin")
    report = suggest_project_output(project, workflow="report", source="artifact.hs")
    negative = suggest_project_output(project, workflow="negative", source="artifact.hs")
    public = suggest_project_output(project, workflow="public", source="customer key.pem")

    assert app == project.root / "outputs" / "hello_world_encrypted_secure_application"
    assert rom == project.root / "outputs" / "sbl_uart.tiimage"
    assert report.parent == project.root / "reports"
    assert negative.parent == project.root / "negative-tests"
    assert public.parent == project.root / "public"


def test_project_path_policy_detects_secret_generation_inside_workspace(tmp_path: Path):
    project = create_project(tmp_path / "studio", name="Demo")
    assert path_is_within_project(project, project.root / "outputs") is True
    assert path_is_within_project(project, tmp_path / "separate-secret-vault") is False


def test_project_safe_reference_never_persists_external_full_path(tmp_path: Path):
    project = create_project(tmp_path / "studio", name="Demo")
    inside = project.root / "outputs" / "firmware.appimage"
    outside = tmp_path / "host-specific" / "firmware.appimage"
    assert project_safe_reference(project, inside) == {"scope": "project", "path": "outputs/firmware.appimage"}
    ref = project_safe_reference(project, outside)
    assert ref == {"scope": "external-name-only", "path": "firmware.appimage"}
    assert "host-specific" not in str(ref)


def test_project_artifact_index_hashes_generated_public_output_without_secret_path(tmp_path: Path):
    project = create_project(tmp_path / "studio", name="Demo")
    output = project.root / "outputs" / "image.bin"
    output.write_bytes(b"public generated artifact")
    result = {
        "operation": "application_build",
        "status": "PASS",
        "private_key": "/home/alice/secret.pem",
        "outputs": [{"type": "application_image", "path": str(output)}],
    }
    records = record_project_artifacts(project, result)
    assert len(records) == 1
    assert records[0]["reference"] == {"scope": "project", "path": "outputs/image.bin"}
    assert records[0]["sha256"]
    assert "/home/alice" not in str(records)
    loaded = read_project_artifacts(project)
    assert loaded == records
    dash = project_dashboard(project)
    assert dash["artifact_count_loaded"] == 1
    assert dash["artifact_index"] == "sessions/artifacts.jsonl"


def test_compact_project_artifacts_external_output_is_basename_only(tmp_path: Path):
    project = create_project(tmp_path / "studio", name="Demo")
    external = tmp_path / "different-host-dir" / "report.md"
    external.parent.mkdir(); external.write_text("report", encoding="utf-8")
    rows = compact_project_artifacts(project, {"operation": "image_report", "status": "PASS", "outputs": [{"type": "report", "path": str(external)}]})
    assert rows[0]["reference"] == {"scope": "external-name-only", "path": "report.md"}
    assert "different-host-dir" not in str(rows[0]["reference"])


def test_alpha10_gui_sources_are_project_aware_and_protect_secret_generation():
    root = Path(__file__).resolve().parents[1] / "src/am64x_secure_toolkit/gui/pages"
    home = (root / "home.py").read_text(encoding="utf-8")
    application = (root / "application.py").read_text(encoding="utf-8")
    rom = (root / "rom.py").read_text(encoding="utf-8")
    keys = (root / "keys.py").read_text(encoding="utf-8")
    negative = (root / "negative.py").read_text(encoding="utf-8")
    reports = (root / "reports.py").read_text(encoding="utf-8")
    project = (root / "project.py").read_text(encoding="utf-8")

    assert "Hızlı Başlangıç" in home and "onboarding_model" in home
    assert "Proje Önerisini Kullan" in application and "suggest_project_output" in application
    assert "Project Output Kullan" in rom and "suggest_project_output" in rom
    assert "Secret-generating key output dizini Project Workspace içinde olamaz" in keys
    assert "Project Public DER Kullan" in keys
    assert "Project Negative-Test" in negative
    assert "Project Reports Kullan" in reports
    assert "Üretilen Dosyalar" in project
    assert "Proje Çalışma Alanı" in project
    assert "Mevcut Projeyi Aç" in project


def test_beta_ux_source_audit_has_zero_findings():
    root = Path(__file__).resolve().parents[1]
    result = audit_gui_sources(root)
    assert result["status"] == "PASS"
    assert result["error_count"] == 0
    assert result["warning_count"] == 0
    assert result["real_qt_render_qa"] == "NOT_EXECUTED_BY_THIS_AUDIT"


def test_reporting_result_exposes_generated_outputs_for_project_artifact_index(tmp_path: Path):
    # We only assert the output contract here; cryptographic report content is covered by test_reporting.py.
    # Image parsing is covered by test_reporting.py; this test uses a minimal synthetic result contract.
    result = {
        "operation": "image_report",
        "status": "PASS",
        "outputs": [
            {"type": "markdown_report", "path": str(tmp_path / "reports" / "r.md")},
            {"type": "json_report", "path": str(tmp_path / "reports" / "r.json")},
        ],
    }
    project = create_project(tmp_path / "studio-report", name="Report")
    rows = compact_project_artifacts(project, result)
    assert [x["type"] for x in rows] == ["markdown_report", "json_report"]
    assert all(x["full_host_path_stored"] is False for x in rows)
