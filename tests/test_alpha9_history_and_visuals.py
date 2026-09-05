from __future__ import annotations

from pathlib import Path

from am64x_secure_toolkit.sdk_diff import compare_sdk_security
from am64x_secure_toolkit.services.presentation import status_text
from am64x_secure_toolkit.services.project import (
    compact_project_event,
    create_project,
    project_dashboard,
    read_project_events,
    record_project_event,
)
from am64x_secure_toolkit.services.sdk_compare import sdk_diff_view_model
from am64x_secure_toolkit.services.workflow_visuals import generic_data_visual_model, secure_debug_visual_model
from am64x_secure_toolkit.services.ui_contract import SECURE_DEBUG_TRANSPORT_OPTIONS


def test_sdk_diff_view_is_semantic_and_hides_configured_key_paths(tmp_path: Path):
    raw = {
        "status": "PARTIAL",
        "labels": {"old": "old", "new": "new"},
        "comparisons": {
            "devconfig": {
                "classification": "MAPPED_SECURITY_BEHAVIOR_CHANGED",
                "review": "REQUIRED",
                "same_sha256": False,
                "old": {"sha256": "a" * 64, "secret_hygiene": []},
                "new": {"sha256": "b" * 64, "secret_hygiene": []},
                "semantic_changes": [{
                    "field": "assignments.APP_SIGNING_KEY.value",
                    "before": "/home/alice/private-old.pem",
                    "after": "/home/alice/private-new.pem",
                }],
            }
        },
        "summary": {
            "security_review_required": ["devconfig"],
            "manual_review_recommended": [],
            "identical": [],
            "secret_hygiene_errors": [],
            "secret_hygiene_warnings": [],
        },
        "interpretation": {"not_a_proof": "not a proof"},
    }
    model = sdk_diff_view_model(raw)
    text = str(model)
    assert "/home/alice" not in text
    assert "<configured value hidden>" in text
    assert model["roles"][0]["review"] == "REQUIRED"


def test_project_activity_event_never_persists_full_or_secret_paths(tmp_path: Path):
    result = {
        "operation": "application_build",
        "status": "PASS",
        "summary": "Build tamamlandı.",
        "private_key": "/home/alice/customer/private.pem",
        "outputs": [{"type": "application", "path": "/home/alice/work/firmware.appimage"}],
        "checks": [{"check": "post_verify", "status": "PASS", "detail": "/home/alice/work/firmware.appimage"}],
    }
    event = compact_project_event(result)
    text = str(event)
    assert "/home/alice" not in text
    assert "private.pem" not in text
    assert event["outputs"][0]["name"] == "firmware.appimage"
    assert event["secret_paths_stored"] is False
    assert event["full_host_paths_stored"] is False


def test_project_activity_persists_and_dashboard_loads_it(tmp_path: Path):
    project = create_project(tmp_path / "studio", name="Demo")
    record_project_event(project, {"operation": "inspect", "status": "PASS", "summary": "Inspection complete"})
    rows = read_project_events(project)
    assert len(rows) == 1
    assert rows[0]["operation"] == "inspect"
    dash = project_dashboard(project)
    assert dash["activity_count_loaded"] == 1
    assert dash["activity_log"] == "sessions/activity.jsonl"
    assert dash["secret_paths_stored"] is False


def test_secure_debug_visual_keeps_policy_decision_separate_from_target_acceptance():
    result = {
        "status": "PASS",
        "policy_decision": "REJECT_BY_POLICY",
        "transport": "tisci",
        "checks": [
            {"check": "certificate_type", "status": "PASS"},
            {"check": "software_revision_extension", "status": "PASS"},
            {"check": "debug_extension", "status": "PASS"},
            {"check": "allow_jtag_unlock", "status": "FAIL"},
            {"check": "jtag_efuse_connectivity", "status": "PASS"},
            {"check": "active_customer_root_of_trust", "status": "NOT_CHECKED"},
        ],
    }
    model = secure_debug_visual_model(result)
    nodes = model["lanes"][0]["nodes"]
    assert nodes[-1]["label"] == "REJECT_BY_POLICY"
    assert nodes[-1]["status"] == "FAIL"
    assert any("target acceptance" in x["text"].lower() for x in model["callouts"])


def test_generic_data_visual_never_calls_target_api_executed():
    model = generic_data_visual_model({
        "status": "PASS",
        "mode": "encrypted+signed",
        "checks": [
            {"check": "generalized_authentication_extension_set", "status": "PASS"},
            {"check": "decryption_random_string", "status": "PASS"},
        ],
    })
    nodes = model["lanes"][0]["nodes"]
    target = [x for x in nodes if x["label"] == "TISCI_MSG_PROC_AUTH_BOOT"][0]
    assert target["status"] == "NOT_CHECKED"



def test_secure_debug_gui_transport_contract_matches_backend_values():
    assert {value for _, value in SECURE_DEBUG_TRANSPORT_OPTIONS} == {"tisci", "sec-ap"}

def test_not_applicable_is_human_readable():
    assert status_text("NOT_APPLICABLE") == "Uygulanmaz"


def test_alpha9_gui_sources_use_human_views_and_persistent_project_history():
    root = Path(__file__).resolve().parents[1] / "src/am64x_secure_toolkit/gui/pages"
    secure_debug = (root / "secure_debug.py").read_text(encoding="utf-8")
    generic = (root / "generic_data.py").read_text(encoding="utf-8")
    reports = (root / "reports.py").read_text(encoding="utf-8")
    sdk = (root / "sdk.py").read_text(encoding="utf-8")
    assert "HumanResultView" in secure_debug and "FlowDiagramWidget" in secure_debug
    assert 'addItems(["sec-ap","tisci","jtag"])' not in secure_debug
    assert "HumanResultView" in generic and "generic_data_visual_model" in generic
    assert "Project History" in reports and "project_history" in reports
    assert "SdkDiffResultView" in sdk
