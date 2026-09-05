from __future__ import annotations

import ast
from pathlib import Path

from am64x_secure_toolkit.services.demo import create_demo_workspace
from am64x_secure_toolkit.services.explanations import explain_check, list_learning_cards
from am64x_secure_toolkit.services.guidance import recommend_workflow
from am64x_secure_toolkit.services.source_registry import get_source, list_sources, source_card


def test_source_registry_has_priority_and_local_reference_metadata():
    rows = list_sources()
    assert rows
    assert rows[0]["priority"] == 1
    auth = get_source("TISCI-AUTH")
    assert auth["expected_filename"].startswith("TISCI-04")
    assert "SHA2-512" in source_card("TISCI-AUTH")


def test_learning_cards_keep_host_target_boundary():
    cards = list_learning_cards()
    text = " ".join(c["body"] for c in cards)
    assert "hardware authentication/decryption enforcement" in text.lower()
    assert any(c["id"] == "signature-vs-hash" for c in cards)


def test_check_explanation_is_source_backed_when_known():
    out = explain_check("appended_payload_sha512_binding")
    assert "bağımsız" in out["explanation"]
    assert "TISCI-AUTH" in out["sources"]


def test_guided_decision_routes_existing_image_to_inspector():
    out = recommend_workflow(has_image=True, goal="verify")
    assert out["workflow"] == "inspector"
    assert "hardware" in out["safety_note"].lower()


def test_guided_decision_provisioning_never_promises_execution():
    out = recommend_workflow(has_image=False, goal="application", provisioning_interest=True)
    assert out["workflow"] == "provisioning"
    assert "OTP/eFuse" in out["safety_note"]


def test_educational_demo_is_explicitly_not_target_ready(tmp_path: Path):
    out = create_demo_workspace(tmp_path / "demo")
    assert out["status"] == "PASS"
    assert "NOT_TARGET_READY" in out["classification"]
    obs = out["expected_observations"]
    assert obs["certificate_signature"] is True
    assert obs["payload_integrity"] is True
    assert obs["load_extension_intentionally_missing"] is True
    assert obs["negative_payload_detected"] is True
    assert any("target-ready" in x.lower() for x in out["non_claims"])


def test_phase7_gui_sources_are_present_and_syntax_valid():
    gui = Path(__file__).parents[1] / "src/am64x_secure_toolkit/gui"
    for rel in ["pages/guide.py", "pages/learn.py", "pages/demo.py", "pages/source_trace.py", "pages/reports.py"]:
        p = gui / rel
        assert p.is_file()
        ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
    main = (gui / "main_window.py").read_text(encoding="utf-8")
    for cls in ["GuidePage", "LearnPage", "DemoPage", "SourceTracePage"]:
        assert cls in main
