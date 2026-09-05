from __future__ import annotations

from am64x_secure_toolkit.services.presentation import error_guidance, image_anatomy_model, result_presentation


def test_result_presentation_hides_full_output_path_and_humanizes_checks():
    result = {
        "status": "PASS",
        "operation": "application_build",
        "summary": "done",
        "checks": [{"check": "signing_key_preflight", "status": "PASS"}],
        "outputs": [{"type": "application_image", "path": "/home/example/private/work/app.hs"}],
        "claims": ["host-side"],
        "non_claims": ["hardware"],
    }
    model = result_presentation(result)
    assert model.title == "Secure Application"
    assert model.status_text == "Başarılı"
    assert model.checks[0]["title"] == "Signing key ön kontrolü"
    assert model.outputs[0]["name"] == "app.hs"
    assert "/home/example" not in str(model.outputs)


def test_image_anatomy_for_encrypted_application_uses_parsed_sizes_only():
    inspection = {
        "classification": "encrypted+signed application/generic data",
        "file": "app.hs",
        "file_size": 1200,
        "certificate_size": 200,
        "appended_size": 1000,
        "decoded": {},
    }
    model = image_anatomy_model(inspection)
    assert [x["label"] for x in model["blocks"]] == ["X.509 Certificate", "Ciphertext"]
    assert [x["size"] for x in model["blocks"]] == [200, 1000]
    assert "offset" not in model["blocks"][1]
    assert "address" not in model["blocks"][1]


def test_image_anatomy_for_rom_uses_declared_components_without_inference():
    inspection = {
        "classification": "ROM combined image",
        "file": "tiboot3.bin",
        "file_size": 1000,
        "certificate_size": 100,
        "appended_size": 900,
        "decoded": {
            "rom_ext_boot_info": {
                "components": [
                    {"component_name": "SBL", "comp_size": 300, "comp_type": 1},
                    {"component_name": "SYSFW", "comp_size": 600, "comp_type": 2},
                ]
            }
        },
    }
    model = image_anatomy_model(inspection)
    assert [x["label"] for x in model["blocks"]] == ["X.509 Certificate", "SBL", "SYSFW"]
    assert sum(x["size"] for x in model["blocks"]) == 1000


def test_guided_error_has_what_why_action_and_technical():
    guide = error_guidance(ValueError("SBL load address boş bırakılamaz"))
    assert guide["title"] == "Girdi doğrulanamadı"
    assert "SBL load address" in guide["what"]
    assert guide["why"]
    assert guide["action"]
    assert guide["technical"].startswith("ValueError:")


def test_alpha6_gui_source_contract():
    from pathlib import Path
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit" / "gui" / "pages"
    application = (root / "application.py").read_text(encoding="utf-8")
    inspector = (root / "inspector.py").read_text(encoding="utf-8")
    reports = (root / "reports.py").read_text(encoding="utf-8")
    common = (root / "common.py").read_text(encoding="utf-8")
    assert "QStackedWidget" in application
    assert "STEP_NAMES" in application
    assert "ImageAnatomyWidget" in inspector
    assert "HumanResultView" in reports
    assert "show_guided_error" in common
