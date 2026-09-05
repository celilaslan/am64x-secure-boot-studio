from __future__ import annotations

from pathlib import Path

from am64x_secure_toolkit.constants import TI_OIDS
from am64x_secure_toolkit.services.certificate_explorer import certificate_explorer_model
from am64x_secure_toolkit.services.claim_boundary import attach_claims
from am64x_secure_toolkit.services.presentation import result_presentation
from am64x_secure_toolkit.services.ui_contract import SDK_INTENT_OPTIONS, SWREV_CONTEXT_OPTIONS
from am64x_secure_toolkit.services.workflow_visuals import (
    boardcfg_policy_visual_model,
    key_revision_visual_model,
    provisioning_visual_model,
    sdk_consumer_chain_model,
    swrev_visual_model,
    writer_authorization_visual_model,
)


def _part(*checks):
    return {"checks": list(checks)}


def test_sdk_consumer_chain_keeps_application_and_rom_controls_separate():
    result = {
        "status": "PASS",
        "inputs": {
            "devconfig": _part(),
            "app_makefile": _part(
                {"check": "application_encryption_selector", "status": "PASS"},
                {"check": "application_encryption_options", "status": "PASS"},
            ),
            "sbl_makefile": _part(
                {"check": "sbl_encryption_selector", "status": "PASS"},
                {"check": "sbl_encryption_options", "status": "PASS"},
            ),
            "app_tool": _part(
                {"check": "application_cli_contract", "status": "PASS"},
                {"check": "application_encryption_oid", "status": "PASS"},
            ),
            "rom_tool": _part(
                {"check": "rom_cli_contract", "status": "PASS"},
                {"check": "rom_sbl_encryption_oid", "status": "PASS"},
            ),
        },
        "cross_checks": [{"check": "separate_encryption_control_chains", "status": "PASS"}],
    }
    model = sdk_consumer_chain_model(result)
    assert [x["label"] for x in model["lanes"]] == ["Application encryption", "ROM/SBL encryption"]
    app_text = " ".join(n["detail"] for n in model["lanes"][0]["nodes"])
    rom_text = " ".join(n["detail"] for n in model["lanes"][1]["nodes"])
    assert "ENC_ENABLED" in app_text
    assert "ENC_SBL_ENABLED" in rom_text
    assert ".1.4" in app_text and ".1.10" in rom_text


def test_provisioning_visual_never_contains_secret_value_path_or_hash():
    result = {
        "status": "PASS",
        "key_count": 2,
        "key_revision": 1,
        "active_key_context": "SMPK/SMEK",
        "public_key_material": {
            "smpk": {"rsa_bits": 4096, "provisioning_sha512": "aa" * 64},
            "bmpk": {"rsa_bits": 4096, "provisioning_sha512": "bb" * 64},
        },
        "secret_format_checks": {"smek": {"status": "PASS"}, "bmek": {"status": "PASS"}},
        "checks": [
            {"check": "smpk_rsa4096", "status": "PASS"},
            {"check": "smpkh_sha512", "status": "PASS"},
            {"check": "bmpk_rsa4096", "status": "PASS"},
            {"check": "bmpkh_sha512", "status": "PASS"},
            {"check": "key_count", "status": "PASS"},
            {"check": "key_revision", "status": "PASS"},
        ],
    }
    text = str(provisioning_visual_model(result))
    assert "aa" * 16 not in text
    assert "bb" * 16 not in text
    assert "/home/" not in text
    assert "OTP Keywriter" in text
    assert "NOT_CHECKED" in text


def test_revision_and_boardcfg_visual_models_preserve_non_execution_boundary():
    key = key_revision_visual_model({
        "status": "PASS", "key_count": 2, "key_revision": 1,
        "active_key_context": {"label": "SMPK/SMEK"},
        "requested_state": {"key_revision": 2, "status": "PASS", "active_key_context": {"label": "BMPK/BMEK"}},
    })
    assert "Target write" in str(key)
    assert "NOT_CHECKED" in str(key)

    sw = swrev_visual_model({
        "status": "PASS", "context": "tiboot3", "reference_revision": 2,
        "certificate_revision": 3, "decision": "ACCEPT_BY_SWREV", "decision_is_source_defined": True,
        "decision_basis": "source-defined compare",
    })
    assert "target acceptance" in str(sw).lower()

    board = boardcfg_policy_visual_model({
        "status": "PASS",
        "normalized": {"secure_debug": {"jtag_unlock_hosts": [5]}, "extended_otp": {"write_host": 5}},
        "summary": {"runtime_jtag_unlock": "ENABLED", "wildcard_uid_policy": "DISABLED"},
        "checks": [{"check": "otp_write_host", "status": "PASS"}],
    })
    assert "BoardCfg target'a gönderilmez" in str(board)

    writer = writer_authorization_visual_model({
        "status": "PASS", "decision": "AUTHORIZED_BY_BOARDCFG",
        "requester_host": 5, "configured_write_host": 5, "detail": "matches",
    })
    assert "TISCI write request" in str(writer)


def test_every_presented_check_has_neden_explanation_even_without_specific_mapping():
    model = result_presentation({
        "status": "FAIL",
        "operation": "sdk_lint",
        "checks": [
            {"check": "application_encryption_selector", "status": "PASS", "detail": "mapped"},
            {"check": "future_unknown_check", "status": "FAIL", "detail": "missing"},
        ],
    })
    assert len(model.checks) == 2
    assert all(x["why"] for x in model.checks)
    assert all(isinstance(x["sources"], list) for x in model.checks)
    assert "sağlanmadığı" in model.checks[1]["why"]


def test_certificate_explorer_entries_map_to_image_anatomy_targets():
    app = certificate_explorer_model({
        "classification": "encrypted+signed application/generic data",
        "extensions": [
            {"oid": TI_OIDS["sysfw_image_integrity"], "name": "integrity"},
            {"oid": TI_OIDS["sysfw_encryption"], "name": "encryption"},
        ],
        "decoded": {},
    })
    app_targets = {x["oid"]: x["anatomy_target"] for x in app["entries"] if x.get("oid")}
    assert app_targets[TI_OIDS["sysfw_image_integrity"]] == "payload_or_ciphertext"
    assert app_targets[TI_OIDS["sysfw_encryption"]] == "payload_or_ciphertext"

    rom = certificate_explorer_model({
        "classification": "ROM combined image",
        "extensions": [{"oid": TI_OIDS["rom_ext_boot_info"], "name": "rom"}],
        "decoded": {},
    })
    ext = next(x for x in rom["entries"] if x.get("oid") == TI_OIDS["rom_ext_boot_info"])
    assert ext["anatomy_target"] == "rom_components"


def test_alpha8_ui_contract_fixes_backend_enum_drift():
    assert dict(SDK_INTENT_OPTIONS)["Production review"] == "production"
    values = {value for _, value in SWREV_CONTEXT_OPTIONS}
    assert values == {"tiboot3", "boardcfg", "debug", "application", "generic"}
    assert "production-review" not in values
    assert "generic-data" not in values


def test_attach_claims_stamps_operation_for_human_presentation():
    result = attach_claims({"status": "PASS"}, "revision", "PASS")
    assert result["operation"] == "revision"
    assert result_presentation(result).title == "KEYREV / SWREV Simulator"


def test_alpha8_gui_source_contract():
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit" / "gui"
    widgets = (root / "widgets.py").read_text(encoding="utf-8")
    sdk = (root / "pages" / "sdk.py").read_text(encoding="utf-8")
    provisioning = (root / "pages" / "provisioning.py").read_text(encoding="utf-8")
    revision = (root / "pages" / "revision.py").read_text(encoding="utf-8")
    boardcfg = (root / "pages" / "boardcfg.py").read_text(encoding="utf-8")
    certificate = (root / "pages" / "certificate.py").read_text(encoding="utf-8")
    assert "class FlowDiagramWidget" in widgets
    assert 'QPushButton("Neden?")' in widgets
    assert "sdk_consumer_chain_model" in sdk and "FlowDiagramWidget" in sdk
    assert "provisioning_visual_model" in provisioning
    assert "SWREV_CONTEXT_OPTIONS" in revision and "swrev_visual_model" in revision
    assert "boardcfg_policy_visual_model" in boardcfg
    assert "Certificate ↔ Image Anatomy" in certificate and "highlight_for_target" in certificate
