from pathlib import Path

from am64x_secure_toolkit.errata import check_errata, list_errata
from am64x_secure_toolkit.services.ui_contract import (
    BOOT_MODE_OPTIONS,
    ERRATA_CATEGORY_OPTIONS,
    ERRATA_CERT_INFO_OPTIONS,
    ERRATA_EMULATOR_OPTIONS,
    ERRATA_FLOW_OPTIONS,
    ERRATA_OUTER_RSA_OPTIONS,
    ERRATA_REDUNDANT_OPTIONS,
    EXPERT_PAGE_KEYS,
    GUIDED_PAGE_KEYS,
    page_visible,
)


def _values(options):
    return [value for _, value in options]


def test_guided_is_strict_subset_of_expert():
    assert set(GUIDED_PAGE_KEYS) < set(EXPERT_PAGE_KEYS)
    assert page_visible("guided", "application")
    assert not page_visible("guided", "provisioning")
    assert page_visible("expert", "provisioning")


def test_errata_list_gui_choices_match_backend_contract():
    for category in _values(ERRATA_CATEGORY_OPTIONS):
        for boot_mode in _values(BOOT_MODE_OPTIONS):
            out = list_errata(revision="SR2.0", category=category, boot_mode=boot_mode)
            assert out["status"] == "PASS"


def test_errata_context_gui_choices_match_backend_contract():
    # Validate every option family against the canonical backend using one variable at a time.
    base = dict(revision="SR2.0", device_state="hs-fs", flow="unknown", primary_boot="unknown", backup_boot="unknown", outer_rsa="unknown", certificate_info="unknown", redundant_content="unknown", external_emulator="unknown")
    for key, options in [
        ("flow", ERRATA_FLOW_OPTIONS),
        ("primary_boot", BOOT_MODE_OPTIONS),
        ("backup_boot", BOOT_MODE_OPTIONS),
        ("outer_rsa", ERRATA_OUTER_RSA_OPTIONS),
        ("certificate_info", ERRATA_CERT_INFO_OPTIONS),
        ("redundant_content", ERRATA_REDUNDANT_OPTIONS),
        ("external_emulator", ERRATA_EMULATOR_OPTIONS),
    ]:
        for value in _values(options):
            args = dict(base); args[key] = value
            assert check_errata(**args)["status"] == "PASS"


def test_alpha5_gui_sources_cover_missing_v1_capabilities():
    root = Path(__file__).resolve().parents[1] / "src" / "am64x_secure_toolkit" / "gui" / "pages"
    keys = (root / "keys.py").read_text(encoding="utf-8")
    negative = (root / "negative.py").read_text(encoding="utf-8")
    reports = (root / "reports.py").read_text(encoding="utf-8")
    cert = (root / "certificate.py").read_text(encoding="utf-8")
    inspector = (root / "inspector.py").read_text(encoding="utf-8")
    assert "preflight_signing_key" in keys and "compare_key_material" in keys and "preflight_mek" in keys
    assert "run_negative_suite" in negative and '"component"' in negative
    assert "write_image_report" in reports and "write_batch_report" in reports and "result_history" in reports
    assert "template_profile" in cert and "validate_profile_file" in cert and "build_certificate" in cert
    assert "dragEnterEvent" in inspector and "dropEvent" in inspector
