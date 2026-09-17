from __future__ import annotations

import ast
from pathlib import Path

GUI = Path(__file__).parents[1] / "src/am64x_secure_toolkit/gui"


def test_phase5_phase6_gui_modules_are_syntax_valid_and_present():
    required = [
        "pages/rom.py", "pages/certificate.py", "pages/sdk.py", "pages/errata.py",
        "pages/provisioning.py", "pages/revision.py", "pages/boardcfg.py",
        "pages/secure_debug.py", "pages/generic_data.py",
    ]
    for rel in required:
        p = GUI / rel
        assert p.is_file(), rel
        ast.parse(p.read_text(encoding="utf-8"), filename=str(p))


def test_main_window_has_no_placeholder_for_phase5_phase6():
    text = (GUI / "main_window.py").read_text(encoding="utf-8")
    assert "PlaceholderPage" not in text
    for cls in ["RomPage", "CertificatePage", "SdkPage", "ErrataPage", "ProvisioningPage", "RevisionPage", "BoardCfgPage", "SecureDebugPage", "GenericDataPage"]:
        assert cls in text


def test_irreversible_execution_labels_are_not_exposed_as_actions():
    text = "\n".join(p.read_text(encoding="utf-8") for p in (GUI / "pages").glob("*.py"))
    forbidden_button_labels = ["BURN EFUSE", "PROVISION DEVICE", "HS-FS -> HS-SE EXECUTE", "WRITE OTP"]
    upper = text.upper()
    for item in forbidden_button_labels:
        assert item not in upper
