from __future__ import annotations

from pathlib import Path

from am64x_secure_toolkit.constants import TI_OIDS
from am64x_secure_toolkit.services.certificate_explorer import certificate_explorer_model
from am64x_secure_toolkit.services.key_roles import key_role, list_key_roles


def test_certificate_explorer_separates_context_consumer_and_extension_claims():
    inspection = {
        "classification": "encrypted+signed application/generic data",
        "subject": "CN=Test",
        "issuer": "CN=Test",
        "spki_sha256": "ab" * 32,
        "signature_algorithm_oid": "1.2.840.113549.1.1.13",
        "signature_hash_algorithm": "sha512",
        "tisci_request_semantics": "authenticated_processor_boot",
        "extensions": [
            {"oid": TI_OIDS["sysfw_image_integrity"], "name": "sysfw_image_integrity", "critical": False},
            {"oid": TI_OIDS["sysfw_encryption"], "name": "sysfw_encryption", "critical": False},
        ],
        "decoded": {
            "sysfw_image_integrity": {"image_size": 512, "sha_type": "sha512"},
            "sysfw_encryption": {"iteration_count": 0},
        },
    }
    model = certificate_explorer_model(inspection)
    assert model["context"] == "Application / generalized-auth certificate"
    assert model["consumer"] == "System Firmware / TIFS"
    integrity = next(x for x in model["entries"] if x.get("oid") == TI_OIDS["sysfw_image_integrity"])
    assert "SHA2-512" in integrity["meaning"]
    assert "Certificate signature" in integrity["does_not_prove"]
    assert integrity["source_id"] == "TISCI-AUTH"


def test_certificate_explorer_keeps_rom_and_keywriter_contexts_distinct():
    rom = certificate_explorer_model({"classification": "ROM combined image", "extensions": [], "decoded": {}})
    kw = certificate_explorer_model({"classification": "Keywriter X.509 certificate", "extensions": [], "decoded": {}})
    assert rom["context"] != kw["context"]
    assert rom["consumer"] == "ROM / RBL"
    assert kw["consumer"] == "OTP Keywriter"


def test_key_role_cards_cover_application_and_provisioning_roles():
    roles = {x["role"] for x in list_key_roles()}
    assert roles == {"application-signing", "application-mek", "smpk", "bmpk", "smek", "bmek"}
    assert key_role("smpk")["algorithm"] == "RSA-4096"
    assert "OTP/eFuse write" in key_role("smpk")["warning"]
    assert key_role("application-mek")["algorithm"] == "AES-256"


def test_alpha7_gui_source_contract():
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit" / "gui" / "pages"
    rom = (root / "rom.py").read_text(encoding="utf-8")
    cert = (root / "certificate.py").read_text(encoding="utf-8")
    keys = (root / "keys.py").read_text(encoding="utf-8")
    home = (root / "home.py").read_text(encoding="utf-8")
    assert "QStackedWidget" in rom and "STEP_NAMES" in rom and "Source Trace'e Git" in rom
    assert "QTreeWidget" in cert and "certificate_explorer_model" in cert and "Ne kanıtlamaz?" in cert
    assert "Key Rolleri" in keys and "list_key_roles" in keys and "Public identity" in keys
    assert "Son İşlem" in home and "Environment" in home and "Project" in home and "_task_card" in home
