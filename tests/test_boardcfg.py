from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from am64x_secure_toolkit.boardcfg import (
    check_boardcfg_profile,
    evaluate_debug_policy,
    evaluate_revision_writer,
    save_boardcfg_profile,
    template_boardcfg_profile,
)
from am64x_secure_toolkit.certificate import build_certificate


@pytest.fixture(scope="module")
def debug_key(tmp_path_factory):
    root = tmp_path_factory.mktemp("boardcfg-debug-key")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    path = root / "debug.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _debug_cert(tmp_path: Path, debug_key: Path, *, revision: int = 3, uid: str = "11" * 32) -> Path:
    profile = {
        "type": "debug",
        "subject": {"common_name": "AM64x Debug Policy Test"},
        "software_revision": revision,
        "debug": {
            "soc_uid": uid,
            "wildcard_uid": False,
            "privilege": 0,
            "reserved": 0,
            "nonsecure_core_ids": [255],
            "secure_core_ids": [255],
        },
        "valid_days": 30,
    }
    profile_path = tmp_path / f"debug-{revision}.yaml"
    _write_yaml(profile_path, profile)
    cert_path = tmp_path / f"debug-{revision}.der"
    build_certificate(profile_path, debug_key, cert_path)
    return cert_path


def test_template_is_safe_and_valid(tmp_path: Path):
    profile = template_boardcfg_profile()
    assert profile["secure_debug"]["allow_jtag_unlock"] == 0
    assert profile["secure_debug"]["allow_wildcard_unlock"] == 0
    assert check_boardcfg_profile(profile)["status"] == "PASS"

    path = tmp_path / "boardcfg.yaml"
    save_boardcfg_profile(profile, path)
    assert path.exists()
    assert check_boardcfg_profile(path)["status"] == "PASS"


def test_invalid_debug_flag_is_rejected():
    profile = template_boardcfg_profile()
    profile["secure_debug"]["allow_jtag_unlock"] = 1
    result = check_boardcfg_profile(profile)
    assert result["status"] == "FAIL"
    assert any(c["check"] == "allow_jtag_unlock" and c["status"] == "FAIL" for c in result["checks"])


def test_reserved_fields_must_be_zero():
    profile = template_boardcfg_profile()
    profile["secure_debug"]["allow_debug_level_rsvd"] = 1
    result = check_boardcfg_profile(profile)
    assert result["status"] == "FAIL"


def test_wildcard_host_cannot_be_otp_write_host():
    profile = template_boardcfg_profile()
    profile["extended_otp"]["write_host"] = 128
    result = check_boardcfg_profile(profile)
    assert result["status"] == "FAIL"
    assert any(c["check"] == "otp_write_host" and c["status"] == "FAIL" for c in result["checks"])


def test_disabled_jtag_with_wildcard_is_reported_as_warning():
    profile = template_boardcfg_profile()
    profile["secure_debug"]["allow_wildcard_unlock"] = 0x5A
    result = check_boardcfg_profile(profile)
    assert result["status"] == "PASS"
    assert result["warnings"]


def test_debug_policy_wildcard_sec_ap_allows_known_policy(tmp_path: Path, debug_key: Path):
    cert = _debug_cert(tmp_path, debug_key, revision=3)
    profile = template_boardcfg_profile()
    profile["secure_debug"]["allow_jtag_unlock"] = 0x5A
    profile["secure_debug"]["allow_wildcard_unlock"] = 0x5A
    profile["secure_debug"]["min_cert_rev"] = 2
    path = tmp_path / "policy.yaml"
    _write_yaml(path, profile)

    out = evaluate_debug_policy(path, cert, transport="sec-ap", jtag_efuse="enabled")
    assert out["status"] == "PASS"
    assert out["policy_decision"] == "POLICY_ALLOWS_REQUEST"
    assert out["target_acceptance"] == "NOT_VERIFIED"


def test_debug_policy_rejects_old_certificate_revision(tmp_path: Path, debug_key: Path):
    cert = _debug_cert(tmp_path, debug_key, revision=1)
    profile = template_boardcfg_profile()
    profile["secure_debug"]["allow_jtag_unlock"] = 0x5A
    profile["secure_debug"]["allow_wildcard_unlock"] = 0x5A
    profile["secure_debug"]["min_cert_rev"] = 2
    path = tmp_path / "old-policy.yaml"
    _write_yaml(path, profile)

    out = evaluate_debug_policy(path, cert, transport="sec-ap", jtag_efuse="enabled")
    assert out["status"] == "PASS"
    assert out["policy_decision"] == "REJECT_BY_POLICY"
    assert any(c["check"] == "min_cert_rev" and c["status"] == "FAIL" for c in out["checks"])


def test_debug_policy_checks_tisci_host_and_uid(tmp_path: Path, debug_key: Path):
    uid = "22" * 32
    cert = _debug_cert(tmp_path, debug_key, revision=5, uid=uid)
    profile = template_boardcfg_profile()
    profile["secure_debug"]["allow_jtag_unlock"] = 0x5A
    profile["secure_debug"]["min_cert_rev"] = 5
    profile["secure_debug"]["jtag_unlock_hosts"] = [10, 11, 12, 13]
    path = tmp_path / "tisci-policy.yaml"
    _write_yaml(path, profile)

    allowed = evaluate_debug_policy(
        path,
        cert,
        transport="tisci",
        host_id=11,
        soc_uid=uid,
        jtag_efuse="enabled",
    )
    assert allowed["policy_decision"] == "POLICY_ALLOWS_REQUEST"

    denied = evaluate_debug_policy(
        path,
        cert,
        transport="tisci",
        host_id=99,
        soc_uid=uid,
        jtag_efuse="enabled",
    )
    assert denied["policy_decision"] == "REJECT_BY_POLICY"


def test_debug_policy_is_indeterminate_without_target_uid(tmp_path: Path, debug_key: Path):
    cert = _debug_cert(tmp_path, debug_key, revision=2, uid="33" * 32)
    profile = template_boardcfg_profile()
    profile["secure_debug"]["allow_jtag_unlock"] = 0x5A
    profile["secure_debug"]["min_cert_rev"] = 1
    path = tmp_path / "uid-policy.yaml"
    _write_yaml(path, profile)

    out = evaluate_debug_policy(path, cert, transport="sec-ap", jtag_efuse="enabled")
    assert out["status"] == "PARTIAL"
    assert out["policy_decision"] == "INDETERMINATE"


def test_revision_writer_policy(tmp_path: Path):
    profile = template_boardcfg_profile()
    profile["extended_otp"]["write_host"] = 7
    path = tmp_path / "writer.yaml"
    _write_yaml(path, profile)

    allowed = evaluate_revision_writer(path, 7)
    assert allowed["decision"] == "AUTHORIZED_BY_BOARDCFG"
    assert allowed["execution"]["tisci_msg_write_swrev"] == "NOT_EXECUTED"

    denied = evaluate_revision_writer(path, 8)
    assert denied["decision"] == "NOT_AUTHORIZED_BY_BOARDCFG"
