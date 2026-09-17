from __future__ import annotations

import json
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from am64x_secure_toolkit.profiles import validate_profile
from am64x_secure_toolkit.provision import provision_preflight, save_provision_profile, template_provision_profile


def _public_der(tmp_path: Path, name: str, bits: int = 4096) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    path = tmp_path / f"{name}.der"
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return path


def _write_profile(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def test_provision_template_contains_no_secret_fields(tmp_path: Path):
    profile = template_provision_profile()
    text = yaml.safe_dump(profile, sort_keys=False)
    assert "private_key" not in text
    assert "smek:" not in text.lower()
    assert "bmek:" not in text.lower()
    out = tmp_path / "provision.yaml"
    save_provision_profile(profile, out)
    assert out.is_file()


def test_keycount1_keyrev1_smpk_passes_and_hash_is_public(tmp_path: Path):
    smpk = _public_der(tmp_path, "smpk")
    profile_path = tmp_path / "provision.yaml"
    _write_profile(profile_path, {
        "type": "hsfs_to_hsse_preflight",
        "mode": "offline_only",
        "key_count": 1,
        "key_revision": 1,
        "smpk_public_der": str(smpk),
        "bmpk_public_der": None,
        "swrev": {"sysfw": None, "sbl": None, "boardcfg": None},
    })
    out = provision_preflight(profile_path)
    assert out["status"] == "PASS"
    assert out["active_key_context"] == "SMPK/SMEK"
    assert out["public_key_material"]["smpk"]["rsa_bits"] == 4096
    assert len(out["public_key_material"]["smpk"]["provisioning_sha512"]) == 128
    assert out["execution"]["otp_keywriter"] == "DISABLED"
    assert out["execution"]["hsfs_to_hsse_transition"] == "NOT_EXECUTED"


def test_keycount2_requires_bmpk(tmp_path: Path):
    smpk = _public_der(tmp_path, "smpk")
    profile_path = tmp_path / "provision.yaml"
    _write_profile(profile_path, {
        "type": "hsfs_to_hsse_preflight",
        "mode": "offline_only",
        "key_count": 2,
        "key_revision": 2,
        "smpk_public_der": str(smpk),
        "bmpk_public_der": None,
        "swrev": {},
    })
    out = provision_preflight(profile_path)
    assert out["status"] == "FAIL"
    assert any(c["check"] == "bmpk_public_der" and c["status"] == "FAIL" for c in out["checks"])


def test_keyrev2_is_rejected_for_keycount1(tmp_path: Path):
    smpk = _public_der(tmp_path, "smpk")
    profile_path = tmp_path / "provision.yaml"
    _write_profile(profile_path, {
        "type": "hsfs_to_hsse_preflight",
        "mode": "offline_only",
        "key_count": 1,
        "key_revision": 2,
        "smpk_public_der": str(smpk),
        "bmpk_public_der": None,
        "swrev": {},
    })
    out = provision_preflight(profile_path)
    assert out["status"] == "FAIL"
    assert any(c["check"] == "key_revision" and c["status"] == "FAIL" for c in out["checks"])


def test_secret_mek_paths_and_values_are_not_recorded(tmp_path: Path):
    smpk = _public_der(tmp_path, "smpk")
    secret_value = "a1" * 32
    smek = tmp_path / "very-secret-smek.txt"
    smek.write_text(secret_value, encoding="ascii")
    profile_path = tmp_path / "provision.yaml"
    _write_profile(profile_path, {
        "type": "hsfs_to_hsse_preflight",
        "mode": "offline_only",
        "key_count": 1,
        "key_revision": 1,
        "smpk_public_der": str(smpk),
        "bmpk_public_der": None,
        "swrev": {},
    })
    report = tmp_path / "report.json"
    out = provision_preflight(profile_path, smek=smek, report=report)
    assert out["status"] == "PASS"
    report_text = report.read_text(encoding="utf-8")
    assert secret_value not in report_text
    assert str(smek) not in report_text
    assert "very-secret-smek.txt" not in report_text
    parsed = json.loads(report_text)
    assert parsed["secret_material_recorded"] is False
    assert parsed["secret_path_recorded"] is False


def test_bad_smek_format_fails_preflight(tmp_path: Path):
    smpk = _public_der(tmp_path, "smpk")
    smek = tmp_path / "smek.txt"
    smek.write_text("ab" * 31, encoding="ascii")
    profile_path = tmp_path / "provision.yaml"
    _write_profile(profile_path, {
        "type": "hsfs_to_hsse_preflight",
        "mode": "offline_only",
        "key_count": 1,
        "key_revision": 1,
        "smpk_public_der": str(smpk),
        "bmpk_public_der": None,
        "swrev": {},
    })
    out = provision_preflight(profile_path, smek=smek)
    assert out["status"] == "FAIL"
    assert any(c["check"] == "smek_format" and c["status"] == "FAIL" for c in out["checks"])


def test_optional_swrev_zero_is_rejected(tmp_path: Path):
    smpk = _public_der(tmp_path, "smpk")
    profile_path = tmp_path / "provision.yaml"
    _write_profile(profile_path, {
        "type": "hsfs_to_hsse_preflight",
        "mode": "offline_only",
        "key_count": 1,
        "key_revision": 1,
        "smpk_public_der": str(smpk),
        "bmpk_public_der": None,
        "swrev": {"sysfw": 0, "sbl": None, "boardcfg": None},
    })
    out = provision_preflight(profile_path)
    assert out["status"] == "FAIL"
    assert any(c["check"] == "swrev_sysfw" and c["status"] == "FAIL" for c in out["checks"])


def test_certificate_keywriter_profile_does_not_invent_keyrev_for_keycount0():
    result = validate_profile({
        "type": "keywriter_preflight",
        "mode": "offline_only",
        "key_count": 0,
        "key_revision": 0,
        "smpk_public_der": None,
        "bmpk_public_der": None,
    })
    assert result["status"] == "FAIL"
    assert any("numeric KEYREV" in issue for issue in result["issues"])


def test_swrev_sbl_sysfw_respect_48_bit_single_copy_width(tmp_path):
    from am64x_secure_toolkit.provision import _validate_optional_swrev

    checks = []
    out = _validate_optional_swrev({"sbl": (1 << 48) - 1, "sysfw": (1 << 48) - 1}, checks)
    assert out["sbl"] == (1 << 48) - 1
    assert out["sysfw"] == (1 << 48) - 1
    assert not any(c["status"] == "FAIL" for c in checks)

    checks = []
    _validate_optional_swrev({"sbl": 1 << 48, "sysfw": 1 << 48}, checks)
    assert sum(c["status"] == "FAIL" for c in checks) == 2


def test_swrev_boardcfg_respects_64_bit_single_copy_width():
    from am64x_secure_toolkit.provision import _validate_optional_swrev

    checks = []
    out = _validate_optional_swrev({"boardcfg": (1 << 64) - 1}, checks)
    assert out["boardcfg"] == (1 << 64) - 1
    checks = []
    _validate_optional_swrev({"boardcfg": 1 << 64}, checks)
    assert any(c["status"] == "FAIL" for c in checks)
