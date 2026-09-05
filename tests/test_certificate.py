from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from am64x_secure_toolkit.certificate import build_certificate, render_openssl_config
from am64x_secure_toolkit.constants import TI_OIDS
from am64x_secure_toolkit.inspect import inspect_artifact
from am64x_secure_toolkit.profiles import template_profile, validate_profile
from am64x_secure_toolkit.verify import verify_artifact


@pytest.fixture(scope="module")
def rsa4096_material(tmp_path_factory):
    root = tmp_path_factory.mktemp("rsa4096")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_path = root / "signing.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_der = root / "public.der"
    public_der.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_der


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def test_application_template_requires_exact_values(tmp_path: Path):
    p = template_profile("app")
    result = validate_profile(p)
    assert result["status"] == "FAIL"
    assert any("input" in x for x in result["issues"])
    assert any("load.dest_addr" in x for x in result["issues"])


def test_application_certificate_and_package_round_trip(tmp_path: Path, rsa4096_material):
    private_key, _ = rsa4096_material
    payload = tmp_path / "app.mcelf"
    payload.write_bytes(b"AM64X" * 100)
    profile = {
        "type": "application",
        "subject": {"common_name": "AM64x Test Application", "organization": "Internship Project"},
        "input": str(payload),
        "software_revision": 1,
        "load": {"dest_addr": "0x70000000", "auth_mode": 1, "copy_as_host": 0},
        "boot": {"enabled": False},
        "valid_days": 30,
    }
    profile_path = tmp_path / "app.yaml"
    _write_yaml(profile_path, profile)
    cert_path = tmp_path / "app.der"
    package_path = tmp_path / "app.secure"

    out = build_certificate(profile_path, private_key, cert_path, package_path)
    assert out["profile_type"] == "application"
    assert out["host_side_verification"] == "PASS"
    assert str(private_key) not in str(out)

    inspected = inspect_artifact(package_path)
    assert inspected["classification"] == "signed application/generic data"
    oids = {e["oid"] for e in inspected["extensions"]}
    assert TI_OIDS["software_revision"] in oids
    assert TI_OIDS["sysfw_image_integrity"] in oids
    assert TI_OIDS["sysfw_image_load"] in oids
    assert verify_artifact(package_path)["overall_host_side_verification"] == "PASS"


def test_render_application_config_contains_source_oids(tmp_path: Path):
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"123456")
    profile = {
        "type": "application",
        "subject": {"common_name": "AM64x Config Test"},
        "input": str(payload),
        "software_revision": 1,
        "load": {"dest_addr": "0x70000000", "auth_mode": 1, "copy_as_host": 0},
        "boot": {"enabled": False},
        "valid_days": 30,
    }
    path = tmp_path / "p.yaml"
    _write_yaml(path, profile)
    text = render_openssl_config(path)
    assert TI_OIDS["software_revision"] in text
    assert TI_OIDS["sysfw_image_integrity"] in text
    assert TI_OIDS["sysfw_image_load"] in text
    assert "2.16.840.1.101.3.4.2.3" in text
    assert "70000000" in text


def test_debug_certificate_structure_is_decoded(tmp_path: Path, rsa4096_material):
    private_key, _ = rsa4096_material
    profile = {
        "type": "debug",
        "subject": {"common_name": "AM64x Debug Test"},
        "software_revision": 1,
        "debug": {
            "soc_uid": "11" * 32,
            "wildcard_uid": False,
            "privilege": 0,
            "reserved": 0,
            "nonsecure_core_ids": [255],
            "secure_core_ids": [255],
        },
        "valid_days": 30,
    }
    path = tmp_path / "debug.yaml"
    _write_yaml(path, profile)
    cert_path = tmp_path / "debug.der"
    out = build_certificate(path, private_key, cert_path)
    assert out["classification"] == "Secure Debug X.509 certificate"

    info = inspect_artifact(cert_path)
    dbg = info["decoded"]["sysfw_debug"]
    assert dbg["uid_length"] == 32
    assert dbg["debug_privilege"] == 0
    assert dbg["reserved_upper16"] == 0
    assert dbg["nonsecure_core_ids"] == [255]
    assert dbg["secure_core_ids"] == [255]
    verification = verify_artifact(cert_path)
    assert verification["overall_host_side_verification"] == "PARTIAL"
    assert any(c["check"] == "target_debug_authorization" and c["status"] == "NOT_CHECKED" for c in verification["checks"])


def test_debug_wildcard_requires_explicit_flag():
    profile = {
        "type": "debug",
        "subject": {"common_name": "AM64x Debug Test"},
        "software_revision": 0,
        "debug": {
            "soc_uid": "00" * 32,
            "wildcard_uid": False,
            "privilege": 0,
            "reserved": 0,
            "nonsecure_core_ids": [255],
            "secure_core_ids": [255],
        },
    }
    result = validate_profile(profile)
    assert result["status"] == "FAIL"
    assert any("all-zero UID" in x for x in result["issues"])


def test_keywriter_preflight_uses_public_der_only(rsa4096_material):
    _, public_der = rsa4096_material
    profile = {
        "type": "keywriter_preflight",
        "mode": "offline_only",
        "key_count": 1,
        "key_revision": 1,
        "smpk_public_der": str(public_der),
        "bmpk_public_der": None,
    }
    result = validate_profile(profile)
    assert result["status"] == "PASS"
    info = result["normalized"]["public_key_info"]["smpk_public_der"]
    assert info["rsa_bits"] == 4096
    assert len(info["sha512"]) == 128
    assert info["target_compatible_rsa4096"] is True


def test_debug_package_is_rejected_before_output_write(tmp_path: Path, rsa4096_material):
    private_key, _ = rsa4096_material
    profile = {
        "type": "debug",
        "subject": {"common_name": "AM64x Debug Test"},
        "software_revision": 1,
        "debug": {
            "soc_uid": "22" * 32,
            "wildcard_uid": False,
            "privilege": 0,
            "reserved": 0,
            "nonsecure_core_ids": [255],
            "secure_core_ids": [255],
        },
    }
    path = tmp_path / "debug.yaml"
    _write_yaml(path, profile)
    cert_path = tmp_path / "should_not_exist.der"
    with pytest.raises(ValueError):
        build_certificate(path, private_key, cert_path, tmp_path / "bad.pkg")
    assert not cert_path.exists()
