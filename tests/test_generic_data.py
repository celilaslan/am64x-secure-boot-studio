from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from am64x_secure_toolkit.constants import TI_OIDS
from am64x_secure_toolkit.generic_data import (
    build_generic_data,
    template_generic_data_profile,
    validate_generic_data_profile,
    verify_generic_data,
)
from am64x_secure_toolkit.inspect import inspect_artifact


@pytest.fixture(scope="module")
def rsa4096_pem(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("generic-key")
    p = d / "signing.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    p.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return p


def _profile(tmp_path: Path, *, encryption: bool, payload: bytes) -> tuple[Path, Path]:
    data = tmp_path / "data.bin"
    data.write_bytes(payload)
    profile = template_generic_data_profile()
    profile["subject"]["organization"] = "Internship Project"
    profile["input"] = str(data)
    profile["load"] = {"dest_addr": 0, "auth_mode": 1, "copy_as_host": 0}
    profile["encryption"]["enabled"] = encryption
    pp = tmp_path / "data.yaml"
    pp.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    return pp, data


def test_generic_template_requires_filled_fields(tmp_path: Path) -> None:
    p = tmp_path / "generic.yaml"
    p.write_text(yaml.safe_dump(template_generic_data_profile(), sort_keys=False), encoding="utf-8")
    out = validate_generic_data_profile(p)
    assert out["status"] == "FAIL"


def test_generic_profile_rejects_boot_extension(tmp_path: Path) -> None:
    pp, _ = _profile(tmp_path, encryption=False, payload=b"abc")
    profile = yaml.safe_load(pp.read_text(encoding="utf-8"))
    profile["boot"] = {"enabled": True}
    pp.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    out = validate_generic_data_profile(pp)
    assert out["status"] == "FAIL"
    assert any("Boot Extension" in x for x in out["issues"])


def test_build_signed_generic_data(tmp_path: Path, rsa4096_pem: Path) -> None:
    pp, original = _profile(tmp_path, encryption=False, payload=b"calibration-data\x00\x01")
    package = tmp_path / "data.secure"
    cert = tmp_path / "data.der"
    out = build_generic_data(pp, rsa4096_pem, package, certificate_output=cert)
    assert out["status"] == "PASS"
    assert out["tisci_request_semantics"] == "generalized_authentication"
    assert out["boot_extension_present"] is False
    assert out["mek_material_recorded"] is False

    info = inspect_artifact(package)
    oids = {x["oid"] for x in info["extensions"]}
    assert TI_OIDS["sysfw_boot"] not in oids
    assert TI_OIDS["sysfw_image_integrity"] in oids
    assert TI_OIDS["sysfw_image_load"] in oids
    assert TI_OIDS["software_revision"] in oids

    ver = verify_generic_data(package, original=original)
    assert ver["status"] == "PASS"


def test_build_encrypted_generic_data_and_round_trip(tmp_path: Path, rsa4096_pem: Path) -> None:
    # Runtime-generated synthetic MEK; test source/package içinde sabit secret tutulmaz.
    mek = tmp_path / "mek.txt"
    mek.write_text(os.urandom(32).hex(), encoding="ascii")
    pp, original = _profile(tmp_path, encryption=True, payload=b"generic-secret-data-31-bytes!!!"[:31])
    package = tmp_path / "data.enc.secure"
    out = build_generic_data(pp, rsa4096_pem, package, mek=mek)
    assert out["status"] == "PASS"
    assert out["mode"] == "encrypted+signed"
    assert out["encryption"]["iv_length"] == 16
    assert out["encryption"]["random_string_length"] == 32
    assert out["encryption"]["salt_length"] == 32
    assert out["encryption"]["sensitive_values_emitted"] is False

    ver = verify_generic_data(package, mek=mek, original=original)
    assert ver["status"] == "PASS"
    statuses = {c["check"]: c["status"] for c in ver["checks"]}
    assert statuses["decryption_random_string"] == "PASS"
    assert statuses["decrypted_original_prefix"] == "PASS"
    assert statuses["decrypted_zero_padding"] == "PASS"


def test_aligned_plaintext_uses_zero_extra_padding(tmp_path: Path, rsa4096_pem: Path) -> None:
    mek = tmp_path / "mek.txt"
    mek.write_text(os.urandom(32).hex(), encoding="ascii")
    pp, _ = _profile(tmp_path, encryption=True, payload=os.urandom(32))
    out = build_generic_data(pp, rsa4096_pem, tmp_path / "aligned.secure", mek=mek)
    assert out["encryption"]["padding_bytes"] == 0


def test_wrong_mek_fails_decryption_check(tmp_path: Path, rsa4096_pem: Path) -> None:
    mek = tmp_path / "mek.txt"
    wrong = tmp_path / "wrong-mek.txt"
    mek.write_text(os.urandom(32).hex(), encoding="ascii")
    wrong.write_text(os.urandom(32).hex(), encoding="ascii")
    pp, original = _profile(tmp_path, encryption=True, payload=b"generic-data")
    package = tmp_path / "data.secure"
    build_generic_data(pp, rsa4096_pem, package, mek=mek)
    ver = verify_generic_data(package, mek=wrong, original=original)
    assert ver["status"] == "FAIL"
    statuses = {c["check"]: c["status"] for c in ver["checks"]}
    assert statuses["decryption_random_string"] == "FAIL"


def test_encrypted_verify_without_mek_is_partial(tmp_path: Path, rsa4096_pem: Path) -> None:
    mek = tmp_path / "mek.txt"
    mek.write_text(os.urandom(32).hex(), encoding="ascii")
    pp, _ = _profile(tmp_path, encryption=True, payload=b"x" * 19)
    package = tmp_path / "data.secure"
    build_generic_data(pp, rsa4096_pem, package, mek=mek)
    ver = verify_generic_data(package)
    assert ver["status"] == "PARTIAL"


def test_mek_whitespace_rejected_for_build(tmp_path: Path, rsa4096_pem: Path) -> None:
    mek = tmp_path / "mek.txt"
    mek.write_text(os.urandom(32).hex() + "\n", encoding="ascii")
    pp, _ = _profile(tmp_path, encryption=True, payload=b"data")
    with pytest.raises(ValueError, match="whitespace"):
        build_generic_data(pp, rsa4096_pem, tmp_path / "data.secure", mek=mek)
