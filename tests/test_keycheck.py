from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from am64x_secure_toolkit.keycheck import compare_key_material, preflight_mek, preflight_signing_key


def _keypair(tmp_path: Path, bits: int = 4096):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_path = tmp_path / f"secret-{bits}.pem"
    public_path = tmp_path / f"public-{bits}.der"
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return key, private_path, public_path


def test_signing_key_preflight_rsa4096_and_no_secret_path(tmp_path: Path):
    _, private_path, _ = _keypair(tmp_path, 4096)
    out = preflight_signing_key(private_path, purpose="application")
    assert out["status"] == "PASS"
    assert out["key"]["rsa_bits"] == 4096
    assert len(out["key"]["der_spki_sha256"]) == 64
    assert str(private_path) not in str(out)
    assert out["secret_material_recorded"] is False
    assert out["secret_path_recorded"] is False


def test_signing_key_preflight_rejects_wrong_key_size_for_keywriter(tmp_path: Path):
    _, _, public_path = _keypair(tmp_path, 2048)
    out = preflight_signing_key(public_path, purpose="keywriter")
    assert out["status"] == "FAIL"
    assert any(c["check"] == "target_key_size" and c["status"] == "FAIL" for c in out["checks"])


def test_rom_key_size_is_not_guessed(tmp_path: Path):
    _, _, public_path = _keypair(tmp_path, 2048)
    out = preflight_signing_key(public_path, purpose="rom")
    assert out["status"] == "PARTIAL"
    assert any(c["check"] == "target_key_size" and c["status"] == "NOT_CHECKED" for c in out["checks"])


def test_public_der_export_contains_only_public_spki(tmp_path: Path):
    key, private_path, _ = _keypair(tmp_path, 4096)
    out_path = tmp_path / "exported-public.der"
    out = preflight_signing_key(private_path, purpose="application", public_der_output=out_path)
    assert out["status"] == "PASS"
    loaded = serialization.load_der_public_key(out_path.read_bytes())
    assert loaded.public_numbers() == key.public_key().public_numbers()


def test_compare_private_and_certificate_public_key(tmp_path: Path):
    key, private_path, _ = _keypair(tmp_path, 4096)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AM64x test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA512())
    )
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    out = compare_key_material(private_path, cert_path)
    assert out["status"] == "PASS"
    assert out["match"] is True
    assert str(private_path) not in str(out)


def test_compare_detects_wrong_public_key_clean(tmp_path: Path):
    a = tmp_path / "a"; a.mkdir()
    b = tmp_path / "b"; b.mkdir()
    _, private_path, _ = _keypair(a, 4096)
    _, _, public_path = _keypair(b, 4096)
    out = compare_key_material(private_path, public_path)
    assert out["status"] == "FAIL"
    assert out["match"] is False


def test_mek_exact_64_hex_passes_without_disclosure(tmp_path: Path):
    mek = tmp_path / "mek.txt"
    secret = "a1" * 32
    mek.write_text(secret, encoding="ascii")
    out = preflight_mek(mek)
    assert out["status"] == "PASS"
    assert out["key_bits_if_valid"] == 256
    assert secret not in str(out)
    assert str(mek) not in str(out)
    assert out["secret_hash_recorded"] is False


def test_mek_trailing_newline_is_partial_not_silent_pass(tmp_path: Path):
    mek = tmp_path / "mek.txt"
    mek.write_text(("0f" * 32) + "\n", encoding="ascii")
    out = preflight_mek(mek)
    assert out["status"] == "PARTIAL"
    assert any(c["check"] == "sdk_file_text_safety" and c["status"] == "WARN" for c in out["checks"])


def test_mek_63_and_65_hex_fail_strict_preflight(tmp_path: Path):
    for n in (63, 65):
        mek = tmp_path / f"mek-{n}.txt"
        mek.write_text("a" * n, encoding="ascii")
        out = preflight_mek(mek)
        assert out["status"] == "FAIL"
        assert any(c["check"] == "aes256_length" and c["status"] == "FAIL" for c in out["checks"])
