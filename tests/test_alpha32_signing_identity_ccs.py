from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from am64x_secure_toolkit.services.certificate_center import certificate_metadata
from am64x_secure_toolkit.services.secure_boot_package import build_secure_boot_package


def _identity_files(root: Path, name: str = "studio") -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    key_path = root / f"{name}.pem"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} application")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA512())
    )
    cert_path = root / f"{name}.der"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return cert_path, key_path, certificate_metadata(cert_path)["spki_sha256"]


def test_selected_certificate_identity_reaches_ccs_output_and_is_verified(tmp_path: Path, monkeypatch):
    cert, key, fingerprint = _identity_files(tmp_path)
    image = tmp_path / "hello_world.mcelf.hs_fs"
    image.write_bytes(b"placeholder")
    captured = {}

    def fake_build(*_args, **kwargs):
        captured.update(kwargs)
        return {
            "status": "PASS",
            "summary": "secure application hazır",
            "output": {"path": str(image), "name": image.name},
            "outputs": [{"type": "application_image", "path": str(image)}],
            "checks": [],
        }

    monkeypatch.setattr(
        "am64x_secure_toolkit.services.secure_boot_package.run_mcu_plus_secure_build",
        fake_build,
    )
    monkeypatch.setattr(
        "am64x_secure_toolkit.services.secure_boot_package.inspect_and_verify",
        lambda *_args, **_kwargs: SimpleNamespace(to_dict=lambda: {
            "status": "PASS",
            "safe_details": {"inspection": {"spki_sha256": fingerprint}},
        }),
    )

    result = build_secure_boot_package(
        application_project=tmp_path,
        sdk_root=tmp_path,
        physical_lifecycle="HS-FS",
        target_lifecycle="HS-FS",
        reference_certificate=cert,
        signing_key=key,
    )

    assert result["status"] == "PASS"
    assert captured["signing_key"] == key
    assert result["signing_identity"]["certificate_name"] == cert.name
    assert result["output_signing_identity_match"]["match"] is True
    assert result["output_signing_identity_match"]["actual_spki_sha256"] == fingerprint
    assert str(key) not in str(result)


def test_mismatched_certificate_and_private_key_fail_before_ccs_build(tmp_path: Path):
    cert, _matching_key, _fingerprint = _identity_files(tmp_path, "certificate")
    _other_cert, other_key, _other_fingerprint = _identity_files(tmp_path, "other")
    with pytest.raises(ValueError, match="aynı public key kimliğine ait değil"):
        build_secure_boot_package(
            application_project=tmp_path,
            sdk_root=tmp_path,
            physical_lifecycle="HS-FS",
            target_lifecycle="HS-FS",
            reference_certificate=cert,
            signing_key=other_key,
        )


def test_certificate_center_hands_identity_to_secure_boot_session():
    root = Path(__file__).resolve().parents[1]
    certificate_page = (root / "src/am64x_secure_toolkit/gui/pages/certificate.py").read_text(encoding="utf-8")
    secure_boot_page = (root / "src/am64x_secure_toolkit/gui/pages/secure_boot.py").read_text(encoding="utf-8")
    state = (root / "src/am64x_secure_toolkit/gui/state.py").read_text(encoding="utf-8")
    assert "Secure Boot'ta Kullan" in certificate_page
    assert "self.state.set_signing_identity" in certificate_page
    assert 'form.addRow("Application certificate"' in secure_boot_page
    assert "reference_certificate=self.certificate.text().strip() or None" in secure_boot_page
    assert "self.signing_certificate_path" in state
