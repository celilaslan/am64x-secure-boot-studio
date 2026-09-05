from __future__ import annotations

from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from am64x_secure_toolkit.certificate import build_certificate
from am64x_secure_toolkit.profiles import template_profile, validate_profile
from am64x_secure_toolkit.services.certificate_center import (
    add_certificate_to_library,
    certificate_metadata,
    compare_certificate_with_private_key,
    export_certificate,
    export_public_key_der,
    list_certificate_library,
    profile_from_certificate,
    remove_certificate_from_library,
)
from am64x_secure_toolkit.services.ui_contract import page_visible


def _key(tmp_path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    p = tmp_path / "signing.pem"
    p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return p


def _app_cert(tmp_path: Path) -> tuple[Path, Path, Path]:
    key = _key(tmp_path)
    payload = tmp_path / "app.mcelf"
    payload.write_bytes(b"AM64X-CERT-CENTER" * 32)
    profile = {
        "type": "application",
        "subject": {
            "country": "TR",
            "state": "Ankara",
            "locality": "Ankara",
            "organization": "Example",
            "organizational_unit": "Embedded",
            "common_name": "AM64x Certificate Center Test",
            "email": "test@example.com",
        },
        "input": str(payload),
        "software_revision": 3,
        "load": {"dest_addr": "0x70000000", "auth_mode": 1, "copy_as_host": 0},
        "boot": {"enabled": False},
        "valid_days": 30,
    }
    pp = tmp_path / "app.yaml"
    pp.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    cert = tmp_path / "app.der"
    build_certificate(pp, key, cert)
    return cert, key, payload


def test_profile_alias_and_subject_country_validation():
    assert template_profile("application")["type"] == "application"
    bad = template_profile("application")
    bad["subject"] = {"common_name": "Test", "country": "TUR"}
    bad["input"] = __file__
    bad["load"]["dest_addr"] = "0x70000000"
    out = validate_profile(bad)
    assert out["status"] == "FAIL"
    assert any("iki ASCII harf" in x for x in out["issues"])


def test_certificate_metadata_export_key_match_and_clone(tmp_path: Path):
    cert, key, payload = _app_cert(tmp_path)
    meta = certificate_metadata(cert)
    assert meta["subject"]["country"] == "TR"
    assert meta["subject"]["common_name"] == "AM64x Certificate Center Test"
    assert meta["classification"] == "signed application/generic data"

    pem = tmp_path / "app.pem"
    der2 = tmp_path / "app2.der"
    pub = tmp_path / "pub.der"
    assert export_certificate(cert, pem, encoding="pem")["status"] == "PASS"
    assert export_certificate(pem, der2, encoding="der")["status"] == "PASS"
    assert der2.read_bytes() == cert.read_bytes()
    assert export_public_key_der(cert, pub)["status"] == "PASS"
    assert compare_certificate_with_private_key(cert, key)["match"] is True

    cloned, warnings = profile_from_certificate(cert, payload_path=payload)
    assert cloned["type"] == "application"
    assert cloned["subject"]["organization"] == "Example"
    assert cloned["software_revision"] == 3
    assert cloned["load"]["dest_addr"] == "0x70000000"
    assert cloned["input"] == str(payload)
    assert warnings


def test_project_certificate_library_only_copies_public_certificate(tmp_path: Path):
    cert, _key_path, _payload = _app_cert(tmp_path)
    project = tmp_path / "project"
    (project / "public").mkdir(parents=True)
    added = add_certificate_to_library(project, cert)
    assert added["status"] == "PASS"
    rows = list_certificate_library(project)
    assert len(rows) == 1
    assert rows[0]["relative_path"].startswith("public/certificates/")
    removed = remove_certificate_from_library(project, rows[0]["relative_path"])
    assert removed["status"] == "PASS"
    assert list_certificate_library(project) == []


def test_certificate_center_is_guided_and_source_contract_is_complete():
    assert page_visible("guided", "certificate") is True
    root = Path(__file__).parents[1] / "src" / "am64x_secure_toolkit"
    page = (root / "gui" / "pages" / "certificate.py").read_text(encoding="utf-8")
    service = (root / "services" / "certificate_center.py").read_text(encoding="utf-8")
    for token in [
        "Certificate Center",
        "Certificate Library",
        "Yeni Sürüm / Export",
        "Certificate ↔ Image Anatomy",
        "ROM / Keywriter / Generic Data",
        "Signed certificate byte'larını doğrudan değiştirmek signature'ı bozar",
    ]:
        assert token in page
    for token in ["Country (C)", "State / Province (ST)", "Organizational Unit (OU)", "Common Name (CN)"]:
        assert token in service


def test_pem_certificate_verify_uses_same_host_side_engine(tmp_path: Path):
    from am64x_secure_toolkit.verify import verify_artifact
    cert, _key_path, _payload = _app_cert(tmp_path)
    pem = tmp_path / "app.pem"
    export_certificate(cert, pem, encoding="pem")
    result = verify_artifact(pem)
    assert result["input_format"] == "PEM"
    assert result["file"] == "app.pem"
    assert result["overall_host_side_verification"] in {"PASS", "PARTIAL"}
    assert any(c["check"] == "certificate_signature_with_embedded_public_key" for c in result["checks"])


def test_certificate_compare_reports_key_and_extension_differences(tmp_path: Path):
    from am64x_secure_toolkit.services.certificate_center import compare_certificates
    cert1, key, payload = _app_cert(tmp_path)
    profile = {
        "type": "application",
        "subject": {"country": "TR", "common_name": "Reissued Certificate"},
        "input": str(payload),
        "software_revision": 4,
        "load": {"dest_addr": "0x70000000", "auth_mode": 1, "copy_as_host": 0},
        "boot": {"enabled": False},
        "valid_days": 60,
    }
    pp = tmp_path / "app-reissue.yaml"
    pp.write_text(yaml.safe_dump(profile, sort_keys=False), encoding="utf-8")
    cert2 = tmp_path / "app-reissue.der"
    build_certificate(pp, key, cert2)
    result = compare_certificates(cert1, cert2)
    assert result["status"] == "PASS"
    assert result["same_certificate_sha256"] is False
    assert result["same_public_key"] is True
    fields = {x["field"]: x for x in result["field_differences"]}
    assert fields["subject_rfc4514"]["same"] is False
    assert fields["spki_sha256"]["same"] is True


def test_subject_rejects_config_injection_and_bad_email():
    base = template_profile("application")
    base["input"] = __file__
    base["load"]["dest_addr"] = "0x70000000"
    base["subject"] = {"common_name": "Good\n[evil]", "country": "TR"}
    out = validate_profile(base)
    assert out["status"] == "FAIL"
    assert any("control/newline" in x for x in out["issues"])

    base["subject"] = {"common_name": "Good", "country": "tr", "email": "not an email"}
    out = validate_profile(base)
    assert out["status"] == "FAIL"
    assert any("subject.email" in x for x in out["issues"])
    assert out["normalized"]["subject"]["country"] == "TR"
