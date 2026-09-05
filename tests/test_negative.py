from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from am64x_secure_toolkit.constants import TI_OIDS
from am64x_secure_toolkit.negative import create_negative_variant, run_negative_suite
from am64x_secure_toolkit.verify import verify_artifact
from am64x_secure_toolkit.x509ext import (
    ExtBootComponent,
    ExtBootInfo,
    SysfwEncryption,
    SysfwImageIntegrity,
    SysfwImageLoad,
)


def _cert_with_extensions(exts):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "negative-test")])
    now = datetime.now(timezone.utc)
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
    )
    for oid, raw in exts:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(oid), raw), critical=False)
    cert = b.sign(key, hashes.SHA512())
    return cert.public_bytes(serialization.Encoding.DER)


def _application(tmp_path, *, encrypted=False):
    payload = bytes(range(64))
    integ = SysfwImageIntegrity({
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": hashlib.sha512(payload).digest(),
        "imageSize": len(payload),
    }).dump()
    load = SysfwImageLoad({
        "destAddr": bytes.fromhex("0000000070000000"),
        "authType": 1,
    }).dump()
    exts = [
        (TI_OIDS["sysfw_image_integrity"], integ),
        (TI_OIDS["sysfw_image_load"], load),
    ]
    if encrypted:
        enc = SysfwEncryption({
            "initalVector": b"I" * 16,
            "randomString": b"R" * 32,
            "iterationCnt": 0,
            "salt": b"\x00\x00",
        }).dump()
        exts.append((TI_OIDS["sysfw_encryption"], enc))
    cert = _cert_with_extensions(exts)
    path = tmp_path / ("app_encrypted.hs" if encrypted else "app_signed.hs")
    path.write_bytes(cert + payload)
    return path


def _rom(tmp_path):
    c1 = b"A" * 16
    c2 = b"B" * 32
    comp1 = ExtBootComponent({
        "compType": 1,
        "bootCore": 16,
        "compOpts": 0,
        "destAddr": bytes.fromhex("70000000"),
        "compSize": len(c1),
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": hashlib.sha512(c1).digest(),
    })
    comp2 = ExtBootComponent({
        "compType": 2,
        "bootCore": 0,
        "compOpts": 0,
        "destAddr": bytes.fromhex("00044000"),
        "compSize": len(c2),
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": hashlib.sha512(c2).digest(),
    })
    ext = ExtBootInfo({
        "extImgSize": len(c1) + len(c2),
        "numComp": 2,
        "comp1": comp1,
        "comp2": comp2,
    }).dump()
    cert = _cert_with_extensions([(TI_OIDS["rom_ext_boot_info"], ext)])
    path = tmp_path / "rom.tiimage"
    path.write_bytes(cert + c1 + c2)
    return path


def _status(result, name):
    return next(c["status"] for c in result["verification"]["checks"] if c["check"] == name)


def test_signature_mutation_detected_without_touching_source(tmp_path):
    source = _application(tmp_path)
    original = source.read_bytes()
    out = tmp_path / "sig.neg"
    result = create_negative_variant(source, "signature", out)
    assert result["negative_test_result"] == "PASS"
    assert result["source_unchanged"] is True
    assert source.read_bytes() == original
    assert result["mutation"]["tbs_unchanged"] is True
    assert _status(result, "certificate_signature_with_embedded_public_key") == "FAIL"
    assert _status(result, "appended_payload_sha512_binding") == "PASS"


def test_tbs_mutation_detected_and_payload_binding_stays_valid(tmp_path):
    source = _application(tmp_path)
    out = tmp_path / "tbs.neg"
    result = create_negative_variant(source, "tbs", out)
    assert result["negative_test_result"] == "PASS"
    assert result["mutation"]["signature_value_unchanged"] is True
    assert _status(result, "certificate_signature_with_embedded_public_key") == "FAIL"
    assert _status(result, "appended_payload_sha512_binding") == "PASS"


def test_payload_mutation_breaks_integrity_but_not_certificate_signature(tmp_path):
    source = _application(tmp_path)
    out = tmp_path / "payload.neg"
    result = create_negative_variant(source, "payload", out, offset=7)
    assert result["negative_test_result"] == "PASS"
    assert _status(result, "certificate_signature_with_embedded_public_key") == "PASS"
    assert _status(result, "appended_payload_sha512_binding") == "FAIL"
    assert result["mutation"]["appended_offset"] == 7


def test_ciphertext_mutation_requires_encrypted_profile_and_is_detected(tmp_path):
    encrypted = _application(tmp_path, encrypted=True)
    result = create_negative_variant(encrypted, "ciphertext", tmp_path / "cipher.neg")
    assert result["negative_test_result"] == "PASS"
    assert _status(result, "appended_payload_sha512_binding") == "FAIL"



def test_payload_mode_rejects_encrypted_image(tmp_path):
    encrypted = _application(tmp_path, encrypted=True)
    try:
        create_negative_variant(encrypted, "payload", tmp_path / "bad.neg")
    except ValueError as exc:
        assert "ciphertext" in str(exc)
    else:
        raise AssertionError("encrypted image payload mode ile reddedilmeliydi")


def test_rom_component_mutation_is_detected(tmp_path):
    source = _rom(tmp_path)
    result = create_negative_variant(source, "component", tmp_path / "rom_c2.neg", component_index=2)
    assert result["negative_test_result"] == "PASS"
    assert _status(result, "rom_component_1_sha512") == "PASS"
    assert _status(result, "rom_component_2_sha512") == "FAIL"


def test_suite_selects_profile_specific_cases(tmp_path):
    signed = _application(tmp_path)
    report = run_negative_suite(signed, tmp_path / "suite")
    assert report["suite_result"] == "PASS"
    assert report["source_unchanged"] is True
    assert [c["test"] for c in report["cases"]] == ["signature", "tbs", "payload"]
    assert (tmp_path / "suite" / "negative_test_report.json").is_file()


def test_rom_suite_checks_each_component(tmp_path):
    rom = _rom(tmp_path)
    report = run_negative_suite(rom, tmp_path / "rom_suite")
    assert report["suite_result"] == "PASS"
    assert [c["test"] for c in report["cases"]] == ["signature", "tbs", "component", "component"]
    assert report["cases"][2]["mutation"]["component_index"] == 1
    assert report["cases"][3]["mutation"]["component_index"] == 2


def test_negative_output_never_overwrites_existing_file(tmp_path):
    source = _application(tmp_path)
    out = tmp_path / "exists.neg"
    out.write_bytes(b"keep")
    try:
        create_negative_variant(source, "signature", out)
    except FileExistsError:
        pass
    else:
        raise AssertionError("existing output korunmalıydı")
    assert out.read_bytes() == b"keep"
