import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from am64x_secure_toolkit.constants import TI_OIDS
from am64x_secure_toolkit.inspect import inspect_artifact
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
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-test")])
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


def test_application_artifact_round_trip(tmp_path):
    payload = b"P" * 48
    integ = SysfwImageIntegrity({
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": hashlib.sha512(payload).digest(),
        "imageSize": len(payload),
    }).dump()
    enc = SysfwEncryption({
        "initalVector": b"I" * 16,
        "randomString": b"R" * 32,
        "iterationCnt": 0,
        "salt": b"\x00\x00",
    }).dump()
    load = SysfwImageLoad({
        "destAddr": bytes.fromhex("0000000070000000"),
        "authType": 1,
    }).dump()
    cert = _cert_with_extensions([
        (TI_OIDS["sysfw_image_integrity"], integ),
        (TI_OIDS["sysfw_image_load"], load),
        (TI_OIDS["sysfw_encryption"], enc),
    ])
    f = tmp_path / "app.hs"
    f.write_bytes(cert + payload)

    info = inspect_artifact(f)
    assert info["classification"] == "encrypted+signed application/generic data"
    assert info["decoded"]["sysfw_encryption"]["iv_length"] == 16
    ver = verify_artifact(f)
    assert ver["overall_host_side_verification"] == "PASS"


def test_official_sdk_four_byte_default_load_address_is_valid(tmp_path):
    """appimage_x509_cert_gen.py uses FORMAT:HEX,OCT:00000000 by default."""
    payload = b"MCELF" * 32
    integ = SysfwImageIntegrity({
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": hashlib.sha512(payload).digest(),
        "imageSize": len(payload),
    }).dump()
    load = SysfwImageLoad({
        "destAddr": bytes.fromhex("00000000"),
        "authType": 1,
    }).dump()
    cert = _cert_with_extensions([
        (TI_OIDS["sysfw_image_integrity"], integ),
        (TI_OIDS["sysfw_image_load"], load),
    ])
    image = tmp_path / "hello_world.mcelf.hs_fs"
    image.write_bytes(cert + payload)
    result = verify_artifact(image)
    width = next(item for item in result["checks"] if item["check"] == "load_dest_addr_width")
    assert width == {
        "check": "load_dest_addr_width", "status": "PASS",
        "actual_bytes": 4, "allowed_bytes": [4, 8],
    }
    assert result["overall_host_side_verification"] == "PASS"


def test_rom_combined_component_hashes(tmp_path):
    c1 = b"ABCD"
    c2 = b"EFGHIJKL"
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
    f = tmp_path / "rom.tiimage"
    f.write_bytes(cert + c1 + c2)

    ver = verify_artifact(f)
    assert ver["classification"] == "ROM combined image"
    assert ver["overall_host_side_verification"] == "PASS"


def test_unknown_certificate_is_not_reported_pass(tmp_path):
    cert = _cert_with_extensions([])
    f = tmp_path / "unknown.der"
    f.write_bytes(cert)
    ver = verify_artifact(f)
    assert ver["overall_host_side_verification"] == "PARTIAL"


def test_rom_combined_rejects_legacy_extension_mix(tmp_path):
    c1 = b"ABCD"
    comp1 = ExtBootComponent({
        "compType": 1,
        "bootCore": 16,
        "compOpts": 0,
        "destAddr": bytes.fromhex("70000000"),
        "compSize": len(c1),
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": hashlib.sha512(c1).digest(),
    })
    ext = ExtBootInfo({"extImgSize": len(c1), "numComp": 1, "comp1": comp1}).dump()
    # Legacy OID content does not need to be decoded for this exclusivity check.
    cert = _cert_with_extensions([
        (TI_OIDS["rom_ext_boot_info"], ext),
        (TI_OIDS["rom_boot_info"], b"\x30\x00"),
    ])
    f = tmp_path / "mixed.tiimage"
    f.write_bytes(cert + c1)
    ver = verify_artifact(f)
    assert ver["overall_host_side_verification"] == "FAIL"
