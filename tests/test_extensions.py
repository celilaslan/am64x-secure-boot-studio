from asn1crypto import core
from am64x_secure_toolkit.x509ext import (
    SysfwEncryption,
    SysfwImageIntegrity,
    SysfwImageLoad,
    ExtBootComponent,
    ExtBootInfo,
    decode_encryption,
    decode_integrity,
    decode_load,
    decode_ext_boot_info,
)


def test_integrity_decode():
    obj = SysfwImageIntegrity({
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": b"A" * 64,
        "imageSize": 1234,
    })
    d = decode_integrity(obj.dump())
    assert d["image_size"] == 1234
    assert d["sha_oid"] == "2.16.840.1.101.3.4.2.3"
    assert len(bytes.fromhex(d["sha_value_hex"])) == 64


def test_encryption_metadata_is_structural_only():
    obj = SysfwEncryption({
        "initalVector": b"I" * 16,
        "randomString": b"R" * 32,
        "iterationCnt": 0,
        "salt": b"\x00\x00",
    })
    d = decode_encryption(obj.dump())
    assert d == {
        "iv_length": 16,
        "random_string_length": 32,
        "iteration_count": 0,
        "salt_length": 2,
    }


def test_ext_boot_info_decode():
    c1 = ExtBootComponent({
        "compType": 1,
        "bootCore": 16,
        "compOpts": 0,
        "destAddr": bytes.fromhex("70000000"),
        "compSize": 4,
        "shaType": "2.16.840.1.101.3.4.2.3",
        "shaValue": b"H" * 64,
    })
    obj = ExtBootInfo({"extImgSize": 4, "numComp": 1, "comp1": c1})
    d = decode_ext_boot_info(obj.dump())
    assert d["num_components"] == 1
    assert d["components"][0]["dest_addr_hex"] == "0x70000000"


def test_load_decode_splits_auth_type():
    obj = SysfwImageLoad({
        "destAddr": bytes.fromhex("0000000070000000"),
        "authType": 0x1201,
    })
    d = decode_load(obj.dump())
    assert d["dest_addr_length"] == 8
    assert d["auth_mode"] == 1
    assert d["copy_as_host"] == 0x12
    assert d["reserved_upper16"] == 0
