"""AM64x/TISCI 12.00.02 için desteklenen X.509 extension decoderları."""

from __future__ import annotations

from asn1crypto import core


class SoftwareRevision(core.Sequence):
    _fields = [("swrv", core.Integer)]


class SysfwBoot(core.Sequence):
    _fields = [
        ("bootCore", core.Integer),
        ("configFlags_set", core.Integer),
        ("configFlags_clr", core.Integer),
        ("resetVec", core.OctetString),
        ("fieldValid", core.Integer),
        ("rsvd1", core.Integer),
        ("rsvd2", core.Integer),
        ("rsvd3", core.Integer),
    ]


class SysfwImageIntegrity(core.Sequence):
    _fields = [
        ("shaType", core.ObjectIdentifier),
        ("shaValue", core.OctetString),
        ("imageSize", core.Integer),
    ]


class SysfwImageLoad(core.Sequence):
    _fields = [
        ("destAddr", core.OctetString),
        ("authType", core.Integer),
    ]


class SysfwEncryption(core.Sequence):
    _fields = [
        ("initalVector", core.OctetString),  # TISCI kaynak yazımı korunur
        ("randomString", core.OctetString),
        ("iterationCnt", core.Integer),
        ("salt", core.OctetString),
    ]


class SysfwDebug(core.Sequence):
    _fields = [
        ("uid", core.OctetString),
        ("debugCtrl", core.Integer),
        ("coreDbgEn", core.Integer),
        ("coreDbgSecEn", core.Integer),
    ]


class ExtBootComponent(core.Sequence):
    _fields = [
        ("compType", core.Integer),
        ("bootCore", core.Integer),
        ("compOpts", core.Integer),
        ("destAddr", core.OctetString),
        ("compSize", core.Integer),
        ("shaType", core.ObjectIdentifier),
        ("shaValue", core.OctetString),
    ]


class ExtBootInfo(core.Sequence):
    _fields = [
        ("extImgSize", core.Integer),
        ("numComp", core.Integer),
        ("comp1", ExtBootComponent, {"optional": True}),
        ("comp2", ExtBootComponent, {"optional": True}),
        ("comp3", ExtBootComponent, {"optional": True}),
        ("comp4", ExtBootComponent, {"optional": True}),
        ("comp5", ExtBootComponent, {"optional": True}),
    ]


class KeywriterEncryptedField(core.Sequence):
    _fields = [
        ("val", core.OctetString),
        ("iv", core.OctetString),
        ("rs", core.OctetString),
        ("size", core.Integer),
        ("action_flags", core.Integer),
    ]


class KeywriterSimpleField(core.Sequence):
    _fields = [
        ("val", core.OctetString),
        ("action_flags", core.Integer),
    ]


class KeywriterVersion(core.Sequence):
    _fields = [("val", core.OctetString)]


def octets_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big") if value else 0


def _int_to_byte_ids(value: int) -> list[int]:
    if value == 0:
        return [0]
    length = max(1, (value.bit_length() + 7) // 8)
    return list(value.to_bytes(length, "big"))


def decode_boot(raw: bytes) -> dict:
    x = SysfwBoot.load(raw)
    reset = x["resetVec"].native
    return {
        "boot_core": int(x["bootCore"].native),
        "config_flags_set": int(x["configFlags_set"].native),
        "config_flags_clr": int(x["configFlags_clr"].native),
        "reset_vector_hex": f"0x{octets_to_int(reset):x}",
        "reset_vector_length": len(reset),
        "field_valid": int(x["fieldValid"].native),
        "reserved": [int(x["rsvd1"].native), int(x["rsvd2"].native), int(x["rsvd3"].native)],
    }


def decode_integrity(raw: bytes) -> dict:
    x = SysfwImageIntegrity.load(raw)
    return {
        "sha_oid": x["shaType"].native,
        "sha_value_hex": x["shaValue"].native.hex(),
        "image_size": int(x["imageSize"].native),
    }


def decode_load(raw: bytes) -> dict:
    x = SysfwImageLoad.load(raw)
    auth_type = int(x["authType"].native)
    dest = x["destAddr"].native
    return {
        "dest_addr_hex": f"0x{octets_to_int(dest):x}",
        "dest_addr_length": len(dest),
        "auth_type_raw": auth_type,
        "auth_mode": auth_type & 0xFF,
        "copy_as_host": (auth_type >> 8) & 0xFF,
        "reserved_upper16": (auth_type >> 16) & 0xFFFF,
    }


def decode_encryption(raw: bytes) -> dict:
    x = SysfwEncryption.load(raw)
    return {
        "iv_length": len(x["initalVector"].native),
        "random_string_length": len(x["randomString"].native),
        "iteration_count": int(x["iterationCnt"].native),
        "salt_length": len(x["salt"].native),
        # Secret-adjacent byte values intentionally not emitted.
    }


def decode_swrv(raw: bytes) -> dict:
    x = SoftwareRevision.load(raw)
    return {"software_revision": int(x["swrv"].native)}


def decode_debug(raw: bytes) -> dict:
    x = SysfwDebug.load(raw)
    ctrl = int(x["debugCtrl"].native)
    nonsecure = int(x["coreDbgEn"].native)
    secure = int(x["coreDbgSecEn"].native)
    return {
        "uid_hex": x["uid"].native.hex(),
        "uid_length": len(x["uid"].native),
        "debug_ctrl_raw": ctrl,
        "debug_privilege": ctrl & 0xFFFF,
        "reserved_upper16": (ctrl >> 16) & 0xFFFF,
        "nonsecure_core_ids": _int_to_byte_ids(nonsecure),
        "secure_core_ids": _int_to_byte_ids(secure),
    }


def decode_ext_boot_info(raw: bytes) -> dict:
    x = ExtBootInfo.load(raw)
    num = int(x["numComp"].native)
    comps = []
    for idx in range(1, min(num, 5) + 1):
        c = x[f"comp{idx}"]
        if c.native is None:
            break
        comps.append({
            "index": idx,
            "comp_type": int(c["compType"].native),
            "boot_core": int(c["bootCore"].native),
            "comp_opts": int(c["compOpts"].native),
            "dest_addr_hex": f"0x{octets_to_int(c['destAddr'].native):x}",
            "comp_size": int(c["compSize"].native),
            "sha_oid": c["shaType"].native,
            "sha_value_hex": c["shaValue"].native.hex(),
        })
    return {
        "ext_image_size": int(x["extImgSize"].native),
        "num_components": num,
        "components": comps,
    }


def decode_keywriter_encrypted_field(raw: bytes) -> dict:
    """Encrypted Keywriter alanını byte değerlerini dışarı vermeden çözer."""
    x = KeywriterEncryptedField.load(raw)
    return {
        "value_length": len(x["val"].native),
        "iv_length": len(x["iv"].native),
        "random_string_length": len(x["rs"].native),
        "declared_size": int(x["size"].native),
        "action_flags_raw": int(x["action_flags"].native),
        "sensitive_values_emitted": False,
    }


def decode_keywriter_simple_field(raw: bytes) -> dict:
    x = KeywriterSimpleField.load(raw)
    return {
        "value_length": len(x["val"].native),
        "action_flags_raw": int(x["action_flags"].native),
        "sensitive_values_emitted": False,
    }


def decode_keywriter_version(raw: bytes) -> dict:
    x = KeywriterVersion.load(raw)
    return {
        "value_length": len(x["val"].native),
        "sensitive_values_emitted": False,
    }
