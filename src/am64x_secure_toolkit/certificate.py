"""AM64x X.509 certificate profile, üretim ve açıklama yardımcıları."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from asn1crypto import core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .constants import SHA512_OID, TI_OIDS
from .inspect import inspect_artifact
from .profiles import load_profile, validate_profile
from .verify import verify_artifact


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


class SysfwIntegrity(core.Sequence):
    _fields = [
        ("shaType", core.ObjectIdentifier),
        ("shaValue", core.OctetString),
        ("imageSize", core.Integer),
    ]


class SysfwLoad(core.Sequence):
    _fields = [
        ("destAddr", core.OctetString),
        ("authType", core.Integer),
    ]


class SysfwSwrev(core.Sequence):
    _fields = [("swrv", core.Integer)]


class SysfwDebug(core.Sequence):
    _fields = [
        ("uid", core.OctetString),
        ("debugCtrl", core.Integer),
        ("coreDbgEn", core.Integer),
        ("coreDbgSecEn", core.Integer),
    ]


def _u64be(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _ids_to_integer(ids: list[int]) -> int:
    return int.from_bytes(bytes(ids), "big")


def _name_from_subject(subject: dict[str, str]) -> x509.Name:
    mapping = [
        ("country", NameOID.COUNTRY_NAME),
        ("state", NameOID.STATE_OR_PROVINCE_NAME),
        ("locality", NameOID.LOCALITY_NAME),
        ("organization", NameOID.ORGANIZATION_NAME),
        ("organizational_unit", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("common_name", NameOID.COMMON_NAME),
        ("email", NameOID.EMAIL_ADDRESS),
    ]
    attrs = []
    for key, oid in mapping:
        value = subject.get(key)
        if value:
            attrs.append(x509.NameAttribute(oid, value))
    if not attrs:
        raise ValueError("certificate subject içinde kullanılabilir alan yok")
    return x509.Name(attrs)


def _load_rsa4096_private_key(path: str | Path) -> rsa.RSAPrivateKey:
    data = Path(path).read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError as exc:
        raise ValueError("password-protected private key bu komutta desteklenmiyor; secret/passphrase komut satırında alınmaz") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("signing key RSA private key olmalıdır")
    if key.key_size != 4096:
        raise ValueError(f"TISCI 12.00.02 hedef profili RSA-4096 gerektirir; verilen RSA-{key.key_size}")
    return key


def _certificate_builder(subject: dict[str, str], key: rsa.RSAPrivateKey, valid_days: int) -> x509.CertificateBuilder:
    name = _name_from_subject(subject)
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )


def _add_custom(builder: x509.CertificateBuilder, oid: str, der_value: bytes) -> x509.CertificateBuilder:
    return builder.add_extension(
        x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), der_value),
        critical=False,
    )


def _app_extensions(normalized: dict[str, Any]) -> list[tuple[str, bytes]]:
    payload = Path(normalized["input"]).read_bytes()
    integrity = SysfwIntegrity({
        "shaType": SHA512_OID,
        "shaValue": hashlib.sha512(payload).digest(),
        "imageSize": len(payload),
    }).dump()
    auth_type = normalized["load_auth_mode"] | (normalized["load_copy_as_host"] << 8)
    load = SysfwLoad({
        "destAddr": _u64be(normalized["load_dest_addr"]),
        "authType": auth_type,
    }).dump()
    swrv = SysfwSwrev({"swrv": normalized["software_revision"]}).dump()
    out = [
        (TI_OIDS["software_revision"], swrv),
        (TI_OIDS["sysfw_image_integrity"], integrity),
        (TI_OIDS["sysfw_image_load"], load),
    ]
    if normalized.get("boot_enabled"):
        boot = SysfwBoot({
            "bootCore": normalized["boot_boot_core"],
            "configFlags_set": normalized["boot_config_flags_set"],
            "configFlags_clr": normalized["boot_config_flags_clr"],
            "resetVec": _u64be(normalized["boot_reset_vector"]),
            "fieldValid": normalized["boot_field_valid"],
            "rsvd1": 0,
            "rsvd2": 0,
            "rsvd3": 0,
        }).dump()
        out.append((TI_OIDS["sysfw_boot"], boot))
    return out


def _debug_extensions(normalized: dict[str, Any]) -> list[tuple[str, bytes]]:
    debug_ctrl = normalized["debug_privilege"] | (normalized["debug_reserved"] << 16)
    debug = SysfwDebug({
        "uid": bytes.fromhex(normalized["debug_soc_uid_hex"]),
        "debugCtrl": debug_ctrl,
        "coreDbgEn": _ids_to_integer(normalized["debug_nonsecure_core_ids"]),
        "coreDbgSecEn": _ids_to_integer(normalized["debug_secure_core_ids"]),
    }).dump()
    swrv = SysfwSwrev({"swrv": normalized["software_revision"]}).dump()
    return [
        (TI_OIDS["software_revision"], swrv),
        (TI_OIDS["sysfw_debug"], debug),
    ]


def build_certificate(
    profile_path: str | Path,
    signing_key: str | Path,
    output: str | Path,
    package: str | Path | None = None,
) -> dict[str, Any]:
    """Application veya Secure Debug certificate üretir.

    Application için `package` verilirse DER certificate + plaintext payload birleştirilir.
    Encrypted application üretimi bu fonksiyonun işi değildir; kurulu TI signer `securectl build app`
    üzerinden kullanılır.
    """
    profile = load_profile(profile_path)
    validation = validate_profile(profile)
    if validation["status"] != "PASS":
        raise ValueError("profile doğrulaması başarısız: " + "; ".join(validation["issues"]))
    normalized = validation["normalized"]
    ptype = normalized["type"]
    if ptype not in {"application", "debug"}:
        raise ValueError("cert build yalnız application ve debug profile üretir; ROM için rom_image_gen.py, Keywriter için offline preflight kullanılır")
    if package is not None and ptype != "application":
        raise ValueError("--package yalnız application profile ile kullanılabilir")

    out = Path(output)
    package_path = Path(package) if package is not None else None
    if out.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {out}")
    if package_path is not None and package_path.exists():
        raise FileExistsError(f"package çıktısı zaten mevcut: {package_path}")

    key = _load_rsa4096_private_key(signing_key)
    builder = _certificate_builder(normalized["subject"], key, normalized["valid_days"])
    extensions = _app_extensions(normalized) if ptype == "application" else _debug_extensions(normalized)
    for oid, der_value in extensions:
        builder = _add_custom(builder, oid, der_value)

    cert = builder.sign(private_key=key, algorithm=hashes.SHA512())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(cert_der)

    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    result: dict[str, Any] = {
        "profile_type": ptype,
        "certificate": str(out),
        "certificate_size": len(cert_der),
        "certificate_sha256": hashlib.sha256(cert_der).hexdigest(),
        "spki_sha256": hashlib.sha256(spki).hexdigest(),
        "signature_algorithm": "sha512WithRSAEncryption",
        "extension_oids": [oid for oid, _ in extensions],
        "private_key_material_recorded": False,
        "private_key_path_recorded": False,
        "warnings": validation["warnings"],
    }

    if package_path is not None:
        payload = Path(normalized["input"]).read_bytes()
        package_bytes = cert_der + payload
        package_path.parent.mkdir(parents=True, exist_ok=True)
        package_path.write_bytes(package_bytes)
        verification = verify_artifact(package_path)
        result.update({
            "package": str(package_path),
            "package_size": len(package_bytes),
            "package_sha256": hashlib.sha256(package_bytes).hexdigest(),
            "host_side_verification": verification["overall_host_side_verification"],
        })
    else:
        result["classification"] = inspect_artifact(out)["classification"]

    return result


def _hex_octet(value: int, width_bytes: int) -> str:
    return value.to_bytes(width_bytes, "big").hex()


def render_openssl_config(profile_path: str | Path) -> str:
    """Application veya Secure Debug profile için okunabilir OpenSSL config üretir."""
    profile = load_profile(profile_path)
    validation = validate_profile(profile)
    if validation["status"] != "PASS":
        raise ValueError("profile doğrulaması başarısız: " + "; ".join(validation["issues"]))
    n = validation["normalized"]
    if n["type"] not in {"application", "debug"}:
        raise ValueError("OpenSSL config yalnız application ve debug profile için üretilir")

    subject = n["subject"]
    subject_lines: list[str] = []
    key_map = {
        "country": "C",
        "state": "ST",
        "locality": "L",
        "organization": "O",
        "organizational_unit": "OU",
        "common_name": "CN",
        "email": "emailAddress",
    }
    for key, out_name in key_map.items():
        if subject.get(key):
            subject_lines.append(f"{out_name} = {subject[key]}")

    lines = [
        "[ req ]",
        "distinguished_name = req_distinguished_name",
        "x509_extensions = v3_ca",
        "prompt = no",
        "dirstring_type = nobmp",
        "",
        "[ req_distinguished_name ]",
        *subject_lines,
        "",
        "[ v3_ca ]",
        "basicConstraints = CA:true",
    ]

    if n["type"] == "application":
        lines += [
            f"{TI_OIDS['software_revision']} = ASN1:SEQUENCE:swrv",
            f"{TI_OIDS['sysfw_image_integrity']} = ASN1:SEQUENCE:sysfw_image_integrity",
            f"{TI_OIDS['sysfw_image_load']} = ASN1:SEQUENCE:sysfw_image_load",
        ]
        if n.get("boot_enabled"):
            lines.append(f"{TI_OIDS['sysfw_boot']} = ASN1:SEQUENCE:sysfw_boot")
        lines += [
            "",
            "[ swrv ]",
            f"swrv = INTEGER:{n['software_revision']}",
            "",
            "[ sysfw_image_integrity ]",
            f"shaType = OID:{SHA512_OID}",
            f"shaValue = FORMAT:HEX,OCT:{n['payload_sha512']}",
            f"imageSize = INTEGER:{n['payload_size']}",
            "",
            "[ sysfw_image_load ]",
            f"destAddr = FORMAT:HEX,OCT:{_hex_octet(n['load_dest_addr'], 8)}",
            f"authType = INTEGER:{n['load_auth_mode'] | (n['load_copy_as_host'] << 8)}",
        ]
        if n.get("boot_enabled"):
            lines += [
                "",
                "[ sysfw_boot ]",
                f"bootCore = INTEGER:{n['boot_boot_core']}",
                f"configFlags_set = INTEGER:{n['boot_config_flags_set']}",
                f"configFlags_clr = INTEGER:{n['boot_config_flags_clr']}",
                f"resetVec = FORMAT:HEX,OCT:{_hex_octet(n['boot_reset_vector'], 8)}",
                f"fieldValid = INTEGER:{n['boot_field_valid']}",
                "rsvd1 = INTEGER:0",
                "rsvd2 = INTEGER:0",
                "rsvd3 = INTEGER:0",
            ]
    else:
        uid = n["debug_soc_uid_hex"]
        ctrl = n["debug_privilege"] | (n["debug_reserved"] << 16)
        nonsec = _ids_to_integer(n["debug_nonsecure_core_ids"])
        sec = _ids_to_integer(n["debug_secure_core_ids"])
        lines += [
            f"{TI_OIDS['software_revision']} = ASN1:SEQUENCE:swrv",
            f"{TI_OIDS['sysfw_debug']} = ASN1:SEQUENCE:debug",
            "",
            "[ swrv ]",
            f"swrv = INTEGER:{n['software_revision']}",
            "",
            "[ debug ]",
            f"debugUID = FORMAT:HEX,OCT:{uid}",
            f"debugType = INTEGER:0x{ctrl:08x}",
            f"coreDbgEn = INTEGER:0x{nonsec:x}",
            f"coreDbgSecEn = INTEGER:0x{sec:x}",
        ]

    return "\n".join(lines) + "\n"


def explain_certificate(path: str | Path) -> str:
    """Certificate/image içeriğini kısa ve doğal Türkçe ile açıklar."""
    info = inspect_artifact(path)
    decoded = info.get("decoded", {})
    lines = [
        f"Dosya: {info['file']}",
        f"Tür: {info['classification']}",
        f"TISCI kullanım biçimi: {info.get('tisci_request_semantics', 'not_determined')}",
        f"Certificate boyutu: {info['certificate_size']} byte",
        f"Certificate SHA-256: {info['certificate_sha256']}",
        f"Public key SPKI SHA-256: {info['spki_sha256']}",
        f"Signature hash: {info.get('signature_hash_algorithm')}",
    ]

    if "software_revision" in decoded and "decode_error" not in decoded["software_revision"]:
        lines.append(f"Software revision: {decoded['software_revision']['software_revision']}")
    if "sysfw_image_integrity" in decoded and "decode_error" not in decoded["sysfw_image_integrity"]:
        integ = decoded["sysfw_image_integrity"]
        lines.append(f"Image integrity: SHA2-512, {integ['image_size']} byte")
    if "sysfw_image_load" in decoded and "decode_error" not in decoded["sysfw_image_load"]:
        load = decoded["sysfw_image_load"]
        lines.append(f"Load: destAddr={load['dest_addr_hex']}, auth_mode={load['auth_mode']}, copy_as_host={load['copy_as_host']}")
    if "sysfw_boot" in decoded and "decode_error" not in decoded["sysfw_boot"]:
        boot = decoded["sysfw_boot"]
        lines.append(f"Boot: core={boot['boot_core']}, resetVec={boot['reset_vector_hex']}")
    if "sysfw_encryption" in decoded and "decode_error" not in decoded["sysfw_encryption"]:
        enc = decoded["sysfw_encryption"]
        lines.append(f"Encryption metadata: IV {enc['iv_length']} byte, randomString {enc['random_string_length']} byte, iterationCnt={enc['iteration_count']}")
    if "sysfw_debug" in decoded and "decode_error" not in decoded["sysfw_debug"]:
        dbg = decoded["sysfw_debug"]
        lines.append(f"Secure Debug: privilege={dbg['debug_privilege']}, non-secure cores={dbg['nonsecure_core_ids']}, secure cores={dbg['secure_core_ids']}")

    if info["classification"] == "Keywriter X.509 certificate":
        lines.append("Keywriter alanlarında key/IV/random-string byte değerleri gösterilmez; yalnız yapısal metadata raporlanır.")

    lines += [
        "",
        "Not: Certificate signature doğrulaması ile target cihazdaki customer Root of Trust enforcement aynı şey değildir.",
    ]
    return "\n".join(lines)
