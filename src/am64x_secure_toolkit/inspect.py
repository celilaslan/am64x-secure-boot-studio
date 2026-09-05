"""X.509 ve secure image dosyalarını değiştirmeden inceler."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .constants import KEYWRITER_OIDS, OID_NAMES, ROM_COMPONENT_TYPES, TI_OIDS, VERIFICATION_SCOPE
from .der import first_der_object_length
from .x509ext import (
    decode_boot,
    decode_debug,
    decode_encryption,
    decode_ext_boot_info,
    decode_integrity,
    decode_keywriter_encrypted_field,
    decode_keywriter_simple_field,
    decode_keywriter_version,
    decode_load,
    decode_swrv,
)


def _fingerprint_spki_sha256(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def _raw_extension(cert: x509.Certificate, oid: str) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value
    except x509.ExtensionNotFound:
        return None
    if isinstance(ext, x509.UnrecognizedExtension):
        return ext.value
    return getattr(ext, "value", None)


def inspect_artifact(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    data = p.read_bytes()
    cert_len = first_der_object_length(data)
    cert_der = data[:cert_len]
    payload = data[cert_len:]
    cert = x509.load_der_x509_certificate(cert_der)

    result: dict[str, Any] = {
        "file": p.name,
        "file_size": len(data),
        "file_sha256": hashlib.sha256(data).hexdigest(),
        "certificate_size": cert_len,
        "certificate_sha256": hashlib.sha256(cert_der).hexdigest(),
        "appended_size": len(payload),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "signature_hash_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
        "spki_sha256": _fingerprint_spki_sha256(cert),
        "extensions": [],
        "decoded": {},
        "classification": "unknown",
        "tisci_request_semantics": "not_determined",
        "verification_scope": VERIFICATION_SCOPE,
    }

    present: set[str] = set()
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        present.add(oid)
        result["extensions"].append({
            "oid": oid,
            "name": OID_NAMES.get(oid, ext.oid._name or "unknown"),
            "critical": ext.critical,
        })

    decoders = [
        (TI_OIDS["software_revision"], "software_revision", decode_swrv),
        (TI_OIDS["sysfw_boot"], "sysfw_boot", decode_boot),
        (TI_OIDS["sysfw_encryption"], "sysfw_encryption", decode_encryption),
        (TI_OIDS["sysfw_debug"], "sysfw_debug", decode_debug),
        (TI_OIDS["sysfw_image_integrity"], "sysfw_image_integrity", decode_integrity),
        (TI_OIDS["sysfw_image_load"], "sysfw_image_load", decode_load),
        (TI_OIDS["rom_ext_boot_info"], "rom_ext_boot_info", decode_ext_boot_info),
    ]
    for oid, name, decoder in decoders:
        raw = _raw_extension(cert, oid)
        if raw is not None:
            try:
                result["decoded"][name] = decoder(raw)
            except Exception as exc:
                result["decoded"][name] = {"decode_error": str(exc)}

    encrypted_kw_names = {
        "keywriter_aes_encrypted_smpkh",
        "keywriter_aes_encrypted_smek",
        "keywriter_aes_encrypted_bmpkh",
        "keywriter_aes_encrypted_bmek",
    }
    simple_kw_names = {
        "keywriter_mpk_options",
        "keywriter_mek_options",
        "keywriter_key_revision",
        "keywriter_msv",
        "keywriter_key_count",
        "keywriter_swrev_sysfw",
        "keywriter_swrev_sbl",
        "keywriter_swrev_sec_boardcfg",
    }
    for name in sorted(encrypted_kw_names):
        oid = TI_OIDS[name]
        raw = _raw_extension(cert, oid)
        if raw is not None:
            try:
                result["decoded"][name] = decode_keywriter_encrypted_field(raw)
            except Exception as exc:
                result["decoded"][name] = {"decode_error": str(exc)}
    for name in sorted(simple_kw_names):
        oid = TI_OIDS[name]
        raw = _raw_extension(cert, oid)
        if raw is not None:
            try:
                result["decoded"][name] = decode_keywriter_simple_field(raw)
            except Exception as exc:
                result["decoded"][name] = {"decode_error": str(exc)}
    raw_version = _raw_extension(cert, TI_OIDS["keywriter_version"])
    if raw_version is not None:
        try:
            result["decoded"]["keywriter_version"] = decode_keywriter_version(raw_version)
        except Exception as exc:
            result["decoded"]["keywriter_version"] = {"decode_error": str(exc)}

    if TI_OIDS["rom_ext_boot_info"] in present:
        result["classification"] = "ROM combined image"
        info = result["decoded"].get("rom_ext_boot_info") or {}
        for c in info.get("components", []):
            c["component_name"] = ROM_COMPONENT_TYPES.get(c["comp_type"], "unmapped component type")
        result["rom_legacy_exclusivity"] = {
            "ext_boot_info_present": True,
            "legacy_boot_info_present": TI_OIDS["rom_boot_info"] in present,
            "legacy_image_integrity_present": TI_OIDS["rom_image_integrity"] in present,
        }
    elif present & KEYWRITER_OIDS:
        result["classification"] = "Keywriter X.509 certificate"
    elif TI_OIDS["sysfw_debug"] in present:
        result["classification"] = "Secure Debug X.509 certificate"
    elif TI_OIDS["sysfw_image_integrity"] in present:
        result["classification"] = (
            "encrypted+signed application/generic data"
            if TI_OIDS["sysfw_encryption"] in present
            else "signed application/generic data"
        )
        if TI_OIDS["sysfw_image_load"] in present:
            result["tisci_request_semantics"] = (
                "authenticated_processor_boot"
                if TI_OIDS["sysfw_boot"] in present
                else "generalized_authentication"
            )
        else:
            result["tisci_request_semantics"] = "incomplete_system_firmware_profile"

    return result
