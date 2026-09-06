"""Bağımsız host-side doğrulamalar; sonuçlar hardware enforcement kanıtı değildir."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .constants import KEYWRITER_OIDS, SHA512_OID, TI_OIDS, VERIFICATION_SCOPE
from .der import first_der_object_length
from .inspect import inspect_artifact


def _verify_embedded_key_signature(cert: x509.Certificate) -> tuple[str, str | None]:
    """Certificate signature'ını certificate içindeki public key ile doğrular.

    Bu kontrol yalnız certificate'ın matematiksel self-consistency durumunu gösterir;
    target cihazdaki Root of Trust eşleşmesini göstermez.
    """
    pub = cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            try:
                if pub.public_numbers().e == 1:
                    return "NOT_CHECKED", "degenerate RSA public key; trusted-signer authenticity değerlendirilmedi"
            except Exception:
                pass
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            return "NOT_CHECKED", f"desteklenmeyen public key türü: {type(pub).__name__}"
        return "PASS", None
    except InvalidSignature:
        return "FAIL", "certificate signature eşleşmiyor"
    except Exception as exc:
        return "NOT_CHECKED", str(exc)


def _overall(checks: list[dict[str, Any]]) -> str:
    statuses = [c.get("status") for c in checks]
    if "FAIL" in statuses:
        return "FAIL"
    if "NOT_CHECKED" in statuses:
        return "PARTIAL"
    return "PASS" if statuses and all(s == "PASS" for s in statuses) else "NOT_CHECKED"


def _check_core_ids(ids: list[int]) -> bool:
    return bool(ids) and all(0 <= x <= 255 for x in ids) and not (255 in ids and len(ids) != 1)


def verify_artifact(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    data = p.read_bytes()
    # Standalone PEM certificate'ları da aynı DER/TI-extension doğrulama motorundan geçir.
    # PEM public material'dir; temporary DER yalnız runtime boyunca tutulur.
    if data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
        cert = x509.load_pem_x509_certificate(data)
        der = cert.public_bytes(serialization.Encoding.DER)
        with tempfile.TemporaryDirectory(prefix="am64x-cert-verify-") as td:
            tmp = Path(td) / "certificate.der"
            tmp.write_bytes(der)
            result = verify_artifact(tmp)
        result["file"] = p.name
        result["input_format"] = "PEM"
        return result
    cert_len = first_der_object_length(data)
    cert = x509.load_der_x509_certificate(data[:cert_len])
    appended = data[cert_len:]
    has_appended_payload = len(appended) > 0
    inspected = inspect_artifact(p)
    present = {x["oid"] for x in inspected.get("extensions", [])}
    classification = inspected["classification"]

    sig_status, sig_reason = _verify_embedded_key_signature(cert)
    checks: list[dict[str, Any]] = [{
        "check": "certificate_signature_with_embedded_public_key",
        "status": sig_status,
        "reason": sig_reason,
        "trust_note": "Bu kontrol embedded public key'in cihazda trusted/provisioned olduğunu kanıtlamaz.",
    }]

    if classification == "unknown":
        checks.append({
            "check": "supported_secure_image_profile",
            "status": "NOT_CHECKED",
            "reason": "Desteklenen ROM, System Firmware, Secure Debug veya Keywriter profili bulunamadı.",
        })

    if classification in {"signed application/generic data", "encrypted+signed application/generic data"}:
        checks.append({
            "check": "system_firmware_load_extension_present",
            "status": "PASS" if TI_OIDS["sysfw_image_load"] in present else "FAIL",
            "reason": None if TI_OIDS["sysfw_image_load"] in present else "TISCI binary authentication için Load Extension gerekir.",
        })
        # TISCI 12.00.02 kaynaklarında application/generic SWREV wording'i aynı release içinde
        # farklı ifade edildiği için burada absence hard-fail yapılmaz.

    integrity = inspected.get("decoded", {}).get("sysfw_image_integrity")
    if integrity and "decode_error" not in integrity:
        declared_size = integrity["image_size"]
        declared_hash = integrity["sha_value_hex"].lower()
        sha_oid = integrity["sha_oid"]
        if not has_appended_payload and classification in {"signed application/generic data", "encrypted+signed application/generic data"}:
            checks.extend([
                {
                    "check": "declared_image_size",
                    "status": "NOT_CHECKED",
                    "declared": declared_size,
                    "reason": "Standalone certificate seçildi; accompanying payload/ciphertext olmadığı için size binding doğrulanamaz.",
                },
                {
                    "check": "appended_payload_sha512_binding",
                    "status": "NOT_CHECKED",
                    "declared_sha512": declared_hash if sha_oid == SHA512_OID else None,
                    "reason": "Standalone certificate seçildi; accompanying payload/ciphertext olmadan integrity hash binding doğrulanamaz.",
                },
            ])
        else:
            checks.append({
                "check": "declared_image_size",
                "status": "PASS" if declared_size == len(appended) else "FAIL",
                "declared": declared_size,
                "actual": len(appended),
            })
            if sha_oid == SHA512_OID:
                actual_hash = hashlib.sha512(appended).hexdigest()
                checks.append({
                    "check": "appended_payload_sha512_binding",
                    "status": "PASS" if actual_hash == declared_hash else "FAIL",
                    "declared_sha512": declared_hash,
                    "actual_sha512": actual_hash,
                })
            else:
                checks.append({
                    "check": "appended_payload_hash_binding",
                    "status": "NOT_CHECKED",
                    "reason": f"Bu sürüm SHA-512 doğrular; certificate {sha_oid} bildiriyor.",
                })
    elif classification in {"signed application/generic data", "encrypted+signed application/generic data"}:
        checks.append({
            "check": "system_firmware_image_integrity_decoded",
            "status": "FAIL",
            "reason": "System Firmware Image Integrity Extension decode edilemedi.",
        })

    load = inspected.get("decoded", {}).get("sysfw_image_load")
    if load and "decode_error" not in load:
        # TI's official appimage_x509_cert_gen.py emits the default destination as
        # FORMAT:HEX,OCT:00000000 (4 bytes). Studio-created profiles may use the
        # full 64-bit representation. Both are valid OCTET STRING encodings; other
        # widths remain a structural failure.
        address_width_ok = load["dest_addr_length"] in {4, 8}
        checks.extend([
            {
                "check": "load_dest_addr_width",
                "status": "PASS" if address_width_ok else "FAIL",
                "actual_bytes": load["dest_addr_length"],
                "allowed_bytes": [4, 8],
            },
            {
                "check": "load_auth_mode",
                "status": "PASS" if load["auth_mode"] in {0, 1, 2} else "FAIL",
                "actual": load["auth_mode"],
                "allowed": [0, 1, 2],
            },
            {
                "check": "load_auth_type_reserved_bits",
                "status": "PASS" if load["reserved_upper16"] == 0 else "FAIL",
                "actual": load["reserved_upper16"],
                "expected": 0,
            },
        ])

    boot = inspected.get("decoded", {}).get("sysfw_boot")
    if boot and "decode_error" not in boot:
        checks.extend([
            {
                "check": "boot_reset_vector_width",
                "status": "PASS" if boot["reset_vector_length"] in {4, 8} else "FAIL",
                "actual_bytes": boot["reset_vector_length"],
                "allowed_bytes": [4, 8],
            },
            {
                "check": "boot_reserved_fields",
                "status": "PASS" if boot["reserved"] == [0, 0, 0] else "FAIL",
                "actual": boot["reserved"],
                "expected": [0, 0, 0],
            },
        ])

    encryption = inspected.get("decoded", {}).get("sysfw_encryption")
    if encryption and "decode_error" not in encryption:
        checks.extend([
            {
                "check": "aes_cbc_ciphertext_block_alignment",
                "status": ("NOT_CHECKED" if not has_appended_payload else ("PASS" if len(appended) % 16 == 0 else "FAIL")),
                "actual_size": len(appended) if has_appended_payload else None,
                "reason": None if has_appended_payload else "Standalone certificate seçildi; ciphertext mevcut değil.",
            },
            {
                "check": "encryption_iv_length",
                "status": "PASS" if encryption["iv_length"] == 16 else "FAIL",
                "actual": encryption["iv_length"],
                "expected": 16,
            },
            {
                "check": "encryption_random_string_length",
                "status": "PASS" if encryption["random_string_length"] == 32 else "FAIL",
                "actual": encryption["random_string_length"],
                "expected": 32,
            },
            {
                "check": "encryption_iteration_count",
                "status": "PASS" if encryption["iteration_count"] == 0 else "FAIL",
                "actual": encryption["iteration_count"],
                "expected": 0,
            },
        ])

    debug = inspected.get("decoded", {}).get("sysfw_debug")
    if classification == "Secure Debug X.509 certificate":
        checks.extend([
            {
                "check": "debug_extension_present",
                "status": "PASS" if TI_OIDS["sysfw_debug"] in present else "FAIL",
            },
            {
                "check": "debug_swrev_extension_present",
                "status": "PASS" if TI_OIDS["software_revision"] in present else "FAIL",
            },
            {
                "check": "debug_certificate_has_no_appended_payload",
                "status": "PASS" if len(appended) == 0 else "FAIL",
                "actual_appended_bytes": len(appended),
            },
        ])
        if not debug or "decode_error" in debug:
            checks.append({"check": "debug_extension_decoded", "status": "FAIL", "reason": "Debug Extension decode edilemedi."})
        else:
            checks.extend([
                {
                    "check": "debug_uid_length",
                    "status": "PASS" if debug["uid_length"] == 32 else "FAIL",
                    "actual": debug["uid_length"],
                    "expected": 32,
                },
                {
                    "check": "debug_privilege_range",
                    "status": "PASS" if debug["debug_privilege"] in {0, 1, 2, 3, 4, 5} else "FAIL",
                    "actual": debug["debug_privilege"],
                    "allowed": [0, 1, 2, 3, 4, 5],
                },
                {
                    "check": "debug_reserved_bits",
                    "status": "PASS" if debug["reserved_upper16"] == 0 else "FAIL",
                    "actual": debug["reserved_upper16"],
                    "expected": 0,
                },
                {
                    "check": "debug_nonsecure_core_id_encoding",
                    "status": "PASS" if _check_core_ids(debug["nonsecure_core_ids"]) else "FAIL",
                    "decoded": debug["nonsecure_core_ids"],
                },
                {
                    "check": "debug_secure_core_id_encoding",
                    "status": "PASS" if _check_core_ids(debug["secure_core_ids"]) else "FAIL",
                    "decoded": debug["secure_core_ids"],
                },
                {
                    "check": "target_debug_authorization",
                    "status": "NOT_CHECKED",
                    "reason": "SOC UID/BoardCfg/eFuse active customer Root of Trust ve runtime izinleri host-side certificate dosyasından doğrulanamaz.",
                },
            ])

    if classification == "Keywriter X.509 certificate":
        decoded = inspected.get("decoded", {})
        keywriter_present = sorted(present & KEYWRITER_OIDS)
        decoded_keywriter_oids = {
            TI_OIDS["keywriter_aes_encrypted_smpkh"],
            TI_OIDS["keywriter_aes_encrypted_smek"],
            TI_OIDS["keywriter_mpk_options"],
            TI_OIDS["keywriter_aes_encrypted_bmpkh"],
            TI_OIDS["keywriter_aes_encrypted_bmek"],
            TI_OIDS["keywriter_mek_options"],
            TI_OIDS["keywriter_key_revision"],
            TI_OIDS["keywriter_msv"],
            TI_OIDS["keywriter_key_count"],
            TI_OIDS["keywriter_swrev_sysfw"],
            TI_OIDS["keywriter_swrev_sbl"],
            TI_OIDS["keywriter_swrev_sec_boardcfg"],
            TI_OIDS["keywriter_version"],
        }
        unsupported_present = sorted((present & KEYWRITER_OIDS) - decoded_keywriter_oids)
        decode_failures = [name for name, value in decoded.items() if name.startswith("keywriter_") and "decode_error" in value]
        checks.extend([
            {
                "check": "keywriter_extension_family_present",
                "status": "PASS" if keywriter_present else "FAIL",
                "oids": keywriter_present,
            },
            {
                "check": "keywriter_supported_extension_decoding",
                "status": "FAIL" if decode_failures else ("NOT_CHECKED" if unsupported_present else "PASS"),
                "decode_failures": decode_failures,
                "not_decoded_oids": unsupported_present,
            },
            {
                "check": "otp_efuse_programming_result",
                "status": "NOT_CHECKED",
                "reason": "Bu kontrol yalnız certificate dosyasını inceler; OTP/eFuse programlama veya HS-FS→HS-SE geçişi çalıştırılmaz.",
            },
        ])

    rom = inspected.get("decoded", {}).get("rom_ext_boot_info")
    if rom and "decode_error" not in rom:
        legacy_conflict = TI_OIDS["rom_boot_info"] in present or TI_OIDS["rom_image_integrity"] in present
        checks.append({
            "check": "rom_combined_legacy_extension_exclusivity",
            "status": "FAIL" if legacy_conflict else "PASS",
            "legacy_boot_info_present": TI_OIDS["rom_boot_info"] in present,
            "legacy_image_integrity_present": TI_OIDS["rom_image_integrity"] in present,
        })
        num = rom.get("num_components", 0)
        parsed_num = len(rom.get("components", []))
        checks.extend([
            {
                "check": "rom_component_count_range",
                "status": "PASS" if 1 <= num <= 5 else "FAIL",
                "actual": num,
                "allowed": "1..5",
            },
            {
                "check": "rom_component_count_decoded",
                "status": "PASS" if num == parsed_num else "FAIL",
                "declared": num,
                "decoded": parsed_num,
            },
        ])
        offset = 0
        total_declared = 0
        for comp in rom.get("components", []):
            size = comp["comp_size"]
            blob = appended[offset:offset + size]
            total_declared += size
            checks.append({
                "check": f"rom_component_{comp['index']}_size",
                "status": ("NOT_CHECKED" if not has_appended_payload else ("PASS" if len(blob) == size else "FAIL")),
                "declared": size,
                "actual": len(blob) if has_appended_payload else None,
                "reason": None if has_appended_payload else "Standalone ROM certificate seçildi; component payload'ları mevcut değil.",
            })
            if has_appended_payload and len(blob) == size:
                if comp["sha_oid"] == SHA512_OID:
                    actual = hashlib.sha512(blob).hexdigest()
                    checks.append({
                        "check": f"rom_component_{comp['index']}_sha512",
                        "status": "PASS" if actual == comp["sha_value_hex"].lower() else "FAIL",
                        "declared_sha512": comp["sha_value_hex"].lower(),
                        "actual_sha512": actual,
                    })
                else:
                    checks.append({
                        "check": f"rom_component_{comp['index']}_hash",
                        "status": "NOT_CHECKED",
                        "reason": f"Desteklenmeyen component hash OID: {comp['sha_oid']}",
                    })
            offset += size
        checks.extend([
            {
                "check": "rom_component_total_size",
                "status": ("NOT_CHECKED" if not has_appended_payload else ("PASS" if total_declared == len(appended) else "FAIL")),
                "declared_component_sum": total_declared,
                "actual_appended": len(appended) if has_appended_payload else None,
                "reason": None if has_appended_payload else "Standalone ROM certificate seçildi; component toplamı image byte'larıyla karşılaştırılamaz.",
            },
            {
                "check": "rom_ext_image_size",
                "status": ("NOT_CHECKED" if not has_appended_payload else ("PASS" if rom["ext_image_size"] == len(appended) else "FAIL")),
                "declared_ext_image_size": rom["ext_image_size"],
                "actual_appended": len(appended) if has_appended_payload else None,
                "reason": None if has_appended_payload else "Standalone ROM certificate seçildi; ext_image_size image byte'larıyla karşılaştırılamaz.",
            },
        ])

    overall = _overall(checks)
    return {
        "file": p.name,
        "classification": classification,
        "overall_host_side_verification": overall,
        "checks": checks,
        "verification_scope": VERIFICATION_SCOPE,
        "note": "Host-side yapısal ve kriptografik doğrulama, hardware/customer enforcement kanıtı değildir.",
    }
