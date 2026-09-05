"""TISCI generalized authentication için generic binary hazırlama ve doğrulama araçları."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import yaml
from asn1crypto import core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .certificate import (
    SysfwIntegrity,
    SysfwLoad,
    SysfwSwrev,
    _add_custom,
    _certificate_builder,
    _load_rsa4096_private_key,
)
from .constants import SHA512_OID, TI_OIDS, VERIFICATION_SCOPE
from .der import first_der_object_length
from .inspect import inspect_artifact
from .verify import verify_artifact
from .x509ext import SysfwEncryption


class GenericEncryption(core.Sequence):
    _fields = [
        ("initalVector", core.OctetString),  # TISCI 12.00.02 kaynak yazımı korunur.
        ("randomString", core.OctetString),
        ("iterationCnt", core.Integer),
        ("salt", core.OctetString),
    ]


LOAD_MODE_NAMES = {
    0: "normal_copy_to_dest_addr",
    1: "in_place_no_move",
    2: "in_place_variant",
}


def template_generic_data_profile() -> dict[str, Any]:
    """Secret içermeyen generalized-authentication profile şablonu."""
    return {
        "type": "generic_data",
        "subject": {
            "common_name": "AM64x Authenticated Data",
            "organization": "<COMPANY_OR_PROJECT_NAME>",
        },
        "input": "<DATA_FILE>",
        "software_revision": 1,
        "load": {
            "dest_addr": "<SOURCE_VERIFIED_VALUE>",
            "auth_mode": 1,
            "copy_as_host": "<SOURCE_VERIFIED_VALUE>",
        },
        "encryption": {
            "enabled": False,
        },
        "valid_days": 3650,
    }


def save_generic_data_profile(profile: dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    if p.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(profile, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _load_profile(path: str | Path) -> dict[str, Any]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("profile dosyasının en üst seviyesi YAML mapping olmalıdır")
    return raw


def _parse_int(value: Any, field: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field}: boolean değer kabul edilmez")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        text = value.strip()
        if text.startswith("<") and text.endswith(">"):
            raise ValueError(f"{field}: örnek değer henüz doldurulmamış")
        n = int(text, 0)
    else:
        raise ValueError(f"{field}: integer veya 0x... biçiminde değer gerekli")
    if n < minimum or (maximum is not None and n > maximum):
        raise ValueError(f"{field}: geçersiz değer {n}")
    return n


def _require_data_file(value: Any) -> Path:
    if value is None or (isinstance(value, str) and value.startswith("<")):
        raise ValueError("input: data dosyası yolu doldurulmalıdır")
    p = Path(str(value)).expanduser()
    if not p.is_file():
        raise FileNotFoundError("input: data dosyası bulunamadı")
    return p


def _validate_subject(value: Any, issues: list[str]) -> dict[str, str]:
    if not isinstance(value, dict):
        issues.append("subject: YAML mapping olmalıdır")
        return {}
    allowed = {"country", "state", "locality", "organization", "organizational_unit", "common_name", "email"}
    out: dict[str, str] = {}
    for key, raw in value.items():
        if key not in allowed:
            issues.append(f"subject.{key}: desteklenmeyen alan")
            continue
        if raw is None:
            continue
        text = str(raw).strip()
        if not text or (text.startswith("<") and text.endswith(">")):
            issues.append(f"subject.{key}: doldurulmuş bir değer gerekli")
            continue
        out[key] = text
    if not out.get("common_name"):
        issues.append("subject.common_name: doldurulmuş bir değer gerekli")
    return out


def validate_generic_data_profile(profile_or_path: dict[str, Any] | str | Path) -> dict[str, Any]:
    profile = _load_profile(profile_or_path) if not isinstance(profile_or_path, dict) else profile_or_path
    issues: list[str] = []
    warnings: list[str] = []
    normalized: dict[str, Any] = {"type": "generic_data"}

    if profile.get("type") != "generic_data":
        issues.append("type: generic_data olmalıdır")

    normalized["subject"] = _validate_subject(profile.get("subject"), issues)

    try:
        p = _require_data_file(profile.get("input"))
        data = p.read_bytes()
        normalized["input"] = str(p)
        normalized["input_size"] = len(data)
        normalized["input_sha256"] = hashlib.sha256(data).hexdigest()
        normalized["input_sha512"] = hashlib.sha512(data).hexdigest()
    except Exception as exc:
        issues.append(str(exc))

    try:
        normalized["software_revision"] = _parse_int(
            profile.get("software_revision"), "software_revision", minimum=1, maximum=0xFFFFFFFF
        )
    except Exception as exc:
        issues.append(str(exc))

    try:
        normalized["valid_days"] = _parse_int(profile.get("valid_days", 3650), "valid_days", minimum=1, maximum=36500)
    except Exception as exc:
        issues.append(str(exc))

    load = profile.get("load")
    if not isinstance(load, dict):
        issues.append("load: YAML mapping olmalıdır")
        load = {}
    try:
        normalized["load_dest_addr"] = _parse_int(load.get("dest_addr"), "load.dest_addr", maximum=0xFFFFFFFFFFFFFFFF)
    except Exception as exc:
        issues.append(str(exc))
    try:
        mode = _parse_int(load.get("auth_mode"), "load.auth_mode", maximum=2)
        normalized["load_auth_mode"] = mode
        normalized["load_auth_mode_name"] = LOAD_MODE_NAMES[mode]
    except Exception as exc:
        issues.append(str(exc))
    try:
        normalized["load_copy_as_host"] = _parse_int(load.get("copy_as_host"), "load.copy_as_host", maximum=0xFF)
    except Exception as exc:
        issues.append(str(exc))

    encryption = profile.get("encryption", {"enabled": False})
    if not isinstance(encryption, dict):
        issues.append("encryption: YAML mapping olmalıdır")
        encryption = {"enabled": False}
    normalized["encryption_enabled"] = bool(encryption.get("enabled", False))

    if "boot" in profile:
        issues.append("boot: generic_data profile Boot Extension kabul etmez; Boot Extension processor-boot akışını ifade eder")

    warnings.extend([
        "load.dest_addr ve load.copy_as_host değerleri toolkit tarafından tahmin edilmez; kullanılacak TISCI çağrısı/SoC bağlamından doğrulanmalıdır.",
        "Generalized Authentication target üzerinde ancak TISCI_MSG_PROC_AUTH_BOOT çağrısıyla anlam kazanır; bu toolkit target API çağrısı yapmaz.",
        "Generic data SWREV alanı TISCI 12.00.02'de zorunlu tutulur; aynı kaynak bu certificate türü için ek revision action'ını future-use olarak açıklar.",
    ])
    if normalized.get("encryption_enabled"):
        warnings.append(
            "Encryption profile TISCI 12.00.02 biçimini kullanır: 16-byte IV, 32-byte randomString, iterationCnt=0 ve 32-byte zero salt. Kurulu SDK 12.00.00.27 application signer'daki daha kısa salt gözlemi bu bağımsız generic-data üretimine taşınmaz."
        )

    return {
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "warnings": warnings,
        "normalized": normalized,
    }


def _strict_mek_bytes(path: str | Path) -> bytes:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError("MEK dosyası bulunamadı")
    raw = p.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("MEK dosyası ASCII hexadecimal metin olmalıdır") from exc
    if text != text.strip():
        raise ValueError("MEK dosyası tam 64 hex karakter içermeli; başta/sonda whitespace kabul edilmez")
    if len(text) != 64:
        raise ValueError("MEK dosyası AES-256 için tam 64 hex karakter içermelidir")
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("MEK dosyası yalnız hexadecimal karakterlerden oluşmalıdır") from exc
    if len(key) != 32:
        raise ValueError("MEK AES-256 için 32 byte olmalıdır")
    return key


def _encrypt_payload(plaintext: bytes, key: bytes) -> tuple[bytes, dict[str, Any], bytes, bytes]:
    padding_count = (-len(plaintext)) % 16
    padded = plaintext + (b"\x00" * padding_count)
    random_string = os.urandom(32)
    iv = os.urandom(16)
    prepared = padded + random_string
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(prepared) + encryptor.finalize()
    metadata = {
        "padding_bytes": padding_count,
        "iv_length": 16,
        "random_string_length": 32,
        "iteration_count": 0,
        "salt_length": 32,
        "salt_all_zero": True,
        "ciphertext_size": len(ciphertext),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "ciphertext_sha512": hashlib.sha512(ciphertext).hexdigest(),
        "sensitive_values_emitted": False,
    }
    return ciphertext, metadata, iv, random_string


def _generic_extensions(n: dict[str, Any], package_payload: bytes, *, iv: bytes | None = None, random_string: bytes | None = None) -> list[tuple[str, bytes]]:
    integrity = SysfwIntegrity({
        "shaType": SHA512_OID,
        "shaValue": hashlib.sha512(package_payload).digest(),
        "imageSize": len(package_payload),
    }).dump()
    auth_type = n["load_auth_mode"] | (n["load_copy_as_host"] << 8)
    load = SysfwLoad({
        "destAddr": n["load_dest_addr"].to_bytes(8, "big"),
        "authType": auth_type,
    }).dump()
    swrv = SysfwSwrev({"swrv": n["software_revision"]}).dump()
    out = [
        (TI_OIDS["software_revision"], swrv),
        (TI_OIDS["sysfw_image_integrity"], integrity),
        (TI_OIDS["sysfw_image_load"], load),
    ]
    if n["encryption_enabled"]:
        if iv is None or random_string is None:
            raise ValueError("encryption metadata eksik")
        enc = GenericEncryption({
            "initalVector": iv,
            "randomString": random_string,
            "iterationCnt": 0,
            "salt": bytes(32),
        }).dump()
        out.append((TI_OIDS["sysfw_encryption"], enc))
    return out


def _raw_extension(cert: x509.Certificate, oid: str) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value
    except x509.ExtensionNotFound:
        return None
    if isinstance(ext, x509.UnrecognizedExtension):
        return ext.value
    return getattr(ext, "value", None)


def build_generic_data(
    profile_path: str | Path,
    signing_key: str | Path,
    output: str | Path,
    *,
    certificate_output: str | Path | None = None,
    mek: str | Path | None = None,
) -> dict[str, Any]:
    """Generic binary için signed veya encrypted+signed TISCI package üretir."""
    validation = validate_generic_data_profile(profile_path)
    if validation["status"] != "PASS":
        raise ValueError("profile doğrulaması başarısız: " + "; ".join(validation["issues"]))
    n = validation["normalized"]

    out = Path(output)
    cert_out = Path(certificate_output) if certificate_output is not None else out.with_suffix(out.suffix + ".der")
    if out.resolve() == cert_out.resolve():
        raise ValueError("--output ve --certificate aynı dosya olamaz")
    if out.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {out}")
    if cert_out.exists():
        raise FileExistsError(f"certificate çıktısı zaten mevcut: {cert_out}")

    plaintext = Path(n["input"]).read_bytes()
    enc_meta: dict[str, Any] | None = None
    iv = random_string = None
    mek_bytes: bytes | None = None
    if n["encryption_enabled"]:
        if mek is None:
            raise ValueError("encryption.enabled=true için --mek gereklidir")
        mek_bytes = _strict_mek_bytes(mek)
        package_payload, enc_meta, iv, random_string = _encrypt_payload(plaintext, mek_bytes)
    else:
        if mek is not None:
            raise ValueError("encryption.enabled=false iken --mek verilmemelidir")
        package_payload = plaintext

    key = _load_rsa4096_private_key(signing_key)
    builder = _certificate_builder(n["subject"], key, n["valid_days"])
    extensions = _generic_extensions(n, package_payload, iv=iv, random_string=random_string)
    for oid, der_value in extensions:
        builder = _add_custom(builder, oid, der_value)
    cert = builder.sign(private_key=key, algorithm=hashes.SHA512())
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    cert_out.parent.mkdir(parents=True, exist_ok=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    cert_out.write_bytes(cert_der)
    package = cert_der + package_payload
    out.write_bytes(package)

    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    verification = verify_generic_data(out, mek=mek if n["encryption_enabled"] else None, original=n["input"])

    result: dict[str, Any] = {
        "status": "PASS" if verification["status"] == "PASS" else "FAIL",
        "mode": "encrypted+signed" if n["encryption_enabled"] else "signed",
        "tisci_request_semantics": "generalized_authentication",
        "certificate": str(cert_out),
        "output": str(out),
        "certificate_size": len(cert_der),
        "package_payload_size": len(package_payload),
        "package_size": len(package),
        "certificate_sha256": hashlib.sha256(cert_der).hexdigest(),
        "package_sha256": hashlib.sha256(package).hexdigest(),
        "input_size": len(plaintext),
        "input_sha256": hashlib.sha256(plaintext).hexdigest(),
        "spki_sha256": hashlib.sha256(spki).hexdigest(),
        "extension_oids": [oid for oid, _ in extensions],
        "boot_extension_present": False,
        "load_auth_mode": n["load_auth_mode"],
        "load_auth_mode_name": n["load_auth_mode_name"],
        "load_copy_as_host": n["load_copy_as_host"],
        "encryption": enc_meta or {"enabled": False},
        "host_side_verification": verification["status"],
        "summary": (
            "Encrypted+signed generic data package üretildi ve host-side kontroller tamamlandı."
            if n["encryption_enabled"] else
            "Signed generic data package üretildi ve host-side kontroller tamamlandı."
        ),
        "checks": verification.get("checks", []),
        "outputs": [
            {"type": "generic_package", "path": str(out)},
            {"type": "certificate", "path": str(cert_out)},
        ],
        "private_key_material_recorded": False,
        "private_key_path_recorded": False,
        "mek_material_recorded": False,
        "mek_path_recorded": False,
        "verification_scope": VERIFICATION_SCOPE,
        "warnings": validation["warnings"],
    }
    return result


def verify_generic_data(
    package_path: str | Path,
    *,
    mek: str | Path | None = None,
    original: str | Path | None = None,
) -> dict[str, Any]:
    """Generic data package'ı host üzerinde doğrular; target TISCI çağrısı yapmaz."""
    p = Path(package_path)
    raw = p.read_bytes()
    cert_len = first_der_object_length(raw)
    cert_der = raw[:cert_len]
    appended = raw[cert_len:]
    cert = x509.load_der_x509_certificate(cert_der)
    present = {ext.oid.dotted_string for ext in cert.extensions}
    encrypted = TI_OIDS["sysfw_encryption"] in present

    base = verify_artifact(p)
    checks: list[dict[str, Any]] = []
    mandatory = [TI_OIDS["software_revision"], TI_OIDS["sysfw_image_integrity"], TI_OIDS["sysfw_image_load"]]
    missing = [oid for oid in mandatory if oid not in present]
    checks.append({
        "check": "generalized_authentication_extension_set",
        "status": "PASS" if not missing and TI_OIDS["sysfw_boot"] not in present else "FAIL",
        "missing_oids": missing,
        "boot_extension_present": TI_OIDS["sysfw_boot"] in present,
    })

    sw = inspect_artifact(p).get("decoded", {}).get("software_revision", {})
    swrev = sw.get("software_revision") if isinstance(sw, dict) else None
    checks.append({
        "check": "software_revision_present_nonzero",
        "status": "PASS" if isinstance(swrev, int) and swrev >= 1 else "FAIL",
        "software_revision": swrev,
    })

    original_bytes: bytes | None = None
    if original is not None:
        op = Path(original)
        if not op.is_file():
            raise FileNotFoundError("original data dosyası bulunamadı")
        original_bytes = op.read_bytes()

    if not encrypted:
        if mek is not None:
            raise ValueError("package encryption extension içermiyor; --mek verilmemelidir")
        if original_bytes is not None:
            checks.append({
                "check": "plaintext_identity",
                "status": "PASS" if appended == original_bytes else "FAIL",
                "original_supplied": True,
            })
    else:
        enc_raw = _raw_extension(cert, TI_OIDS["sysfw_encryption"])
        if enc_raw is None:
            checks.append({"check": "encryption_extension_decode", "status": "FAIL"})
        else:
            enc = SysfwEncryption.load(enc_raw)
            iv = enc["initalVector"].native
            random_string = enc["randomString"].native
            iteration = int(enc["iterationCnt"].native)
            salt = enc["salt"].native
            checks.extend([
                {"check": "encryption_iv_length", "status": "PASS" if len(iv) == 16 else "FAIL", "actual": len(iv), "expected": 16},
                {"check": "encryption_random_string_length", "status": "PASS" if len(random_string) == 32 else "FAIL", "actual": len(random_string), "expected": 32},
                {"check": "encryption_iteration_count", "status": "PASS" if iteration == 0 else "FAIL", "actual": iteration, "expected": 0},
                {"check": "encryption_salt_tisci_12_00_02", "status": "PASS" if len(salt) == 32 and salt == bytes(32) else "FAIL", "length": len(salt), "all_zero": salt == bytes(len(salt))},
            ])

            if mek is None:
                checks.append({
                    "check": "decryption_random_string",
                    "status": "NOT_CHECKED",
                    "reason": "Encrypted package için --mek verilmedi; ciphertext integrity kontrolü yapılır ancak decryption correctness doğrulanmaz.",
                })
            else:
                key = _strict_mek_bytes(mek)
                if len(appended) % 16:
                    checks.append({"check": "decryption_ciphertext_alignment", "status": "FAIL", "actual_size": len(appended)})
                else:
                    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                    decrypted = decryptor.update(appended) + decryptor.finalize()
                    rs_ok = len(decrypted) >= 32 and decrypted[-32:] == random_string
                    checks.append({
                        "check": "decryption_random_string",
                        "status": "PASS" if rs_ok else "FAIL",
                        "decrypted_size": len(decrypted),
                        "sensitive_values_emitted": False,
                    })
                    if original_bytes is not None:
                        pad = (-len(original_bytes)) % 16
                        body = decrypted[:-32] if len(decrypted) >= 32 else b""
                        checks.extend([
                            {"check": "decrypted_original_prefix", "status": "PASS" if body[:len(original_bytes)] == original_bytes else "FAIL"},
                            {"check": "decrypted_zero_padding", "status": "PASS" if len(body) == len(original_bytes) + pad and body[len(original_bytes):] == bytes(pad) else "FAIL", "expected_padding_bytes": pad},
                        ])

    fail = any(c["status"] == "FAIL" for c in checks) or base["overall_host_side_verification"] == "FAIL"
    partial = any(c["status"] == "NOT_CHECKED" for c in checks) or base["overall_host_side_verification"] in {"PARTIAL", "NOT_CHECKED"}
    status = "FAIL" if fail else ("PARTIAL" if partial else "PASS")
    return {
        "status": status,
        "operation": "generic_data_verify",
        "summary": (
            "Encrypted generic data package host üzerinde doğrulandı; target TISCI request çalıştırılmadı."
            if encrypted else
            "Signed generic data package host üzerinde doğrulandı; target TISCI request çalıştırılmadı."
        ),
        "file": p.name,
        "mode": "encrypted+signed" if encrypted else "signed",
        "tisci_request_semantics": "generalized_authentication",
        "base_host_side_verification": base["overall_host_side_verification"],
        "checks": checks,
        "private_key_material_recorded": False,
        "mek_material_recorded": False,
        "mek_path_recorded": False,
        "decrypted_payload_emitted": False,
        "target_tisci_request_executed": False,
        "hardware_enforcement_verified": False,
        "verification_scope": VERIFICATION_SCOPE,
    }
