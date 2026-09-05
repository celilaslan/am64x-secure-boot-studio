from __future__ import annotations

import hashlib
import string
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_HEX = set(string.hexdigits)


def _public_info(public_key: Any) -> dict[str, Any]:
    if not isinstance(public_key, rsa.RSAPublicKey):
        return {
            "algorithm": type(public_key).__name__,
            "rsa": False,
            "rsa_bits": None,
            "public_exponent": None,
            "der_spki_sha256": None,
            "der_spki_bytes": None,
        }
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    numbers = public_key.public_numbers()
    return {
        "algorithm": "RSA",
        "rsa": True,
        "rsa_bits": public_key.key_size,
        "public_exponent": numbers.e,
        "der_spki_sha256": hashlib.sha256(der).hexdigest(),
        "der_spki_bytes": len(der),
    }


def _load_key_material(path: Path) -> tuple[str, Any, bytes | None]:
    """Load a public/private key or certificate without exposing its bytes.

    Returns (input_class, public_key, public_der_if_original_public_input).
    Private-key passwords are intentionally not accepted by this helper.
    """
    if not path.is_file():
        raise FileNotFoundError("anahtar/certificate dosyası bulunamadı")
    data = path.read_bytes()
    if not data:
        raise ValueError("anahtar/certificate dosyası boş")

    # Private key first. Encrypted private keys are detected but no passphrase is requested.
    for loader in (serialization.load_pem_private_key, serialization.load_der_private_key):
        try:
            private_key = loader(data, password=None)
            return "private_key", private_key.public_key(), None
        except TypeError as exc:
            msg = str(exc).lower()
            if "password" in msg and "encrypted" in msg:
                raise ValueError(
                    "private key şifreli; bu preflight passphrase istemez veya kaydetmez. "
                    "Public key/certificate ile kontrol yapın."
                ) from None
        except (ValueError, UnsupportedAlgorithmError):
            pass

    for loader, label, encoding in (
        (serialization.load_pem_public_key, "public_key", serialization.Encoding.PEM),
        (serialization.load_der_public_key, "public_key", serialization.Encoding.DER),
    ):
        try:
            pub = loader(data)
            original_der = None
            if encoding == serialization.Encoding.DER:
                original_der = data
            return label, pub, original_der
        except (ValueError, UnsupportedAlgorithmError):
            pass

    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            cert = loader(data)
            return "certificate", cert.public_key(), None
        except ValueError:
            pass

    raise ValueError("dosya desteklenen PEM/DER private key, public key veya X.509 certificate olarak okunamadı")


# cryptography exposes UnsupportedAlgorithm under exceptions; import late-compatible alias.
try:
    from cryptography.exceptions import UnsupportedAlgorithm as UnsupportedAlgorithmError
except Exception:  # pragma: no cover
    UnsupportedAlgorithmError = ValueError


def _purpose_requirement(purpose: str) -> dict[str, Any]:
    if purpose == "application":
        return {
            "source_scope": "TISCI 12.00.02 System Firmware authentication",
            "rsa_bits_required": 4096,
            "rule": "TISCI authentication flow currently supports RSA-4K signatures.",
        }
    if purpose == "debug":
        return {
            "source_scope": "TISCI 12.00.02 Secure Debug/System Firmware",
            "rsa_bits_required": 4096,
            "rule": "Secure Debug certificate System Firmware tarafından doğrulanır; active SMPK/BMPK bağlamı RSA-4K olarak kontrol edilir.",
        }
    if purpose == "keywriter":
        return {
            "source_scope": "TISCI 12.00.02 Key Writer",
            "rsa_bits_required": 4096,
            "rule": "Bu Key Writer sürümü SMPK/BMPK için yalnız 4096-bit RSA destekler.",
        }
    if purpose == "rom":
        return {
            "source_scope": "AM64x ROM combined-image signing",
            "rsa_bits_required": None,
            "rule": "Toolkit ROM signer için key-size gereksinimini bu preflight'ta genellemez; exact ROM/SDK akışı ayrıca doğrulanmalıdır.",
        }
    return {
        "source_scope": "generic local key inspection",
        "rsa_bits_required": None,
        "rule": "Yalnız local key yapısı raporlanır; target uyumluluğu çıkarımı yapılmaz.",
    }


def preflight_signing_key(path: Path, *, purpose: str = "application", public_der_output: Path | None = None) -> dict[str, Any]:
    input_class, pub, _ = _load_key_material(path)
    info = _public_info(pub)
    requirement = _purpose_requirement(purpose)

    checks: list[dict[str, Any]] = []
    checks.append({"check": "key_parse", "status": "PASS", "detail": f"{input_class} olarak okundu"})
    if info["rsa"]:
        checks.append({"check": "rsa_key", "status": "PASS", "detail": f"RSA-{info['rsa_bits']}"})
    else:
        checks.append({"check": "rsa_key", "status": "FAIL", "detail": "RSA key değil"})

    required_bits = requirement["rsa_bits_required"]
    if required_bits is None:
        checks.append({
            "check": "target_key_size",
            "status": "NOT_CHECKED",
            "detail": requirement["rule"],
        })
    elif info["rsa"] and info["rsa_bits"] == required_bits:
        checks.append({"check": "target_key_size", "status": "PASS", "detail": f"RSA-{required_bits}"})
    else:
        checks.append({"check": "target_key_size", "status": "FAIL", "detail": f"RSA-{required_bits} gerekli"})

    if info["rsa"]:
        checks.append({
            "check": "public_exponent",
            "status": "INFO",
            "detail": f"gözlenen exponent={info['public_exponent']}; toolkit bu özellik için target kabul/reddet kuralı uygulamaz",
        })

    public_out = None
    if public_der_output is not None:
        if public_der_output.exists():
            raise FileExistsError("public DER çıktı dosyası zaten mevcut")
        public_der_output.parent.mkdir(parents=True, exist_ok=True)
        public_der_output.write_bytes(
            pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        public_out = str(public_der_output)

    hard_fail = any(c["status"] == "FAIL" for c in checks)
    partial = any(c["status"] == "NOT_CHECKED" for c in checks)
    status = "FAIL" if hard_fail else ("PARTIAL" if partial else "PASS")

    return {
        "status": status,
        "operation": "signing_key_preflight",
        "purpose": purpose,
        "input_class": input_class,
        "key": info,
        "target_requirement": requirement,
        "checks": checks,
        "public_der_output": public_out,
        "secret_material_recorded": False,
        "secret_path_recorded": False,
        "note": "DER-SPKI SHA-256 public fingerprint'tir; SMPKH/BMPKH provisioning hash'i değildir.",
    }


def preflight_mek(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError("MEK dosyası bulunamadı")
    data = path.read_bytes()
    if not data:
        raise ValueError("MEK dosyası boş")

    checks: list[dict[str, Any]] = []
    try:
        text = data.decode("ascii")
        checks.append({"check": "ascii_text", "status": "PASS"})
    except UnicodeDecodeError:
        text = ""
        checks.append({"check": "ascii_text", "status": "FAIL", "detail": "raw hexadecimal text olarak okunamadı"})

    raw_char_count = len(text)
    outer_ws = len(text) - len(text.strip()) if text else 0
    trimmed = text.strip()
    trimmed_is_hex = bool(trimmed) and all(ch in _HEX for ch in trimmed)
    exact_raw_64_hex = len(text) == 64 and all(ch in _HEX for ch in text)
    trimmed_64_hex = len(trimmed) == 64 and trimmed_is_hex

    if trimmed_is_hex:
        checks.append({"check": "hexadecimal", "status": "PASS"})
    else:
        checks.append({"check": "hexadecimal", "status": "FAIL", "detail": "yalnız hexadecimal karakterler beklenir"})

    if len(trimmed) == 64:
        checks.append({"check": "aes256_length", "status": "PASS", "detail": "64 hex karakter = 256 bit"})
    else:
        checks.append({
            "check": "aes256_length",
            "status": "FAIL",
            "detail": f"64 hex karakter gerekli; gözlenen trimmed uzunluk={len(trimmed)}",
        })

    if exact_raw_64_hex:
        checks.append({
            "check": "sdk_file_text_safety",
            "status": "PASS",
            "detail": "dosya tam 64 hexadecimal karakter içeriyor; ek whitespace yok",
        })
    elif trimmed_64_hex and outer_ws:
        checks.append({
            "check": "sdk_file_text_safety",
            "status": "WARN",
            "detail": "64 hex karakter çevresinde whitespace var. Kurulu SDK signer text'i OpenSSL -K'ya doğrudan ilettiği için temiz dosya tercih edilir.",
        })
    else:
        checks.append({
            "check": "sdk_file_text_safety",
            "status": "FAIL",
            "detail": "kurulu SDK/OpenSSL zinciri için güvenli strict format sağlanmıyor",
        })

    hard_fail = any(c["status"] == "FAIL" for c in checks)
    warn = any(c["status"] == "WARN" for c in checks)
    status = "FAIL" if hard_fail else ("PARTIAL" if warn else "PASS")

    return {
        "status": status,
        "operation": "mek_format_preflight",
        "format": "raw_hex_text",
        "raw_character_count": raw_char_count,
        "trimmed_character_count": len(trimmed),
        "outer_whitespace_characters": outer_ws,
        "key_bits_if_valid": 256 if trimmed_64_hex else None,
        "checks": checks,
        "secret_material_recorded": False,
        "secret_path_recorded": False,
        "secret_hash_recorded": False,
        "note": "MEK değeri veya hash'i çıktıya yazılmaz. Installed OpenSSL 3.5.6, 63/65 hex girdilerini warning ile kabul ettiği için toolkit 64-hex formatı ayrıca kontrol eder.",
    }


def compare_key_material(private_key_path: Path, public_or_cert_path: Path) -> dict[str, Any]:
    private_class, private_pub, _ = _load_key_material(private_key_path)
    if private_class != "private_key":
        raise ValueError("ilk girdi private key olmalıdır")
    reference_class, reference_pub, _ = _load_key_material(public_or_cert_path)

    a = _public_info(private_pub)
    b = _public_info(reference_pub)
    if not a["rsa"] or not b["rsa"]:
        status = "FAIL"
        match = False
    else:
        match = a["der_spki_sha256"] == b["der_spki_sha256"]
        status = "PASS" if match else "FAIL"

    return {
        "status": status,
        "operation": "key_pair_compare",
        "reference_input_class": reference_class,
        "private_key_public_spki_sha256": a["der_spki_sha256"],
        "reference_public_spki_sha256": b["der_spki_sha256"],
        "match": match,
        "secret_material_recorded": False,
        "secret_path_recorded": False,
        "note": "Karşılaştırma yalnız public DER-SPKI fingerprint üzerinden yapılır; private key içeriği veya hash'i raporlanmaz.",
    }
