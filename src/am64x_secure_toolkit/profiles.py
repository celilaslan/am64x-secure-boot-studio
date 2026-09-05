"""Certificate profile şablonları ve girdi doğrulama yardımcıları."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


PROFILE_TYPES = {"application", "debug", "rom", "keywriter_preflight"}


def template_profile(kind: str) -> dict[str, Any]:
    """Doldurulabilir, secret içermeyen örnek profile döndürür."""
    aliases = {"application": "app", "keywriter_preflight": "keywriter"}
    kind = aliases.get(kind, kind)
    if kind == "app":
        return {
            "type": "application",
            "subject": {
                "common_name": "AM64x Secure Application",
                "organization": "<COMPANY_OR_PROJECT_NAME>",
            },
            "input": "<PAYLOAD_PATH>",
            "software_revision": 1,
            "load": {
                "dest_addr": "<SOURCE_VERIFIED_VALUE>",
                "auth_mode": 1,
                "copy_as_host": 0,
            },
            "boot": {
                "enabled": False,
                "boot_core": None,
                "config_flags_set": 0,
                "config_flags_clr": 0,
                "reset_vector": None,
                "field_valid": 0,
            },
            "valid_days": 3650,
        }
    if kind == "debug":
        return {
            "type": "debug",
            "subject": {
                "common_name": "AM64x Secure Debug Certificate",
                "organization": "<COMPANY_OR_PROJECT_NAME>",
            },
            "software_revision": 1,
            "debug": {
                "soc_uid": "<64_HEX_SOC_UID>",
                "wildcard_uid": False,
                "privilege": 0,
                "reserved": 0,
                "nonsecure_core_ids": [255],
                "secure_core_ids": [255],
            },
            "valid_days": 3650,
        }
    if kind == "rom":
        return {
            "type": "rom",
            "tool": "<SDK>/source/security/security_common/tools/boot/signing/rom_image_gen.py",
            "software_revision": 1,
            "sbl_bin": "<SBL_BIN>",
            "sysfw_bin": "<SYSFW_BIN>",
            "sysfw_inner_cert": "<SYSFW_INNER_CERT_OR_NULL>",
            "boardcfg_blob": "<BOARDCFG_BLOB>",
            "sbl_loadaddr": "<SOURCE_VERIFIED_VALUE>",
            "sysfw_loadaddr": "<SOURCE_VERIFIED_VALUE>",
            "bcfg_loadaddr": "<SOURCE_VERIFIED_VALUE>",
        }
    if kind == "keywriter":
        return {
            "type": "keywriter_preflight",
            "mode": "offline_only",
            "key_count": None,
            "key_revision": None,
            "smpk_public_der": None,
            "bmpk_public_der": None,
            "notes": "Bu profile private key, SMEK veya BMEK değeri yazılmaz; OTP/eFuse işlemi çalıştırılmaz.",
        }
    raise ValueError(f"bilinmeyen certificate profile türü: {kind}")


def save_profile(profile: dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    if p.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(profile, sort_keys=False, allow_unicode=True), encoding="utf-8")


def load_profile(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
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
        hi = f"..{maximum}" if maximum is not None else " veya daha büyük"
        raise ValueError(f"{field}: beklenen aralık {minimum}{hi}, verilen {n}")
    return n


def _parse_hex(value: Any, field: str, byte_length: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field}: hexadecimal metin gerekli")
    text = value.strip().lower()
    if text.startswith("<") and text.endswith(">"):
        raise ValueError(f"{field}: örnek değer henüz doldurulmamış")
    if text.startswith("0x"):
        text = text[2:]
    if len(text) != byte_length * 2:
        raise ValueError(f"{field}: tam {byte_length} byte ({byte_length * 2} hex karakter) gerekli")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{field}: geçersiz hexadecimal değer") from exc


def _require_file(value: Any, field: str) -> Path:
    if value is None:
        raise ValueError(f"{field}: dosya yolu gerekli")
    text = str(value)
    if text.startswith("<"):
        raise ValueError(f"{field}: örnek dosya yolu henüz doldurulmamış")
    p = Path(text).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"{field}: dosya bulunamadı: {p}")
    return p


def _validate_subject(profile: dict[str, Any], issues: list[str]) -> dict[str, str]:
    subject = profile.get("subject") or {}
    if not isinstance(subject, dict):
        issues.append("subject: YAML mapping olmalıdır")
        return {}
    cn = str(subject.get("common_name", "")).strip()
    if not cn or (cn.startswith("<") and cn.endswith(">")):
        issues.append("subject.common_name: doldurulmuş bir değer gerekli")
    out: dict[str, str] = {}
    allowed = {"country", "state", "locality", "organization", "organizational_unit", "common_name", "email"}
    for key, value in subject.items():
        if key not in allowed:
            issues.append(f"subject.{key}: desteklenmeyen Subject alanı")
            continue
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        if text.startswith("<") and text.endswith(">"):
            issues.append(f"subject.{key}: örnek değer henüz doldurulmamış")
            continue
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
            issues.append(f"subject.{key}: control/newline karakteri kabul edilmez")
            continue
        if len(text) > 512:
            issues.append(f"subject.{key}: 512 karakterden uzun değer kabul edilmez")
            continue
        if key == "country":
            if len(text) != 2 or not text.isascii() or not text.isalpha():
                issues.append("subject.country: X.509 Country (C) alanı iki ASCII harf olmalıdır")
                continue
            text = text.upper()
        if key == "email":
            if not text.isascii() or "@" not in text or any(ch.isspace() for ch in text) or len(text) > 254:
                issues.append("subject.email: geçerli ASCII email biçimi gerekli")
                continue
        out[key] = text
    return out


def _validate_core_ids(values: Any, field: str, issues: list[str]) -> list[int]:
    if not isinstance(values, list) or not values:
        issues.append(f"{field}: boş olmayan liste gerekli; hiçbir core seçilmeyecekse [255] kullanılır")
        return []
    out: list[int] = []
    for i, value in enumerate(values):
        try:
            out.append(_parse_int(value, f"{field}[{i}]", minimum=0, maximum=255))
        except Exception as exc:
            issues.append(str(exc))
    if 255 in out and len(out) != 1:
        issues.append(f"{field}: 0xFF no-core işaretidir; başka processor ID ile birlikte kullanılamaz")
    return out


def _rsa4096_public_der_info(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    pub = serialization.load_der_public_key(data)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError(f"{path}: DER public key RSA değil")
    return {
        "path": str(path),
        "rsa_bits": pub.key_size,
        "sha512": hashlib.sha512(data).hexdigest(),
        "target_compatible_rsa4096": pub.key_size == 4096,
    }


def validate_profile(profile: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    warnings: list[str] = []
    normalized: dict[str, Any] = {}
    ptype = profile.get("type")
    if ptype not in PROFILE_TYPES:
        return {
            "status": "FAIL",
            "issues": [f"type: şu değerlerden biri olmalı: {sorted(PROFILE_TYPES)}"],
            "warnings": [],
            "normalized": {},
        }
    normalized["type"] = ptype

    if ptype in {"application", "debug"}:
        normalized["subject"] = _validate_subject(profile, issues)
        try:
            normalized["software_revision"] = _parse_int(profile.get("software_revision"), "software_revision", minimum=0, maximum=0xFFFFFFFF)
        except Exception as exc:
            issues.append(str(exc))
        try:
            normalized["valid_days"] = _parse_int(profile.get("valid_days", 3650), "valid_days", minimum=1, maximum=36500)
        except Exception as exc:
            issues.append(str(exc))

    if ptype == "application":
        if normalized.get("software_revision") == 0:
            warnings.append("TISCI Authentication and Decryption guide, authenticated binary için software revision değerinde önerilen minimum olarak 1 verir.")
        try:
            input_path = _require_file(profile.get("input"), "input")
            normalized["input"] = str(input_path)
            payload = input_path.read_bytes()
            normalized["payload_size"] = len(payload)
            normalized["payload_sha512"] = hashlib.sha512(payload).hexdigest()
        except Exception as exc:
            issues.append(str(exc))

        load = profile.get("load") or {}
        if not isinstance(load, dict):
            issues.append("load: YAML mapping olmalıdır")
            load = {}
        try:
            normalized["load_dest_addr"] = _parse_int(load.get("dest_addr"), "load.dest_addr", minimum=0, maximum=0xFFFFFFFFFFFFFFFF)
        except Exception as exc:
            issues.append(str(exc))
        try:
            normalized["load_auth_mode"] = _parse_int(load.get("auth_mode"), "load.auth_mode", minimum=0, maximum=2)
        except Exception as exc:
            issues.append(str(exc))
        try:
            normalized["load_copy_as_host"] = _parse_int(load.get("copy_as_host", 0), "load.copy_as_host", minimum=0, maximum=255)
        except Exception as exc:
            issues.append(str(exc))

        boot = profile.get("boot") or {"enabled": False}
        if not isinstance(boot, dict):
            issues.append("boot: YAML mapping olmalıdır")
            boot = {"enabled": False}
        enabled = bool(boot.get("enabled", False))
        normalized["boot_enabled"] = enabled
        if enabled:
            for key, maximum in [
                ("boot_core", 0xFFFFFFFF),
                ("config_flags_set", 0xFFFFFFFF),
                ("config_flags_clr", 0xFFFFFFFF),
                ("field_valid", 0xFFFFFFFF),
            ]:
                try:
                    normalized[f"boot_{key}"] = _parse_int(boot.get(key), f"boot.{key}", minimum=0, maximum=maximum)
                except Exception as exc:
                    issues.append(str(exc))
            try:
                normalized["boot_reset_vector"] = _parse_int(boot.get("reset_vector"), "boot.reset_vector", minimum=0, maximum=0xFFFFFFFFFFFFFFFF)
            except Exception as exc:
                issues.append(str(exc))
            warnings.append("Boot Extension içindeki processor ID, flag ve reset vector değerleri toolkit tarafından tahmin edilmez; exact SoC/API kaynağından alınmalıdır.")

    elif ptype == "debug":
        debug = profile.get("debug") or {}
        if not isinstance(debug, dict):
            issues.append("debug: YAML mapping olmalıdır")
            debug = {}
        try:
            uid = _parse_hex(debug.get("soc_uid"), "debug.soc_uid", 32)
            normalized["debug_soc_uid_hex"] = uid.hex()
            wildcard = bool(debug.get("wildcard_uid", False))
            normalized["debug_wildcard_uid"] = wildcard
            if uid == bytes(32) and not wildcard:
                issues.append("debug.soc_uid: all-zero UID yalnız debug.wildcard_uid=true ile kullanılabilir")
            if wildcard:
                warnings.append("Wildcard UID ancak target Security Board Configuration buna izin veriyorsa anlamlıdır; toolkit target BoardCfg politikasını burada doğrulamaz.")
        except Exception as exc:
            issues.append(str(exc))
        try:
            normalized["debug_privilege"] = _parse_int(debug.get("privilege"), "debug.privilege", minimum=0, maximum=5)
        except Exception as exc:
            issues.append(str(exc))
        try:
            reserved = _parse_int(debug.get("reserved", 0), "debug.reserved", minimum=0, maximum=0xFFFF)
            normalized["debug_reserved"] = reserved
            if reserved != 0:
                issues.append("debug.reserved: reserved 16-bit alan sıfır olmalıdır")
        except Exception as exc:
            issues.append(str(exc))
        normalized["debug_nonsecure_core_ids"] = _validate_core_ids(debug.get("nonsecure_core_ids"), "debug.nonsecure_core_ids", issues)
        normalized["debug_secure_core_ids"] = _validate_core_ids(debug.get("secure_core_ids"), "debug.secure_core_ids", issues)
        warnings.append("Certificate oluşturmak JTAG açma işlemi değildir; target UID, active customer key ve BoardCfg izinleri ayrıca target üzerinde değerlendirilir.")

    elif ptype == "rom":
        for field in ["tool", "sbl_bin", "sysfw_bin", "boardcfg_blob"]:
            try:
                normalized[field] = str(_require_file(profile.get(field), field))
            except Exception as exc:
                issues.append(str(exc))
        inner = profile.get("sysfw_inner_cert")
        if inner not in {None, "", "null"}:
            if isinstance(inner, str) and inner.startswith("<"):
                issues.append("sysfw_inner_cert: HS image kullanılacaksa exact dosya yolu girilmeli; kullanılmayacaksa null yapılmalı")
            else:
                try:
                    normalized["sysfw_inner_cert"] = str(_require_file(inner, "sysfw_inner_cert"))
                except Exception as exc:
                    issues.append(str(exc))
        for field in ["sbl_loadaddr", "sysfw_loadaddr", "bcfg_loadaddr"]:
            try:
                normalized[field] = _parse_int(profile.get(field), field, minimum=0, maximum=0xFFFFFFFFFFFFFFFF)
            except Exception as exc:
                issues.append(str(exc))
        try:
            normalized["software_revision"] = _parse_int(profile.get("software_revision"), "software_revision", minimum=0, maximum=0xFFFFFFFF)
        except Exception as exc:
            issues.append(str(exc))
        warnings.append("ROM combined certificate/image üretimi kurulu rom_image_gen.py üzerinden yapılır; certificate yapısı burada yeniden uygulanmaz.")

    elif ptype == "keywriter_preflight":
        if profile.get("mode") != "offline_only":
            issues.append("mode: Keywriter profile yalnız offline_only olabilir")
        try:
            key_count = _parse_int(profile.get("key_count"), "key_count", minimum=0, maximum=2)
            normalized["key_count"] = key_count
        except Exception as exc:
            issues.append(str(exc))
            key_count = None

        raw_key_revision = profile.get("key_revision")
        key_revision = None
        if key_count == 0:
            if raw_key_revision is not None:
                issues.append("key_count=0 için numeric KEYREV uydurulmaz; key_revision null bırakılmalıdır")
            normalized["key_revision"] = None
        else:
            try:
                key_revision = _parse_int(raw_key_revision, "key_revision", minimum=1, maximum=2)
                normalized["key_revision"] = key_revision
                if key_count is not None and key_revision > key_count:
                    issues.append("key_revision: key_count değerinden büyük olamaz")
                if key_count == 1 and key_revision != 1:
                    issues.append("key_count=1 için geçerli key_revision değeri 1'dir")
            except Exception as exc:
                issues.append(str(exc))

        pub_info: dict[str, Any] = {}
        smpk_val = profile.get("smpk_public_der")
        bmpk_val = profile.get("bmpk_public_der")

        if key_count in {1, 2}:
            if not smpk_val:
                issues.append("smpk_public_der: key_count 1 veya 2 için SMPK public DER gerekli")
            else:
                try:
                    p = _require_file(smpk_val, "smpk_public_der")
                    info = _rsa4096_public_der_info(p)
                    pub_info["smpk_public_der"] = info
                    if not info["target_compatible_rsa4096"]:
                        issues.append("smpk_public_der: TISCI 12.00.02 Key Writer SMPK için 4096-bit RSA destekler")
                except Exception as exc:
                    issues.append(str(exc))
        elif key_count == 0 and smpk_val:
            issues.append("key_count=0 iken smpk_public_der tanımlanmamalıdır")

        if key_count == 2:
            if not bmpk_val:
                issues.append("bmpk_public_der: key_count=2 için BMPK public DER gerekli")
            else:
                try:
                    p = _require_file(bmpk_val, "bmpk_public_der")
                    info = _rsa4096_public_der_info(p)
                    pub_info["bmpk_public_der"] = info
                    if not info["target_compatible_rsa4096"]:
                        issues.append("bmpk_public_der: TISCI 12.00.02 Key Writer BMPK için 4096-bit RSA destekler")
                except Exception as exc:
                    issues.append(str(exc))
        elif key_count in {0, 1} and bmpk_val:
            issues.append(f"key_count={key_count} iken bmpk_public_der tanımlanmamalıdır")

        normalized["public_key_info"] = pub_info
        warnings.append("Bu profile private key, SMEK veya BMEK değeri kabul etmez ve OTP Keywriter/eFuse programlama çalıştırmaz.")

    return {
        "status": "PASS" if not issues else "FAIL",
        "issues": issues,
        "warnings": warnings,
        "normalized": normalized,
    }


def validate_profile_file(path: str | Path) -> dict[str, Any]:
    result = validate_profile(load_profile(path))
    result["profile"] = Path(path).name
    return result
