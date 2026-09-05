"""HS-FS -> HS-SE için yalnız offline provisioning hazırlık kontrolleri."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .keycheck import preflight_mek


PROFILE_TYPE = "hsfs_to_hsse_preflight"


def template_provision_profile() -> dict[str, Any]:
    """Secret içermeyen doldurulabilir provisioning preflight profile döndürür."""
    return {
        "type": PROFILE_TYPE,
        "mode": "offline_only",
        "key_count": None,
        "key_revision": None,
        "smpk_public_der": "<SMPK_PUBLIC_DER_PATH>",
        "bmpk_public_der": None,
        "swrev": {
            "sysfw": None,
            "sbl": None,
            "boardcfg": None,
        },
        "notes": (
            "Bu dosyaya private key, SMEK/BMEK değeri veya secret path yazılmaz. "
            "Araç OTP Keywriter çalıştırmaz ve eFuse programlamaz."
        ),
    }


def save_provision_profile(profile: dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    if p.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(profile, sort_keys=False, allow_unicode=True), encoding="utf-8")


def load_provision_profile(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("profile dosyasının en üst seviyesi YAML mapping olmalıdır")
    return raw


def _parse_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field}: boolean değer kabul edilmez")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        text = value.strip()
        if not text or (text.startswith("<") and text.endswith(">")):
            raise ValueError(f"{field}: değer henüz doldurulmamış")
        n = int(text, 0)
    else:
        raise ValueError(f"{field}: integer değer gerekli")
    if not minimum <= n <= maximum:
        raise ValueError(f"{field}: beklenen aralık {minimum}..{maximum}, verilen {n}")
    return n


def _require_public_der(value: Any, field: str) -> Path:
    if value is None:
        raise ValueError(f"{field}: DER public key gerekli")
    text = str(value).strip()
    if not text or text.startswith("<"):
        raise ValueError(f"{field}: DER public key yolu henüz doldurulmamış")
    p = Path(text).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"{field}: DER public key dosyası bulunamadı")
    return p


def _public_der_info(path: Path, role: str) -> dict[str, Any]:
    data = path.read_bytes()
    try:
        pub = serialization.load_der_public_key(data)
    except Exception as exc:
        raise ValueError(f"{role}: dosya geçerli DER public key olarak okunamadı") from exc
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError(f"{role}: TISCI 12.00.02 Key Writer için RSA public key gerekli")
    return {
        "role": role,
        "file_name": path.name,
        "rsa_bits": pub.key_size,
        # TISCI Key Writer provisioning hash'i, verilen DER public-key byte'larının SHA2-512'sidir.
        "provisioning_sha512": hashlib.sha512(data).hexdigest(),
        "der_bytes": len(data),
    }


def _add(checks: list[dict[str, Any]], name: str, status: str, detail: str) -> None:
    checks.append({"check": name, "status": status, "detail": detail})


def _validate_optional_swrev(swrev: Any, checks: list[dict[str, Any]]) -> dict[str, Any]:
    if swrev is None:
        swrev = {}
    if not isinstance(swrev, dict):
        _add(checks, "swrev_structure", "FAIL", "swrev YAML mapping olmalıdır")
        return {}

    out: dict[str, Any] = {}
    limits = {
        "sysfw": (1 << 48) - 1,
        "sbl": (1 << 48) - 1,
        "boardcfg": (1 << 64) - 1,
    }
    for field in ("sysfw", "sbl", "boardcfg"):
        value = swrev.get(field)
        if value is None:
            out[field] = None
            _add(
                checks,
                f"swrev_{field}",
                "NOT_CHECKED",
                "Bu SWREV alanı profile'da programlanmak üzere seçilmedi.",
            )
            continue
        try:
            # Key Writer, SWREV kullanımını optional tanımlar; kullanılıyorsa başlangıç non-zero olmalıdır.
            n = _parse_int(value, f"swrev.{field}", 1, limits[field])
            out[field] = n
            _add(
                checks,
                f"swrev_{field}",
                "PASS",
                f"Non-zero revision değeri alanın tek-kopya genişliğiyle uyumlu; eFuse double-redundancy encoding'i bu araç tarafından üretilmez.",
            )
        except Exception as exc:
            out[field] = None
            _add(checks, f"swrev_{field}", "FAIL", str(exc))
    return out


def _mek_check(path: Path | None, label: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    if path is None:
        _add(
            checks,
            f"{label.lower()}_format",
            "NOT_CHECKED",
            f"{label} local secret dosyası verilmedi; değer/profile/report içine alınmadı.",
        )
        return {"status": "NOT_CHECKED"}
    try:
        result = preflight_mek(path)
    except Exception:
        _add(checks, f"{label.lower()}_format", "FAIL", f"{label} local dosyası okunamadı veya geçersiz")
        return {"status": "FAIL"}

    status = result.get("status", "FAIL")
    mapped = "WARN" if status == "PARTIAL" else status
    _add(
        checks,
        f"{label.lower()}_format",
        mapped,
        "AES-256 raw-hex format kontrolü yapıldı; secret değer, path ve hash raporlanmadı.",
    )
    return {
        "status": status,
        "format": result.get("format"),
        "key_bits_if_valid": result.get("key_bits_if_valid"),
        "secret_material_recorded": False,
        "secret_path_recorded": False,
        "secret_hash_recorded": False,
    }


def provision_preflight(
    profile_path: str | Path,
    *,
    smek: Path | None = None,
    bmek: Path | None = None,
    report: Path | None = None,
) -> dict[str, Any]:
    """Provisioning girdilerini offline kontrol eder; hiçbir target işlemi yapmaz."""
    profile = load_provision_profile(profile_path)
    checks: list[dict[str, Any]] = []

    if profile.get("type") != PROFILE_TYPE:
        _add(checks, "profile_type", "FAIL", f"type={PROFILE_TYPE} olmalıdır")
    else:
        _add(checks, "profile_type", "PASS", PROFILE_TYPE)

    if profile.get("mode") != "offline_only":
        _add(checks, "mode", "FAIL", "Provisioning preflight yalnız offline_only modunda çalışır")
    else:
        _add(checks, "mode", "PASS", "offline_only")

    key_count: int | None = None
    key_revision: int | None = None
    try:
        key_count = _parse_int(profile.get("key_count"), "key_count", 1, 2)
        _add(
            checks,
            "key_count",
            "PASS",
            "1=SMPK seti, 2=SMPK+BMPK setleri; HS-FS->HS-SE hedefi için customer root-key seti seçildi.",
        )
    except Exception as exc:
        _add(checks, "key_count", "FAIL", str(exc))

    try:
        key_revision = _parse_int(profile.get("key_revision"), "key_revision", 1, 2)
        if key_count is not None and key_revision > key_count:
            raise ValueError("key_revision: key_count değerinden büyük olamaz")
        if key_count == 1 and key_revision != 1:
            raise ValueError("key_count=1 için geçerli key_revision değeri 1'dir")
        _add(
            checks,
            "key_revision",
            "PASS",
            "KEYREV=1 SMPK/SMEK, KEYREV=2 BMPK/BMEK active-key context'ini seçer.",
        )
    except Exception as exc:
        _add(checks, "key_revision", "FAIL", str(exc))

    public_info: dict[str, Any] = {}

    # SMPK, her HS-FS -> HS-SE profile'ında ana customer signing setidir.
    try:
        smpk_path = _require_public_der(profile.get("smpk_public_der"), "smpk_public_der")
        info = _public_der_info(smpk_path, "SMPK")
        public_info["smpk"] = info
        if info["rsa_bits"] != 4096:
            _add(checks, "smpk_rsa4096", "FAIL", f"SMPK {info['rsa_bits']}-bit; bu Key Writer sürümü 4096-bit RSA destekler")
        else:
            _add(checks, "smpk_rsa4096", "PASS", "SMPK public DER RSA-4096")
        _add(checks, "smpkh_sha512", "PASS", "SMPKH adayı exact DER public-key byte'ları üzerinden SHA2-512 ile hesaplandı")
    except Exception as exc:
        _add(checks, "smpk_public_der", "FAIL", str(exc))

    bmpk_value = profile.get("bmpk_public_der")
    if key_count == 2:
        try:
            bmpk_path = _require_public_der(bmpk_value, "bmpk_public_der")
            info = _public_der_info(bmpk_path, "BMPK")
            public_info["bmpk"] = info
            if info["rsa_bits"] != 4096:
                _add(checks, "bmpk_rsa4096", "FAIL", f"BMPK {info['rsa_bits']}-bit; bu Key Writer sürümü 4096-bit RSA destekler")
            else:
                _add(checks, "bmpk_rsa4096", "PASS", "BMPK public DER RSA-4096")
            _add(checks, "bmpkh_sha512", "PASS", "BMPKH adayı exact DER public-key byte'ları üzerinden SHA2-512 ile hesaplandı")
        except Exception as exc:
            _add(checks, "bmpk_public_der", "FAIL", str(exc))
    elif key_count == 1:
        if bmpk_value not in (None, "", "null"):
            _add(checks, "bmpk_key_count_consistency", "FAIL", "key_count=1 iken BMPK public DER tanımlanmamalıdır")
        else:
            _add(checks, "bmpk_key_count_consistency", "PASS", "key_count=1: backup BMPK seti yok")

    if "smpk" in public_info and "bmpk" in public_info:
        if public_info["smpk"]["provisioning_sha512"] == public_info["bmpk"]["provisioning_sha512"]:
            _add(checks, "primary_backup_distinct", "WARN", "SMPK ve BMPK public DER hash'leri aynı; bu durum backup ayrımı açısından ayrıca gözden geçirilmelidir")
        else:
            _add(checks, "primary_backup_distinct", "PASS", "SMPK ve BMPK public DER hash'leri farklı")

    swrev = _validate_optional_swrev(profile.get("swrev"), checks)

    if key_count == 1 and bmek is not None:
        _add(checks, "bmek_key_count_consistency", "FAIL", "key_count=1 profile ile BMEK local preflight girdisi birlikte kullanılamaz")
        bmek_result = {"status": "FAIL"}
    else:
        bmek_result = _mek_check(bmek, "BMEK", checks)
    smek_result = _mek_check(smek, "SMEK", checks)

    _add(
        checks,
        "ti_fek_keywriter_package_match",
        "NOT_CHECKED",
        "TISCI, TI FEK ile Keywriter firmware'in aynı Keywriter package'ından olmasını ister; bu eşleşme için package girdisi verilmedi.",
    )

    fail = any(c["status"] == "FAIL" for c in checks)
    warn = any(c["status"] == "WARN" for c in checks)
    status = "FAIL" if fail else ("PARTIAL" if warn else "PASS")

    active_context = None
    if key_revision == 1:
        active_context = "SMPK/SMEK"
    elif key_revision == 2:
        active_context = "BMPK/BMEK"

    result: dict[str, Any] = {
        "status": status,
        "operation": "hsfs_to_hsse_offline_preflight",
        "key_count": key_count,
        "key_revision": key_revision,
        "active_key_context": active_context,
        "public_key_material": public_info,
        "swrev": swrev,
        "secret_format_checks": {
            "smek": smek_result,
            "bmek": bmek_result,
        },
        "checks": checks,
        "execution": {
            "otp_keywriter": "DISABLED",
            "efuse_programming": "DISABLED",
            "hsfs_to_hsse_transition": "NOT_EXECUTED",
            "keyrev_write": "NOT_EXECUTED",
            "swrev_write": "NOT_EXECUTED",
        },
        "provisioning_execution_ready": "NOT_DECLARED",
        "secret_material_recorded": False,
        "secret_path_recorded": False,
        "secret_hash_recorded": False,
        "note": (
            "PASS yalnız bu offline profile ve verilen host-side girdilerin tutarlı olduğunu gösterir. "
            "OTP/eFuse programlama, HS-SE transition veya customer Root of Trust enforcement sonucu değildir."
        ),
    }

    if report is not None:
        rp = Path(report)
        if rp.exists():
            raise FileExistsError(f"rapor zaten mevcut: {rp}")
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result = dict(result)
        result["report"] = str(rp)

    return result
