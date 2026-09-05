"""Security Board Configuration için offline policy ve tutarlılık kontrolleri."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .inspect import inspect_artifact


PROFILE_TYPE = "security_boardcfg_policy"
SECDBG_MAGIC = 0x42AF
OTP_MAGIC = 0x4081
ENABLE_MAGIC = 0x5A
WILDCARD_HOST_ID = 128


def template_boardcfg_profile() -> dict[str, Any]:
    """Doldurulabilir Security BoardCfg policy profile döndürür."""
    return {
        "type": PROFILE_TYPE,
        "secure_debug": {
            "subhdr_magic": "0x42AF",
            "allow_jtag_unlock": 0,
            "allow_wildcard_unlock": 0,
            "allow_debug_level_rsvd": 0,
            "rsvd": 0,
            "min_cert_rev": 0,
            "jtag_unlock_hosts": [0, 0, 0, 0],
        },
        "extended_otp": {
            "subhdr_magic": "0x4081",
            "write_host": None,
        },
        "notes": (
            "Bu profile yalnız Security Board Configuration policy alanlarını temsil eder. "
            "Toolkit target'a BoardCfg göndermez, debug açmaz ve revision yazma çağrısı yapmaz."
        ),
    }


def save_boardcfg_profile(profile: dict[str, Any], path: str | Path) -> None:
    p = Path(path)
    if p.exists():
        raise FileExistsError(f"çıktı zaten mevcut: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(profile, sort_keys=False, allow_unicode=True), encoding="utf-8")


def load_boardcfg_profile(path: str | Path) -> dict[str, Any]:
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


def _add(checks: list[dict[str, Any]], name: str, status: str, detail: str) -> None:
    checks.append({"check": name, "status": status, "detail": detail})


def _parse_flag(value: Any, field: str) -> int:
    n = _parse_int(value, field, 0, 0xFF)
    if n not in {0, ENABLE_MAGIC}:
        raise ValueError(f"{field}: yalnız 0 veya 0x5A kabul edilir")
    return n


def _normalize_uid(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().lower().replace("0x", "").replace(":", "").replace(" ", "")
    if len(text) != 64:
        raise ValueError("SOC UID 256 bit olmalıdır: 64 hexadecimal karakter")
    try:
        bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("SOC UID hexadecimal biçimde olmalıdır") from exc
    return text


def check_boardcfg_profile(profile_or_path: dict[str, Any] | str | Path) -> dict[str, Any]:
    """Security BoardCfg policy alanlarını source-backed kurallarla kontrol eder."""
    profile = (
        load_boardcfg_profile(profile_or_path)
        if isinstance(profile_or_path, (str, Path))
        else profile_or_path
    )
    if not isinstance(profile, dict):
        raise ValueError("profile mapping olmalıdır")

    checks: list[dict[str, Any]] = []
    normalized: dict[str, Any] = {"secure_debug": {}, "extended_otp": {}}

    if profile.get("type") != PROFILE_TYPE:
        _add(checks, "profile_type", "FAIL", f"type={PROFILE_TYPE} olmalıdır")
    else:
        _add(checks, "profile_type", "PASS", PROFILE_TYPE)

    sec = profile.get("secure_debug")
    if not isinstance(sec, dict):
        _add(checks, "secure_debug_structure", "FAIL", "secure_debug YAML mapping olmalıdır")
        sec = {}

    try:
        magic = _parse_int(sec.get("subhdr_magic"), "secure_debug.subhdr_magic", 0, 0xFFFF)
        normalized["secure_debug"]["subhdr_magic"] = magic
        if magic != SECDBG_MAGIC:
            raise ValueError(f"secure_debug.subhdr_magic: TISCI 12.00.02 için 0x{SECDBG_MAGIC:04X} olmalıdır")
        _add(checks, "secure_debug_magic", "PASS", "Secure Debug Unlock subheader magic = 0x42AF")
    except Exception as exc:
        _add(checks, "secure_debug_magic", "FAIL", str(exc))

    flag_values: dict[str, int | None] = {}
    for field in ("allow_jtag_unlock", "allow_wildcard_unlock"):
        try:
            n = _parse_flag(sec.get(field), f"secure_debug.{field}")
            normalized["secure_debug"][field] = n
            flag_values[field] = n
            _add(checks, field, "PASS", f"{field}=0x{n:02X}")
        except Exception as exc:
            flag_values[field] = None
            _add(checks, field, "FAIL", str(exc))

    for field in ("allow_debug_level_rsvd", "rsvd"):
        try:
            n = _parse_int(sec.get(field), f"secure_debug.{field}", 0, 0xFF)
            normalized["secure_debug"][field] = n
            if n != 0:
                raise ValueError(f"secure_debug.{field}: reserved alan bu sürümde 0 olmalıdır")
            _add(checks, field, "PASS", f"{field}=0")
        except Exception as exc:
            _add(checks, field, "FAIL", str(exc))

    try:
        min_rev = _parse_int(sec.get("min_cert_rev"), "secure_debug.min_cert_rev", 0, 0xFFFFFFFF)
        normalized["secure_debug"]["min_cert_rev"] = min_rev
        _add(checks, "min_cert_rev", "PASS", f"minimum debug certificate revision = {min_rev}")
    except Exception as exc:
        _add(checks, "min_cert_rev", "FAIL", str(exc))

    hosts = sec.get("jtag_unlock_hosts")
    if not isinstance(hosts, list) or len(hosts) != 4:
        _add(checks, "jtag_unlock_hosts", "FAIL", "secure_debug.jtag_unlock_hosts tam 4 elemanlı liste olmalıdır")
        normalized_hosts: list[int] = []
    else:
        normalized_hosts = []
        try:
            for idx, value in enumerate(hosts):
                normalized_hosts.append(_parse_int(value, f"secure_debug.jtag_unlock_hosts[{idx}]", 0, 0xFF))
            normalized["secure_debug"]["jtag_unlock_hosts"] = normalized_hosts
            detail = (
                "host 128 bulundu: TISCI üzerinden tüm host'lara izin veren wildcard host policy"
                if WILDCARD_HOST_ID in normalized_hosts
                else "4 host policy alanı biçimsel olarak geçerli"
            )
            _add(checks, "jtag_unlock_hosts", "PASS", detail)
        except Exception as exc:
            _add(checks, "jtag_unlock_hosts", "FAIL", str(exc))

    warnings: list[str] = []
    if flag_values.get("allow_jtag_unlock") == 0 and flag_values.get("allow_wildcard_unlock") == ENABLE_MAGIC:
        warnings.append(
            "allow_wildcard_unlock=0x5A ayarlı fakat allow_jtag_unlock=0 iken bu alan System Firmware runtime debug akışında kullanılmaz."
        )
    if flag_values.get("allow_jtag_unlock") == 0 and WILDCARD_HOST_ID in normalized_hosts:
        warnings.append(
            "jtag_unlock_hosts içinde 128 var ancak allow_jtag_unlock=0 iken runtime debug açma devre dışıdır."
        )

    otp = profile.get("extended_otp")
    if otp is None:
        otp = {}
    if not isinstance(otp, dict):
        _add(checks, "extended_otp_structure", "FAIL", "extended_otp YAML mapping olmalıdır")
        otp = {}

    try:
        otp_magic = _parse_int(otp.get("subhdr_magic"), "extended_otp.subhdr_magic", 0, 0xFFFF)
        normalized["extended_otp"]["subhdr_magic"] = otp_magic
        if otp_magic != OTP_MAGIC:
            raise ValueError(f"extended_otp.subhdr_magic: TISCI 12.00.02 için 0x{OTP_MAGIC:04X} olmalıdır")
        _add(checks, "extended_otp_magic", "PASS", "Extended OTP subheader magic = 0x4081")
    except Exception as exc:
        _add(checks, "extended_otp_magic", "FAIL", str(exc))

    write_host = otp.get("write_host")
    if write_host is None:
        normalized["extended_otp"]["write_host"] = None
        _add(
            checks,
            "otp_write_host",
            "NOT_CHECKED",
            "write_host profile'da belirtilmedi; revision-write authorization değerlendirilmedi.",
        )
    else:
        try:
            write_host_n = _parse_int(write_host, "extended_otp.write_host", 0, 0xFF)
            if write_host_n == WILDCARD_HOST_ID:
                raise ValueError("extended_otp.write_host: wildcard host ID 128 kullanılamaz")
            normalized["extended_otp"]["write_host"] = write_host_n
            _add(
                checks,
                "otp_write_host",
                "PASS",
                "write_host biçimsel olarak geçerli; secure-proxy-thread eşleşmesi exact SoC host map olmadan doğrulanmadı.",
            )
            _add(
                checks,
                "otp_write_host_secure_proxy_mapping",
                "NOT_CHECKED",
                "TISCI write_host'un secure proxy thread'e map olmasını ister; bu profile SoC host map içermez.",
            )
        except Exception as exc:
            _add(checks, "otp_write_host", "FAIL", str(exc))

    fail = any(c["status"] == "FAIL" for c in checks)
    status = "FAIL" if fail else "PASS"

    runtime_debug = "ENABLED" if flag_values.get("allow_jtag_unlock") == ENABLE_MAGIC else "DISABLED"
    wildcard_uid = "ENABLED" if flag_values.get("allow_wildcard_unlock") == ENABLE_MAGIC else "DISABLED"

    return {
        "status": status,
        "profile_type": PROFILE_TYPE,
        "normalized": normalized,
        "summary": {
            "runtime_jtag_unlock": runtime_debug,
            "wildcard_uid_policy": wildcard_uid,
            "tisci_all_hosts": WILDCARD_HOST_ID in normalized_hosts,
        },
        "checks": checks,
        "warnings": warnings,
        "execution": {
            "boardcfg_sent_to_target": False,
            "secure_debug_unlock": "NOT_EXECUTED",
            "tisci_msg_write_swrev": "NOT_EXECUTED",
            "tisci_msg_write_keyrev": "NOT_EXECUTED",
            "otp_efuse_write": "NOT_EXECUTED",
        },
    }


def evaluate_debug_policy(
    profile_path: str | Path,
    certificate: str | Path,
    *,
    transport: str,
    host_id: int | None = None,
    soc_uid: str | None = None,
    jtag_efuse: str = "unknown",
) -> dict[str, Any]:
    """Debug certificate'ı yalnız BoardCfg runtime policy açısından offline değerlendirir."""
    checked = check_boardcfg_profile(profile_path)
    if checked["status"] != "PASS":
        return {
            "status": "FAIL",
            "policy_decision": "INVALID_BOARDCFG_PROFILE",
            "boardcfg": checked,
            "execution": "OFFLINE_ONLY",
        }

    if transport not in {"tisci", "sec-ap"}:
        raise ValueError("transport: tisci veya sec-ap olmalıdır")
    if jtag_efuse not in {"enabled", "disabled", "unknown"}:
        raise ValueError("jtag_efuse: enabled, disabled veya unknown olmalıdır")
    if host_id is not None:
        host_id = _parse_int(host_id, "host_id", 0, 0xFF)
    uid = _normalize_uid(soc_uid)

    image = inspect_artifact(certificate)
    checks: list[dict[str, Any]] = []

    if image.get("classification") != "Secure Debug X.509 certificate":
        _add(checks, "certificate_type", "FAIL", "Girdi Secure Debug X.509 certificate olarak sınıflandırılmadı")
    else:
        _add(checks, "certificate_type", "PASS", "Secure Debug X.509 certificate")

    decoded = image.get("decoded", {})
    swrev = decoded.get("software_revision")
    debug = decoded.get("sysfw_debug")
    if not isinstance(swrev, dict) or "software_revision" not in swrev:
        _add(checks, "software_revision_extension", "FAIL", "System Firmware Software Revision Extension bulunamadı veya çözülemedi")
        cert_rev = None
    else:
        cert_rev = int(swrev["software_revision"])
        _add(checks, "software_revision_extension", "PASS", f"certificate revision = {cert_rev}")

    if not isinstance(debug, dict) or "uid_hex" not in debug:
        _add(checks, "debug_extension", "FAIL", "System Firmware Debug Extension bulunamadı veya çözülemedi")
        cert_uid = None
    else:
        cert_uid = str(debug["uid_hex"]).lower()
        _add(checks, "debug_extension", "PASS", "Debug Extension çözüldü")

    sec = checked["normalized"]["secure_debug"]
    allow_jtag = sec.get("allow_jtag_unlock")
    allow_wildcard = sec.get("allow_wildcard_unlock")
    min_rev = sec.get("min_cert_rev")
    hosts = sec.get("jtag_unlock_hosts", [])

    reject = False
    unknown = False

    if allow_jtag != ENABLE_MAGIC:
        _add(checks, "allow_jtag_unlock", "FAIL", "BoardCfg runtime JTAG unlock'a izin vermiyor")
        reject = True
    else:
        _add(checks, "allow_jtag_unlock", "PASS", "BoardCfg runtime JTAG unlock'a izin veriyor")

    if cert_rev is not None and isinstance(min_rev, int):
        if cert_rev < min_rev:
            _add(checks, "min_cert_rev", "FAIL", f"certificate revision {cert_rev}, minimum {min_rev} değerinden düşük")
            reject = True
        else:
            _add(checks, "min_cert_rev", "PASS", f"certificate revision {cert_rev} >= minimum {min_rev}")

    if jtag_efuse == "disabled":
        _add(checks, "jtag_efuse_connectivity", "FAIL", "JTAG connectivity eFuse tarafında disabled olarak belirtildi")
        reject = True
    elif jtag_efuse == "enabled":
        _add(checks, "jtag_efuse_connectivity", "PASS", "JTAG connectivity eFuse tarafında enabled olarak belirtildi")
    else:
        _add(checks, "jtag_efuse_connectivity", "NOT_CHECKED", "JTAG connectivity eFuse durumu verilmedi")
        unknown = True

    if allow_wildcard == ENABLE_MAGIC:
        _add(checks, "soc_uid_policy", "PASS", "BoardCfg wildcard UID policy nedeniyle SOC UID eşleşmesi atlanabilir")
    elif cert_uid is None:
        pass
    elif uid is None:
        _add(checks, "soc_uid_policy", "NOT_CHECKED", "Wildcard kapalı; karşılaştırma için target SOC UID verilmedi")
        unknown = True
    elif cert_uid != uid:
        _add(checks, "soc_uid_policy", "FAIL", "Certificate UID ile verilen target SOC UID eşleşmiyor")
        reject = True
    else:
        _add(checks, "soc_uid_policy", "PASS", "Certificate UID target SOC UID ile eşleşiyor")

    if transport == "tisci":
        if host_id is None:
            _add(checks, "jtag_unlock_host", "NOT_CHECKED", "TISCI transport için requester host ID verilmedi")
            unknown = True
        elif WILDCARD_HOST_ID in hosts:
            _add(checks, "jtag_unlock_host", "PASS", "jtag_unlock_hosts içinde 128: TISCI requester host policy tarafından izinli")
        elif host_id in hosts:
            _add(checks, "jtag_unlock_host", "PASS", f"host ID {host_id}, jtag_unlock_hosts içinde")
        else:
            _add(checks, "jtag_unlock_host", "FAIL", f"host ID {host_id}, jtag_unlock_hosts içinde değil")
            reject = True
    else:
        _add(checks, "jtag_unlock_host", "NOT_APPLICABLE", "jtag_unlock_hosts alanı TISCI requester host policy'sidir; Sec-AP için uygulanmadı")

    _add(
        checks,
        "active_customer_root_of_trust",
        "NOT_CHECKED",
        "Active SMPK/BMPK trust, public-key-hash eFuse eşleşmesi ve target signature acceptance bu offline BoardCfg kontrolüyle doğrulanamaz.",
    )

    if any(c["status"] == "FAIL" for c in checks if c["check"] in {"certificate_type", "software_revision_extension", "debug_extension"}):
        status = "FAIL"
        decision = "INVALID_DEBUG_CERTIFICATE"
    elif reject:
        status = "PASS"
        decision = "REJECT_BY_POLICY"
    elif unknown:
        status = "PARTIAL"
        decision = "INDETERMINATE"
    else:
        status = "PASS"
        decision = "POLICY_ALLOWS_REQUEST"

    return {
        "status": status,
        "operation": "secure_debug_boardcfg_policy_evaluation",
        "policy_decision": decision,
        "transport": transport,
        "certificate": {
            "file": Path(certificate).name,
            "classification": image.get("classification"),
            "software_revision": cert_rev,
            "uid_length": debug.get("uid_length") if isinstance(debug, dict) else None,
            "debug_privilege": debug.get("debug_privilege") if isinstance(debug, dict) else None,
        },
        "checks": checks,
        "target_acceptance": "NOT_VERIFIED",
        "execution": {
            "debug_unlock": "NOT_EXECUTED",
            "boardcfg_write": "NOT_EXECUTED",
            "permanent_debug_change": "NOT_EXECUTED",
        },
    }


def evaluate_revision_writer(profile_path: str | Path, host_id: int) -> dict[str, Any]:
    """TISCI_MSG_WRITE_SWREV/KEYREV için BoardCfg write_host policy'sini offline değerlendirir."""
    checked = check_boardcfg_profile(profile_path)
    if checked["status"] != "PASS":
        return {
            "status": "FAIL",
            "decision": "INVALID_BOARDCFG_PROFILE",
            "boardcfg": checked,
            "execution": "OFFLINE_ONLY",
        }
    requester = _parse_int(host_id, "host_id", 0, 0xFF)
    write_host = checked["normalized"]["extended_otp"].get("write_host")
    if write_host is None:
        return {
            "status": "PARTIAL",
            "decision": "INDETERMINATE",
            "requester_host": requester,
            "configured_write_host": None,
            "detail": "write_host profile'da belirtilmedi.",
            "execution": {
                "tisci_msg_write_swrev": "NOT_EXECUTED",
                "tisci_msg_write_keyrev": "NOT_EXECUTED",
                "otp_efuse_write": "NOT_EXECUTED",
            },
        }

    allowed = requester == write_host
    return {
        "status": "PASS",
        "decision": "AUTHORIZED_BY_BOARDCFG" if allowed else "NOT_AUTHORIZED_BY_BOARDCFG",
        "requester_host": requester,
        "configured_write_host": write_host,
        "detail": (
            "Requester host, BoardCfg write_host ile eşleşiyor. Bu yalnız policy sonucudur; TISCI çağrısı yapılmadı."
            if allowed
            else "Requester host, BoardCfg write_host ile eşleşmiyor."
        ),
        "secure_proxy_mapping": "NOT_CHECKED",
        "execution": {
            "tisci_msg_write_swrev": "NOT_EXECUTED",
            "tisci_msg_write_keyrev": "NOT_EXECUTED",
            "otp_efuse_write": "NOT_EXECUTED",
        },
    }
