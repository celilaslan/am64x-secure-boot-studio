from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .explanations import explain_check
from .secret_policy import sanitize_for_record

_STATUS_TEXT = {
    "PASS": "Başarılı",
    "FAIL": "Başarısız",
    "PARTIAL": "Kısmi",
    "NOT_CHECKED": "Kontrol edilmedi",
    "NOT_APPLICABLE": "Uygulanmaz",
    "INFO": "Bilgi",
    "WARN": "Uyarı",
    "ERROR": "Hata",
}

_CHECK_TITLES = {
    "artifact_parse": "Dosya yapısı okunabildi",
    "host_side_verify": "Host-side doğrulama",
    "signing_key_preflight": "Signing key ön kontrolü",
    "private_key_required_for_build": "Private signing key gerekli",
    "mek_preflight": "Encryption key ön kontrolü",
    "ti_signing_tool": "TI application signing tool",
    "post_verify": "Üretim sonrası doğrulama",
    "certificate_signature_with_embedded_public_key": "Certificate signature",
    "appended_payload_sha512_binding": "Payload / ciphertext SHA-512 binding",
    "system_firmware_load_extension_present": "System Firmware Load Extension",
    "aes_cbc_ciphertext_block_alignment": "AES-CBC block alignment",
    "encryption_iv_length": "Encryption IV uzunluğu",
    "encryption_random_string_length": "Decryption correctness random string",
    "encryption_iteration_count": "Encryption iteration count",
    "target_debug_authorization": "Target debug authorization",
    "otp_efuse_programming_result": "OTP/eFuse programming sonucu",
    "rom_combined_legacy_extension_exclusivity": "ROM extension uyumluluğu",
    "rom_component_count_range": "ROM component sayısı",
    "rom_component_count_decoded": "ROM component decode",
    "rom_component_total_size": "ROM component toplam boyutu",
    "rom_ext_image_size": "ROM image boyutu",
    "certificate_type": "Certificate türü",
    "software_revision_extension": "Software Revision Extension",
    "debug_extension": "Secure Debug Extension",
    "allow_jtag_unlock": "BoardCfg JTAG unlock policy",
    "min_cert_rev": "Minimum debug certificate revision",
    "jtag_efuse_connectivity": "JTAG eFuse connectivity",
    "soc_uid_policy": "SOC UID policy",
    "jtag_unlock_host": "TISCI requester Host ID policy",
    "active_customer_root_of_trust": "Active customer Root of Trust",
    "generalized_authentication_extension_set": "Generalized Authentication extension set",
    "software_revision_present_nonzero": "Generic data SWREV",
    "decryption_random_string": "Decryption random-string check",
    "decrypted_original_prefix": "Decrypted original-data match",
    "decrypted_zero_padding": "Decrypted zero padding",
    "physical_and_target_lifecycle_distinguished": "Kart durumu ve üretim hedefi",
    "application_secure_build": "Secure application üretimi",
    "application_certificate_and_image_verify": "Certificate ve image doğrulaması",
    "selected_certificate_private_key_match": "Seçilen certificate ve private key eşleşmesi",
    "output_certificate_identity_match": "CCS çıktısındaki certificate kimliği",
    "boot_image_build": "SBL / combined boot image",
    "global_devconfig_unchanged": "Global devconfig.mak değiştirilmedi",
    "otp_efuse_untouched": "OTP/eFuse değiştirilmedi",
    "mcu_plus_sdk_make": "CCS / MCU+ SDK build",
    "ccs_bootimage_post_build": "CCS boot-image post-build",
    "signed_output_discovery": "Signed application çıktısı",
    "application_mcu_plus_sdk_make": "CCS / MCU+ SDK build",
    "application_ccs_bootimage_post_build": "CCS boot-image post-build",
    "application_signed_output_discovery": "Signed application çıktısı",
    "application_global_devconfig_unchanged": "Application build devconfig kontrolü",
}

_OPERATION_TITLES = {
    "application_build": "Secure Application",
    "rom_build": "ROM Combined Image",
    "inspect": "Image İnceleme",
    "inspect_verify": "Image İnceleme ve Doğrulama",
    "negative_test": "Negatif Test",
    "key_preflight": "Key Ön Kontrolü",
    "key_generate_signing": "Signing Key Üretimi",
    "key_generate_mek": "Encryption Key Üretimi",
    "key_generate_set": "Key Set Üretimi",
    "certificate_profile": "Certificate Profile",
    "sdk_lint": "SDK Inspector",
    "sdk_diff": "SDK Compare",
    "errata": "Errata Advisor",
    "provision_preflight": "Provisioning Hazırlığı",
    "revision": "KEYREV / SWREV Simulator",
    "boardcfg": "Security BoardCfg",
    "secure_debug": "Secure Debug",
    "generic_data": "Generic Data",
    "generic_data_build": "Generic Data Build",
    "secure_debug_boardcfg_policy_evaluation": "Secure Debug Policy",
    "generic_data_verify": "Generic Data Verify",
    "generic_data_profile": "Generic Data Profile",
    "secure_boot_package_build": "Secure Boot Paketi",
    "ccs_secure_build": "CCS Secure Application",
    "ccs_sbl_secure_build": "SBL / Combined Boot Image",
    "uart_ospi_flash": "UART / OSPI Yükleme",
}


@dataclass(frozen=True)
class ResultPresentation:
    status: str
    status_text: str
    title: str
    summary: str
    checks: list[dict[str, Any]]
    outputs: list[dict[str, str]]
    claims: list[str]
    non_claims: list[str]
    technical: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def humanize_identifier(value: str) -> str:
    if value in _CHECK_TITLES:
        return _CHECK_TITLES[value]
    text = value.replace("_", " ").replace("-", " ").strip()
    if not text:
        return "Kontrol"
    replacements = {
        "sha512": "SHA-512",
        "sha256": "SHA-256",
        "spki": "SPKI",
        "x509": "X.509",
        "mek": "MEK",
        "smpk": "SMPK",
        "bmpk": "BMPK",
        "sbl": "SBL",
        "sysfw": "SYSFW",
        "rom": "ROM",
        "aes": "AES",
        "iv": "IV",
    }
    words = []
    for word in text.split():
        lower = word.lower()
        words.append(replacements.get(lower, word.capitalize()))
    return " ".join(words)


def status_text(status: str | None) -> str:
    return _STATUS_TEXT.get(str(status or "INFO"), str(status or "Bilgi"))


def _compact_detail(check: dict[str, Any]) -> str:
    if check.get("detail"):
        return str(check["detail"])
    if check.get("reason"):
        return str(check["reason"])
    pairs: list[str] = []
    preferred = (
        "actual", "expected", "allowed", "actual_size", "expected_bytes",
        "declared", "decoded", "actual_bytes", "actual_appended_bytes",
        "declared_component_sum", "actual_appended",
    )
    for key in preferred:
        if key in check:
            value = check[key]
            if isinstance(value, (dict, list)):
                value = str(value)
            pairs.append(f"{humanize_identifier(key)}: {value}")
    return " · ".join(pairs) if pairs else "—"


def _safe_output(output: dict[str, Any]) -> dict[str, str]:
    kind = str(output.get("type") or "output")
    path = output.get("path")
    # Results should not expose a full host path. The selected field remains visible in
    # the active UI, but share-safe result cards only show the final file name.
    name = Path(str(path)).name if path else "—"
    return {"type": humanize_identifier(kind), "name": name}


def result_presentation(result: dict[str, Any]) -> ResultPresentation:
    safe = sanitize_for_record(result)
    status = str(safe.get("status") or safe.get("overall_host_side_verification") or "INFO")
    operation = str(safe.get("operation") or safe.get("classification") or "result")
    title = _OPERATION_TITLES.get(operation, humanize_identifier(operation))
    raw_summary = safe.get("summary_text") or safe.get("summary") or safe.get("note")
    summary = str(raw_summary) if isinstance(raw_summary, (str, int, float)) else "İşlem sonucu hazır."

    raw_checks = safe.get("checks")
    if not isinstance(raw_checks, list):
        verification = safe.get("verification") or safe.get("safe_details", {}).get("verification") or {}
        raw_checks = verification.get("checks", []) if isinstance(verification, dict) else []
    if not raw_checks:
        gathered: list[dict[str, Any]] = []
        inputs = safe.get("inputs") if isinstance(safe.get("inputs"), dict) else {}
        for role, part in inputs.items():
            if not isinstance(part, dict):
                continue
            for row in part.get("checks", []):
                if isinstance(row, dict):
                    item = dict(row)
                    item.setdefault("detail", f"{humanize_identifier(str(role))}: {row.get('detail', '—')}")
                    gathered.append(item)
        for row in safe.get("cross_checks", []) if isinstance(safe.get("cross_checks"), list) else []:
            if isinstance(row, dict):
                gathered.append(row)
        raw_checks = gathered
    if not raw_checks and safe.get("model") == "key_revision_offline":
        raw_checks = [{
            "check": "keycnt_keyrev_relationship",
            "status": safe.get("status", "INFO"),
            "detail": safe.get("detail", "KEYCNT/KEYREV relationship"),
        }]
        requested = safe.get("requested_state")
        if isinstance(requested, dict):
            raw_checks.append({
                "check": "proposed_keyrev_state",
                "status": requested.get("status", "INFO"),
                "detail": requested.get("detail", "Proposed KEYREV state"),
            })
            raw_checks.append({
                "check": "keyrev_target_write",
                "status": "NOT_CHECKED",
                "detail": requested.get("write_note", "Target write not executed"),
            })
    if not raw_checks and safe.get("model") == "swrev_offline":
        raw_checks = [{
            "check": "swrev_comparison",
            "status": "PASS" if safe.get("decision_is_source_defined") else "NOT_CHECKED",
            "detail": safe.get("decision_basis", safe.get("decision", "No decision")),
        }, {
            "check": "swrev_target_acceptance",
            "status": "NOT_CHECKED",
            "detail": "Signature, integrity, active Root of Trust ve hardware acceptance bu simulator tarafından çalıştırılmaz.",
        }]
    if not raw_checks and safe.get("decision") in {"AUTHORIZED_BY_BOARDCFG", "NOT_AUTHORIZED_BY_BOARDCFG", "INDETERMINATE"}:
        decision = str(safe.get("decision"))
        raw_checks = [{
            "check": "boardcfg_revision_writer_policy",
            "status": "PASS" if decision == "AUTHORIZED_BY_BOARDCFG" else ("FAIL" if decision == "NOT_AUTHORIZED_BY_BOARDCFG" else "NOT_CHECKED"),
            "detail": safe.get("detail", decision),
        }, {
            "check": "revision_writer_target_execution",
            "status": "NOT_CHECKED",
            "detail": "TISCI write request ve OTP/eFuse operation çalıştırılmadı.",
        }]
    checks: list[dict[str, Any]] = []
    for check in raw_checks or []:
        if not isinstance(check, dict):
            continue
        check_id = str(check.get("check") or "check")
        check_status = str(check.get("status") or "INFO")
        detail = _compact_detail(check)
        why = explain_check(check_id, check_status, detail)
        checks.append({
            "status": check_status,
            "status_text": status_text(check_status),
            "check": check_id,
            "title": humanize_identifier(check_id),
            "detail": detail,
            "why": str(why.get("explanation") or ""),
            "sources": [str(x) for x in why.get("sources", [])],
        })

    outputs = [_safe_output(x) for x in safe.get("outputs", []) if isinstance(x, dict)]
    return ResultPresentation(
        status=status,
        status_text=status_text(status),
        title=title,
        summary=summary,
        checks=checks,
        outputs=outputs,
        claims=[str(x) for x in safe.get("claims", [])],
        non_claims=[str(x) for x in safe.get("non_claims", [])],
        technical=safe,
    )


def image_anatomy_model(inspection: dict[str, Any]) -> dict[str, Any]:
    """Return a share-safe, display-oriented image layout model.

    This function does not infer missing offsets or addresses. It uses only values
    parsed from the selected artifact.
    """
    classification = str(inspection.get("classification") or "unknown")
    certificate_size = int(inspection.get("certificate_size") or 0)
    appended_size = int(inspection.get("appended_size") or 0)
    blocks: list[dict[str, Any]] = []
    if certificate_size:
        blocks.append({
            "kind": "certificate",
            "label": "X.509 Certificate",
            "size": certificate_size,
            "detail": "Certificate metadata ve signature",
        })

    rom = (inspection.get("decoded") or {}).get("rom_ext_boot_info") or {}
    components = rom.get("components", []) if isinstance(rom, dict) else []
    if classification == "ROM combined image" and components:
        for component in components:
            size = int(component.get("comp_size") or 0)
            label = str(component.get("component_name") or f"Component {component.get('index', '?')}")
            blocks.append({
                "kind": "rom_component",
                "label": label,
                "size": size,
                "detail": f"Component type {component.get('comp_type', '?')}",
            })
    elif appended_size:
        encrypted = "encrypted" in classification.lower()
        blocks.append({
            "kind": "ciphertext" if encrypted else "payload",
            "label": "Ciphertext" if encrypted else "Appended Payload",
            "size": appended_size,
            "detail": "AES-256-CBC encrypted payload" if encrypted else "Signed/authenticated payload",
        })

    total = sum(max(int(x.get("size") or 0), 0) for x in blocks)
    for block in blocks:
        size = max(int(block.get("size") or 0), 0)
        block["fraction"] = (size / total) if total else 0.0

    return {
        "classification": classification,
        "file": str(inspection.get("file") or ""),
        "total_size": int(inspection.get("file_size") or total),
        "blocks": blocks,
        "tisci_request_semantics": str(inspection.get("tisci_request_semantics") or "not_determined"),
    }


def error_guidance(exc: BaseException) -> dict[str, str]:
    """Convert an exception into a concise 'what / why / next action' UI model."""
    technical = f"{type(exc).__name__}: {exc}"
    if isinstance(exc, FileNotFoundError):
        return {
            "title": "Gerekli dosya bulunamadı",
            "what": str(exc) or "Seçilen veya otomatik çözümlenmesi gereken dosya bulunamadı.",
            "why": "Dosya yolu değişmiş, SDK root yanlış seçilmiş veya gerekli TI tool bu SDK kurulumunda bulunmuyor olabilir.",
            "action": "Environment ekranında SDK root ve tool discovery sonucunu kontrol edin; ardından ilgili dosyayı yeniden seçin.",
            "technical": technical,
        }
    if isinstance(exc, PermissionError):
        return {
            "title": "Dosyaya erişilemiyor",
            "what": str(exc) or "İşlem için gerekli dosya açılamadı veya output yazılamadı.",
            "why": "Dosya/dizin izinleri veya başka bir süreç tarafından kilitlenmiş bir output buna neden olabilir.",
            "action": "Erişim izinlerini ve output dizinini kontrol edin. Secret dosyalarda güvenli izinleri gevşetmek yerine erişim sahibini düzeltin.",
            "technical": technical,
        }
    if isinstance(exc, ValueError):
        return {
            "title": "Girdi doğrulanamadı",
            "what": str(exc) or "Bir alan beklenen formatta değil.",
            "why": "Zorunlu alan boş, sayı/format geçersiz veya seçilen workflow ile uyumsuz bir girdi verilmiş olabilir.",
            "action": "Kırmızı/eksik alanları kontrol edin. Exact address, ID, OID veya key formatını tahmin etmeyin; source-backed değeri kullanın.",
            "technical": technical,
        }
    return {
        "title": "İşlem tamamlanamadı",
        "what": str(exc) or "Beklenmeyen bir hata oluştu.",
        "why": "Girdi, environment, external TI tool veya local runtime kaynaklı bir hata olabilir.",
        "action": "Önce Environment ve input dosyalarını kontrol edin. Gerekirse teknik ayrıntıyı açıp hatayı kaynak tool çıktısıyla birlikte inceleyin.",
        "technical": technical,
    }
