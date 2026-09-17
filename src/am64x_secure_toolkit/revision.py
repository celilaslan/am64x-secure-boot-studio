from __future__ import annotations

from typing import Any

KEY_CONTEXTS = {
    1: {
        "signing": "SMPK",
        "encryption": "SMEK",
        "label": "SMPK/SMEK",
    },
    2: {
        "signing": "BMPK",
        "encryption": "BMEK",
        "label": "BMPK/BMEK",
    },
}


def _status_for_key_state(key_count: int, key_revision: int | None) -> tuple[str, str]:
    if key_count not in {0, 1, 2}:
        return "FAIL", "KEYCNT yalnız 0, 1 veya 2 olabilir."
    if key_count == 0:
        if key_revision is not None:
            return "FAIL", "KEYCNT=0 için numeric KEYREV değeri modellenmez; customer root-key set yoktur."
        return "PASS", "Customer root-key set yok; active customer key context yok."
    if key_revision is None:
        return "FAIL", "KEYCNT>0 için KEYREV değeri gerekli."
    if key_revision not in {1, 2}:
        return "FAIL", "Bu sürümde modellenen KEYREV değerleri 1 ve 2'dir."
    if key_revision > key_count:
        return "FAIL", "KEYREV, KEYCNT değerinden büyük olamaz."
    if key_count == 1 and key_revision != 1:
        return "FAIL", "KEYCNT=1 durumunda yalnız SMPK/SMEK seti mevcuttur; KEYREV=1 beklenir."
    return "PASS", "KEYCNT/KEYREV kombinasyonu TISCI 12.00.02 alan semantiğiyle uyumludur."


def simulate_key_revision(key_count: int, key_revision: int | None, target_key_revision: int | None = None) -> dict[str, Any]:
    """KEYCNT/KEYREV ilişkisini yalnız offline durum modeli olarak değerlendirir."""
    status, detail = _status_for_key_state(key_count, key_revision)
    active = KEY_CONTEXTS.get(key_revision) if status == "PASS" and key_revision is not None else None

    result: dict[str, Any] = {
        "status": status,
        "model": "key_revision_offline",
        "key_count": key_count,
        "key_revision": key_revision,
        "active_key_context": active,
        "detail": detail,
        "source_rules": {
            "key_count": {
                "0": "customer root-key set yok",
                "1": "SMPK seti mevcut",
                "2": "SMPK + BMPK setleri mevcut",
            },
            "key_revision_max": "KEYREV <= KEYCNT",
            "key_revision_1": "SMPK/SMEK context",
            "key_revision_2": "BMPK/BMEK context",
        },
        "execution": {
            "keyrev_write": "NOT_EXECUTED",
            "efuse_programming": "NOT_EXECUTED",
            "otp_keywriter": "NOT_EXECUTED",
        },
        "note": (
            "Bu sonuç yalnız KEYCNT/KEYREV alanlarının mantıksal ilişkisini gösterir. "
            "Runtime write izni, OTP state'i, provisioning başarısı veya hardware enforcement sonucu değildir."
        ),
    }

    if target_key_revision is not None:
        t_status, t_detail = _status_for_key_state(key_count, target_key_revision)
        result["requested_state"] = {
            "key_revision": target_key_revision,
            "status": t_status,
            "active_key_context": KEY_CONTEXTS.get(target_key_revision) if t_status == "PASS" else None,
            "detail": t_detail,
            "write_feasibility": "NOT_CHECKED",
            "write_note": (
                "Araç yalnız hedef durumun KEYCNT ile tutarlılığını değerlendirir; "
                "KEYREV write işleminin hedef cihazda izinli veya uygulanabilir olduğunu söylemez."
            ),
        }
        if status == "PASS" and t_status == "PASS" and key_revision == target_key_revision:
            result["requested_state"]["relationship"] = "SAME_STATE"
        elif status == "PASS" and t_status == "PASS":
            result["requested_state"]["relationship"] = "DIFFERENT_VALID_STATE"

    return result


def key_revision_matrix() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for key_count, revs in [(0, [None]), (1, [1, 2]), (2, [1, 2])]:
        for rev in revs:
            status, detail = _status_for_key_state(key_count, rev)
            rows.append({
                "key_count": key_count,
                "key_revision": rev,
                "status": status,
                "active_key_context": KEY_CONTEXTS.get(rev) if status == "PASS" and rev is not None else None,
                "detail": detail,
            })
    return {
        "status": "PASS",
        "model": "key_revision_matrix",
        "rows": rows,
        "execution": "OFFLINE_ONLY",
    }


def _require_nonnegative(value: int, name: str) -> int:
    if value < 0:
        raise ValueError(f"{name} negatif olamaz")
    return value


def simulate_swrev(context: str, reference_revision: int, certificate_revision: int) -> dict[str, Any]:
    """TISCI 12.00.02'de açıkça tanımlanan SWREV compare bağlamlarını simüle eder."""
    reference_revision = _require_nonnegative(reference_revision, "reference_revision")
    certificate_revision = _require_nonnegative(certificate_revision, "certificate_revision")

    result: dict[str, Any] = {
        "status": "PASS",
        "model": "swrev_offline",
        "context": context,
        "reference_revision": reference_revision,
        "certificate_revision": certificate_revision,
        "execution": {
            "swrev_write": "NOT_EXECUTED",
            "efuse_programming": "NOT_EXECUTED",
        },
    }

    if context == "tiboot3":
        accepted = certificate_revision >= reference_revision
        result.update({
            "reference_meaning": "bootloader SWREV eFuse",
            "decision": "ACCEPT_BY_SWREV" if accepted else "REJECT_BY_SWREV",
            "decision_basis": (
                "ROM, tiboot3 certificate SWREV değerini bootloader SWREV eFuse değeriyle karşılaştırır; "
                "certificate değeri daha düşükse reject eder."
            ),
            "decision_is_source_defined": True,
        })
    elif context == "boardcfg":
        accepted = certificate_revision >= reference_revision
        result.update({
            "reference_meaning": "configuration SWREV eFuse",
            "decision": "ACCEPT_BY_SWREV" if accepted else "REJECT_BY_SWREV",
            "decision_basis": (
                "SYSFW, Board Configuration certificate SWREV değerini configuration SWREV eFuse değeriyle karşılaştırır; "
                "certificate değeri daha düşükse reject eder."
            ),
            "decision_is_source_defined": True,
        })
    elif context == "debug":
        accepted = certificate_revision >= reference_revision
        result.update({
            "reference_meaning": "Security Board Configuration min_cert_rev",
            "decision": "PASS_REVISION_GATE" if accepted else "FAIL_REVISION_GATE",
            "decision_basis": (
                "Secure Debug certificate revision, Security Board Configuration içindeki minimum certificate revision eşiğini karşılamalıdır."
            ),
            "decision_is_source_defined": True,
            "important": "Revision gate tek başına debug authorization sonucu değildir; signature, UID, debug permission ve host policy kontrolleri ayrıca vardır.",
        })
    elif context in {"application", "generic"}:
        result.update({
            "reference_meaning": "user-supplied comparison value; hardware threshold olarak yorumlanmaz",
            "decision": "NO_CURRENT_ENFORCEMENT_MODELED",
            "decision_basis": (
                "TISCI 12.00.02 authentication dokümanı SWREV extension'ı mandatory olarak tanımlar, "
                "ancak parsing/validation sonrasında bu sürümde ek bir işlem uygulanmadığını belirtir."
            ),
            "decision_is_source_defined": True,
            "application_swrev_enforcement": "NOT_VERIFIED",
        })
    else:
        raise ValueError("context: tiboot3, boardcfg, debug, application veya generic olmalıdır")

    result["note"] = (
        "Bu simülasyon yalnız revision karşılaştırmasını gösterir. Signature, integrity, lifecycle, active Root of Trust "
        "ve target hardware acceptance ayrı kontrollerdir."
    )
    return result


def swrev_field_info() -> dict[str, Any]:
    return {
        "status": "PASS",
        "model": "swrev_field_info",
        "keywriter_fields": {
            "SWREV-SBL": {"encoded_bits": 96, "single_copy_bits": 48},
            "SWREV-SYSFW": {"encoded_bits": 96, "single_copy_bits": 48},
            "SWREV-BOARDCONFIG": {"encoded_bits": 128, "single_copy_bits": 64},
        },
        "properties": {
            "double_redundancy": True,
            "usage": "optional",
            "factory_initial_value": 1,
            "nonzero_required_if_revision_checks_are_used": True,
        },
        "encoding_generation": "NOT_IMPLEMENTED",
        "execution": "OFFLINE_ONLY",
        "note": "Toolkit eFuse bit encoding'i üretmez ve SWREV yazma işlemi yapmaz.",
    }
