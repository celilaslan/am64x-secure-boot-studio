from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .sdk_lint import (
    _display_path,
    _extract_assignments,
    _last_assignment,
    _read_text,
    _secret_hygiene_findings,
    _sha256,
)

_ROLES = ("devconfig", "app_makefile", "sbl_makefile", "app_tool", "rom_tool")


def _bool_features(text: str, mapping: dict[str, str]) -> dict[str, bool]:
    return {name: token in text for name, token in mapping.items()}


def _summarize_assignment(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        return {"state": "NOT_FOUND"}
    # Satır numarası source sürümleri arasında doğal olarak değişebilir; semantic diff'e katılmaz.
    out = {k: v for k, v in row.items() if k != "line"}
    return out


def _devconfig_features(text: str) -> dict[str, Any]:
    assignments = _extract_assignments(text)
    names = ["DEVICE_TYPE", "ENC_ENABLED", "ENC_SBL_ENABLED", "APP_SIGNING_KEY", "APP_ENCRYPTION_KEY"]
    return {
        "assignments": {name: _summarize_assignment(_last_assignment(assignments, name)) for name in names},
    }


def _app_makefile_features(text: str) -> dict[str, Any]:
    return {
        "consumer": _bool_features(text, {
            "appimage_x509_cert_gen": "appimage_x509_cert_gen.py",
            "enc_enabled_selector": "ENC_ENABLED",
            "signing_key_route": "APP_SIGNING_KEY",
            "encryption_key_route": "APP_ENCRYPTION_KEY",
            "enc_option": "--enc",
            "enckey_option": "--enckey",
        })
    }


def _sbl_makefile_features(text: str) -> dict[str, Any]:
    return {
        "consumer": _bool_features(text, {
            "rom_image_gen": "rom_image_gen.py",
            "enc_sbl_enabled_selector": "ENC_SBL_ENABLED",
            "bootimage_cert_key": "BOOTIMAGE_CERT_KEY",
            "encryption_key_route": "APP_ENCRYPTION_KEY",
            "sbl_enc_option": "--sbl-enc",
            "enc_key_option": "--enc-key",
            "full_debug_marker": "DBG_FULL_ENABLE",
            "debug_option": "--debug",
        })
    }


def _app_tool_features(text: str) -> dict[str, Any]:
    low = text.lower()
    return {
        "cli": _bool_features(text, {
            "authtype": "--authtype",
            "enc": "--enc",
            "enckey": "--enckey",
        }),
        "crypto": {
            "aes_256_cbc": "aes-256-cbc" in low,
            "openssl_raw_key_K": "-K" in text,
            "sha512": "sha512" in low,
        },
        "oids": _bool_features(text, {
            "encryption_1_4": "1.3.6.1.4.1.294.1.4",
            "integrity_1_34": "1.3.6.1.4.1.294.1.34",
            "load_1_35": "1.3.6.1.4.1.294.1.35",
            "boot_1_33": "1.3.6.1.4.1.294.1.33",
        }),
        "implementation_markers": _bool_features(text, {
            "openssl_rand_16": "openssl rand 16",
            "openssl_rand_32": "openssl rand 32",
            "test_salt_0000": 'v_TEST_IMAGE_KEY_DERIVE_SALT = "0000"',
            "nopad": "-nopad",
        }),
    }


def _rom_tool_features(text: str) -> dict[str, Any]:
    low = text.lower()
    return {
        "cli": _bool_features(text, {
            "sbl_enc": "--sbl-enc",
            "enc_key": "--enc-key",
            "debug": "--debug",
            "sysfw_inner_cert": "--sysfw-inner-cert",
            "boardcfg_blob": "--boardcfg-blob",
        }),
        "crypto": {
            "aes_256_cbc": "aes-256-cbc" in low,
            "openssl_raw_key_K": "-K" in text,
            "sha512": "sha512" in low,
        },
        "oids": _bool_features(text, {
            "combined_1_9": "1.3.6.1.4.1.294.1.9",
            "sbl_encryption_1_10": "1.3.6.1.4.1.294.1.10",
        }),
        "implementation_markers": _bool_features(text, {
            "openssl_rand_16": "openssl rand 16",
            "openssl_rand_32": "openssl rand 32",
            "nopad": "-nopad",
        }),
    }


_EXTRACTORS: dict[str, Callable[[str], dict[str, Any]]] = {
    "devconfig": _devconfig_features,
    "app_makefile": _app_makefile_features,
    "sbl_makefile": _sbl_makefile_features,
    "app_tool": _app_tool_features,
    "rom_tool": _rom_tool_features,
}


def _flatten(prefix: str, value: Any, out: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for key in sorted(value):
            _flatten(f"{prefix}.{key}" if prefix else key, value[key], out)
    else:
        out[prefix] = value


def _semantic_changes(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    flat_old: dict[str, Any] = {}
    flat_new: dict[str, Any] = {}
    _flatten("", old, flat_old)
    _flatten("", new, flat_new)
    changes: list[dict[str, Any]] = []
    for key in sorted(set(flat_old) | set(flat_new)):
        before = flat_old.get(key, "<MISSING>")
        after = flat_new.get(key, "<MISSING>")
        if before != after:
            changes.append({"field": key, "before": before, "after": after})
    return changes


def _side_record(path: Path, role: str) -> dict[str, Any]:
    text = _read_text(path)
    return {
        "path": _display_path(path),
        "sha256": _sha256(path),
        "features": _EXTRACTORS[role](text),
        "secret_hygiene": _secret_hygiene_findings(text, role),
    }


def _compare_role(role: str, old_path: Path, new_path: Path) -> dict[str, Any]:
    old = _side_record(old_path, role)
    new = _side_record(new_path, role)
    same_hash = old["sha256"] == new["sha256"]
    changes = _semantic_changes(old["features"], new["features"])

    if same_hash:
        classification = "IDENTICAL"
        review = "NOT_REQUIRED"
    elif changes:
        classification = "MAPPED_SECURITY_BEHAVIOR_CHANGED"
        review = "REQUIRED"
    else:
        classification = "CONTENT_CHANGED_NO_MAPPED_SECURITY_CHANGE"
        review = "RECOMMENDED"

    return {
        "role": role,
        "old": old,
        "new": new,
        "same_sha256": same_hash,
        "classification": classification,
        "review": review,
        "semantic_changes": changes,
    }


def compare_sdk_security(
    *,
    old_devconfig: Path | None = None,
    new_devconfig: Path | None = None,
    old_app_makefile: Path | None = None,
    new_app_makefile: Path | None = None,
    old_sbl_makefile: Path | None = None,
    new_sbl_makefile: Path | None = None,
    old_app_tool: Path | None = None,
    new_app_tool: Path | None = None,
    old_rom_tool: Path | None = None,
    new_rom_tool: Path | None = None,
    old_label: str = "old",
    new_label: str = "new",
    report: Path | None = None,
) -> dict[str, Any]:
    pairs = {
        "devconfig": (old_devconfig, new_devconfig),
        "app_makefile": (old_app_makefile, new_app_makefile),
        "sbl_makefile": (old_sbl_makefile, new_sbl_makefile),
        "app_tool": (old_app_tool, new_app_tool),
        "rom_tool": (old_rom_tool, new_rom_tool),
    }

    supplied = [role for role, pair in pairs.items() if any(pair)]
    if not supplied:
        raise ValueError("Karşılaştırma için en az bir old/new dosya çifti verilmelidir")

    incomplete = [role for role, (old, new) in pairs.items() if (old is None) != (new is None)]
    if incomplete:
        raise ValueError("Her karşılaştırılan rol için hem old hem new dosyası verilmelidir: " + ", ".join(incomplete))

    comparisons: dict[str, Any] = {}
    required_review: list[str] = []
    recommended_review: list[str] = []
    identical: list[str] = []
    hygiene_errors: list[str] = []
    hygiene_warnings: list[str] = []

    for role, (old, new) in pairs.items():
        if old is None or new is None:
            continue
        row = _compare_role(role, old, new)
        comparisons[role] = row
        if row["review"] == "REQUIRED":
            required_review.append(role)
        elif row["review"] == "RECOMMENDED":
            recommended_review.append(role)
        else:
            identical.append(role)

        for side in ("old", "new"):
            for finding in row[side].get("secret_hygiene", []):
                marker = f"{role}:{side}:{finding['code']}"
                if finding.get("severity") == "ERROR":
                    hygiene_errors.append(marker)
                elif finding.get("severity") == "WARNING":
                    hygiene_warnings.append(marker)

    if hygiene_errors:
        status = "FAIL"
    elif required_review or recommended_review or hygiene_warnings:
        status = "PARTIAL"
    else:
        status = "PASS"

    result: dict[str, Any] = {
        "status": status,
        "tool": "sdk_security_diff",
        "labels": {"old": old_label, "new": new_label},
        "comparisons": comparisons,
        "summary": {
            "security_review_required": required_review,
            "manual_review_recommended": recommended_review,
            "identical": identical,
            "secret_hygiene_errors": hygiene_errors,
            "secret_hygiene_warnings": hygiene_warnings,
        },
        "interpretation": {
            "identical": "SHA-256 aynı; karşılaştırılan dosya byte-for-byte aynıdır.",
            "mapped_change": "Toolkit'in izlediği security/configuration davranışlarından en az biri değişmiştir; source review gerekir.",
            "unmapped_change": "Dosya içeriği değişmiştir ancak izlenen alanlarda fark bulunmamıştır; değişiklik güvenlik açısından önemsiz kabul edilmez, manuel review önerilir.",
            "not_a_proof": "Bu karşılaştırma build sonucu, hardware enforcement veya yeni SDK sürümünün güvenli olduğu sonucunu kanıtlamaz.",
        },
        "execution": {
            "files_modified": "NO",
            "build_executed": "NO",
            "signing_executed": "NO",
            "otp_efuse": "NOT_EXECUTED",
            "debug_unlock": "NOT_EXECUTED",
            "lifecycle_change": "NOT_EXECUTED",
        },
    }

    if report:
        if report.exists():
            raise FileExistsError(f"rapor zaten mevcut: {report}")
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        result["report"] = _display_path(report)

    return result
