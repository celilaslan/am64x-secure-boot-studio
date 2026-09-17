from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

PROJECT_REFERENCE_HASHES = {
    "devconfig": "286cfcf740fb57461fd1aa6221a302541e68ec55425d5aa5f5bb57b2cb625c4a",
    "app_makefile": "5531e8611af2d75a569ec139ef3545b374164a34ce63c2b0e52eccaccf7c09db",
    "sbl_makefile": "bf3128916468e24bde4aa679b30612f62d1365c11156a2f804d79d081c4019e8",
    "app_tool": "48fb8b12375dc38cedb702db007ac8ba1a61376f72d5da28a9e75e29ce584efd",
    "rom_tool": "c9537fbed70bfee74dc0b4eb2558e83263ee890c8152a986f478146308cb839b",
}

_SAFE_ENUM_VARS = {"DEVICE_TYPE", "ENC_ENABLED", "ENC_SBL_ENABLED"}
_KEY_VARS = {"APP_SIGNING_KEY", "APP_ENCRYPTION_KEY", "CUST_MPK", "CUST_MEK", "ROM_DEGENERATE_KEY", "APP_DEGENERATE_KEY"}
_TRACKED_VARS = _SAFE_ENUM_VARS | {"APP_SIGNING_KEY", "APP_ENCRYPTION_KEY"}

_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*([?:+]?=)\s*(.*?)\s*$")
_RAW_SECRET_HEX_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
_PRIVATE_MARKERS = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _display_path(path: Path) -> str:
    """Machine-specific home prefix'i <HOME> olarak gösterir."""
    try:
        resolved = path.expanduser().resolve()
    except OSError:
        resolved = path.expanduser()
    home = Path.home().resolve()
    try:
        rel = resolved.relative_to(home)
        return f"<HOME>/{rel.as_posix()}"
    except ValueError:
        return str(resolved)


def _read_text(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(path)
    return path.read_text(encoding="utf-8", errors="replace")


def _noncomment_lines(text: str) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    for no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        # Make/Python satırlarında inline comment için kaba ama secret-safe görünüm.
        line = raw.split("#", 1)[0].rstrip()
        if line.strip():
            rows.append((no, line))
    return rows


def _safe_assignment_value(name: str, value: str) -> dict[str, Any]:
    clean = value.strip()
    if name in _SAFE_ENUM_VARS:
        low = clean.lower()
        if name == "DEVICE_TYPE" and clean in {"GP", "HS"}:
            return {"state": "KNOWN_VALUE", "value": clean}
        if name in {"ENC_ENABLED", "ENC_SBL_ENABLED"} and low in {"yes", "no"}:
            return {"state": "KNOWN_VALUE", "value": low}
        if not clean:
            return {"state": "EMPTY"}
        return {"state": "CUSTOM_OR_UNRESOLVED"}

    # Key yönlendirmelerinde yalnız tanınan Make variable referansları gösterilir.
    refs = re.findall(r"\$\(([^)]+)\)|\$\{([^}]+)\}", clean)
    names = [a or b for a, b in refs]
    known = [n for n in names if n in _KEY_VARS]
    if clean == "":
        return {"state": "EMPTY"}
    if known and len(known) == len(names) and ("/" not in clean and "\\" not in clean):
        return {"state": "VARIABLE_REFERENCE", "references": known}
    return {"state": "SET_REDACTED"}


def _extract_assignments(text: str) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {name: [] for name in _TRACKED_VARS}
    for no, line in _noncomment_lines(text):
        m = _ASSIGN_RE.match(line)
        if not m:
            continue
        name, op, value = m.groups()
        if name not in _TRACKED_VARS:
            continue
        row = {"line": no, "operator": op}
        row.update(_safe_assignment_value(name, value))
        out[name].append(row)
    return out


def _last_assignment(assignments: dict[str, list[dict[str, Any]]], name: str) -> dict[str, Any] | None:
    rows = assignments.get(name) or []
    return rows[-1] if rows else None


def _pattern_check(text: str, check: str, patterns: list[str], *, all_required: bool = True) -> dict[str, Any]:
    hits = {p: (p in text) for p in patterns}
    ok = all(hits.values()) if all_required else any(hits.values())
    return {
        "check": check,
        "status": "PASS" if ok else "FAIL",
        "patterns": hits,
    }


def _secret_hygiene_findings(text: str, role: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for no, raw in enumerate(text.splitlines(), 1):
        upper = raw.upper()
        if any(marker in upper for marker in _PRIVATE_MARKERS):
            findings.append({
                "severity": "ERROR",
                "code": "PRIVATE_KEY_MATERIAL_IN_SOURCE",
                "role": role,
                "line": no,
                "detail": "Private-key PEM marker source/config dosyasında bulundu; içerik raporlanmadı.",
            })
        if _RAW_SECRET_HEX_RE.search(raw) and re.search(r"(?i)\b(MEK|ENCKEY|ENCRYPTION_KEY|CUST_MEK|KEY)\b", raw):
            findings.append({
                "severity": "ERROR",
                "code": "POTENTIAL_RAW_KEY_LITERAL",
                "role": role,
                "line": no,
                "detail": "Key/MEK bağlamında 64-hex literal görüldü; değer raporlanmadı.",
            })
        # Make/config recipe içinde key argümanı doğrudan literal path/value ile kurulmuşsa yalnız satırı bildir.
        if role in {"devconfig", "app_makefile", "sbl_makefile"} and re.search(
            r"(?:--enckey|--enc-key|--key)\s+(?!\$\(|\$\{|['\"]?\$)[^\s\\]+", raw
        ):
            findings.append({
                "severity": "WARNING",
                "code": "LITERAL_KEY_ARGUMENT",
                "role": role,
                "line": no,
                "detail": "Signing/encryption key argümanında Make variable yerine literal girdi görülüyor; path/value raporlanmadı.",
            })
    return findings


def _file_record(path: Path, role: str) -> dict[str, Any]:
    digest = _sha256(path)
    reference = PROJECT_REFERENCE_HASHES.get(role)
    status = None
    if reference is not None:
        status = "MATCH_PROJECT_REFERENCE" if digest == reference else "DIFFERS_FROM_PROJECT_REFERENCE"
    return {
        "role": role,
        "path": _display_path(path),
        "sha256": digest,
        "reference_sha256": reference,
        "reference_status": status,
    }


def _lint_devconfig(path: Path) -> dict[str, Any]:
    text = _read_text(path)
    assignments = _extract_assignments(text)
    checks: list[dict[str, Any]] = []

    for name in ["DEVICE_TYPE", "ENC_ENABLED", "ENC_SBL_ENABLED"]:
        row = _last_assignment(assignments, name)
        checks.append({
            "check": f"{name}_defined",
            "status": "PASS" if row else "FAIL",
            "detail": row if row else "Tanım bulunamadı.",
        })

    # Key variable isimleri bulunmalı; gerçek path/value asla raporlanmaz.
    for name in ["APP_SIGNING_KEY", "APP_ENCRYPTION_KEY"]:
        rows = assignments.get(name) or []
        checks.append({
            "check": f"{name}_routing_present",
            "status": "PASS" if rows else "FAIL",
            "assignments": rows,
        })

    return {
        "file": _file_record(path, "devconfig"),
        "assignments": assignments,
        "checks": checks,
        "secret_hygiene": _secret_hygiene_findings(text, "devconfig"),
        "notes": [
            "DEVICE_TYPE build selector'dır; fiziksel GP/HS-FS/HS-SE lifecycle proof değildir.",
            "ENC_ENABLED ve ENC_SBL_ENABLED farklı image katmanlarını kontrol eder.",
            "Key routing değerleri yalnız tanınan Make variable referanslarıysa gösterilir; custom path/value redacted bırakılır.",
        ],
    }


def _lint_app_makefile(path: Path) -> dict[str, Any]:
    text = _read_text(path)
    checks = [
        _pattern_check(text, "application_signer_consumer", ["appimage_x509_cert_gen.py", "APP_SIGNING_KEY"]),
        _pattern_check(text, "application_encryption_selector", ["ENC_ENABLED"]),
        _pattern_check(text, "application_encryption_options", ["--enc", "--enckey", "APP_ENCRYPTION_KEY"]),
    ]
    return {
        "file": _file_record(path, "app_makefile"),
        "checks": checks,
        "secret_hygiene": _secret_hygiene_findings(text, "app_makefile"),
    }


def _lint_sbl_makefile(path: Path, intent: str) -> dict[str, Any]:
    text = _read_text(path)
    checks = [
        _pattern_check(text, "rom_generator_consumer", ["rom_image_gen.py", "BOOTIMAGE_CERT_KEY"]),
        _pattern_check(text, "sbl_encryption_selector", ["ENC_SBL_ENABLED"]),
        _pattern_check(text, "sbl_encryption_options", ["--sbl-enc", "--enc-key", "APP_ENCRYPTION_KEY"]),
    ]
    full_debug = "DBG_FULL_ENABLE" in text or bool(re.search(r"--debug\s+[^\s\\]+", text))
    debug_check: dict[str, Any] = {
        "check": "rom_full_debug_option",
        "detected": full_debug,
        "intent": intent,
    }
    if intent == "production" and full_debug:
        debug_check.update({
            "status": "FAIL",
            "detail": "Production intent seçildi; SDK dokümanı development için kullanılan full debug seçeneğinin production'a geçerken kaldırılmasını ister.",
        })
    elif full_debug:
        debug_check.update({"status": "PASS", "detail": "Development intent ile full debug seçeneği uyumlu."})
    else:
        debug_check.update({"status": "PASS", "detail": "Full debug seçeneği bulunmadı."})
    checks.append(debug_check)

    return {
        "file": _file_record(path, "sbl_makefile"),
        "checks": checks,
        "secret_hygiene": _secret_hygiene_findings(text, "sbl_makefile"),
    }


def _lint_app_tool(path: Path) -> dict[str, Any]:
    text = _read_text(path)
    checks = [
        _pattern_check(text, "application_cli_contract", ["--authtype", "--enc", "--enckey"]),
        _pattern_check(text, "application_encryption_algorithm", ["aes-256-cbc", "-K"]),
        _pattern_check(text, "application_encryption_oid", ["1.3.6.1.4.1.294.1.4"]),
        _pattern_check(text, "application_integrity_oid", ["1.3.6.1.4.1.294.1.34", "sha512"]),
    ]
    return {
        "file": _file_record(path, "app_tool"),
        "checks": checks,
        "secret_hygiene": _secret_hygiene_findings(text, "app_tool"),
    }


def _lint_rom_tool(path: Path) -> dict[str, Any]:
    text = _read_text(path)
    checks = [
        _pattern_check(text, "rom_cli_contract", ["--sbl-enc", "--enc-key"]),
        _pattern_check(text, "rom_encryption_algorithm", ["aes-256-cbc", "-K"]),
        _pattern_check(text, "rom_combined_image_oid", ["1.3.6.1.4.1.294.1.9"]),
        _pattern_check(text, "rom_sbl_encryption_oid", ["1.3.6.1.4.1.294.1.10"]),
    ]
    return {
        "file": _file_record(path, "rom_tool"),
        "checks": checks,
        "secret_hygiene": _secret_hygiene_findings(text, "rom_tool"),
    }


def _parse_make_db(path: Path) -> dict[str, Any]:
    text = _read_text(path)
    assignments = _extract_assignments(text)
    resolved: dict[str, Any] = {}
    for name in sorted(_TRACKED_VARS):
        row = _last_assignment(assignments, name)
        if row:
            resolved[name] = row
    return {
        "file": {
            "path": _display_path(path),
            "sha256": _sha256(path),
        },
        "resolved_variables": resolved,
        "note": "Bu dosya toolkit tarafından üretilmedi; yalnız önceden alınmış Make database çıktısı read-only olarak ayrıştırıldı.",
    }


def _cross_checks(parts: dict[str, Any], make_db: dict[str, Any] | None, intent: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    app = parts.get("app_makefile")
    sbl = parts.get("sbl_makefile")

    if app and sbl:
        app_ok = all(c["status"] == "PASS" for c in app["checks"] if c["check"] in {"application_encryption_selector", "application_encryption_options"})
        sbl_ok = all(c["status"] == "PASS" for c in sbl["checks"] if c["check"] in {"sbl_encryption_selector", "sbl_encryption_options"})
        checks.append({
            "check": "separate_encryption_control_chains",
            "status": "PASS" if app_ok and sbl_ok else "FAIL",
            "detail": "ENC_ENABLED -> application signer ve ENC_SBL_ENABLED -> ROM/SBL generator zincirleri ayrı consumer olarak kontrol edildi.",
        })

    if make_db:
        rv = make_db["resolved_variables"]
        enc = rv.get("ENC_ENABLED")
        enc_sbl = rv.get("ENC_SBL_ENABLED")
        dtype = rv.get("DEVICE_TYPE")
        signing = rv.get("APP_SIGNING_KEY")
        enckey = rv.get("APP_ENCRYPTION_KEY")

        if enc and enc.get("state") == "KNOWN_VALUE" and enc.get("value") == "yes":
            checks.append({
                "check": "resolved_application_encryption_has_key",
                "status": "PASS" if enckey and enckey.get("state") not in {"EMPTY"} else "FAIL",
                "detail": "Resolved ENC_ENABLED=yes ise APP_ENCRYPTION_KEY boş olmamalıdır; değer/path raporlanmaz.",
            })
        if dtype and dtype.get("state") == "KNOWN_VALUE" and dtype.get("value") == "HS":
            checks.append({
                "check": "resolved_hs_signing_key_present",
                "status": "PASS" if signing and signing.get("state") not in {"EMPTY"} else "FAIL",
                "detail": "Resolved DEVICE_TYPE=HS ise APP_SIGNING_KEY boş olmamalıdır; lifecycle sonucu çıkarılmaz.",
            })
            if enc_sbl and enc_sbl.get("state") == "KNOWN_VALUE" and enc_sbl.get("value") == "yes":
                checks.append({
                    "check": "resolved_hs_sbl_encryption_has_key",
                    "status": "PASS" if enckey and enckey.get("state") not in {"EMPTY"} else "FAIL",
                    "detail": "Resolved HS + ENC_SBL_ENABLED=yes ise APP_ENCRYPTION_KEY boş olmamalıdır.",
                })

    checks.append({
        "check": "execution_boundary",
        "status": "PASS",
        "detail": "Linter source/config dosyalarını read-only inceler; build, signing, OTP/eFuse, debug unlock veya lifecycle işlemi çalıştırmaz.",
    })
    return checks


def lint_sdk_security(
    *,
    devconfig: Path | None = None,
    app_makefile: Path | None = None,
    sbl_makefile: Path | None = None,
    app_tool: Path | None = None,
    rom_tool: Path | None = None,
    make_db: Path | None = None,
    intent: str = "development",
    report: Path | None = None,
) -> dict[str, Any]:
    if intent not in {"development", "production"}:
        raise ValueError("intent development veya production olmalıdır")
    supplied = [devconfig, app_makefile, sbl_makefile, app_tool, rom_tool, make_db]
    if not any(supplied):
        raise ValueError("En az bir SDK/config/source dosyası verilmelidir")

    parts: dict[str, Any] = {}
    if devconfig:
        parts["devconfig"] = _lint_devconfig(devconfig)
    if app_makefile:
        parts["app_makefile"] = _lint_app_makefile(app_makefile)
    if sbl_makefile:
        parts["sbl_makefile"] = _lint_sbl_makefile(sbl_makefile, intent)
    if app_tool:
        parts["app_tool"] = _lint_app_tool(app_tool)
    if rom_tool:
        parts["rom_tool"] = _lint_rom_tool(rom_tool)
    make_db_result = _parse_make_db(make_db) if make_db else None

    findings: list[dict[str, Any]] = []
    failures: list[str] = []
    warnings: list[str] = []
    advisories: list[str] = []

    for role, part in parts.items():
        findings.extend(part.get("secret_hygiene", []))
        for check in part.get("checks", []):
            if check.get("status") == "FAIL":
                failures.append(f"{role}:{check.get('check')}")
        ref_status = part.get("file", {}).get("reference_status")
        if ref_status == "DIFFERS_FROM_PROJECT_REFERENCE":
            advisories.append(f"{role}:project_reference_hash_differs")

    cross = _cross_checks(parts, make_db_result, intent)
    for check in cross:
        if check.get("status") == "FAIL":
            failures.append(f"cross:{check.get('check')}")

    for finding in findings:
        if finding["severity"] == "ERROR":
            failures.append(f"secret_hygiene:{finding['code']}")
        elif finding["severity"] == "WARNING":
            warnings.append(f"secret_hygiene:{finding['code']}")

    expected_full_roles = {"devconfig", "app_makefile", "sbl_makefile", "app_tool", "rom_tool"}
    missing_roles = sorted(expected_full_roles - set(parts))
    if missing_roles:
        warnings.append("partial_input_set")

    if failures:
        status = "FAIL"
    elif warnings:
        status = "PARTIAL"
    else:
        status = "PASS"

    result: dict[str, Any] = {
        "status": status,
        "tool": "sdk_security_linter",
        "intent": intent,
        "inputs": parts,
        "make_database": make_db_result,
        "cross_checks": cross,
        "summary": {
            "failures": failures,
            "warnings": warnings,
            "advisories": advisories,
            "missing_optional_for_full_chain": missing_roles,
        },
        "interpretation": {
            "device_type": "DEVICE_TYPE build selector'dır; physical lifecycle proof değildir.",
            "encryption_controls": "ENC_ENABLED ve ENC_SBL_ENABLED farklı consumer zincirleridir.",
            "build_result": "Static lint sonucu build veya hardware security verification değildir.",
            "source_drift": "Reference SHA farkı tek başına hata değildir; bu sürüme özgü varsayımların yeniden kontrol edilmesi gerektiğini gösterir.",
        },
        "execution": {
            "files_modified": "NO",
            "make_executed": "NO",
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
