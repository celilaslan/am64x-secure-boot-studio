from __future__ import annotations

"""Display-oriented semantic models for complex Studio workflows.

These helpers are intentionally pure Python. They never read secret values, execute target
operations, infer missing addresses/IDs, or convert an offline result into hardware evidence.
Qt pages consume these models to render diagrams/cards while tests lock the semantics.
"""

from typing import Any, Iterable


_VALID_STATUS = {"PASS", "FAIL", "PARTIAL", "NOT_CHECKED", "WARN", "INFO", "ERROR"}


def _status(value: Any, default: str = "INFO") -> str:
    text = str(value or default)
    return text if text in _VALID_STATUS else default


def _check_status(checks: Iterable[dict[str, Any]], ids: set[str], *, missing: str = "NOT_CHECKED") -> str:
    rows = [x for x in checks if isinstance(x, dict) and str(x.get("check")) in ids]
    if not rows:
        return missing
    states = {_status(x.get("status")) for x in rows}
    if "FAIL" in states or "ERROR" in states:
        return "FAIL"
    if "WARN" in states or "PARTIAL" in states:
        return "PARTIAL"
    if states <= {"PASS", "INFO"}:
        return "PASS"
    return "NOT_CHECKED"


def _part_status(part: dict[str, Any] | None, relevant: set[str] | None = None) -> str:
    if not part:
        return "NOT_CHECKED"
    checks = [x for x in part.get("checks", []) if isinstance(x, dict)]
    if relevant is not None:
        checks = [x for x in checks if str(x.get("check")) in relevant]
    if not checks:
        return "INFO"
    return _check_status(checks, {str(x.get("check")) for x in checks})


def sdk_consumer_chain_model(result: dict[str, Any]) -> dict[str, Any]:
    """Render ENC_ENABLED and ENC_SBL_ENABLED as separate source-to-consumer chains."""
    inputs = result.get("inputs") if isinstance(result.get("inputs"), dict) else {}
    cross = [x for x in result.get("cross_checks", []) if isinstance(x, dict)]

    dev = inputs.get("devconfig") if isinstance(inputs.get("devconfig"), dict) else None
    app_make = inputs.get("app_makefile") if isinstance(inputs.get("app_makefile"), dict) else None
    sbl_make = inputs.get("sbl_makefile") if isinstance(inputs.get("sbl_makefile"), dict) else None
    app_tool = inputs.get("app_tool") if isinstance(inputs.get("app_tool"), dict) else None
    rom_tool = inputs.get("rom_tool") if isinstance(inputs.get("rom_tool"), dict) else None

    dev_app = _part_status(dev, {"devconfig_enc_enabled", "devconfig_app_encryption_key"})
    dev_sbl = _part_status(dev, {"devconfig_enc_sbl_enabled", "devconfig_app_encryption_key"})
    if dev and dev_app == "INFO":
        dev_app = "PASS"
    if dev and dev_sbl == "INFO":
        dev_sbl = "PASS"

    app_status = _part_status(app_make, {"application_encryption_selector", "application_encryption_options"})
    sbl_status = _part_status(sbl_make, {"sbl_encryption_selector", "sbl_encryption_options"})
    app_tool_status = _part_status(app_tool, {"application_cli_contract", "application_encryption_algorithm", "application_encryption_oid", "application_integrity_oid"})
    rom_tool_status = _part_status(rom_tool, {"rom_cli_contract", "rom_encryption_algorithm", "rom_sbl_encryption_oid", "rom_combined_image_oid"})

    separation = _check_status(cross, {"separate_encryption_control_chains"})

    return {
        "title": "SDK encryption consumer chain",
        "status": _status(result.get("status"), "INFO"),
        "lanes": [
            {
                "label": "Application encryption",
                "status": app_status if app_status != "NOT_CHECKED" else dev_app,
                "nodes": [
                    {"label": "devconfig.mak", "detail": "ENC_ENABLED", "status": dev_app},
                    {"label": "Application Makefile", "detail": "--enc / --enckey mapping", "status": app_status},
                    {"label": "appimage_x509_cert_gen.py", "detail": "AES-256-CBC · OID .1.4 · integrity OID .1.34", "status": app_tool_status},
                    {"label": "Application image", "detail": "certificate + payload/ciphertext", "status": "INFO" if app_tool_status != "FAIL" else "FAIL"},
                ],
            },
            {
                "label": "ROM/SBL encryption",
                "status": sbl_status if sbl_status != "NOT_CHECKED" else dev_sbl,
                "nodes": [
                    {"label": "devconfig.mak", "detail": "ENC_SBL_ENABLED", "status": dev_sbl},
                    {"label": "SBL Makefile", "detail": "--sbl-enc / --enc-key mapping", "status": sbl_status},
                    {"label": "rom_image_gen.py", "detail": "SBL encryption · OID .1.10", "status": rom_tool_status},
                    {"label": "ROM combined image", "detail": "certificate + SBL + SYSFW + inner cert + BoardCfg", "status": "INFO" if rom_tool_status != "FAIL" else "FAIL"},
                ],
            },
        ],
        "callouts": [
            {"status": separation, "text": "ENC_ENABLED ve ENC_SBL_ENABLED farklı artifact katmanlarını kontrol eder."},
            {"status": "INFO", "text": "Static source mapping build veya hardware security verification değildir."},
        ],
    }


def provisioning_visual_model(result: dict[str, Any]) -> dict[str, Any]:
    """Visualize only non-secret provisioning roles and offline state."""
    key_count = result.get("key_count")
    key_revision = result.get("key_revision")
    active = result.get("active_key_context") or "Belirlenmedi"
    public = result.get("public_key_material") if isinstance(result.get("public_key_material"), dict) else {}
    secret_checks = result.get("secret_format_checks") if isinstance(result.get("secret_format_checks"), dict) else {}
    checks = [x for x in result.get("checks", []) if isinstance(x, dict)]

    smpk_status = _check_status(checks, {"smpk_rsa4096", "smpkh_sha512", "smpk_public_der"})
    bmpk_status = _check_status(checks, {"bmpk_rsa4096", "bmpkh_sha512", "bmpk_public_der", "bmpk_key_count_consistency"})
    smek_status = _status((secret_checks.get("smek") or {}).get("status"), "NOT_CHECKED") if isinstance(secret_checks.get("smek"), dict) else "NOT_CHECKED"
    bmek_status = _status((secret_checks.get("bmek") or {}).get("status"), "NOT_CHECKED") if isinstance(secret_checks.get("bmek"), dict) else "NOT_CHECKED"

    primary_detail = "RSA-4096 public DER → SMPKH candidate" if "smpk" in public else "SMPK public material henüz doğrulanmadı"
    backup_expected = key_count == 2
    backup_detail = "RSA-4096 public DER → BMPKH candidate" if "bmpk" in public else ("Backup set profile'da bekleniyor" if backup_expected else "Backup set kullanılmıyor")

    return {
        "title": "HS-FS → HS-SE offline provisioning hazırlığı",
        "status": _status(result.get("status"), "INFO"),
        "lanes": [
            {
                "label": "Primary customer key set",
                "nodes": [
                    {"label": "SMPK", "detail": primary_detail, "status": smpk_status},
                    {"label": "SMEK", "detail": "256-bit secret format check; value/hash gösterilmez", "status": smek_status},
                ],
            },
            {
                "label": "Backup customer key set",
                "nodes": [
                    {"label": "BMPK", "detail": backup_detail, "status": bmpk_status if backup_expected else "INFO"},
                    {"label": "BMEK", "detail": "256-bit optional backup secret", "status": bmek_status if backup_expected else "INFO"},
                ],
            },
            {
                "label": "Revision selection",
                "nodes": [
                    {"label": f"KEYCNT = {key_count if key_count is not None else '—'}", "detail": "Programlanan customer key-set sayısı", "status": _check_status(checks, {"key_count"})},
                    {"label": f"KEYREV = {key_revision if key_revision is not None else '—'}", "detail": f"Active context: {active}", "status": _check_status(checks, {"key_revision"})},
                ],
            },
        ],
        "callouts": [
            {"status": "INFO", "text": "Private/symmetric key değeri, secret path veya secret hash bu görsel modele girmez."},
            {"status": "NOT_CHECKED", "text": "OTP Keywriter, eFuse programming ve HS-FS→HS-SE transition çalıştırılmaz."},
        ],
    }


def key_revision_visual_model(result: dict[str, Any]) -> dict[str, Any]:
    """Display the current and requested active customer key context without implying a write."""
    current = result.get("active_key_context") if isinstance(result.get("active_key_context"), dict) else None
    requested = result.get("requested_state") if isinstance(result.get("requested_state"), dict) else None
    key_count = result.get("key_count")
    current_rev = result.get("key_revision")

    current_label = current.get("label") if current else ("No customer key context" if key_count == 0 else "Invalid / unresolved")
    current_status = _status(result.get("status"), "INFO")
    nodes = [
        {"label": f"KEYCNT {key_count}", "detail": "Available customer key sets", "status": current_status},
        {"label": f"Current KEYREV {current_rev if current_rev is not None else '—'}", "detail": str(current_label), "status": current_status},
    ]
    if requested:
        req_context = requested.get("active_key_context") if isinstance(requested.get("active_key_context"), dict) else None
        nodes.append({
            "label": f"Proposed KEYREV {requested.get('key_revision')}",
            "detail": str((req_context or {}).get("label") or requested.get("detail") or "Unresolved"),
            "status": _status(requested.get("status"), "INFO"),
        })
        nodes.append({
            "label": "Target write",
            "detail": "NOT EXECUTED · feasibility NOT CHECKED",
            "status": "NOT_CHECKED",
        })
    return {
        "title": "KEYREV active-key model",
        "status": current_status,
        "lanes": [{"label": "Offline state model", "nodes": nodes}],
        "callouts": [{"status": "INFO", "text": "Valid state ≠ target write authorization veya provisioning success."}],
    }


def swrev_visual_model(result: dict[str, Any]) -> dict[str, Any]:
    decision = str(result.get("decision") or "NO_DECISION")
    source_defined = bool(result.get("decision_is_source_defined"))
    return {
        "title": "SWREV comparison",
        "status": _status(result.get("status"), "INFO"),
        "lanes": [{
            "label": str(result.get("context") or "context"),
            "nodes": [
                {"label": f"Reference {result.get('reference_revision', '—')}", "detail": str(result.get("reference_meaning") or "Reference value"), "status": "INFO"},
                {"label": f"Certificate {result.get('certificate_revision', '—')}", "detail": "Certificate SWREV", "status": "INFO"},
                {"label": decision, "detail": str(result.get("decision_basis") or "No source-defined enforcement decision modeled"), "status": "PASS" if source_defined else "NOT_CHECKED"},
            ],
        }],
        "callouts": [{"status": "NOT_CHECKED", "text": "Signature, integrity, active Root of Trust ve target acceptance ayrı kontrollerdir."}],
    }


def boardcfg_policy_visual_model(result: dict[str, Any]) -> dict[str, Any]:
    normalized = result.get("normalized") if isinstance(result.get("normalized"), dict) else {}
    secure = normalized.get("secure_debug") if isinstance(normalized.get("secure_debug"), dict) else {}
    otp = normalized.get("extended_otp") if isinstance(normalized.get("extended_otp"), dict) else {}
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    checks = [x for x in result.get("checks", []) if isinstance(x, dict)]

    unlock = summary.get("runtime_jtag_unlock") or "UNKNOWN"
    wildcard = summary.get("wildcard_uid_policy") or "UNKNOWN"
    hosts = secure.get("jtag_unlock_hosts") if isinstance(secure.get("jtag_unlock_hosts"), list) else []
    write_host = otp.get("write_host")

    return {
        "title": "Security BoardCfg policy map",
        "status": _status(result.get("status"), "INFO"),
        "lanes": [
            {
                "label": "Secure Debug runtime policy",
                "nodes": [
                    {"label": f"JTAG unlock {unlock}", "detail": "Runtime BoardCfg permission", "status": _check_status(checks, {"allow_jtag_unlock"}, missing="INFO")},
                    {"label": f"Wildcard UID {wildcard}", "detail": "UID match policy", "status": _check_status(checks, {"allow_wildcard_unlock"}, missing="INFO")},
                    {"label": f"Allowed hosts: {len(hosts)}", "detail": "Host IDs profile'dan; SoC meaning tahmin edilmez", "status": _check_status(checks, {"jtag_unlock_hosts"}, missing="INFO")},
                ],
            },
            {
                "label": "Revision writer policy",
                "nodes": [
                    {"label": f"write_host = {write_host if write_host is not None else '—'}", "detail": "TISCI_MSG_WRITE_SWREV/KEYREV requester policy", "status": _check_status(checks, {"otp_write_host"}, missing="NOT_CHECKED")},
                    {"label": "Secure Proxy mapping", "detail": "Exact SoC host/thread map olmadan doğrulanmaz", "status": _check_status(checks, {"otp_write_host_secure_proxy_mapping"}, missing="NOT_CHECKED")},
                ],
            },
        ],
        "callouts": [{"status": "NOT_CHECKED", "text": "BoardCfg target'a gönderilmez; debug unlock, SWREV/KEYREV write ve OTP/eFuse execution yoktur."}],
    }


def writer_authorization_visual_model(result: dict[str, Any]) -> dict[str, Any]:
    requester = result.get("requester_host")
    configured = result.get("configured_write_host")
    decision = str(result.get("decision") or "INDETERMINATE")
    return {
        "title": "Revision writer authorization",
        "status": _status(result.get("status"), "INFO"),
        "lanes": [{
            "label": "Offline BoardCfg policy",
            "nodes": [
                {"label": f"Requester Host {requester if requester is not None else '—'}", "detail": "User-supplied Host ID", "status": "INFO"},
                {"label": f"Configured write_host {configured if configured is not None else '—'}", "detail": "BoardCfg profile value", "status": "INFO" if configured is not None else "NOT_CHECKED"},
                {"label": decision, "detail": str(result.get("detail") or "Policy decision"), "status": "PASS" if decision == "AUTHORIZED_BY_BOARDCFG" else ("FAIL" if decision == "NOT_AUTHORIZED_BY_BOARDCFG" else "NOT_CHECKED")},
            ],
        }],
        "callouts": [{"status": "NOT_CHECKED", "text": "TISCI write request ve eFuse operation çalıştırılmaz."}],
    }


def secure_debug_visual_model(result: dict[str, Any]) -> dict[str, Any]:
    """Visualize certificate → BoardCfg policy → target prerequisites without implying unlock."""
    checks = [x for x in result.get("checks", []) if isinstance(x, dict)]
    decision = str(result.get("policy_decision") or "INDETERMINATE")
    cert_status = _check_status(checks, {"certificate_type", "software_revision_extension", "debug_extension"})
    policy_status = _check_status(checks, {"allow_jtag_unlock", "min_cert_rev", "soc_uid_policy", "jtag_unlock_host"})
    prereq_status = _check_status(checks, {"jtag_efuse_connectivity", "active_customer_root_of_trust"})
    decision_status = {
        "POLICY_ALLOWS_REQUEST": "PASS",
        "REJECT_BY_POLICY": "FAIL",
        "INVALID_DEBUG_CERTIFICATE": "FAIL",
        "INVALID_BOARDCFG_PROFILE": "FAIL",
        "INDETERMINATE": "NOT_CHECKED",
    }.get(decision, "INFO")
    transport = str(result.get("transport") or "—")
    return {
        "title": "Secure Debug offline policy flow",
        "status": _status(result.get("status"), "INFO"),
        "lanes": [{
            "label": "Certificate ve runtime policy",
            "nodes": [
                {"label": "Secure Debug X.509", "detail": "SWREV + Debug Extension", "status": cert_status},
                {"label": "Security BoardCfg", "detail": "JTAG unlock · min cert rev · UID/host policy", "status": policy_status},
                {"label": f"Transport: {transport}", "detail": "TISCI requester host policy yalnız TISCI context'te uygulanır", "status": "INFO"},
                {"label": "Target prerequisites", "detail": "JTAG eFuse + active customer Root of Trust", "status": prereq_status},
                {"label": decision, "detail": "Offline policy decision; target acceptance değildir", "status": decision_status},
            ],
        }],
        "callouts": [
            {"status": "NOT_CHECKED", "text": "JTAG unlock/debug port opening çalıştırılmaz."},
            {"status": "NOT_CHECKED", "text": "Active SMPK/BMPK trust ve target acceptance (certificate/signature) doğrulanmaz."},
        ],
    }


def generic_data_visual_model(result: dict[str, Any]) -> dict[str, Any]:
    """Visualize generalized-authentication package semantics for profile/build/verify results."""
    mode = str(result.get("mode") or ("encrypted+signed" if result.get("encrypted") else "signed"))
    checks = [x for x in result.get("checks", []) if isinstance(x, dict)]
    overall = _status(result.get("status"), "INFO")
    encrypted = mode == "encrypted+signed" or bool((result.get("encryption") or {}).get("enabled"))
    integrity = _check_status(checks, {"appended_payload_sha512_binding", "image_data_integrity", "generic_payload_integrity"}, missing="INFO")
    extset = _check_status(checks, {"generalized_authentication_extension_set", "software_revision_present_nonzero"}, missing="INFO")
    decrypt = _check_status(checks, {"decryption_random_string", "decrypted_original_prefix", "decrypted_zero_padding"}, missing="NOT_CHECKED")
    nodes = [
        {"label": "Generic binary", "detail": "Boot Extension kullanılmaz", "status": "INFO"},
    ]
    if encrypted:
        nodes.extend([
            {"label": "Prepare + AES-256-CBC", "detail": "zero padding + 32-byte random string + 16-byte IV", "status": decrypt if decrypt != "NOT_CHECKED" else "INFO"},
            {"label": "Ciphertext", "detail": "Image Integrity SHA-512 ciphertext üzerinde", "status": integrity},
        ])
    else:
        nodes.append({"label": "Payload", "detail": "Image Integrity SHA-512 payload üzerinde", "status": integrity})
    nodes.extend([
        {"label": "X.509 certificate", "detail": "SWREV + Image Integrity + Load" + (" + Encryption" if encrypted else ""), "status": extset},
        {"label": "Secure package", "detail": "DER certificate + appended payload/ciphertext", "status": overall},
        {"label": "TISCI_MSG_PROC_AUTH_BOOT", "detail": "Target API call bu toolkit tarafından çalıştırılmaz", "status": "NOT_CHECKED"},
    ])
    return {
        "title": "Generalized Authentication package flow",
        "status": overall,
        "lanes": [{"label": mode, "nodes": nodes}],
        "callouts": [
            {"status": "INFO", "text": "Generic data certificate processor Boot Extension taşımaz."},
            {"status": "NOT_CHECKED", "text": "Target authentication/decryption acceptance ve hardware enforcement doğrulanmaz."},
        ],
    }
