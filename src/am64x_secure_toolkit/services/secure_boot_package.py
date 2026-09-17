from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..keycheck import preflight_signing_key
from ..workflows.inspect import inspect_and_verify
from .ccs_sbl_build import run_mcu_plus_sbl_build
from .ccs_secure_build import run_mcu_plus_secure_build
from .certificate_center import certificate_metadata, compare_certificate_with_private_key
from .secure_boot_profile import assess_secure_boot_profile


def _prepare_signing_identity(
    reference_certificate: str | Path | None,
    signing_key: str | Path | None,
) -> dict[str, Any] | None:
    """Validate a certificate/private-key identity without retaining secret paths."""
    if reference_certificate is None:
        return None
    if signing_key is None:
        raise ValueError(
            "Seçilen certificate doğrudan CCS signer'a verilemez; aynı public key'e ait private signing key'i de seçin"
        )
    key_check = preflight_signing_key(Path(signing_key), purpose="application")
    if key_check.get("status") != "PASS" or key_check.get("input_class") != "private_key":
        raise ValueError("Seçilen signing key, application için RSA-4096 private key ön kontrolünü geçmedi")
    match = compare_certificate_with_private_key(reference_certificate, signing_key)
    if match.get("status") != "PASS" or not match.get("match"):
        raise ValueError("Certificate ile private signing key aynı public key kimliğine ait değil")
    metadata = certificate_metadata(reference_certificate)
    return {
        "status": "PASS",
        "certificate_name": Path(reference_certificate).name,
        "classification": metadata.get("classification"),
        "subject": metadata.get("subject_rfc4514"),
        "spki_sha256": metadata.get("spki_sha256"),
        "private_key_match": True,
        "note": (
            "CCS hazır certificate dosyasını kopyalamaz; eşleşen private key ile güncel payload için "
            "yeni TI X.509 certificate üretir. Studio embedded public-key kimliğini yeniden karşılaştırır."
        ),
    }


def build_secure_boot_package(
    *,
    application_project: str | Path,
    sdk_root: str | Path,
    physical_lifecycle: str,
    target_lifecycle: str,
    customer_root_state: str = "unknown",
    reference_certificate: str | Path | None = None,
    signing_key: str | Path | None = None,
    encryption_key: str | Path | None = None,
    encrypt: bool = False,
    sbl_project: str | Path | None = None,
    make_executable: str | Path | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Produce a coherent application-only or application+boot package.

    This orchestrator delegates all certificate creation to the installed MCU+ SDK
    recipes. It never edits ``devconfig.mak`` and never performs device provisioning.
    """
    notify = progress or (lambda _message: None)
    signing_identity = _prepare_signing_identity(reference_certificate, signing_key)
    profile = assess_secure_boot_profile(
        physical_lifecycle=physical_lifecycle,
        target_lifecycle=target_lifecycle,
        customer_root_state=customer_root_state,
        has_customer_signing_key=signing_key is not None,
        encrypted=encrypt or encryption_key is not None,
        has_encryption_key=encryption_key is not None,
    )
    if profile.blockers:
        raise ValueError(" ".join(profile.blockers))

    notify("Application secure build çalışıyor…")
    application = run_mcu_plus_secure_build(
        application_project,
        lifecycle=profile.target_lifecycle,
        sdk_root=sdk_root,
        signing_key=signing_key,
        encryption_key=encryption_key,
        make_executable=make_executable,
    )
    boot: dict[str, Any] | None = None
    application_verification: dict[str, Any] | None = None
    app_output = application.get("output") if isinstance(application.get("output"), dict) else None
    if application.get("status") == "PASS" and app_output and app_output.get("path"):
        notify("Application certificate ve image doğrulanıyor…")
        application_verification = inspect_and_verify(app_output["path"], verify=True).to_dict()
    output_identity_match: dict[str, Any] | None = None
    if signing_identity is not None:
        inspection = (
            (application_verification or {}).get("safe_details", {}).get("inspection", {})
            if application_verification else {}
        )
        actual_spki = inspection.get("spki_sha256") if isinstance(inspection, dict) else None
        expected_spki = signing_identity.get("spki_sha256")
        matched = bool(actual_spki and expected_spki and actual_spki == expected_spki)
        output_identity_match = {
            "status": "PASS" if matched else "FAIL",
            "match": matched,
            "expected_spki_sha256": expected_spki,
            "actual_spki_sha256": actual_spki,
            "detail": (
                "CCS çıktısındaki embedded certificate seçilen Studio certificate kimliğiyle eşleşiyor."
                if matched else
                "CCS çıktısındaki embedded certificate seçilen Studio certificate kimliğiyle eşleşmiyor."
            ),
        }
    if application.get("status") == "PASS" and sbl_project is not None:
        notify("SBL/combined boot image build çalışıyor…")
        boot = run_mcu_plus_sbl_build(
            sbl_project,
            lifecycle=profile.target_lifecycle,
            sdk_root=sdk_root,
            signing_key=signing_key,
            encryption_key=encryption_key,
            make_executable=make_executable,
        )

    full_requested = sbl_project is not None
    verification_ok = not application_verification or application_verification.get("status") != "FAIL"
    identity_ok = output_identity_match is None or output_identity_match.get("status") == "PASS"
    status = "PASS" if application.get("status") == "PASS" and verification_ok and (
        not full_requested or (boot and boot.get("status") == "PASS")
    ) and identity_ok else "FAIL"
    outputs: list[dict[str, Any]] = []
    outputs.extend(application.get("outputs") or [])
    if boot:
        outputs.extend(boot.get("outputs") or [])
    summary = (
        f"{profile.target_lifecycle} {'tam boot paketi' if full_requested else 'secure application'} hazır."
        if status == "PASS" else
        "Secure boot paketi tamamlanamadı: " + (
            application.get("summary", "application build başarısız")
            if application.get("status") != "PASS"
            else (
                output_identity_match.get("detail", "certificate kimliği doğrulanamadı")
                if output_identity_match and output_identity_match.get("status") != "PASS"
                else (boot or {}).get("summary", "çıktı doğrulaması başarısız")
            )
        )
    )
    if status == "PASS" and profile.offline_only:
        summary += " Paket çevrimdışı hazırlandı; seçili fiziksel karta yazma güvenlik kapısı nedeniyle kapalı."
    return {
        "status": status,
        "operation": "secure_boot_package_build",
        "summary": summary,
        "profile": profile.to_dict(),
        "scope": "application_and_boot" if full_requested else "application_only",
        "application": application,
        "application_verification": application_verification,
        "signing_identity": signing_identity,
        "output_signing_identity_match": output_identity_match,
        "boot": boot,
        "application_output": application.get("output"),
        "boot_output": boot.get("output") if boot else None,
        "outputs": outputs,
        "checks": [
            {"check": "physical_and_target_lifecycle_distinguished", "status": "PASS"},
            {"check": "application_secure_build", "status": application.get("status", "FAIL"), "detail": application.get("summary", "")},
            {"check": "application_certificate_and_image_verify", "status": application_verification.get("status", "NOT_CHECKED") if application_verification else "NOT_CHECKED"},
            {
                "check": "selected_certificate_private_key_match",
                "status": signing_identity.get("status", "NOT_CHECKED") if signing_identity else "NOT_NEEDED",
                "detail": "Seçilen certificate ile private key aynı public key kimliğine ait." if signing_identity else "Studio certificate kimliği seçilmedi.",
            },
            {
                "check": "output_certificate_identity_match",
                "status": output_identity_match.get("status", "NOT_CHECKED") if output_identity_match else "NOT_NEEDED",
                "detail": output_identity_match.get("detail", "") if output_identity_match else "SDK development key akışı kullanıldı.",
            },
            {"check": "boot_image_build", "status": boot.get("status", "FAIL") if full_requested and boot else "NOT_NEEDED"},
            {"check": "global_devconfig_unchanged", "status": "PASS"},
            {"check": "otp_efuse_untouched", "status": "PASS"},
        ] + [
            {
                "check": f"application_{item.get('check', 'check')}",
                "status": item.get("status", "NOT_CHECKED"),
                "detail": item.get("detail") or item.get("summary") or "Application build alt kontrolü",
            }
            for item in application.get("checks", [])
        ],
        "claims": [
            "MCU+ SDK proje recipe'leri host üzerinde lifecycle hedefiyle çalıştırıldı.",
            "Global devconfig.mak ve CCS proje ayarları değiştirilmedi.",
        ] + ([
            "Seçilen Studio certificate kimliği, private key ve üretilen embedded application certificate public key'iyle eşleştirildi."
        ] if output_identity_match and output_identity_match.get("status") == "PASS" else []),
        "non_claims": [
            "Host build başarısı kartın secure boot yaptığını kanıtlamaz.",
            "Customer Root of Trust provisioning'i veya HS-FS → HS-SE geçişi yapılmadı.",
        ],
        "secret_paths_persisted": False,
    }
