from __future__ import annotations

from pathlib import Path

from ..build import build_app
from ..keycheck import preflight_mek, preflight_signing_key
from ..services.claim_boundary import claims_for
from ..services.environment import EnvironmentResolution
from ..workflow import WorkflowResult


def application_build_workflow(
    *,
    environment: EnvironmentResolution,
    input_image: str | Path,
    signing_key: str | Path,
    output: str | Path,
    encryption_key: str | Path | None = None,
    dry_run: bool = False,
    post_verify: bool = True,
) -> WorkflowResult:
    if environment.app_signing_tool is None:
        raise FileNotFoundError("appimage_x509_cert_gen.py environment içinde çözümlenemedi")
    key_check = preflight_signing_key(Path(signing_key), purpose="application")
    checks = [{"check": "signing_key_preflight", "status": key_check["status"]}]
    if key_check.get("input_class") != "private_key":
        checks.append({"check": "private_key_required_for_build", "status": "FAIL", "detail": "TI signing tool build için private key gerekir"})
        claims, non_claims = claims_for("application_build", "FAIL", encrypted=encryption_key is not None)
        return WorkflowResult("FAIL", "application_build", "Application build için private signing key gereklidir.", checks=checks, claims=claims, non_claims=non_claims, safe_details={"signing_key": key_check})
    if key_check["status"] != "PASS":
        claims, non_claims = claims_for("application_build", "FAIL", encrypted=encryption_key is not None)
        return WorkflowResult("FAIL", "application_build", "Signing key preflight başarısız.", checks=checks, claims=claims, non_claims=non_claims, safe_details={"signing_key": key_check})
    mek_check = None
    if encryption_key is not None:
        mek_check = preflight_mek(Path(encryption_key))
        checks.append({"check": "mek_preflight", "status": mek_check["status"]})
        if mek_check["status"] != "PASS":
            claims, non_claims = claims_for("application_build", "FAIL", encrypted=True)
            return WorkflowResult("FAIL", "application_build", "MEK preflight başarısız.", checks=checks, claims=claims, non_claims=non_claims, safe_details={"signing_key": key_check, "mek": mek_check})
    build_result = build_app(
        signing_tool=environment.app_signing_tool,
        input_image=input_image,
        signing_key=signing_key,
        encryption_key=encryption_key,
        output=output,
        python_executable=environment.python_executable,
        dry_run=dry_run,
        post_verify=post_verify and not dry_run,
    )
    if dry_run:
        status = "NOT_CHECKED"
    else:
        status = build_result.get("overall_result", "ERROR")
        if status not in {"PASS", "FAIL", "PARTIAL", "NOT_CHECKED"}:
            status = "ERROR"
    tool_status = "NOT_CHECKED" if dry_run else ("PASS" if build_result.get("exit_code") == 0 else "FAIL")
    tool_check = {"check": "ti_signing_tool", "status": tool_status}
    if tool_status == "FAIL" and build_result.get("failure_excerpt"):
        tool_check["detail"] = "TI signer başarısız; redacted diagnostic Teknik Ayrıntılar içinde mevcut."
    checks.append(tool_check)
    if build_result.get("wrapper_error"):
        checks.append({"check": "studio_staging_publish", "status": "FAIL", "detail": "TI tool sonrasında output staging/publish tamamlanamadı."})
    if post_verify and not dry_run:
        checks.append({"check": "post_verify", "status": build_result.get("post_verify") or "NOT_CHECKED"})
    claims, non_claims = claims_for("application_build", status, encrypted=encryption_key is not None)
    return WorkflowResult(
        status=status,
        operation="application_build",
        summary=("Dry run tamamlandı; TI tool çalıştırılmadı." if dry_run else ("Application workflow tamamlandı." if status == "PASS" else "Application workflow tamamlandı ancak tüm kontroller PASS değil.")),
        checks=checks,
        outputs=[{"type": "application_image", "path": build_result.get("output")}],
        claims=claims,
        non_claims=non_claims,
        sources=["SDK-SECURE-BOOT", "SDK-TOOLS-SECURITY", "TISCI-AUTH", "TISCI-X509"],
        safe_details={"build": build_result, "signing_key_preflight": key_check, "mek_preflight": mek_check},
    )
