from __future__ import annotations

from pathlib import Path

from ..build import build_rom
from ..keycheck import preflight_mek, preflight_signing_key
from ..services.claim_boundary import claims_for
from ..services.environment import EnvironmentResolution
from ..workflow import WorkflowResult


def rom_build_workflow(
    *,
    environment: EnvironmentResolution,
    sbl_bin: str | Path,
    sysfw_bin: str | Path,
    boardcfg_blob: str | Path,
    sbl_loadaddr: str,
    sysfw_loadaddr: str,
    bcfg_loadaddr: str,
    swrv: int,
    signing_key: str | Path,
    output: str | Path,
    sysfw_inner_cert: str | Path | None = None,
    debug: str | None = None,
    sbl_encryption_key: str | Path | None = None,
    dry_run: bool = False,
    post_verify: bool = True,
) -> WorkflowResult:
    if environment.rom_signing_tool is None:
        raise FileNotFoundError("rom_image_gen.py environment içinde çözümlenemedi")
    key_check = preflight_signing_key(Path(signing_key), purpose="rom")
    checks = [{"check": "signing_key_preflight", "status": key_check["status"]}]
    if key_check.get("input_class") != "private_key":
        checks.append({"check": "private_key_required_for_build", "status": "FAIL", "detail": "TI ROM signer build için private key gerekir"})
        claims, non_claims = claims_for("rom_build", "FAIL", encrypted=sbl_encryption_key is not None)
        return WorkflowResult("FAIL", "rom_build", "ROM build için private signing key gereklidir.", checks=checks, claims=claims, non_claims=non_claims, safe_details={"signing_key": key_check})
    if key_check["status"] == "FAIL":
        claims, non_claims = claims_for("rom_build", "FAIL", encrypted=sbl_encryption_key is not None)
        return WorkflowResult("FAIL", "rom_build", "ROM signing key preflight başarısız.", checks=checks, claims=claims, non_claims=non_claims, safe_details={"signing_key": key_check})
    mek_check = None
    if sbl_encryption_key is not None:
        mek_check = preflight_mek(Path(sbl_encryption_key))
        checks.append({"check": "sbl_encryption_key_preflight", "status": mek_check["status"]})
        if mek_check["status"] != "PASS":
            claims, non_claims = claims_for("rom_build", "FAIL", encrypted=True)
            return WorkflowResult("FAIL", "rom_build", "SBL encryption key preflight başarısız.", checks=checks, claims=claims, non_claims=non_claims, safe_details={"signing_key": key_check, "mek": mek_check})

    result = build_rom(
        signing_tool=environment.rom_signing_tool,
        sbl_bin=sbl_bin,
        sysfw_bin=sysfw_bin,
        boardcfg_blob=boardcfg_blob,
        sbl_loadaddr=sbl_loadaddr,
        sysfw_loadaddr=sysfw_loadaddr,
        bcfg_loadaddr=bcfg_loadaddr,
        swrv=swrv,
        signing_key=signing_key,
        output=output,
        sysfw_inner_cert=sysfw_inner_cert,
        debug=debug,
        sbl_encryption_key=sbl_encryption_key,
        python_executable=environment.python_executable,
        dry_run=dry_run,
        post_verify=post_verify and not dry_run,
    )
    if dry_run:
        status = "NOT_CHECKED"
    else:
        status = result.get("overall_result", "ERROR")
        if status not in {"PASS", "FAIL", "PARTIAL", "NOT_CHECKED"}:
            status = "ERROR"
    checks.append({"check": "ti_rom_generator", "status": "NOT_CHECKED" if dry_run else ("PASS" if result.get("exit_code") == 0 else "FAIL")})
    if post_verify and not dry_run:
        checks.append({"check": "post_verify", "status": result.get("post_verify") or "NOT_CHECKED"})
    claims, non_claims = claims_for("rom_build", status, encrypted=sbl_encryption_key is not None)
    return WorkflowResult(
        status=status,
        operation="rom_build",
        summary="Dry run tamamlandı; TI tool çalıştırılmadı." if dry_run else "ROM combined-image workflow tamamlandı.",
        checks=checks,
        outputs=[{"type": "rom_combined_image", "path": result.get("output")}],
        claims=claims,
        non_claims=non_claims,
        sources=["SDK-SECURE-BOOT", "SDK-TOOLS-SECURITY", "TRM-BOOT", "ERRATA-REVJ"],
        safe_details={"build": result, "signing_key_preflight": key_check, "mek_preflight": mek_check},
    )
