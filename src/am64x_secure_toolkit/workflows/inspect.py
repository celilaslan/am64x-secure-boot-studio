from __future__ import annotations

from pathlib import Path

from ..inspect import inspect_artifact
from ..services.claim_boundary import claims_for
from ..verify import verify_artifact
from ..workflow import WorkflowResult


def inspect_and_verify(path: str | Path, *, verify: bool = True) -> WorkflowResult:
    inspected = inspect_artifact(path)
    checks = [{"check": "artifact_parse", "status": "PASS", "detail": inspected.get("artifact_type", "parsed")}]
    safe_details = {"inspection": inspected}
    status = "PASS"
    if verify:
        verified = verify_artifact(path)
        verify_status = verified.get("overall_host_side_verification", "ERROR")
        status = verify_status if verify_status in {"PASS", "FAIL", "PARTIAL", "NOT_CHECKED"} else "ERROR"
        checks.append({"check": "host_side_verify", "status": status})
        safe_details["verification"] = verified
    claims, non_claims = claims_for("inspect_verify" if verify else "inspect", status)
    return WorkflowResult(
        status=status,
        operation="inspect_verify" if verify else "inspect",
        summary="Image/certificate host-side inceleme tamamlandı." if status == "PASS" else "İnceleme tamamlandı; bazı kontroller PASS değil.",
        checks=checks,
        claims=claims,
        non_claims=non_claims,
        sources=["TISCI-X509"],
        safe_details=safe_details,
    )
