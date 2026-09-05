from __future__ import annotations

from pathlib import Path

from ..keygen import generate_key_set, generate_mek, generate_signing_key
from ..workflow import WorkflowResult


def generate_keys_workflow(output_dir: str | Path, *, kind: str, role: str = "application", profile: str = "development", backup: bool = False) -> WorkflowResult:
    if kind == "signing":
        result = generate_signing_key(output_dir, role=role)
    elif kind == "mek":
        result = generate_mek(output_dir, role=role)
    elif kind == "set":
        result = generate_key_set(output_dir, profile=profile, backup=backup)
    else:
        raise ValueError("kind signing, mek veya set olmalı")
    return WorkflowResult(
        status=result["status"],
        operation=result["operation"],
        summary="Synthetic/non-production key generation tamamlandı.",
        claims=result.get("claims", []),
        non_claims=result.get("non_claims", []),
        sources=["TISCI-AUTH", "TISCI-KEYWRITER"],
        safe_details=result,
    )
