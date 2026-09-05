from __future__ import annotations

"""Display-oriented model for SDK security semantic comparison.

The model deliberately omits full host paths and secret-bearing source text. It surfaces
only mapped security semantics, hashes already present in the diff result, and review state.
"""

from typing import Any

_ROLE_LABELS = {
    "devconfig": "devconfig.mak",
    "app_makefile": "Application Makefile",
    "sbl_makefile": "SBL Makefile",
    "app_tool": "Application signer",
    "rom_tool": "ROM signer",
}

_CLASS_LABELS = {
    "IDENTICAL": "Byte-for-byte aynı",
    "MAPPED_SECURITY_BEHAVIOR_CHANGED": "Security mapping değişti",
    "CONTENT_CHANGED_NO_MAPPED_SECURITY_CHANGE": "İçerik değişti / mapped fark yok",
}

_REVIEW_STATUS = {
    "REQUIRED": "FAIL",
    "RECOMMENDED": "PARTIAL",
    "NOT_REQUIRED": "PASS",
}


def _safe_change_value(field: str, value: Any) -> Any:
    upper = field.upper()
    if "APP_SIGNING_KEY" in upper or "APP_ENCRYPTION_KEY" in upper:
        text = str(value)
        if "$(" in text or "${" in text or text in {"", "<MISSING>"}:
            return text
        return "<configured value hidden>"
    return value


def sdk_diff_view_model(result: dict[str, Any]) -> dict[str, Any]:
    comparisons = result.get("comparisons") if isinstance(result.get("comparisons"), dict) else {}
    roles: list[dict[str, Any]] = []
    for role, raw in comparisons.items():
        if not isinstance(raw, dict):
            continue
        review = str(raw.get("review") or "RECOMMENDED")
        changes = [x for x in raw.get("semantic_changes", []) if isinstance(x, dict)]
        old = raw.get("old") if isinstance(raw.get("old"), dict) else {}
        new = raw.get("new") if isinstance(raw.get("new"), dict) else {}
        roles.append({
            "role": str(role),
            "label": _ROLE_LABELS.get(str(role), str(role)),
            "classification": str(raw.get("classification") or "UNKNOWN"),
            "classification_label": _CLASS_LABELS.get(str(raw.get("classification")), str(raw.get("classification") or "UNKNOWN")),
            "review": review,
            "status": _REVIEW_STATUS.get(review, "PARTIAL"),
            "same_sha256": bool(raw.get("same_sha256")),
            "old_sha256": str(old.get("sha256") or ""),
            "new_sha256": str(new.get("sha256") or ""),
            "changes": [{
                "field": str(x.get("field") or ""),
                "before": _safe_change_value(str(x.get("field") or ""), x.get("before")),
                "after": _safe_change_value(str(x.get("field") or ""), x.get("after")),
            } for x in changes],
            "secret_hygiene_old": [
                {"severity": str(x.get("severity") or "INFO"), "code": str(x.get("code") or "")}
                for x in old.get("secret_hygiene", []) if isinstance(x, dict)
            ],
            "secret_hygiene_new": [
                {"severity": str(x.get("severity") or "INFO"), "code": str(x.get("code") or "")}
                for x in new.get("secret_hygiene", []) if isinstance(x, dict)
            ],
        })
    return {
        "status": str(result.get("status") or "INFO"),
        "labels": dict(result.get("labels") or {}),
        "roles": roles,
        "summary": dict(result.get("summary") or {}),
        "not_a_proof": str((result.get("interpretation") or {}).get("not_a_proof") or ""),
    }
