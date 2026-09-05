from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

VALID_STATUSES = {"PASS", "FAIL", "PARTIAL", "NOT_CHECKED", "INFO", "WARN", "ERROR"}


@dataclass(frozen=True)
class WorkflowCheck:
    check: str
    status: str
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f"geçersiz workflow status: {self.status}")


@dataclass
class WorkflowResult:
    status: str
    operation: str
    summary: str
    checks: list[dict[str, Any]] = field(default_factory=list)
    outputs: list[dict[str, Any]] = field(default_factory=list)
    claims: list[str] = field(default_factory=list)
    non_claims: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    safe_details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(f"geçersiz workflow status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_status(value: str | None) -> str:
    if value in VALID_STATUSES:
        return value
    if value == "SUCCESS":
        return "PASS"
    return "ERROR"
