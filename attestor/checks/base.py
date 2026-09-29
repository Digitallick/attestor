from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from attestor.models import SEVERITY_RANK, Case, Claim, Finding, Severity

if TYPE_CHECKING:
    from attestor.judge import Judge


def cap(severity: Severity, ceiling: Severity) -> Severity:
    return severity if SEVERITY_RANK[severity] <= SEVERITY_RANK[ceiling] else ceiling


@dataclass
class CheckContext:
    check_id: str
    case: Case
    claims: list[Claim]
    options: dict[str, Any]
    severity: Severity
    refs: list[str]
    judge: Judge | None = None
    judge_calls: list[dict[str, Any]] = field(default_factory=list)

    def finding(
        self,
        message: str,
        *,
        claim_index: int | None = None,
        severity: Severity | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            severity=severity or self.severity,
            message=message,
            claim_index=claim_index,
            evidence=evidence or {},
            regulatory_refs=list(self.refs),
        )


class BaseCheck:
    id: ClassVar[str]
    title: ClassVar[str]
    default_severity: ClassVar[Severity] = Severity.WARN

    def run(self, ctx: CheckContext) -> list[Finding]:
        raise NotImplementedError


_REGISTRY: dict[str, type[BaseCheck]] = {}


def register(cls: type[BaseCheck]) -> type[BaseCheck]:
    if cls.id in _REGISTRY:
        raise ValueError(f"check '{cls.id}' is already registered")
    _REGISTRY[cls.id] = cls
    return cls


def registered() -> dict[str, type[BaseCheck]]:
    return dict(sorted(_REGISTRY.items()))
