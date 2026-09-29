from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from attestor.errors import PolicyError
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

    def number(self, key: str, default: float, *, low: float = 0.0, high: float = 1.0) -> float:
        value = self.options.get(key, default)
        is_number = isinstance(value, (int, float)) and not isinstance(value, bool)
        if not is_number or not low <= value <= high:
            raise PolicyError(f"{self.check_id}.{key} must be a number from {low} to {high}")
        return float(value)

    def items(self, key: str, default: list | None = None, kinds: tuple = (str,)) -> list:
        value = self.options.get(key, [] if default is None else default)
        if not isinstance(value, list) or not all(isinstance(v, kinds) for v in value):
            names = " or ".join(k.__name__ for k in kinds)
            raise PolicyError(f"{self.check_id}.{key} must be a list of {names}")
        return value

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
