"""Helpers for asserting compliance inside a test suite."""

from __future__ import annotations

from pathlib import Path

from attestor.engine import check_case
from attestor.judge import Judge
from attestor.loader import load_case
from attestor.models import Case, Report, Severity
from attestor.policy import Policy, load_policy


def assert_compliant(
    case: Case | str | Path,
    policy: Policy | str | Path | None = None,
    *,
    allow_warn: bool = True,
    judge: Judge | None = None,
) -> Report:
    """Fail the test if the case has blocking findings (or warnings, with allow_warn=False)."""
    case = case if isinstance(case, Case) else load_case(case)
    policy = policy if isinstance(policy, Policy) else load_policy(policy)
    report = check_case(case, policy, judge=judge)
    failing = [
        f for f in report.findings
        if f.severity is Severity.BLOCK or (not allow_warn and f.severity is Severity.WARN)
    ]
    if failing:
        lines = [f"{report.case_id}: {report.verdict.value}"]
        lines += [f"  [{f.severity.value}] {f.check_id}: {f.message}" for f in failing]
        raise AssertionError("\n".join(lines))
    return report
