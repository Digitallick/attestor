from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from attestor.models import Case, Source

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
CASES = EXAMPLES / "cases"
FIXED_NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def make_case(answer: str, sources: dict[str, str] | None = None) -> Case:
    return Case(
        id="t",
        answer=answer,
        sources=[Source(id=k, text=v) for k, v in (sources or {}).items()],
    )


def run_check(check_id, case, options=None, severity=None, judge=None, judge_calls=None):
    from attestor.checks import CheckContext, all_checks
    from attestor.claims import extract_claims

    check_cls = all_checks()[check_id]
    ctx = CheckContext(
        check_id=check_id,
        case=case,
        claims=extract_claims(case.answer),
        options=options or {},
        severity=severity or check_cls.default_severity,
        refs=["REF"],
        judge=judge,
        judge_calls=judge_calls if judge_calls is not None else [],
    )
    return check_cls().run(ctx)


class FakeJudge:
    name = "fake"

    def __init__(self, supported=True, error=None):
        self.supported = supported
        self.error = error
        self.calls = []

    def assess(self, claim, sources):
        from attestor.judge import JudgeVerdict

        if self.error:
            raise self.error
        self.calls.append(claim)
        return JudgeVerdict(supported=self.supported, rationale="because", quote="quoted")
