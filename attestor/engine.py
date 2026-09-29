from __future__ import annotations

from datetime import datetime, timezone

from attestor._version import __version__
from attestor.checks import CheckContext, all_checks
from attestor.checks.pii_leak import redact
from attestor.claims import extract_claims
from attestor.judge import Judge
from attestor.models import SEVERITY_RANK, Case, Finding, Report, Severity, Verdict
from attestor.policy import Policy, load_policy


def verdict_for(findings: list[Finding]) -> Verdict:
    severities = {f.severity for f in findings}
    if Severity.BLOCK in severities:
        return Verdict.BLOCK
    if Severity.WARN in severities:
        return Verdict.WARN
    return Verdict.PASS


def _redact_value(value):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    return value


def _redacted(finding: Finding) -> Finding:
    return finding.model_copy(update={
        "message": redact(finding.message),
        "evidence": _redact_value(finding.evidence),
    })


def check_case(
    case: Case,
    policy: Policy | None = None,
    *,
    judge: Judge | None = None,
    now: datetime | None = None,
) -> Report:
    policy = policy or load_policy()
    claims = extract_claims(case.answer)
    findings: list[Finding] = []
    judge_calls: list[dict] = []
    ran: list[str] = []

    for check_id, check_cls in all_checks().items():
        config = policy.config_for(check_id)
        if not config.enabled:
            continue
        ctx = CheckContext(
            check_id=check_id,
            case=case,
            claims=claims,
            options=config.options,
            severity=config.severity or check_cls.default_severity,
            refs=config.regulatory_refs,
            judge=judge,
            judge_calls=judge_calls,
        )
        findings.extend(_redacted(f) for f in check_cls().run(ctx))
        ran.append(check_id)

    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.claim_index or 0, f.check_id))
    return Report(
        case_id=case.id,
        verdict=verdict_for(findings),
        findings=findings,
        checks_run=ran,
        pack=policy.pack,
        case_sha256=case.sha256(),
        policy_sha256=policy.sha256(),
        judge_calls=judge_calls,
        attestor_version=__version__,
        timestamp=(now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
    )
