from __future__ import annotations

import re

from attestor.checks.base import BaseCheck, CheckContext, register
from attestor.errors import PolicyError
from attestor.models import Finding, Severity
from attestor.text import clean


def _compile(item) -> tuple[str, re.Pattern]:
    if isinstance(item, str):
        label, pattern = item, re.escape(item)
    elif isinstance(item, dict) and ("pattern" in item or "text" in item):
        pattern = item.get("pattern") or re.escape(item["text"])
        label = item.get("label") or item.get("text") or pattern
    else:
        raise PolicyError("required_disclosures: each phrase needs 'pattern' or 'text'")
    try:
        return label, re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise PolicyError(f"required_disclosures: bad pattern {pattern!r}: {exc}") from exc


@register
class RequiredDisclosures(BaseCheck):
    id = "required_disclosures"
    title = "Required disclaimers are present"
    default_severity = Severity.WARN

    def run(self, ctx: CheckContext) -> list[Finding]:
        answer = clean(ctx.case.answer)
        findings = []
        for item in ctx.options.get("phrases", []):
            label, pattern = _compile(item)
            if not pattern.search(answer):
                findings.append(ctx.finding(
                    f"Missing required disclosure: {label}",
                    evidence={"label": label, "pattern": pattern.pattern},
                ))
        return findings
