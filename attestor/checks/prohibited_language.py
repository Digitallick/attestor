from __future__ import annotations

import re

from attestor.checks.base import BaseCheck, CheckContext, register
from attestor.errors import PolicyError
from attestor.models import Finding, Severity
from attestor.text import clean

# "No investment is risk-free" should not trip the "risk-free" rule.
_NEGATION = re.compile(r"\b(?:no|not|never|isn't|aren't|cannot|can't|nothing|without)\b[^.]*$",
                       re.IGNORECASE)


@register
class ProhibitedLanguage(BaseCheck):
    id = "prohibited_language"
    title = "No promissory or exaggerated wording"
    default_severity = Severity.BLOCK

    def run(self, ctx: CheckContext) -> list[Finding]:
        terms = [*ctx.options.get("terms", []), *ctx.options.get("extra_terms", [])]
        try:
            patterns = [re.compile(rf"(?<!\w)(?:{t})(?!\w)", re.IGNORECASE) for t in terms]
        except re.error as exc:
            raise PolicyError(f"prohibited_language: bad term: {exc}") from exc

        findings = []
        for claim in ctx.claims:
            text = clean(claim.text)
            for pattern in patterns:
                for match in pattern.finditer(text):
                    if _NEGATION.search(text[max(0, match.start() - 40) : match.start()]):
                        continue
                    findings.append(ctx.finding(
                        f'Prohibited wording: "{match.group(0)}"',
                        claim_index=claim.index,
                        evidence={"match": match.group(0)},
                    ))
        return findings
