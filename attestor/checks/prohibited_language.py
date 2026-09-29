from __future__ import annotations

import re

from attestor.checks.base import BaseCheck, CheckContext, register
from attestor.errors import PolicyError
from attestor.models import Finding, Severity
from attestor.text import clean

_NEGATION = re.compile(r"\b(?:no|not|never|none|nothing|without|isn't|aren't|cannot|can't)\b",
                       re.IGNORECASE)
_CLAUSE_BREAK = re.compile(r"[,;:]|\b(?:and|but|while|whereas|although|though)\b", re.IGNORECASE)


def _negated(before: str) -> bool:
    """True for "no investment is risk-free", false for "no fees and guaranteed returns"."""
    clause = _CLAUSE_BREAK.split(before)[-1]
    return bool(_NEGATION.search(" ".join(clause.split()[-3:])))


@register
class ProhibitedLanguage(BaseCheck):
    id = "prohibited_language"
    title = "No promissory or exaggerated wording"
    default_severity = Severity.BLOCK

    def run(self, ctx: CheckContext) -> list[Finding]:
        terms = [*ctx.items("terms"), *ctx.items("extra_terms")]
        try:
            patterns = [re.compile(rf"(?<!\w)(?:{t})(?!\w)", re.IGNORECASE) for t in terms]
        except re.error as exc:
            raise PolicyError(f"prohibited_language: bad term: {exc}") from exc

        findings = []
        for claim in ctx.claims:
            text = clean(claim.text)
            for pattern in patterns:
                for match in pattern.finditer(text):
                    if _negated(text[: match.start()]):
                        continue
                    findings.append(ctx.finding(
                        f'Prohibited wording: "{match.group(0)}"',
                        claim_index=claim.index,
                        evidence={"match": match.group(0)},
                    ))
        return findings
