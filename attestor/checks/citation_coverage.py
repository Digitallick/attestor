from attestor.checks.base import BaseCheck, CheckContext, register
from attestor.models import Finding, Severity


@register
class CitationCoverage(BaseCheck):
    id = "citation_coverage"
    title = "Factual statements carry a citation"
    default_severity = Severity.WARN

    def run(self, ctx: CheckContext) -> list[Finding]:
        factual = [c for c in ctx.claims if c.is_factual]
        if not factual:
            return []
        uncited = [c for c in factual if not c.citations]
        coverage = 1 - len(uncited) / len(factual)
        if coverage >= float(ctx.options.get("min_coverage", 1.0)):
            return []
        return [
            ctx.finding(
                "Factual statement has no citation",
                claim_index=claim.index,
                evidence={"claim": claim.text, "coverage": round(coverage, 3)},
            )
            for claim in uncited
        ]
