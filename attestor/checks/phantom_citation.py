from attestor.checks.base import BaseCheck, CheckContext, register
from attestor.models import Finding, Severity


@register
class PhantomCitation(BaseCheck):
    id = "phantom_citation"
    title = "Citations point to sources that exist"
    default_severity = Severity.BLOCK

    def run(self, ctx: CheckContext) -> list[Finding]:
        known = sorted(s.id for s in ctx.case.sources)
        return [
            ctx.finding(
                f"Citation [{source_id}] does not match any provided source",
                claim_index=claim.index,
                evidence={"citation": source_id, "known_sources": known},
            )
            for claim in ctx.claims
            for source_id in claim.citations
            if source_id not in known
        ]
