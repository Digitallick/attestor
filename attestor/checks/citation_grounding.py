from __future__ import annotations

from attestor.checks.base import BaseCheck, CheckContext, cap, register
from attestor.errors import JudgeError, PolicyError
from attestor.models import Claim, Finding, Severity, Source
from attestor.text import (
    best_sentence,
    figure_supported,
    figures,
    longest_match_ratio,
    ngram_overlap,
    source_figures,
    token_recall,
)


def support_score(claim: str, source: str) -> float:
    return max(
        token_recall(claim, source),
        ngram_overlap(claim, source),
        longest_match_ratio(claim, source),
    )


@register
class CitationGrounding(BaseCheck):
    id = "citation_grounding"
    title = "Cited statements are supported by their sources"
    default_severity = Severity.BLOCK

    def run(self, ctx: CheckContext) -> list[Finding]:
        support = ctx.number("support_threshold", 0.6)
        reject = ctx.number("reject_threshold", 0.3)
        if reject > support:
            raise PolicyError(
                "citation_grounding needs 0 <= reject_threshold <= support_threshold <= 1"
            )

        findings = []
        for claim in ctx.claims:
            sources = [s for s in map(ctx.case.source, claim.citations) if s is not None]
            if not sources:
                continue  # uncited or phantom; other checks report those

            score, best = max(((support_score(claim.text, s.text), s) for s in sources),
                              key=lambda pair: pair[0])
            evidence = {
                "score": round(score, 3),
                "source_id": best.id,
                "closest_passage": best_sentence(claim.text, best.text),
            }
            pool = set().union(*(source_figures(s.text) for s in sources))
            missing = [text for key, text in figures(claim.text).items()
                       if not figure_supported(key, pool)]

            if missing:
                findings.append(ctx.finding(
                    f"Figures not found in cited sources: {', '.join(missing)}",
                    claim_index=claim.index,
                    evidence={**evidence, "missing_figures": missing},
                ))
            elif score <= reject:
                findings.append(ctx.finding(
                    f"Statement is not supported by the cited source (score {score:.2f})",
                    claim_index=claim.index,
                    evidence=evidence,
                ))
            elif score < support:
                findings.extend(self._uncertain(ctx, claim, sources, score, evidence))
        return findings

    def _uncertain(self, ctx: CheckContext, claim: Claim, sources: list[Source],
                   score: float, evidence: dict) -> list[Finding]:
        soft = cap(ctx.severity, Severity.WARN)
        if ctx.judge is None:
            return [ctx.finding(
                f"Support is uncertain (score {score:.2f}); review it or run with --judge",
                claim_index=claim.index, severity=soft, evidence=evidence,
            )]
        try:
            verdict = ctx.judge.assess(claim.text, sources)
        except JudgeError as exc:
            ctx.judge_calls.append({"claim_index": claim.index, "judge": ctx.judge.name,
                                    "supported": None, "error": str(exc)})
            return [ctx.finding(
                f"Support is uncertain and the judge was unavailable: {exc}",
                claim_index=claim.index, severity=soft, evidence=evidence,
            )]

        ctx.judge_calls.append(
            {"claim_index": claim.index, "judge": ctx.judge.name, "supported": verdict.supported}
        )
        if verdict.supported:
            return []
        return [ctx.finding(
            f"Judge found the statement unsupported: {verdict.rationale}",
            claim_index=claim.index,
            evidence={**evidence, "judge": ctx.judge.name, "judge_quote": verdict.quote},
        )]
