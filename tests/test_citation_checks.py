import pytest
from helpers import FakeJudge, make_case, run_check

from attestor.errors import JudgeError, PolicyError
from attestor.models import Severity

S1 = "FY2025 revenue was $412.6 million, up 8.4% year over year. Adjusted EBITDA margin was 17.2%."
FOOTPRINT = "Northwind Logistics operates 38 distribution centers across North America."
PARAPHRASE = "Northwind Logistics runs 38 warehouse sites throughout North America [S1]."


def test_phantom_citation_flagged():
    findings = run_check("phantom_citation", make_case("Up 5% [S9].", {"S1": "Up 5%."}))
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["citation"] == "S9"
    assert f.claim_index == 1
    assert f.severity is Severity.BLOCK
    assert f.regulatory_refs == ["REF"]


def test_known_citation_is_fine():
    assert run_check("phantom_citation", make_case("Up 5% [S1].", {"S1": "Up 5%."})) == []


def test_uncited_factual_statement():
    case = make_case("Revenue grew 8% [S1]. Margins rose to 20%.", {"S1": "Revenue grew 8%."})
    findings = run_check("citation_coverage", case)
    assert [f.claim_index for f in findings] == [2]
    assert findings[0].evidence["coverage"] == 0.5


def test_coverage_ignores_non_factual_sentences():
    assert run_check("citation_coverage", make_case("This is not investment advice.")) == []


def test_coverage_threshold():
    case = make_case("Revenue grew 8% [S1]. Margins rose to 20%.", {"S1": "Revenue grew 8%."})
    assert run_check("citation_coverage", case, options={"min_coverage": 0.5}) == []


def test_supported_statement_passes():
    case = make_case("Revenue was $412.6 million in FY2025 [S1].", {"S1": S1})
    assert run_check("citation_grounding", case) == []


def test_invented_figure_is_blocked():
    case = make_case("Adjusted EBITDA margin was 21.5% [S1].", {"S1": S1})
    findings = run_check("citation_grounding", case)
    assert len(findings) == 1
    assert findings[0].severity is Severity.BLOCK
    assert findings[0].evidence["missing_figures"] == ["21.5%"]


def test_unrelated_statement_is_blocked():
    findings = run_check("citation_grounding", make_case("The CEO resigned last spring [S1].",
                                                         {"S1": S1}))
    assert len(findings) == 1
    assert "not supported" in findings[0].message


def test_uncertain_statement_warns_without_judge():
    findings = run_check("citation_grounding", make_case(PARAPHRASE, {"S1": FOOTPRINT}))
    assert len(findings) == 1
    assert findings[0].severity is Severity.WARN
    assert 0.3 < findings[0].evidence["score"] < 0.6


def test_judge_clears_uncertain_statement():
    judge, calls = FakeJudge(supported=True), []
    findings = run_check("citation_grounding", make_case(PARAPHRASE, {"S1": FOOTPRINT}),
                         judge=judge, judge_calls=calls)
    assert findings == []
    assert calls == [{"claim_index": 1, "judge": "fake", "supported": True}]


def test_judge_rejection_blocks():
    findings = run_check("citation_grounding", make_case(PARAPHRASE, {"S1": FOOTPRINT}),
                         judge=FakeJudge(supported=False))
    assert findings[0].severity is Severity.BLOCK
    assert findings[0].evidence["judge_quote"] == "quoted"


def test_judge_failure_warns_instead_of_passing():
    judge, calls = FakeJudge(error=JudgeError("no credentials")), []
    findings = run_check("citation_grounding", make_case(PARAPHRASE, {"S1": FOOTPRINT}),
                         judge=judge, judge_calls=calls)
    assert findings[0].severity is Severity.WARN
    assert "no credentials" in findings[0].message
    assert calls == [{"claim_index": 1, "judge": "fake", "supported": None,
                      "error": "no credentials"}]


def test_confident_statements_never_reach_the_judge():
    judge = FakeJudge()
    run_check("citation_grounding", make_case("Revenue was $412.6 million [S1].", {"S1": S1}),
              judge=judge)
    assert judge.calls == []


def test_bad_thresholds_rejected():
    with pytest.raises(PolicyError):
        run_check("citation_grounding", make_case("x [S1].", {"S1": "x"}),
                  options={"support_threshold": 0.5, "reject_threshold": 0.7})


@pytest.mark.parametrize("claim,source", [
    ("FY2025 revenue was $500 million [S1].", "FY2024 revenue was $500 million."),
    ("Q4 revenue was $500 million [S1].", "Q3 revenue was $500 million."),
    ("Revenue was $500 billion [S1].", "Revenue was $500 million."),
    ("Revenue grew 12% [S1].", "Revenue grew $12 million."),
])
def test_wrong_unit_scale_or_period_is_blocked(claim, source):
    findings = run_check("citation_grounding", make_case(claim, {"S1": source}))
    assert len(findings) == 1
    assert findings[0].evidence["missing_figures"]


@pytest.mark.parametrize("claim,source", [
    ("Revenue was $4.2 million [S1].", "Revenue was $4,200,000."),
    ("Revenue was $4,200,000 [S1].", "Revenue was $4.2 million."),
    ("Revenue peaked in 2024 [S1].", "Revenue peaked in FY2024."),
    ("It ranked 3rd in the region [S1].", "It ranked third in the region."),
    ("Revenue rose 12 percent [S1].", "Revenue rose 12%."),
])
def test_equivalent_figures_are_not_flagged(claim, source):
    findings = run_check("citation_grounding", make_case(claim, {"S1": source}))
    assert not any("missing_figures" in f.evidence for f in findings)


@pytest.mark.parametrize("check_id,options", [
    ("citation_grounding", {"support_threshold": "high"}),
    ("citation_grounding", {"reject_threshold": True}),
    ("citation_coverage", {"min_coverage": "abc"}),
    ("citation_coverage", {"min_coverage": 2}),
])
def test_bad_option_types_are_policy_errors(check_id, options):
    with pytest.raises(PolicyError):
        run_check(check_id, make_case("Revenue grew 8% [S1].", {"S1": "Revenue grew 8%."}),
                  options=options)


@pytest.mark.parametrize("claim,source", [
    ("Spreads widened 0.5% [S1].", "Spreads widened 50 bps."),
    ("Leverage is 12.5x EBITDA [S1].", "Leverage is 12.5 times EBITDA."),
    ("Sales in H1 2025 rose [S1].", "Sales in 1H25 rose."),
    ("Sales in Q2 2024 rose [S1].", "Sales in 2Q24 rose."),
    ("The deck is at https://example.com/deck/2024/10 [S1].", "The deck is online."),
    ("The quarter closed on 3/31/2025 [S1].", "The quarter closed on March 31, 2025."),
])
def test_common_financial_notation_is_not_flagged(claim, source):
    findings = run_check("citation_grounding", make_case(claim, {"S1": source}))
    assert not any("missing_figures" in f.evidence for f in findings)
