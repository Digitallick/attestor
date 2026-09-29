from helpers import CASES, EXAMPLES, FIXED_NOW, FakeJudge

from attestor import check_case, load_case, load_policy
from attestor.engine import verdict_for
from attestor.models import Case, Finding, Severity, Verdict
from attestor.policy import policy_from_dict


def test_good_memo_passes():
    report = check_case(load_case(CASES / "good_memo.json"))
    assert report.verdict is Verdict.PASS, report.findings


def test_bad_memo_blocks_on_every_check():
    report = check_case(load_case(CASES / "bad_memo.json"))
    assert report.verdict is Verdict.BLOCK
    assert {f.check_id for f in report.findings} == {
        "citation_grounding", "citation_coverage", "phantom_citation",
        "pii_leak", "prohibited_language", "required_disclosures",
    }


def test_findings_sorted_block_first():
    report = check_case(load_case(CASES / "bad_memo.json"))
    ranks = [f.severity is Severity.BLOCK for f in report.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_borderline_warns_and_judge_clears_it():
    case = load_case(CASES / "borderline.json")
    assert check_case(case).verdict is Verdict.WARN
    judged = check_case(case, judge=FakeJudge(supported=True))
    assert judged.verdict is Verdict.PASS
    assert len(judged.judge_calls) == 1


def test_reports_are_deterministic():
    case = load_case(CASES / "bad_memo.json")
    first = check_case(case, now=FIXED_NOW).model_dump()
    assert check_case(case, now=FIXED_NOW).model_dump() == first


def test_empty_answer():
    case = Case(id="empty", answer="")
    assert check_case(case, policy_from_dict({"pack": "general"})).verdict is Verdict.PASS
    assert check_case(case).verdict is Verdict.WARN  # finance still wants its disclaimers


def test_disabled_checks_do_not_run():
    report = check_case(Case(id="x", answer="Hi."), policy_from_dict({"pack": "general"}))
    assert "required_disclosures" not in report.checks_run


def test_example_policy_loads():
    assert load_policy(EXAMPLES / "attestor.yaml").pack == "finance"


def test_verdict_for():
    warn = Finding(check_id="c", severity=Severity.WARN, message="m")
    info = Finding(check_id="c", severity=Severity.INFO, message="m")
    assert verdict_for([]) is Verdict.PASS
    assert verdict_for([info]) is Verdict.PASS
    assert verdict_for([info, warn]) is Verdict.WARN


def test_findings_never_echo_pii_even_with_pii_check_off():
    policy = policy_from_dict({"checks": {"pii_leak": {"enabled": False}}})
    report = check_case(load_case(CASES / "bad_memo.json"), policy)
    dumped = report.model_dump_json()
    assert "123-45-6789" not in dumped
    assert "jane.doe@northwind-capital.com" not in dumped
