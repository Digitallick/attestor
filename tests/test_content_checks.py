import pytest
from helpers import make_case, run_check

from attestor.errors import PolicyError


def pii(answer, **options):
    return run_check("pii_leak", make_case(answer), options=options or None)


def test_ssn_detected_and_masked():
    findings = pii("SSN on file is 123-45-6789.")
    assert [f.evidence for f in findings] == [{"detector": "ssn", "masked": "*******6789"}]


def test_value_never_in_output():
    findings = pii("SSN 123-45-6789, card 4111 1111 1111 1111, mail jane.doe@example.com.")
    dumped = " ".join(f.model_dump_json() for f in findings)
    for raw in ("123-45-6789", "4111 1111 1111 1111", "jane.doe@example.com"):
        assert raw not in dumped
    assert {f.evidence["detector"] for f in findings} == {"ssn", "credit_card", "email"}


def test_card_must_pass_luhn():
    assert pii("Card 4111 1111 1111 1112 on file.") == []


def test_iban_validated():
    assert pii("Pay GB82 WEST 1234 5698 7654 32 now.")[0].evidence["detector"] == "iban"
    assert pii("Pay GB00 WEST 1234 5698 7654 32 now.") == []


def test_phone_and_account():
    detectors = {f.evidence["detector"] for f in pii(
        "Call (604) 555-0199 or wire to account number 004512345678."
    )}
    assert detectors == {"phone", "us_bank_account"}


def test_detector_subset():
    assert pii("Mail a.b@example.com", detectors=["ssn"]) == []


def test_unknown_detector():
    with pytest.raises(PolicyError):
        pii("x", detectors=["dna"])


PHRASES = [
    {"label": "Not investment advice", "pattern": "not (?:intended as )?investment advice"},
    "Past performance",
]


def test_missing_disclosures():
    findings = run_check("required_disclosures", make_case("Revenue grew."),
                         options={"phrases": PHRASES})
    assert [f.evidence["label"] for f in findings] == ["Not investment advice", "Past performance"]


def test_disclosures_present():
    answer = "This is not investment advice. Past performance is no guarantee."
    assert run_check("required_disclosures", make_case(answer), options={"phrases": PHRASES}) == []


def test_plain_string_is_literal():
    assert run_check("required_disclosures", make_case("Risk (high) applies."),
                     options={"phrases": ["risk (high)"]}) == []


def test_bad_disclosure_pattern():
    with pytest.raises(PolicyError):
        run_check("required_disclosures", make_case("x"), options={"phrases": [{"pattern": "("}]})


TERMS = [r"guaranteed (?:returns?|profits?)", r"risk[- ]free"]


def test_promissory_wording_flagged():
    findings = run_check("prohibited_language", make_case("This fund offers guaranteed returns."),
                         options={"terms": TERMS})
    assert len(findings) == 1
    assert findings[0].evidence["match"] == "guaranteed returns"
    assert findings[0].claim_index == 1


def test_negated_wording_ignored():
    case = make_case("No investment is risk-free. Returns are not guaranteed.")
    assert run_check("prohibited_language", case, options={"terms": TERMS}) == []


def test_extra_terms():
    findings = run_check("prohibited_language", make_case("It's a no-brainer."),
                         options={"terms": TERMS, "extra_terms": ["no-brainer"]})
    assert len(findings) == 1
