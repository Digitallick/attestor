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


def test_redact_masks_every_detector():
    from attestor.checks.pii_leak import redact

    text = "SSN 123-45-6789, mail jane.doe@example.com, call (604) 555-0199."
    assert redact(text) == "SSN *******6789, mail j***@example.com, call **********0199."


@pytest.mark.parametrize("answer", [
    "No fees and guaranteed returns of 8%.",
    "Unlike stocks that are not safe, this is risk-free.",
    "It's not just safe, it's risk-free.",
])
def test_negation_elsewhere_in_sentence_does_not_hide_a_promise(answer):
    assert len(run_check("prohibited_language", make_case(answer), options={"terms": TERMS})) == 1


def test_negation_that_governs_the_term_still_suppresses():
    case = make_case("There is no risk-free option. Nothing is risk-free.")
    assert run_check("prohibited_language", case, options={"terms": TERMS}) == []


@pytest.mark.parametrize("check_id,options", [
    ("prohibited_language", {"terms": "risk-free"}),
    ("prohibited_language", {"terms": [3]}),
    ("required_disclosures", {"phrases": "not investment advice"}),
    ("pii_leak", {"detectors": "ssn"}),
])
def test_scalar_where_list_expected_is_policy_error(check_id, options):
    with pytest.raises(PolicyError, match="list"):
        run_check(check_id, make_case("x"), options=options)


def test_space_separated_figures_are_not_phone_numbers():
    assert pii("Price targets of 150 250 3000 were discussed.") == []
    assert pii("Call 604-555-0199 or 604.555.0199.") != []
