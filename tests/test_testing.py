import pytest
from helpers import CASES

from attestor.testing import assert_compliant


def test_passes_good_memo():
    assert assert_compliant(CASES / "good_memo.json").verdict.value == "PASS"


def test_raises_on_blocking_findings():
    with pytest.raises(AssertionError, match="phantom_citation"):
        assert_compliant(CASES / "bad_memo.json")


def test_warnings_can_fail_too():
    assert_compliant(CASES / "borderline.json")
    with pytest.raises(AssertionError, match="citation_grounding"):
        assert_compliant(CASES / "borderline.json", allow_warn=False)
