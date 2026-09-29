import pytest

from attestor.text import (
    best_sentence,
    content_tokens,
    longest_match_ratio,
    ngram_overlap,
    numbers,
    token_recall,
)


def test_numbers_are_canonicalised():
    assert numbers("Revenue of $1,200.50 and 4.0x leverage") == {"1200.5", "4"}


def test_numbers_skip_labels_like_fiscal_years():
    assert numbers("FY2025 and Q3 results, per the 10-K") == {"10"}


def test_content_tokens_drop_stopwords():
    assert content_tokens("The margin was 17.2% in the year") == ["margin", "17.2%", "year"]


def test_curly_quotes_and_dashes_normalised():
    assert content_tokens("Low–to–mid “growth”") == ["low", "mid", "growth"]


def test_token_recall():
    assert token_recall("revenue grew strongly", "Revenue grew 8%.") == pytest.approx(2 / 3)
    assert token_recall("the of", "anything") == 0.0


def test_ngram_overlap():
    assert ngram_overlap("term loan matures march 2029", "The term loan matures in March 2029.") == 1.0


def test_longest_match_ratio():
    assert longest_match_ratio("north america", "Operates across North America.") == 1.0
    assert longest_match_ratio("", "x") == 0.0


def test_best_sentence_picks_closest():
    source = "Revenue was $10 million. Margin was 12%. Headcount is 40."
    assert best_sentence("margin 12%", source) == "Margin was 12%."
