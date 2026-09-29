from attestor.claims import extract_claims, is_factual, split_sentences


def test_splits_sentences_and_reads_citations():
    claims = extract_claims("Revenue grew 8% [S1]. Margins held at 17% [S1, S2]. Nice.")
    assert [c.text for c in claims] == ["Revenue grew 8%.", "Margins held at 17%.", "Nice."]
    assert [c.citations for c in claims] == [["S1"], ["S1", "S2"], []]
    assert [c.index for c in claims] == [1, 2, 3]


def test_adjacent_markers():
    assert extract_claims("Up 5% [S1][S2].")[0].citations == ["S1", "S2"]


def test_marker_after_period_belongs_to_previous_sentence():
    claims = extract_claims("Revenue grew 8%. [S1] Margins fell [S2].")
    assert [c.citations for c in claims] == [["S1"], ["S2"]]
    assert claims[0].text == "Revenue grew 8%."


def test_abbreviations_do_not_split():
    sentences = split_sentences("The U.S. Treasury curve steepened [S1]. Spreads tightened.")
    assert sentences == ["The U.S. Treasury curve steepened [S1].", "Spreads tightened."]


def test_decimals_and_emails_do_not_split():
    assert len(split_sentences("Leverage is 4.0x. Email a.b@example.com today.")) == 2


def test_bullets_and_headings():
    text = "## Summary\n- Revenue grew 8% [S1]\n- Margin was 17%\n\nDone here."
    assert split_sentences(text) == ["Revenue grew 8% [S1]", "Margin was 17%", "Done here."]


def test_empty_answer():
    assert extract_claims("") == []
    assert extract_claims("   \n\n") == []


def test_is_factual():
    assert is_factual("Revenue grew 8% last year.")
    assert is_factual("The company outperformed its peers in every market.")
    assert not is_factual("This is not investment advice.")
    assert not is_factual("Past performance is not indicative of future results.")
    assert not is_factual("Did revenue grow 8%?")
