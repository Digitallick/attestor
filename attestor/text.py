"""Normalisation and cheap overlap measures used to score claim support."""

from __future__ import annotations

import re
from difflib import SequenceMatcher

_STOPWORDS = """
    a about above across after all also an and any are as at be been before being between both
    but by can could did do does during each for from had has have he her his how i if in into
    is it its just more most no nor not of on only or other our out over per s same she should
    so such than that the their them then there these they this those through to under up very
    was we were what when where which while who whom will with would you
"""
STOPWORDS = frozenset(_STOPWORDS.split())

_PUNCT = str.maketrans({
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2013": "-", "\u2014": "-", "\u00a0": " ",
})
_THOUSANDS = re.compile(r"(?<=\d),(?=\d{3}\b)")
_TOKEN = re.compile(r"[a-z0-9]+(?:\.\d+)*[a-z%]*")
# Figures, but not digits glued to letters like FY2025 or Q3.
_NUMBER = re.compile(r"(?<![A-Za-z0-9.])\d+(?:\.\d+)?")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def clean(text: str) -> str:
    return " ".join(_THOUSANDS.sub("", text.translate(_PUNCT)).split())


def normalize(text: str) -> str:
    return clean(text).lower()


def tokens(text: str) -> list[str]:
    return _TOKEN.findall(normalize(text))


def content_tokens(text: str) -> list[str]:
    return [t for t in tokens(text) if t not in STOPWORDS]


def numbers(text: str) -> set[str]:
    return {_canonical_number(n) for n in _NUMBER.findall(clean(text))}


def _canonical_number(value: str) -> str:
    return value.rstrip("0").rstrip(".") if "." in value else value


def token_recall(claim: str, source: str) -> float:
    wanted = set(content_tokens(claim))
    if not wanted:
        return 0.0
    return len(wanted & set(content_tokens(source))) / len(wanted)


def _ngrams(toks: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(toks[i : i + n]) for i in range(len(toks) - n + 1)}


def ngram_overlap(claim: str, source: str, n: int = 3) -> float:
    grams = _ngrams(content_tokens(claim), n)
    if not grams:
        return 0.0
    return len(grams & _ngrams(content_tokens(source), n)) / len(grams)


def longest_match_ratio(claim: str, source: str) -> float:
    a, b = normalize(claim), normalize(source)
    if not a:
        return 0.0
    match = SequenceMatcher(None, a, b, autojunk=False).find_longest_match(0, len(a), 0, len(b))
    return match.size / len(a)


def best_sentence(claim: str, source: str) -> str:
    """The source sentence that shares the most content words with the claim."""
    candidates = [s for s in _SENTENCE_END.split(clean(source)) if s]
    if not candidates:
        return ""
    return max(candidates, key=lambda s: token_recall(claim, s))
