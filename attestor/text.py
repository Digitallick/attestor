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
_CURRENCIES = "$\u20ac\u00a3\u00a5"
_SCALES = {
    "thousand": 1e3, "k": 1e3, "million": 1e6, "mn": 1e6, "mm": 1e6, "m": 1e6,
    "billion": 1e9, "bn": 1e9, "b": 1e9, "trillion": 1e12, "tn": 1e12,
}
# A number with optional currency, scale and unit. Digits glued to letters (FY2025, Q3, 3rd)
# are not matched here; period labels are handled by _PERIOD.
_FIGURE = re.compile(
    r"(?<![\w.])(?P<cur>[$\u20ac\u00a3\u00a5])?(?P<num>\d+(?:\.\d+)?)"
    r"(?:\s?(?P<scale>thousand|million|billion|trillion|mn|mm|bn|tn|k|m|b)\b)?"
    r"(?:\s?(?P<pct>%|percent\b|per cent\b|pct\b)|(?P<mult>x)\b|\s(?P<bps>bps|basis points)\b)?"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_PERIOD = re.compile(r"\b(FY|CY|Q[1-4]|H[12])\s?'?(\d{4}|\d{2})?(?!\w)", re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def clean(text: str) -> str:
    return " ".join(_THOUSANDS.sub("", text.translate(_PUNCT)).split())


def normalize(text: str) -> str:
    return clean(text).lower()


def tokens(text: str) -> list[str]:
    return _TOKEN.findall(normalize(text))


def content_tokens(text: str) -> list[str]:
    return [t for t in tokens(text) if t not in STOPWORDS]


Figure = tuple[str, object]  # (unit, value): ("$", 4200000.0), ("%", 12.0), ("period", "FY2025")


def _scan(text: str) -> list[tuple[int, Figure, str, list[Figure]]]:
    """Every figure in the text as (position, key, original text, keys it implies)."""
    text = clean(text)
    found = []
    for m in _PERIOD.finditer(text):
        label, year = m.group(1).upper(), m.group(2)
        if year and len(year) == 2:
            year = "20" + year
        if year and label in ("FY", "CY"):
            name = f"{label}{year}"
        elif year:
            name = f"{label} {year}"
        else:
            name = label
        key = ("period", name)
        implied = [("period", label), ("", float(year))] if year else []
        found.append((m.start(), key, m.group(0), implied))
    for m in _FIGURE.finditer(text):
        value = float(m["num"]) * _SCALES.get((m["scale"] or "").lower(), 1)
        unit = ("%" if m["pct"] else "x" if m["mult"] else "bps" if m["bps"] else m["cur"] or "")
        found.append((m.start(), (unit, round(value, 4)), m.group(0).strip(), []))
    return sorted(found, key=lambda item: item[0])


def figures(text: str) -> dict[Figure, str]:
    """Figures in reading order, keyed by normalised (unit, value)."""
    result: dict[Figure, str] = {}
    for _, key, original, _ in _scan(text):
        result.setdefault(key, original)
    return result


def source_figures(text: str) -> set[Figure]:
    """Figures a source supports. "FY2024" also supports the bare year 2024."""
    keys: set[Figure] = set()
    for _, key, _, implied in _scan(text):
        keys.add(key)
        keys.update(implied)
    return keys


def _compatible(a: str, b: str) -> bool:
    # A bare number can stand in for a currency amount ("4,200,000" vs "$4.2 million").
    return a == b or (a == "" and b in _CURRENCIES) or (b == "" and a in _CURRENCIES)


def figure_supported(key: Figure, pool: set[Figure]) -> bool:
    if key in pool:
        return True
    unit, value = key
    if unit == "period":
        return False
    return any(u != "period" and v == value and _compatible(unit, u) for u, v in pool)


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
