"""Split an answer into sentence-level claims and read their citation markers."""

from __future__ import annotations

import re

from attestor.models import Claim
from attestor.text import content_tokens

CITATION = re.compile(r"\[\s*([A-Za-z0-9_-]+(?:\s*[,;]\s*[A-Za-z0-9_-]+)*)\s*\]")
_SPLIT_IDS = re.compile(r"\s*[,;]\s*")
_MARKERS_AFTER_PUNCT = re.compile(r"([.!?])((?:\s*\[[^\]]+\])+)")
_BOUNDARY = re.compile(r"(?:(?<=[.!?])|(?<=[.!?][\"')]))\s+(?=[\[\"'(]?[A-Z0-9])")
_BULLET = re.compile(r"^(?:[-*•]|\d+[.)])\s+")
_SPACE_BEFORE_PUNCT = re.compile(r"\s+([.,;:!?])")

_ABBREVIATIONS = {
    "u.s", "u.k", "e.g", "i.e", "inc", "corp", "co", "ltd", "llc", "vs", "mr", "mrs", "ms",
    "dr", "st", "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov",
    "dec", "approx", "est", "fig",
}

_FACT_WORDS = re.compile(
    r"\b(?:revenue|sales|ebitda|margin|profit|income|earnings|growth|grew|grow|increased?"
    r"|decreased?|declin\w*|rose|fell|raised|acquired|owns|holds|operates|employs|reported"
    r"|generated|outperform\w*|underperform\w*|largest|biggest|highest|lowest|leading|record"
    r"|market share|valuation|valued|rated|ranked)\b",
    re.IGNORECASE,
)


def is_factual(text: str) -> bool:
    """Heuristic: sentences with figures or performance language need a source."""
    if text.rstrip().endswith("?") or len(content_tokens(text)) < 3:
        return False
    return bool(re.search(r"\d", text) or _FACT_WORDS.search(text))


def _blocks(text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if current:
            blocks.append(" ".join(current))
            current.clear()

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            flush()
            continue
        if _BULLET.match(line):
            flush()
            line = _BULLET.sub("", line)
        current.append(line)
    flush()
    return blocks


def _ends_with_abbreviation(piece: str) -> bool:
    last = piece.rsplit(None, 1)[-1].lstrip("(\"'").rstrip(".").lower()
    return last in _ABBREVIATIONS or bool(re.fullmatch(r"[a-z]", last))


def split_sentences(text: str) -> list[str]:
    sentences: list[str] = []
    for block in _blocks(text):
        # "Revenue grew 8%. [S1]" -> "Revenue grew 8% [S1]."
        block = _MARKERS_AFTER_PUNCT.sub(r"\2\1", block)
        pending = ""
        for piece in _BOUNDARY.split(block):
            pending = f"{pending} {piece}" if pending else piece
            if not _ends_with_abbreviation(pending):
                sentences.append(pending.strip())
                pending = ""
        if pending:
            sentences.append(pending.strip())
    return [s for s in sentences if s]


def extract_claims(answer: str) -> list[Claim]:
    claims = []
    for index, sentence in enumerate(split_sentences(answer), start=1):
        cited: list[str] = []
        for match in CITATION.finditer(sentence):
            for source_id in _SPLIT_IDS.split(match.group(1)):
                if source_id not in cited:
                    cited.append(source_id)
        text = " ".join(CITATION.sub("", sentence).split())
        text = _SPACE_BEFORE_PUNCT.sub(r"\1", text)
        claims.append(Claim(index=index, text=text, citations=cited, is_factual=is_factual(text)))
    return claims
