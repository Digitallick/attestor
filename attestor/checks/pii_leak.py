from __future__ import annotations

import re

from attestor.checks.base import BaseCheck, CheckContext, register
from attestor.errors import PolicyError
from attestor.models import Finding, Severity


def _luhn_ok(value: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", value)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _iban_ok(value: str) -> bool:
    compact = value.replace(" ", "")
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


# name -> (pattern, optional validator, capture group holding the value)
DETECTORS = {
    "ssn": (re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None, 0),
    "credit_card": (re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), _luhn_ok, 0),
    "iban": (re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"),
             _iban_ok, 0),
    "us_bank_account": (
        re.compile(r"\b(?:account|acct|routing|aba)(?:\s+(?:number|no\.?|#))?\s*[:#]?\s*(\d{6,17})\b",
                   re.IGNORECASE),
        None,
        1,
    ),
    "email": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None, 0),
    "phone": (
        re.compile(r"(?<!\d)(?:\+?1[ .-]?)?(?:\(\d{3}\) ?|\d{3}[.-])\d{3}[.-]\d{4}(?!\d)"), None, 0
    ),
}


LABELS = {
    "ssn": "SSN",
    "credit_card": "card number",
    "iban": "IBAN",
    "us_bank_account": "bank account number",
    "email": "email address",
    "phone": "phone number",
}


def mask(detector: str, value: str) -> str:
    if detector == "email":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    return "*" * max(len(value) - 4, 0) + value[-4:]


def find_pii(text: str, detectors=None) -> list[tuple[str, int, int, str]]:
    """(detector, start, end, value) for each hit, first detector wins on overlaps."""
    hits: list[tuple[str, int, int, str]] = []
    for name, (pattern, validator, group) in DETECTORS.items():
        if detectors is not None and name not in detectors:
            continue
        for match in pattern.finditer(text):
            start, end = match.span(group)
            value = match.group(group)
            if any(start < h_end and h_start < end for _, h_start, h_end, _ in hits):
                continue
            if validator and not validator(value):
                continue
            hits.append((name, start, end, value))
    return hits


def redact(text: str) -> str:
    """Mask anything any detector recognises. Used on every finding before it leaves the engine."""
    for name, start, end, value in sorted(find_pii(text), key=lambda h: h[1], reverse=True):
        text = text[:start] + mask(name, value) + text[end:]
    return text


@register
class PiiLeak(BaseCheck):
    id = "pii_leak"
    title = "No personal or account data in the answer"
    default_severity = Severity.BLOCK

    def run(self, ctx: CheckContext) -> list[Finding]:
        enabled = ctx.items("detectors", default=list(DETECTORS))
        unknown = sorted(set(enabled) - set(DETECTORS))
        if unknown:
            raise PolicyError(f"pii_leak: unknown detector(s) {', '.join(unknown)}")
        return [
            ctx.finding(
                f"Possible {LABELS[name]} in answer",
                evidence={"detector": name, "masked": mask(name, value)},
            )
            for name, _, _, value in find_pii(ctx.case.answer, enabled)
        ]
