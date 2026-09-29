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
    "phone": (re.compile(r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]\d{4}(?!\d)"), None, 0),
}


def mask(detector: str, value: str) -> str:
    if detector == "email":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    return "*" * max(len(value) - 4, 0) + value[-4:]


@register
class PiiLeak(BaseCheck):
    id = "pii_leak"
    title = "No personal or account data in the answer"
    default_severity = Severity.BLOCK

    def run(self, ctx: CheckContext) -> list[Finding]:
        enabled = ctx.options.get("detectors", list(DETECTORS))
        unknown = sorted(set(enabled) - set(DETECTORS))
        if unknown:
            raise PolicyError(f"pii_leak: unknown detector(s) {', '.join(unknown)}")

        findings, taken = [], []
        for name in DETECTORS:  # fixed order so overlaps resolve the same way every run
            if name not in enabled:
                continue
            pattern, validator, group = DETECTORS[name]
            for match in pattern.finditer(ctx.case.answer):
                start, end = match.span(group)
                value = match.group(group).strip()
                if any(start < t_end and t_start < end for t_start, t_end in taken):
                    continue
                if validator and not validator(value):
                    continue
                taken.append((start, end))
                findings.append(ctx.finding(
                    f"Possible {name.replace('_', ' ')} in answer",
                    evidence={"detector": name, "masked": mask(name, value)},
                ))
        return findings
