from attestor.checks import (  # noqa: F401  (importing registers the built-in checks)
    citation_coverage,
    citation_grounding,
    phantom_citation,
    pii_leak,
    prohibited_language,
    required_disclosures,
)
from attestor.checks.base import BaseCheck, CheckContext, cap, register, registered


def all_checks() -> dict[str, type[BaseCheck]]:
    return registered()


__all__ = ["BaseCheck", "CheckContext", "all_checks", "cap", "register"]
