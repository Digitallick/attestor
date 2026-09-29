from attestor.checks import citation_coverage, citation_grounding, phantom_citation  # noqa: F401
from attestor.checks.base import BaseCheck, CheckContext, cap, register, registered


def all_checks() -> dict[str, type[BaseCheck]]:
    return registered()
