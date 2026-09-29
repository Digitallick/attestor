from attestor.checks.base import BaseCheck, CheckContext, cap, register, registered


def all_checks() -> dict[str, type[BaseCheck]]:
    return registered()
