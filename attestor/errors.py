class AttestorError(Exception):
    """Base class for errors that are reported to the user without a traceback."""


class CaseError(AttestorError):
    """A case file is missing, unreadable or invalid."""


class PolicyError(AttestorError):
    """A policy or pack is invalid."""


class JudgeError(AttestorError):
    """The LLM judge could not be created or did not return a usable answer."""


class AuditError(AttestorError):
    """The audit log is missing or unreadable."""
