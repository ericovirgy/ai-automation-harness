"""Exception hierarchy. Messages name fields and types, never user-supplied values."""

from __future__ import annotations


class HarnessError(Exception):
    """Base class for all harness errors."""


class MalformedRequestError(HarnessError):
    """A tool request is structurally invalid."""


class MalformedPolicyError(HarnessError):
    """A policy document is invalid, ambiguous or inconsistent with the registry."""


class ToolDeclarationError(HarnessError):
    """A tool declaration is invalid or inconsistent."""


class RegistrySealedError(HarnessError):
    """The registry was sealed and can no longer be modified."""


class ApprovalError(HarnessError):
    """An approval operation is not permitted in the current state."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ExecutionRefusedError(HarnessError):
    """The executor refused to run a tool because authorisation was not established."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class AuditIntegrityError(HarnessError):
    """An audit event or chain is malformed or has been tampered with."""


class ToolFailure(HarnessError):
    """Raised by a tool handler to report an expected failure (for example 'file not found')."""


class InvariantError(HarnessError):
    """An internal invariant was violated. Always a bug; the harness stops rather than guess."""
