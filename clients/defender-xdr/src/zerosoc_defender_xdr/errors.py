"""Errors raised by the tool client."""

from __future__ import annotations


class DefenderApiError(Exception):
    """An API call failed. Carries what an operator needs: status, API, call, message, remediation."""

    def __init__(
        self,
        *,
        status: int,
        api: str,
        method: str,
        path: str,
        code: str,
        message: str,
        hint: str = "",
    ) -> None:
        self.status = status
        self.api = api
        self.method = method
        self.path = path
        self.code = code
        self.message = message
        self.hint = hint
        label = f"{code}: " if code else ""
        super().__init__(f"{api} API error ({status}) on {method} {path}: {label}{message}{hint}")


class ActionsDisabledError(PermissionError):
    """A response action was called on a client that was not created with allow_actions=True."""


class RedirectLoopError(RuntimeError):
    """Merged incidents point at each other, or the chain is longer than any real merge history."""


class InvalidInputError(ValueError):
    """The caller passed something the operation cannot use; the message says what to pass instead."""
