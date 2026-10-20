"""Errors raised by the AbuseIPDB client.

A failure carries a code a host can act on and a plain sentence. It never carries the service's own
text: an error body may say anything, including where to buy a bigger plan, and whatever the host
reads aloud to a person or a model should be the host's words.
"""

from __future__ import annotations

from typing import Literal

Code = Literal[
    "unauthorized",
    "plan",
    "forbidden",
    "invalid_input",
    "quota",
    "unavailable",
    "timeout",
    "network",
    "unexpected",
]

SENTENCES: dict[Code, str] = {
    "unauthorized": "AbuseIPDB refused the key: it is missing, wrong or revoked.",
    "plan": "The AbuseIPDB plan behind this key does not cover the request.",
    "forbidden": "AbuseIPDB refused the request.",
    "invalid_input": "AbuseIPDB could not read the request.",
    "quota": "The AbuseIPDB plan's daily quota is spent; it resets at midnight UTC.",
    "unavailable": "AbuseIPDB is not answering right now.",
    "timeout": "AbuseIPDB did not answer in time.",
    "network": "AbuseIPDB could not be reached.",
    "unexpected": "AbuseIPDB answered in a shape this client does not know.",
}


class AbuseIPDBError(Exception):
    """A call failed. ``code`` says how, ``status`` is the HTTP status where there was one."""

    def __init__(self, code: Code, *, status: int | None = None) -> None:
        self.code: Code = code
        self.status = status
        super().__init__(SENTENCES[code])


class InvalidInputError(ValueError):
    """The caller passed something this client never sends: the message says what to pass."""
