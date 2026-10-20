"""The operation registry: what the client can do, declared once.

Every public operation of `AbuseIPDBClient` is decorated with `@operation`, which records the tool
name a host may offer it under and that it only reads. A host builds its agent-facing tools from
these entries and holds no API code of its own.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

Kind = Literal["read"]

F = TypeVar("F", bound=Callable[..., Any])

_ATTRIBUTE = "__operation__"


@dataclass(frozen=True)
class Operation:
    name: str
    """The `AbuseIPDBClient` method."""
    tool: str
    """The tool name a host offers it under."""
    kind: Kind
    """Every operation of this client reads: none reports, none changes anything."""
    description: str


def operation(*, tool: str) -> Callable[[F], F]:
    def decorate(method: F) -> F:
        described = Operation(
            name=method.__name__,
            tool=tool,
            kind="read",
            description=inspect.cleandoc(method.__doc__ or ""),
        )
        if not described.description:
            raise TypeError(
                f"operation {described.name} needs a docstring: it is the tool description"
            )
        setattr(method, _ATTRIBUTE, described)
        return method

    return decorate


def operations_of(owner: type[Any]) -> tuple[Operation, ...]:
    """Every operation declared on a class, in definition order."""
    return tuple(
        described
        for value in vars(owner).values()
        if isinstance(described := getattr(value, _ATTRIBUTE, None), Operation)
    )
