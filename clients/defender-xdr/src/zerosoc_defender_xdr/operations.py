"""The operation registry: what the client can do, declared once, read by the MCP server.

Every public operation of `DefenderClient` is decorated with `@operation`. The decorator records the
MCP tool name, whether the call reads, writes triage metadata or acts on the estate, the API it
reaches and the application permissions it needs. The MCP server registers one tool per entry and
holds no API code of its own; the capability manifest is generated from the same entries.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Concatenate, Literal, ParamSpec, Protocol, TypeVar

from .errors import ActionsDisabledError

Kind = Literal["read", "write", "action"]
ApiName = Literal["graph", "mde", "local"]


@dataclass(frozen=True)
class Operation:
    name: str
    """The `DefenderClient` method."""
    tool: str
    """The MCP tool that wraps it."""
    kind: Kind
    """read: no side effect. write: triage metadata (comments, status, tags). action: changes the
    estate (isolation, quarantine, indicators, live response) and is off unless explicitly enabled."""
    api: ApiName
    permissions: tuple[str, ...]
    description: str


class _Gated(Protocol):
    _allow_actions: bool


P = ParamSpec("P")
R = TypeVar("R")
S = TypeVar("S", bound=_Gated)

_ATTRIBUTE = "__operation__"


def operation(
    *, tool: str, api: ApiName, kind: Kind = "read", permissions: tuple[str, ...] = ()
) -> Callable[
    [Callable[Concatenate[S, P], Awaitable[R]]], Callable[Concatenate[S, P], Awaitable[R]]
]:
    def decorate(
        method: Callable[Concatenate[S, P], Awaitable[R]],
    ) -> Callable[Concatenate[S, P], Awaitable[R]]:
        described = Operation(
            name=method.__name__,
            tool=tool,
            kind=kind,
            api=api,
            permissions=permissions,
            description=inspect.cleandoc(method.__doc__ or ""),
        )
        if not described.description:
            raise TypeError(
                f"operation {described.name} needs a docstring: it is the tool description"
            )

        @functools.wraps(method)
        async def call(self: S, /, *args: P.args, **kwargs: P.kwargs) -> R:
            if kind == "action" and not self._allow_actions:
                raise ActionsDisabledError(
                    f"{described.name} is a response action and this client was created without"
                    " allow_actions=True"
                )
            return await method(self, *args, **kwargs)

        setattr(call, _ATTRIBUTE, described)
        return call

    return decorate


def operations_of(owner: type[Any]) -> tuple[Operation, ...]:
    """Every operation declared on a class and its bases, in definition order, names unique."""
    found: dict[str, Operation] = {}
    for klass in reversed(owner.__mro__):
        for value in vars(klass).values():
            described = getattr(value, _ATTRIBUTE, None)
            if isinstance(described, Operation):
                found[described.name] = described
    tools = [o.tool for o in found.values()]
    duplicated = {t for t in tools if tools.count(t) > 1}
    if duplicated:
        raise TypeError(f"tool names declared twice: {sorted(duplicated)}")
    return tuple(found.values())
