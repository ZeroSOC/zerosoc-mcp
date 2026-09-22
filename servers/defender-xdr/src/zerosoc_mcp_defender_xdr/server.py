"""The MCP server: one tool per operation of the tool client, and no API code of its own."""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from zerosoc_defender_xdr.auth import CREDENTIAL_VARIABLES, Token, TokenCredential, credential_from
from zerosoc_defender_xdr.capabilities import version
from zerosoc_defender_xdr.client import OPERATIONS, DefenderClient
from zerosoc_defender_xdr.errors import (
    ActionsDisabledError,
    DefenderApiError,
    InvalidInputError,
    RedirectLoopError,
)

NAME = "zerosoc-defender-xdr"
ALLOW_ACTIONS = "DEFENDER_MCP_ALLOW_ACTIONS"
ENTITLEMENTS = "DEFENDER_MCP_ENTITLEMENTS"
"""Comma-separated entitlement ids this tenant has, for the sources a licensing tier gates and
no query can settle (see TABLE_ENTITLEMENTS). Setting it states the **complete** set, so an
entitlement left out is stated to be absent; leaving it unset states nothing, and the probe
then reports those sources as undeclared rather than guessing either way."""
INSTRUCTIONS = (
    "Microsoft Defender XDR for one tenant. Call defender_get_capabilities once before"
    " investigating: it says which hunting tables and APIs this tenant exposes, so an empty result"
    " is read as a visibility gap and not as a finding. Start an incident from"
    " defender_get_incident, then defender_get_incident_evidence for every entity its alerts cite."
    " Timestamps are UTC. Tools that write say so in their description; response actions are listed"
    f" only when the deployment sets {ALLOW_ACTIONS}=true."
)


class NotConfiguredError(RuntimeError):
    pass


EXPLAINED = (
    DefenderApiError,
    ActionsDisabledError,
    RedirectLoopError,
    NotConfiguredError,
    InvalidInputError,
)
"""Failures whose text is written for the agent: status, message, remediation. Anything else is a
crash, and its text stays on the server."""


class _NotConfigured:
    """Stands in for the credential so the server starts, lists its tools and explains itself."""

    async def get_token(self, *scopes: str) -> Token:
        raise NotConfiguredError(
            "Authentication is not configured. Set the environment variables "
            + ", ".join(CREDENTIAL_VARIABLES)
            + " for an app registration with application permissions in the tenant."
        )


@dataclass(frozen=True)
class Settings:
    credential: TokenCredential | None
    allow_actions: bool
    entitlements: frozenset[str] | None

    def credential_or_placeholder(self) -> TokenCredential:
        return self.credential or _NotConfigured()


def settings_from(environment: Mapping[str, str]) -> Settings:
    return Settings(
        credential=credential_from(environment),
        allow_actions=environment.get(ALLOW_ACTIONS, "").strip().lower() == "true",
        entitlements=_declared(environment.get(ENTITLEMENTS)),
    )


def _declared(value: str | None) -> frozenset[str] | None:
    """The declared entitlements, or None when the deployment declared nothing.

    An empty or whitespace-only value is a declaration that the tenant has none, which is not
    the same as saying nothing: the first answers the question, the second leaves it open.
    """
    if value is None:
        return None
    return frozenset(part.strip() for part in value.split(",") if part.strip())


def build_server(client: DefenderClient) -> MCPServer:
    """Register every operation the client allows. Response actions follow the client's own gate."""
    server = MCPServer(name=NAME, version=version(), instructions=INSTRUCTIONS)
    for operation in OPERATIONS:
        if operation.kind == "action" and not client.allow_actions:
            continue
        server.add_tool(
            _explaining(getattr(client, operation.name)),
            name=operation.tool,
            description=operation.description,
            annotations=ToolAnnotations(
                read_only_hint=operation.kind == "read",
                destructive_hint=operation.kind == "action",
                open_world_hint=operation.api != "local",
            ),
            structured_output=False,
        )
    return server


def _explaining(call: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """The operation, unchanged, with its explained failures passed to the agent as tool errors."""

    @functools.wraps(call)
    async def tool(*args: Any, **kwargs: Any) -> Any:
        try:
            return await call(*args, **kwargs)
        except EXPLAINED as error:
            raise ToolError(str(error)) from error

    return tool


async def warm_up(client: DefenderClient, log: Callable[[str], None]) -> None:
    """Probe the tenant as the server starts, so the first question about capabilities is already
    answered. A probe that cannot run is reported and never stops the server."""
    try:
        binding = await client.get_capabilities()
    except Exception as error:
        log(f"capability probe did not run: {error}")
        return
    log(f"capability probe: hunting {binding['probe']['hunting']}")
