"""`mcp-defender-xdr`: run the server over stdio, configured from the environment."""

from __future__ import annotations

import asyncio
import os
import sys

from zerosoc_defender_xdr.auth import CREDENTIAL_VARIABLES
from zerosoc_defender_xdr.client import DefenderClient

from .server import ALLOW_ACTIONS, build_server, settings_from, warm_up


def main() -> None:
    settings = settings_from(os.environ)
    client = DefenderClient(
        settings.credential_or_placeholder(), allow_actions=settings.allow_actions
    )
    if settings.credential is None:
        print(f"warning: set {', '.join(CREDENTIAL_VARIABLES)} to reach a tenant", file=sys.stderr)
    actions = "ENABLED" if settings.allow_actions else f"disabled (set {ALLOW_ACTIONS}=true)"
    print(f"zerosoc-defender-xdr MCP server: response actions {actions}", file=sys.stderr)
    asyncio.run(_serve(client, probe=settings.credential is not None))


def _log(message: str) -> None:
    print(message, file=sys.stderr)  # standard output belongs to the protocol


async def _serve(client: DefenderClient, *, probe: bool) -> None:
    warming = asyncio.create_task(warm_up(client, _log)) if probe else None
    try:
        await build_server(client).run_stdio_async()
    finally:
        if warming is not None:
            warming.cancel()
        await client.aclose()


if __name__ == "__main__":
    main()
