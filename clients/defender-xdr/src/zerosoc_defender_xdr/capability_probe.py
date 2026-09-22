"""The capability probe as an operation."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Annotated, Any, cast

from pydantic import Field

from .operations import operation, operations_of
from .probe import build_binding, run_probe
from .surface import Surface
from .transport import JsonObject

if TYPE_CHECKING:
    from .client import DefenderClient


class CapabilityProbe(Surface):
    _binding: dict[str, Any] | None = None
    _probing: asyncio.Lock | None = None

    @operation(
        tool="defender_get_capabilities",
        api="graph",
        permissions=("SecurityIncident.Read.All", "SecurityAlert.Read.All"),
    )
    async def get_capabilities(
        self,
        refresh: Annotated[
            bool, Field(description="Probe the tenant again instead of returning the last result.")
        ] = False,
    ) -> JsonObject:
        """What this tenant exposes, as a ZeroSOC capability binding. Call it once before
        investigating. It checks which hunting tables hold data, which are exposed but empty and
        which the licence does not expose at all, which APIs answer, and which application
        permissions are granted, so an empty query result is read correctly: a visibility gap, a
        missing licence or a missing permission. A table only a licensed feature writes is
        reported against the entitlement the deployment declared, because no query tells a
        tenant that lacks the feature from one where it has not acted. Returns `capabilities` (capability class to tool),
        `data_sources` (each playbook data source, available or not, with the reason in
        `data_source_notes`) and `probe` (every check, the granted roles, the classes left unbound
        and the checks that stay manual). The probe only reads; the result is kept until refresh."""
        if self._probing is None:
            self._probing = asyncio.Lock()
        async with self._probing:  # callers that arrive during a probe wait for it, then share it
            if self._binding is not None and not refresh:
                return self._binding
            result = await run_probe(cast("DefenderClient", self), entitlements=self._entitlements)
            tools = {o.name: o.tool for o in operations_of(type(self))}
            binding = build_binding(result, tools, actions_enabled=self._allow_actions)
            # a probe taken during an outage describes the outage: answer with it, do not keep it
            self._binding = binding if result.complete else None
            return binding
