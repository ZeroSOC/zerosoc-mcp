"""What every group of operations shares: the transport, the action gate, parameter vocabulary."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .transport import MDE, JsonObject, Param, Transport, capped, odata


class Surface:
    """Base of the operation groups that `DefenderClient` is composed of."""

    _api: Transport
    _allow_actions: bool

    async def _mde_get(self, path: str) -> JsonObject:
        return await self._api.request(MDE, "GET", path)

    async def _mde_list(
        self, path: str, filter: str | None, top: int | None, skip: int = 0, *, maximum: int = 100
    ) -> JsonObject:
        """One bounded page of a Defender for Endpoint collection."""
        return await self._api.request(
            MDE, "GET", path, params=odata(filter, capped(top, 25, maximum), skip)
        )

    async def _mde_bounded(
        self, path: str, top: int | None, *, params: dict[str, Param] | None = None
    ) -> JsonObject:
        """A collection the API returns whole: cut here, and say how much there was."""
        result = await self._api.request(MDE, "GET", path, params=params)
        items = list(result.get("value") or [])
        size = capped(top, 25, 200)
        return {**result, "value": items[:size], "total": len(items), "hasMore": len(items) > size}

    async def _mde_post(self, path: str, body: JsonObject) -> JsonObject:
        return await self._api.request(MDE, "POST", path, json=body)


Filter = Annotated[
    str | None,
    Field(description="OData $filter expression. Refine the filter instead of paging deep."),
]
Skip = Annotated[int, Field(description="Number of entries to skip (paging).", ge=0)]
OrderBy = Annotated[str | None, Field(description='OData $orderby, e.g. "createdDateTime desc".')]
MachineId = Annotated[str, Field(description="The Defender for Endpoint machine (device) ID.")]
Comment = Annotated[str, Field(description="Why the action is taken; recorded with the action.")]

Classification = Literal[
    "unknown", "falsePositive", "truePositive", "informationalExpectedActivity"
]
Determination = Literal[
    "unknown",
    "apt",
    "malware",
    "securityPersonnel",
    "securityTesting",
    "unwantedSoftware",
    "multiStagedAttack",
    "compromisedAccount",
    "phishing",
    "maliciousUserActivity",
    "notMalicious",
    "lineOfBusinessApplication",
    "confirmedActivity",
    "other",
]


def top(what: str, default: int, maximum: int) -> object:
    return Field(
        description=f"Maximum number of {what} to return (default {default}, max {maximum})."
    )
