"""Exposure score, secure score and antivirus health (Defender for Endpoint API)."""

from __future__ import annotations

from typing import Annotated

from .operations import operation
from .surface import Filter, Surface, top
from .transport import JsonObject

_SCORE = ("Score.Read.All",)


class Scoring(Surface):
    @operation(tool="defender_get_exposure_score", api="mde", permissions=_SCORE)
    async def get_exposure_score(self) -> JsonObject:
        """Get the organization's exposure score: lower is better."""
        return await self._mde_get("/exposureScore")

    @operation(tool="defender_get_secure_score", api="mde", permissions=_SCORE)
    async def get_secure_score(self) -> JsonObject:
        """Get the Microsoft Secure Score for Devices: higher is better."""
        return await self._mde_get("/configurationScore")

    @operation(tool="defender_get_machine_group_exposure_score", api="mde", permissions=_SCORE)
    async def get_machine_group_exposure_score(self) -> JsonObject:
        """Get the exposure score of each device group."""
        return await self._mde_get("/exposureScore/byMachineGroups")

    @operation(tool="defender_get_device_health", api="mde", permissions=("Machine.Read.All",))
    async def list_device_antivirus_health(
        self,
        filter: Filter = None,
        top: Annotated[int, top("devices", 25, 100)] = 25,
    ) -> JsonObject:
        """List the antivirus health of devices: mode, engine, platform and signature versions and
        their freshness, last quick and full scan. A device whose antivirus is passive, disabled or
        out of date explains a missing detection."""
        return await self._mde_list("/deviceavinfo", filter, top)

    @operation(
        tool="defender_export_antivirus_health", api="mde", permissions=("Machine.Read.All",)
    )
    async def export_antivirus_health(self) -> JsonObject:
        """Get the short-lived download links of the full antivirus health report of every device.
        For a bounded look at it use defender_get_device_health."""
        return await self._mde_get("/machines/InfoGatheringExport")
