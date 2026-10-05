"""Threat indicators: allow, audit and block lists (Defender for Endpoint API, /indicators)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

from .errors import InvalidInputError
from .operations import operation
from .surface import Filter, Skip, Surface, top
from .transport import MDE, JsonObject, seg

IndicatorType = Literal[
    "FileSha1", "FileSha256", "FileMd5", "CertificateThumbprint", "IpAddress", "DomainName", "Url"
]
IndicatorAction = Literal[
    "Warn", "Block", "Audit", "Alert", "AlertAndBlock", "BlockAndRemediate", "Allowed"
]
Severity = Literal["Informational", "Low", "Medium", "High"]
_WRITE = ("Ti.ReadWrite.All",)
MAX_IMPORT = 500


class Indicator(BaseModel):
    """One indicator of a bulk import."""

    indicatorValue: str = Field(description="The hash, IP address, domain or URL.")
    indicatorType: IndicatorType
    action: IndicatorAction
    title: str
    description: str | None = None
    severity: Severity | None = None
    expirationTime: str | None = Field(default=None, description="UTC ISO 8601.")


class Indicators(Surface):
    @operation(tool="defender_get_indicators", api="mde", permissions=("Ti.Read.All",))
    async def list_indicators(
        self,
        filter: Filter = None,
        top: Annotated[int, top("indicators", 25, 100)] = 25,
        skip: Skip = 0,
    ) -> JsonObject:
        """List the custom indicators (allow, audit, warn, block) of the tenant, with OData
        filtering, e.g. "indicatorValue eq '203.0.113.7'", "action eq 'Block'"."""
        return await self._mde_list("/indicators", filter, top, skip)

    @operation(tool="defender_create_indicator", api="mde", kind="action", permissions=_WRITE)
    async def create_indicator(
        self,
        indicator_value: Annotated[str, Field(description="The hash, IP address, domain or URL.")],
        indicator_type: Annotated[IndicatorType, Field(description="Type of indicator.")],
        action: Annotated[IndicatorAction, Field(description="What happens on a match.")],
        title: Annotated[str, Field(description="Title of the indicator.")],
        description: Annotated[str, Field(description="Why it exists; name the case.")],
        severity: Annotated[Severity | None, Field(description="Severity of the alert.")] = None,
        recommended_actions: Annotated[
            str | None, Field(description="Recommended actions shown with the alert.")
        ] = None,
        expiration_time: Annotated[
            str | None,
            Field(description="UTC ISO 8601 expiry. Prefer an expiry to a permanent block."),
        ] = None,
        generate_alert: Annotated[
            bool | None, Field(description="Raise an alert on match.")
        ] = None,
        rbac_group_names: Annotated[
            list[str] | None, Field(description="Device groups the indicator applies to.")
        ] = None,
    ) -> JsonObject:
        """RESPONSE ACTION. Create an indicator that blocks, warns, audits or allows a file hash, IP
        address, domain, URL or certificate on every onboarded device. Returns the indicator with
        its id: keep it, it is what defender_delete_indicator needs to roll the block back."""
        body = {
            "indicatorValue": indicator_value,
            "indicatorType": indicator_type,
            "action": action,
            "title": title,
            "description": description,
            "severity": severity,
            "recommendedActions": recommended_actions,
            "expirationTime": expiration_time,
            "generateAlert": generate_alert,
            "rbacGroupNames": rbac_group_names,
        }
        return await self._mde_post("/indicators", {k: v for k, v in body.items() if v is not None})

    @operation(tool="defender_import_indicators", api="mde", kind="action", permissions=_WRITE)
    async def import_indicators(
        self,
        indicators: Annotated[
            list[Indicator], Field(description=f"Indicators to import (max {MAX_IMPORT}).")
        ],
    ) -> JsonObject:
        """RESPONSE ACTION. Create or update many indicators in one call. The result reports each
        indicator's outcome separately: check it, a batch can partly fail."""
        if not 0 < len(indicators) <= MAX_IMPORT:
            raise InvalidInputError(f"pass between 1 and {MAX_IMPORT} indicators")
        return await self._mde_post(
            "/indicators/import",
            {"Indicators": [i.model_dump(exclude_none=True) for i in indicators]},
        )

    @operation(tool="defender_delete_indicator", api="mde", kind="action", permissions=_WRITE)
    async def delete_indicator(
        self, indicator_id: Annotated[str, Field(description="The indicator ID.")]
    ) -> JsonObject:
        """RESPONSE ACTION. Delete an indicator by ID: the rollback of defender_create_indicator."""
        await self._api.request(MDE, "DELETE", f"/indicators/{seg(indicator_id)}")
        return {"deleted": indicator_id}

    @operation(
        tool="defender_batch_delete_indicators", api="mde", kind="action", permissions=_WRITE
    )
    async def batch_delete_indicators(
        self,
        indicator_ids: Annotated[list[str], Field(description="Indicator IDs (max 500).")],
    ) -> JsonObject:
        """RESPONSE ACTION. Delete many indicators by ID in one call."""
        if not 0 < len(indicator_ids) <= MAX_IMPORT:
            raise InvalidInputError(f"pass between 1 and {MAX_IMPORT} indicator ids")
        await self._mde_post("/indicators/BatchDelete", {"IndicatorIds": indicator_ids})
        return {"deleted": indicator_ids}
