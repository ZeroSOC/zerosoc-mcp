"""Alerts of every Defender XDR workload (Microsoft Graph security API, /security/alerts_v2)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .errors import InvalidInputError
from .operations import operation
from .surface import Classification, Determination, Filter, OrderBy, Surface, top
from .transport import GRAPH, JsonObject, capped, odata, seg

AlertId = Annotated[str, Field(description="The alert ID.")]
_READ = ("SecurityAlert.Read.All",)
_WRITE = ("SecurityAlert.ReadWrite.All",)


class Alerts(Surface):
    @operation(tool="defender_list_alerts", api="graph", permissions=_READ)
    async def list_alerts(
        self,
        filter: Filter = None,
        top: Annotated[int, top("alerts", 25, 100)] = 25,
        orderby: OrderBy = None,
    ) -> JsonObject:
        """List alerts from all Defender XDR workloads: Endpoint, Office 365 email, Identity, Cloud
        Apps and Entra ID Protection. Supports OData filtering with Graph camelCase values, e.g.
        "severity eq 'high'", "status eq 'new'", "serviceSource eq 'microsoftDefenderForEndpoint'",
        "createdDateTime gt 2026-01-01T00:00:00Z". Each alert carries its evidence inline. For the
        alerts of one incident use defender_get_incident_alerts."""
        return await self._api.request(
            GRAPH,
            "GET",
            "/security/alerts_v2",
            params=odata(filter, capped(top, 25, 100), orderby=orderby),
        )

    @operation(tool="defender_get_alert", api="graph", permissions=_READ)
    async def get_alert(self, alert_id: AlertId) -> JsonObject:
        """Get one alert with its full evidence (files, processes, registry keys, IPs, URLs, users,
        mailboxes, devices), MITRE techniques, detection source, detector ID and comment thread."""
        return await self._api.request(GRAPH, "GET", f"/security/alerts_v2/{seg(alert_id)}")

    @operation(tool="defender_update_alert", api="graph", kind="write", permissions=_WRITE)
    async def update_alert(
        self,
        alert_id: AlertId,
        status: Annotated[
            Literal["new", "inProgress", "resolved"] | None, Field(description="Alert status.")
        ] = None,
        assigned_to: Annotated[str | None, Field(description="Owner (UPN or email).")] = None,
        classification: Annotated[
            Classification | None, Field(description="Classification.")
        ] = None,
        determination: Annotated[Determination | None, Field(description="Determination.")] = None,
    ) -> JsonObject:
        """Update an alert (a triage write): status, assignee, classification and determination."""
        body = {
            "status": status,
            "assignedTo": assigned_to,
            "classification": classification,
            "determination": determination,
        }
        body = {k: v for k, v in body.items() if v is not None}
        if not body:
            raise InvalidInputError("nothing to update: pass at least one property")
        return await self._api.request(
            GRAPH, "PATCH", f"/security/alerts_v2/{seg(alert_id)}", json=body
        )

    @operation(tool="defender_add_alert_comment", api="graph", kind="write", permissions=_WRITE)
    async def add_alert_comment(
        self,
        alert_id: AlertId,
        comment: Annotated[str, Field(description="The comment text to append to the thread.")],
    ) -> JsonObject:
        """Append a comment to an alert's comment thread (a triage write), visible to analysts in
        the Defender portal. Notes about the whole case belong on the incident instead."""
        return await self._api.request(
            GRAPH,
            "POST",
            f"/security/alerts_v2/{seg(alert_id)}/comments",
            json={"@odata.type": "microsoft.graph.security.alertComment", "comment": comment},
        )
