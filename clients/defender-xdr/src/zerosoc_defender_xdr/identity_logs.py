"""Entra ID sign-in and directory audit logs (Microsoft Graph, /auditLogs)."""

from __future__ import annotations

from typing import Annotated

from .operations import operation
from .surface import Filter, OrderBy, Surface, top
from .transport import GRAPH, JsonObject, capped, odata

_PERMISSIONS = ("AuditLog.Read.All", "Directory.Read.All")


class IdentityLogs(Surface):
    @operation(tool="entra_list_sign_ins", api="graph", permissions=_PERMISSIONS)
    async def list_sign_ins(
        self,
        filter: Filter = None,
        top: Annotated[int, top("sign-ins", 25, 100)] = 25,
        orderby: OrderBy = None,
    ) -> JsonObject:
        """List interactive sign-ins from the Entra ID sign-in log: user, application, client and IP
        address, location, device, conditional access result, MFA detail, risk and error code.
        Always filter, e.g. "userPrincipalName eq 'alice@contoso.com' and createdDateTime ge
        2026-01-01T00:00:00Z", "ipAddress eq '203.0.113.7'", "status/errorCode ne 0". Timestamps are
        UTC. Requires an Entra ID P1 or P2 licence in the tenant; retention is 30 days."""
        return await self._api.request(
            GRAPH,
            "GET",
            "/auditLogs/signIns",
            params=odata(filter, capped(top, 25, 100), orderby=orderby),
        )

    @operation(tool="entra_list_directory_audits", api="graph", permissions=_PERMISSIONS)
    async def list_directory_audits(
        self,
        filter: Filter = None,
        top: Annotated[int, top("audit events", 25, 100)] = 25,
        orderby: OrderBy = None,
    ) -> JsonObject:
        """List Entra ID directory audit events: changes to users, groups, roles, applications,
        service principals, credentials and policies, with who made them. Always filter, e.g.
        "activityDisplayName eq 'Add member to role'", "initiatedBy/user/userPrincipalName eq
        'alice@contoso.com'", "activityDateTime ge 2026-01-01T00:00:00Z",
        "targetResources/any(t: t/id eq '<object id>')". Timestamps are UTC."""
        return await self._api.request(
            GRAPH,
            "GET",
            "/auditLogs/directoryAudits",
            params=odata(filter, capped(top, 25, 100), orderby=orderby),
        )
