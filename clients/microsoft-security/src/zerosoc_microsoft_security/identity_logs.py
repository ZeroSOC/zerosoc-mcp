"""Entra ID sign-in and directory audit logs (Microsoft Graph, /auditLogs), and which Entra ID plan
the tenant has, which decides whether the sign-in log can be read at all."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from .errors import InvalidInputError
from .operations import operation
from .surface import Filter, OrderBy, Surface, top
from .transport import GRAPH, JsonObject, capped, odata

_PERMISSIONS = ("AuditLog.Read.All", "Directory.Read.All")

ENTRA_P1_PLAN = "41781fb2-bc02-4b7c-bd55-b576c07bb09d"
"""Service plan `AAD_PREMIUM`, Entra ID P1: in Business Premium, E3 and EMS E3, or bought alone."""
ENTRA_P2_PLAN = "eec0eb4f-6444-4f95-aba0-50c24d67f998"
"""Service plan `AAD_PREMIUM_P2`, Entra ID P2: in E5 and EMS E5, or bought alone."""
ACTIVE_SUBSCRIPTION = ("Enabled", "Warning")
"""A subscription whose services work: `Warning` is the grace period after it lapses."""
SIGN_IN_LIMIT = 50_000
"""The most sign-ins one window returns; a window holding more is cut and says so."""
SIGN_IN_PAGE = 1000
"""The page size asked of the sign-in log, its maximum."""

EntraPlan = Literal["P1", "P2"]


@dataclass(frozen=True)
class SignInWindow:
    """The interactive sign-ins of one window, as the sign-in log lists them."""

    start: str
    end: str
    sign_ins: tuple[JsonObject, ...]
    truncated: bool
    """True when the window held more than `SIGN_IN_LIMIT`: some sign-ins are missing."""


class IdentityLogs(Surface):
    async def sign_ins_between(self, start: str, end: str) -> SignInWindow:
        """**The data plane**: every interactive sign-in created in ``[start, end)``, read page by
        page up to `SIGN_IN_LIMIT`. Graph v1.0 lists interactive sign-ins only. A sign-in is listed
        some minutes after it happens (5 to 9 measured on a Business Premium tenant), so a poller
        reads a window reaching back beyond its interval and drops what it has seen by `id`.

        Needs Entra ID P1 or P2 in the tenant (`entra_id_plan`); without it the log answers 403.
        """
        low, high = _instant(start, "start"), _instant(end, "end")
        found = await self._api.collect(
            GRAPH,
            "/auditLogs/signIns",
            params={
                "$filter": f"createdDateTime ge {low} and createdDateTime lt {high}",
                "$top": str(SIGN_IN_PAGE),
            },
            limit=SIGN_IN_LIMIT + 1,
        )
        return SignInWindow(
            start=low,
            end=high,
            sign_ins=tuple(found[:SIGN_IN_LIMIT]),
            truncated=len(found) > SIGN_IN_LIMIT,
        )

    async def entra_id_plan(self) -> EntraPlan | None:
        """**The data plane**: the highest Entra ID plan the tenant has in use, read from its
        subscriptions (`subscribedSkus`), whatever product brings it; None when it has neither.
        This is what the tenant bought; a probe of the sign-in log shows only what answers today.
        Needs `Organization.Read.All` or `Directory.Read.All`."""
        skus = await self._api.collect(
            GRAPH,
            "/subscribedSkus",
            params={"$select": "skuPartNumber,capabilityStatus,consumedUnits,servicePlans"},
            limit=1000,
        )
        return entra_id_plan(skus)

    @operation(tool="entra_list_sign_ins", api="graph", permissions=_PERMISSIONS)
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


def entra_id_plan(skus: Iterable[Any]) -> EntraPlan | None:
    """`subscribedSkus` -> "P2", "P1" or None. A plan counts when its subscription is active, has
    seats assigned, and the plan is provisioned in it: a suspended trial, a subscription nobody is
    assigned to, or a plan switched off in it brings nothing."""
    plans = {
        str(plan.get("servicePlanId", "")).lower()
        for sku in skus
        if sku.get("capabilityStatus") in ACTIVE_SUBSCRIPTION
        and (sku.get("consumedUnits") or 0) > 0
        for plan in sku.get("servicePlans") or []
        if plan.get("provisioningStatus") == "Success"
    }
    if ENTRA_P2_PLAN in plans:
        return "P2"
    if ENTRA_P1_PLAN in plans:
        return "P1"
    return None


def _instant(value: str, what: str) -> str:
    """An ISO 8601 timestamp with a zone, as the UTC literal an OData filter takes."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None:
        raise InvalidInputError(
            f"{what} must be an ISO 8601 timestamp with a zone such as 2026-09-30T08:00:00Z, "
            f"not {value!r}"
        )
    return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
