"""Advanced hunting (Microsoft Graph security API, POST /security/runHuntingQuery)."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from .capabilities import TABLE_ENTITLEMENTS
from .operations import operation
from .surface import Surface, top
from .transport import GRAPH, JsonObject

HUNTING_TABLES: dict[str, str] = {
    "AlertInfo": "alert metadata across all Defender workloads",
    "AlertEvidence": "entities associated with alerts",
    "DeviceInfo": "device inventory and state",
    "DeviceProcessEvents": "process creation on onboarded devices",
    "DeviceNetworkEvents": "network connections made by onboarded devices",
    "DeviceFileEvents": "file creation, modification and deletion",
    "DeviceRegistryEvents": "registry changes",
    "DeviceLogonEvents": "logons on onboarded devices",
    "DeviceImageLoadEvents": "DLL loads",
    "DeviceEvents": "miscellaneous endpoint events, including antivirus and exploit protection",
    "DeviceTvmSoftwareInventory": "software inventory from vulnerability management",
    "DeviceTvmSoftwareVulnerabilities": "software vulnerabilities from vulnerability management",
    "IdentityInfo": "user identity details from the directory",
    "IdentityLogonEvents": "authentication events from identity sources",
    "IdentityDirectoryEvents": "directory object changes",
    "IdentityQueryEvents": "LDAP and other directory queries",
    "EmailEvents": "email messages and delivery actions",
    "EmailAttachmentInfo": "email attachment metadata",
    "EmailUrlInfo": "URLs in emails",
    "EmailPostDeliveryEvents": "actions taken on emails after delivery",
    "UrlClickEvents": "clicks on links protected by safe links",
    "CloudAppEvents": "activity in cloud applications, including mailbox audit events",
    "DisruptionAndResponseEvents": "automatic attack disruption actions, such as contained users",
}
"""The tables the capability probe checks, with what each holds. Which of them a tenant exposes, and
which hold data, depends on its licences: ask defender_get_capabilities before spending queries."""

DISRUPTION_TABLE = "DisruptionAndResponseEvents"
_DEVICE_COLUMNS = (
    "DeviceId",
    "SourceDeviceId",
    "TargetDeviceId",
    "DeviceName",
    "SourceDeviceName",
    "TargetDeviceName",
)
_USER_COLUMNS = ("SourceUserName", "SourceUserSid")
_NO_ROWS = (
    "no rows: the table records the outcomes of a containment (blocked logons, blocked file and RPC"
    " access, disconnected sessions, policy applications), never the containment itself, so an asset"
    " contained and never challenged leaves no row. This is not evidence that nothing was contained:"
    " the incident's Action center in the portal is the record of the action, and defender_get_capabilities"
    " says under probe.manual_checks whether it must be read by hand."
)


def kql_literal(value: str) -> str:
    """`value` as a KQL string literal, so a name that carries a quote is matched and never parsed."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def disruption_query(device: str | None, user: str | None, limit: int) -> str:
    """The bounded query over the disruption table, one `take` past the cap to know if more exist."""
    lines = [DISRUPTION_TABLE]
    if device:
        literal = kql_literal(device)
        lines.append("| where " + " or ".join(f"{c} =~ {literal}" for c in _DEVICE_COLUMNS))
    if user:
        literal = kql_literal(user)
        lines.append("| where " + " or ".join(f"{c} =~ {literal}" for c in _USER_COLUMNS))
    lines.append("| order by Timestamp desc")
    lines.append(f"| take {limit}")
    return "\n".join(lines)


class Hunting(Surface):
    @operation(
        tool="defender_run_hunting_query", api="graph", permissions=("ThreatHunting.Read.All",)
    )
    async def run_hunting_query(
        self,
        query: Annotated[
            str,
            Field(
                description="The Kusto Query Language (KQL) query. End exploratory queries with"
                " '| limit N' to keep results context-friendly."
            ),
        ],
        timespan: Annotated[
            str | None,
            Field(
                description="ISO 8601 duration limiting how far back to query, e.g. 'P7D' or"
                " 'PT12H'. Defaults to the service maximum (30 days)."
            ),
        ] = None,
    ) -> JsonObject:
        """Run an advanced hunting query (KQL) across Defender XDR data: endpoint, identity, email
        and cloud apps in one query. Tables include AlertInfo, AlertEvidence, DeviceProcessEvents,
        DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceEvents,
        IdentityLogonEvents, IdentityDirectoryEvents, EmailEvents, EmailUrlInfo, UrlClickEvents and
        CloudAppEvents. Which tables hold data depends on the tenant's licences: an empty result
        from a table that defender_get_capabilities reports as empty or not exposed is a visibility
        gap, not a finding and not a permissions problem. The sensor records no creation event for
        some processes (services started before it, some short-lived instances): a process absent
        from DeviceProcessEvents may still be there as the InitiatingProcessId and
        InitiatingProcessCreationTime of other events, so look there before concluding it did not
        run. Match a process by PID together with its creation time, never by PID alone.
        Timestamps are UTC. Data is limited to
        the last 30 days. Example: "DeviceProcessEvents | where Timestamp > ago(1d) | where
        FileName =~ 'powershell.exe' | project Timestamp, DeviceName, ProcessCommandLine | limit 50"."""
        body = {"Query": query, "Timespan": timespan}
        return await self._api.request(
            GRAPH,
            "POST",
            "/security/runHuntingQuery",
            json={k: v for k, v in body.items() if v},
        )

    @operation(
        tool="defender_get_disruption_events", api="graph", permissions=("ThreatHunting.Read.All",)
    )
    async def list_disruption_events(
        self,
        device: Annotated[
            str | None,
            Field(
                description="A device ID or device name: rows where it reported, originated or was"
                " the target of the event."
            ),
        ] = None,
        user: Annotated[
            str | None,
            Field(description="An account name or SID: rows about that contained account."),
        ] = None,
        timespan: Annotated[
            str,
            Field(
                description="ISO 8601 duration limiting how far back to read, e.g. 'P7D' or"
                " 'PT12H'. The service keeps 30 days."
            ),
        ] = "P7D",
        top: Annotated[int, top("events", 25, 100)] = 25,
    ) -> JsonObject:
        """What automatic attack disruption did on the endpoints, from the
        DisruptionAndResponseEvents hunting table: the logons, file and RPC access and sessions a
        contained user or device was blocked from (ActionType, e.g. ContainedUserLogonBlocked), the
        predictive-shielding policies applied, and which device reported each, newest first,
        within a time window and optionally for one device or one account. Call it before reporting
        containment state: the incident, alert and machine-action APIs return none of these
        actions. The table records the outcomes of a containment and never the containment itself,
        so an empty answer is not evidence that nothing was contained; the result says so and
        names the portal's Action center as the record. Only Defender for Endpoint controls appear
        here (a user disabled in the directory does not). Rows exist only where the tenant is
        entitled to the feature, which no query can tell: defender_get_capabilities reports the
        entitlement the deployment declared."""
        limit = max(1, min(top, 100))
        query = disruption_query(device, user, limit + 1)
        answer = await self.run_hunting_query(query, timespan=timespan)
        rows: list[Any] = list(answer.get("results") or [])
        result: JsonObject = {
            "table": DISRUPTION_TABLE,
            "timespan": timespan,
            "query": query,
            "entitlement": self._entitlement_note(),
            "results": rows[:limit],
            "rowCount": min(len(rows), limit),
            "hasMore": len(rows) > limit,
        }
        if not rows:
            result["note"] = _NO_ROWS
        return result

    def _entitlement_note(self) -> str:
        """What the deployment declared about the feature that writes the table."""
        entitlement = TABLE_ENTITLEMENTS[DISRUPTION_TABLE]
        if self._entitlements is None:
            return (
                f"undeclared: the deployment did not say whether it has {entitlement}, which is"
                " what writes this table, so an empty answer cannot be read either way"
            )
        if entitlement in self._entitlements:
            return f"{entitlement} is declared: the table is written when the feature acts"
        return f"{entitlement} is not among the declared entitlements: the feature is stated absent"
