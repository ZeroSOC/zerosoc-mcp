"""Advanced hunting (Microsoft Graph security API, POST /security/runHuntingQuery)."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .operations import operation
from .surface import Surface
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
