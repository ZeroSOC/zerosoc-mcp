"""What this integration can satisfy: capability classes, data sources, and the manifest of both.

Static knowledge only. The ZeroSOC skills ask for capability classes and name the data sources their
playbooks need; this module says which operation (and so which MCP tool) satisfies each class, and
which probe checks make each data source available. The probe (`probe.py`) adds what one tenant
actually exposes and produces the capability binding file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import metadata, resources
from typing import Any

SERVER = "defender-xdr"
ALERT_TYPE_MAP = "alert_types.defender-xdr.json"
RAW_TABLES = ("DeviceProcessEvents", "IdentityLogonEvents", "EmailEvents", "CloudAppEvents")


@dataclass(frozen=True)
class Option:
    """One way to satisfy a class: the first option whose requirements the tenant meets is bound."""

    operation: str
    requires_any: tuple[str, ...] = ()
    requires_all: tuple[str, ...] = ()
    notes: str = ""
    rollback: str | None = None


@dataclass(frozen=True)
class ClassBinding:
    klass: str
    options: tuple[Option, ...]


def _hunting(*tables: str) -> tuple[str, ...]:
    return tuple(f"hunting:{t}" for t in tables)


_MDE = ("api:mde.machines",)

CLASS_BINDINGS: tuple[ClassBinding, ...] = (
    ClassBinding(
        "asset.cmdb",
        (
            Option(
                "get_machine",
                requires_all=_MDE,
                notes="device role, OS, exposure, tags and device value (list_software for the software"
                " inventory); business criticality comes from the SOC Knowledge Base",
            ),
        ),
    ),
    ClassBinding(
        "identity.directory",
        (
            Option(
                "run_hunting_query",
                requires_all=_hunting("IdentityInfo"),
                notes="the IdentityInfo table: department, title, group membership, assigned roles",
            ),
            Option(
                "get_user_machines",
                requires_all=_MDE,
                notes="logon relationships only; role and privilege need a directory tool bound here",
            ),
        ),
    ),
    ClassBinding(
        "cases.store",
        (
            Option(
                "list_incidents",
                requires_all=("api:graph.incidents",),
                notes="open and closed incidents and their entities; the 90-day retrospective sweep"
                " runs here, never through telemetry",
            ),
        ),
    ),
    ClassBinding(
        "malware.repository",
        (
            Option(
                "get_file_info",
                requires_all=_MDE,
                notes="prevalence and first seen by hash (get_file_statistics for the organization);"
                " only the hash leaves the environment",
            ),
        ),
    ),
    ClassBinding(
        "decode",
        (
            Option(
                "decode_command",
                requires_all=("always:local",),
                notes="encoded PowerShell commands; timestamp_to_utc for time zones",
            ),
        ),
    ),
    ClassBinding(
        "telemetry.endpoint",
        (
            Option(
                "run_hunting_query",
                requires_all=_hunting("DeviceProcessEvents"),
                notes="raw endpoint telemetry through the Device* hunting tables",
            ),
            Option(
                "get_incident_evidence",
                requires_all=("api:graph.alerts",),
                notes="alert evidence only: there is no query language to translate playbook"
                " questions into; every question the evidence does not answer is a visibility gap",
            ),
        ),
    ),
    ClassBinding(
        "telemetry.identity",
        (
            Option(
                "list_sign_ins",
                requires_all=("api:graph.sign_ins",),
                notes="sign-in log (list_directory_audits for directory changes)",
            ),
            Option(
                "run_hunting_query",
                requires_all=_hunting("IdentityLogonEvents"),
                notes="the Identity* hunting tables",
            ),
        ),
    ),
    ClassBinding(
        "telemetry.email",
        (
            Option(
                "run_hunting_query",
                requires_all=_hunting("EmailEvents"),
                notes="the Email* and UrlClickEvents hunting tables",
            ),
        ),
    ),
    ClassBinding(
        "telemetry.cloud",
        (
            Option(
                "run_hunting_query",
                requires_all=_hunting("CloudAppEvents"),
                notes="the CloudAppEvents hunting table",
            ),
        ),
    ),
    ClassBinding(
        "telemetry.network",
        (
            Option(
                "run_hunting_query",
                requires_all=_hunting("DeviceNetworkEvents"),
                notes="connections as seen by the endpoint sensor; no proxy, DNS or firewall logs",
            ),
        ),
    ),
    ClassBinding(
        "siem.search",
        (
            Option(
                "run_hunting_query",
                requires_any=_hunting(*RAW_TABLES),
                notes="cross-workload KQL over the hunting tables the tenant exposes, 30 days",
            ),
        ),
    ),
    ClassBinding(
        "containment.isolate_host",
        (
            Option(
                "isolate_machine",
                requires_all=(*_MDE, "role:mde/Machine.Isolate"),
                rollback="unisolate_machine",
            ),
        ),
    ),
    ClassBinding(
        "containment.quarantine_file",
        (
            Option(
                "stop_and_quarantine_file",
                requires_all=(*_MDE, "role:mde/Machine.StopAndQuarantine"),
                notes="release from quarantine is done on the device or in the portal",
            ),
        ),
    ),
    ClassBinding(
        "containment.block_indicator",
        (
            Option(
                "create_indicator",
                requires_all=(*_MDE, "role:mde/Ti.ReadWrite.All"),
                notes="enforced on onboarded devices, not at the perimeter",
                rollback="delete_indicator",
            ),
        ),
    ),
    ClassBinding(
        "ticketing",
        (
            Option(
                "add_incident_comment",
                requires_all=("api:graph.incidents", "role:graph/SecurityIncident.ReadWrite.All"),
                notes="tuning tickets as incident comments until a ticketing tool is bound",
            ),
        ),
    ),
)

MANUAL_CHECKS: tuple[dict[str, str], ...] = (
    {
        "id": "attack_disruption_actions",
        "description": "Automatic attack disruption (for example a contained user) is not returned"
        " by the incident, alert or machine-action APIs. Where the DisruptionAndResponseEvents"
        " hunting table holds data, query it; otherwise check the incident's Action center in the"
        " portal by hand and record what it shows. Never report containment state without it.",
        "automated_by": "hunting:DisruptionAndResponseEvents",
    },
)


def _load_data_sources() -> dict[str, dict[str, Any]]:
    text = resources.files(__package__).joinpath("data_sources.json").read_text(encoding="utf-8")
    sources: dict[str, dict[str, Any]] = json.loads(text)["data_sources"]
    return sources


DATA_SOURCES: dict[str, dict[str, Any]] = _load_data_sources()
"""Framework `required_data_sources` name -> {"any_of": [checks], "note"?, "fallback"?}."""


ENTITLEMENTS: dict[str, str] = {
    "endpoint_p2": "Microsoft Defender for Endpoint Plan 2, however it is bought — as a Microsoft"
    " 365 licence assigned to users, or as the Defender for Servers plan billed on an Azure"
    " subscription. The two are indistinguishable from this API.",
}
"""Entitlement id -> what it is. An entitlement decides whether a source *can* answer; it is not a
permission and not a table's current contents."""

TABLE_ENTITLEMENTS: dict[str, str] = {
    "DisruptionAndResponseEvents": "endpoint_p2",
}
"""Hunting table -> the entitlement that writes it, for the tables a tier gates.

A table that is absent from this map is written by ordinary traffic, so an empty answer from it
means the traffic did not occur. A table that is present is written only by a licensed feature, and
then an empty answer is ambiguous: the tenant may lack the feature, or the feature may simply not
have acted. **No query resolves that ambiguity** — the table's schema resolves at every tier and the
query succeeds and returns nothing either way — so the entitlement is declared by the deployment
rather than probed. Entries are added as a tier is established, never guessed.
"""


def tool_ref(tool: str) -> str:
    return f"mcp:{SERVER}/{tool}"


def operation_ref(operation: str) -> str:
    return f"{SERVER}:{operation}"


def version() -> str:
    try:
        return metadata.version("zerosoc-defender-xdr")
    except metadata.PackageNotFoundError:  # running from a source tree that was never installed
        return "0+unknown"
