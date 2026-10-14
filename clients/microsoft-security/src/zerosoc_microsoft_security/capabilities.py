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
"""The integration's id in the capabilities manifest and the binding (`mcp:defender-xdr/<tool>`,
`defender-xdr:<operation>`). It predates the package's rename to microsoft-security and stays:
bindings, conformance corpora and the skills' source profile are keyed on it."""
SOURCE_PROFILES: dict[str, str] = {SERVER: "zerosoc-defender-xdr/source_profile.json"}
"""Source identifier -> the source profile of this technology, as the binding names it.

The profile lives with the tool skill of its technology, so the binding names it from there and
the skills' loader looks for it beside the binding file first (a deployment's own copy wins) and
then beside the installed skills. The probe emits nothing else for it: the name resolves wherever
the tool skill is installed, so a freshly probed deployment reads its alert-type rules with no file
copied by hand.
"""
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
                " runs here, never through telemetry, read on from nextSkip until hasMore is false",
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
        "containment.suspend_sessions",
        (
            Option(
                "revoke_sign_in_sessions",
                requires_all=("api:graph.users",),
                requires_any=(
                    "role:graph/User.RevokeSessions.All",
                    "role:graph/User.ReadWrite.All",
                ),
                notes="ends every session of the account and changes nothing about it: the person"
                " signs in again, so there is no rollback to call. Access tokens already issued"
                " live until they expire, up to an hour",
            ),
        ),
    ),
    ClassBinding(
        "containment.disable_account",
        (
            Option(
                "disable_account",
                requires_all=("api:graph.users",),
                requires_any=(
                    "role:graph/User.EnableDisableAccount.All",
                    "role:graph/User.ReadWrite.All",
                ),
                notes="the sessions already open are not ended by it; pair it with"
                " containment.suspend_sessions. An account mastered in on-premises Active Directory"
                " is disabled there, not here",
                rollback="enable_account",
            ),
        ),
    ),
    ClassBinding(
        "containment.remove_inbox_rule",
        (
            Option(
                "delete_inbox_rule",
                requires_all=("api:graph.users",),
                requires_any=("role:graph/Mail.ReadWrite",),
                notes="removal destroys the rule, so read it with mailbox_get_inbox_rule first:"
                " what that answers is the only thing the rollback can be made from",
                rollback="create_inbox_rule",
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
        "description": "Automatic attack disruption actions (a contained user or device, a disabled"
        " account) are returned by no API: the machine-action types are the manual ones, alert"
        " evidence carries the state of the automated investigation, and the"
        " DisruptionAndResponseEvents hunting table records only the outcomes of a containment"
        " (blocked logons, blocked file and RPC access, disconnected sessions, policy"
        " applications), never the containment itself. Where the table holds rows, read them with"
        " the tool named here; where it holds none, the incident's Action center in the portal is"
        " the record of the action: read it by hand and record what it shows. Never report"
        " containment state without one of the two.",
        "automated_by": "hunting:DisruptionAndResponseEvents",
        "operation": "list_disruption_events",
    },
)
"""A check no API automates fully. `automated_by` is the probe check that, when it holds rows,
lets `operation` answer instead of the portal; the binding says per tenant whether that is so."""


def _load_data_sources() -> dict[str, dict[str, Any]]:
    text = resources.files(__package__).joinpath("data_sources.json").read_text(encoding="utf-8")
    sources: dict[str, dict[str, Any]] = json.loads(text)["data_sources"]
    return sources


DATA_SOURCES: dict[str, dict[str, Any]] = _load_data_sources()
"""Framework `required_data_sources` name -> {"any_of": [checks], "note"?, "fallback"?}."""


ENTITLEMENTS: dict[str, str] = {
    "endpoint_p2": "Microsoft Defender for Endpoint Plan 2, however it is bought — as a Microsoft"
    " 365 licence assigned to users, or as the Defender for Servers plan billed on an Azure"
    " subscription. The two are indistinguishable from this API. Defender for Business, which"
    " Microsoft 365 Business Premium includes, does not write the device event tables.",
    "endpoint_p1": "No Defender for Endpoint Plan 2: Plan 1, Defender for Business, or no endpoint"
    " plan. Declared to state endpoint_p2 absent.",
    "office365_p2": "Microsoft Defender for Office 365 Plan 2, alone or in a suite. Plan 1, which"
    " Microsoft 365 Business Premium includes, does not write the email hunting tables.",
    "office365_p1": "No Defender for Office 365 Plan 2: Plan 1, Exchange Online Protection alone,"
    " or no mail plan. Declared to state office365_p2 absent.",
}
"""Entitlement id -> what it is. An entitlement decides whether a source *can* answer; it is not a
permission and not a table's current contents."""
ENTITLEMENT_FAMILIES: dict[str, str] = {
    "endpoint_p2": "endpoint",
    "endpoint_p1": "endpoint",
    "office365_p2": "office365",
    "office365_p1": "office365",
}
"""Entitlement id -> the family of tiers it belongs to. A declaration speaks for the families it names
an id of, and for no other: a deployment that declared `endpoint_p2` before the email tables were
gated said nothing about them, and they stay undeclared. An empty declaration states that the tenant
has none of them, as it always has."""


def entitlement_stated(entitlement: str, declared: frozenset[str] | None) -> bool | None:
    """Whether a declaration states the entitlement held (True) or absent (False), or says nothing
    about it (None): nothing was declared, or the declaration names no id of its family."""
    if declared is None:
        return None
    if entitlement in declared:
        return True
    family = ENTITLEMENT_FAMILIES[entitlement]
    if not declared or any(ENTITLEMENT_FAMILIES.get(d) == family for d in declared):
        return False
    return None


def check_entitlements(declared: frozenset[str] | None) -> frozenset[str] | None:
    """The declaration, refused when it names an id this integration does not know: a misspelt id
    would state its family absent, or nothing at all, and the probe would report either with
    confidence."""
    unknown = sorted((declared or frozenset()) - set(ENTITLEMENTS))
    if unknown:
        raise ValueError(
            f"unknown entitlement ids {', '.join(unknown)}; the known ids are"
            f" {', '.join(ENTITLEMENTS)}"
        )
    return declared


_DEVICE_TABLES = (
    "DeviceInfo",
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceLogonEvents",
    "DeviceImageLoadEvents",
    "DeviceEvents",
)
_EMAIL_TABLES = (
    "EmailEvents",
    "EmailAttachmentInfo",
    "EmailUrlInfo",
    "EmailPostDeliveryEvents",
    "UrlClickEvents",
)

TABLE_ENTITLEMENTS: dict[str, str] = {
    "DisruptionAndResponseEvents": "endpoint_p2",
    **dict.fromkeys(_DEVICE_TABLES, "endpoint_p2"),
    **dict.fromkeys(_EMAIL_TABLES, "office365_p2"),
}
"""Hunting table -> the entitlement that writes it, for the tables a tier gates.

A table that is absent from this map has no tier established as gating it, and is read as it
answers. A table that is present is written only under its entitlement, and then an empty answer is ambiguous: the tenant may
lack the entitlement, or nothing may have written to the table. **No query resolves that ambiguity**
— the table's schema resolves at every tier and the query succeeds and returns nothing either way —
so the entitlement is declared by the deployment rather than probed, and an empty gated table with
nothing declared is unavailable, never a quiet tenant. Entries are added as a tier is established,
never guessed: on a Microsoft 365 Business Premium tenant with onboarded devices and mail, hunting
answered, the directory, vulnerability-management and alert tables held rows, and the device event
and email tables held none.
"""
ACTING_TABLES: frozenset[str] = frozenset({"DisruptionAndResponseEvents"})
"""The gated tables written only when their feature acts. Under a declared entitlement an empty one
is an answer: the feature did not act. Every other gated table is written by each device or mailbox
the entitlement covers, as it runs, so under the entitlement an empty one says that no source
reported, which is a gap and not an answer."""


def tool_ref(tool: str) -> str:
    return f"mcp:{SERVER}/{tool}"


def operation_ref(operation: str) -> str:
    return f"{SERVER}:{operation}"


def version() -> str:
    try:
        return metadata.version("zerosoc-microsoft-security")
    except metadata.PackageNotFoundError:  # running from a source tree that was never installed
        return "0+unknown"
