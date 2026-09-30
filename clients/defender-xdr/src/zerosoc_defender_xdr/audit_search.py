"""The Microsoft 365 audit log through Microsoft Graph Audit Search (/security/auditLog/queries).

A search is asynchronous: it is created, it runs for minutes, and its records are read when it has
succeeded. The agent-plane operations expose those three steps. `alert_policy_alerts` is the data
plane: it runs one search for the alert records of a time window and returns them as typed alerts.

Two properties of the service shape every caller:

- **A search cannot be deleted.** Creating one adds a saved search to the tenant's audit search list
  (`DELETE` answers 405). A poller leaves one entry per poll behind; name them recognisably.
- **Auditing must be on.** Unified audit logging is off by default on the small-business plans, and
  with it off there is nothing to search. The client never turns it on.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from pydantic import Field

from .errors import DefenderApiError, InvalidInputError
from .operations import operation
from .surface import Surface, top
from .transport import GRAPH, JsonObject, capped, odata, seg

_PERMISSIONS = ("AuditLogsQuery.Read.All",)
_PATH = "/security/auditLog/queries"

ALERT_RECORD_TYPE = "securityComplianceAlerts"
"""Record type 40: what an Office 365 alert policy writes when it raises, updates or names an alert."""
ALERT_OPERATIONS = ("AlertTriggered", "AlertEntityGenerated", "AlertUpdated")
RUNNING = ("notStarted", "running")
POLL_SECONDS = 30.0
TIMEOUT_SECONDS = 900.0
ACTIVITY_SLACK_SECONDS = 300
"""How far either side of an alert's activity time the activity behind it is looked for."""
ACTIVITY_LIMIT = 20
RECORD_LIMIT = 5000
"""Alert records read from one search at most; `AlertSearch.truncated` says when the limit was hit."""

Timestamp = Annotated[str, Field(description="UTC ISO 8601 timestamp, e.g. 2026-09-30T08:00:00Z.")]
Names = Annotated[
    list[str] | None,
    Field(description="Optional list; a record matches when it matches any entry."),
]


class AuditingDisabledError(DefenderApiError):
    """The tenant does not record the audit log, so no search can answer. Only the tenant's admin can
    turn it on (Microsoft Purview, Audit); this client never does."""


@dataclass(frozen=True)
class AlertEntity:
    """One entity an alert names (`AlertEntityGenerated`). For an activity alert this is the actor."""

    type: str
    id: str
    data: JsonObject = field(default_factory=dict)
    """The record's `Data`, decoded: for an activity alert it holds the exact activity time
    (`ts`), the operation (`op`) and the acting user (`suid`); for a user-reported message the
    reporter, sender, subject and message id."""


@dataclass(frozen=True)
class AlertPolicyAlert:
    """An Office 365 alert-policy alert, rebuilt from its audit records.

    The records say *that* an activity matched a policy and *who* did it, not what the activity
    changed: the user who received a role, the rule an inbox got. A caller that needs the target
    reads the activity itself (the directory audit log, or an audit search on `operation` and
    `actor` around `activity_time`).
    """

    alert_id: str
    name: str
    """The policy's name as raised, e.g. "Creation of forwarding/redirect rule"."""
    policy_id: str
    severity: str
    category: str
    alert_type: str
    """"System" for a built-in policy, "Custom" for one the tenant created."""
    status: str
    """The latest status the records carry (Active, Investigating, Resolved...)."""
    created: str
    """When the alert was raised (UTC)."""
    operation: str | None
    """The audited activity that matched, e.g. "Add member to role." or "New-InboxRule"."""
    workload: str | None
    actor: str | None
    activity_time: str | None
    """When the matched activity happened: the entity's exact time when there is one, else the
    start of the window the policy evaluated."""
    entities: tuple[AlertEntity, ...]
    data: JsonObject
    """The raising record's `Data`, decoded, for fields this type does not name."""

    def as_json(self) -> JsonObject:
        return {
            "alertId": self.alert_id,
            "name": self.name,
            "policyId": self.policy_id,
            "severity": self.severity,
            "category": self.category,
            "alertType": self.alert_type,
            "status": self.status,
            "created": self.created,
            "operation": self.operation,
            "workload": self.workload,
            "actor": self.actor,
            "activityTime": self.activity_time,
            "entities": [{"type": e.type, "id": e.id, "data": e.data} for e in self.entities],
            "data": self.data,
        }


@dataclass(frozen=True)
class AlertSearch:
    """One completed search for alert records."""

    query_id: str
    start: str
    end: str
    requested: float
    """Epoch seconds when the search was created."""
    completed: float
    """Epoch seconds when it was seen succeeded: `completed - requested` is the search's own cost."""
    alerts: tuple[AlertPolicyAlert, ...]
    truncated: bool
    """True when the search held more records than `RECORD_LIMIT`."""


class AuditSearch(Surface):
    @operation(tool="audit_list_searches", api="graph", permissions=_PERMISSIONS)
    async def list_audit_searches(
        self, top: Annotated[int, top("searches", 25, 100)] = 25
    ) -> JsonObject:
        """List the audit log searches already created in the tenant, newest first where the service
        orders them: id, name, time window, filters and status. Searches cannot be deleted, so this
        list only grows. Requires unified audit logging to be on in the tenant."""
        return await self._api.request(GRAPH, "GET", _PATH, params=odata(top=capped(top, 25, 100)))

    @operation(tool="audit_start_search", api="graph", permissions=_PERMISSIONS)
    async def start_audit_search(
        self,
        start: Timestamp,
        end: Timestamp,
        record_types: Names = None,
        operations: Names = None,
        user_principal_names: Names = None,
        keyword: Annotated[str | None, Field(description="Free-text keyword filter.")] = None,
        display_name: Annotated[
            str, Field(description="Name shown in the tenant's audit search list.")
        ] = "zerosoc audit search",
    ) -> JsonObject:
        """Start an asynchronous search of the Microsoft 365 unified audit log (Exchange, SharePoint,
        OneDrive, Teams, Entra ID, alert policies). Filter by record type (e.g.
        "securityComplianceAlerts", "exchangeAdmin", "exchangeItem", "sharePointFileOperation"),
        by operation (e.g. "New-InboxRule", "Add-MailboxPermission", "MailItemsAccessed") and by
        user. Returns the search with its id and status; poll audit_get_search until the status is
        "succeeded" (typically 2 to 5 minutes), then read audit_list_search_records. Records reach
        the log minutes after the activity. The search stays in the tenant's audit search list:
        the service offers no way to delete it."""
        body: JsonObject = {
            "displayName": display_name,
            "filterStartDateTime": _utc(start, "start"),
            "filterEndDateTime": _utc(end, "end"),
        }
        for key, value in (
            ("recordTypeFilters", record_types),
            ("operationFilters", operations),
            ("userPrincipalNameFilters", user_principal_names),
        ):
            if value:
                body[key] = list(value)
        if keyword:
            body["keywordFilter"] = keyword
        return await self._api.request(GRAPH, "POST", _PATH, json=body)

    @operation(tool="audit_get_search", api="graph", permissions=_PERMISSIONS)
    async def get_audit_search(
        self, query_id: Annotated[str, Field(description="The audit search id.")]
    ) -> JsonObject:
        """Get one audit log search: its filters and status (notStarted, running, succeeded, failed,
        cancelled). Records can be read once the status is succeeded."""
        return await self._api.request(GRAPH, "GET", f"{_PATH}/{seg(query_id)}")

    @operation(tool="audit_list_search_records", api="graph", permissions=_PERMISSIONS)
    async def list_audit_search_records(
        self,
        query_id: Annotated[str, Field(description="The audit search id.")],
        top: Annotated[int, top("records", 25, 100)] = 25,
    ) -> JsonObject:
        """List the records a succeeded audit search found: when, which operation, by whom, from
        which client IP, on which object, and the full audit data of each record."""
        return await self._api.request(
            GRAPH,
            "GET",
            f"{_PATH}/{seg(query_id)}/records",
            params=odata(top=capped(top, 25, 100)),
        )

    async def alert_policy_alerts(
        self,
        start: str,
        end: str,
        *,
        display_name: str = "zerosoc alert-policy intake",
        poll_seconds: float = POLL_SECONDS,
        timeout_seconds: float = TIMEOUT_SECONDS,
    ) -> AlertSearch:
        """**The data plane**: every alert-policy alert whose records fall in ``[start, end)``.

        One search on the alert record type, waited for, read whole (up to `RECORD_LIMIT`
        records) and folded into one `AlertPolicyAlert` per alert id. Records arrive late (on a
        Business Premium tenant an alert was searchable 9 to 15 minutes after it was raised), so a
        poller searches a window reaching back well beyond its interval and deduplicates on
        `alert_id`.

        Raises `AuditingDisabledError` when the tenant does not record the audit log, and
        `TimeoutError` when the search has not completed within ``timeout_seconds``.
        """
        requested = time.time()
        created = await self._audit_call(
            "POST",
            _PATH,
            json={
                "displayName": display_name,
                "filterStartDateTime": _utc(start, "start"),
                "filterEndDateTime": _utc(end, "end"),
                "recordTypeFilters": [ALERT_RECORD_TYPE],
            },
        )
        query_id = str(created.get("id", ""))
        status = str(created.get("status", ""))
        while status in RUNNING:
            if time.time() - requested > timeout_seconds:
                raise TimeoutError(
                    f"audit search {query_id} still {status} after {timeout_seconds:.0f} s"
                )
            await self._api.pause(poll_seconds)
            status = str(
                (await self._audit_call("GET", f"{_PATH}/{seg(query_id)}")).get("status", "")
            )
        if status != "succeeded":
            _refuse(status, f"{_PATH}/{seg(query_id)}")
        completed = time.time()
        records = await self._api.collect(
            GRAPH, f"{_PATH}/{seg(query_id)}/records", limit=RECORD_LIMIT + 1
        )
        return AlertSearch(
            query_id=query_id,
            start=start,
            end=end,
            requested=requested,
            completed=completed,
            alerts=fold_alert_records(records[:RECORD_LIMIT]),
            truncated=len(records) > RECORD_LIMIT,
        )

    async def activity_behind(self, alert: AlertPolicyAlert) -> list[JsonObject]:
        """**The data plane**: the audited activity an alert matched, read where it can be read now.

        An alert names the actor and the operation, not what the operation changed. For an Entra ID
        operation (workload ``AzureActiveDirectory``) the change is in the directory audit log: the
        events of the same activity by the same actor within `ACTIVITY_SLACK_SECONDS` of the
        activity time, with their target resources (the user who received a role, and the role;
        the application a user consented to). For any other workload the activity is only in the
        unified audit log, and reading it is a second search of minutes; this answers an empty
        list, and the caller records the target as not read.
        """
        if alert.workload != "AzureActiveDirectory" or not (
            alert.operation and alert.actor and alert.activity_time
        ):
            return []
        at = _instant(alert.activity_time)
        low = (at - timedelta(seconds=ACTIVITY_SLACK_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        high = (at + timedelta(seconds=ACTIVITY_SLACK_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        activity = alert.operation.rstrip(".").replace("'", "''")
        actor = alert.actor.replace("'", "''")
        found = await self._api.request(
            GRAPH,
            "GET",
            "/auditLogs/directoryAudits",
            params=odata(
                f"activityDisplayName eq '{activity}'"
                f" and initiatedBy/user/userPrincipalName eq '{actor}'"
                f" and activityDateTime ge {low} and activityDateTime le {high}",
                ACTIVITY_LIMIT,
            ),
        )
        return list(found.get("value") or [])

    async def _audit_call(self, method: str, path: str, json: Any = None) -> JsonObject:
        try:
            if method == "POST":
                return await self._api.request(GRAPH, "POST", path, json=json)
            return await self._api.request(GRAPH, "GET", path)
        except DefenderApiError as error:
            if "auditingdisabled" in f"{error.code} {error.message}".replace(" ", "").lower():
                raise _disabled(method, path, error.message) from error
            raise


def fold_alert_records(records: list[JsonObject]) -> tuple[AlertPolicyAlert, ...]:
    """Audit records of type `securityComplianceAlerts` -> one alert per alert id, oldest first.

    `AlertTriggered` names the policy and the matched operation, `AlertEntityGenerated` adds one
    entity each, `AlertUpdated` moves the status. Records of other types are ignored; an alert
    whose raising record is not in the window is skipped (a later search holds it).
    """
    grouped: dict[str, list[JsonObject]] = {}
    for record in records:
        audit = record.get("auditData") or {}
        alert_id = str(audit.get("AlertId") or "")
        if alert_id and record.get("operation") in ALERT_OPERATIONS:
            grouped.setdefault(alert_id, []).append(record)
    alerts = [a for a in (_alert(alert_id, rs) for alert_id, rs in grouped.items()) if a]
    return tuple(sorted(alerts, key=lambda a: (a.created, a.alert_id)))


def _alert(alert_id: str, records: list[JsonObject]) -> AlertPolicyAlert | None:
    ordered = sorted(records, key=lambda r: str(r.get("createdDateTime", "")))
    raised = next((r for r in ordered if r.get("operation") == "AlertTriggered"), None)
    if raised is None:
        return None
    audit = raised.get("auditData") or {}
    data = _decoded(audit.get("Data"))
    entities = tuple(
        AlertEntity(
            type=str((r.get("auditData") or {}).get("EntityType", "")),
            id=str((r.get("auditData") or {}).get("AlertEntityId", "")),
            data=_decoded((r.get("auditData") or {}).get("Data")),
        )
        for r in ordered
        if r.get("operation") == "AlertEntityGenerated"
    )
    exact = [str(e.data["ts"]) for e in entities if e.data.get("ts")]
    latest = ordered[-1].get("auditData") or {}
    return AlertPolicyAlert(
        alert_id=alert_id,
        name=str(audit.get("Name", "")),
        policy_id=str(audit.get("PolicyId", "")),
        severity=str(audit.get("Severity", "")),
        category=str(audit.get("Category", "")),
        alert_type=str(audit.get("AlertType", "")),
        status=str(latest.get("Status") or audit.get("Status", "")),
        created=str(raised.get("createdDateTime", "")),
        operation=_text(data.get("op")),
        workload=_text(data.get("wl")),
        actor=_text(data.get("f3u")) or next((_text(e.data.get("suid")) for e in entities), None),
        activity_time=min(exact) if exact else _text(data.get("ts")),
        entities=entities,
        data=data,
    )


def _decoded(value: Any) -> JsonObject:
    """`Data` is a JSON document inside a string; anything unreadable is kept, not dropped."""
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        found = json.loads(str(value))
    except ValueError:
        return {"raw": str(value)}
    return found if isinstance(found, dict) else {"raw": found}


def _instant(value: str) -> datetime:
    """An audit timestamp as an aware UTC datetime. The audit log writes seven fractional digits
    ("2026-09-30T08:29:58.0000000Z"), one more than the standard library reads."""
    trimmed = re.sub(r"(\.\d{6})\d+", r"\1", value.strip()).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(trimmed)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _text(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _utc(value: str, what: str) -> str:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise InvalidInputError(
            f"{what} must be an ISO 8601 timestamp such as 2026-09-30T08:00:00Z, not {value!r}"
        ) from None
    return value


def _disabled(method: str, path: str, message: str) -> AuditingDisabledError:
    return AuditingDisabledError(
        status=0,
        api=GRAPH.name,
        method=method,
        path=path,
        code="AuditingDisabled",
        message=message or "unified audit logging is off in this tenant",
        hint=(
            " Hint: the tenant's admin turns it on in Microsoft Purview, Audit (Start recording"
            " user and admin activity); searches answer a few hours later."
        ),
    )


def _refuse(status: str, path: str) -> None:
    if "disabled" in status.lower():
        raise _disabled("GET", path, f"search status {status}")
    raise DefenderApiError(
        status=0,
        api=GRAPH.name,
        method="GET",
        path=path,
        code="AuditSearchFailed",
        message=f"the audit search ended with status {status or 'unknown'}",
    )
