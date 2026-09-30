"""The Microsoft 365 audit log search: the data plane that turns alert records into typed alerts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from defender_fakes import Script
from zerosoc_defender_xdr.audit_search import (
    ALERT_RECORD_TYPE,
    AuditingDisabledError,
    fold_alert_records,
)
from zerosoc_defender_xdr.client import DefenderClient
from zerosoc_defender_xdr.errors import DefenderApiError, InvalidInputError

G = "https://graph.microsoft.com/v1.0"
QUERIES = f"{G}/security/auditLog/queries"
RECORDS: list[dict[str, Any]] = json.loads(
    (Path(__file__).parent / "fixtures" / "audit_alert_records.json").read_text()
)["value"]


def test_records_fold_into_one_alert_per_alert_id_oldest_first() -> None:
    alerts = fold_alert_records(RECORDS)

    assert [a.name for a in alerts] == [
        "Creation of forwarding/redirect rule",
        "Admin role assigned",
    ]


def test_an_activity_alert_carries_the_operation_the_actor_and_the_exact_activity_time() -> None:
    role = fold_alert_records(RECORDS)[1]

    assert (role.operation, role.workload, role.actor) == (
        "Add member to role.",
        "AzureActiveDirectory",
        "admin@contoso.onmicrosoft.com",
    )
    assert role.activity_time == "2026-09-30T08:29:58.0000000Z"
    assert (role.alert_type, role.severity, role.status) == ("Custom", "Medium", "Active")
    assert [(e.type, e.id) for e in role.entities] == [("User", "admin@contoso.onmicrosoft.com")]


def test_the_latest_update_sets_the_status_and_the_window_start_stands_in_for_the_time() -> None:
    rule = fold_alert_records(RECORDS)[0]

    assert rule.status == "Investigating"
    assert rule.activity_time == "2026-09-30T06:45:00.0000000Z"
    assert rule.entities == ()


def test_an_alert_whose_raising_record_is_outside_the_window_waits_for_a_later_search() -> None:
    names = {a.alert_id for a in fold_alert_records(RECORDS)}

    assert "e5e5e5e5-0000-0000-0000-000000000003" not in names
    assert "f6f6f6f6-0000-0000-0000-000000000004" not in names


def test_unreadable_data_is_kept_not_dropped() -> None:
    raised = {**RECORDS[4], "operation": "AlertTriggered"}

    (alert,) = fold_alert_records([raised])

    assert alert.data == {"raw": "not json"}


async def test_the_data_plane_searches_the_alert_record_type_waits_and_reads_everything(
    client: DefenderClient, script: Script
) -> None:
    script.json("POST", QUERIES, {"id": "q-1", "status": "notStarted"})
    script.on(
        "GET",
        f"{QUERIES}/q-1",
        httpx.Response(200, json={"id": "q-1", "status": "running"}),
        httpx.Response(200, json={"id": "q-1", "status": "succeeded"}),
    )
    script.on(
        "GET",
        f"{QUERIES}/q-1/records",
        httpx.Response(
            200,
            json={"value": RECORDS[:3], "@odata.nextLink": f"{QUERIES}/q-1/records?$skiptoken=2"},
        ),
        httpx.Response(200, json={"value": RECORDS[3:]}),
    )

    found = await client.alert_policy_alerts("2026-09-30T07:00:00Z", "2026-09-30T09:00:00Z")

    (created,) = script.sent("POST", "/auditLog/queries")
    assert Script.body(created) == {
        "displayName": "zerosoc alert-policy intake",
        "filterStartDateTime": "2026-09-30T07:00:00Z",
        "filterEndDateTime": "2026-09-30T09:00:00Z",
        "recordTypeFilters": [ALERT_RECORD_TYPE],
    }
    assert found.query_id == "q-1"
    assert [a.alert_id for a in found.alerts] == [
        "c3c3c3c3-0000-0000-0000-000000000002",
        "a1a1a1a1-0000-0000-0000-000000000001",
    ]
    assert found.truncated is False
    assert found.completed >= found.requested


async def test_a_tenant_without_auditing_is_named_as_such(
    client: DefenderClient, script: Script
) -> None:
    script.json(
        "POST",
        QUERIES,
        {"error": {"code": "BadRequest", "message": "Status: AuditingDisabledTenant"}},
        status=400,
    )

    with pytest.raises(AuditingDisabledError, match="Start recording"):
        await client.alert_policy_alerts("2026-09-30T07:00:00Z", "2026-09-30T09:00:00Z")


async def test_a_search_that_fails_is_an_error_not_an_empty_answer(
    client: DefenderClient, script: Script
) -> None:
    script.json("POST", QUERIES, {"id": "q-2", "status": "running"})
    script.json("GET", f"{QUERIES}/q-2", {"id": "q-2", "status": "failed"})

    with pytest.raises(DefenderApiError, match="ended with status failed"):
        await client.alert_policy_alerts("2026-09-30T07:00:00Z", "2026-09-30T09:00:00Z")
    assert script.sent("GET", "/records") == []


async def test_a_search_that_never_completes_times_out(
    client: DefenderClient, script: Script
) -> None:
    script.json("POST", QUERIES, {"id": "q-3", "status": "running"})
    script.json("GET", f"{QUERIES}/q-3", {"id": "q-3", "status": "running"})

    with pytest.raises(TimeoutError, match="q-3"):
        await client.alert_policy_alerts(
            "2026-09-30T07:00:00Z", "2026-09-30T09:00:00Z", timeout_seconds=-1
        )


async def test_a_missing_permission_says_which_one(client: DefenderClient, script: Script) -> None:
    script.json(
        "POST",
        QUERIES,
        {"error": {"code": "UnknownError", "message": "App dont have any permissions"}},
        status=403,
    )

    with pytest.raises(DefenderApiError, match=r"AuditLogsQuery\.Read\.All"):
        await client.alert_policy_alerts("2026-09-30T07:00:00Z", "2026-09-30T09:00:00Z")


async def test_a_search_window_must_be_timestamps(client: DefenderClient, script: Script) -> None:
    with pytest.raises(InvalidInputError, match="ISO 8601"):
        await client.start_audit_search(start="yesterday", end="2026-09-30T09:00:00Z")
    assert script.requests == []


async def test_the_activity_behind_an_entra_alert_is_read_from_the_directory_audit_log(
    client: DefenderClient, script: Script
) -> None:
    role = fold_alert_records(RECORDS)[1]
    event = {"activityDisplayName": "Add member to role", "targetResources": [{"id": "u-2"}]}
    script.json("GET", f"{G}/auditLogs/directoryAudits", {"value": [event]})

    found = await client.activity_behind(role)

    assert found == [event]
    (request,) = script.requests
    assert request.url.params["$filter"] == (
        "activityDisplayName eq 'Add member to role'"
        " and initiatedBy/user/userPrincipalName eq 'admin@contoso.onmicrosoft.com'"
        " and activityDateTime ge 2026-09-30T08:24:58Z and activityDateTime le 2026-09-30T08:34:58Z"
    )


async def test_the_activity_behind_any_other_workload_is_not_read_here(
    client: DefenderClient, script: Script
) -> None:
    rule = fold_alert_records(RECORDS)[0]

    assert await client.activity_behind(rule) == []
    assert script.requests == []
