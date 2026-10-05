"""The Microsoft 365 audit log search: the data plane that turns alert records into typed alerts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from defender_fakes import Script
from zerosoc_microsoft_security.audit_search import (
    ACTIVITY_RECORD_TYPES,
    ALERT_RECORD_TYPE,
    AuditingDisabledError,
    fold_alert_records,
)
from zerosoc_microsoft_security.client import MicrosoftSecurityClient
from zerosoc_microsoft_security.errors import DefenderApiError, InvalidInputError

G = "https://graph.microsoft.com/v1.0"
QUERIES = f"{G}/security/auditLog/queries"
RECORDS: list[dict[str, Any]] = json.loads(
    (Path(__file__).parent / "fixtures" / "audit_alert_records.json").read_text()
)["value"]
ACTIVITY: list[dict[str, Any]] = json.loads(
    (Path(__file__).parent / "fixtures" / "audit_alert_activity_records.json").read_text()
)["value"]
REPEAT, REPORT = "a7a7a7a7-0000-0000-0000-000000000001", "c9c9c9c9-0000-0000-0000-000000000002"


def _alert(records: list[dict[str, Any]], alert_id: str) -> Any:
    return next(a for a in fold_alert_records(records) if a.alert_id == alert_id)


def _without(*ids: str) -> list[dict[str, Any]]:
    return [r for r in ACTIVITY if r["id"] not in ids]


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


def test_a_repeat_activity_folded_into_the_alert_is_an_activity_of_its_own() -> None:
    alert = _alert(ACTIVITY, REPEAT)

    assert [(a.record_id, a.record_type, a.noted) for a in alert.activities] == [
        ("30000000-0000-0000-0000-000000000001", 1, "2026-10-05T15:33:15Z"),
        ("30000000-0000-0000-0000-000000000004", 1, "2026-10-05T15:39:27Z"),
    ]
    assert [a.repeat for a in alert.activities] == [False, True]
    assert [a.operation for a in alert.activities] == ["Add-MailboxPermission"] * 2
    assert [a.record and a.record["ObjectId"] for a in alert.activities] == ["finance", "payroll"]
    assert alert.status == "Investigating"


def test_an_activity_whose_record_the_search_did_not_return_is_kept_unread() -> None:
    alert = _alert(_without("30000000-0000-0000-0000-000000000004"), REPEAT)

    (_, later) = alert.activities
    assert (later.record_id, later.record, later.operation) == (
        "30000000-0000-0000-0000-000000000004",
        None,
        None,
    )


def test_a_user_report_points_to_its_submission_record_not_to_the_entity_sid() -> None:
    alert = _alert(ACTIVITY, REPORT)

    (report,) = alert.activities
    assert (report.record_id, report.record_type, report.noted, report.operation) == (
        "40000000-0000-0000-0000-000000000003",
        29,
        "2026-10-05T16:19:16Z",
        "UserSubmission",
    )


def test_a_user_report_finds_its_submission_record_before_the_update_points_to_it() -> None:
    alert = _alert(_without("40000000-0000-0000-0000-000000000004"), REPORT)

    assert [(a.record_id, a.noted) for a in alert.activities] == [
        ("40000000-0000-0000-0000-000000000003", "2026-10-05T16:19:16Z")
    ]


def test_a_user_report_whose_submission_record_is_not_searchable_yet_has_no_activity() -> None:
    first = _without("40000000-0000-0000-0000-000000000003", "40000000-0000-0000-0000-000000000004")

    assert _alert(first, REPORT).activities == ()


def test_a_user_report_named_only_by_its_update_is_still_the_raising_activity() -> None:
    alert = _alert(_without("40000000-0000-0000-0000-000000000003"), REPORT)

    (report,) = alert.activities
    assert (report.record_id, report.repeat, report.noted, report.record) == (
        "40000000-0000-0000-0000-000000000003",
        False,
        "2026-10-05T16:19:16Z",
        None,
    )


def test_a_user_report_reads_the_same_from_one_search_to_the_next() -> None:
    late = ("40000000-0000-0000-0000-000000000003", "40000000-0000-0000-0000-000000000004")
    seen = [
        [(a.record_id, a.repeat, a.noted) for a in _alert(_without(*gone), REPORT).activities]
        for gone in (late[1:], late[:1], ())
    ]

    assert seen == [[("40000000-0000-0000-0000-000000000003", False, "2026-10-05T16:19:16Z")]] * 3


def test_each_report_entity_names_its_own_submission() -> None:
    entity = next(r for r in ACTIVITY if r["id"] == "40000000-0000-0000-0000-000000000002")
    submission = next(r for r in ACTIVITY if r["id"] == "40000000-0000-0000-0000-000000000003")
    other_entity = json.loads(json.dumps(entity))
    other_entity["id"] = other_entity["auditData"]["Id"] = "40000000-0000-0000-0000-000000000012"
    other_entity["auditData"]["Data"] = (
        entity["auditData"]["Data"]
        .replace("5a5a5a5a-0000", "5a5a5a5a-1111")
        .replace("5b5b5b5b-0000", "5b5b5b5b-1111")
    )
    other_submission = json.loads(json.dumps(submission))
    other_submission["id"] = "40000000-0000-0000-0000-000000000013"
    other_submission["auditData"]["Id"] = "40000000-0000-0000-0000-000000000013"
    other_submission["auditData"]["SubmissionId"] = "5b5b5b5b-1111-0000-0000-000000000009"
    records = [other_submission, other_entity, *_without("40000000-0000-0000-0000-000000000004")]

    (report,) = _alert(records, REPORT).activities

    assert report.record_id == "40000000-0000-0000-0000-000000000003"


def test_a_pointer_resolves_on_the_audit_id_even_when_the_listing_id_differs() -> None:
    records = json.loads(json.dumps(ACTIVITY))
    records[0]["id"] = "listing-id-1"

    first = _alert(records, REPEAT).activities[0]

    assert (first.record_id, first.operation) == (
        "30000000-0000-0000-0000-000000000001",
        "Add-MailboxPermission",
    )


def test_activities_are_part_of_the_alert_as_json() -> None:
    alert = _alert(_without("30000000-0000-0000-0000-000000000004"), REPEAT)

    assert alert.as_json()["activities"][1] == {
        "recordId": "30000000-0000-0000-0000-000000000004",
        "repeat": True,
        "recordType": 1,
        "noted": "2026-10-05T15:39:27Z",
        "operation": None,
        "record": None,
    }


def test_unreadable_data_is_kept_not_dropped() -> None:
    raised = {**RECORDS[4], "operation": "AlertTriggered"}

    (alert,) = fold_alert_records([raised])

    assert alert.data == {"raw": "not json"}


async def test_the_data_plane_searches_the_alert_record_type_waits_and_reads_everything(
    client: MicrosoftSecurityClient, script: Script
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
        "recordTypeFilters": [ALERT_RECORD_TYPE, *ACTIVITY_RECORD_TYPES],
    }
    assert found.query_id == "q-1"
    assert [a.alert_id for a in found.alerts] == [
        "c3c3c3c3-0000-0000-0000-000000000002",
        "a1a1a1a1-0000-0000-0000-000000000001",
    ]
    assert found.truncated is False
    assert found.completed >= found.requested


async def test_the_data_plane_can_search_the_alert_records_alone(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    script.json("POST", QUERIES, {"id": "q-4", "status": "succeeded"})
    script.json("GET", f"{QUERIES}/q-4/records", {"value": ACTIVITY})

    found = await client.alert_policy_alerts(
        "2026-10-05T15:00:00Z", "2026-10-05T17:00:00Z", activity_types=()
    )

    (created,) = script.sent("POST", "/auditLog/queries")
    assert Script.body(created)["recordTypeFilters"] == [ALERT_RECORD_TYPE]
    assert [a.alert_id for a in found.alerts] == [REPEAT, REPORT]


async def test_a_tenant_without_auditing_is_named_as_such(
    client: MicrosoftSecurityClient, script: Script
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
    client: MicrosoftSecurityClient, script: Script
) -> None:
    script.json("POST", QUERIES, {"id": "q-2", "status": "running"})
    script.json("GET", f"{QUERIES}/q-2", {"id": "q-2", "status": "failed"})

    with pytest.raises(DefenderApiError, match="ended with status failed"):
        await client.alert_policy_alerts("2026-09-30T07:00:00Z", "2026-09-30T09:00:00Z")
    assert script.sent("GET", "/records") == []


async def test_a_search_that_never_completes_times_out(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    script.json("POST", QUERIES, {"id": "q-3", "status": "running"})
    script.json("GET", f"{QUERIES}/q-3", {"id": "q-3", "status": "running"})

    with pytest.raises(TimeoutError, match="q-3"):
        await client.alert_policy_alerts(
            "2026-09-30T07:00:00Z", "2026-09-30T09:00:00Z", timeout_seconds=-1
        )


async def test_a_missing_permission_says_which_one(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    script.json(
        "POST",
        QUERIES,
        {"error": {"code": "UnknownError", "message": "App dont have any permissions"}},
        status=403,
    )

    with pytest.raises(DefenderApiError, match=r"AuditLogsQuery\.Read\.All"):
        await client.alert_policy_alerts("2026-09-30T07:00:00Z", "2026-09-30T09:00:00Z")


async def test_a_search_window_must_be_timestamps(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    with pytest.raises(InvalidInputError, match="ISO 8601"):
        await client.start_audit_search(start="yesterday", end="2026-09-30T09:00:00Z")
    assert script.requests == []


async def test_the_activity_behind_an_entra_alert_is_read_from_the_directory_audit_log(
    client: MicrosoftSecurityClient, script: Script
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
    client: MicrosoftSecurityClient, script: Script
) -> None:
    rule = fold_alert_records(RECORDS)[0]

    assert await client.activity_behind(rule) == []
    assert script.requests == []
