"""The Microsoft 365 audit log search: the data plane that turns alert records into typed alerts."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

import httpx
import pytest
from defender_fakes import Script
from zerosoc_microsoft_security.audit_search import (
    ACTIVITY_RECORD_TYPES,
    ACTIVITY_SLACK_SECONDS,
    ALERT_RECORD_TYPE,
    CONNECTION_GAP_SECONDS,
    CONNECTION_VECTOR,
    SAME_REQUEST_LIMIT,
    AuditingDisabledError,
    connection_groups,
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
        "sameRequest": [],
        "sameRequestCount": 0,
        "sameConnection": [],
        "sameConnectionCount": 0,
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


def _step(record_id: str, operation: str, request: str | None, at: str) -> dict[str, Any]:
    """An Exchange admin record of one step of a job, as the search returns it."""
    audit = {
        "Id": record_id,
        "CreationTime": at,
        "RecordType": 1,
        "Operation": operation,
        "UserId": "NT SERVICE\\ExampleService",
        "ResultStatus": "True",
        **({"RequestId": request} if request else {}),
    }
    return {
        "id": record_id,
        "createdDateTime": f"{at}Z",
        "auditLogRecordType": "ExchangeAdmin",
        "operation": operation,
        "auditData": audit,
    }


def _in_request(request: str, *ids: str) -> list[dict[str, Any]]:
    """The fixture with its activity records made steps of one request."""
    out = []
    for record in ACTIVITY:
        if record["id"] in ids:
            record = {**record, "auditData": {**record["auditData"], "RequestId": request}}
        out.append(record)
    return out


RAISING = "30000000-0000-0000-0000-000000000001"


def test_an_activity_carries_the_other_records_of_its_request_oldest_first() -> None:
    """A job (a service provisioning an organization runs dozens of commands under one request)
    is what tells one step of it from a lone change. The search already returned its records."""
    records = [
        *_in_request("job-1", RAISING),
        _step(
            "50000000-0000-0000-0000-000000000002",
            "Install-ResourceConfig",
            "job-1",
            "2026-10-05T15:30:40",
        ),
        _step(
            "50000000-0000-0000-0000-000000000001",
            "Set-TenantObjectVersion",
            "job-1",
            "2026-10-05T15:30:20",
        ),
        _step(
            "50000000-0000-0000-0000-000000000003", "Set-Mailbox", "job-2", "2026-10-05T15:30:41"
        ),
        _step("50000000-0000-0000-0000-000000000004", "Set-Mailbox", None, "2026-10-05T15:30:42"),
    ]

    first, _ = _alert(records, REPEAT).activities

    assert [r["Operation"] for r in first.same_request] == [
        "Set-TenantObjectVersion",
        "Install-ResourceConfig",
    ], "the job's other steps, and nothing of another request or of none"
    assert first.same_request_count == 2


def test_a_record_with_no_request_or_not_returned_has_no_job() -> None:
    first, later = _alert(_without("30000000-0000-0000-0000-000000000004"), REPEAT).activities

    assert (first.same_request, first.same_request_count) == ((), 0)
    assert (later.record, later.same_request, later.same_request_count) == (None, (), 0)


def test_a_long_job_is_bounded_and_says_how_many_it_had() -> None:
    steps = [
        _step(
            f"60000000-0000-0000-0000-{n:012d}",
            "Set-Mailbox",
            "job-1",
            f"2026-10-05T15:{n // 60:02d}:{n % 60:02d}",
        )
        for n in range(SAME_REQUEST_LIMIT + 5)
    ]

    first, _ = _alert([*_in_request("job-1", RAISING), *steps], REPEAT).activities

    assert len(first.same_request) == SAME_REQUEST_LIMIT
    assert first.same_request_count == SAME_REQUEST_LIMIT + 5
    assert first.same_request[0]["Id"] == steps[0]["id"], "the start of the job is kept"


def test_the_job_is_part_of_the_activity_as_json() -> None:
    records = [
        *_in_request("job-1", RAISING),
        _step(
            "50000000-0000-0000-0000-000000000001",
            "Set-TenantObjectVersion",
            "job-1",
            "2026-10-05T15:30:20",
        ),
    ]

    shown = _alert(records, REPEAT).as_json()["activities"][0]

    assert [r["Operation"] for r in shown["sameRequest"]] == ["Set-TenantObjectVersion"]
    assert shown["sameRequestCount"] == 1


SERVICE = r"NT SERVICE\ExampleService"
SERVER = "EXAMPLE01 (15.21.0000.000)"


def _connected(
    record: dict[str, Any], client: str, *, actor: str = SERVICE, server: str = SERVER
) -> dict[str, Any]:
    """A record made one of the connection client opened to the server, by actor."""
    audit = {
        **record["auditData"],
        "UserId": actor,
        "ClientIP": client,
        "OriginatingServer": server,
    }
    return {**record, "auditData": audit}


def _by_connection(client: str) -> list[dict[str, Any]]:
    """The fixture with the raising activity made a service's, on connection client."""
    return [_connected(r, client) if r["id"] == RAISING else r for r in ACTIVITY]


def test_an_activity_carries_the_other_records_of_its_client_connection() -> None:
    """A provisioning job can give each command its own request; every command of the job still
    comes over one connection to one server. Another port, actor or server is another connection."""
    step = _step
    records = [
        *_by_connection("[::1]:11880"),
        _connected(
            step(
                "70000000-0000-0000-0000-000000000002", "Set-Mailbox", "r-2", "2026-10-05T15:30:25"
            ),
            "[::1]:11880",
        ),
        _connected(
            step(
                "70000000-0000-0000-0000-000000000001",
                "Set-TransportConfig",
                "r-1",
                "2026-10-05T15:30:21",
            ),
            "[::1]:11880",
        ),
        _connected(
            step(
                "70000000-0000-0000-0000-000000000003", "Set-Mailbox", "r-3", "2026-10-05T15:30:26"
            ),
            "[::1]:13877",
        ),
        _connected(
            step(
                "70000000-0000-0000-0000-000000000004", "Set-Mailbox", "r-4", "2026-10-05T15:30:27"
            ),
            "[::1]:11880",
            actor=r"NT SERVICE\Other",
        ),
    ]

    first, _ = _alert(records, REPEAT).activities

    assert [r["Operation"] for r in first.same_connection] == ["Set-TransportConfig", "Set-Mailbox"]
    assert first.same_connection_count == 2
    shown = _alert(records, REPEAT).as_json()["activities"][0]
    assert [r["Operation"] for r in shown["sameConnection"]] == [
        "Set-TransportConfig",
        "Set-Mailbox",
    ]
    assert shown["sameConnectionCount"] == 2


def test_an_address_without_a_port_names_no_connection() -> None:
    records = [
        *_by_connection("203.0.113.7"),
        _connected(
            _step(
                "70000000-0000-0000-0000-000000000001", "Set-Mailbox", "r-1", "2026-10-05T15:30:21"
            ),
            "203.0.113.7",
        ),
    ]

    first, _ = _alert(records, REPEAT).activities

    assert (first.same_connection, first.same_connection_count) == ((), 0)


def test_a_connection_outlives_a_build_change_and_ends_when_it_goes_quiet() -> None:
    """The server's build suffix can change in the middle of one job, and the actor's spelling is
    not the connection; time is. A record more than the window after the previous one of its
    connection is a later connection on a reused port."""
    quiet = CONNECTION_GAP_SECONDS + 1
    records = [
        *_by_connection("[::1]:11880"),
        _connected(
            _step(
                "70000000-0000-0000-0000-000000000001", "Set-Mailbox", "r-1", "2026-10-05T15:30:21"
            ),
            "[::1]:11880",
            actor=SERVICE.upper(),
            server="EXAMPLE01 (15.21.0000.002)\r\n",
        ),
        _connected(
            _step(
                "70000000-0000-0000-0000-000000000002",
                "Set-Mailbox",
                "r-2",
                f"2026-10-05T15:{30 + quiet // 60:02d}:{30 + quiet % 60:02d}",
            ),
            "[::1]:11880",
        ),
    ]

    first, _ = _alert(records, REPEAT).activities

    assert [r["Id"] for r in first.same_connection] == ["70000000-0000-0000-0000-000000000001"]
    assert first.same_connection_count == 1


def test_a_record_named_by_its_search_id_alone_still_carries_its_connection() -> None:
    """The alert's pointer can name the record by the id the search gives it, with no `Id` in its
    audit data: the connection is found from either."""
    records = [
        *_by_connection("[::1]:11880"),
        _connected(
            _step(
                "70000000-0000-0000-0000-000000000001", "Set-Mailbox", "r-1", "2026-10-05T15:30:21"
            ),
            "[::1]:11880",
        ),
    ]
    records = [
        {**r, "auditData": {k: v for k, v in r["auditData"].items() if k != "Id"}}
        if r["id"] == RAISING
        else r
        for r in records
    ]

    first, _ = _alert(records, REPEAT).activities

    assert first.record is not None and "Id" not in first.record
    assert [r["Id"] for r in first.same_connection] == ["70000000-0000-0000-0000-000000000001"]
    assert first.same_connection_count == 1


def test_a_connection_goes_quiet_within_the_reach_of_an_activity() -> None:
    assert CONNECTION_GAP_SECONDS == ACTIVITY_SLACK_SECONDS


def _vector() -> dict[str, Any]:
    text = resources.files("zerosoc_microsoft_security").joinpath(CONNECTION_VECTOR).read_text()
    found: dict[str, Any] = json.loads(text)
    return found


@pytest.mark.parametrize("case", _vector()["cases"], ids=lambda case: case["name"])
def test_the_connection_key_meets_the_test_vector_it_ships(case: dict[str, Any]) -> None:
    """The vector is in the package, so a consumer that keeps its own copy of the rule runs the
    same records through it and expects the same groups."""
    groups = connection_groups(case["records"])

    assert [[r["Id"] for r in group] for group in groups] == case["groups"]


def test_the_vector_states_the_window_the_rule_applies() -> None:
    assert _vector()["window_seconds"] == CONNECTION_GAP_SECONDS


async def test_the_data_plane_hands_back_every_activity_record_it_read(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    """A caller that keeps what bears on its open cases reads it from the same search, with no
    second one (ZeroSOC's intake keeps the records that name an open Case's entities)."""
    script.json("POST", QUERIES, {"id": "q-2", "status": "succeeded"})
    script.on(
        "GET", f"{QUERIES}/q-2", httpx.Response(200, json={"id": "q-2", "status": "succeeded"})
    )
    script.on("GET", f"{QUERIES}/q-2/records", httpx.Response(200, json={"value": ACTIVITY}))

    found = await client.alert_policy_alerts("2026-10-05T15:00:00Z", "2026-10-05T16:00:00Z")

    expected = [r["auditData"] for r in ACTIVITY if r["auditData"].get("RecordType") != 40]
    assert list(found.activities) == expected
    assert all(a.get("RecordType") != 40 for a in found.activities), (
        "the alert records are the alerts"
    )


async def test_an_activity_search_reads_the_records_of_its_window_and_people(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    """A caller asking what an account did in a past window searches for it once, within its own
    allowance, and reads every record (ZeroSOC's investigation, ZeroSOC/zerosoc-platform-azure#170)."""
    script.json("POST", QUERIES, {"id": "q-3", "status": "running"})
    script.on(
        "GET", f"{QUERIES}/q-3", httpx.Response(200, json={"id": "q-3", "status": "succeeded"})
    )
    script.on("GET", f"{QUERIES}/q-3/records", httpx.Response(200, json={"value": ACTIVITY}))

    found = await client.activity_records(
        "2026-10-05T14:00:00Z",
        "2026-10-05T16:00:00Z",
        user_principal_names=["admin@contoso.onmicrosoft.com"],
        display_name="zerosoc case search",
    )

    (created,) = script.sent("POST", "/auditLog/queries")
    assert Script.body(created) == {
        "displayName": "zerosoc case search",
        "filterStartDateTime": "2026-10-05T14:00:00Z",
        "filterEndDateTime": "2026-10-05T16:00:00Z",
        "recordTypeFilters": list(ACTIVITY_RECORD_TYPES),
        "userPrincipalNameFilters": ["admin@contoso.onmicrosoft.com"],
    }
    assert found.query_id == "q-3" and not found.truncated
    assert list(found.records) == [r["auditData"] for r in ACTIVITY]
