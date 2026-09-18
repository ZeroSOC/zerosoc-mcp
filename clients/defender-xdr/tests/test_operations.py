"""Every operation, once: the call it makes. One table, so a new operation without a row fails."""

from __future__ import annotations

import base64
from typing import Any

import httpx
import pytest
from defender_fakes import Script
from zerosoc_defender_xdr.client import OPERATIONS, DefenderClient
from zerosoc_defender_xdr.errors import ActionsDisabledError
from zerosoc_defender_xdr.indicators import Indicator
from zerosoc_defender_xdr.machine_actions import CommandParam, LiveResponseCommand

G = "https://graph.microsoft.com/v1.0"
M = "https://api.securitycenter.microsoft.com/api"
LIST = {"$top": "25"}

# operation, arguments, method, URL, query or JSON body
CALLS: list[tuple[str, dict[str, Any], str, str, dict[str, Any] | None]] = [
    (
        "list_alerts",
        {"filter": "severity eq 'high'"},
        "GET",
        f"{G}/security/alerts_v2",
        {"$filter": "severity eq 'high'", **LIST},
    ),
    ("get_alert", {"alert_id": "da-1"}, "GET", f"{G}/security/alerts_v2/da-1", None),
    (
        "update_alert",
        {"alert_id": "da-1", "status": "resolved", "assigned_to": "a@b.c"},
        "PATCH",
        f"{G}/security/alerts_v2/da-1",
        {"status": "resolved", "assignedTo": "a@b.c"},
    ),
    (
        "add_alert_comment",
        {"alert_id": "da-1", "comment": "x"},
        "POST",
        f"{G}/security/alerts_v2/da-1/comments",
        {"@odata.type": "microsoft.graph.security.alertComment", "comment": "x"},
    ),
    (
        "run_hunting_query",
        {"query": "AlertInfo | take 1", "timespan": "P1D"},
        "POST",
        f"{G}/security/runHuntingQuery",
        {"Query": "AlertInfo | take 1", "Timespan": "P1D"},
    ),
    ("list_sign_ins", {"top": 5}, "GET", f"{G}/auditLogs/signIns", {"$top": "5"}),
    ("list_directory_audits", {}, "GET", f"{G}/auditLogs/directoryAudits", LIST),
    ("list_machines", {"skip": 25}, "GET", f"{M}/machines", {**LIST, "$skip": "25"}),
    ("get_machine", {"machine_id": "m1"}, "GET", f"{M}/machines/m1", None),
    (
        "find_machines_by_ip",
        {"ip": "10.0.0.1", "timestamp": "2026-09-10T10:00:00Z"},
        "GET",
        f"{M}/machines/findbyip(ip='10.0.0.1',timestamp=2026-09-10T10%3A00%3A00Z)",
        None,
    ),
    (
        "find_machines_by_tag",
        {"tag": "lab"},
        "GET",
        f"{M}/machines/findbytag",
        {"tag": "lab", "useStartsWithFilter": "false"},
    ),
    ("get_machine_logon_users", {"machine_id": "m1"}, "GET", f"{M}/machines/m1/logonusers", None),
    ("get_machine_alerts", {"machine_id": "m1"}, "GET", f"{M}/machines/m1/alerts", LIST),
    (
        "update_machine",
        {"machine_id": "m1", "device_value": "High"},
        "PATCH",
        f"{M}/machines/m1",
        {"deviceValue": "High"},
    ),
    (
        "add_remove_machine_tag",
        {"machine_id": "m1", "value": "t", "action": "Add"},
        "POST",
        f"{M}/machines/m1/tags",
        {"Value": "t", "Action": "Add"},
    ),
    (
        "isolate_machine",
        {"machine_id": "m1", "comment": "c"},
        "POST",
        f"{M}/machines/m1/isolate",
        {"Comment": "c", "IsolationType": "Full"},
    ),
    (
        "unisolate_machine",
        {"machine_id": "m1", "comment": "c"},
        "POST",
        f"{M}/machines/m1/unisolate",
        {"Comment": "c"},
    ),
    (
        "run_av_scan",
        {"machine_id": "m1", "comment": "c", "scan_type": "Full"},
        "POST",
        f"{M}/machines/m1/runAntiVirusScan",
        {"Comment": "c", "ScanType": "Full"},
    ),
    (
        "restrict_code_execution",
        {"machine_id": "m1", "comment": "c"},
        "POST",
        f"{M}/machines/m1/restrictCodeExecution",
        {"Comment": "c"},
    ),
    (
        "unrestrict_code_execution",
        {"machine_id": "m1", "comment": "c"},
        "POST",
        f"{M}/machines/m1/unrestrictCodeExecution",
        {"Comment": "c"},
    ),
    (
        "stop_and_quarantine_file",
        {"machine_id": "m1", "comment": "c", "sha1": "ab"},
        "POST",
        f"{M}/machines/m1/StopAndQuarantineFile",
        {"Comment": "c", "Sha1": "ab"},
    ),
    (
        "collect_investigation_package",
        {"machine_id": "m1", "comment": "c"},
        "POST",
        f"{M}/machines/m1/collectInvestigationPackage",
        {"Comment": "c"},
    ),
    (
        "offboard_machine",
        {"machine_id": "m1", "comment": "c"},
        "POST",
        f"{M}/machines/m1/offboard",
        {"Comment": "c"},
    ),
    ("get_file_info", {"file_hash": "ab"}, "GET", f"{M}/files/ab", None),
    ("get_file_statistics", {"file_hash": "ab"}, "GET", f"{M}/files/ab/stats", None),
    ("get_file_alerts", {"file_hash": "ab"}, "GET", f"{M}/files/ab/alerts", LIST),
    ("get_file_machines", {"file_hash": "ab"}, "GET", f"{M}/files/ab/machines", LIST),
    ("get_domain_alerts", {"domain": "x.test"}, "GET", f"{M}/domains/x.test/alerts", LIST),
    ("get_domain_machines", {"domain": "x.test"}, "GET", f"{M}/domains/x.test/machines", LIST),
    ("get_domain_statistics", {"domain": "x.test"}, "GET", f"{M}/domains/x.test/stats", None),
    ("get_ip_alerts", {"ip": "10.0.0.1"}, "GET", f"{M}/ips/10.0.0.1/alerts", LIST),
    ("get_ip_statistics", {"ip": "10.0.0.1"}, "GET", f"{M}/ips/10.0.0.1/stats", None),
    ("get_user_alerts", {"user_id": "LAB\\alice"}, "GET", f"{M}/users/LAB%5Calice/alerts", LIST),
    ("get_user_machines", {"user_id": "alice"}, "GET", f"{M}/users/alice/machines", LIST),
    ("list_indicators", {}, "GET", f"{M}/indicators", LIST),
    (
        "create_indicator",
        {
            "indicator_value": "203.0.113.7",
            "indicator_type": "IpAddress",
            "action": "Block",
            "title": "t",
            "description": "CASE-1",
            "expiration_time": "2026-10-01T00:00:00Z",
        },
        "POST",
        f"{M}/indicators",
        {
            "indicatorValue": "203.0.113.7",
            "indicatorType": "IpAddress",
            "action": "Block",
            "title": "t",
            "description": "CASE-1",
            "expirationTime": "2026-10-01T00:00:00Z",
        },
    ),
    (
        "import_indicators",
        {
            "indicators": [
                Indicator(
                    indicatorValue="x.test", indicatorType="DomainName", action="Block", title="t"
                )
            ]
        },
        "POST",
        f"{M}/indicators/import",
        {
            "Indicators": [
                {
                    "indicatorValue": "x.test",
                    "indicatorType": "DomainName",
                    "action": "Block",
                    "title": "t",
                }
            ]
        },
    ),
    ("delete_indicator", {"indicator_id": "7"}, "DELETE", f"{M}/indicators/7", None),
    (
        "batch_delete_indicators",
        {"indicator_ids": ["7", "8"]},
        "POST",
        f"{M}/indicators/BatchDelete",
        {"IndicatorIds": ["7", "8"]},
    ),
    (
        "list_machine_actions",
        {"filter": "machineId eq 'm1'"},
        "GET",
        f"{M}/machineactions",
        {"$filter": "machineId eq 'm1'", **LIST},
    ),
    ("get_machine_action", {"action_id": "a1"}, "GET", f"{M}/machineactions/a1", None),
    ("get_package_uri", {"action_id": "a1"}, "GET", f"{M}/machineactions/a1/getPackageUri", None),
    (
        "get_live_response_result",
        {"action_id": "a1", "command_index": 0},
        "GET",
        f"{M}/machineactions/a1/GetLiveResponseResultDownloadLink(index=0)",
        None,
    ),
    ("list_investigations", {}, "GET", f"{M}/investigations", LIST),
    ("get_investigation", {"investigation_id": "i1"}, "GET", f"{M}/investigations/i1", None),
    ("list_library_files", {}, "GET", f"{M}/libraryfiles", None),
    (
        "cancel_machine_action",
        {"action_id": "a1", "comment": "c"},
        "POST",
        f"{M}/machineactions/a1/cancel",
        {"Comment": "c"},
    ),
    (
        "run_live_response",
        {
            "machine_id": "m1",
            "comment": "c",
            "commands": [
                LiveResponseCommand(
                    type="GetFile", params=[CommandParam(key="Path", value="C:\\a")]
                )
            ],
        },
        "POST",
        f"{M}/machines/m1/runliveresponse",
        {
            "Commands": [{"type": "GetFile", "params": [{"key": "Path", "value": "C:\\a"}]}],
            "Comment": "c",
        },
    ),
    (
        "start_investigation",
        {"machine_id": "m1", "comment": "c"},
        "POST",
        f"{M}/machines/m1/startInvestigation",
        {"Comment": "c"},
    ),
    ("delete_library_file", {"file_name": "a.ps1"}, "DELETE", f"{M}/libraryfiles/a.ps1", None),
    ("list_vulnerabilities", {}, "GET", f"{M}/vulnerabilities", LIST),
    ("get_vulnerability", {"cve_id": "CVE-1"}, "GET", f"{M}/vulnerabilities/CVE-1", None),
    (
        "get_machine_vulnerabilities",
        {"machine_id": "m1"},
        "GET",
        f"{M}/machines/m1/vulnerabilities",
        None,
    ),
    (
        "get_machines_by_vulnerability",
        {"cve_id": "CVE-1"},
        "GET",
        f"{M}/vulnerabilities/CVE-1/machineReferences",
        None,
    ),
    ("list_software", {}, "GET", f"{M}/software", LIST),
    ("get_software", {"software_id": "s"}, "GET", f"{M}/software/s", None),
    (
        "get_software_vulnerabilities",
        {"software_id": "s"},
        "GET",
        f"{M}/software/s/vulnerabilities",
        None,
    ),
    (
        "get_machines_by_software",
        {"software_id": "s"},
        "GET",
        f"{M}/software/s/machineReferences",
        None,
    ),
    (
        "get_software_version_distribution",
        {"software_id": "s"},
        "GET",
        f"{M}/software/s/distributions",
        None,
    ),
    ("list_recommendations", {}, "GET", f"{M}/recommendations", LIST),
    ("get_recommendation", {"recommendation_id": "r"}, "GET", f"{M}/recommendations/r", None),
    (
        "get_recommendation_machines",
        {"recommendation_id": "r"},
        "GET",
        f"{M}/recommendations/r/machineReferences",
        None,
    ),
    (
        "get_recommendation_vulnerabilities",
        {"recommendation_id": "r"},
        "GET",
        f"{M}/recommendations/r/vulnerabilities",
        None,
    ),
    ("list_remediation_activities", {}, "GET", f"{M}/remediationTasks", LIST),
    ("get_remediation_activity", {"activity_id": "t"}, "GET", f"{M}/remediationTasks/t", None),
    (
        "get_remediation_exposed_devices",
        {"activity_id": "t"},
        "GET",
        f"{M}/remediationTasks/t/machineReferences",
        None,
    ),
    (
        "export_assessment",
        {"assessment_type": "softwareInventory"},
        "GET",
        f"{M}/machines/SoftwareInventoryByMachine",
        {"$top": "50"},
    ),
    ("get_exposure_score", {}, "GET", f"{M}/exposureScore", None),
    ("get_secure_score", {}, "GET", f"{M}/configurationScore", None),
    ("get_machine_group_exposure_score", {}, "GET", f"{M}/exposureScore/byMachineGroups", None),
    ("list_device_antivirus_health", {}, "GET", f"{M}/deviceavinfo", LIST),
    ("export_antivirus_health", {}, "GET", f"{M}/machines/InfoGatheringExport", None),
]

TESTED_ELSEWHERE = {
    # test_incidents.py
    "list_incidents",
    "get_incident",
    "resolve_incident",
    "get_incident_alerts",
    "get_incident_evidence",
    "update_incident",
    "add_incident_comment",
    # below
    "upload_library_file",
    "decode_command",
    "timestamp_to_utc",
    # test_probe.py
    "get_capabilities",
}


def test_every_operation_has_a_test() -> None:
    declared = {o.name for o in OPERATIONS}
    covered = {name for name, *_ in CALLS} | TESTED_ELSEWHERE
    assert declared - covered == set(), "operations without a test"
    assert covered - declared == set(), "tests for operations that no longer exist"


@pytest.mark.parametrize(
    ("name", "arguments", "method", "url", "payload"), CALLS, ids=[c[0] for c in CALLS]
)
async def test_an_operation_makes_exactly_the_call_it_documents(
    acting_client: DefenderClient,
    script: Script,
    name: str,
    arguments: dict[str, Any],
    method: str,
    url: str,
    payload: dict[str, Any] | None,
) -> None:
    script.on(method, url, lambda _r: httpx.Response(200, json={"ok": True}))

    await getattr(acting_client, name)(**arguments)

    assert len(script.requests) == 1
    request = script.requests[0]
    assert (request.method, str(request.url).split("?")[0]) == (method, url)
    if method == "GET":
        assert dict(request.url.params) == (payload or {})
    elif payload is not None:
        assert Script.body(request) == payload


@pytest.mark.parametrize("name", [o.name for o in OPERATIONS if o.kind == "action"])
async def test_a_response_action_is_refused_unless_the_client_allows_actions(
    client: DefenderClient, script: Script, name: str
) -> None:
    arguments = next((a for n, a, *_ in CALLS if n == name), None) or {
        "file": base64.b64encode(b"x").decode(),
        "file_name": "a.ps1",
    }
    with pytest.raises(ActionsDisabledError):
        await getattr(client, name)(**arguments)
    assert script.requests == []


def test_everything_that_changes_the_estate_is_an_action() -> None:
    """Writes are triage metadata only; anything else that is not a GET must be gated."""
    writes = {o.name for o in OPERATIONS if o.kind == "write"}
    assert writes == {
        "update_incident",
        "add_incident_comment",
        "update_alert",
        "add_alert_comment",
        "update_machine",
        "add_remove_machine_tag",
    }
    reads_that_post = (
        {n for n, _a, method, *_ in CALLS if method != "GET"}
        - writes
        - {o.name for o in OPERATIONS if o.kind == "action"}
    )
    assert reads_that_post == {"run_hunting_query"}  # a query, sent as POST


async def test_a_library_upload_is_multipart(acting_client: DefenderClient, script: Script) -> None:
    script.on("POST", f"{M}/libraryfiles", lambda _r: httpx.Response(200, json={}))
    await acting_client.upload_library_file(
        file=base64.b64encode(b"Get-Process").decode(), file_name="ps.ps1", description="d"
    )
    request = script.requests[0]
    assert request.headers["content-type"].startswith("multipart/form-data")
    assert b'filename="ps.ps1"' in request.content and b"Get-Process" in request.content
    assert b'name="Description"' in request.content


async def test_the_helpers_answer_without_any_call(client: DefenderClient, script: Script) -> None:
    payload = base64.b64encode("whoami".encode("utf-16-le")).decode()
    assert await client.decode_command(f"powershell -enc {payload}") == {
        "decoded": "whoami",
        "found": True,
        "rounds": 1,
        "layers": ["whoami"],
        "capped": False,
    }
    assert await client.decode_command("cmd /c dir") == {
        "decoded": None,
        "found": False,
        "rounds": 0,
        "layers": [],
        "capped": False,
    }
    nested = base64.b64encode(f"powershell -enc {payload}".encode("utf-16-le")).decode()
    doubled = await client.decode_command(f"powershell -NoProfile -enc {nested}")
    assert (doubled["decoded"], doubled["rounds"], doubled["capped"]) == ("whoami", 2, False)
    assert await client.timestamp_to_utc("2026-09-10T14:00:00", assume_zone="Europe/Rome") == {
        "utc": "2026-09-10T12:00:00Z"
    }
    assert script.requests == []


async def test_list_caps_hold_whatever_is_asked(client: DefenderClient, script: Script) -> None:
    script.json("GET", f"{M}/machines", {"value": []})
    await client.list_machines(top=100000)
    await client.list_machines(top=0)
    assert [r.url.params["$top"] for r in script.requests] == ["100", "1"]


BOUNDED_BY_THE_CLIENT = [
    ("get_machine_vulnerabilities", {"machine_id": "m1"}, f"{M}/machines/m1/vulnerabilities"),
    (
        "get_machines_by_vulnerability",
        {"cve_id": "CVE-1"},
        f"{M}/vulnerabilities/CVE-1/machineReferences",
    ),
    ("get_software_vulnerabilities", {"software_id": "s"}, f"{M}/software/s/vulnerabilities"),
    ("get_machines_by_software", {"software_id": "s"}, f"{M}/software/s/machineReferences"),
    (
        "get_recommendation_machines",
        {"recommendation_id": "r"},
        f"{M}/recommendations/r/machineReferences",
    ),
    (
        "get_recommendation_vulnerabilities",
        {"recommendation_id": "r"},
        f"{M}/recommendations/r/vulnerabilities",
    ),
    (
        "get_remediation_exposed_devices",
        {"activity_id": "t"},
        f"{M}/remediationTasks/t/machineReferences",
    ),
    ("list_library_files", {}, f"{M}/libraryfiles"),
    (
        "find_machines_by_ip",
        {"ip": "10.0.0.1", "timestamp": "2026-09-10T10:00:00Z"},
        f"{M}/machines/findbyip(ip='10.0.0.1',timestamp=2026-09-10T10%3A00%3A00Z)",
    ),
    ("find_machines_by_tag", {"tag": "lab"}, f"{M}/machines/findbytag"),
    ("get_machine_logon_users", {"machine_id": "m1"}, f"{M}/machines/m1/logonusers"),
]


@pytest.mark.parametrize(
    ("name", "arguments", "url"), BOUNDED_BY_THE_CLIENT, ids=[c[0] for c in BOUNDED_BY_THE_CLIENT]
)
async def test_a_collection_the_api_does_not_page_is_cut_by_the_client_and_says_so(
    client: DefenderClient, script: Script, name: str, arguments: dict[str, Any], url: str
) -> None:
    script.json("GET", url, {"value": list(range(300))})

    default = await getattr(client, name)(**arguments)
    asked = await getattr(client, name)(**arguments, top=100000)

    assert (len(default["value"]), default["total"], default["hasMore"]) == (25, 300, True)
    assert (len(asked["value"]), asked["hasMore"]) == (200, True)


def test_every_operation_that_returns_a_collection_takes_a_cap() -> None:
    import inspect

    uncapped = {
        o.name
        for o in OPERATIONS
        if o.name.startswith(("list_", "find_"))
        and "top" not in inspect.signature(getattr(DefenderClient, o.name)).parameters
    }
    assert uncapped == set()
