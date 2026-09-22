from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from defender_fakes import Script
from zerosoc_defender_xdr.client import DefenderClient
from zerosoc_defender_xdr.errors import RedirectLoopError

G = "https://graph.microsoft.com/v1.0"
INCIDENT_14: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "incident_14.json").read_text()
)


def merged(script: Script) -> None:
    """Incident 17 was merged into 14, which is live."""
    script.json(
        "GET",
        f"{G}/security/incidents/17",
        {"id": "17", "status": "redirected", "redirectIncidentId": "14"},
    )
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)


async def test_list_incidents_is_capped(client: DefenderClient, script: Script) -> None:
    script.json("GET", f"{G}/security/incidents", {"value": []})
    await client.list_incidents(
        filter="status eq 'active'", top=500, orderby="createdDateTime desc"
    )
    assert dict(script.requests[0].url.params) == {
        "$filter": "status eq 'active'",
        "$top": "50",
        "$orderby": "createdDateTime desc",
    }


async def test_a_comment_on_a_merged_incident_lands_on_the_master(
    client: DefenderClient, script: Script
) -> None:
    merged(script)
    script.json("POST", f"{G}/security/incidents/14/comments", {"value": [{"comment": "note"}]})

    result = await client.add_incident_comment("17", "note")

    assert [str(r.url) for r in script.sent("POST", "/comments")] == [
        f"{G}/security/incidents/14/comments"
    ]
    assert Script.body(script.sent("POST", "/comments")[0]) == {
        "@odata.type": "microsoft.graph.security.alertComment",
        "comment": "note",
    }
    assert (result["incidentId"], result["redirectedFrom"]) == ("14", ["17"])


async def test_an_update_of_a_merged_incident_lands_on_the_master(
    client: DefenderClient, script: Script
) -> None:
    merged(script)
    script.json("PATCH", f"{G}/security/incidents/14", {"id": "14", "status": "inProgress"})

    result = await client.update_incident("17", status="inProgress", custom_tags=["zerosoc"])

    sent = script.sent("PATCH", "/security/incidents/")
    assert [str(r.url) for r in sent] == [f"{G}/security/incidents/14"]
    assert Script.body(sent[0]) == {"status": "inProgress", "customTags": ["zerosoc"]}
    assert result["redirectedFrom"] == ["17"]


async def test_a_live_incident_is_written_where_it_is(
    client: DefenderClient, script: Script
) -> None:
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)
    script.json("POST", f"{G}/security/incidents/14/comments", {"value": []})
    result = await client.add_incident_comment("14", "note")
    assert (result["incidentId"], result["redirectedFrom"]) == ("14", [])


async def test_an_update_that_changes_nothing_is_refused(client: DefenderClient) -> None:
    with pytest.raises(ValueError, match="nothing to update"):
        await client.update_incident("14")


async def test_a_chain_of_merges_is_followed_to_its_end(
    client: DefenderClient, script: Script
) -> None:
    script.json(
        "GET",
        f"{G}/security/incidents/20",
        {"id": "20", "status": "redirected", "redirectIncidentId": "17"},
    )
    merged(script)
    resolved = await client.resolve_incident("20")
    assert (resolved["incidentId"], resolved["redirectedFrom"]) == ("14", ["20", "17"])
    assert resolved["status"] == "active"


async def test_merges_that_point_at_each_other_are_an_error_not_a_hang(
    client: DefenderClient, script: Script
) -> None:
    script.json(
        "GET",
        f"{G}/security/incidents/1",
        {"id": "1", "status": "redirected", "redirectIncidentId": "2"},
    )
    script.json(
        "GET",
        f"{G}/security/incidents/2",
        {"id": "2", "status": "redirected", "redirectIncidentId": "1"},
    )
    with pytest.raises(RedirectLoopError):
        await client.add_incident_comment("1", "note")
    assert not script.sent("POST", "/comments")


async def test_the_evidence_inventory_reads_the_master_and_reports_the_count(
    client: DefenderClient, script: Script
) -> None:
    merged(script)

    result = await client.get_incident_evidence("17")

    assert (result["incidentId"], result["redirectedFrom"]) == ("14", ["17"])
    assert (result["alertCount"], result["entityCount"], result["returned"]) == (3, 13, 13)
    assert result["hasMore"] is False
    assert "$expand=alerts" in str(script.requests[-1].url).replace("%24", "$")


async def test_the_evidence_inventory_pages_through_every_alert(
    client: DefenderClient, script: Script
) -> None:
    first, rest = INCIDENT_14["alerts"][:1], INCIDENT_14["alerts"][1:]
    script.json(
        "GET",
        f"{G}/security/incidents/14",
        {
            **INCIDENT_14,
            "alerts": first,
            "alerts@odata.nextLink": f"{G}/security/incidents/14/alerts?$skiptoken=x",
        },
    )
    script.json("GET", f"{G}/security/incidents/14/alerts", {"value": rest})

    result = await client.get_incident_evidence("14")

    assert (result["alertCount"], result["entityCount"]) == (3, 13)


async def test_the_evidence_inventory_can_be_filtered_and_paged_without_losing_the_count(
    client: DefenderClient, script: Script
) -> None:
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)

    result = await client.get_incident_evidence("14", types=["process", "file"], top=3, skip=1)

    assert result["entityCount"] == 13  # always the whole incident: it is what reconciles
    assert (result["matching"], result["returned"], result["hasMore"]) == (4, 3, False)
    assert {e["type"] for e in result["entities"]} <= {"process", "file"}


async def test_incident_alerts_are_paged_and_can_be_summarized(
    client: DefenderClient, script: Script
) -> None:
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)

    page = await client.get_incident_alerts("14", top=2, skip=1, summary_only=True)

    assert (page["totalAlerts"], page["returned"], page["hasMore"]) == (3, 2, False)
    assert [a["id"] for a in page["alerts"]] == ["da-2", "da-3"]
    assert "evidence" not in page["alerts"][0] and page["alerts"][0]["detectorId"] == "det-2"


async def test_an_incident_id_is_data_not_path_syntax(
    client: DefenderClient, script: Script
) -> None:
    script.on(
        "GET",
        f"{G}/security/incidents/14%2F..%2F..%2Fusers",
        lambda _r: httpx.Response(200, json={"id": "x"}),
    )
    await client.get_incident("14/../../users")
    assert script.requests[0].url.raw_path.startswith(
        b"/v1.0/security/incidents/14%2F..%2F..%2Fusers"
    )


async def test_an_incident_too_large_to_read_whole_says_so(
    client: DefenderClient, script: Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("zerosoc_defender_xdr.incidents.MAX_ALERTS", 2)
    script.json(
        "GET",
        f"{G}/security/incidents/14",
        {
            **INCIDENT_14,
            "alerts": INCIDENT_14["alerts"][:2],
            "alerts@odata.nextLink": f"{G}/security/incidents/14/alerts?$skiptoken=x",
        },
    )
    result = await client.get_incident_evidence("14")
    assert result["alertsTruncated"] is True and result["alertCount"] == 2
    assert "not the whole incident" in result["note"]


async def test_a_whole_incident_is_not_flagged(client: DefenderClient, script: Script) -> None:
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)
    result = await client.get_incident_evidence("14")
    assert result["alertsTruncated"] is False and "note" not in result


async def test_a_negative_skip_is_no_skip(client: DefenderClient, script: Script) -> None:
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)
    page = await client.get_incident_alerts("14", skip=-5, summary_only=True)
    assert [a["id"] for a in page["alerts"]] == ["da-1", "da-2", "da-3"]


# --- the data plane: complete records, one call (ADR-0009) ----------------------------------------


async def test_an_incident_record_is_one_expansion_whatever_the_alert_count(
    client: DefenderClient, script: Script
) -> None:
    """The deterministic reader takes the whole incident in one call. Paging it for a model's
    budget cost one read per page, each re-expanding the incident and slicing the result."""
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)

    record = await client.incident_record("14")

    assert len(script.sent("GET", "/security/incidents/14")) == 1
    assert [a["id"] for a in record["alerts"]] == ["da-1", "da-2", "da-3"]
    assert record["incidentId"] == "14" and record["redirectedFrom"] == []
    assert record["alertsTruncated"] is False
    assert record["displayName"] == INCIDENT_14["displayName"], "the incident itself, whole"
    assert "alerts@odata.nextLink" not in record


async def test_an_incident_record_follows_the_merge_chain_and_reads_the_master(
    client: DefenderClient, script: Script
) -> None:
    merged(script)

    record = await client.incident_record("17")

    assert record["incidentId"] == "14" and record["redirectedFrom"] == ["17"]
    assert len(record["alerts"]) == 3
    assert len(script.sent("GET", "/security/incidents")) == 2, "one hop, then the master"


async def test_an_incident_record_follows_the_expansion_paging_once(
    client: DefenderClient, script: Script
) -> None:
    first = {
        "id": "14",
        "status": "active",
        "alerts": [{"id": "da-1"}],
        "alerts@odata.nextLink": f"{G}/security/incidents/14/alerts?$skiptoken=2",
    }
    script.json("GET", f"{G}/security/incidents/14", first)
    script.json("GET", f"{G}/security/incidents/14/alerts", {"value": [{"id": "da-2"}]})

    record = await client.incident_record("14")

    assert [a["id"] for a in record["alerts"]] == ["da-1", "da-2"]
    assert len(script.sent("GET", "/security/incidents/14/alerts")) == 1


async def test_the_agent_plane_pages_the_same_record_without_expanding_it_again(
    client: DefenderClient, script: Script
) -> None:
    """The MCP tool keeps its shape for a model and calls the data plane: one API call is still
    implemented once (ADR-0005), and the page is cut from the record rather than re-fetched."""
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)

    page = await client.get_incident_alerts("14", top=2, skip=0)

    assert len(script.sent("GET", "/security/incidents/14")) == 1
    assert (page["totalAlerts"], page["returned"], page["hasMore"]) == (3, 2, True)


async def test_an_expansion_that_never_ends_is_stopped_and_says_so(
    client: DefenderClient, script: Script
) -> None:
    """A page that answers with no alerts and still offers a next link used to be followed for as
    long as the source offered one: the alert ceiling only stops a walk that is making progress."""
    script.json(
        "GET",
        f"{G}/security/incidents/14",
        {
            "id": "14",
            "status": "active",
            "alerts": [{"id": "da-1"}],
            "alerts@odata.nextLink": f"{G}/security/incidents/14/alerts?$skiptoken=2",
        },
    )
    script.json(
        "GET",
        f"{G}/security/incidents/14/alerts",
        {"value": [], "@odata.nextLink": f"{G}/security/incidents/14/alerts?$skiptoken=3"},
    )

    record = await client.incident_record("14")

    assert [a["id"] for a in record["alerts"]] == ["da-1"]
    assert record["alertsTruncated"] is True, "what was not read is said, not passed over"
    assert len(script.sent("GET", "/security/incidents/14/alerts")) == 100


async def test_the_other_write_surfaces_go_in_the_same_patch(
    client: DefenderClient, script: Script
) -> None:
    """Severity, the resolving comment and the description are writable properties of the incident,
    measured against a live one: an executor that closes a Case in the source sets them with the
    classification, in one write, rather than leaving the record disagreeing with itself."""
    script.json("GET", f"{G}/security/incidents/14", INCIDENT_14)
    script.json("PATCH", f"{G}/security/incidents/14", {"id": "14", "status": "resolved"})

    await client.update_incident(
        "14",
        status="resolved",
        classification="falsePositive",
        determination="notMalicious",
        severity="medium",
        resolving_comment="The signing chain is the vendor's own.",
        description="## Triage\nNothing of the alert survived the check.",
    )

    sent = script.sent("PATCH", "/security/incidents/")
    assert Script.body(sent[0]) == {
        "status": "resolved",
        "classification": "falsePositive",
        "determination": "notMalicious",
        "severity": "medium",
        "resolvingComment": "The signing chain is the vendor's own.",
        "description": "## Triage\nNothing of the alert survived the check.",
    }


async def test_a_resolving_comment_past_what_the_source_keeps_is_refused(
    client: DefenderClient,
) -> None:
    """The API answers 200 and stores the first 30,000 characters. A caller told the write
    succeeded would never learn the tail is gone, so the length is refused before it is sent."""
    with pytest.raises(ValueError, match="30000"):
        await client.update_incident("14", resolving_comment="x" * 30_001)
