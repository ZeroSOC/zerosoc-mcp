"""Reading what automatic attack disruption did, without writing the query by hand."""

from __future__ import annotations

from typing import Any

import httpx
from defender_fakes import FakeCredential, Script
from zerosoc_defender_xdr.client import DefenderClient
from zerosoc_defender_xdr.hunting import disruption_query, kql_literal
from zerosoc_defender_xdr.transport import Transport

G = "https://graph.microsoft.com/v1.0"


def row(n: int) -> dict[str, Any]:
    return {
        "Timestamp": f"2026-09-10T10:{n:02d}:00Z",
        "ActionType": "ContainedUserLogonBlocked",
        "DeviceName": "host-1",
        "SourceUserName": "contained.user",
        "ReportType": "Prevented",
    }


def hunting(rows: list[dict[str, Any]], script: Script) -> None:
    script.on(
        "POST",
        f"{G}/security/runHuntingQuery",
        lambda _r: httpx.Response(200, json={"schema": [], "results": rows}),
    )


def test_a_name_is_matched_as_a_literal_and_never_parsed() -> None:
    assert kql_literal("host-1") == '"host-1"'
    assert kql_literal('a"b') == '"a\\"b"'
    assert kql_literal("a\\b") == '"a\\\\b"'
    query = disruption_query(None, 'x" or 1==1 //', 5)
    assert 'SourceUserName =~ "x\\" or 1==1 //"' in query
    assert query.count("| where") == 1


def test_the_query_is_bounded_and_scoped_to_what_was_asked() -> None:
    both = disruption_query("host-1", "S-1-5-21-1", 26)
    assert both.startswith("DisruptionAndResponseEvents\n| where DeviceId")
    assert 'SourceUserSid =~ "S-1-5-21-1"' in both
    assert both.endswith("| order by Timestamp desc\n| take 26")
    assert disruption_query(None, None, 3) == (
        "DisruptionAndResponseEvents\n| order by Timestamp desc\n| take 3"
    )


async def test_the_rows_are_cut_at_the_cap_and_the_answer_says_there_were_more(
    client: DefenderClient, script: Script
) -> None:
    hunting([row(n) for n in range(3)], script)

    answer = await client.list_disruption_events(user="contained.user", top=2)

    assert [r["Timestamp"] for r in answer["results"]] == [row(0)["Timestamp"], row(1)["Timestamp"]]
    assert (answer["rowCount"], answer["hasMore"]) == (2, True)
    assert "note" not in answer
    body = Script.body(script.requests[0])
    assert body["Query"].endswith("| take 3") and body["Timespan"] == "P7D"
    assert 'SourceUserName =~ "contained.user"' in body["Query"]


async def test_the_cap_holds_whatever_is_asked(client: DefenderClient, script: Script) -> None:
    hunting([], script)
    await client.list_disruption_events(top=100000)
    await client.list_disruption_events(top=0)
    queries = [Script.body(r)["Query"] for r in script.requests]
    assert queries[0].endswith("| take 101") and queries[1].endswith("| take 2")


async def test_no_rows_is_not_read_as_nothing_contained(
    client: DefenderClient, script: Script
) -> None:
    """The table holds the outcomes of a containment, not the containment. An asset contained and
    never challenged leaves no row, so the answer says where the record of the action is."""
    hunting([], script)

    answer = await client.list_disruption_events(device="host-1", timespan="PT12H")

    assert answer["results"] == [] and answer["rowCount"] == 0 and answer["hasMore"] is False
    assert "never the containment itself" in answer["note"]
    assert "Action center" in answer["note"]
    assert answer["timespan"] == "PT12H"
    assert "undeclared" in answer["entitlement"]


async def test_the_answer_carries_what_the_deployment_declared_about_the_feature(
    script: Script,
) -> None:
    hunting([], script)
    http = httpx.AsyncClient(transport=httpx.MockTransport(script))

    async def no_sleep(_s: float) -> None:
        return None

    def client_with(entitlements: frozenset[str] | None) -> DefenderClient:
        return DefenderClient(
            transport=Transport(FakeCredential(), http=http, sleep=no_sleep),
            entitlements=entitlements,
        )

    declared = await client_with(frozenset({"endpoint_p2"})).list_disruption_events()
    assert declared["entitlement"].startswith("endpoint_p2 is declared")
    absent = await client_with(frozenset()).list_disruption_events()
    assert "stated absent" in absent["entitlement"]
