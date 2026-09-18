from __future__ import annotations

import httpx
import pytest
from defender_fakes import FakeCredential, Script
from zerosoc_defender_xdr.auth import ClientSecretCredential
from zerosoc_defender_xdr.transport import GRAPH, MDE, DefenderApiError, Transport

G = "https://graph.microsoft.com/v1.0"
M = "https://api.securitycenter.microsoft.com/api"


async def test_each_api_gets_a_token_for_its_own_scope(
    transport: Transport, script: Script, credential: FakeCredential
) -> None:
    script.json("GET", f"{G}/security/incidents", {"value": []})
    script.json("GET", f"{M}/machines", {"value": []})

    await transport.request(GRAPH, "GET", "/security/incidents")
    await transport.request(MDE, "GET", "/machines")

    assert [r.headers["authorization"] for r in script.requests] == [
        "Bearer token-for-https://graph.microsoft.com/.default",
        "Bearer token-for-https://api.securitycenter.microsoft.com/.default",
    ]


async def test_a_token_is_reused_until_it_nears_expiry(
    transport: Transport, script: Script, credential: FakeCredential
) -> None:
    script.json("GET", f"{G}/security/incidents", {"value": []})
    await transport.request(GRAPH, "GET", "/security/incidents")
    await transport.request(GRAPH, "GET", "/security/incidents")
    assert len(credential.calls) == 1


async def test_empty_query_values_are_dropped(transport: Transport, script: Script) -> None:
    script.json("GET", f"{G}/security/incidents", {"value": []})
    await transport.request(
        GRAPH, "GET", "/security/incidents", params={"$top": 5, "$filter": None, "$orderby": ""}
    )
    assert dict(script.requests[0].url.params) == {"$top": "5"}


async def test_an_error_carries_status_api_message_and_the_permission_hint(
    transport: Transport, script: Script
) -> None:
    script.json("GET", f"{M}/machines", {"error": {"code": "Forbidden", "message": "nope"}}, 403)
    with pytest.raises(DefenderApiError) as caught:
        await transport.request(MDE, "GET", "/machines")
    error = caught.value
    assert (error.status, error.api, error.code) == (403, "mde", "Forbidden")
    assert "nope" in str(error) and "GET /machines" in str(error)
    assert "WindowsDefenderATP application permissions" in str(error)


async def test_a_400_has_no_permission_hint(transport: Transport, script: Script) -> None:
    script.json("GET", f"{G}/security/incidents", {"error": {"message": "bad filter"}}, 400)
    with pytest.raises(DefenderApiError) as caught:
        await transport.request(GRAPH, "GET", "/security/incidents")
    assert "Hint" not in str(caught.value)


async def test_an_empty_body_is_an_empty_object(transport: Transport, script: Script) -> None:
    script.on("DELETE", f"{M}/indicators/7", lambda _r: httpx.Response(204))
    assert await transport.request(MDE, "DELETE", "/indicators/7") == {}


async def test_throttling_is_retried_after_the_delay_the_service_asks_for(
    script: Script, credential: FakeCredential
) -> None:
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    script.on(
        "GET",
        f"{G}/security/incidents",
        httpx.Response(429, headers={"Retry-After": "7"}, json={"error": {"message": "slow"}}),
        httpx.Response(200, json={"value": [1]}),
    )
    transport = Transport(
        credential, http=httpx.AsyncClient(transport=httpx.MockTransport(script)), sleep=sleep
    )
    assert await transport.request(GRAPH, "GET", "/security/incidents") == {"value": [1]}
    assert slept == [7.0]


async def test_throttling_gives_up_after_the_retry_budget(
    transport: Transport, script: Script
) -> None:
    script.json("GET", f"{G}/security/incidents", {"error": {"message": "slow"}}, 429)
    with pytest.raises(DefenderApiError) as caught:
        await transport.request(GRAPH, "GET", "/security/incidents")
    assert caught.value.status == 429
    assert len(script.requests) == 4


async def test_collect_follows_next_links_up_to_the_limit(
    transport: Transport, script: Script
) -> None:
    script.on(
        "GET",
        f"{G}/security/alerts_v2",
        httpx.Response(
            200, json={"value": [1, 2], "@odata.nextLink": f"{G}/security/alerts_v2?$skiptoken=a"}
        ),
        httpx.Response(
            200, json={"value": [3, 4], "@odata.nextLink": f"{G}/security/alerts_v2?$skiptoken=b"}
        ),
        httpx.Response(200, json={"value": [5]}),
    )
    assert await transport.collect(GRAPH, "/security/alerts_v2", limit=3) == [1, 2, 3]
    assert len(script.requests) == 2


async def test_a_next_link_to_another_host_is_never_followed(
    transport: Transport, script: Script
) -> None:
    script.json(
        "GET",
        f"{G}/security/alerts_v2",
        {"value": [1], "@odata.nextLink": "https://evil.example/steal?x=1"},
    )
    with pytest.raises(DefenderApiError, match="refusing to follow"):
        await transport.collect(GRAPH, "/security/alerts_v2", limit=10)
    assert all(r.url.host == "graph.microsoft.com" for r in script.requests)


async def test_client_secret_credential_posts_the_client_credentials_grant() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"access_token": "abc", "expires_in": 3600})

    credential = ClientSecretCredential(
        "tenant-1",
        "client-1",
        "s3cret",
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    token = await credential.get_token("https://graph.microsoft.com/.default")

    assert token.token == "abc"
    assert str(seen[0].url) == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
    form = dict(httpx.QueryParams(seen[0].content.decode()))
    assert form == {
        "grant_type": "client_credentials",
        "client_id": "client-1",
        "client_secret": "s3cret",
        "scope": "https://graph.microsoft.com/.default",
    }


async def test_a_refused_token_request_never_echoes_the_secret() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, json={"error": "invalid_client", "error_description": "AADSTS7000215: bad secret"}
        )

    credential = ClientSecretCredential(
        "tenant-1",
        "client-1",
        "s3cret",
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(DefenderApiError) as caught:
        await credential.get_token("https://graph.microsoft.com/.default")
    assert "AADSTS7000215" in str(caught.value)
    assert "s3cret" not in str(caught.value)


async def test_a_write_is_never_repeated_on_a_gateway_error(
    transport: Transport, script: Script
) -> None:
    """503 may come after the service acted: only reads are retried. 429 is a refusal: all are."""
    script.json("POST", f"{G}/security/incidents/14/comments", {"error": {"message": "busy"}}, 503)
    with pytest.raises(DefenderApiError):
        await transport.request(GRAPH, "POST", "/security/incidents/14/comments", json={})
    assert len(script.requests) == 1

    script.on(
        "POST",
        f"{G}/security/runHuntingQuery",
        httpx.Response(429, headers={"Retry-After": "1"}),
        httpx.Response(200, json={"results": []}),
    )
    assert await transport.request(GRAPH, "POST", "/security/runHuntingQuery", json={}) == {
        "results": []
    }


async def test_a_success_that_is_not_json_is_an_api_error_with_its_call(
    transport: Transport, script: Script
) -> None:
    script.on(
        "GET", f"{G}/security/incidents", lambda _r: httpx.Response(200, text="<html>proxy</html>")
    )
    with pytest.raises(DefenderApiError) as caught:
        await transport.request(GRAPH, "GET", "/security/incidents")
    assert "GET /security/incidents" in str(caught.value) and "not JSON" in str(caught.value)
