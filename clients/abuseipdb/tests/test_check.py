"""An address's reputation (#44): one bare public address in, a normalised answer out.

What the answer carries is what a host needs to weigh it — the score, how many reports by how
many reporters, what kinds of abuse, who runs the address and whether it is a Tor exit — and never
the reports' comments, which anyone may write and which no host should read as an instruction.
"""

from __future__ import annotations

import json

import httpx
import pytest
from abuseipdb_fakes import BASE, CLEAN, KEY, TOR_EXIT, Script, quota
from zerosoc_abuseipdb import (
    OPERATIONS,
    AbuseIPDBClient,
    AbuseIPDBError,
    InvalidInputError,
)


def _client(script: Script, **kwargs: object) -> AbuseIPDBClient:
    clock = kwargs.pop("clock", None)
    return AbuseIPDBClient(
        KEY,
        transport=httpx.MockTransport(script),
        clock=clock or (lambda: 1_000.0),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


async def test_a_check_is_normalised_and_carries_no_comment() -> None:
    script = Script().json("GET", "/api/v2/check", TOR_EXIT)
    result = await _client(script).check("185.220.101.1")
    (request,) = script.requests
    assert request.headers["Key"] == KEY
    assert request.url.params["ipAddress"] == "185.220.101.1"
    assert request.url.params["maxAgeInDays"] == "90"
    assert "verbose" in request.url.params
    document = result.document()
    assert document["ip"] == "185.220.101.1"
    assert (document["score"], document["total_reports"], document["distinct_reporters"]) == (
        100,
        3,
        2,
    )
    assert document["is_tor"] is True and document["is_whitelisted"] is False
    assert (document["country_code"], document["usage_type"], document["isp"]) == (
        "DE",
        "University/College/School",
        "Example e.V.",
    )
    assert document["categories"] == {"Brute-Force": 2, "SSH": 2, "Hacking": 1, "Port Scan": 1}
    assert document["unknown_categories"] == 1
    assert document["last_reported_at"] == "2026-10-20T07:10:42+00:00"
    assert (document["source"], document["max_age_in_days"]) == ("abuseipdb", 90)
    assert "IGNORE" not in json.dumps(document) and "comment" not in json.dumps(document)


async def test_a_clean_address_is_an_answer_with_no_reports() -> None:
    script = Script().json("GET", "/api/v2/check", CLEAN)
    result = await _client(script).check("8.8.8.8", max_age_in_days=30)
    assert script.requests[0].url.params["maxAgeInDays"] == "30"
    assert (result.score, result.total_reports, result.categories) == (0, 0, {})
    assert result.last_reported_at is None and result.is_whitelisted is True


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "::1",
        "fd00::1",
        "8.8.8.0/24",
        "8.8.8.8:53",
        "http://8.8.8.8/",
        "dns.google",
        "fe80::1%eth0",
        "",
    ],
)
async def test_only_one_bare_public_address_is_ever_sent(value: str) -> None:
    script = Script().json("GET", "/api/v2/check", CLEAN)
    with pytest.raises(InvalidInputError):
        await _client(script).check(value)
    assert script.requests == []


@pytest.mark.parametrize("days", [0, 366, -1])
async def test_the_window_is_one_to_365_days(days: int) -> None:
    with pytest.raises(InvalidInputError):
        await _client(Script()).check("8.8.8.8", max_age_in_days=days)


async def test_an_ipv4_mapped_address_is_sent_as_its_ipv4() -> None:
    script = Script().json("GET", "/api/v2/check", CLEAN)
    await _client(script).check("::ffff:8.8.8.8")
    assert script.requests[0].url.params["ipAddress"] == "8.8.8.8"


async def test_the_quota_is_read_off_every_answer() -> None:
    script = Script().json("GET", "/api/v2/check", CLEAN, headers=quota(remaining=42))
    client = _client(script)
    assert client.quota is None
    await client.check("8.8.8.8")
    assert client.quota is not None
    assert (client.quota.limit, client.quota.remaining, client.quota.reset) == (
        10_000,
        42,
        1792540800,
    )


async def test_a_repeat_within_the_ttl_is_answered_from_the_cache() -> None:
    now = [1_000.0]
    script = Script().json("GET", "/api/v2/check", CLEAN)
    client = _client(script, clock=lambda: now[0], cache_seconds=3600)
    first = await client.check("8.8.8.8")
    again = await client.check("8.8.8.8")
    assert again == first and len(script.requests) == 1
    await client.check("8.8.8.8", max_age_in_days=30)
    assert len(script.requests) == 2  # another window is another question
    now[0] += 3601
    await client.check("8.8.8.8")
    assert len(script.requests) == 3


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "unauthorized"),
        (402, "plan"),
        (403, "forbidden"),
        (422, "invalid_input"),
        (429, "quota"),
        (500, "unavailable"),
        (503, "unavailable"),
    ],
)
async def test_a_failure_is_a_neutral_code_with_no_sales_text(status: int, code: str) -> None:
    body = {"errors": [{"detail": "Upgrade your plan at https://www.abuseipdb.com/pricing"}]}
    script = Script().json("GET", "/api/v2/check", body, status=status)
    with pytest.raises(AbuseIPDBError) as failed:
        await _client(script).check("8.8.8.8")
    assert failed.value.code == code and failed.value.status == status
    assert "pricing" not in str(failed.value) and "Upgrade" not in str(failed.value)


async def test_a_failure_is_not_cached() -> None:
    script = Script().json("GET", "/api/v2/check", {"errors": []}, status=503)
    client = _client(script)
    for _ in range(2):
        with pytest.raises(AbuseIPDBError):
            await client.check("8.8.8.8")
    assert len(script.requests) == 2


async def test_a_timeout_and_a_network_error_are_neutral_too() -> None:
    def slow(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    def down(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    for handler, code in ((slow, "timeout"), (down, "network")):
        with pytest.raises(AbuseIPDBError) as failed:
            await _client(Script().on("GET", "/api/v2/check", handler)).check("8.8.8.8")
        assert failed.value.code == code


async def test_an_answer_of_the_wrong_shape_is_refused() -> None:
    script = Script().json("GET", "/api/v2/check", {"data": "nope"})
    with pytest.raises(AbuseIPDBError) as failed:
        await _client(script).check("8.8.8.8")
    assert failed.value.code == "unexpected"


async def test_the_base_url_is_configurable() -> None:
    seen: list[str] = []

    def proxy(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url).split("?")[0])
        return httpx.Response(200, json=CLEAN, headers=quota())

    client = AbuseIPDBClient(
        "a-proxy-key",
        base_url="https://proxy.example/abuseipdb/",
        transport=httpx.MockTransport(proxy),
    )
    await client.check("8.8.8.8")
    assert seen == ["https://proxy.example/abuseipdb/check"]
    assert BASE.endswith("/api/v2")


def test_the_operations_are_declared_once_and_read_only() -> None:
    assert [(o.name, o.tool, o.kind) for o in OPERATIONS][:1] == [
        ("check", "abuseipdb_check_ip", "read")
    ]
    assert all(o.kind == "read" and o.description for o in OPERATIONS)
