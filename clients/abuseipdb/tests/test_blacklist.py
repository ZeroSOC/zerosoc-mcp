"""The blacklist (#44): synced to a local store on a schedule, matched with no request.

A listed address costs no query and tells AbuseIPDB nothing. A sync that fails keeps the last good
copy, and the store says when it was refreshed, so a host can say how fresh its answer is.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from abuseipdb_fakes import KEY, Script, quota
from zerosoc_abuseipdb import AbuseIPDBClient, AbuseIPDBError, BlacklistStore

LISTED: dict[str, Any] = {
    "meta": {"generatedAt": "2026-10-20T16:57:16+00:00"},
    "data": [
        {
            "ipAddress": "171.25.158.87",
            "countryCode": "SE",
            "abuseConfidenceScore": 100,
            "lastReportedAt": "2026-10-20T16:17:01+00:00",
        },
        {
            "ipAddress": "2001:db8:dead::1",
            "countryCode": None,
            "abuseConfidenceScore": 80,
            "lastReportedAt": "2026-10-20T15:00:00+00:00",
        },
    ],
}


def _client(script: Script) -> AbuseIPDBClient:
    return AbuseIPDBClient(
        KEY, transport=httpx.MockTransport(script), wall_clock=lambda: 1_792_500_000.0
    )


async def test_a_sync_writes_the_store_and_a_lookup_makes_no_request(tmp_path: Path) -> None:
    script = Script().json(
        "GET", "/api/v2/blacklist", LISTED, headers=quota(remaining=99, limit=100)
    )
    store = BlacklistStore(tmp_path / "blacklist.json")
    synced = await _client(script).sync_blacklist(store)
    (request,) = script.requests
    assert request.url.params["confidenceMinimum"] == "75"
    assert request.url.params["limit"] == "10000"
    assert (synced.count, synced.generated_at, synced.confidence_minimum) == (
        2,
        "2026-10-20T16:57:16+00:00",
        75,
    )
    assert synced.synced_at == 1_792_500_000_000

    reopened = BlacklistStore(tmp_path / "blacklist.json")
    hit = reopened.lookup("171.25.158.87")
    assert hit is not None and (hit.score, hit.country_code) == (100, "SE")
    assert hit.last_reported_at == "2026-10-20T16:17:01+00:00"
    assert (
        reopened.lookup(" 2001:db8:dead:0::1 ") is not None
    )  # the same address, written otherwise
    assert reopened.lookup("8.8.8.8") is None
    assert reopened.lookup("not an address") is None
    assert len(script.requests) == 1


async def test_the_threshold_and_the_limit_are_the_hosts(tmp_path: Path) -> None:
    script = Script().json("GET", "/api/v2/blacklist", LISTED)
    await _client(script).sync_blacklist(
        BlacklistStore(tmp_path / "b.json"), confidence_minimum=90, limit=500
    )
    assert script.requests[0].url.params["confidenceMinimum"] == "90"
    assert script.requests[0].url.params["limit"] == "500"


@pytest.mark.parametrize(("minimum", "limit"), [(24, 10), (101, 10), (75, 0)])
async def test_a_threshold_outside_25_to_100_or_no_limit_is_refused(
    tmp_path: Path, minimum: int, limit: int
) -> None:
    with pytest.raises(ValueError):
        await _client(Script()).sync_blacklist(
            BlacklistStore(tmp_path / "b.json"), confidence_minimum=minimum, limit=limit
        )


async def test_a_failed_sync_keeps_the_last_good_copy(tmp_path: Path) -> None:
    path = tmp_path / "blacklist.json"
    store = BlacklistStore(path)
    await _client(Script().json("GET", "/api/v2/blacklist", LISTED)).sync_blacklist(store)
    before = path.read_bytes()
    for failing in (
        Script().json("GET", "/api/v2/blacklist", {"errors": []}, status=429),
        Script().json("GET", "/api/v2/blacklist", {"meta": {}, "data": "nope"}),
    ):
        with pytest.raises(AbuseIPDBError):
            await _client(failing).sync_blacklist(store)
    assert path.read_bytes() == before
    assert store.lookup("171.25.158.87") is not None


async def test_an_entry_that_is_not_an_address_is_skipped_not_fatal(tmp_path: Path) -> None:
    odd = {
        "meta": {"generatedAt": "x"},
        "data": [*LISTED["data"], {"ipAddress": "nope"}, "garbage"],
    }
    store = BlacklistStore(tmp_path / "b.json")
    synced = await _client(Script().json("GET", "/api/v2/blacklist", odd)).sync_blacklist(store)
    assert synced.count == 2 and synced.skipped == 2


def test_an_empty_or_missing_store_answers_nothing(tmp_path: Path) -> None:
    store = BlacklistStore(tmp_path / "none.json")
    assert store.lookup("171.25.158.87") is None
    assert store.synced_at is None and store.count == 0


def test_a_corrupt_store_reads_as_empty_and_is_never_trusted(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text("{not json", encoding="utf-8")
    store = BlacklistStore(path)
    assert store.lookup("171.25.158.87") is None and store.synced_at is None


async def test_the_store_is_written_whole_or_not_at_all(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    await _client(Script().json("GET", "/api/v2/blacklist", LISTED)).sync_blacklist(
        BlacklistStore(path)
    )
    names, held = _on_disk(tmp_path, path)
    assert names == ["b.json"]  # no temporary file left behind
    assert held["format"] == "zerosoc-abuseipdb-blacklist" and held["version"] == 1


def _on_disk(folder: Path, path: Path) -> tuple[list[str], dict[str, Any]]:
    return sorted(p.name for p in folder.iterdir()), json.loads(path.read_text(encoding="utf-8"))


async def test_the_check_quota_and_the_download_quota_are_kept_apart(tmp_path: Path) -> None:
    """A plan allows many checks a day and few blacklist downloads, each counted on its own; a
    sync must not make the checks left read as the downloads left."""
    script = (
        Script()
        .json(
            "GET",
            "/api/v2/check",
            {"data": {"ipAddress": "8.8.8.8", "reports": []}},
            headers=quota(remaining=9_990, limit=10_000),
        )
        .json("GET", "/api/v2/blacklist", LISTED, headers=quota(remaining=98, limit=100))
    )
    client = _client(script)
    await client.check("8.8.8.8")
    await client.sync_blacklist(BlacklistStore(tmp_path / "b.json"))
    assert client.quota is not None and (client.quota.limit, client.quota.remaining) == (
        10_000,
        9_990,
    )
    assert client.blacklist_quota is not None
    assert (client.blacklist_quota.limit, client.blacklist_quota.remaining) == (100, 98)
