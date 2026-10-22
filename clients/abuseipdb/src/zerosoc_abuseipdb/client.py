"""Deterministic, typed access to AbuseIPDB.

`check` asks about one address and answers what a host needs to weigh it: the confidence score,
how many reports by how many reporters, what kinds of abuse were reported, who runs the address,
and whether it is a Tor exit or on AbuseIPDB's own allowlist. Three things are never done:

*   **Nothing but one bare public address is sent.** A private, shared, reserved or multicast
    address, a range, a URL, a host name or an address with a port is refused before any request:
    it says nothing to AbuseIPDB and something about the network that holds it.
*   **No report comment is returned.** Anyone can write one, so it can say anything, including
    instructions for whoever reads it. The kinds of abuse are counted from the reports' categories.
*   **No service text is passed on.** A failure is a code and a sentence of this client's own
    (`errors.AbuseIPDBError`).

The key and the base URL are the caller's: the service's own address by default, or any endpoint
that answers in its shape. Answers are cached for a while, since a lookup costs one check of the
plan's daily quota, and the quota is read off every answer.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from .blacklist import BlacklistStore, Synced
from .categories import CATEGORIES
from .errors import AbuseIPDBError, Code, InvalidInputError
from .operations import Operation, operation, operations_of

BASE_URL = "https://api.abuseipdb.com/api/v2"
TIMEOUT_SECONDS = 20.0
CACHE_SECONDS = 3600
"""How long an answer stands. A report filed in the hour moves a score little; a check costs quota."""
MAX_AGE_DEFAULT = 90

_STATUS: dict[int, Code] = {
    401: "unauthorized",
    402: "plan",
    403: "forbidden",
    422: "invalid_input",
    429: "quota",
}


@dataclass(frozen=True)
class Quota:
    """The plan's quota as the last answer stated it."""

    limit: int
    remaining: int
    reset: int | None
    """When it resets, in seconds since the epoch, where the answer says."""


@dataclass(frozen=True)
class CheckResult:
    """What AbuseIPDB knows of one address, in the client's own terms."""

    ip: str
    score: int
    """AbuseIPDB's confidence of abuse, 0-100: one source's reading, not a count of engines."""
    total_reports: int
    distinct_reporters: int
    categories: dict[str, int]
    """Reports per kind of abuse, by AbuseIPDB's category names."""
    unknown_categories: int
    """Category ids this client has no name for, counted rather than dropped."""
    is_tor: bool
    is_whitelisted: bool
    is_public: bool
    country_code: str | None
    country_name: str | None
    usage_type: str | None
    isp: str | None
    domain: str | None
    hostnames: tuple[str, ...]
    last_reported_at: str | None
    max_age_in_days: int
    checked_at: int
    """When the answer was read, in milliseconds since the epoch."""
    source: str = field(default="abuseipdb")

    def document(self) -> dict[str, Any]:
        held = asdict(self)
        held["hostnames"] = list(self.hostnames)
        return held


def public_address(value: str) -> str:
    """The address as it is sent, or `InvalidInputError` when it is not one bare public address."""
    text = (value or "").strip()
    if not text or "/" in text or "%" in text:
        raise InvalidInputError("pass one bare IP address, not a range, a URL or a host name")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise InvalidInputError(f"{text!r} is not an IP address") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast:
        raise InvalidInputError(
            f"{address} is not a public address: private, shared, reserved and multicast addresses"
            " are never sent"
        )
    return str(address)


class AbuseIPDBClient:
    """One key's access to AbuseIPDB, read-only."""

    def __init__(
        self,
        key: str,
        *,
        base_url: str = BASE_URL,
        timeout: float = TIMEOUT_SECONDS,
        cache_seconds: float = CACHE_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if not key:
            raise ValueError(
                "pass the AbuseIPDB key, or the key of the endpoint that answers for it"
            )
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/",
            timeout=httpx.Timeout(timeout),
            headers={"Accept": "application/json", "Key": key},
            transport=transport,
        )
        self._cache_seconds = cache_seconds
        self._clock = clock
        self._wall_clock = wall_clock
        self._cache: dict[tuple[str, int], tuple[float, CheckResult]] = {}
        # each endpoint has a daily quota of its own: many checks, few blacklist downloads
        self._quotas: dict[str, Quota] = {}

    @property
    def quota(self) -> Quota | None:
        """The checks' quota as the last check stated it; None before the first."""
        return self._quotas.get("check")

    @property
    def blacklist_quota(self) -> Quota | None:
        """The blacklist downloads' quota as the last download stated it; None before the first."""
        return self._quotas.get("blacklist")

    async def aclose(self) -> None:
        await self._http.aclose()

    @operation(tool="abuseipdb_check_ip")
    async def check(self, ip: str, max_age_in_days: int = MAX_AGE_DEFAULT) -> CheckResult:
        """An IP address's AbuseIPDB reputation: its abuse confidence score (0-100), how many reports by
        how many distinct reporters in the window, the kinds of abuse reported, its country, network
        operator and usage type, and whether it is a Tor exit or on AbuseIPDB's allowlist. One public
        address only; reports' free-text comments are never returned."""
        address = public_address(ip)
        if not 1 <= max_age_in_days <= 365:
            raise InvalidInputError("max_age_in_days is a window of 1 to 365 days")
        key = (address, max_age_in_days)
        held = self._cache.get(key)
        now = self._clock()
        if held is not None and held[0] > now:
            return held[1]
        data = await self._get(
            "check", {"ipAddress": address, "maxAgeInDays": max_age_in_days, "verbose": ""}
        )
        result = self._result(data, max_age_in_days)
        self._cache[key] = (now + self._cache_seconds, result)
        return result

    async def sync_blacklist(
        self, store: BlacklistStore, *, confidence_minimum: int = 75, limit: int = 10_000
    ) -> Synced:
        """Download the blacklist (addresses at or above ``confidence_minimum``, at most ``limit``)
        into ``store``, whole. On any failure the store keeps its last good copy. A plan allows a
        number of downloads a day; AbuseIPDB regenerates the list hourly, so a daily sync is the
        usual schedule."""
        if not 25 <= confidence_minimum <= 100:
            raise ValueError("confidence_minimum is 25 to 100, as AbuseIPDB takes it")
        if limit < 1:
            raise ValueError("limit is at least 1")
        body = await self._get(
            "blacklist", {"confidenceMinimum": confidence_minimum, "limit": limit}, whole=True
        )
        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, list):
            raise AbuseIPDBError("unexpected", status=200)
        meta = body.get("meta") if isinstance(body.get("meta"), dict) else {}
        # the store writes a file: off the event loop, so a host's other calls go on meanwhile
        return await asyncio.to_thread(
            store.replace,
            data,
            generated_at=meta.get("generatedAt"),
            confidence_minimum=confidence_minimum,
            synced_at=int(self._wall_clock() * 1000),
        )

    async def _get(self, path: str, params: Mapping[str, str | int], *, whole: bool = False) -> Any:
        try:
            response = await self._http.get(path, params=params)
        except httpx.TimeoutException as exc:
            raise AbuseIPDBError("timeout") from exc
        except httpx.HTTPError as exc:
            raise AbuseIPDBError("network") from exc
        self._read_quota(path, response.headers)
        if response.status_code != 200:
            code = _STATUS.get(response.status_code)
            if code is None:
                code = "unavailable" if response.status_code >= 500 else "unexpected"
            raise AbuseIPDBError(code, status=response.status_code)
        try:
            body = response.json()
        except ValueError as exc:
            raise AbuseIPDBError("unexpected", status=200) from exc
        if not isinstance(body, dict):
            raise AbuseIPDBError("unexpected", status=200)
        return body if whole else body.get("data")

    def _read_quota(self, path: str, headers: httpx.Headers) -> None:
        limit, remaining = headers.get("X-RateLimit-Limit"), headers.get("X-RateLimit-Remaining")
        if limit and remaining and limit.isdigit() and remaining.isdigit():
            reset = headers.get("X-RateLimit-Reset")
            self._quotas[path] = Quota(
                int(limit), int(remaining), int(reset) if reset and reset.isdigit() else None
            )

    def _result(self, data: Any, max_age_in_days: int) -> CheckResult:
        if not isinstance(data, dict) or not data.get("ipAddress"):
            raise AbuseIPDBError("unexpected", status=200)
        counted: Counter[str] = Counter()
        unknown = 0
        for report in data.get("reports") or ():
            # only the categories are read: the comment never leaves this method
            for category in (report or {}).get("categories") or ():
                name = CATEGORIES.get(category) if isinstance(category, int) else None
                if name is None:
                    unknown += 1
                else:
                    counted[name] += 1
        return CheckResult(
            ip=str(data["ipAddress"]),
            score=int(data.get("abuseConfidenceScore") or 0),
            total_reports=int(data.get("totalReports") or 0),
            distinct_reporters=int(data.get("numDistinctUsers") or 0),
            categories=dict(counted.most_common()),
            unknown_categories=unknown,
            is_tor=bool(data.get("isTor")),
            is_whitelisted=bool(data.get("isWhitelisted")),
            is_public=bool(data.get("isPublic", True)),
            country_code=_text(data.get("countryCode")),
            country_name=_text(data.get("countryName")),
            usage_type=_text(data.get("usageType")),
            isp=_text(data.get("isp")),
            domain=_text(data.get("domain")),
            hostnames=tuple(str(h) for h in data.get("hostnames") or () if h),
            last_reported_at=_text(data.get("lastReportedAt")),
            max_age_in_days=max_age_in_days,
            checked_at=int(self._wall_clock() * 1000),
        )


def _text(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


OPERATIONS: tuple[Operation, ...] = operations_of(AbuseIPDBClient)
