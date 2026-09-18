"""HTTP transport shared by every operation: tokens per API, query building, paging, errors, retry."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json as jsonlib
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

import httpx

from .auth import TokenCredential
from .errors import DefenderApiError

JsonObject = dict[str, Any]
Param = str | int | bool | None
Method = Literal["GET", "POST", "PATCH", "DELETE"]

RETRIES = 3
THROTTLED = 429
"""The service refused the call before acting on it: safe to repeat for every method."""
UNAVAILABLE = 503
"""May arrive after the service acted: repeated for reads only, never for a write or an action."""
MAX_RETRY_DELAY = 30.0
TOKEN_SKEW = 60


@dataclass(frozen=True)
class Api:
    name: str
    base_url: str
    scope: str
    permission_hint: str


GRAPH = Api(
    "graph",
    "https://graph.microsoft.com/v1.0",
    "https://graph.microsoft.com/.default",
    " Hint: verify the app registration has the required Microsoft Graph application permissions"
    " (SecurityIncident.ReadWrite.All, SecurityAlert.ReadWrite.All, ThreatHunting.Read.All;"
    " AuditLog.Read.All for the sign-in and directory audit logs) with admin consent.",
)
MDE = Api(
    "mde",
    "https://api.securitycenter.microsoft.com/api",
    "https://api.securitycenter.microsoft.com/.default",
    " Hint: verify the app registration has the required WindowsDefenderATP application permissions"
    " (e.g. Machine.Read.All, Ti.ReadWrite.All, Vulnerability.Read.All) with admin consent.",
)


def seg(value: str | int) -> str:
    """One URL path segment: identifiers from alerts and users are data, never path syntax."""
    return quote(str(value), safe="")


def odata(
    filter: str | None = None,
    top: int | None = None,
    skip: int | None = None,
    orderby: str | None = None,
) -> dict[str, Param]:
    return {"$filter": filter, "$top": top, "$skip": skip or None, "$orderby": orderby}


def capped(top: int | None, default: int, maximum: int) -> int:
    """Every list operation is bounded: a conservative default, a hard ceiling, never below one."""
    return max(1, min(top if top is not None else default, maximum))


class Transport:
    def __init__(
        self,
        credential: TokenCredential,
        *,
        http: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._credential = credential
        self._http = http or httpx.AsyncClient(timeout=timeout)
        self._sleep = sleep
        self._tokens: dict[str, tuple[str, int]] = {}

    async def aclose(self) -> None:
        await self._http.aclose()

    async def token(self, api: Api) -> str:
        cached = self._tokens.get(api.scope)
        if cached and time.time() < cached[1] - TOKEN_SKEW:
            return cached[0]
        fresh = await self._credential.get_token(api.scope)
        self._tokens[api.scope] = (fresh.token, int(fresh.expires_on))
        return fresh.token

    async def claims(self, api: Api) -> dict[str, Any] | None:
        """The claims of the bearer token for an API, read without verification: for reporting the
        tenant and the granted application permissions, never for a decision about trust."""
        try:
            payload = (await self.token(api)).split(".")[1]
            found = jsonlib.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (IndexError, ValueError, binascii.Error):
            return None
        return found if isinstance(found, dict) else None

    async def request(
        self,
        api: Api,
        method: Method,
        path: str,
        *,
        params: Mapping[str, Param] | None = None,
        json: Any = None,
        form: Mapping[str, str] | None = None,
        files: Mapping[str, tuple[str, bytes]] | None = None,
    ) -> JsonObject:
        """One call. `json` is the usual body; `form` and `files` send multipart form data."""
        return await self._send(
            api, method, f"{api.base_url}{path}", path, params, json, form, files
        )

    async def collect(
        self, api: Api, path: str, *, params: Mapping[str, Param] | None = None, limit: int
    ) -> list[Any]:
        """The `value` items of a collection, following `@odata.nextLink` until `limit` is reached."""
        items: list[Any] = []
        page = await self.request(api, "GET", path, params=params)
        while True:
            items.extend(page.get("value") or [])
            next_link = page.get("@odata.nextLink")
            if not next_link or len(items) >= limit:
                return items[:limit]
            page = await self.follow(api, str(next_link), path)

    async def follow(self, api: Api, next_link: str, path: str) -> JsonObject:
        """GET a next link, only on the API's own host: the bearer token goes nowhere else."""
        target, home = httpx.URL(next_link), httpx.URL(api.base_url)
        if (target.scheme, target.host, target.port) != (home.scheme, home.host, home.port):
            raise DefenderApiError(
                status=0,
                api=api.name,
                method="GET",
                path=path,
                code="UnexpectedNextLink",
                message="refusing to follow a next link outside the API host",
            )
        return await self._send(api, "GET", next_link, path, None, None, None, None)

    async def _send(
        self,
        api: Api,
        method: Method,
        url: str,
        path: str,
        params: Mapping[str, Param] | None,
        json: Any,
        form: Mapping[str, str] | None,
        files: Mapping[str, tuple[str, bytes]] | None,
    ) -> JsonObject:
        query = {k: _text(v) for k, v in (params or {}).items() if v is not None and v != ""}
        for attempt in range(RETRIES + 1):
            headers = {"Authorization": f"Bearer {await self.token(api)}"}
            response = await self._http.request(
                method,
                url,
                params=query or None,
                json=json,
                data=dict(form) if form else None,
                files=dict(files) if files else None,
                headers=headers,
            )
            repeatable = response.status_code == THROTTLED or (
                response.status_code == UNAVAILABLE and method == "GET"
            )
            if repeatable and attempt < RETRIES:
                await self._sleep(_retry_delay(response, attempt))
                continue
            break
        if response.is_success:
            if not response.content:
                return {}
            try:
                body = response.json()
            except ValueError:
                raise DefenderApiError(
                    status=response.status_code,
                    api=api.name,
                    method=method,
                    path=path,
                    code="NotJson",
                    message="the response is not JSON: is a proxy in the way?",
                ) from None
            return body if isinstance(body, dict) else {"value": body}
        raise _error(api, method, path, response)


def _text(value: Param) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value)


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    try:
        asked = float(response.headers.get("Retry-After", ""))
    except ValueError:
        asked = float(2**attempt)
    return max(0.0, min(asked, MAX_RETRY_DELAY))


def _error(api: Api, method: str, path: str, response: httpx.Response) -> DefenderApiError:
    code, message = "", response.text[:2000]
    try:
        detail = response.json().get("error", {})
        if isinstance(detail, dict):
            code, message = str(detail.get("code", "")), str(detail.get("message", message))
    except (ValueError, AttributeError):
        pass
    hint = api.permission_hint if response.status_code in (401, 403) else ""
    return DefenderApiError(
        status=response.status_code,
        api=api.name,
        method=method,
        path=path,
        code=code,
        message=message,
        hint=hint,
    )
