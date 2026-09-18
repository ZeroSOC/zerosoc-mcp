"""Test doubles: a fake credential and a scripted HTTP transport. No network, no tenant."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from zerosoc_defender_xdr.auth import Token

Handler = Callable[[httpx.Request], httpx.Response]


class FakeCredential:
    """Counts token requests; the token names its scope so tests can see which API was called."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def get_token(self, *scopes: str) -> Token:
        self.calls.append(scopes[0])
        return Token(token=f"token-for-{scopes[0]}", expires_on=4102444800)


@dataclass
class Script:
    """Routes "METHOD url-without-query" to a canned response and records every request."""

    routes: dict[str, list[httpx.Response] | Handler] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)

    def on(self, method: str, url: str, *responses: httpx.Response | Handler) -> Script:
        first = responses[0]
        self.routes[f"{method} {url}"] = first if callable(first) else list(responses)  # type: ignore[arg-type]
        return self

    def json(self, method: str, url: str, body: Any, status: int = 200) -> Script:
        return self.on(method, url, lambda _request: httpx.Response(status, json=body))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = f"{request.method} {str(request.url).split('?')[0]}"
        route = self.routes.get(key)
        if route is None:
            return httpx.Response(404, json={"error": {"message": f"no route for {key}"}})
        if callable(route):
            return route(request)
        return route.pop(0) if len(route) > 1 else route[0]

    def sent(self, method: str, url_part: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and url_part in str(r.url)]

    @staticmethod
    def body(request: httpx.Request) -> Any:
        return json.loads(request.content)


def jwt(roles: list[str]) -> str:
    """An unsigned token with a `roles` claim, shaped like the ones the identity platform issues."""
    import base64

    def part(value: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none'})}.{part({'roles': roles})}.signature"


class RoleCredential:
    """Hands out tokens whose `roles` claim depends on the API asked for."""

    def __init__(self, graph: list[str], mde: list[str]) -> None:
        self._roles = {"graph.microsoft.com": graph, "api.securitycenter.microsoft.com": mde}

    async def get_token(self, *scopes: str) -> Token:
        host = scopes[0].split("/")[2]
        return Token(token=jwt(self._roles[host]), expires_on=4102444800)
