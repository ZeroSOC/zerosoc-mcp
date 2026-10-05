"""Credentials. The client asks a credential for a bearer token per API scope and nothing else.

`TokenCredential` has the shape of the async credentials of the Azure identity library, so a managed
identity, a certificate credential or a token service that hands out the connector's token can be
passed in unchanged. `ClientSecretCredential` is the dependency-free default for an app registration
with a client secret.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .errors import DefenderApiError

AUTHORITY = "https://login.microsoftonline.com"
CREDENTIAL_VARIABLES = ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET")


class AccessToken(Protocol):
    @property
    def token(self) -> str: ...

    @property
    def expires_on(self) -> int: ...


class TokenCredential(Protocol):
    async def get_token(self, *scopes: str) -> AccessToken: ...


@dataclass(frozen=True)
class Token:
    token: str
    expires_on: int
    """Expiry as seconds since the epoch."""


class ClientSecretCredential:
    """OAuth 2.0 client-credentials grant for one tenant (application permissions)."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = http

    def __repr__(self) -> str:  # the secret never reaches a log line through repr()
        return (
            f"ClientSecretCredential(tenant_id={self._tenant_id!r}, client_id={self._client_id!r})"
        )

    async def get_token(self, *scopes: str) -> Token:
        form = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": " ".join(scopes),
        }
        url = f"{AUTHORITY}/{self._tenant_id}/oauth2/v2.0/token"
        if self._http is not None:
            response = await self._http.post(url, data=form)
        else:
            async with httpx.AsyncClient(timeout=30) as http:
                response = await http.post(url, data=form)
        payload = _json(response)
        if response.status_code != 200 or "access_token" not in payload:
            raise DefenderApiError(
                status=response.status_code,
                api="login",
                method="POST",
                path=f"/{self._tenant_id}/oauth2/v2.0/token",
                code=str(payload.get("error", "")),
                message=str(payload.get("error_description", "token request refused")),
                hint=" Hint: check the tenant id, the client id and the client secret.",
            )
        return Token(
            str(payload["access_token"]), int(time.time()) + int(payload.get("expires_in", 3600))
        )


def credential_from(environment: Mapping[str, str]) -> ClientSecretCredential | None:
    """The app registration named by the environment, or None when any of the three is missing."""
    tenant, client, secret = (environment.get(name, "").strip() for name in CREDENTIAL_VARIABLES)
    return ClientSecretCredential(tenant, client, secret) if tenant and client and secret else None


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
