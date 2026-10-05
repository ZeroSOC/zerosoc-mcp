"""Shared fixtures."""

from __future__ import annotations

import httpx
import pytest
from defender_fakes import FakeCredential, Script
from zerosoc_microsoft_security.client import MicrosoftSecurityClient
from zerosoc_microsoft_security.transport import Transport


@pytest.fixture
def script() -> Script:
    return Script()


@pytest.fixture
def credential() -> FakeCredential:
    return FakeCredential()


async def _no_sleep(_seconds: float) -> None:
    return None


@pytest.fixture
def transport(script: Script, credential: FakeCredential) -> Transport:
    http = httpx.AsyncClient(transport=httpx.MockTransport(script))
    return Transport(credential, http=http, sleep=_no_sleep)


@pytest.fixture
def client(transport: Transport) -> MicrosoftSecurityClient:
    return MicrosoftSecurityClient(transport=transport)


@pytest.fixture
def acting_client(transport: Transport) -> MicrosoftSecurityClient:
    return MicrosoftSecurityClient(transport=transport, allow_actions=True)
