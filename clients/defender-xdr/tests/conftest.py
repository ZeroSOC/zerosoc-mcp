"""Shared fixtures."""

from __future__ import annotations

import httpx
import pytest
from defender_fakes import FakeCredential, Script
from zerosoc_defender_xdr.client import DefenderClient
from zerosoc_defender_xdr.transport import Transport


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
def client(transport: Transport) -> DefenderClient:
    return DefenderClient(transport=transport)


@pytest.fixture
def acting_client(transport: Transport) -> DefenderClient:
    return DefenderClient(transport=transport, allow_actions=True)
