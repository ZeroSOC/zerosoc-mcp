"""The sign-in log read by window, and the tenant's Entra ID plan read from its subscriptions."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from defender_fakes import Script
from zerosoc_microsoft_security import identity_logs
from zerosoc_microsoft_security.client import MicrosoftSecurityClient
from zerosoc_microsoft_security.errors import InvalidInputError
from zerosoc_microsoft_security.identity_logs import ENTRA_P1_PLAN, ENTRA_P2_PLAN, entra_id_plan

G = "https://graph.microsoft.com/v1.0"
SIGN_INS = f"{G}/auditLogs/signIns"
SKUS = f"{G}/subscribedSkus"
SMB = "de377cbc-0019-4ec2-b77c-3f223947e102"
"""Service plan `AAD_SMB`, which Business Premium also carries and which is not Entra ID P1."""


def _sku(
    *plans: str, status: str = "Enabled", consumed: int = 3, provisioning: str = "Success"
) -> dict[str, Any]:
    """One subscription, shaped as `subscribedSkus` answers with the fields the client selects."""
    return {
        "skuPartNumber": "SPB",
        "capabilityStatus": status,
        "consumedUnits": consumed,
        "servicePlans": [
            {"servicePlanId": p, "servicePlanName": "X", "provisioningStatus": provisioning}
            for p in plans
        ],
    }


async def test_a_window_is_read_page_by_page_with_its_bounds_in_utc(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    script.on(
        "GET",
        SIGN_INS,
        httpx.Response(200, json=_page([{"id": "s1"}, {"id": "s2"}], f"{SIGN_INS}?$skiptoken=2")),
        httpx.Response(200, json=_page([{"id": "s3"}])),
    )

    found = await client.sign_ins_between("2026-11-06T10:00:00+01:00", "2026-11-06T09:05:00Z")

    first = script.sent("GET", "/auditLogs/signIns")[0]
    assert first.url.params["$filter"] == (
        "createdDateTime ge 2026-11-06T09:00:00Z and createdDateTime lt 2026-11-06T09:05:00Z"
    )
    assert first.url.params["$top"] == "1000"
    assert [s["id"] for s in found.sign_ins] == ["s1", "s2", "s3"]
    assert (found.start, found.end, found.truncated) == (
        "2026-11-06T09:00:00Z",
        "2026-11-06T09:05:00Z",
        False,
    )


async def test_a_window_holding_more_than_the_limit_is_cut_and_says_so(
    client: MicrosoftSecurityClient, script: Script, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(identity_logs, "SIGN_IN_LIMIT", 2)
    script.json("GET", SIGN_INS, {"value": [{"id": "s1"}, {"id": "s2"}, {"id": "s3"}]})

    found = await client.sign_ins_between("2026-11-06T09:00:00Z", "2026-11-06T09:05:00Z")

    assert [s["id"] for s in found.sign_ins] == ["s1", "s2"]
    assert found.truncated is True


@pytest.mark.parametrize(
    "bound", ["yesterday", "2026-11-06T09:00:00", "2026-11-06T09:00:00Z or true eq true"]
)
async def test_a_window_bound_must_be_a_timestamp_with_a_zone(
    client: MicrosoftSecurityClient, script: Script, bound: str
) -> None:
    with pytest.raises(InvalidInputError, match="with a zone"):
        await client.sign_ins_between(bound, "2026-11-06T09:05:00Z")
    assert script.requests == []


@pytest.mark.parametrize(
    ("skus", "plan"),
    [
        ([_sku(ENTRA_P1_PLAN, SMB)], "P1"),
        ([_sku(ENTRA_P1_PLAN), _sku(ENTRA_P2_PLAN, ENTRA_P1_PLAN)], "P2"),
        ([_sku(ENTRA_P2_PLAN.upper(), status="Warning")], "P2"),
        ([_sku(SMB)], None),
        ([_sku(ENTRA_P1_PLAN, status="Suspended")], None),
        ([_sku(ENTRA_P1_PLAN, consumed=0)], None),
        ([_sku(ENTRA_P1_PLAN, provisioning="Disabled")], None),
        ([], None),
    ],
    ids=[
        "business premium",
        "p2 above p1",
        "grace period",
        "smb plan alone",
        "suspended",
        "no seats",
        "plan switched off",
        "no subscription",
    ],
)
def test_the_plan_is_what_an_active_subscription_brings(
    skus: list[dict[str, Any]], plan: str | None
) -> None:
    assert entra_id_plan(skus) == plan


async def test_the_plan_is_read_from_the_subscriptions(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    script.json("GET", SKUS, {"value": [_sku(ENTRA_P1_PLAN)]})

    assert await client.entra_id_plan() == "P1"
    (sent,) = script.sent("GET", "/subscribedSkus")
    assert "servicePlans" in sent.url.params["$select"]


def _page(items: list[dict[str, Any]], next_link: str | None = None) -> dict[str, Any]:
    return {"value": items, **({"@odata.nextLink": next_link} if next_link else {})}
