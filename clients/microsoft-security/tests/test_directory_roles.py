"""Directory roles: who holds one, read whole or cut where the caller said, and never cut silently.

The call the operation opens with is in the table in `test_operations.py`. What is here is what the
table cannot say: that each role's members are read from the role itself, paged to the end rather
than expanded (an expansion stops at twenty and says nothing), that a member of any type comes back
in one shape, and that a role cut at the cap says so.
"""

from __future__ import annotations

from typing import Any

import httpx
from defender_fakes import Script
from zerosoc_microsoft_security.client import MicrosoftSecurityClient
from zerosoc_microsoft_security.identity import MEMBER_FIELDS

G = "https://graph.microsoft.com/v1.0"
ADMINS = {
    "id": "role-1",
    "displayName": "Global Administrator",
    "roleTemplateId": "tmpl-1",
    "description": "not asked for",
}
READERS = {"id": "role-2", "displayName": "Security Reader", "roleTemplateId": "tmpl-2"}
ALICE: dict[str, Any] = {
    "@odata.type": "#microsoft.graph.user",
    "id": "u-1",
    "displayName": "Alice Example",
    "userPrincipalName": "alice@contoso.com",
    "userType": "Member",
}
AUTOMATION: dict[str, Any] = {
    "@odata.type": "#microsoft.graph.servicePrincipal",
    "id": "sp-1",
    "displayName": "Automation",
}
UNREADABLE: dict[str, Any] = {"@odata.type": "#microsoft.graph.group", "id": "g-1"}
"""A member of a type the application may not read comes back with its type and id only."""


def members(role: str) -> str:
    return f"{G}/directoryRoles/{role}/members"


async def test_every_role_comes_with_its_members_in_one_shape(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    """A user, a service principal and a member the application cannot read all answer with the
    same keys, so a caller tells them apart by `@odata.type` rather than by what is missing."""
    script.json("GET", f"{G}/directoryRoles", {"value": [ADMINS, READERS]})
    script.json("GET", members("role-1"), {"value": [ALICE, AUTOMATION, UNREADABLE]})
    script.json("GET", members("role-2"), {"value": []})

    answer = await client.list_directory_roles()

    assert answer["total"] == 2
    admins, readers = answer["value"]
    assert set(admins) == {"id", "displayName", "roleTemplateId", "members", "hasMoreMembers"}
    assert (admins["displayName"], admins["roleTemplateId"], admins["hasMoreMembers"]) == (
        "Global Administrator",
        "tmpl-1",
        False,
    )
    assert admins["members"] == [
        ALICE,
        {**AUTOMATION, "userPrincipalName": None, "userType": None},
        {**UNREADABLE, "displayName": None, "userPrincipalName": None, "userType": None},
    ]
    assert all(tuple(m) == MEMBER_FIELDS for m in admins["members"])
    assert (readers["members"], readers["hasMoreMembers"]) == ([], False)


async def test_members_are_read_from_the_role_and_asked_for_the_fields_a_caller_needs(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    """`userType` is not in the directory's default set for an account, and an expansion cannot
    select, so the members are read from the role with the fields named."""
    script.json("GET", f"{G}/directoryRoles", {"value": [ADMINS]})
    script.json("GET", members("role-1"), {"value": [ALICE]})

    await client.list_directory_roles()

    read = script.sent("GET", "/members")[0]
    assert "$expand" not in script.requests[0].url.params
    assert set(read.url.params["$select"].split(",")) == {
        "id",
        "displayName",
        "userPrincipalName",
        "userType",
    }


async def test_a_role_with_more_members_than_one_page_is_read_to_the_end(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    """The service pages a large role; the operation follows the next link rather than answering
    with the first page as if it were the whole role."""
    first = [{**ALICE, "id": f"u-{n}"} for n in range(3)]
    second = [{**ALICE, "id": f"u-{n}"} for n in range(3, 5)]
    script.json("GET", f"{G}/directoryRoles", {"value": [ADMINS]})
    # The scripted transport routes on the URL without its query, and the next link differs from
    # the first request only in its query: one route answers both, with the pages in order.
    script.on(
        "GET",
        members("role-1"),
        httpx.Response(
            200,
            json={"value": first, "@odata.nextLink": f"{members('role-1')}?$skiptoken=page2"},
        ),
        httpx.Response(200, json={"value": second}),
    )

    answer = await client.list_directory_roles()

    role = answer["value"][0]
    assert [m["id"] for m in role["members"]] == [f"u-{n}" for n in range(5)]
    assert role["hasMoreMembers"] is False
    assert script.requests[-1].url.params["$skiptoken"] == "page2"


async def test_a_role_cut_at_the_cap_says_so(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    """A caller deciding who is privileged must know when it has not seen everyone."""
    script.json("GET", f"{G}/directoryRoles", {"value": [ADMINS, READERS]})
    script.json("GET", members("role-1"), {"value": [{**ALICE, "id": f"u-{n}"} for n in range(5)]})
    script.json("GET", members("role-2"), {"value": [ALICE, AUTOMATION]})

    answer = await client.list_directory_roles(top=2)

    admins, readers = answer["value"]
    assert ([m["id"] for m in admins["members"]], admins["hasMoreMembers"]) == (
        ["u-0", "u-1"],
        True,
    )
    assert (len(readers["members"]), readers["hasMoreMembers"]) == (2, False)


async def test_the_member_cap_holds_whatever_is_asked(
    client: MicrosoftSecurityClient, script: Script
) -> None:
    script.json("GET", f"{G}/directoryRoles", {"value": [ADMINS]})
    script.json("GET", members("role-1"), {"value": [{**ALICE, "id": f"u-{n}"} for n in range(5)]})

    none = await client.list_directory_roles(top=0)
    assert len(none["value"][0]["members"]) == 1
