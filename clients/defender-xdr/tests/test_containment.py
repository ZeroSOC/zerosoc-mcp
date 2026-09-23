"""Identity and mailbox containment: what each action answers, and what it refuses to lose.

The call each one makes is in the table in `test_operations.py`. What is here is what the table
cannot say: that an action the service answers with no content still says what it did, that a
mailbox's rules are cut rather than poured out whole, and that a rule can be read, removed and put
back with the behaviour it had.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from defender_fakes import Script
from zerosoc_defender_xdr.client import DefenderClient
from zerosoc_defender_xdr.errors import ActionsDisabledError

G = "https://graph.microsoft.com/v1.0"
RULES = f"{G}/users/u-1/mailFolders/inbox/messageRules"
ENCODED = "AAMkADYAAA%3D"
"""The rule's id as a path segment: an identifier the service gave us is data, never syntax."""
RULE: dict[str, Any] = {
    "id": "AAMkADYAAA=",
    "@odata.etag": 'W/"CQAAABYAAAA="',
    "displayName": "Move replies out of sight",
    "sequence": 1,
    "isEnabled": True,
    "isReadOnly": False,
    "hasError": False,
    "conditions": {"senderContains": ["payments"]},
    "actions": {"moveToFolder": "RSS Feeds", "stopProcessingRules": True},
}


async def test_an_account_action_the_directory_answers_with_nothing_still_says_what_it_did(
    acting_client: DefenderClient, script: Script
) -> None:
    """A property write answers 204 No Content. An operation that returned that as it stands would
    tell a caller nothing about the account it just disabled."""
    script.on("PATCH", f"{G}/users/u-1", lambda _r: httpx.Response(204))
    script.on(
        "POST",
        f"{G}/users/u-1/revokeSignInSessions",
        lambda _r: httpx.Response(200, json={"value": True}),
    )

    assert await acting_client.disable_account("u-1") == {"userId": "u-1", "accountEnabled": False}
    assert await acting_client.enable_account("u-1") == {"userId": "u-1", "accountEnabled": True}
    assert await acting_client.revoke_sign_in_sessions("u-1") == {"userId": "u-1", "revoked": True}


async def test_reading_an_account_asks_for_the_field_containment_is_decided_on(
    client: DefenderClient, script: Script
) -> None:
    """`accountEnabled` is not in the directory's default set: an operation that did not ask for it
    would answer without the one field that says whether the account is contained."""
    script.json("GET", f"{G}/users/u-1", {"id": "u-1", "accountEnabled": True})

    await client.get_user("u-1")

    assert "accountEnabled" in script.requests[0].url.params["$select"]


async def test_a_mailbox_with_more_rules_than_asked_for_is_cut_and_says_so(
    client: DefenderClient, script: Script
) -> None:
    """The mailbox returns its rules whole; an agent's context does not."""
    script.json("GET", RULES, {"value": [{"id": f"r-{n}"} for n in range(9)]})

    answer = await client.list_inbox_rules("u-1", top=4)

    assert [r["id"] for r in answer["value"]] == ["r-0", "r-1", "r-2", "r-3"]
    assert (answer["total"], answer["hasMore"], answer["userId"]) == (9, True, "u-1")


async def test_a_rule_is_read_removed_and_put_back_with_the_behaviour_it_had(
    acting_client: DefenderClient, script: Script
) -> None:
    """The service keeps no copy of a removed rule, so the restore is made from what was read. The
    fields the service owns are dropped: a restore that sent them back would be refused, and the
    rule that comes back is a new rule with the old behaviour."""
    script.json("GET", f"{RULES}/{ENCODED}", RULE)
    script.on("DELETE", f"{RULES}/{ENCODED}", lambda _r: httpx.Response(204))
    script.json("POST", RULES, {**RULE, "id": "AAMkADZAAA="})

    captured = await acting_client.get_inbox_rule("u-1", RULE["id"])
    removed = await acting_client.delete_inbox_rule("u-1", RULE["id"])
    restored = await acting_client.create_inbox_rule("u-1", captured)

    assert removed == {"userId": "u-1", "ruleId": RULE["id"], "deleted": True}
    sent = Script.body(script.sent("POST", "messageRules")[0])
    assert set(sent) == {"displayName", "sequence", "isEnabled", "conditions", "actions"}
    assert sent["conditions"] == RULE["conditions"] and sent["actions"] == RULE["actions"]
    assert restored["id"] != RULE["id"], "a restored rule is a new rule"


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("revoke_sign_in_sessions", {"user_id": "u-1"}),
        ("disable_account", {"user_id": "u-1"}),
        ("enable_account", {"user_id": "u-1"}),
        ("delete_inbox_rule", {"user_id": "u-1", "rule_id": "r-1"}),
        ("create_inbox_rule", {"user_id": "u-1", "rule": {}}),
    ],
)
async def test_containing_an_identity_is_a_response_action(
    client: DefenderClient, script: Script, name: str, arguments: dict[str, Any]
) -> None:
    """Every one of them changes the estate, so every one is behind the deployment's own gate —
    including the two that undo the other two: a rollback is an action like any other."""
    with pytest.raises(ActionsDisabledError):
        await getattr(client, name)(**arguments)
    assert script.requests == []


async def test_reading_the_directory_and_the_rules_needs_no_gate(
    client: DefenderClient, script: Script
) -> None:
    """Reading is how an approval is decided; it is not what an approval is for."""
    script.json("GET", f"{G}/users", {"value": []})
    script.json("GET", RULES, {"value": []})

    await client.list_users(filter="accountEnabled eq false")
    await client.list_inbox_rules("u-1")

    assert len(script.requests) == 2
