"""Inbox rules (Microsoft Graph, /users/{id}/mailFolders/inbox/messageRules).

A rule that forwards, moves or deletes mail is how a mailbox takeover stays quiet: the owner never
sees the replies. Containing it means removing the rule, and removing it destroys it — the service
keeps no copy — so this surface reads a rule before anything deletes one, and can put back exactly
what it read.

Nothing here reads a message. The rules are settings on the mailbox, not its contents: an
integration that could read the mail would be a different integration, with a different permission
and a different conversation with the customer.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from .operations import operation
from .surface import Surface, top
from .transport import GRAPH, JsonObject, capped, seg

_READ = ("Mail.Read",)
"""Reading the rules of a mailbox. `Mail.ReadWrite` grants it too."""
_WRITE = ("Mail.ReadWrite",)
"""Removing a rule, and putting one back."""

READ_ONLY_FIELDS = ("id", "@odata.etag", "@odata.context", "isReadOnly", "hasError")
"""What the service owns on a rule. A restore that sent them back would be refused, so they are
dropped and the restored rule is a new rule with the old behaviour."""

MailboxId = Annotated[
    str,
    Field(
        description="The mailbox owner: their object id or user principal name (alice@contoso.com)."
    ),
]
RuleId = Annotated[str, Field(description="The inbox rule's id, from mailbox_list_inbox_rules.")]


class Mailbox(Surface):
    @operation(tool="mailbox_list_inbox_rules", api="graph", permissions=_READ)
    async def list_inbox_rules(
        self,
        user_id: MailboxId,
        top: Annotated[int, top("rules", 25, 100)] = 25,
    ) -> JsonObject:
        """List the inbox rules of a mailbox: each rule's id, display name, whether it is enabled,
        the conditions it matches on and the actions it takes — forward, redirect, move to a
        folder, mark as read, delete. Read this when an account is suspected of takeover: a rule
        that forwards to an address outside the organization, or moves replies into a folder nobody
        opens, is how the owner is kept from noticing. The mailbox returns its rules whole; the
        answer is cut to `top` and says how many there were."""
        answer = await self._api.request(
            GRAPH, "GET", f"/users/{seg(user_id)}/mailFolders/inbox/messageRules"
        )
        rules = list(answer.get("value") or [])
        size = capped(top, 25, 100)
        return {
            "userId": user_id,
            "value": rules[:size],
            "total": len(rules),
            "hasMore": len(rules) > size,
        }

    @operation(tool="mailbox_get_inbox_rule", api="graph", permissions=_READ)
    async def get_inbox_rule(self, user_id: MailboxId, rule_id: RuleId) -> JsonObject:
        """Get one inbox rule whole, with every condition and action it carries. Read it before
        removing it: removal destroys the rule, and this answer is what a restore is made from."""
        return await self._api.request(
            GRAPH,
            "GET",
            f"/users/{seg(user_id)}/mailFolders/inbox/messageRules/{seg(rule_id)}",
        )

    @operation(tool="mailbox_delete_inbox_rule", api="graph", kind="action", permissions=_WRITE)
    async def delete_inbox_rule(self, user_id: MailboxId, rule_id: RuleId) -> JsonObject:
        """RESPONSE ACTION. Remove an inbox rule from a mailbox. The service keeps no copy, so read
        the rule first (mailbox_get_inbox_rule) and keep what it answered: that is the only thing a
        restore can be made from, and mailbox_create_inbox_rule takes it back unchanged. Removing a
        rule does not undo what it already did — mail it moved stays where it was put."""
        await self._api.request(
            GRAPH,
            "DELETE",
            f"/users/{seg(user_id)}/mailFolders/inbox/messageRules/{seg(rule_id)}",
        )
        return {"userId": user_id, "ruleId": rule_id, "deleted": True}

    @operation(tool="mailbox_create_inbox_rule", api="graph", kind="action", permissions=_WRITE)
    async def create_inbox_rule(
        self,
        user_id: MailboxId,
        rule: Annotated[
            dict[str, Any],
            Field(
                description="The rule to create, as mailbox_get_inbox_rule answers one:"
                " displayName, sequence, isEnabled, conditions, actions, exceptions. The fields the"
                " service owns (id, etag, isReadOnly, hasError) are dropped."
            ),
        ],
    ) -> JsonObject:
        """RESPONSE ACTION. Create an inbox rule on a mailbox — the rollback of
        mailbox_delete_inbox_rule, made from what was read before the removal. The rule that comes
        back is a new rule with a new id and the old behaviour; nothing restores the original id.
        A rule put back on a mailbox is a rule that will act on mail again, so whoever asks for it
        says they read what it does."""
        body = {k: v for k, v in rule.items() if k not in READ_ONLY_FIELDS}
        return await self._api.request(
            GRAPH, "POST", f"/users/{seg(user_id)}/mailFolders/inbox/messageRules", json=body
        )
