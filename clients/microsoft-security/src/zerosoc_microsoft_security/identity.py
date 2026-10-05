"""Entra ID accounts (Microsoft Graph, /users): who an account is, which directory roles it holds
(/directoryRoles), and the two ways to contain it.

An incident that reaches an identity is contained in the directory, not on the endpoint. Two actions
belong here and no others: ending the account's sessions, and disabling it. Both are recorded with
the account they act on; neither deletes anything, and each is undone by an ordinary operation — the
person signs in again, or the account is enabled again — which is what makes them usable under an
approval rather than a change window.

Nothing here resets a password, adds or removes an authentication method, or edits any other
property of the account. Those are identity administration, they are not reversible in the same
breath, and a security integration that could do them would be a standing invitation to.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .operations import operation
from .surface import Filter, Surface, top
from .transport import GRAPH, JsonObject, capped, odata, seg

_READ = ("User.Read.All",)
"""Reading the directory. `Directory.Read.All` grants it too, where a tenant prefers that."""
_ROLES = ("RoleManagement.Read.Directory",)
"""Reading the activated directory roles and who holds them. `Directory.Read.All` grants it too,
where a tenant prefers that. A member is described in full only where the application may read its
type as well (`User.Read.All` for an account, which `_READ` already asks for); otherwise the
directory answers with its type and id alone. `Directory.Read.All` reads every type."""
_REVOKE = ("User.RevokeSessions.All",)
"""Ending an account's sessions. `User.ReadWrite.All` grants it too; this one is the least
privilege that does, and it cannot change anything about the account."""
_ENABLE = ("User.EnableDisableAccount.All",)
"""Turning an account off and on again. `User.ReadWrite.All` grants it too and much else besides."""

FIELDS = (
    "id,displayName,userPrincipalName,mail,accountEnabled,userType,jobTitle,department,"
    "officeLocation,createdDateTime,onPremisesSyncEnabled,onPremisesSamAccountName"
)
"""What an account answers with. `accountEnabled` is not in the directory's own default set, and it
is the one field a reader deciding on containment — or reading back what containment did — needs."""

ROLE_FIELDS = "id,displayName,roleTemplateId"
_MEMBER_SELECT = "id,displayName,userPrincipalName,userType"
MEMBER_FIELDS = ("@odata.type", "id", "userPrincipalName", "displayName", "userType")
"""What a role member answers with, whatever its type: `@odata.type` tells an account from a
service principal or a group, and a property the type does not have is null. `userType` is not in
the directory's default set for an account, so it is asked for by name."""
MAX_ROLES = 500
"""Activated roles come from the directory's catalog of built-in roles, well under this; the bound
is there so that no answer is unbounded."""

UserId = Annotated[
    str,
    Field(
        description="The account: its object id or its user principal name"
        " (alice@contoso.com). Both are accepted wherever an account is named."
    ),
]


class Identity(Surface):
    @operation(tool="entra_list_users", api="graph", permissions=_READ)
    async def list_users(
        self,
        filter: Filter = None,
        top: Annotated[int, top("accounts", 25, 100)] = 25,
    ) -> JsonObject:
        """List Entra ID accounts with the fields an investigation reads: display name, user
        principal name, mail, whether the account is enabled, its type (Member or Guest), job title
        and department, when it was created, and whether it is synchronised from on-premises Active
        Directory. Always filter, e.g. "startswith(displayName,'Rossi')",
        "userPrincipalName eq 'alice@contoso.com'", "accountEnabled eq false". Prefer
        entra_get_user when the account is already named. Timestamps are UTC."""
        return await self._api.request(
            GRAPH,
            "GET",
            "/users",
            params={**odata(filter, capped(top, 25, 100)), "$select": FIELDS},
        )

    @operation(tool="entra_get_user", api="graph", permissions=_READ)
    async def get_user(self, user_id: UserId) -> JsonObject:
        """Get one Entra ID account: display name, user principal name, mail, whether it is
        enabled, its type, job title, department, office, when it was created and whether it is
        synchronised from on-premises Active Directory. Read it before containing an account, and
        again afterwards to see what the containment left behind."""
        return await self._api.request(
            GRAPH, "GET", f"/users/{seg(user_id)}", params={"$select": FIELDS}
        )

    @operation(tool="entra_list_directory_roles", api="graph", permissions=_ROLES)
    async def list_directory_roles(
        self,
        filter: Filter = None,
        top: Annotated[int, top("members per role", 100, 1000)] = 100,
    ) -> JsonObject:
        """List the Entra ID directory roles that are in use in the tenant, each with who holds
        it: the role's id, display name and roleTemplateId (the same in every tenant for a built-in
        role, so match on it rather than on the name), and for each member its @odata.type (user,
        servicePrincipal or group), id, userPrincipalName, displayName and userType (Member or
        Guest); a property the member's type does not have is null. Use it to tell privileged
        accounts from the rest, e.g. before trusting an account's activity or approving action on
        it; prefer entra_get_user to read one account. Only activated roles appear, which is every
        role anyone holds. The members are the active, tenant-wide assignments: an eligible
        assignment not activated now, or one scoped to an administrative unit, is not listed, and a
        group that holds a role is listed as the group, not its members. Filter by role, e.g.
        "roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'" (Global Administrator) or
        "displayName eq 'Security Administrator'". Each role's members are read to the end and cut
        at `top`; `hasMoreMembers` says a role was cut, so raise `top` rather than reading the
        list as complete."""
        roles = await self._api.collect(
            GRAPH,
            "/directoryRoles",
            params={**odata(filter), "$select": ROLE_FIELDS},
            limit=MAX_ROLES,
        )
        size = capped(top, 100, 1000)
        value = [await self._role_with_members(role, size) for role in roles]
        return {"value": value, "total": len(value)}

    async def _role_with_members(self, role: JsonObject, size: int) -> JsonObject:
        """One role and its members. Read from the role rather than expanded on the list: an
        expansion of directory objects stops at twenty members, offers no next link and takes no
        $select, so it would cut a large role silently and never carry `userType`. One more than
        the cap is read, which is how a cut is told from a role that fits exactly."""
        path = f"/directoryRoles/{seg(role['id'])}/members"
        found = await self._api.collect(
            GRAPH, path, params={"$select": _MEMBER_SELECT}, limit=size + 1
        )
        return {
            "id": role.get("id"),
            "displayName": role.get("displayName"),
            "roleTemplateId": role.get("roleTemplateId"),
            "members": [{k: m.get(k) for k in MEMBER_FIELDS} for m in found[:size]],
            "hasMoreMembers": len(found) > size,
        }

    @operation(
        tool="entra_revoke_sign_in_sessions", api="graph", kind="action", permissions=_REVOKE
    )
    async def revoke_sign_in_sessions(self, user_id: UserId) -> JsonObject:
        """RESPONSE ACTION. End every sign-in session of an account: refresh tokens are invalidated
        and the person is asked to sign in again everywhere. It contains a session an attacker
        holds — a stolen token, a hijacked browser — and it changes nothing about the account
        itself, so there is nothing to undo: whoever knows the credential and passes
        multifactor signs in again. Access tokens already issued live until they expire, up to an
        hour, so this is a containment that completes rather than one that takes effect at once.
        Pair it with entra_disable_account where the credential itself is compromised."""
        answer = await self._api.request(
            GRAPH, "POST", f"/users/{seg(user_id)}/revokeSignInSessions"
        )
        return {"userId": user_id, "revoked": answer.get("value", True)}

    @operation(tool="entra_disable_account", api="graph", kind="action", permissions=_ENABLE)
    async def disable_account(self, user_id: UserId) -> JsonObject:
        """RESPONSE ACTION. Disable an Entra ID account: it can no longer sign in anywhere. Use it
        when the credential is compromised rather than a single session; the sessions already open
        are not ended by it, so revoke them with entra_revoke_sign_in_sessions as well. Reversed by
        entra_enable_account, which is the only thing it takes back. A service or an application
        that runs under the account stops with it, so read the account first (entra_get_user) and
        say so on the approval. An account synchronised from on-premises Active Directory is
        disabled in the directory it is mastered in, not here."""
        return await self._set_enabled(user_id, enabled=False)

    @operation(tool="entra_enable_account", api="graph", kind="action", permissions=_ENABLE)
    async def enable_account(self, user_id: UserId) -> JsonObject:
        """RESPONSE ACTION. Enable an Entra ID account again: the rollback of
        entra_disable_account. It restores nothing else — a session ended stays ended — and an
        account that was disabled before the incident is not one to enable here."""
        return await self._set_enabled(user_id, enabled=True)

    async def _set_enabled(self, user_id: str, *, enabled: bool) -> JsonObject:
        """The directory answers a property write with no content, so what comes back is what was
        asked and that it was accepted, rather than an empty object that reads as nothing."""
        await self._api.request(
            GRAPH, "PATCH", f"/users/{seg(user_id)}", json={"accountEnabled": enabled}
        )
        return {"userId": user_id, "accountEnabled": enabled}
