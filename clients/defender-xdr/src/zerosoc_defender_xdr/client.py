"""`DefenderClient`: the typed tool client. One method per API operation, grouped by surface."""

from __future__ import annotations

from typing import Any

from .alerts import Alerts
from .auth import TokenCredential
from .capability_probe import CapabilityProbe
from .entities import Entities
from .helpers import Helpers
from .hunting import Hunting
from .identity_logs import IdentityLogs
from .incidents import Incidents
from .indicators import Indicators
from .machine_actions import MachineActions
from .machines import Machines
from .operations import Operation, operations_of
from .scoring import Scoring
from .transport import GRAPH, MDE, Transport
from .vulnerabilities import Vulnerabilities


class DefenderClient(
    Incidents,
    Alerts,
    Hunting,
    IdentityLogs,
    Machines,
    Entities,
    Indicators,
    MachineActions,
    Vulnerabilities,
    Scoring,
    Helpers,
    CapabilityProbe,
):
    """Deterministic, typed access to Microsoft Defender XDR for one tenant.

    Response actions raise `ActionsDisabledError` unless the client is created with
    `allow_actions=True`: safe by default, for the engine as for the MCP server.
    """

    def __init__(
        self,
        credential: TokenCredential | None = None,
        *,
        transport: Transport | None = None,
        allow_actions: bool = False,
        entitlements: frozenset[str] | None = None,
    ) -> None:
        if transport is None:
            if credential is None:
                raise ValueError("pass a credential or a transport")
            transport = Transport(credential)
        self._api = transport
        self._allow_actions = allow_actions
        self._entitlements = entitlements

    @property
    def allow_actions(self) -> bool:
        return self._allow_actions

    @property
    def entitlements(self) -> frozenset[str] | None:
        """What the deployment declared it is entitled to; None when it declared nothing."""
        return self._entitlements

    async def token_claims(self) -> dict[str, dict[str, Any] | None]:
        """Per API, the claims of the token in use (tenant, granted roles); None when unreadable."""
        return {api.name: await self._api.claims(api) for api in (GRAPH, MDE)}

    async def aclose(self) -> None:
        await self._api.aclose()


OPERATIONS: tuple[Operation, ...] = operations_of(DefenderClient)
