"""The capability probe: ask one tenant what it exposes, and write the capability binding file.

The probe only reads. It calls the client's own operations with the smallest possible request: one
row from each hunting table, one item from each API it depends on. It reads the application
permissions from the tokens' `roles` claim, so a missing permission is told apart from a missing
licence, and an empty table from both.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from .capabilities import (
    ALERT_TYPE_MAP,
    CLASS_BINDINGS,
    DATA_SOURCES,
    MANUAL_CHECKS,
    RAW_TABLES,
    TABLE_ENTITLEMENTS,
    Option,
    operation_ref,
    tool_ref,
    version,
)
from .errors import DefenderApiError
from .hunting import HUNTING_TABLES

if TYPE_CHECKING:
    from .client import DefenderClient

Status = Literal[
    "available",
    "empty",
    "entitled_no_rows",
    "undeclared",
    "not_exposed",
    "unlicensed",
    "forbidden",
    "error",
    "granted",
    "missing",
    "unknown",
]
_UNLICENSED = re.compile(r"licen[cs]e|account mode is inactive", re.IGNORECASE)
"""How the services word a refusal that no permission would lift: the tenant has not bought, or no
longer runs, the service behind the API."""
API_CHECKS: dict[str, str] = {
    "graph.incidents": "list_incidents",
    "graph.alerts": "list_alerts",
    "graph.sign_ins": "list_sign_ins",
    "graph.users": "list_users",
    "graph.directory_audits": "list_directory_audits",
    "mde.machines": "list_machines",
    "mde.software": "list_software",
    "mde.machine_actions": "list_machine_actions",
}
"""Check -> the list operation asked for a single item."""
CONCURRENCY = 4
_ALERT_EVIDENCE_NOTE = (
    "the process, file, registry and network entities cited by the alerts are available as alert"
    " evidence (defender_get_incident_evidence)"
)


@dataclass(frozen=True)
class Check:
    status: Status
    detail: str = ""

    @property
    def ok(self) -> bool:
        """`unknown` is a permission that could not be read from the token: not a reason to unbind.

        `entitled_no_rows` is a source the deployment has and that holds nothing today, which is an
        answer and not a gap. `undeclared` is not ok: a tier nobody stated cannot be assumed.
        """
        return self.status in ("available", "granted", "unknown", "entitled_no_rows")


@dataclass(frozen=True)
class ProbeResult:
    checked_at: str
    tenant_id: str | None
    roles: dict[str, list[str] | None]
    checks: dict[str, Check]
    entitlements: frozenset[str] | None = None
    """What the deployment declared it is entitled to, or None when it declared nothing. Declared
    means the set is complete: an entitlement absent from a stated set is stated to be absent."""

    @property
    def complete(self) -> bool:
        """No check failed for a reason of the moment: the result describes the tenant, not an outage."""
        return all(check.status != "error" for check in self.checks.values())

    def check(self, check_id: str) -> Check:
        kind, _, subject = check_id.partition(":")
        if kind == "always":
            return Check("available")
        if kind == "role":
            api, _, role = subject.partition("/")
            granted = self.roles.get(api)
            if granted is None:
                return Check("unknown", f"{role}: the token's roles could not be read")
            return (
                Check("granted") if role in granted else Check("missing", f"{role} is not granted")
            )
        found = self.checks.get(check_id, Check("error", f"{check_id} was not checked"))
        if kind == "hunting" and found.status == "empty":
            return self._entitled(subject, found)
        return found

    def _entitled(self, table: str, found: Check) -> Check:
        """An empty table that only a licensed feature writes says nothing on its own.

        Its schema resolves at every tier and the query succeeds either way, so no observation
        separates a tenant that lacks the feature from one where the feature has not acted. What
        the deployment declared decides it, and where it declared nothing the honest answer is that
        nobody knows — which is a visibility gap, not an absence.
        """
        entitlement = TABLE_ENTITLEMENTS.get(table)
        if entitlement is None:
            return found  # written by ordinary traffic: empty means the traffic did not occur
        if self.entitlements is None:
            return Check("undeclared", f"no deployment entitlement was declared for {entitlement}")
        if entitlement in self.entitlements:
            return Check("entitled_no_rows", f"{entitlement} is declared; the table holds no rows")
        return Check("unlicensed", f"{entitlement} is not among the declared entitlements")


async def run_probe(
    client: DefenderClient, *, entitlements: frozenset[str] | None = None
) -> ProbeResult:
    limit = asyncio.Semaphore(CONCURRENCY)

    async def table(name: str) -> tuple[str, Check]:
        async with limit:
            try:
                result = await client.run_hunting_query(f"{name} | take 1")
            except DefenderApiError as error:
                return f"hunting:{name}", _failed(error)
        return f"hunting:{name}", Check("available" if result.get("results") else "empty")

    async def api(name: str, operation: str) -> tuple[str, Check]:
        async with limit:
            try:
                await getattr(client, operation)(top=1)
            except DefenderApiError as error:
                return f"api:{name}", _failed(error)
        return f"api:{name}", Check("available")

    checks = await asyncio.gather(
        *(api(name, operation) for name, operation in API_CHECKS.items()),
        *(table(name) for name in HUNTING_TABLES),
    )
    claims = await client.token_claims()
    return ProbeResult(
        checked_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        tenant_id=next((str(c["tid"]) for c in claims.values() if c and c.get("tid")), None),
        roles={
            name: sorted(map(str, found.get("roles") or [])) if found is not None else None
            for name, found in claims.items()
        },
        checks=dict(checks),
        entitlements=entitlements,
    )


def _failed(error: DefenderApiError) -> Check:
    detail = f"{error.code}: {error.message}" if error.code else error.message
    if error.status in (401, 403):
        return Check("unlicensed" if _UNLICENSED.search(error.message) else "forbidden", detail)
    if error.status == 400 and "failed to resolve" in error.message.lower():
        return Check("not_exposed", detail)
    return Check("error", f"HTTP {error.status} {detail}")


# --- probe result -> capability binding ------------------------------------------------------------


def build_binding(
    result: ProbeResult, tools: Mapping[str, str], *, actions_enabled: bool
) -> dict[str, Any]:
    """The capability binding file of the ZeroSOC skills, for what this tenant exposes.

    `tools` maps operation to MCP tool name. `actions_enabled` is the deployment's own gate: a
    containment class stays bound to its operation, with a note when the deployment has actions off.
    """
    hunting = _hunting_summary(result)
    capabilities: dict[str, dict[str, str]] = {}
    unbound: dict[str, str] = {}
    for binding in CLASS_BINDINGS:
        option = next((o for o in binding.options if not _unmet(o, result)), None)
        if option is None:
            unbound[binding.klass] = "; ".join(_unmet(binding.options[0], result))
            continue
        capabilities[binding.klass] = _entry(option, result, tools, actions_enabled, binding.klass)

    sources: dict[str, bool] = {}
    notes: dict[str, str] = {}
    alert_evidence = result.check("api:graph.alerts").ok
    for name, rule in DATA_SOURCES.items():
        checks: list[str] = rule.get("any_of", [])
        sources[name] = any(result.check(c).ok for c in checks)
        parts = [] if sources[name] else [_why(c, result.check(c)) for c in checks]
        if rule.get("note"):
            parts.append(str(rule["note"]))
        if not sources[name] and rule.get("fallback") == "alert_evidence" and alert_evidence:
            parts.append(_ALERT_EVIDENCE_NOTE)
        if parts:
            notes[name] = "; ".join(parts)

    return {
        "deployment": f"Microsoft Defender XDR tenant probed on {result.checked_at} through the"
        f" {tool_ref('').rstrip('/')} integration {version()} (hunting: {hunting}). Generated by the"
        " capability probe: bind the classes this technology does not satisfy, such as"
        " soc.knowledge_base and reputation.multi_engine, before use.",
        "alert_type_map": ALERT_TYPE_MAP,
        "capabilities": capabilities,
        "data_sources": sources,
        "data_source_notes": notes,
        "probe": {
            "checked_at": result.checked_at,
            "tenant_id": result.tenant_id,
            "hunting": hunting,
            "alert_evidence": alert_evidence,
            "response_actions_enabled": actions_enabled,
            "roles": result.roles,
            # resolved, not raw: an empty table a licence gates is published as what it
            # means for this deployment, which is the whole point of declaring the tier
            "checks": {name: asdict(result.check(name)) for name in sorted(result.checks)},
            "unbound": unbound,
            "manual_checks": [
                dict(m, automated=result.check(m["automated_by"]).ok) for m in MANUAL_CHECKS
            ],
        },
    }


def _unmet(option: Option, result: ProbeResult) -> list[str]:
    unmet = [_why(c, result.check(c)) for c in option.requires_all if not result.check(c).ok]
    if option.requires_any and not any(result.check(c).ok for c in option.requires_any):
        unmet.extend(_why(c, result.check(c)) for c in option.requires_any)
    return unmet


def _entry(
    option: Option, result: ProbeResult, tools: Mapping[str, str], actions_enabled: bool, klass: str
) -> dict[str, str]:
    notes = [option.notes] if option.notes else []
    if option.rollback:
        notes.append(f"reversed by {tools[option.rollback]}")
    notes.extend(
        result.check(c).detail for c in option.requires_all if result.check(c).status == "unknown"
    )
    if klass.startswith("containment.") and not actions_enabled:
        notes.append(
            "response actions are disabled in this deployment: the tool is not listed and the"
            " operation refuses until they are enabled"
        )
    entry = {
        "tool": tool_ref(tools[option.operation]),
        "operation": operation_ref(option.operation),
    }
    if notes:
        entry["notes"] = "; ".join(notes)
    return entry


def _why(check_id: str, check: Check) -> str:
    kind, _, subject = check_id.partition(":")
    if kind == "hunting":
        return {
            "empty": f"{subject} is exposed but returned no rows in the last 30 days: not licensed"
            " for this tenant, or no onboarded source",
            "undeclared": f"{subject} is written only by a licensed feature and holds no rows, and"
            " this deployment declared no entitlement: whether the feature is absent or simply has"
            " not acted cannot be read from the API. Declare the entitlement, or answer it from the"
            " portal.",
            "not_exposed": f"{subject} is not exposed at this licence level",
            "forbidden": f"{subject} could not be read: the application permission"
            " ThreatHunting.Read.All is missing or not consented",
        }.get(check.status, f"{subject}: {check.detail}")
    if kind == "role":
        return check.detail
    if check.status == "unlicensed":
        return f"{subject} is not licensed in this tenant ({check.detail})"
    return f"{subject} refused the call ({check.detail})" if check.detail else f"{subject} failed"


def _hunting_summary(result: ProbeResult) -> str:
    statuses = {t: result.check(f"hunting:{t}").status for t in HUNTING_TABLES}
    if any(statuses[t] == "available" for t in statuses if not t.startswith("Alert")):
        return "available" if any(statuses[t] == "available" for t in RAW_TABLES) else "partial"
    if any(status == "available" for status in statuses.values()):
        return "alert tables only"
    if statuses and all(status == "forbidden" for status in statuses.values()):
        return "forbidden"
    return "unavailable"
