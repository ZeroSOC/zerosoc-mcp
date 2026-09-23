"""The capability probe: what one tenant exposes, turned into a capability binding file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import jsonschema
import pytest
from defender_fakes import RoleCredential, Script
from zerosoc_defender_xdr.capabilities import CLASS_BINDINGS, DATA_SOURCES
from zerosoc_defender_xdr.client import OPERATIONS, DefenderClient
from zerosoc_defender_xdr.hunting import HUNTING_TABLES
from zerosoc_defender_xdr.manifest import manifest
from zerosoc_defender_xdr.transport import Transport

G = "https://graph.microsoft.com/v1.0"
M = "https://api.securitycenter.microsoft.com/api"
SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "zerosoc.capabilities.schema.json").read_text()
)

GRAPH_ROLES = [
    "SecurityIncident.ReadWrite.All",
    "SecurityAlert.ReadWrite.All",
    "ThreatHunting.Read.All",
    "AuditLog.Read.All",
    "User.Read.All",
    "User.RevokeSessions.All",
    "User.EnableDisableAccount.All",
    "Mail.ReadWrite",
]
MDE_ROLES = [
    "Machine.Read.All",
    "Machine.Isolate",
    "Machine.StopAndQuarantine",
    "File.Read.All",
    "Software.Read.All",
    "Ti.ReadWrite.All",
]


def tenant(
    *,
    tables_with_rows: set[str],
    tables_not_exposed: set[str] = frozenset(),  # type: ignore[assignment]
    hunting_status: int = 200,
    sign_ins_status: int = 200,
    graph_roles: list[str] = GRAPH_ROLES,
    mde_roles: list[str] = MDE_ROLES,
    allow_actions: bool = True,
    machines_status: int = 200,
    users_status: int = 200,
    entitlements: frozenset[str] | None = None,
) -> DefenderClient:
    script = Script()

    def hunting(request: httpx.Request) -> httpx.Response:
        if hunting_status != 200:
            return httpx.Response(
                hunting_status, json={"error": {"code": "Forbidden", "message": "no"}}
            )
        table = Script.body(request)["Query"].split("|")[0].strip()
        if table in tables_not_exposed:
            return httpx.Response(
                400,
                json={
                    "error": {
                        "code": "BadRequest",
                        "message": f"'take' operator: Failed to resolve table or column expression named '{table}'",
                    }
                },
            )
        rows = [{"Timestamp": "2026-09-10T10:00:00Z"}] if table in tables_with_rows else []
        return httpx.Response(200, json={"schema": [], "results": rows})

    script.on("POST", f"{G}/security/runHuntingQuery", hunting)
    script.json("GET", f"{G}/security/incidents", {"value": [{"id": "14"}]})
    script.json("GET", f"{G}/security/alerts_v2", {"value": [{"id": "da-1"}]})
    script.json(
        "GET",
        f"{G}/auditLogs/signIns",
        {"value": []}
        if sign_ins_status == 200
        else {
            "error": {
                "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                "message": "Neither tenant is B2C or tenant doesn't have premium license",
            }
        },
        sign_ins_status,
    )
    script.json("GET", f"{G}/auditLogs/directoryAudits", {"value": []})
    script.json(
        "GET",
        f"{G}/users",
        {"value": [{"id": "u-1"}]} if users_status == 200 else {"error": {"message": "no"}},
        users_status,
    )
    script.on(
        "GET",
        f"{M}/machines",
        lambda _r: httpx.Response(
            machines_status if not script.sent("GET", "/api/machines")[1:] else 200,
            json={"value": [{"id": "m1"}]},
        ),
    )
    script.json("GET", f"{M}/software", {"value": []})
    script.json("GET", f"{M}/machineactions", {"value": []})

    async def no_sleep(_seconds: float) -> None:
        return None

    http = httpx.AsyncClient(transport=httpx.MockTransport(script))
    client = DefenderClient(
        transport=Transport(RoleCredential(graph_roles, mde_roles), http=http, sleep=no_sleep),
        allow_actions=allow_actions,
        entitlements=entitlements,
    )
    client.script = script  # type: ignore[attr-defined]
    return client


def defender_for_business(**overrides: Any) -> DefenderClient:
    """Alert tables hold rows, device tables are exposed but empty, email and cloud tables are absent.

    `DisruptionAndResponseEvents` is exposed and empty, not absent: its schema resolves at every
    tier and only a licensed feature ever writes it, which is the case the entitlement exists for.
    """
    return tenant(
        tables_with_rows={"AlertInfo", "AlertEvidence"},
        tables_not_exposed={
            t for t in HUNTING_TABLES if t.startswith(("Email", "UrlClick", "CloudApp", "Identity"))
        },
        **overrides,
    )


async def test_a_defender_for_business_tenant_has_alert_evidence_and_no_hunting_sources() -> None:
    binding = await defender_for_business().get_capabilities()

    sources, notes = binding["data_sources"], binding["data_source_notes"]
    for hunting_source in (
        "EDR",
        "EDR / endpoint process telemetry",
        "Endpoint telemetry",
        "Server EDR",
        "Netflow to/from the device",
        "Email gateway logs",
        "Mailbox audit logs",
        "CASB",
    ):
        assert sources[hunting_source] is False, hunting_source
    for alert_source in ("Anti-virus / anti-malware", "User-reported phishing mailbox"):
        assert sources[alert_source] is True, alert_source
    assert "DeviceProcessEvents is exposed but returned no rows" in notes["EDR"]
    assert "alert evidence" in notes["EDR"]
    assert "EmailEvents is not exposed" in notes["Email gateway logs"]

    endpoint = binding["capabilities"]["telemetry.endpoint"]
    assert endpoint["tool"] == "mcp:defender-xdr/defender_get_incident_evidence"
    assert endpoint["operation"] == "defender-xdr:get_incident_evidence"
    assert "alert evidence only" in endpoint["notes"]
    assert binding["probe"]["alert_evidence"] is True
    assert binding["probe"]["hunting"] == "alert tables only"


async def test_the_binding_is_a_valid_binding_file_that_answers_every_data_source() -> None:
    binding = await defender_for_business().get_capabilities()

    jsonschema.validate(binding, SCHEMA)
    assert set(binding["data_sources"]) == set(DATA_SOURCES) and len(DATA_SOURCES) == 85
    assert all(isinstance(v, bool) for v in binding["data_sources"].values())
    assert binding["alert_type_map"] == "alert_types.defender-xdr.json"
    assert "Defender XDR" in binding["deployment"]


async def test_the_sign_in_log_is_a_source_once_a_tool_reads_it() -> None:
    binding = await defender_for_business().get_capabilities()
    assert binding["data_sources"]["Identity provider sign-in logs"] is True
    assert (
        binding["capabilities"]["telemetry.identity"]["tool"]
        == "mcp:defender-xdr/entra_list_sign_ins"
    )


async def test_a_tenant_without_a_premium_directory_licence_has_no_sign_in_log() -> None:
    binding = await defender_for_business(sign_ins_status=403).get_capabilities()
    assert binding["data_sources"]["Identity provider sign-in logs"] is False
    assert "premium license" in binding["data_source_notes"]["Identity provider sign-in logs"]
    assert "telemetry.identity" not in binding["capabilities"]


async def test_a_tenant_with_full_hunting_binds_telemetry_to_the_query_tool() -> None:
    binding = await tenant(tables_with_rows=set(HUNTING_TABLES)).get_capabilities()

    assert binding["data_sources"]["EDR"] is True and "EDR" not in binding["data_source_notes"]
    assert binding["data_sources"]["Email gateway logs"] is True
    for klass in ("telemetry.endpoint", "telemetry.email", "telemetry.cloud", "siem.search"):
        assert (
            binding["capabilities"][klass]["tool"] == "mcp:defender-xdr/defender_run_hunting_query"
        )
    assert binding["probe"]["hunting"] == "available"


async def test_a_missing_permission_is_told_apart_from_a_missing_licence() -> None:
    binding = await defender_for_business(
        hunting_status=403,
        graph_roles=[r for r in GRAPH_ROLES if not r.startswith("ThreatHunting")],
    ).get_capabilities()

    assert binding["probe"]["hunting"] == "forbidden"
    assert binding["probe"]["checks"]["hunting:DeviceProcessEvents"]["status"] == "forbidden"
    assert "ThreatHunting.Read.All" in binding["data_source_notes"]["EDR"]
    # alert evidence does not depend on hunting
    assert (
        binding["capabilities"]["telemetry.endpoint"]["operation"]
        == "defender-xdr:get_incident_evidence"
    )


async def test_containment_is_bound_only_with_the_permission_to_act() -> None:
    binding = await defender_for_business(
        mde_roles=[r for r in MDE_ROLES if r != "Ti.ReadWrite.All"]
    ).get_capabilities()

    assert binding["capabilities"]["containment.isolate_host"]["tool"] == (
        "mcp:defender-xdr/defender_isolate_machine"
    )
    assert (
        "defender_unisolate_machine" in binding["capabilities"]["containment.isolate_host"]["notes"]
    )
    assert "containment.block_indicator" not in binding["capabilities"]
    assert "Ti.ReadWrite.All" in binding["probe"]["unbound"]["containment.block_indicator"]
    assert binding["probe"]["roles"]["mde"] == sorted(
        r for r in MDE_ROLES if r != "Ti.ReadWrite.All"
    )


async def test_identity_and_mailbox_containment_bind_where_the_directory_answers() -> None:
    binding = await defender_for_business().get_capabilities()

    sessions = binding["capabilities"]["containment.suspend_sessions"]
    assert sessions["tool"] == "mcp:defender-xdr/entra_revoke_sign_in_sessions"
    assert "no rollback to call" in sessions["notes"]
    account = binding["capabilities"]["containment.disable_account"]
    assert account["tool"] == "mcp:defender-xdr/entra_disable_account"
    assert "reversed by entra_enable_account" in account["notes"]
    rule = binding["capabilities"]["containment.remove_inbox_rule"]
    assert rule["tool"] == "mcp:defender-xdr/mailbox_delete_inbox_rule"
    assert "reversed by mailbox_create_inbox_rule" in rule["notes"]


async def test_identity_containment_is_unbound_without_the_permission_to_act() -> None:
    """A tenant that grants the directory read and no write reads accounts and contains none."""
    binding = await defender_for_business(
        graph_roles=[
            r for r in GRAPH_ROLES if r not in ("User.RevokeSessions.All", "Mail.ReadWrite")
        ]
    ).get_capabilities()

    assert "containment.disable_account" in binding["capabilities"]  # its own role is still granted
    assert "containment.suspend_sessions" not in binding["capabilities"]
    assert "User.RevokeSessions.All" in binding["probe"]["unbound"]["containment.suspend_sessions"]
    assert "Mail.ReadWrite" in binding["probe"]["unbound"]["containment.remove_inbox_rule"]


async def test_a_directory_that_does_not_answer_contains_no_account() -> None:
    binding = await defender_for_business(users_status=403).get_capabilities()

    for klass in (
        "containment.suspend_sessions",
        "containment.disable_account",
        "containment.remove_inbox_rule",
    ):
        assert klass not in binding["capabilities"]
        assert "graph.users refused the call" in binding["probe"]["unbound"][klass]


async def test_the_probe_runs_once_until_a_refresh_is_asked() -> None:
    client = defender_for_business()
    await client.get_capabilities()
    calls = len(client.script.requests)  # type: ignore[attr-defined]
    await client.get_capabilities()
    assert len(client.script.requests) == calls  # type: ignore[attr-defined]
    await client.get_capabilities(refresh=True)
    assert len(client.script.requests) == 2 * calls  # type: ignore[attr-defined]


async def test_the_probe_only_reads() -> None:
    client = defender_for_business()
    await client.get_capabilities()
    posts = [r for r in client.script.requests if r.method != "GET"]  # type: ignore[attr-defined]
    assert {str(r.url) for r in posts} == {f"{G}/security/runHuntingQuery"}


def test_the_manifest_lists_the_classes_the_server_satisfies_with_tool_and_operation() -> None:
    document = manifest()
    by_name = {o.name: o for o in OPERATIONS}

    assert document["server"] == "defender-xdr"
    assert set(document["capabilities"]) >= {
        "asset.cmdb",
        "identity.directory",
        "cases.store",
        "malware.repository",
        "decode",
        "telemetry.endpoint",
        "telemetry.identity",
        "telemetry.email",
        "telemetry.cloud",
        "telemetry.network",
        "siem.search",
        "containment.isolate_host",
        "containment.quarantine_file",
        "containment.block_indicator",
        "ticketing",
    }
    for klass, options in document["capabilities"].items():
        for option in options:
            operation = by_name[option["operation"].removeprefix("defender-xdr:")]
            assert option["tool"] == f"mcp:defender-xdr/{operation.tool}", klass
            assert option["kind"] == operation.kind
    assert {b.klass for b in CLASS_BINDINGS} == set(document["capabilities"])
    assert len(document["tools"]) == len(OPERATIONS)
    assert document["manual_checks"][0]["id"] == "attack_disruption_actions"


@pytest.mark.parametrize("binding", CLASS_BINDINGS, ids=lambda b: b.klass)
def test_a_class_binding_names_real_operations_and_known_checks(binding: Any) -> None:
    names = {o.name for o in OPERATIONS}
    for option in binding.options:
        assert option.operation in names
        assert option.rollback is None or option.rollback in names
        for check in option.requires_any + option.requires_all:
            kind, _, subject = check.partition(":")
            assert kind in {"api", "hunting", "role", "always"}, check
            assert kind != "hunting" or subject in HUNTING_TABLES


async def test_a_deployment_with_actions_off_says_so_on_the_containment_classes() -> None:
    binding = await defender_for_business(allow_actions=False).get_capabilities()
    isolate = binding["capabilities"]["containment.isolate_host"]
    assert isolate["operation"] == "defender-xdr:isolate_machine"
    assert "response actions are disabled in this deployment" in isolate["notes"]
    assert "disabled" not in binding["capabilities"]["cases.store"].get("notes", "")
    assert binding["probe"]["response_actions_enabled"] is False


async def test_a_probe_taken_during_an_outage_is_not_kept() -> None:
    client = defender_for_business(machines_status=500)
    first = await client.get_capabilities()
    assert first["probe"]["checks"]["api:mde.machines"]["status"] == "error"
    assert "asset.cmdb" not in first["capabilities"]

    second = await client.get_capabilities()  # no refresh asked: the failed probe was not cached

    assert second["probe"]["checks"]["api:mde.machines"]["status"] == "available"
    assert "asset.cmdb" in second["capabilities"]


async def test_two_callers_at_once_share_one_probe() -> None:
    import asyncio

    client = defender_for_business()
    await asyncio.gather(client.get_capabilities(), client.get_capabilities())
    hunting = [r for r in client.script.requests if r.method == "POST"]  # type: ignore[attr-defined]
    assert len(hunting) == len(HUNTING_TABLES)


# --- refusals seen on test tenants ----------------------------------------------------------------

LIVE_REFUSALS = [
    (
        403,
        "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
        "Tenant is not a B2C tenant and doesn't have premium license",
        "unlicensed",
    ),
    (
        401,
        "Unauthorized",
        "Unauthorized request - reason of failure: Account mode is inactive",
        "unlicensed",
    ),
    (401, "Unauthorized", "Unauthorized request - reason of failure: No Tvm license", "unlicensed"),
    (
        403,
        "Authentication_MSGraphPermissionMissing",
        "The principal does not have required Microsoft Graph permission(s): AuditLog.Read.All",
        "forbidden",
    ),
    (
        403,
        "Forbidden",
        "Missing application roles. API required roles: Machine.Read.All",
        "forbidden",
    ),
]


@pytest.mark.parametrize(("status", "code", "message", "expected"), LIVE_REFUSALS)
def test_a_refusal_for_a_licence_is_not_a_refusal_for_a_permission(
    status: int, code: str, message: str, expected: str
) -> None:
    from zerosoc_defender_xdr.errors import DefenderApiError
    from zerosoc_defender_xdr.probe import _failed

    error = DefenderApiError(
        status=status, api="x", method="GET", path="/", code=code, message=message
    )
    assert _failed(error).status == expected


async def test_an_unlicensed_service_is_named_as_such_in_the_binding() -> None:
    binding = await defender_for_business(sign_ins_status=403).get_capabilities()
    assert binding["probe"]["checks"]["api:graph.sign_ins"]["status"] == "unlicensed"
    assert (
        "not licensed in this tenant"
        in binding["data_source_notes"]["Identity provider sign-in logs"]
    )
    assert "not licensed" in binding["probe"]["unbound"]["telemetry.identity"]


# --- an entitlement is declared, never read out of an empty table ---------------------------------


async def test_an_empty_table_only_a_licence_writes_is_undeclared_rather_than_absent() -> None:
    """Its schema resolves at every tier and the query succeeds either way, so an empty answer does
    not say whether the tenant lacks the feature or the feature has not acted. A deployment that
    declared nothing gets neither answer, and is told so."""
    binding = await defender_for_business().get_capabilities()

    check = binding["probe"]["checks"]["hunting:DisruptionAndResponseEvents"]
    assert check["status"] == "undeclared"
    assert "endpoint_p2" in check["detail"]

    disruption = next(
        m for m in binding["probe"]["manual_checks"] if m["id"] == "attack_disruption_actions"
    )
    assert disruption["automated"] is False, "nobody said the tenant has it"


async def test_a_declared_entitlement_makes_an_empty_table_an_answer() -> None:
    """A source the deployment has, holding nothing today, has answered: there was nothing. That is
    a finding, and the check behind it stands automated."""
    binding = await defender_for_business(
        entitlements=frozenset({"endpoint_p2"})
    ).get_capabilities()

    check = binding["probe"]["checks"]["hunting:DisruptionAndResponseEvents"]
    assert check["status"] == "entitled_no_rows"

    disruption = next(
        m for m in binding["probe"]["manual_checks"] if m["id"] == "attack_disruption_actions"
    )
    assert disruption["automated"] is True


async def test_a_declaration_that_leaves_an_entitlement_out_states_its_absence() -> None:
    """Declaring is declaring the whole set: an entitlement left out of a stated set is stated to be
    absent, which is a different answer from saying nothing at all."""
    binding = await defender_for_business(entitlements=frozenset()).get_capabilities()

    check = binding["probe"]["checks"]["hunting:DisruptionAndResponseEvents"]
    assert check["status"] == "unlicensed"
    assert "not among the declared entitlements" in check["detail"]


async def test_a_table_no_licence_gates_is_untouched_by_the_declaration() -> None:
    """Most tables are written by ordinary traffic, where an empty answer means the traffic did not
    occur. The entitlement machinery must not reach them."""
    for declared in (None, frozenset(), frozenset({"endpoint_p2"})):
        binding = await defender_for_business(entitlements=declared).get_capabilities()
        assert binding["probe"]["checks"]["hunting:DeviceProcessEvents"]["status"] == "empty"
        assert binding["data_sources"]["EDR"] is False
