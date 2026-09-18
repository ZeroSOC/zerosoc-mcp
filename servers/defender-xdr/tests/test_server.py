"""The MCP server is a wrapper: every tool is a tool-client operation, and it runs on its own."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from defender_fakes import FakeCredential, Script
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver.exceptions import ToolError
from zerosoc_defender_xdr.client import OPERATIONS, DefenderClient
from zerosoc_defender_xdr.transport import Transport
from zerosoc_mcp_defender_xdr.server import build_server, settings_from, warm_up

G = "https://graph.microsoft.com/v1.0"
SOURCES = Path(__file__).parents[1] / "src" / "zerosoc_mcp_defender_xdr"


def client_for(script: Script, *, allow_actions: bool = False) -> DefenderClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(script))
    return DefenderClient(
        transport=Transport(FakeCredential(), http=http), allow_actions=allow_actions
    )


def payload(result: Any) -> Any:
    return json.loads(result.content[0].text)


async def test_every_tool_is_an_operation_of_the_tool_client_and_nothing_else() -> None:
    server = build_server(client_for(Script(), allow_actions=True))
    tools = {t.name: t for t in await server.list_tools()}

    assert set(tools) == {o.tool for o in OPERATIONS}
    for operation in OPERATIONS:
        assert tools[operation.tool].description == operation.description


def test_the_server_holds_no_api_code_of_its_own() -> None:
    """No HTTP library, no API host, no endpoint path: the wrapper cannot duplicate a call."""
    for source in SOURCES.glob("*.py"):
        text = source.read_text()
        imported = {
            (node.module or "") if isinstance(node, ast.ImportFrom) else alias.name
            for node in ast.walk(ast.parse(text))
            if isinstance(node, ast.Import | ast.ImportFrom)
            for alias in node.names
        }
        assert not {i.split(".")[0] for i in imported} & {"httpx", "requests", "urllib", "aiohttp"}
        for fragment in ("graph.microsoft.com", "securitycenter", "/security/", "/machines"):
            assert fragment not in text, f"{source.name} mentions {fragment}"


async def test_response_actions_are_not_even_listed_unless_enabled() -> None:
    actions = {o.tool for o in OPERATIONS if o.kind == "action"}
    safe = {t.name for t in await build_server(client_for(Script())).list_tools()}
    assert actions and not safe & actions
    assert {o.tool for o in OPERATIONS if o.kind != "action"} == safe


async def test_tools_say_whether_they_read_write_or_act() -> None:
    server = build_server(client_for(Script(), allow_actions=True))
    hints = {t.name: t.annotations for t in await server.list_tools()}
    assert hints["defender_list_incidents"].read_only_hint is True
    assert hints["defender_add_incident_comment"].read_only_hint is False
    assert hints["defender_add_incident_comment"].destructive_hint is False
    assert hints["defender_isolate_machine"].destructive_hint is True


async def test_parameters_are_described_for_the_agent() -> None:
    server = build_server(client_for(Script()))
    schema = {t.name: t.input_schema for t in await server.list_tools()}[
        "defender_get_incident_evidence"
    ]
    assert schema["required"] == ["incident_id"]
    assert "reconcile" not in schema["properties"]["incident_id"]["description"]
    assert all(p.get("description") for p in schema["properties"].values())


async def test_a_tool_call_is_the_operation_call() -> None:
    script = Script().json("GET", f"{G}/security/incidents", {"value": [{"id": "14"}]})
    server = build_server(client_for(script))

    result = await server.call_tool(
        "defender_list_incidents", {"filter": "status eq 'active'", "top": 5}
    )

    assert payload(result) == {"value": [{"id": "14"}]}
    assert dict(script.requests[0].url.params) == {"$filter": "status eq 'active'", "$top": "5"}


async def test_an_api_failure_reaches_the_agent_with_its_remediation() -> None:
    script = Script().json(
        "GET", f"{G}/security/incidents", {"error": {"code": "Forbidden", "message": "no"}}, 403
    )
    server = build_server(client_for(script))

    with pytest.raises(ToolError) as caught:
        await server.call_tool("defender_list_incidents", {})

    assert "403" in str(caught.value) and "SecurityIncident.ReadWrite.All" in str(caught.value)


async def test_a_crash_keeps_its_text_on_the_server() -> None:
    def broken(_request: httpx.Request) -> httpx.Response:
        raise KeyError("internal detail")

    server = build_server(client_for(Script().on("GET", f"{G}/security/incidents", broken)))
    with pytest.raises(Exception) as caught:
        await server.call_tool("defender_list_incidents", {})
    assert "internal detail" not in str(caught.value)


async def test_without_credentials_every_call_says_what_to_set() -> None:
    settings = settings_from({})
    assert settings.credential is None and settings.allow_actions is False
    server = build_server(DefenderClient(settings.credential_or_placeholder()))

    with pytest.raises(ToolError) as caught:
        await server.call_tool("defender_list_incidents", {})

    for name in ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"):
        assert name in str(caught.value)


def test_actions_need_the_exact_opt_in() -> None:
    assert settings_from({"DEFENDER_MCP_ALLOW_ACTIONS": "true"}).allow_actions is True
    for value in ("1", "yes", "TRUE ", ""):
        assert settings_from({"DEFENDER_MCP_ALLOW_ACTIONS": value}).allow_actions is (
            value.strip().lower() == "true"
        )


async def test_the_server_runs_standalone_over_stdio() -> None:
    """A separate process, no engine, no credentials: an MCP host can list and call tools."""
    parameters = StdioServerParameters(
        command=sys.executable, args=["-m", "zerosoc_mcp_defender_xdr"], env={"PATH": ""}
    )
    async with stdio_client(parameters) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        names = {t.name for t in (await session.list_tools()).tools}
        decoded = await session.call_tool(
            "defender_decode_command", {"command_line": "powershell -enc dwBoAG8AYQBtAGkA"}
        )

        refused = await session.call_tool("defender_list_incidents", {})

    assert "defender_get_incident_evidence" in names and "defender_isolate_machine" not in names
    assert payload(decoded) == {
        "decoded": "whoami",
        "found": True,
        "rounds": 1,
        "layers": ["whoami"],
        "capped": False,
    }
    assert refused.is_error and "DEFENDER_TENANT_ID" in refused.content[0].text


async def test_a_bad_argument_is_explained_and_a_parse_crash_is_not() -> None:
    server = build_server(client_for(Script()))
    with pytest.raises(ToolError, match="not a timestamp"):
        await server.call_tool("defender_to_utc", {"timestamp": "yesterday"})

    def garbled(_request: httpx.Request) -> httpx.Response:
        raise ValueError("internal parse detail")

    server = build_server(client_for(Script().on("GET", f"{G}/security/incidents", garbled)))
    with pytest.raises(Exception) as caught:
        await server.call_tool("defender_list_incidents", {})
    assert "internal parse detail" not in str(caught.value)


async def test_the_tenant_is_probed_as_the_server_starts_and_a_failed_probe_stops_nothing() -> None:
    lines: list[str] = []

    class Probed:
        async def get_capabilities(self) -> dict[str, Any]:
            return {"probe": {"hunting": "alert tables only"}}

    class Unreachable:
        async def get_capabilities(self) -> dict[str, Any]:
            raise OSError("network is down")

    await warm_up(Probed(), lines.append)  # type: ignore[arg-type]
    await warm_up(Unreachable(), lines.append)  # type: ignore[arg-type]

    assert lines == [
        "capability probe: hunting alert tables only",
        "capability probe did not run: network is down",
    ]
